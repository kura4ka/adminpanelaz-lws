#include "panel_history.h"

#include "host_metrics.h"
#include "vpn_status.h"
#include "wireguard_status.h"

#include <openssl/evp.h>
#include <sqlite3.h>
#include <errno.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum {
    SAMPLE_SECONDS = 60,
    CLIENT_BUCKET_SECONDS = 3600,
    DAY_SECONDS = 86400,
    RETENTION_DAYS = 30,
    MAX_COUNTERS_PER_SNAPSHOT = 2048,
    MAX_AUDIT_RESULTS = 200
};

static sqlite3 *db;
static int64_t last_sample;
static int64_t last_legacy_sample;
static int64_t last_legacy_traffic;

static int64_t add_counter(int64_t left, int64_t right)
{
    return left > INT64_MAX - right ? INT64_MAX : left + right;
}

static void sql_add_counter(sqlite3_context *context, int count, sqlite3_value **values)
{
    (void)count;
    int64_t left = sqlite3_value_int64(values[0]);
    int64_t right = sqlite3_value_int64(values[1]);
    sqlite3_result_int64(context, add_counter(left >= 0 ? left : 0, right >= 0 ? right : 0));
}

struct counter_sum {
    int64_t value;
    bool present;
};

static void sum_step(sqlite3_context *context, int count, sqlite3_value **values)
{
    (void)count;
    if (sqlite3_value_type(values[0]) == SQLITE_NULL)
        return;
    struct counter_sum *sum = sqlite3_aggregate_context(context, sizeof(*sum));
    if (!sum) {
        sqlite3_result_error_nomem(context);
        return;
    }
    int64_t number = sqlite3_value_int64(values[0]);
    sum->value = add_counter(sum->value, number >= 0 ? number : 0);
    sum->present = true;
}

static void sum_finish(sqlite3_context *context)
{
    struct counter_sum *sum = sqlite3_aggregate_context(context, 0);
    if (sum && sum->present)
        sqlite3_result_int64(context, sum->value);
}

static const char *const action_names[] = {
    [PANEL_HISTORY_LOGIN] = "login",
    [PANEL_HISTORY_LOGOUT] = "logout",
    [PANEL_HISTORY_PASSWORD_CHANGE] = "password_change",
    [PANEL_HISTORY_BACKUP_CREATE] = "backup_create",
    [PANEL_HISTORY_BACKUP_UPLOAD] = "backup_upload",
    [PANEL_HISTORY_BACKUP_DELETE] = "backup_delete",
    [PANEL_HISTORY_BACKUP_RESTORE] = "backup_restore",
    [PANEL_HISTORY_CLIENT_CHANGE] = "client_change",
    [PANEL_HISTORY_NODE_CHANGE] = "node_change",
    [PANEL_HISTORY_ROUTING_CHANGE] = "routing_change",
    [PANEL_HISTORY_SETTINGS_CHANGE] = "settings_change"
};

static bool audit_action_name(const char *value, size_t length)
{
    static const char allowed[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.:-";
    return value && length > 0 && length <= 64 && strspn(value, allowed) == length && value[length] == '\0';
}

static bool run(const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static bool prepare(sqlite3_stmt **statement, const char *sql)
{
    return sqlite3_prepare_v2(db, sql, -1, statement, NULL) == SQLITE_OK;
}

void panel_history_close(void)
{
    if (db)
        sqlite3_close(db);
    db = NULL;
    last_sample = 0;
    last_legacy_sample = 0;
    last_legacy_traffic = 0;
}

bool panel_history_open(const char *data_dir)
{
    static const char schema[] =
        "PRAGMA cache_size=-128;"
        "PRAGMA temp_store=FILE;"
        "PRAGMA mmap_size=0;"
        "BEGIN;"
        "CREATE TABLE IF NOT EXISTS observation ("
        "ts INTEGER PRIMARY KEY,cpu INTEGER,mem_used INTEGER,mem_total INTEGER,"
        "disk_used INTEGER,disk_total INTEGER,openvpn INTEGER,wireguard INTEGER,rx INTEGER,tx INTEGER,"
        "traffic_complete INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS peer_counter ("
        "identity BLOB PRIMARY KEY,last_seen INTEGER NOT NULL,rx INTEGER NOT NULL,tx INTEGER NOT NULL"
        ") WITHOUT ROWID;"
        "CREATE INDEX IF NOT EXISTS peer_counter_seen ON peer_counter(last_seen,identity);"
        "CREATE TABLE IF NOT EXISTS client_traffic ("
        "ts INTEGER NOT NULL,client TEXT NOT NULL,rx INTEGER NOT NULL,tx INTEGER NOT NULL,"
        "PRIMARY KEY(ts,client)) WITHOUT ROWID;"
        "CREATE INDEX IF NOT EXISTS client_traffic_client ON client_traffic(client,ts);"
        "CREATE TABLE IF NOT EXISTS audit_event ("
        "id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,actor INTEGER,action INTEGER NOT NULL,"
        "success INTEGER NOT NULL);"
        "CREATE INDEX IF NOT EXISTS audit_event_ts ON audit_event(ts);"
        "CREATE TABLE IF NOT EXISTS legacy_observation ("
        "ts INTEGER PRIMARY KEY,cpu INTEGER,mem_used INTEGER,mem_total INTEGER,"
        "disk_percent INTEGER,openvpn INTEGER,wireguard INTEGER,amneziawg2 INTEGER,rx INTEGER,tx INTEGER);"
        "CREATE TABLE IF NOT EXISTS legacy_client_traffic ("
        "ts INTEGER NOT NULL,client TEXT NOT NULL,rx INTEGER NOT NULL,tx INTEGER NOT NULL,"
        "PRIMARY KEY(client,ts)) WITHOUT ROWID;"
        "CREATE INDEX IF NOT EXISTS legacy_client_traffic_ts ON legacy_client_traffic(ts);"
        "CREATE TABLE IF NOT EXISTS legacy_audit_event ("
        "id INTEGER PRIMARY KEY,ts INTEGER NOT NULL,actor INTEGER,action TEXT NOT NULL,"
        "success INTEGER);"
        "CREATE INDEX IF NOT EXISTS legacy_audit_event_ts ON legacy_audit_event(ts);"
        "CREATE VIEW IF NOT EXISTS history_series AS "
        "SELECT ts,cpu,mem_used,mem_total,disk_used,disk_total,"
        "CAST(CASE WHEN disk_total>0 THEN 1000.0*disk_used/disk_total+0.5 END AS INTEGER) disk_percent,"
        "openvpn,wireguard,NULL amneziawg2,rx,tx,traffic_complete FROM observation UNION ALL "
        "SELECT ts,cpu,mem_used,mem_total,NULL,NULL,disk_percent,openvpn,wireguard,amneziawg2,rx,tx,"
        "CASE WHEN rx IS NOT NULL THEN 1 END FROM legacy_observation;";
    static const char complete_schema[] = "COMMIT;";
    if (db || !data_dir || !*data_dir)
        return false;
    char path[4096];
    int length = snprintf(path, sizeof(path), "%s/lws-history.db", data_dir);
    if (length < 0 || (size_t)length >= sizeof(path))
        return false;

    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
#ifdef SQLITE_OPEN_NOFOLLOW
    flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    sqlite3_stmt *latest = NULL;
    bool ok = sqlite3_open_v2(path, &db, flags, NULL) == SQLITE_OK &&
        sqlite3_create_function_v2(db, "apaz_counter_sum", 1, SQLITE_UTF8, NULL, NULL,
                                   sum_step, sum_finish, NULL) == SQLITE_OK &&
        sqlite3_create_function_v2(db, "apaz_counter_add", 2, SQLITE_UTF8, NULL, sql_add_counter,
                                   NULL, NULL, NULL) == SQLITE_OK &&
        sqlite3_busy_timeout(db, 50) == SQLITE_OK && run(schema) &&
        run(complete_schema) &&
        prepare(&latest, "SELECT (SELECT max(ts) FROM observation),"
                         "(SELECT max(ts) FROM legacy_observation),"
                         "(SELECT max(ts) FROM legacy_observation WHERE rx IS NOT NULL)") &&
        sqlite3_step(latest) == SQLITE_ROW;
    if (ok) {
        last_sample = sqlite3_column_int64(latest, 0);
        last_legacy_sample = sqlite3_column_int64(latest, 1);
        last_legacy_traffic = sqlite3_column_int64(latest, 2);
    }
    sqlite3_finalize(latest);
    if (!ok)
        panel_history_close();
    return ok;
}

static bool parse_counter(const char *str, int64_t *value)
{
    if (!str || !*str || str[strspn(str, "0123456789")])
        return false;
    errno = 0;
    uintmax_t number = strtoumax(str, NULL, 10);
    if (errno || number > INT64_MAX)
        return false;
    *value = (int64_t)number;
    return true;
}

struct counter_writer {
    sqlite3_stmt *previous;
    sqlite3_stmt *store;
    sqlite3_stmt *client;
    EVP_MD_CTX *digest;
    int64_t ts;
};

struct snapshot_result {
    struct counter_writer *writer;
    const char *source;
    int64_t rx;
    int64_t tx;
    size_t seen;
    int64_t connected;
    bool wireguard;
    bool failed;
    bool incomplete;
};

static bool counter_identity(const struct snapshot_result *snapshot, const struct vpn_counter *row,
                             unsigned char output[EVP_MAX_MD_SIZE], unsigned int *length)
{
    EVP_MD_CTX *ctx = snapshot->writer->digest;
    const char *protocol = snapshot->wireguard ? "wireguard" : "openvpn";
    const char *parts[] = { protocol, snapshot->source, row->name, row->remote,
                            snapshot->wireguard ? NULL : row->virtual_ip,
                            snapshot->wireguard ? NULL : row->since };
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
        return false;
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); ++i) {
        const char *part = parts[i] ? parts[i] : "";
        if (EVP_DigestUpdate(ctx, part, strlen(part) + 1) != 1)
            return false;
    }
    return EVP_DigestFinal_ex(ctx, output, length) == 1;
}

static bool write_client_traffic(struct snapshot_result *snapshot, const struct vpn_counter *row,
                                 int64_t rx, int64_t tx)
{
    if (!rx && !tx)
        return true;
    const char *name = row->name;
    char wireguard_name[PANEL_HISTORY_CLIENT_MAX + 1];
    if (snapshot->wireguard) {
        int length = snprintf(wireguard_name, sizeof(wireguard_name), "%s · %s", row->remote, name);
        if (length < 0 || (size_t)length >= sizeof(wireguard_name))
            return false;
        name = wireguard_name;
    }
    if (strlen(name) > PANEL_HISTORY_CLIENT_MAX)
        return true;
    struct counter_writer *writer = snapshot->writer;
    sqlite3_stmt *statement = writer->client;
    int64_t hour = writer->ts - writer->ts % CLIENT_BUCKET_SECONDS;
    bool ok = sqlite3_bind_int64(statement, 1, hour) == SQLITE_OK &&
        sqlite3_bind_text(statement, 2, name, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int64(statement, 3, rx) == SQLITE_OK &&
        sqlite3_bind_int64(statement, 4, tx) == SQLITE_OK && sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_reset(statement);
    return ok;
}

static bool write_counter(struct snapshot_result *snapshot, const struct vpn_counter *row,
                          int64_t rx, int64_t tx)
{
    unsigned char identity[EVP_MAX_MD_SIZE];
    unsigned int length;
    if (!counter_identity(snapshot, row, identity, &length))
        return false;

    struct counter_writer *writer = snapshot->writer;
    sqlite3_stmt *previous = writer->previous;
    int state = sqlite3_bind_blob(previous, 1, identity, (int)length, SQLITE_TRANSIENT);
    if (state == SQLITE_OK)
        state = sqlite3_step(previous);
    if (state != SQLITE_DONE && state != SQLITE_ROW) {
        sqlite3_reset(previous);
        return false;
    }
    int64_t prior_ts = 0, prior_rx = 0, prior_tx = 0;
    if (state == SQLITE_ROW) {
        prior_ts = sqlite3_column_int64(previous, 0);
        prior_rx = sqlite3_column_int64(previous, 1);
        prior_tx = sqlite3_column_int64(previous, 2);
    }
    sqlite3_reset(previous);
    if (prior_ts == writer->ts)
        return true;
    if (prior_ts >= writer->ts - 1800 && prior_rx == rx && prior_tx == tx && state == SQLITE_ROW)
        return true;

    sqlite3_stmt *store = writer->store;
    bool ok = sqlite3_bind_blob(store, 1, identity, (int)length, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int64(store, 2, writer->ts) == SQLITE_OK &&
        sqlite3_bind_int64(store, 3, rx) == SQLITE_OK &&
        sqlite3_bind_int64(store, 4, tx) == SQLITE_OK && sqlite3_step(store) == SQLITE_DONE;
    sqlite3_reset(store);
    if (!ok)
        return false;

    /* Existing peers and sessions seen during legacy monitoring start at a native baseline. */
    int64_t began;
    bool new_openvpn_session = !snapshot->wireguard &&
        (!last_legacy_traffic || (parse_counter(row->since, &began) &&
            began > last_legacy_traffic && began - last_legacy_traffic >= SAMPLE_SECONDS));
    if (state == SQLITE_ROW || new_openvpn_session) {
        int64_t delta_rx = rx >= prior_rx ? rx - prior_rx : rx;
        int64_t delta_tx = tx >= prior_tx ? tx - prior_tx : tx;
        snapshot->rx = add_counter(snapshot->rx, delta_rx);
        snapshot->tx = add_counter(snapshot->tx, delta_tx);
        return write_client_traffic(snapshot, row, delta_rx, delta_tx);
    }
    return true;
}

static bool record_counter(const struct vpn_counter *row, void *context)
{
    struct snapshot_result *snapshot = context;
    if (row->name && row->connected)
        ++snapshot->connected;
    if (++snapshot->seen > MAX_COUNTERS_PER_SNAPSHOT) {
        snapshot->incomplete = true;
        return true;
    }

    int64_t rx, tx;
    if (!row->name || !parse_counter(row->rx, &rx) || !parse_counter(row->tx, &tx)) {
        snapshot->incomplete = true;
        return true;
    }
    snapshot->failed = !write_counter(snapshot, row, rx, tx);
    return !snapshot->failed;
}

static bool collect_vpn(struct snapshot_result *result, bool *available, int64_t now)
{
    if (!run("SAVEPOINT vpn_source"))
        return false;
    bool complete = result->wireguard
        ? wireguard_status_counters(result->source, now, record_counter, result)
        : vpn_status_counters(result->source, record_counter, result);
    if (!complete && !run("ROLLBACK TO vpn_source"))
        return false;
    *available = complete;
    return run("RELEASE vpn_source") && !result->failed;
}

struct vpn_observation {
    int64_t openvpn;
    int64_t wireguard;
    int64_t rx;
    int64_t tx;
    bool have_openvpn;
    bool have_wireguard;
    bool have_traffic;
    bool incomplete;
};

static bool collect_openvpn(struct counter_writer *writer, struct vpn_observation *vpn,
                            const char *const *paths, size_t count, int64_t now)
{
    for (size_t i = 0; i < count; ++i) {
        if (!paths[i])
            continue;
        /* Repeated status arguments refer to the same connections and counters. */
        size_t first = 0;
        while (first < i && (!paths[first] || strcmp(paths[first], paths[i])))
            ++first;
        if (first != i)
            continue;

        struct snapshot_result snapshot = { .writer = writer, .source = paths[i] };
        bool complete;
        if (!collect_vpn(&snapshot, &complete, now))
            return false;
        vpn->incomplete |= !complete || snapshot.incomplete;
        if (complete) {
            vpn->have_openvpn = true;
            vpn->openvpn += snapshot.connected;
            vpn->have_traffic = true;
            vpn->rx = add_counter(vpn->rx, snapshot.rx);
            vpn->tx = add_counter(vpn->tx, snapshot.tx);
        }
    }
    return true;
}

static bool collect_wireguard(struct counter_writer *writer, struct vpn_observation *vpn,
                              const char *path, int64_t now)
{
    if (!path)
        return true;
    struct snapshot_result snapshot = { .writer = writer, .source = path, .wireguard = true };
    if (!collect_vpn(&snapshot, &vpn->have_wireguard, now))
        return false;
    vpn->incomplete |= !vpn->have_wireguard || snapshot.incomplete;
    if (vpn->have_wireguard) {
        vpn->wireguard = snapshot.connected;
        vpn->have_traffic = true;
        vpn->rx = add_counter(vpn->rx, snapshot.rx);
        vpn->tx = add_counter(vpn->tx, snapshot.tx);
    }
    return true;
}

static bool bind_optional(sqlite3_stmt *statement, int field, int64_t value, bool present)
{
    int state = present ? sqlite3_bind_int64(statement, field, value) : sqlite3_bind_null(statement, field);
    return state == SQLITE_OK;
}

static bool bind_metric(sqlite3_stmt *statement, int field, struct host_metric metric)
{
    bool present = metric.present && metric.value <= INT64_MAX;
    return bind_optional(statement, field, present ? (int64_t)metric.value : 0, present);
}

static bool store_observation(int64_t ts, const struct host_resources *host,
                              const struct vpn_observation *vpn)
{
    sqlite3_stmt *statement = NULL;
    bool ok = prepare(&statement, "INSERT INTO observation VALUES(?,?,?,?,?,?,?,?,?,?,?)") &&
        sqlite3_bind_int64(statement, 1, ts) == SQLITE_OK &&
        bind_metric(statement, 2, host->cpu_tenths) &&
        bind_metric(statement, 3, host->memory_used) &&
        bind_metric(statement, 4, host->memory_total) &&
        bind_metric(statement, 5, host->disk_used) &&
        bind_metric(statement, 6, host->disk_total) &&
        bind_optional(statement, 7, vpn->openvpn, vpn->have_openvpn) &&
        bind_optional(statement, 8, vpn->wireguard, vpn->have_wireguard) &&
        bind_optional(statement, 9, vpn->rx, vpn->have_traffic) &&
        bind_optional(statement, 10, vpn->tx, vpn->have_traffic) &&
        sqlite3_bind_int(statement, 11, vpn->have_traffic && !vpn->incomplete) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    return ok;
}

static bool prune(const char *sql, int64_t cutoff)
{
    sqlite3_stmt *statement = NULL;
    bool ok = prepare(&statement, sql) && sqlite3_bind_int64(statement, 1, cutoff) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    return ok;
}

bool panel_history_sample(const char *data_dir, const char *const *openvpn_paths,
                          size_t openvpn_count, const char *wireguard_path, int64_t now)
{
    if (!db || !data_dir || now < SAMPLE_SECONDS || (openvpn_count && !openvpn_paths))
        return false;
    int64_t ts = now - now % SAMPLE_SECONDS;
    if (ts <= last_sample || ts <= last_legacy_sample)
        return true;

    struct host_resources host;
    struct vpn_observation vpn = {0};
    struct counter_writer writer = { .ts = ts, .digest = EVP_MD_CTX_new() };
    host_metrics_resources(data_dir, &host);
    int64_t cutoff = ts - RETENTION_DAYS * DAY_SECONDS;
    bool new_hour = ts / CLIENT_BUCKET_SECONDS != last_sample / CLIENT_BUCKET_SECONDS;
    bool ok = writer.digest && run("BEGIN IMMEDIATE") &&
        prepare(&writer.previous, "SELECT last_seen,rx,tx FROM peer_counter WHERE identity=?") &&
        prepare(&writer.store, "INSERT INTO peer_counter VALUES(?,?,?,?) ON CONFLICT(identity) "
                "DO UPDATE SET last_seen=excluded.last_seen,rx=excluded.rx,tx=excluded.tx") &&
        prepare(&writer.client, "INSERT INTO client_traffic VALUES(?,?,?,?) ON CONFLICT(ts,client) "
                "DO UPDATE SET rx=apaz_counter_add(client_traffic.rx,excluded.rx),"
                "tx=apaz_counter_add(client_traffic.tx,excluded.tx)") &&
        collect_openvpn(&writer, &vpn, openvpn_paths, openvpn_count, now) &&
        collect_wireguard(&writer, &vpn, wireguard_path, now) &&
        store_observation(ts, &host, &vpn) &&
        prune("DELETE FROM observation WHERE ts<?", cutoff) &&
        prune("DELETE FROM audit_event WHERE ts<?", cutoff) &&
        prune("DELETE FROM peer_counter WHERE last_seen<?", cutoff) &&
        prune("DELETE FROM legacy_observation WHERE ts<?", cutoff) &&
        prune("DELETE FROM legacy_audit_event WHERE ts<?", cutoff) &&
        run("DELETE FROM peer_counter WHERE identity IN (SELECT identity FROM peer_counter "
            "ORDER BY last_seen DESC,identity DESC LIMIT -1 OFFSET 32768)") &&
        (!new_hour || (prune("DELETE FROM client_traffic WHERE ts<?", cutoff - cutoff % CLIENT_BUCKET_SECONDS) &&
            prune("DELETE FROM legacy_client_traffic WHERE ts<?", cutoff - cutoff % CLIENT_BUCKET_SECONDS) &&
            run("DELETE FROM client_traffic WHERE (ts,client)<=("
                "SELECT ts,client FROM client_traffic ORDER BY ts DESC,client DESC LIMIT 1 OFFSET 200000)"))) &&
        run("COMMIT");
    sqlite3_finalize(writer.previous);
    sqlite3_finalize(writer.store);
    sqlite3_finalize(writer.client);
    EVP_MD_CTX_free(writer.digest);
    if (ok)
        last_sample = ts;
    else
        run("ROLLBACK");
    return ok;
}

bool panel_history_audit(int64_t now, int64_t actor_id, enum panel_history_action action, bool success)
{
    if (!db || now < 0 || (unsigned int)action >= sizeof(action_names) / sizeof(action_names[0]))
        return false;

    sqlite3_stmt *insert = NULL;
    bool ok = run("BEGIN IMMEDIATE") &&
        prepare(&insert, "INSERT INTO audit_event (ts,actor,action,success) VALUES(?,?,?,?)") &&
        sqlite3_bind_int64(insert, 1, now) == SQLITE_OK &&
        bind_optional(insert, 2, actor_id, actor_id > 0) &&
        sqlite3_bind_int(insert, 3, action) == SQLITE_OK &&
        sqlite3_bind_int(insert, 4, success) == SQLITE_OK && sqlite3_step(insert) == SQLITE_DONE;
    sqlite3_finalize(insert);
    if (ok)
        ok = prune("DELETE FROM audit_event WHERE id<=?", sqlite3_last_insert_rowid(db) - 4096) &&
            run("COMMIT");
    if (!ok)
        run("ROLLBACK");
    return ok;
}

struct json_buffer {
    char *out;
    size_t capacity;
    size_t used;
    bool failed;
};

static void json_append(struct json_buffer *json, const char *format, ...)
{
    if (json->failed)
        return;
    va_list args;
    va_start(args, format);
    size_t remaining = json->capacity - json->used;
    int length = vsnprintf(json->out + json->used, remaining, format, args);
    va_end(args);
    if (length < 0 || (size_t)length >= remaining)
        json->failed = true;
    else
        json->used += (size_t)length;
}

static void json_column(struct json_buffer *json, sqlite3_stmt *row, int column, const char *key)
{
    if (sqlite3_column_type(row, column) == SQLITE_NULL)
        json_append(json, ",\"%s\":null", key);
    else
        json_append(json, ",\"%s\":%" PRId64, key, (int64_t)sqlite3_column_int64(row, column));
}

static void json_resources(struct json_buffer *json, sqlite3_stmt *row)
{
    if (sqlite3_column_type(row, 2) == SQLITE_NULL) {
        json_append(json, ",\"cpu_percent\":null");
    } else {
        int cpu = sqlite3_column_int(row, 2);
        json_append(json, ",\"cpu_percent\":%d.%d", cpu / 10, cpu % 10);
    }
    json_column(json, row, 3, "memory_used_bytes");
    json_column(json, row, 4, "memory_total_bytes");
    json_column(json, row, 5, "disk_used_bytes");
    json_column(json, row, 6, "disk_total_bytes");
    if (sqlite3_column_type(row, 7) == SQLITE_NULL) {
        json_append(json, ",\"disk_percent\":null");
    } else {
        int disk = sqlite3_column_int(row, 7);
        json_append(json, ",\"disk_percent\":%d.%d", disk / 10, disk % 10);
    }
}

static void json_connections(struct json_buffer *json, sqlite3_stmt *row)
{
    json_column(json, row, 2, "openvpn");
    json_column(json, row, 3, "wireguard");
    json_column(json, row, 4, "total");
    json_column(json, row, 5, "amneziawg2");
}

static void json_traffic(struct json_buffer *json, sqlite3_stmt *row)
{
    json_column(json, row, 2, "rx_bytes");
    json_column(json, row, 3, "tx_bytes");
    json_append(json, ",\"complete\":%s", sqlite3_column_int(row, 4) ? "true" : "false");
}

static void json_audit(struct json_buffer *json, sqlite3_stmt *row)
{
    json_column(json, row, 2, "actor_id");
    if (sqlite3_column_type(row, 5) == SQLITE_TEXT) {
        const char *name = (const char *)sqlite3_column_text(row, 5);
        size_t length = (size_t)sqlite3_column_bytes(row, 5);
        json_append(json, ",\"action\":\"%s\"", audit_action_name(name, length) ? name : "unknown");
    } else {
        unsigned int action = (unsigned int)sqlite3_column_int(row, 3);
        const char *name = action < sizeof(action_names) / sizeof(action_names[0]) ? action_names[action] : "unknown";
        json_append(json, ",\"action\":\"%s\"", name);
    }
    if (sqlite3_column_type(row, 4) == SQLITE_NULL)
        json_append(json, ",\"success\":null");
    else
        json_append(json, ",\"success\":%s", sqlite3_column_int(row, 4) ? "true" : "false");
}

struct query {
    const char *sql;
    void (*write)(struct json_buffer *, sqlite3_stmt *);
};

static const struct query queries[] = {
    [PANEL_HISTORY_RESOURCES] = {
        "SELECT min(ts),count(*),CAST(avg(cpu)+0.5 AS INTEGER),CAST(avg(mem_used) AS INTEGER),"
        "CAST(avg(mem_total) AS INTEGER),CAST(avg(disk_used) AS INTEGER),CAST(avg(disk_total) AS INTEGER),"
        "CAST(avg(disk_percent)+0.5 AS INTEGER) "
        "FROM history_series WHERE ts>=?1 AND ts<=?2",
        json_resources
    },
    [PANEL_HISTORY_CONNECTIONS] = {
        "SELECT min(ts),count(*),CAST(avg(openvpn)+0.5 AS INTEGER),CAST(avg(wireguard)+0.5 AS INTEGER),"
        "CAST(avg(CASE WHEN openvpn IS NULL AND wireguard IS NULL AND amneziawg2 IS NULL THEN NULL "
        "ELSE coalesce(openvpn,0)+coalesce(wireguard,0)+coalesce(amneziawg2,0) END)+0.5 AS INTEGER),"
        "CAST(avg(amneziawg2)+0.5 AS INTEGER) FROM history_series WHERE ts>=?1 AND ts<=?2",
        json_connections
    },
    [PANEL_HISTORY_TRAFFIC] = {
        "SELECT min(ts),count(*),apaz_counter_sum(rx),apaz_counter_sum(tx),min(traffic_complete) "
        "FROM history_series WHERE ts>=?1 AND ts<=?2",
        json_traffic
    },
    [PANEL_HISTORY_AUDIT] = {
        "SELECT ts,1,actor,action,success,legacy_name,id FROM ("
        "SELECT ts,actor,action,success,NULL legacy_name,id FROM audit_event "
        "WHERE ts>=?1 AND ts<=?2 UNION ALL "
        "SELECT ts,actor,NULL,success,action,id FROM legacy_audit_event WHERE ts>=?1 AND ts<=?2"
        ") ORDER BY ts DESC,id DESC LIMIT ?3",
        json_audit
    }
};

static const struct query client_query = {
    "WITH t AS (SELECT apaz_counter_sum(rx) rx,apaz_counter_sum(tx) tx FROM ("
    "SELECT rx,tx FROM client_traffic WHERE client=?3 AND ts>=?4 AND ts<=?2 UNION ALL "
    "SELECT rx,tx FROM legacy_client_traffic WHERE client=?3 AND ts>=?4 AND ts<=?2)) "
    "SELECT min(o.ts),count(o.ts),"
    "CASE WHEN count(o.rx)>0 THEN coalesce((SELECT rx FROM t),0) END,"
    "CASE WHEN count(o.tx)>0 THEN coalesce((SELECT tx FROM t),0) END,min(o.traffic_complete) "
    "FROM history_series o WHERE o.ts>=?1 AND o.ts<=?2 AND ("
    "EXISTS (SELECT 1 FROM client_traffic WHERE client=?3) OR "
    "EXISTS (SELECT 1 FROM legacy_client_traffic WHERE client=?3))",
    json_traffic
};

static void json_point(const struct query *query, struct json_buffer *json,
                       sqlite3_stmt *statement, int64_t *samples)
{
    int64_t rows = sqlite3_column_int64(statement, 1);
    if (!rows)
        return;
    json_append(json, "%s{\"timestamp\":%" PRId64, *samples ? "," : "",
                (int64_t)sqlite3_column_int64(statement, 0));
    query->write(json, statement);
    json_append(json, "}");
    *samples += rows;
}

static bool json_buckets(const struct query *query, struct json_buffer *json, sqlite3_stmt *statement,
                         int64_t start, int64_t end, int bucket, const char *client, int64_t *samples)
{
    for (;;) {
        int64_t left = bucket - 1 - start % bucket;
        int64_t stop = end - start < left ? end : start + left;
        bool ok = sqlite3_bind_int64(statement, 1, start) == SQLITE_OK &&
            sqlite3_bind_int64(statement, 2, stop) == SQLITE_OK && (!client ||
            sqlite3_bind_int64(statement, 4, start) == SQLITE_OK) &&
            sqlite3_step(statement) == SQLITE_ROW;
        if (ok)
            json_point(query, json, statement, samples);
        sqlite3_reset(statement);
        if (!ok || json->failed)
            return false;
        if (stop == end)
            return true;
        start = stop + 1;
    }
}

static bool json_audit_range(const struct query *query, struct json_buffer *json, sqlite3_stmt *statement,
                             int64_t start, int64_t now, int64_t *samples)
{
    if (sqlite3_bind_int64(statement, 1, start) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 2, now) != SQLITE_OK ||
        sqlite3_bind_int(statement, 3, MAX_AUDIT_RESULTS) != SQLITE_OK)
        return false;
    int state;
    while (!json->failed && (state = sqlite3_step(statement)) == SQLITE_ROW)
        json_point(query, json, statement, samples);
    return !json->failed && state == SQLITE_DONE;
}

static size_t history_json(char *out, size_t capacity, enum panel_history_kind kind,
                           const char *client, unsigned int days, int64_t now)
{
    if (!out || !capacity)
        return 0;
    out[0] = '\0';
    if (!db || now < 0 || (days != 1 && days != 7 && days != 30) ||
        (unsigned int)kind >= sizeof(queries) / sizeof(queries[0]))
        return 0;
    const struct query *query = client ? &client_query : &queries[kind];
    int64_t range = (int64_t)days * DAY_SECONDS;
    /* Fixed UTC buckets keep chart positions and response size stable. */
    int bucket = days == 1 ? (client ? CLIENT_BUCKET_SECONDS : kind == PANEL_HISTORY_RESOURCES ? 720 : 600) :
        days == 7 ? 7200 : 21600;
    sqlite3_stmt *statement = NULL;
    int64_t start = now >= range ? now - range + 1 : 0;
    if (client && start % CLIENT_BUCKET_SECONDS)
        start += CLIENT_BUCKET_SECONDS - start % CLIENT_BUCKET_SECONDS;
    struct json_buffer json = { .out = out, .capacity = capacity };
    json_append(&json, "{\"days\":%u,\"from\":%" PRId64 ",\"through\":%" PRId64 ",\"points\":[",
                days, start, now);
    int64_t samples = 0;
    bool ok = prepare(&statement, query->sql) &&
        (!client || sqlite3_bind_text(statement, 3, client, -1, SQLITE_TRANSIENT) == SQLITE_OK) &&
        (kind == PANEL_HISTORY_AUDIT ? json_audit_range(query, &json, statement, start, now, &samples)
                                   : json_buckets(query, &json, statement, start, now, bucket, client, &samples));
    sqlite3_finalize(statement);
    json_append(&json, "],\"sample_count\":%" PRId64 "}", samples);
    if (!ok || json.failed) {
        out[0] = '\0';
        return 0;
    }
    return json.used;
}

size_t panel_history_json(char *out, size_t capacity, enum panel_history_kind kind,
                          unsigned int days, int64_t now)
{
    return history_json(out, capacity, kind, NULL, days, now);
}

size_t panel_history_client_json(char *out, size_t capacity, const char *client,
                                 unsigned int days, int64_t now)
{
    if (!client || !*client || strlen(client) > PANEL_HISTORY_CLIENT_MAX) {
        if (out && capacity)
            out[0] = '\0';
        return 0;
    }
    return history_json(out, capacity, PANEL_HISTORY_TRAFFIC, client, days, now);
}

#ifdef PANEL_HISTORY_MIGRATION
#include "panel_history_migration.inc"
#endif
