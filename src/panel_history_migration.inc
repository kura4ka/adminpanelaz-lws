#include <math.h>

struct migration {
    sqlite3 *source;
    int64_t node_id;
    int64_t start;
    int64_t end;
};

static bool legacy_prepare(const struct migration *migration, sqlite3_stmt **statement, const char *sql)
{
    return sqlite3_prepare_v3(migration->source, sql, -1, SQLITE_PREPARE_NO_VTAB, statement, NULL) == SQLITE_OK;
}

static bool source_local_node(const struct migration *migration)
{
    sqlite3_stmt *statement = NULL;
    bool ok = legacy_prepare(migration, &statement,
        "SELECT 1 FROM nodes WHERE id=? AND is_local=1 AND node_kind='vpn'") &&
        sqlite3_bind_int64(statement, 1, migration->node_id) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_ROW && sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    return ok;
}

static bool source_tables(const struct migration *migration)
{
    sqlite3_stmt *statement = NULL;
    bool ok = legacy_prepare(migration, &statement, "SELECT count(*) FROM sqlite_schema WHERE "
        "type='table' AND name IN ('nodes','node_resource_sample','connection_count_samples',"
        "'user_traffic_sample','user_action_logs')") &&
        sqlite3_step(statement) == SQLITE_ROW && sqlite3_column_int(statement, 0) == 5;
    sqlite3_finalize(statement);
    return ok;
}

static bool legacy_marker(int64_t node_id)
{
    sqlite3_stmt *statement = NULL;
    bool ok = run("CREATE TABLE IF NOT EXISTS legacy_history_import ("
                  "singleton INTEGER PRIMARY KEY CHECK(singleton=1),node_id INTEGER NOT NULL)") &&
        prepare(&statement, "INSERT INTO legacy_history_import VALUES(1,?) "
                            "ON CONFLICT(singleton) DO UPDATE SET node_id=excluded.node_id "
                            "WHERE legacy_history_import.node_id=excluded.node_id") &&
        sqlite3_bind_int64(statement, 1, node_id) == SQLITE_OK &&
        sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(db) == 1;
    sqlite3_finalize(statement);
    return ok;
}

static bool nonnegative(sqlite3_stmt *row, int column, int64_t maximum, bool optional,
                        int64_t *result)
{
    int type = sqlite3_column_type(row, column);
    *result = 0;
    if (type == SQLITE_NULL)
        return optional;
    if (type != SQLITE_INTEGER)
        return false;
    int64_t value = sqlite3_column_int64(row, column);
    if (value < 0 || value > maximum)
        return false;
    *result = value;
    return true;
}

static bool bind_legacy_int(sqlite3_stmt *output, int target, sqlite3_stmt *input, int column,
                            int64_t multiplier, int64_t maximum)
{
    int64_t value;
    return nonnegative(input, column, maximum, true, &value) &&
        bind_optional(output, target, value * multiplier, sqlite3_column_type(input, column) != SQLITE_NULL);
}

static bool bind_legacy_percent(sqlite3_stmt *output, int target, sqlite3_stmt *input, int column)
{
    int type = sqlite3_column_type(input, column);
    if (type == SQLITE_NULL)
        return bind_optional(output, target, 0, false);
    if (type != SQLITE_INTEGER && type != SQLITE_FLOAT)
        return false;
    double value = sqlite3_column_double(input, column);
    return isfinite(value) && value >= 0 && value <= 100 &&
        bind_optional(output, target, (int64_t)(value * 10 + 0.5), true);
}

static bool timestamp(sqlite3_stmt *row, int64_t *ts)
{
    return nonnegative(row, 0, INT64_MAX, false, ts) && *ts > 0;
}

static bool legacy_text(sqlite3_stmt *row, int column, int maximum, const char **result)
{
    if (sqlite3_column_type(row, column) != SQLITE_TEXT)
        return false;
    const char *value = (const char *)sqlite3_column_text(row, column);
    int bytes = sqlite3_column_bytes(row, column);
    if (!value || bytes < 1 || bytes > maximum || strlen(value) != (size_t)bytes)
        return false;
    *result = value;
    return true;
}

static bool resource_row(sqlite3_stmt *input, sqlite3_stmt *output, sqlite3_stmt *unused)
{
    (void)unused;
    int64_t ts;
    static const int64_t mib = INT64_C(1048576);
    return timestamp(input, &ts) &&
        sqlite3_bind_int64(output, 1, ts - ts % SAMPLE_SECONDS) == SQLITE_OK &&
        bind_legacy_percent(output, 2, input, 1) &&
        bind_legacy_int(output, 3, input, 2, mib, INT64_MAX / mib) &&
        bind_legacy_int(output, 4, input, 3, mib, INT64_MAX / mib) &&
        bind_legacy_percent(output, 5, input, 4) && sqlite3_step(output) == SQLITE_DONE;
}

static bool connection_row(sqlite3_stmt *input, sqlite3_stmt *output, sqlite3_stmt *unused)
{
    (void)unused;
    int64_t ts;
    return timestamp(input, &ts) &&
        sqlite3_bind_int64(output, 1, ts - ts % SAMPLE_SECONDS) == SQLITE_OK &&
        bind_legacy_int(output, 2, input, 1, 1, INT32_MAX) &&
        bind_legacy_int(output, 3, input, 2, 1, INT32_MAX) &&
        bind_legacy_int(output, 4, input, 3, 1, INT32_MAX) && sqlite3_step(output) == SQLITE_DONE;
}

static bool traffic_row(sqlite3_stmt *input, sqlite3_stmt *output, sqlite3_stmt *client_output)
{
    int64_t ts, rx, tx;
    const char *client;
    return timestamp(input, &ts) && legacy_text(input, 1, PANEL_HISTORY_CLIENT_MAX, &client) &&
        nonnegative(input, 2, INT64_MAX, false, &rx) && nonnegative(input, 3, INT64_MAX, false, &tx) &&
        sqlite3_bind_int64(output, 1, ts - ts % SAMPLE_SECONDS) == SQLITE_OK &&
        sqlite3_bind_int64(output, 2, rx) == SQLITE_OK && sqlite3_bind_int64(output, 3, tx) == SQLITE_OK &&
        sqlite3_step(output) == SQLITE_DONE &&
        sqlite3_bind_int64(client_output, 1, ts - ts % CLIENT_BUCKET_SECONDS) == SQLITE_OK &&
        sqlite3_bind_text(client_output, 2, client, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
        sqlite3_bind_int64(client_output, 3, rx) == SQLITE_OK &&
        sqlite3_bind_int64(client_output, 4, tx) == SQLITE_OK && sqlite3_step(client_output) == SQLITE_DONE;
}

static bool ends_with(const char *text, const char *suffix)
{
    size_t n = strlen(text), length = strlen(suffix);
    return n >= length && strcmp(text + n - length, suffix) == 0;
}

static bool audit_row(sqlite3_stmt *input, sqlite3_stmt *output, sqlite3_stmt *unused)
{
    (void)unused;
    int64_t ts, id;
    const char *action;
    if (!timestamp(input, &ts) || !nonnegative(input, 1, INT64_MAX, false, &id) || !id ||
        !legacy_text(input, 3, 64, &action) || !audit_action_name(action, strlen(action)))
        return false;
    bool success = ends_with(action, "_success");
    bool failed = ends_with(action, "_failed");
    return sqlite3_bind_int64(output, 1, id) == SQLITE_OK &&
        sqlite3_bind_int64(output, 2, ts) == SQLITE_OK && bind_legacy_int(output, 3, input, 2, 1, INT64_MAX) &&
        sqlite3_bind_text(output, 4, action, -1, SQLITE_TRANSIENT) == SQLITE_OK &&
        bind_optional(output, 5, success, success || failed) && sqlite3_step(output) == SQLITE_DONE;
}

struct import_table {
    const char *query;
    const char *insert;
    const char *insert_client;
    bool use_node;
    bool (*copy)(sqlite3_stmt *, sqlite3_stmt *, sqlite3_stmt *);
};

/* The pinned source stores naive UTC datetimes as ISO text, with optional fractions. */
#define LEGACY_TS "unixepoch(created_at)"
#define LEGACY_RANGE "(" LEGACY_TS " BETWEEN ?2 AND ?3 OR " LEGACY_TS " IS NULL)"

static const struct import_table resources = {
    "SELECT " LEGACY_TS " AS ts,cpu_percent,memory_used_mb,memory_total_mb,disk_percent "
    "FROM node_resource_sample WHERE node_id=?1 AND " LEGACY_RANGE " ORDER BY ts,id",
    "INSERT INTO legacy_observation(ts,cpu,mem_used,mem_total,disk_percent) VALUES(?,?,?,?,?) "
    "ON CONFLICT(ts) DO UPDATE SET cpu=excluded.cpu,mem_used=excluded.mem_used,"
    "mem_total=excluded.mem_total,disk_percent=excluded.disk_percent",
    NULL, true, resource_row
};

static const struct import_table connections = {
    "SELECT " LEGACY_TS " AS ts,openvpn_count,wireguard_count,amneziawg2_count "
    "FROM connection_count_samples WHERE node_id=?1 AND " LEGACY_RANGE " ORDER BY ts,id",
    "INSERT INTO legacy_observation(ts,openvpn,wireguard,amneziawg2) VALUES(?,?,?,?) "
    "ON CONFLICT(ts) DO UPDATE SET openvpn=excluded.openvpn,wireguard=excluded.wireguard,"
    "amneziawg2=excluded.amneziawg2",
    NULL, true, connection_row
};

static const struct import_table traffic = {
    "SELECT " LEGACY_TS ",common_name,delta_received,delta_sent FROM user_traffic_sample "
    "WHERE node_id=?1 AND " LEGACY_RANGE,
    "INSERT INTO legacy_observation(ts,rx,tx) VALUES(?,?,?) "
    "ON CONFLICT(ts) DO UPDATE SET rx=apaz_counter_add(legacy_observation.rx,excluded.rx),"
    "tx=apaz_counter_add(legacy_observation.tx,excluded.tx)",
    "INSERT INTO legacy_client_traffic(ts,client,rx,tx) VALUES(?,?,?,?) "
    "ON CONFLICT(client,ts) DO UPDATE SET rx=apaz_counter_add(legacy_client_traffic.rx,excluded.rx),"
    "tx=apaz_counter_add(legacy_client_traffic.tx,excluded.tx)",
    true, traffic_row
};

static const struct import_table audit_log = {
    "SELECT " LEGACY_TS " AS ts,id,user_id,action FROM user_action_logs WHERE " LEGACY_RANGE
    " ORDER BY ts DESC NULLS FIRST,id DESC LIMIT 4096",
    "INSERT INTO legacy_audit_event VALUES(?,?,?,?,?)", NULL, false, audit_row
};

static bool import_rows(const struct migration *migration, const struct import_table *table, size_t *count)
{
    sqlite3_stmt *input = NULL, *output = NULL, *client = NULL;
    bool ok = legacy_prepare(migration, &input, table->query) &&
        (!table->use_node || sqlite3_bind_int64(input, 1, migration->node_id) == SQLITE_OK) &&
        sqlite3_bind_int64(input, 2, migration->start) == SQLITE_OK &&
        sqlite3_bind_int64(input, 3, migration->end) == SQLITE_OK &&
        prepare(&output, table->insert) &&
        (!table->insert_client || prepare(&client, table->insert_client));
    int state = SQLITE_DONE;
    while (ok && (state = sqlite3_step(input)) == SQLITE_ROW) {
        ok = table->copy(input, output, client);
        sqlite3_reset(output);
        if (client)
            sqlite3_reset(client);
        if (ok)
            ++*count;
    }
    sqlite3_finalize(input);
    sqlite3_finalize(output);
    sqlite3_finalize(client);
    return ok && state == SQLITE_DONE;
}

static bool cap_legacy_end(struct migration *migration, const char *sql)
{
    sqlite3_stmt *native = NULL;
    bool ok = prepare(&native, sql) && sqlite3_step(native) == SQLITE_ROW;
    if (ok && sqlite3_column_type(native, 0) == SQLITE_INTEGER) {
        int64_t min = sqlite3_column_int64(native, 0);
        if (min <= migration->end)
            migration->end = min > 0 ? min - 1 : 0;
    }
    sqlite3_finalize(native);
    return ok && migration->end >= migration->start;
}

bool panel_history_import_legacy(const char *source_path, int64_t local_node_id, int64_t now,
                                 struct panel_history_import_count *count)
{
    if (!db || !source_path || !*source_path || local_node_id <= 0 || now <= 0 || !count)
        return false;
    *count = (struct panel_history_import_count){0};
    int64_t range = RETENTION_DAYS * DAY_SECONDS;
    struct migration migration = {
        .node_id = local_node_id, .start = now > range ? now - range : 0, .end = now
    };
    struct migration audit = migration;
    int flags = SQLITE_OPEN_READONLY;
#ifdef SQLITE_OPEN_NOFOLLOW
    flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    bool ok = sqlite3_open_v2(source_path, &migration.source, flags, NULL) == SQLITE_OK &&
        sqlite3_db_config(migration.source, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, NULL) == SQLITE_OK &&
        sqlite3_exec(migration.source, "PRAGMA query_only=ON;BEGIN", NULL, NULL, NULL) == SQLITE_OK &&
        source_tables(&migration) && source_local_node(&migration) &&
        run("BEGIN IMMEDIATE") && legacy_marker(local_node_id) &&
        cap_legacy_end(&migration, "SELECT min(ts) FROM observation") &&
        run("DELETE FROM legacy_observation;DELETE FROM legacy_client_traffic;DELETE FROM legacy_audit_event") &&
        import_rows(&migration, &resources, &count->resources) &&
        import_rows(&migration, &connections, &count->connections) &&
        import_rows(&migration, &traffic, &count->traffic);
    audit.source = migration.source;
    ok = ok && cap_legacy_end(&audit, "SELECT min(ts) FROM audit_event") &&
        import_rows(&audit, &audit_log, &count->audit) &&
        run("DELETE FROM legacy_client_traffic WHERE (ts,client)<=("
            "SELECT ts,client FROM legacy_client_traffic ORDER BY ts DESC,client DESC LIMIT 1 OFFSET 200000)") &&
        run("COMMIT");
    sqlite3_close(migration.source);
    if (!ok) {
        run("ROLLBACK");
        *count = (struct panel_history_import_count){0};
    }
    return ok;
}
