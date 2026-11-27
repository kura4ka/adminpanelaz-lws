#include "panel_portal.h"
#include "panel_profiles.h"

#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <openssl/evp.h>
#include <sqlite3.h>

enum { MAX_TARGET_ROWS = 321, POLICY_SIZE = 2048, APP_LINKS_SIZE = 12288 };
enum { REQUEST_PEERS = 128, REQUEST_LIMIT = 30, REQUEST_WINDOW = 60 };
enum { OPENVPN = 1, WIREGUARD = 2, AMNEZIAWG = 4, AWG2 = 8 };
enum { ROUTE_AZ = 1, ROUTE_VPN = 2 };
enum { GROUP_COMBINED = 1, GROUP_UDP = 2, GROUP_TCP = 4 };

static sqlite3 *db;
static char portal_domain[254];
static struct request_peer {
    char address[64];
    time_t requests[REQUEST_LIMIT];
    time_t seen;
    unsigned int next;
} peers[REQUEST_PEERS];

static const struct protocol {
    unsigned int bit;
    const char *key;
    const char *feature_env;
} protocols[] = {
    {OPENVPN, "openvpn", "FEATURE_OPENVPN_ENABLED"},
    {WIREGUARD, "wireguard", "FEATURE_WIREGUARD_ENABLED"},
    {AMNEZIAWG, "amneziawg", "FEATURE_AMNEZIAWG_ENABLED"},
    {AWG2, "amneziawg2", "FEATURE_AWG2_ENABLED"}
};

static const struct variant {
    unsigned int protocol_index;
    unsigned int route;
    unsigned int group;
    const char *name;
    const char *suffix;
} variants[] = {
    {0, ROUTE_AZ, GROUP_COMBINED, "antizapret", ".ovpn"},
    {0, ROUTE_AZ, GROUP_UDP, "antizapret-udp", "-udp.ovpn"},
    {0, ROUTE_AZ, GROUP_TCP, "antizapret-tcp", "-tcp.ovpn"},
    {0, ROUTE_VPN, GROUP_COMBINED, "vpn", ".ovpn"},
    {0, ROUTE_VPN, GROUP_UDP, "vpn-udp", "-udp.ovpn"},
    {0, ROUTE_VPN, GROUP_TCP, "vpn-tcp", "-tcp.ovpn"},
    {1, ROUTE_AZ, 0, "antizapret", ".conf"},
    {1, ROUTE_VPN, 0, "vpn", ".conf"},
    {2, ROUTE_AZ, 0, "antizapret", ".conf"},
    {2, ROUTE_VPN, 0, "vpn", ".conf"}
};

struct token {
    sqlite3_int64 user;
    sqlite3_int64 node;
    char name[33];
};

struct policy {
    unsigned int protocols;
    unsigned int routes;
    unsigned int groups;
};

struct json {
    char *out;
    size_t capacity;
    size_t length;
    bool failed;
};

struct target {
    sqlite3_int64 node;
    char node_label[513];
    char name[33];
    unsigned int protocols;
    unsigned int files;
    sqlite3_int64 deadline;
    sqlite3_int64 config_deadline;
    sqlite3_int64 owner_deadline;
    sqlite3_int64 traffic;
    sqlite3_int64 traffic_limit;
    bool blocked;
};

static void json_printf(struct json *json, const char *format, ...)
{
    if (json->failed)
        return;
    va_list args;
    va_start(args, format);
    int count = vsnprintf(json->out + json->length, json->capacity - json->length, format, args);
    va_end(args);
    if (count < 0 || (size_t)count >= json->capacity - json->length) {
        json->failed = true;
        return;
    }
    json->length += (size_t)count;
}

static void json_text(struct json *json, const char *text)
{
    if (!text) {
        json_printf(json, "null");
        return;
    }
    json_printf(json, "\"");
    for (const unsigned char *p = (const unsigned char *)text; *p && !json->failed; ++p) {
        if (*p < 32)
            json_printf(json, "\\u%04x", (unsigned int)*p);
        else if (*p == '"' || *p == '\\')
            json_printf(json, "\\%c", *p);
        else
            json_printf(json, "%c", *p);
    }
    json_printf(json, "\"");
}

static char ascii_lower(char ch)
{
    return ch >= 'A' && ch <= 'Z' ? (char)(ch + ('a' - 'A')) : ch;
}

static bool ascii_equal(const char *a, const char *b)
{
    while (*a && ascii_lower(*a) == ascii_lower(*b)) {
        ++a;
        ++b;
    }
    return *a == *b;
}

static bool feature_enabled(const char *env_name)
{
    const char *value = getenv(env_name);
    return !value || !(ascii_equal(value, "0") || ascii_equal(value, "false") ||
                       ascii_equal(value, "no") || ascii_equal(value, "off"));
}

static bool urlsafe(const char *value, size_t max)
{
    if (!value || !*value)
        return false;
    size_t length = strspn(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-");
    return length <= max && value[length] == '\0';
}

bool panel_portal_token_valid(const char *token)
{
    return urlsafe(token, PANEL_PORTAL_TOKEN_MAX);
}

static bool parse_host(const char *host, char name[254])
{
    if (!host)
        return false;
    size_t length = strcspn(host, ":");
    if (!length || length >= 254)
        return false;
    size_t label = 0;
    for (size_t i = 0; i < length; ++i) {
        char ch = ascii_lower(host[i]);
        if (ch == '.') {
            if (!label || name[i - 1] == '-')
                return false;
            label = 0;
        } else if ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || (ch == '-' && label)) {
            if (++label > 63)
                return false;
        } else {
            return false;
        }
        name[i] = ch;
    }
    if (!label || name[length - 1] == '-')
        return false;
    name[length] = '\0';
    if (!host[length])
        return true;
    const char *port = host + length + 1;
    size_t digits = strspn(port, "0123456789");
    if (!digits || digits > 5 || port[digits])
        return false;
    long value = strtol(port, NULL, 10);
    return value >= 1 && value <= 65535;
}

bool panel_portal_host_matches(const char *host)
{
    char name[254];
    return db && parse_host(host, name) && !strcmp(portal_domain, name);
}

bool panel_portal_allow_request(const char *peer_address)
{
    if (!peer_address || !*peer_address || strlen(peer_address) >= sizeof(peers[0].address))
        return false;
    time_t now = time(NULL);
    struct request_peer *unused = NULL;
    for (size_t i = 0; i < REQUEST_PEERS; ++i) {
        struct request_peer *peer = &peers[i];
        if (!peer->address[0] || now < peer->seen || now - peer->seen >= REQUEST_WINDOW) {
            if (!unused)
                unused = peer;
        } else if (!strcmp(peer->address, peer_address)) {
            time_t earliest = peer->requests[peer->next];
            if (earliest && now - earliest < REQUEST_WINDOW)
                return false;
            peer->seen = peer->requests[peer->next] = now;
            peer->next = (peer->next + 1) % REQUEST_LIMIT;
            return true;
        }
    }
    if (!unused)
        return false;
    memset(unused, 0, sizeof(*unused));
    strcpy(unused->address, peer_address);
    unused->seen = unused->requests[0] = now;
    unused->next = 1;
    return true;
}

static const char *column_text(sqlite3_stmt *stmt, int column)
{
    return (const char *)sqlite3_column_text(stmt, column);
}

static bool copy_column(sqlite3_stmt *stmt, int column, char *out, size_t capacity)
{
    const char *value = column_text(stmt, column);
    int bytes = sqlite3_column_bytes(stmt, column);
    if (bytes < 0 || (size_t)bytes >= capacity || (value && (size_t)bytes != strlen(value)))
        return false;
    memcpy(out, value ? value : "", (size_t)bytes + 1);
    return true;
}

static bool read_setting(const char *key, char *out, size_t capacity)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT value FROM app_settings WHERE key=?1", -1, &stmt, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(stmt, 1, key, -1, SQLITE_STATIC);
    out[0] = '\0';
    int result = sqlite3_step(stmt);
    bool ok = result == SQLITE_DONE || (result == SQLITE_ROW && copy_column(stmt, 0, out, capacity));
    sqlite3_finalize(stmt);
    return ok;
}

bool panel_portal_open(const char *path)
{
    panel_portal_close();
    if (!path || !*path)
        return true;
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_PRIVATECACHE, NULL) != SQLITE_OK)
        goto fail;
    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 1024 * 1024);
    sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, NULL);
    if (sqlite3_exec(db, "PRAGMA query_only=ON;PRAGMA cache_size=-128;PRAGMA mmap_size=0;PRAGMA temp_store=FILE;",
                     NULL, NULL, NULL) != SQLITE_OK)
        goto fail;
    char domain[254];
    if (!read_setting("portal_domain", domain, sizeof(domain)) || strchr(domain, ':') ||
        !parse_host(domain, portal_domain) || !strchr(portal_domain, '.'))
        goto fail;
    return true;

fail:
    panel_portal_close();
    return false;
}

void panel_portal_close(void)
{
    if (db)
        sqlite3_close(db);
    db = NULL;
    portal_domain[0] = '\0';
    memset(peers, 0, sizeof(peers));
}

static int ttl_days(void)
{
    char raw[32];
    if (!read_setting("portal_link_ttl_days", raw, sizeof(raw)))
        return -1;
    const char *value = raw[0] ? raw : getenv("PORTAL_LINK_TTL_DAYS");
    if (!value || !*value)
        return 30;
    char *end;
    long days = strtol(value, &end, 10);
    if (end == value || end[strspn(end, " \t\r\n")] || days < 0)
        return 30;
    return days > 3650 ? 3650 : (int)days;
}

static int resolve_token(const char *value, struct token *token)
{
    static const char sql[] =
        "SELECT 0,node_id,client_name,created_at,unixepoch(created_at),1"
        " FROM client_portal_tokens WHERE token=?1 AND revoked_at IS NULL"
        " UNION ALL SELECT t.user_id,0,'',t.created_at,unixepoch(t.created_at),coalesce(u.is_active,0)"
        " FROM user_portal_tokens AS t LEFT JOIN users AS u ON u.id=t.user_id"
        " WHERE t.token=?1 AND t.revoked_at IS NULL";
    if (!panel_portal_token_valid(value))
        return 404;
    int ttl = ttl_days();
    sqlite3_stmt *stmt = NULL;
    if (ttl < 0 || sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return 503;
    sqlite3_bind_text(stmt, 1, value, -1, SQLITE_STATIC);
    int result = sqlite3_step(stmt);
    int status = result == SQLITE_DONE ? 404 : 503;
    if (result == SQLITE_ROW) {
        token->user = sqlite3_column_int64(stmt, 0);
        token->node = sqlite3_column_int64(stmt, 1);
        bool valid = sqlite3_column_int(stmt, 5) == 1 && copy_column(stmt, 2, token->name, sizeof(token->name)) &&
            ((token->user > 0 && !token->node && !token->name[0]) ||
             (!token->user && token->node > 0 && urlsafe(token->name, 32)));
        if (ttl && sqlite3_column_type(stmt, 3) != SQLITE_NULL) {
            sqlite3_int64 created = sqlite3_column_int64(stmt, 4);
            valid = valid && sqlite3_column_type(stmt, 4) != SQLITE_NULL &&
                created + (sqlite3_int64)ttl * 86400 > (sqlite3_int64)time(NULL);
        }
        result = sqlite3_step(stmt);
        status = result == SQLITE_DONE && valid ? 200 :
            result == SQLITE_ROW || result == SQLITE_DONE ? 404 : 503;
    }
    sqlite3_finalize(stmt);
    return status;
}

static int bounded_work(void *context)
{
    unsigned int *remaining = context;
    return !*remaining || !--*remaining;
}

static int begin_read(const char *host, unsigned int *remaining)
{
    if (!panel_portal_host_matches(host))
        return 404;
    if (!feature_enabled("FEATURE_CLIENT_PORTAL_ENABLED"))
        return 403;
    if (sqlite3_exec(db, "BEGIN", NULL, NULL, NULL) != SQLITE_OK)
        return 503;
    *remaining = 250;
    sqlite3_progress_handler(db, 1000, bounded_work, remaining);
    return 200;
}

static void end_read(void)
{
    sqlite3_progress_handler(db, 0, NULL, NULL);
    sqlite3_exec(db, "ROLLBACK", NULL, NULL, NULL);
}

static const char *skip_spaces(const char *raw)
{
    return raw ? raw + strspn(raw, " \t\r\n") : "";
}

static bool visibility_policy(const char *role, const char *raw, const char *fallback, struct policy *policy)
{
    *policy = (struct policy){ OPENVPN | WIREGUARD | AMNEZIAWG | AWG2,
        ROUTE_AZ | ROUTE_VPN, GROUP_COMBINED | GROUP_UDP | GROUP_TCP };
    if (role && !strcmp(role, "admin"))
        return true;
    raw = skip_spaces(raw);
    if (!*raw)
        raw = skip_spaces(fallback);
    if (!*raw)
        return true;
    if (strlen(raw) >= POLICY_SIZE)
        return false;
    static const char sql[] =
        "SELECT axis.key,trim(item.value,' '||char(9,10,13)) FROM json_each(?1) AS axis"
        " JOIN json_each(CASE WHEN axis.type='array' THEN axis.value ELSE '[]' END) AS item WHERE item.type='text'";
    if (*raw != '{')
        return false;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(stmt, 1, raw, -1, SQLITE_STATIC);
    *policy = (struct policy){0};
    int result;
    while ((result = sqlite3_step(stmt)) == SQLITE_ROW) {
        const char *axis = column_text(stmt, 0);
        const char *item = column_text(stmt, 1);
        if (!axis || !item || (size_t)sqlite3_column_bytes(stmt, 0) != strlen(axis) ||
            (size_t)sqlite3_column_bytes(stmt, 1) != strlen(item))
            continue;
        if (!strcmp(axis, "protocols")) {
            for (size_t i = 0; i < sizeof(protocols) / sizeof(protocols[0]); ++i)
                if (ascii_equal(item, protocols[i].key))
                    policy->protocols |= protocols[i].bit;
        } else if (!strcmp(axis, "routes")) {
            if (ascii_equal(item, "az"))
                policy->routes |= ROUTE_AZ;
            if (ascii_equal(item, "vpn"))
                policy->routes |= ROUTE_VPN;
        } else if (!strcmp(axis, "openvpn_groups")) {
            if (ascii_equal(item, "udp_tcp"))
                policy->groups |= GROUP_COMBINED;
            if (ascii_equal(item, "udp"))
                policy->groups |= GROUP_UDP;
            if (ascii_equal(item, "tcp"))
                policy->groups |= GROUP_TCP;
        }
    }
    sqlite3_finalize(stmt);
    return result == SQLITE_DONE;
}

static sqlite3_stmt *target_rows(const struct token *token)
{
    static const char sql[] =
        "WITH targets AS ("
        " SELECT * FROM vpn_configs WHERE ?1=0 AND node_id=?2 AND client_name=?3"
        " UNION ALL SELECT * FROM vpn_configs WHERE ?1>0 AND owner_id=?1)"
        " SELECT c.node_id,coalesce(nullif(trim(n.portal_label),''),n.name),c.client_name,c.vpn_type,"
        " u.role,u.visible_vpn_profiles,unixepoch(u.access_until),unixepoch(c.expires_at),"
        " unixepoch(c.cert_expires_at),"
        " unixepoch(coalesce(o.access_until,w.expires_at,a.access_until)),"
        " (coalesce(o.is_temp_blocked,w.is_temp_blocked,a.is_temp_blocked,0) OR"
        " coalesce(o.is_permanent_blocked,w.is_permanent_blocked,a.is_permanent_blocked,0) OR"
        " coalesce(unixepoch(coalesce(o.block_until,w.block_until,a.block_until))>unixepoch('now'),0)),"
        " coalesce(o.traffic_limit_bytes,w.traffic_limit_bytes,a.traffic_limit_bytes,0),"
        " (SELECT coalesce(total(max(0,coalesce(t.total_received,0))+max(0,coalesce(t.total_sent,0))),0)"
        " FROM user_traffic_stat_protocol AS t WHERE t.node_id=c.node_id AND t.common_name=c.client_name"
        " AND (t.protocol_type=c.vpn_type OR (c.vpn_type='openvpn' AND t.protocol_type IN ('openvpn-udp','openvpn-tcp')))),"
        " (u.suspended_at IS NOT NULL OR coalesce(u.traffic_limit_blocked,0))"
        " FROM targets AS c JOIN nodes AS n ON n.id=c.node_id AND n.is_local=1"
        " JOIN users AS u ON u.id=c.owner_id AND u.is_active=1"
        " LEFT JOIN openvpn_access_policy AS o ON c.vpn_type='openvpn' AND o.node_id=c.node_id AND o.client_name=c.client_name"
        " LEFT JOIN wg_access_policy AS w ON c.vpn_type='wireguard' AND w.node_id=c.node_id AND w.client_name=lower(c.client_name)"
        " LEFT JOIN amneziawg2_access_policies AS a ON c.vpn_type='amneziawg2' AND a.node_id=c.node_id AND a.client_name=lower(c.client_name)"
        " WHERE c.ha_primary_config_id IS NULL AND (?1=0 OR n.status IS NOT 'offline')"
        " AND (SELECT count(*) FROM nodes WHERE is_local=1)=1"
        " AND (c.vpn_type='openvpn' OR NOT EXISTS (SELECT 1 FROM vpn_configs AS other"
        " WHERE other.node_id=c.node_id AND other.vpn_type=c.vpn_type"
        " AND lower(other.client_name)=lower(c.client_name) AND other.client_name<>c.client_name))"
        " ORDER BY c.node_id,c.client_name,c.vpn_type LIMIT ?4";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return NULL;
    sqlite3_bind_int64(stmt, 1, token->user);
    sqlite3_bind_int64(stmt, 2, token->node);
    sqlite3_bind_text(stmt, 3, token->name, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 4, MAX_TARGET_ROWS);
    return stmt;
}

static unsigned int protocol_mask(const char *name)
{
    if (!name)
        return 0;
    if (!strcmp(name, "wireguard"))
        return WIREGUARD | AMNEZIAWG;
    for (size_t i = 0; i < sizeof(protocols) / sizeof(protocols[0]); ++i)
        if (!strcmp(name, protocols[i].key))
            return protocols[i].bit;
    return 0;
}

static sqlite3_int64 earliest(sqlite3_int64 a, sqlite3_int64 b)
{
    if (!a || (b && b < a))
        return b;
    return a;
}

static void add_status(struct target *target, sqlite3_stmt *row)
{
    target->owner_deadline = earliest(target->owner_deadline, sqlite3_column_int64(row, 6));
    target->config_deadline = earliest(target->config_deadline, sqlite3_column_int64(row, 7));
    target->config_deadline = earliest(target->config_deadline, sqlite3_column_int64(row, 8));
    target->deadline = earliest(target->deadline, sqlite3_column_int64(row, 9));
    target->blocked = target->blocked || sqlite3_column_int(row, 10) || sqlite3_column_int(row, 13);
    sqlite3_int64 limit = sqlite3_column_int64(row, 11);
    if (limit > 0)
        target->traffic_limit = earliest(target->traffic_limit, limit);
    double traffic = sqlite3_column_double(row, 12);
    if (traffic >= (double)(INT64_MAX - target->traffic))
        target->traffic = INT64_MAX;
    else if (traffic > 0)
        target->traffic += (sqlite3_int64)traffic;
}

static sqlite3_int64 access_deadline(const struct target *target)
{
    sqlite3_int64 deadline = target->deadline ? target->deadline : target->config_deadline;
    return earliest(deadline, target->owner_deadline);
}

static const char *iso_time(sqlite3_int64 value, char buffer[32])
{
    if (!value)
        return NULL;
    time_t stamp = (time_t)value;
    struct tm *utc = gmtime(&stamp);
    return utc && strftime(buffer, 32, "%Y-%m-%dT%H:%M:%SZ", utc) ? buffer : NULL;
}

static void bytes_label(sqlite3_int64 value, char out[32])
{
    static const char *units[] = {"Б", "КиБ", "МиБ", "ГиБ", "ТиБ", "ПиБ", "ЭиБ"};
    double size = (double)value;
    size_t i = 0;
    while (size >= 1024.0 && i + 1 < sizeof(units) / sizeof(units[0])) {
        size /= 1024.0;
        ++i;
    }
    snprintf(out, 32, i ? "%.1f %s" : "%.0f %s", size, units[i]);
}

static void append_status(struct json *json, const struct target *target)
{
    sqlite3_int64 deadline = access_deadline(target);
    bool expired = deadline && deadline <= (sqlite3_int64)time(NULL);
    json_printf(json, "{\"status\":\"%s\",\"status_label\":", target->blocked ? "blocked" : expired ? "expired" : "active");
    json_text(json, target->blocked ? "Заблокирована" : expired ? "Истекла" : "Активна");
    char date[32];
    const char *iso = iso_time(deadline, date);
    json_printf(json, ",\"expires_at\":");
    json_text(json, iso);
    json_printf(json, ",\"expires_label\":");
    if (iso)
        date[10] = '\0';
    json_text(json, iso ? date : "Бессрочно");
    json_printf(json, ",\"traffic_used_bytes\":%lld,\"traffic_limit_bytes\":", (long long)target->traffic);
    if (target->traffic_limit > 0)
        json_printf(json, "%lld", (long long)target->traffic_limit);
    else
        json_printf(json, "null");
    char used[32], limit[32], label[70];
    bytes_label(target->traffic, used);
    bytes_label(target->traffic_limit, limit);
    snprintf(label, sizeof(label), "%s / %s", used, target->traffic_limit > 0 ? limit : "∞");
    json_printf(json, ",\"traffic_label\":");
    json_text(json, label);
    json_printf(json, "}");
}

static bool file_digest(const char *path, char id[27])
{
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size;
    if (!EVP_Digest(path, strlen(path), digest, &size, EVP_sha256(), NULL) || size != 32)
        return false;
    static const char hex[] = "0123456789abcdef";
    id[0] = 'f';
    id[1] = '_';
    for (size_t i = 0; i < 12; ++i) {
        id[2 + i * 2] = hex[digest[i] >> 4];
        id[3 + i * 2] = hex[digest[i] & 15];
    }
    id[26] = '\0';
    return true;
}

static const char *legacy_profile_root(void)
{
    const char *root = getenv("APAZ_PORTAL_LEGACY_PROFILE_ROOT");
    return root && root[0] == '/' && !strstr(root, "..") && strlen(root) <= 300 ? root : "/root/antizapret/client";
}

struct delivery {
    const char *directory;
    const char *token;
    const char *host;
    const char *file_id;
    const char *legacy_path;
    bool secure;
    FILE *file;
    size_t size;
    char filename[129];
};

struct metadata {
    struct json *json;
    sqlite3_int64 last_node;
    bool user;
};

static void start_target(struct json *json, const struct target *target, bool root)
{
    json_printf(json, "%s\"node_id\":%lld,\"client_name\":", root ? "," : "{", (long long)target->node);
    json_text(json, target->name);
    json_printf(json, ",\"files\":[");
}

static void start_user_target(struct metadata *meta, const struct target *target)
{
    if (meta->last_node == target->node) {
        json_printf(meta->json, ",");
    } else {
        if (meta->last_node)
            json_printf(meta->json, "]},");
        json_printf(meta->json, "{\"node_id\":%lld,\"label\":", (long long)target->node);
        json_text(meta->json, target->node_label);
        json_printf(meta->json, ",\"clients\":[");
        meta->last_node = target->node;
    }
    start_target(meta->json, target, false);
}

static void append_file(struct json *json, const struct delivery *delivery, const char *id,
                        const char *filename, const struct protocol *protocol, bool first)
{
    char url[480];
    int length = snprintf(url, sizeof(url), "%s://%s/api/public/portal/%s/download?file_id=%s",
                          delivery->secure ? "https" : "http", delivery->host, delivery->token, id);
    if (length < 0 || (size_t)length >= sizeof(url)) {
        json->failed = true;
        return;
    }
    json_printf(json, "%s{\"file_id\":\"%s\",\"label\":", first ? "" : ",", id);
    json_text(json, filename);
    json_printf(json, ",\"filename\":");
    json_text(json, filename);
    json_printf(json, ",\"vpn_type\":\"%s\",\"download_url\":", protocol->key);
    json_text(json, url);
    if (protocol->bit == OPENVPN && delivery->secure)
        json_printf(json, ",\"openvpn_import_url\":\"openvpn://import-profile/%s\"", url);
    json_printf(json, "}");
}

struct variant_visit {
    const struct variant *variant;
    const struct protocol *protocol;
    const char *client_name;
    struct delivery *delivery;
    struct target *target;
    struct metadata *meta;
};

static bool visit_profile(void *context, const char *disk_name, FILE *file, size_t size)
{
    const struct variant_visit *visit = context;
    const struct variant *variant = visit->variant;
    const struct protocol *protocol = visit->protocol;
    struct delivery *delivery = visit->delivery;
    const char *root = legacy_profile_root();
    char path[PANEL_PORTAL_PATH_MAX], id[27];
    int length = snprintf(path, sizeof(path), "%s%s%s/%s/%s", root,
                          root[strlen(root) - 1] == '/' ? "" : "/", protocol->key, variant->name, disk_name);
    if (length < 0 || (size_t)length >= sizeof(path) || !file_digest(path, id) ||
        (!visit->meta && strcmp(delivery->file_id ? delivery->file_id : delivery->legacy_path,
                                delivery->file_id ? id : path))) {
        fclose(file);
        return true;
    }
    const char *prefix = protocol->bit == WIREGUARD ? "WG-" : protocol->bit == AMNEZIAWG ? "AWG-" : "";
    char filename[129];
    snprintf(filename, sizeof(filename), "%s%s-%s%s", prefix,
             variant->route == ROUTE_AZ ? "AZ" : "VPN", visit->client_name, variant->suffix);
    if (!visit->meta) {
        delivery->file = file;
        delivery->size = size;
        strcpy(delivery->filename, filename);
        return false;
    }

    fclose(file);
    struct target *target = visit->target;
    struct metadata *meta = visit->meta;
    if (target->files == 0 && meta->user)
        start_user_target(meta, target);
    append_file(meta->json, delivery, id, filename, protocol, target->files == 0);
    target->files++;
    target->protocols |= protocol->bit;
    return !meta->json->failed;
}

static void collect_files(sqlite3_stmt *row, const char *name, const char *fallback,
                          struct delivery *delivery, struct target *target, struct metadata *meta)
{
    struct policy policy;
    if (!visibility_policy(column_text(row, 4), column_text(row, 5), fallback, &policy))
        return;
    unsigned int mask = protocol_mask(column_text(row, 3)) & policy.protocols;
    for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); ++i) {
        const struct variant *variant = &variants[i];
        const struct protocol *protocol = &protocols[variant->protocol_index];
        if (!(mask & protocol->bit) || !(policy.routes & variant->route) ||
            (variant->group && !(policy.groups & variant->group)) || !feature_enabled(protocol->feature_env))
            continue;
        struct variant_visit visit = {variant, protocol, name, delivery, target, meta};
        panel_profile_visit_variant(delivery->directory, protocol->key, variant->name, name, visit_profile, &visit);
        if (delivery->file || (meta && meta->json->failed))
            return;
    }
}

static void finish_target(struct json *json, const struct target *target)
{
    json_printf(json, "],\"protocols\":[");
    bool first = true;
    for (size_t i = 0; i < sizeof(protocols) / sizeof(protocols[0]); ++i) {
        if (!(target->protocols & protocols[i].bit))
            continue;
        json_printf(json, "%s\"%s\"", first ? "" : ",", protocols[i].key);
        first = false;
    }
    json_printf(json, "],\"status\":");
    append_status(json, target);
    json_printf(json, "}");
}

static bool user_status(struct json *json, sqlite3_int64 user)
{
    static const char sql[] = "SELECT suspended_at,(CASE WHEN suspend_reason_visible=1 THEN suspend_reason END),"
        " traffic_limit_blocked,unixepoch(access_until),portal_banner_text,unixepoch(portal_banner_at)"
        " FROM users WHERE id=?1";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_int64(stmt, 1, user);
    bool ok = sqlite3_step(stmt) == SQLITE_ROW;
    if (ok) {
        sqlite3_int64 deadline = sqlite3_column_int64(stmt, 3), now = (sqlite3_int64)time(NULL);
        bool suspended = sqlite3_column_type(stmt, 0) != SQLITE_NULL;
        const char *state = suspended ? "suspended" : sqlite3_column_int(stmt, 2) ? "traffic_limit" :
            !deadline || deadline > now + 7 * 86400 ? NULL : deadline <= now ? "expired" : "expiring";
        char date[32];
        json_printf(json, ",\"closed_access\":");
        if (state) {
            json_printf(json, "{\"state\":\"%s\",\"requests_enabled\":false,\"messaging_enabled\":false,"
                        "\"contact_url\":null,\"reason\":", state);
            json_text(json, suspended ? column_text(stmt, 1) : NULL);
            json_printf(json, ",\"access_until\":");
            json_text(json, !suspended && !sqlite3_column_int(stmt, 2) ? iso_time(deadline, date) : NULL);
            json_printf(json, "}");
        } else {
            json_printf(json, "null");
        }
        const char *banner = column_text(stmt, 4);
        json_printf(json, ",\"portal_banner\":");
        if (banner && *banner) {
            json_printf(json, "{\"text\":");
            json_text(json, banner);
            json_printf(json, ",\"created_at\":");
            json_text(json, iso_time(sqlite3_column_int64(stmt, 5), date));
            json_printf(json, "}");
        } else {
            json_printf(json, "null");
        }
    }
    sqlite3_finalize(stmt);
    return ok;
}

static bool app_links(struct json *json)
{
    char raw[APP_LINKS_SIZE];
    if (!read_setting("portal_app_links", raw, sizeof(raw)))
        return false;
    json_printf(json, ",\"app_links\":{");
    if (!*raw) {
        json_printf(json, "}");
        return true;
    }
    static const char sql[] =
        "SELECT p.key,v.key,trim(v.value) FROM json_each(CASE WHEN json_valid(?1) THEN ?1 ELSE '{}' END) p"
        " JOIN json_each(CASE WHEN p.type='object' THEN p.value ELSE '{}' END) v"
        " WHERE p.key IN ('openvpn','wireguard','amneziawg','amneziawg2')"
        " AND v.key IN ('windows','android','ios','mac','linux') AND v.type='text' ORDER BY p.key,v.key";
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK)
        return false;
    sqlite3_bind_text(stmt, 1, raw, -1, SQLITE_STATIC);
    char protocol[16] = "", platform[12] = "";
    int result;
    while ((result = sqlite3_step(stmt)) == SQLITE_ROW && !json->failed) {
        char link[501];
        if (!copy_column(stmt, 2, link, sizeof(link)) ||
            (strncmp(link, "https://", 8) && strncmp(link, "http://", 7)) ||
            strpbrk(link, " \t\r\n"))
            continue;
        const char *p = column_text(stmt, 0);
        const char *v = column_text(stmt, 1);
        if (strcmp(protocol, p)) {
            if (protocol[0])
                json_printf(json, "},");
            strcpy(protocol, p);
            platform[0] = '\0';
            json_printf(json, "\"%s\":{", protocol);
        }
        if (!strcmp(platform, v))
            continue;
        json_printf(json, "%s\"%s\":", platform[0] ? "," : "", v);
        json_text(json, link);
        strcpy(platform, v);
    }
    sqlite3_finalize(stmt);
    json_printf(json, "%s}", protocol[0] ? "}" : "");
    return result == SQLITE_DONE;
}

static int build_meta(const struct token *token, struct delivery *delivery, struct json *json)
{
    char title[513], default_policy[POLICY_SIZE];
    if (!read_setting("portal_title", title, sizeof(title)) ||
        !read_setting("user_visible_vpn_profiles_default", default_policy, sizeof(default_policy)))
        return 503;
    json_printf(json, "{\"kind\":\"%s\",\"brand_title\":", token->user ? "user" : "client");
    json_text(json, *title ? title : "Подключение");
    if (!app_links(json))
        return 503;
    json_printf(json, ",\"unlock_codes_enabled\":false");
    if (token->user) {
        if (!user_status(json, token->user))
            return 503;
        json_printf(json, ",\"nodes\":[");
    }

    sqlite3_stmt *stmt = target_rows(token);
    if (!stmt)
        return 503;
    int result = SQLITE_OK;
    unsigned int count = 0;
    struct target target = {0};
    struct metadata meta = {.json = json, .user = token->user != 0};
    while (!json->failed && (result = sqlite3_step(stmt)) == SQLITE_ROW) {
        if (++count == MAX_TARGET_ROWS)
            break;
        char name[33];
        sqlite3_int64 node = sqlite3_column_int64(stmt, 0);
        if (node < 1 || !copy_column(stmt, 2, name, sizeof(name)) || !urlsafe(name, 32))
            continue;
        if (node != target.node || strcmp(name, target.name)) {
            if (target.node && (!meta.user || target.files))
                finish_target(json, &target);
            target = (struct target){.node = node};
            strcpy(target.name, name);
            if (!copy_column(stmt, 1, target.node_label, sizeof(target.node_label)) || !target.node_label[0])
                snprintf(target.node_label, sizeof(target.node_label), "Сервер %lld", (long long)node);
            if (!meta.user)
                start_target(json, &target, true);
        }
        add_status(&target, stmt);
        collect_files(stmt, name, default_policy, delivery, &target, &meta);
    }
    sqlite3_finalize(stmt);
    if (json->failed || result != SQLITE_DONE)
        return 503;
    if (target.node && (!meta.user || target.files))
        finish_target(json, &target);
    else if (!meta.user)
        return 404;
    if (meta.user)
        json_printf(json, "%s]}", meta.last_node ? "]}" : "");
    return json->failed ? 503 : 200;
}

int panel_portal_meta(const char *host, const char *value, const char *profiles_dir,
                      bool secure, char *out, size_t capacity)
{
    if (!out || !capacity)
        return 503;
    unsigned int remaining;
    int status = begin_read(host, &remaining);
    if (status != 200)
        return status;
    struct token token;
    status = resolve_token(value, &token);
    if (status == 200) {
        struct delivery delivery = {.directory = profiles_dir, .token = value, .host = host, .secure = secure};
        struct json json = {.out = out, .capacity = capacity};
        status = build_meta(&token, &delivery, &json);
    }
    end_read();
    return status;
}

static bool valid_file_id(const char *id)
{
    return !strncmp(id, "f_", 2) && strlen(id + 2) == 24 && strspn(id + 2, "abcdef0123456789") == 24;
}

static int find_file(const struct token *token, struct delivery *delivery)
{
    char default_policy[POLICY_SIZE];
    if (!read_setting("user_visible_vpn_profiles_default", default_policy, sizeof(default_policy)))
        return 503;
    sqlite3_stmt *stmt = target_rows(token);
    if (!stmt)
        return 503;
    int result;
    unsigned int count = 0;
    while ((result = sqlite3_step(stmt)) == SQLITE_ROW && ++count < MAX_TARGET_ROWS) {
        char name[33];
        if (!copy_column(stmt, 2, name, sizeof(name)) || !urlsafe(name, 32))
            continue;
        collect_files(stmt, name, default_policy, delivery, NULL, NULL);
        if (delivery->file)
            break;
    }
    sqlite3_finalize(stmt);
    return delivery->file ? 200 : result == SQLITE_DONE ? 404 : 503;
}

int panel_portal_download(const char *host, const char *value, const char *profiles_dir,
                          const char *file_id, const char *legacy_path,
                          FILE **file, char filename[129], size_t *size)
{
    unsigned int remaining;
    int status = begin_read(host, &remaining);
    if (status != 200)
        return status;
    struct token token;
    status = resolve_token(value, &token);
    if (status == 200) {
        const char *id = file_id && *file_id ? file_id : NULL;
        if (id ? !valid_file_id(id) : (!legacy_path || !*legacy_path || strlen(legacy_path) >= PANEL_PORTAL_PATH_MAX ||
                                       strstr(legacy_path, ".."))) {
            status = 400;
        } else {
            struct delivery delivery = {.directory = profiles_dir, .file_id = id, .legacy_path = legacy_path};
            status = find_file(&token, &delivery);
            if (status == 200) {
                *file = delivery.file;
                *size = delivery.size;
                strcpy(filename, delivery.filename);
            }
        }
    }
    end_read();
    return status;
}
