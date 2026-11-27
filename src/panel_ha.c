#include "panel_ha.h"

#include <errno.h>
#include <inttypes.h>
#include <sqlite3.h>
#include <stdlib.h>
#include <string.h>

enum { PATH_LIMIT = 4096, NAME_LIMIT = 128, DOMAIN_LIMIT = 253 };

enum check_result {
    CHECK_NEVER,
    CHECK_OK,
    CHECK_DATABASE,
    CHECK_EMPTY,
    CHECK_DOMAIN,
    CHECK_PANEL_DOMAIN,
    CHECK_MODE,
    CHECK_MEMBER,
    CHECK_DUPLICATE,
    CHECK_IN_OTHER_GROUP,
    CHECK_OFFLINE,
    CHECK_VERSIONS,
    CHECK_PARITY_UNAVAILABLE,
    CHECK_AGENT_VERSION
};

struct group {
    int64_t id;
    char name[NAME_LIMIT + 1];
    char domain[DOMAIN_LIMIT + 1];
    char wg_domain[DOMAIN_LIMIT + 1];
    bool auto_mode;
    int64_t primary;
    int64_t replicas[PANEL_HA_MAX_REPLICAS];
    size_t replica_count;
    enum check_result verification;
    char created[21];
    char updated[21];
    char verified[21];
};

static char database_path[PATH_LIMIT];

static const char schema[] =
    "BEGIN IMMEDIATE;"
    "CREATE TABLE IF NOT EXISTS sync_groups("
    "id INTEGER PRIMARY KEY AUTOINCREMENT,"
    "name TEXT NOT NULL,"
    "domain TEXT NOT NULL,"
    "wg_domain TEXT NOT NULL,"
    "auto_mode INTEGER NOT NULL CHECK(auto_mode IN (0,1)),"
    "last_verification INTEGER CHECK(last_verification>=2),"
    "verified_at INTEGER,"
    "created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),"
    "updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')),"
    "CHECK((last_verification IS NULL) = (verified_at IS NULL)));"
    "CREATE TABLE IF NOT EXISTS sync_group_members("
    "node_id INTEGER PRIMARY KEY CHECK(node_id>0),"
    "group_id INTEGER NOT NULL REFERENCES sync_groups(id) ON DELETE CASCADE,"
    "position INTEGER NOT NULL CHECK(position>=0),"
    "UNIQUE(group_id,position));"
    "COMMIT;";

static sqlite3 *connect_db(const char *path, int flags)
{
    sqlite3 *db = NULL;
    int result = sqlite3_open_v2(path, &db, flags | SQLITE_OPEN_PRIVATECACHE, NULL);
    if (result == SQLITE_OK) {
        sqlite3_busy_timeout(db, 25);
        result = sqlite3_exec(db, "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;", NULL, NULL, NULL);
    }
    if (result == SQLITE_OK)
        return db;
    sqlite3_close(db);
    return NULL;
}

bool panel_ha_open(const char *path)
{
    if (database_path[0] || !path || !path[0] || strlen(path) >= sizeof(database_path))
        return false;
    sqlite3 *db = connect_db(path, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    if (!db)
        return false;
    bool ok = sqlite3_exec(db, schema, NULL, NULL, NULL) == SQLITE_OK;
    sqlite3_close(db);
    if (ok)
        memcpy(database_path, path, strlen(path) + 1);
    return ok;
}

void panel_ha_close(void)
{
    database_path[0] = '\0';
}

static bool prepare_id(sqlite3 *db, const char *sql, int64_t id, sqlite3_stmt **stmt)
{
    return sqlite3_prepare_v2(db, sql, -1, stmt, NULL) == SQLITE_OK &&
           sqlite3_bind_int64(*stmt, 1, id) == SQLITE_OK;
}

enum panel_ha_node_role panel_ha_node_role(int64_t node_id)
{
    if (node_id == 0)
        return PANEL_HA_STANDALONE;
    if (node_id < 0 || !database_path[0])
        return PANEL_HA_LOOKUP_FAILED;
    sqlite3 *db = connect_db(database_path, SQLITE_OPEN_READONLY);
    if (!db)
        return PANEL_HA_LOOKUP_FAILED;
    sqlite3_stmt *stmt = NULL;
    enum panel_ha_node_role role = PANEL_HA_LOOKUP_FAILED;
    if (prepare_id(db, "SELECT position FROM sync_group_members WHERE node_id=?1", node_id, &stmt)) {
        int result = sqlite3_step(stmt);
        if (result == SQLITE_ROW)
            role = sqlite3_column_int(stmt, 0) == 0 ? PANEL_HA_PRIMARY : PANEL_HA_REPLICA;
        else if (result == SQLITE_DONE)
            role = PANEL_HA_STANDALONE;
    }
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return role;
}

static bool ascii_space(unsigned char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f';
}

static bool trim_text(char *out, size_t capacity, const char *input)
{
    const char *start = input;
    while (ascii_space((unsigned char)*start))
        ++start;
    const char *end = start + strlen(start);
    while (end > start && ascii_space((unsigned char)end[-1]))
        --end;
    size_t size = (size_t)(end - start);
    if (size >= capacity)
        return false;
    memcpy(out, start, size);
    out[size] = '\0';
    return true;
}

static bool valid_name(const char *text)
{
    const unsigned char *p = (const unsigned char *)text;
    if (!*p)
        return false;
    while (*p) {
        unsigned char lead = *p++;
        if (lead < 0x20 || lead == 0x7f || (lead >= 0x80 && lead < 0xc2) || lead > 0xf4)
            return false;
        if (lead < 0x80)
            continue;
        unsigned char second = *p;
        if ((lead == 0xe0 && second < 0xa0) || (lead == 0xed && second > 0x9f) ||
            (lead == 0xf0 && second < 0x90) || (lead == 0xf4 && second > 0x8f))
            return false;
        size_t tail = lead < 0xe0 ? 1 : lead < 0xf0 ? 2 : 3;
        while (tail--) {
            if (*p < 0x80 || *p > 0xbf)
                return false;
            ++p;
        }
    }
    return true;
}

static bool dns_name(char out[DOMAIN_LIMIT + 1], const char *input)
{
    char trimmed[DOMAIN_LIMIT + 2];
    if (!trim_text(trimmed, sizeof(trimmed), input))
        return false;
    size_t len = strlen(trimmed);
    if (len && trimmed[len - 1] == '.')
        --len;
    if (len > DOMAIN_LIMIT)
        return false;
    size_t label = 0;
    bool letter = false;
    for (size_t i = 0; i < len; ++i) {
        char c = trimmed[i];
        if (c >= 'A' && c <= 'Z')
            c = (char)(c + ('a' - 'A'));
        if (c == '.') {
            if (!label || out[i - 1] == '-')
                return false;
            label = 0;
            letter = false;
        } else {
            bool alpha = c >= 'a' && c <= 'z';
            if (!alpha && !(c >= '0' && c <= '9') && (c != '-' || !label))
                return false;
            if (++label > 63)
                return false;
            letter = letter || alpha;
        }
        out[i] = c;
    }
    out[len] = '\0';
    return label && letter && out[len - 1] != '-' && strchr(out, '.');
}

static bool matches_panel_host(const char *domain, const char *panel_host)
{
    if (!panel_host || !panel_host[0])
        return false;
    const char *scheme = strstr(panel_host, "://");
    if (scheme)
        panel_host = scheme + 3;
    size_t length = strcspn(panel_host, ":/?#");
    char trimmed[DOMAIN_LIMIT + 2];
    char normalized[DOMAIN_LIMIT + 1];
    if (!length || length >= sizeof(trimmed))
        return false;
    memcpy(trimmed, panel_host, length);
    trimmed[length] = '\0';
    return dns_name(normalized, trimmed) && !strcmp(normalized, domain);
}

static int compare_ids(const void *left, const void *right)
{
    int64_t a = *(const int64_t *)left;
    int64_t b = *(const int64_t *)right;
    return (a > b) - (a < b);
}

static enum check_result apply_fields(struct group *group, const struct panel_ha_fields *fields)
{
    if (!fields || (fields->name &&
        (!trim_text(group->name, sizeof(group->name), fields->name) || !valid_name(group->name))))
        return CHECK_EMPTY;
    if (fields->shared_domain && !dns_name(group->domain, fields->shared_domain))
        return CHECK_DOMAIN;
    if (fields->shared_domain_wireguard) {
        char trimmed[DOMAIN_LIMIT + 2];
        if (!trim_text(trimmed, sizeof(trimmed), fields->shared_domain_wireguard) ||
            (trimmed[0] && !dns_name(group->wg_domain, trimmed)))
            return CHECK_DOMAIN;
        if (!trimmed[0])
            group->wg_domain[0] = '\0';
    }
    if (fields->sync_mode) {
        if (!strcmp(fields->sync_mode, "auto"))
            group->auto_mode = true;
        else if (!strcmp(fields->sync_mode, "manual_full"))
            group->auto_mode = false;
        else
            return CHECK_MODE;
    }
    if (fields->primary_node_id)
        group->primary = fields->primary_node_id;
    if (fields->replica_node_ids) {
        if (fields->replica_count > PANEL_HA_MAX_REPLICAS)
            return CHECK_EMPTY;
        group->replica_count = fields->replica_count;
        memcpy(group->replicas, fields->replica_node_ids, group->replica_count * sizeof(group->replicas[0]));
        qsort(group->replicas, group->replica_count, sizeof(group->replicas[0]), compare_ids);
        size_t unique = 0;
        for (size_t i = 0; i < group->replica_count; ++i) {
            if (i == 0 || group->replicas[i] != group->replicas[i - 1])
                group->replicas[unique++] = group->replicas[i];
        }
        group->replica_count = unique;
    }
    if (!group->name[0] || !group->domain[0] || !group->replica_count)
        return CHECK_EMPTY;
    return CHECK_OK;
}

static bool agent_too_old(const char *version)
{
    unsigned long components[3];
    if (*version == 'v')
        ++version;
    for (size_t i = 0; i < 3; ++i) {
        if (*version < '0' || *version > '9')
            return false;
        char *end;
        errno = 0;
        components[i] = strtoul(version, &end, 10);
        if (errno || (i < 2 && *end != '.'))
            return false;
        version = i < 2 ? end + 1 : end;
    }
    if (*version && *version != '-' && *version != '+')
        return false;
    /* Upstream introduced the HA archive and fingerprint contract in 1.5.0. */
    return components[0] == 0 ||
           (components[0] == 1 && (components[1] < 5 ||
               (components[1] == 5 && components[2] == 0 && *version == '-')));
}

static enum check_result check_group(sqlite3 *db, const struct group *group, const char *panel_host,
                                    panel_ha_node_lookup lookup, void *context, bool check_agent_version)
{
    if (matches_panel_host(group->domain, panel_host) || matches_panel_host(group->wg_domain, panel_host))
        return CHECK_PANEL_DOMAIN;
    if (!lookup || group->primary <= 0)
        return CHECK_MEMBER;

    sqlite3_stmt *stmt = NULL;
    enum check_result result = CHECK_DATABASE;
    if (sqlite3_prepare_v2(db, "SELECT group_id FROM sync_group_members WHERE node_id=?1",
                           -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return result;
    }

    char version[PANEL_HA_VERSION_MAX + 1] = "";
    for (size_t i = 0; i <= group->replica_count; ++i) {
        int64_t id = i == 0 ? group->primary : group->replicas[i - 1];
        struct panel_ha_node_info info = {0};
        if (i && id == group->primary) {
            result = CHECK_DUPLICATE;
            break;
        }
        if (id <= 0 || !lookup(id, &info, context) || !info.vpn) {
            result = CHECK_MEMBER;
            break;
        }
        if (sqlite3_bind_int64(stmt, 1, id) != SQLITE_OK) {
            result = CHECK_DATABASE;
            break;
        }
        int step = sqlite3_step(stmt);
        if (step == SQLITE_ROW && sqlite3_column_int64(stmt, 0) != group->id) {
            result = CHECK_IN_OTHER_GROUP;
            break;
        }
        if (step != SQLITE_DONE && step != SQLITE_ROW) {
            result = CHECK_DATABASE;
            break;
        }
        if (!info.online) {
            result = CHECK_OFFLINE;
            break;
        }
        info.agent_version[PANEL_HA_VERSION_MAX] = '\0';
        if (check_agent_version && agent_too_old(info.agent_version)) {
            result = CHECK_AGENT_VERSION;
            break;
        }
        info.antizapret_version[PANEL_HA_VERSION_MAX] = '\0';
        if (info.antizapret_version[0]) {
            if (version[0] && strcmp(version, info.antizapret_version)) {
                result = CHECK_VERSIONS;
                break;
            }
            memcpy(version, info.antizapret_version, strlen(info.antizapret_version) + 1);
        }
        result = CHECK_OK;
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);
    return result;
}

static bool copy_column(sqlite3_stmt *stmt, int column, char *out, size_t capacity)
{
    const unsigned char *value = sqlite3_column_text(stmt, column);
    size_t size = (size_t)sqlite3_column_bytes(stmt, column);
    if (!value || size >= capacity || memchr(value, '\0', size))
        return false;
    memcpy(out, value, size + 1);
    return true;
}

/* Returns 1 for a complete group, 0 for a missing group, and -1 for a DB error. */
static int read_group(sqlite3 *db, int64_t id, struct group *group)
{
    static const char query[] =
        "SELECT name,domain,wg_domain,auto_mode,last_verification,"
        "strftime('%Y-%m-%dT%H:%M:%SZ',created_at,'unixepoch'),"
        "strftime('%Y-%m-%dT%H:%M:%SZ',updated_at,'unixepoch'),"
        "coalesce(strftime('%Y-%m-%dT%H:%M:%SZ',verified_at,'unixepoch'),'') "
        "FROM sync_groups WHERE id=?1";
    sqlite3_stmt *stmt = NULL;
    int step = prepare_id(db, query, id, &stmt) ? sqlite3_step(stmt) : SQLITE_ERROR;
    if (step != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        return step == SQLITE_DONE ? 0 : -1;
    }
    memset(group, 0, sizeof(*group));
    group->id = id;
    group->auto_mode = sqlite3_column_int(stmt, 3) != 0;
    group->verification = (enum check_result)sqlite3_column_int(stmt, 4);
    bool ok = copy_column(stmt, 0, group->name, sizeof(group->name)) &&
              copy_column(stmt, 1, group->domain, sizeof(group->domain)) &&
              copy_column(stmt, 2, group->wg_domain, sizeof(group->wg_domain)) &&
              copy_column(stmt, 5, group->created, sizeof(group->created)) &&
              copy_column(stmt, 6, group->updated, sizeof(group->updated)) &&
              copy_column(stmt, 7, group->verified, sizeof(group->verified));
    sqlite3_finalize(stmt);
    stmt = NULL;
    if (!ok || !prepare_id(db,
                           "SELECT node_id,position FROM sync_group_members WHERE group_id=?1 ORDER BY position",
                           id, &stmt)) {
        sqlite3_finalize(stmt);
        return -1;
    }
    for (size_t index = 0; (step = sqlite3_step(stmt)) == SQLITE_ROW; ++index) {
        int64_t member = sqlite3_column_int64(stmt, 0);
        if (index > PANEL_HA_MAX_REPLICAS || member <= 0 ||
            sqlite3_column_int(stmt, 1) != (int)index) {
            step = SQLITE_CORRUPT;
            break;
        }
        if (!index)
            group->primary = member;
        else
            group->replicas[group->replica_count++] = member;
    }
    sqlite3_finalize(stmt);
    return step == SQLITE_DONE && group->primary > 0 && group->replica_count ? 1 : -1;
}

static bool group_changed(const struct group *before, const struct group *after)
{
    return strcmp(before->domain, after->domain) || strcmp(before->wg_domain, after->wg_domain) ||
           before->auto_mode != after->auto_mode || before->primary != after->primary ||
           before->replica_count != after->replica_count ||
           memcmp(before->replicas, after->replicas, after->replica_count * sizeof(after->replicas[0]));
}

static bool exec_id(sqlite3 *db, const char *sql, int64_t id)
{
    sqlite3_stmt *stmt = NULL;
    bool ok = prepare_id(db, sql, id, &stmt) && sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

static bool write_members(sqlite3 *db, const struct group *group)
{
    sqlite3_stmt *stmt = NULL;
    bool ok = sqlite3_prepare_v2(db, "INSERT INTO sync_group_members VALUES(?1,?2,?3)", -1, &stmt, NULL) ==
              SQLITE_OK;
    for (size_t i = 0; ok && i <= group->replica_count; ++i) {
        int64_t member = i ? group->replicas[i - 1] : group->primary;
        ok = sqlite3_bind_int64(stmt, 1, member) == SQLITE_OK &&
             sqlite3_bind_int64(stmt, 2, group->id) == SQLITE_OK &&
             sqlite3_bind_int(stmt, 3, (int)i) == SQLITE_OK &&
             sqlite3_step(stmt) == SQLITE_DONE && sqlite3_reset(stmt) == SQLITE_OK;
    }
    sqlite3_finalize(stmt);
    return ok;
}

static bool write_group(sqlite3 *db, struct group *group, bool reset)
{
    const char *sql = group->id ?
        "UPDATE sync_groups SET name=?1, domain=?2, wg_domain=?3, auto_mode=?4,"
        "updated_at=strftime('%s','now'),"
        "last_verification=CASE WHEN ?5 THEN NULL ELSE last_verification END,"
        "verified_at=CASE WHEN ?5 THEN NULL ELSE verified_at END WHERE id=?6" :
        "INSERT INTO sync_groups(name,domain,wg_domain,auto_mode) VALUES(?1,?2,?3,?4)";
    sqlite3_stmt *stmt = NULL;
    bool ok = sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) == SQLITE_OK &&
              sqlite3_bind_text(stmt, 1, group->name, -1, SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_text(stmt, 2, group->domain, -1, SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_text(stmt, 3, group->wg_domain, -1, SQLITE_STATIC) == SQLITE_OK &&
              sqlite3_bind_int(stmt, 4, group->auto_mode) == SQLITE_OK &&
              (!group->id || (sqlite3_bind_int(stmt, 5, reset) == SQLITE_OK &&
                              sqlite3_bind_int64(stmt, 6, group->id) == SQLITE_OK)) &&
              sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    if (!ok)
        return false;
    if (group->id && !exec_id(db, "DELETE FROM sync_group_members WHERE group_id=?1", group->id))
        return false;
    if (!group->id)
        group->id = sqlite3_last_insert_rowid(db);
    return write_members(db, group);
}

static bool save_verify(sqlite3 *db, int64_t id, enum check_result result)
{
    sqlite3_stmt *stmt = NULL;
    bool ok = prepare_id(db, "UPDATE sync_groups SET last_verification=?2,"
                            "verified_at=strftime('%s','now') WHERE id=?1", id, &stmt) &&
              sqlite3_bind_int(stmt, 2, (int)result) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return ok;
}

static const char *check_detail(enum check_result result)
{
    switch (result) {
    case CHECK_OK: return "Предварительная проверка пройдена";
    case CHECK_EMPTY: return "Укажите название, общий домен, primary и от 1 до 16 реплик";
    case CHECK_DOMAIN: return "Укажите действительное доменное имя VPN";
    case CHECK_PANEL_DOMAIN: return "Общий домен VPN совпадает с доменом панели";
    case CHECK_MODE: return "Допустимые режимы синхронизации: manual_full и auto";
    case CHECK_MEMBER: return "Укажите существующие VPN-узлы для primary и реплик";
    case CHECK_DUPLICATE: return "Primary не может быть в списке реплик";
    case CHECK_IN_OTHER_GROUP: return "Один из узлов уже входит в другую HA-группу";
    case CHECK_OFFLINE: return "Проверьте доступность primary и всех реплик";
    case CHECK_VERSIONS: return "У узлов разные версии AntiZapret";
    case CHECK_PARITY_UNAVAILABLE: return "Последняя проверка связи с узлами успешна. Проверка паритета VPN пока недоступна";
    case CHECK_AGENT_VERSION: return "Для HA требуется версия node agent 1.5.0 или новее";
    default: return "Не удалось прочитать или обновить HA-группу";
    }
}

static void json_text(FILE *file, const char *value)
{
    if (!value) {
        fputs("null", file);
        return;
    }
    fputc('"', file);
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor; ++cursor) {
        if (*cursor == '"' || *cursor == '\\')
            fputc('\\', file);
        if (*cursor < 0x20)
            fprintf(file, "\\u%04x", (unsigned int)*cursor);
        else
            fputc(*cursor, file);
    }
    fputc('"', file);
}

static int error_json(FILE *file, int status, const char *message)
{
    fputs("{\"error\":", file);
    json_text(file, message);
    fputc('}', file);
    return status;
}

static int check_error(FILE *file, enum check_result result)
{
    if (result == CHECK_DATABASE)
        return error_json(file, 500, check_detail(result));
    if (result == CHECK_PANEL_DOMAIN)
        return error_json(file, 400, check_detail(result));
    return error_json(file, 422, check_detail(result));
}

static void write_verification(FILE *file, const struct group *group)
{
    fprintf(file, "{\"ready\":false,\"primary_node_id\":%" PRId64 ",\"shared_domain\":", group->primary);
    json_text(file, group->domain);
    fputs(",\"shared_domain_wireguard\":", file);
    json_text(file, group->wg_domain[0] ? group->wg_domain : NULL);
    fputs(",\"replicas\":[],\"summary\":", file);
    json_text(file, check_detail(group->verification));
    fputc('}', file);
}

static void write_status_fields(FILE *file, const struct group *group)
{
    fputs("\"sync_status\":\"unknown\",\"last_sync_at\":null,\"last_sync_task_id\":null,"
          "\"last_sync_error\":null,\"last_verify_at\":", file);
    json_text(file, group->verified[0] ? group->verified : NULL);
    fputs(",\"last_verify_result\":", file);
    if (group->verification)
        write_verification(file, group);
    else
        fputs("null", file);
}

static void load_member(int64_t id, struct panel_ha_node_info *info,
                        panel_ha_node_lookup lookup, void *context)
{
    memset(info, 0, sizeof(*info));
    if (!lookup || !lookup(id, info, context) || !info->vpn) {
        memset(info, 0, sizeof(*info));
        info->health_unknown = true;
        return;
    }
    info->name[PANEL_HA_NODE_NAME_MAX] = '\0';
    info->host[PANEL_HA_NODE_HOST_MAX] = '\0';
}

static void write_member_json(FILE *file, int64_t id, bool primary, const struct panel_ha_node_info *member)
{
    fprintf(file, "{\"node_id\":%" PRId64 ",\"role\":\"%s\",\"node_name\":", id,
            primary ? "primary" : "replica");
    json_text(file, valid_name(member->name) ? member->name : NULL);
    fputs(",\"host\":", file);
    json_text(file, valid_name(member->host) ? member->host : NULL);
    fprintf(file, ",\"online\":%s,\"status\":\"%s\",\"client_count\":null}",
            member->online ? "true" : "false",
            member->online ? "online" : member->health_unknown ? "unknown" : "offline");
}

static void write_group_json(FILE *file, const struct group *group,
                             panel_ha_node_lookup lookup, void *context)
{
    fprintf(file, "{\"id\":%" PRId64 ",\"name\":", group->id);
    json_text(file, group->name);
    fputs(",\"shared_domain\":", file);
    json_text(file, group->domain);
    fputs(",\"shared_domain_wireguard\":", file);
    json_text(file, group->wg_domain[0] ? group->wg_domain : NULL);
    struct panel_ha_node_info primary;
    load_member(group->primary, &primary, lookup, context);
    fprintf(file, ",\"primary_node_id\":%" PRId64 ",\"primary_node_name\":", group->primary);
    json_text(file, valid_name(primary.name) ? primary.name : NULL);
    fputs(",\"replica_node_ids\":[", file);
    for (size_t i = 0; i < group->replica_count; ++i)
        fprintf(file, "%s%" PRId64, i ? "," : "", group->replicas[i]);
    fputs("],\"members\":[", file);
    write_member_json(file, group->primary, true, &primary);
    for (size_t i = 0; i < group->replica_count; ++i) {
        struct panel_ha_node_info replica;
        load_member(group->replicas[i], &replica, lookup, context);
        fputc(',', file);
        write_member_json(file, group->replicas[i], false, &replica);
    }
    fprintf(file, "],\"sync_mode\":\"%s\",\"ready\":%s,\"created_at\":",
            group->auto_mode ? "auto" : "manual_full", group->verification ? "false" : "null");
    json_text(file, group->created);
    fputs(",\"updated_at\":", file);
    json_text(file, group->updated);
    fputs(",\"warnings\":[", file);
    json_text(file, "Перенос состояния VPN между узлами пока недоступен");
    fputs("],", file);
    write_status_fields(file, group);
    fputc('}', file);
}

static int list_groups(sqlite3 *db, FILE *file, panel_ha_node_lookup lookup, void *context)
{
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "SELECT id FROM sync_groups ORDER BY name COLLATE NOCASE,id", -1, &stmt, NULL) !=
        SQLITE_OK) {
        sqlite3_finalize(stmt);
        return check_error(file, CHECK_DATABASE);
    }
    fputc('[', file);
    bool first = true;
    int step;
    while ((step = sqlite3_step(stmt)) == SQLITE_ROW) {
        struct group group;
        if (read_group(db, sqlite3_column_int64(stmt, 0), &group) != 1) {
            step = SQLITE_CORRUPT;
            break;
        }
        if (!first)
            fputc(',', file);
        write_group_json(file, &group, lookup, context);
        first = false;
    }
    sqlite3_finalize(stmt);
    if (step != SQLITE_DONE)
        return 500;
    fputc(']', file);
    return 200;
}

enum request_action {
    ACTION_NONE, ACTION_LIST, ACTION_GET, ACTION_STATUS, ACTION_CREATE, ACTION_UPDATE,
    ACTION_DELETE, ACTION_PREFLIGHT, ACTION_VERIFY, ACTION_APPLY_DOMAIN, ACTION_SETUP, ACTION_PUSH_FULL
};

static enum request_action get_action(const char *action)
{
    static const struct {
        const char *text;
        enum request_action action;
    } names[] = {
        {"list", ACTION_LIST}, {"get", ACTION_GET}, {"status", ACTION_STATUS},
        {"create", ACTION_CREATE}, {"update", ACTION_UPDATE}, {"delete", ACTION_DELETE},
        {"preflight", ACTION_PREFLIGHT}, {"verify", ACTION_VERIFY}, {"apply-shared-domain", ACTION_APPLY_DOMAIN},
        {"setup", ACTION_SETUP}, {"push-full", ACTION_PUSH_FULL}
    };
    for (size_t i = 0; action && i < sizeof(names) / sizeof(names[0]); ++i) {
        if (!strcmp(action, names[i].text))
            return names[i].action;
    }
    return ACTION_NONE;
}

static bool commit(sqlite3 *db)
{
    return sqlite3_exec(db, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
}

static int perform_request(sqlite3 *db, enum request_action action, int64_t group_id,
                           const struct panel_ha_fields *fields, const char *panel_host,
                           panel_ha_node_lookup lookup, void *context, FILE *file)
{
    if (action == ACTION_LIST)
        return list_groups(db, file, lookup, context);

    struct group group = {0};
    if (group_id) {
        int loaded = read_group(db, group_id, &group);
        if (loaded < 0)
            return check_error(file, CHECK_DATABASE);
        if (!loaded)
            return error_json(file, 404, "HA-группа не найдена");
    }
    if (action == ACTION_GET) {
        write_group_json(file, &group, lookup, context);
        return 200;
    }
    if (action == ACTION_STATUS) {
        fprintf(file, "{\"group_id\":%" PRId64 ",", group.id);
        write_status_fields(file, &group);
        fputs(",\"progress_percent\":null,\"progress_stage\":null}", file);
        return 200;
    }
    if (action == ACTION_DELETE) {
        if (!exec_id(db, "DELETE FROM sync_groups WHERE id=?1", group.id) || !commit(db))
            return check_error(file, CHECK_DATABASE);
        fputs("{\"message\":\"HA-группа расформирована\"}", file);
        return 200;
    }

    struct group before = group;
    if (fields || action == ACTION_CREATE || action == ACTION_UPDATE || (action == ACTION_PREFLIGHT && !group_id)) {
        enum check_result validation = apply_fields(&group, fields);
        if (validation != CHECK_OK)
            return check_error(file, validation);
    }
    bool check_agent_version = action != ACTION_CREATE && action != ACTION_UPDATE;
    enum check_result check = check_group(db, &group, panel_host, lookup, context, check_agent_version);
    if (action == ACTION_VERIFY && check != CHECK_DATABASE) {
        group.verification = check == CHECK_OK ? CHECK_PARITY_UNAVAILABLE : check;
        if (!save_verify(db, group.id, group.verification) || !commit(db))
            return check_error(file, CHECK_DATABASE);
        write_verification(file, &group);
        return 200;
    }
    if (check != CHECK_OK)
        return check_error(file, check);
    if (action == ACTION_PREFLIGHT) {
        fputs("{\"valid\":true,\"ready\":false,\"shared_domain\":", file);
        json_text(file, group.domain);
        fputs(",\"effective_wireguard_domain\":", file);
        json_text(file, group.wg_domain[0] ? group.wg_domain : group.domain);
        fputs(",\"summary\":", file);
        json_text(file, check_detail(CHECK_OK));
        fputc('}', file);
        return 200;
    }
    if (action == ACTION_APPLY_DOMAIN || action == ACTION_SETUP || action == ACTION_PUSH_FULL)
        return error_json(file, 501, "Перенос состояния VPN между узлами пока недоступен");
    if (!write_group(db, &group, group_changed(&before, &group)) ||
        read_group(db, group.id, &group) != 1 || !commit(db))
        return check_error(file, CHECK_DATABASE);
    write_group_json(file, &group, lookup, context);
    return action == ACTION_CREATE ? 201 : 200;
}

int panel_ha_request(const char *action, int64_t group_id, const struct panel_ha_fields *fields,
                     const char *panel_host, panel_ha_node_lookup lookup, void *context, FILE *output)
{
    if (!output)
        return 500;
    enum request_action kind = get_action(action);
    if (kind == ACTION_NONE || group_id < 0 ||
        (group_id == 0 && kind != ACTION_CREATE && kind != ACTION_LIST && kind != ACTION_PREFLIGHT) ||
        (group_id > 0 && (kind == ACTION_CREATE || kind == ACTION_LIST)))
        return error_json(output, 404, "Операция HA не найдена");
    if (!database_path[0])
        return check_error(output, CHECK_DATABASE);

    bool write = kind == ACTION_CREATE || kind == ACTION_UPDATE || kind == ACTION_DELETE || kind == ACTION_VERIFY;
    sqlite3 *db = connect_db(database_path, write ? SQLITE_OPEN_READWRITE : SQLITE_OPEN_READONLY);
    if (!db)
        return check_error(output, CHECK_DATABASE);
    int status = sqlite3_exec(db, write ? "BEGIN IMMEDIATE" : "BEGIN", NULL, NULL, NULL) == SQLITE_OK ?
        perform_request(db, kind, group_id, fields, panel_host, lookup, context, output) :
        check_error(output, CHECK_DATABASE);
    sqlite3_close(db);
    return ferror(output) ? 500 : status;
}
