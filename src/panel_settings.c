#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "panel_settings.h"

#include <sqlite3.h>

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

enum { PATH_CAP = 4096, ENV_LIMIT = 1024 * 1024, ENV_LINE_LIMIT = 4096 };

struct feature {
    const char *key;
    const char *env_key;
    const char *label;
    bool default_enabled;
    bool background;
};

static const struct feature features[] = {
    { "traffic_sync", "TRAFFIC_SYNC_ENABLED", "Синхронизация трафика", true, true },
    { "wg_policy_sync", "WG_POLICY_SYNC_ENABLED", "Синхронизация политик WG/AWG 1.5", true, true },
    { "resource_monitor", "MONITOR_ENABLED", "Мониторинг нагрузки CPU/RAM", true, true },
    { "openvpn", "FEATURE_OPENVPN_ENABLED", "OpenVPN", true, false },
    { "wireguard", "FEATURE_WIREGUARD_ENABLED", "WireGuard", true, false },
    { "amneziawg", "FEATURE_AMNEZIAWG_ENABLED", "AmneziaWG 1.5", true, false },
    { "logs_dashboard", "FEATURE_LOGS_DASHBOARD_ENABLED", "Наблюдение", true, false },
    { "server_monitor", "FEATURE_SERVER_MONITOR_ENABLED", "Ресурсы хоста", true, false },
    { "routing", "FEATURE_ROUTING_ENABLED", "Маршрутизация", true, false },
    { "antizapret_config", "FEATURE_ANTIZAPRET_CONFIG_ENABLED", "AntiZapret", true, false },
    { "warper", "FEATURE_WARPER_ENABLED", "AZ-WARP", true, false },
    { "awg2", "FEATURE_AWG2_ENABLED", "AWG 2.0", false, false },
    { "edit_files", "FEATURE_EDIT_FILES_ENABLED", "Файлы AntiZapret", true, false },
    { "telegram", "FEATURE_TELEGRAM_ENABLED", "Telegram", false, false },
    { "telegram_widgets", "FEATURE_TELEGRAM_WIDGETS_ENABLED", "Telegram-виджеты", false, false },
    { "proxy_nodes", "FEATURE_PROXY_NODES_ENABLED", "Прокси-узлы", false, false },
    { "backups", "FEATURE_BACKUPS_ENABLED", "Резервные копии", true, false },
    { "maintenance", "FEATURE_MAINTENANCE_ENABLED", "Обслуживание", true, false },
    { "security", "FEATURE_SECURITY_ENABLED", "Безопасность", true, false },
    { "diagnostics_tests", "FEATURE_DIAGNOSTICS_TESTS_ENABLED", "Диагностика", true, false },
    { "user_management", "FEATURE_USER_MANAGEMENT_ENABLED", "Пользователи панели", true, false },
    { "clients_page", "FEATURE_CLIENTS_PAGE_ENABLED", "Клиенты", true, false },
    { "user_provisioning", "FEATURE_USER_PROVISIONING_ENABLED", "Абоненты", false, false },
    { "user_messaging", "FEATURE_USER_MESSAGING_ENABLED", "Сообщения абонентов", false, false },
    { "action_logs", "FEATURE_ACTION_LOGS_ENABLED", "Логи действий", true, false },
    { "system_updates", "FEATURE_SYSTEM_UPDATES_ENABLED", "Обновления системы", true, false },
    { "qr_downloads", "FEATURE_QR_DOWNLOADS_ENABLED", "Выдача VPN-профилей", true, false },
    { "unlock_codes", "FEATURE_UNLOCK_CODES_ENABLED", "Unlock-коды доступа", true, false },
    { "client_portal", "FEATURE_CLIENT_PORTAL_ENABLED", "Клиентский портал", true, false },
    { "vpn_network", "FEATURE_VPN_NETWORK_ENABLED", "Адрес сайта и HTTPS", true, false },
    { "active_web_sessions", "ACTIVE_WEB_SESSION_TRACKING_ENABLED", "Учёт активных web-сессий", true, true },
    { "nightly_idle_restart", "NIGHTLY_IDLE_RESTART_ENABLED", "Ночной рестарт при простое", true, true },
    { "runtime_backup_cleanup", "RUNTIME_BACKUP_CLEANUP_ENABLED", "Очистка runtime-бэкапов CIDR", true, true },
    { "nodes", "FEATURE_NODES_ENABLED", "Узлы", true, false },
    { "node_ssh_transport", "FEATURE_NODE_SSH_TRANSPORT_ENABLED", "SSH transport узлов", false, false },
    { "panel_ops", "FEATURE_PANEL_OPS_ENABLED", "Операции панели", true, false },
    { "node_health", "NODE_HEALTH_SYNC_ENABLED", "Опрос health узлов", true, true },
    { "cert_sync", "CERT_SYNC_ENABLED", "Синхронизация сертификатов OpenVPN", true, true },
    { "resource_metrics", "RESOURCE_METRICS_ENABLED", "Метрики ресурсов VPN-узлов", true, true },
    { "panel_resource_metrics", "PANEL_RESOURCE_METRICS_ENABLED", "Метрики ресурсов панели", true, true },
    { "cidr_scheduler", "CIDR_DB_REFRESH_ENABLED", "Планировщик CIDR DB", true, true },
    { "node_sync_reconcile", "NODE_SYNC_RECONCILE_ENABLED", "Сверка Node Sync", true, true },
    { "retention", "RETENTION_ENABLED", "Автоочистка БД (retention)", true, true },
    { "key_rotation", "FEATURE_KEY_ROTATION_ENABLED", "Ротация API-ключей узлов", true, true },
    { "user_reminders", "SELF_SERVICE_REMINDER_ENABLED", "Напоминания self-service", true, true },
    { "alert_rules", "ALERT_RULES_ENABLED", "Правила алертов", true, true },
    { "noc_reports", "NOC_REPORT_ENABLED", "NOC-отчёты по расписанию", true, true },
    { "cloudflare_ips_update", "CLOUDFLARE_IPS_AUTO_UPDATE", "Автообновление Cloudflare IP", false, true },
    { "access_expiry", "FEATURE_ACCESS_EXPIRY_ENABLED", "Автоистечение access-until", true, true },
    { "connection_history", "FEATURE_CONNECTION_HISTORY_ENABLED", "История подключений (сэмплы)", true, true },
};

enum { FEATURE_COUNT = sizeof(features) / sizeof(features[0]) };

static sqlite3 *settings_db;
static bool settings_state[FEATURE_COUNT];

struct json_buffer {
    char *out;
    size_t capacity;
    size_t size;
    bool ok;
};

static void append(struct json_buffer *json, const char *format, ...)
{
    if (!json->ok)
        return;
    size_t remaining = json->capacity - json->size;
    va_list args;
    va_start(args, format);
    int written = vsnprintf(json->out + json->size, remaining, format, args);
    va_end(args);
    if (written < 0 || (size_t)written >= remaining)
        json->ok = false;
    else
        json->size += (size_t)written;
}

static const char *json_bool(bool value)
{
    return value ? "true" : "false";
}

static int find_feature(const char *key, bool use_env_name)
{
    if (key)
        for (int index = 0; index < FEATURE_COUNT; ++index)
            if (strcmp(use_env_name ? features[index].env_key : features[index].key, key) == 0)
                return index;
    return -1;
}

static bool state_enabled(const bool *state, const char *key)
{
    int index = find_feature(key, false);
    return index >= 0 && state[index];
}

static int protocol_count(const bool *state)
{
    return state_enabled(state, "openvpn") + state_enabled(state, "wireguard") +
           state_enabled(state, "amneziawg") + state_enabled(state, "awg2");
}

static bool vpn_protocol(const char *key)
{
    return strcmp(key, "openvpn") == 0 || strcmp(key, "wireguard") == 0 ||
           strcmp(key, "amneziawg") == 0 || strcmp(key, "awg2") == 0;
}

static bool valid_state(const bool *state)
{
    bool provisioning = state_enabled(state, "user_provisioning");
    return protocol_count(state) > 0 &&
           (state_enabled(state, "clients_page") || provisioning) &&
           (!provisioning || state_enabled(state, "user_management")) &&
           (!state_enabled(state, "user_messaging") || (provisioning && state_enabled(state, "telegram")));
}

static bool env_bool(const char *text, bool *value)
{
    char lower[6];
    size_t len = strlen(text);
    if (len >= sizeof(lower))
        return false;
    for (size_t index = 0; index <= len; ++index)
        lower[index] = (char)tolower((unsigned char)text[index]);
    if (strcmp(lower, "1") == 0 || strcmp(lower, "true") == 0 ||
        strcmp(lower, "yes") == 0 || strcmp(lower, "on") == 0) {
        *value = true;
        return true;
    }
    if (strcmp(lower, "0") == 0 || strcmp(lower, "false") == 0 ||
        strcmp(lower, "no") == 0 || strcmp(lower, "off") == 0) {
        *value = false;
        return true;
    }
    return false;
}

static bool execute(const char *sql)
{
    return sqlite3_exec(settings_db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static bool load_settings(bool *state, bool *stored)
{
    for (int index = 0; index < FEATURE_COUNT; ++index) {
        const char *value = getenv(features[index].env_key);
        state[index] = features[index].default_enabled;
        if (value && *value && !env_bool(value, &state[index]))
            state[index] = false;
        stored[index] = false;
    }
    sqlite3_stmt *statement = NULL;
    bool success = sqlite3_prepare_v2(settings_db, "SELECT key, enabled FROM feature_flags",
                                      -1, &statement, NULL) == SQLITE_OK;
    if (success) {
        int result;
        while ((result = sqlite3_step(statement)) == SQLITE_ROW) {
            const char *key = (const char *)sqlite3_column_text(statement, 0);
            int index = find_feature(key, false);
            int enabled = sqlite3_column_int(statement, 1);
            if (index >= 0 && sqlite3_column_type(statement, 1) == SQLITE_INTEGER &&
                (enabled == 0 || enabled == 1)) {
                state[index] = enabled != 0;
                stored[index] = true;
            }
        }
        success = result == SQLITE_DONE;
    }
    sqlite3_finalize(statement);
    return success;
}

static bool prepare_database_file(const char *path)
{
#ifndef _WIN32
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return errno == EEXIST;
    return close(fd) == 0;
#else
    (void)path;
    return true;
#endif
}

bool panel_settings_open(const char *data_dir)
{
    if (settings_db || !data_dir || !*data_dir)
        return false;
    char path[PATH_CAP];
    int length = snprintf(path, sizeof(path), "%s/panel-settings.db", data_dir);
    if (length < 0 || (size_t)length >= sizeof(path) || !prepare_database_file(path))
        return false;
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
#ifdef SQLITE_OPEN_NOFOLLOW
    flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    bool stored[FEATURE_COUNT];
    if (sqlite3_open_v2(path, &settings_db, flags, NULL) != SQLITE_OK ||
        sqlite3_busy_timeout(settings_db, 150) != SQLITE_OK ||
        !execute("PRAGMA trusted_schema=OFF; PRAGMA cache_size=-32;") ||
        !execute("CREATE TABLE IF NOT EXISTS feature_flags ("
                 "key TEXT PRIMARY KEY, enabled INTEGER NOT NULL CHECK(enabled IN (0,1))"
                 ") WITHOUT ROWID;") || !load_settings(settings_state, stored)) {
        panel_settings_close();
        return false;
    }
    return true;
}

void panel_settings_close(void)
{
    if (settings_db) {
        sqlite3_close(settings_db);
        settings_db = NULL;
    }
}

bool panel_settings_enabled(const char *key)
{
    return settings_db && state_enabled(settings_state, key);
}

bool panel_settings_json(char *out, size_t capacity)
{
    if (!settings_db || !out || capacity == 0)
        return false;
    struct json_buffer json = { out, capacity, 0, true };
    append(&json, "{\"features\":{");
    for (int index = 0; index < FEATURE_COUNT; ++index)
        append(&json, "%s\"%s\":%s", index ? "," : "", features[index].key, json_bool(settings_state[index]));
    append(&json, "},\"items\":[");
    int enabled_count = 0;
    int protocols = protocol_count(settings_state);
    for (int index = 0; index < FEATURE_COUNT; ++index) {
        const struct feature *feature = &features[index];
        bool enabled = settings_state[index];
        bool locked = protocols == 1 && enabled && vpn_protocol(feature->key);
        enabled_count += enabled;
        append(&json, "%s{\"key\":\"%s\",\"label\":\"%s\",\"group\":\"%s\","
                      "\"default\":%s,\"enabled\":%s,\"locked\":%s}",
               index ? "," : "", feature->key, feature->label, feature->background ? "background" : "app_module",
               json_bool(feature->default_enabled), json_bool(enabled), json_bool(locked));
    }
    append(&json, "],\"total\":%d,\"enabled_count\":%d,\"disabled_count\":%d}",
           FEATURE_COUNT, enabled_count, FEATURE_COUNT - enabled_count);
    return json.ok;
}

static enum panel_settings_result apply_settings(const bool *values, const bool *requested, bool keep_stored)
{
    if (!settings_db || !execute("BEGIN IMMEDIATE"))
        return PANEL_SETTINGS_ERROR;

    bool next[FEATURE_COUNT], stored[FEATURE_COUNT], changed[FEATURE_COUNT];
    bool success = load_settings(next, stored);
    enum panel_settings_result result = PANEL_SETTINGS_ERROR;
    sqlite3_stmt *statement = NULL;
    if (success) {
        for (int index = 0; index < FEATURE_COUNT; ++index) {
            changed[index] = requested[index] && (!keep_stored || !stored[index]);
            if (changed[index])
                next[index] = values[index];
        }
        int management = find_feature("user_management", false);
        int provisioning = find_feature("user_provisioning", false);
        if (!keep_stored && changed[management] && !next[management]) {
            changed[provisioning] = true;
            next[provisioning] = false;
        }
        if (!valid_state(next)) {
            result = PANEL_SETTINGS_CONFLICT;
            success = false;
        }
    }
    if (success)
        success = sqlite3_prepare_v2(settings_db,
                                     "INSERT INTO feature_flags(key, enabled) VALUES(?,?)"
                                     " ON CONFLICT(key) DO UPDATE SET enabled=excluded.enabled",
                                     -1, &statement, NULL) == SQLITE_OK;
    for (int index = 0; success && index < FEATURE_COUNT; ++index) {
        if (changed[index]) {
            success = sqlite3_bind_text(statement, 1, features[index].key, -1, SQLITE_STATIC) == SQLITE_OK &&
                      sqlite3_bind_int(statement, 2, next[index]) == SQLITE_OK &&
                      sqlite3_step(statement) == SQLITE_DONE && sqlite3_reset(statement) == SQLITE_OK;
        }
    }
    sqlite3_finalize(statement);
    if (success && execute("COMMIT")) {
        memcpy(settings_state, next, sizeof(next));
        return PANEL_SETTINGS_OK;
    }
    execute("ROLLBACK");
    return result;
}

enum panel_settings_result panel_settings_set(const char *key, bool enabled)
{
    int index = find_feature(key, false);
    if (index < 0)
        return PANEL_SETTINGS_INVALID;
    bool values[FEATURE_COUNT] = {false};
    bool requested[FEATURE_COUNT] = {false};
    values[index] = enabled;
    requested[index] = true;
    return apply_settings(values, requested, false);
}

static char *trim(char *text)
{
    while (isspace((unsigned char)*text))
        ++text;
    size_t end = strlen(text);
    while (end > 0 && isspace((unsigned char)text[end - 1]))
        text[--end] = '\0';
    return text;
}

static bool import_line(char *line, bool *values, bool *requested)
{
    char *key = trim(line);
    if (!*key || *key == '#')
        return true;
    char *value = strchr(key, '=');
    if (!value)
        return true;
    *value++ = '\0';
    int index = find_feature(trim(key), true);
    if (index < 0)
        return true;
    value = trim(value);
    size_t len = strlen(value);
    if (len >= 2 && (value[0] == '"' || value[0] == '\'') && value[len - 1] == value[0]) {
        value[len - 1] = '\0';
        value = trim(value + 1);
    }
    if (!*value)
        values[index] = features[index].default_enabled;
    else if (!env_bool(value, &values[index]))
        return false;
    requested[index] = true;
    return true;
}

enum panel_settings_result panel_settings_open_regular(const char *directory, const char *name, FILE **out,
                                                       unsigned long long *size)
{
#ifdef _WIN32
    char path[PATH_CAP];
    if (directory) {
        DWORD flags = GetFileAttributesA(directory);
        if (flags == INVALID_FILE_ATTRIBUTES || !(flags & FILE_ATTRIBUTE_DIRECTORY) ||
            flags & FILE_ATTRIBUTE_REPARSE_POINT)
            return PANEL_SETTINGS_UNAVAILABLE;
        int length = snprintf(path, sizeof(path), "%s/%s", directory, name);
        if (length < 0 || (size_t)length >= sizeof(path))
            return PANEL_SETTINGS_UNAVAILABLE;
        name = path;
    }
    HANDLE handle = CreateFileA(name, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (handle == INVALID_HANDLE_VALUE)
        return GetLastError() == ERROR_FILE_NOT_FOUND ? PANEL_SETTINGS_MISSING : PANEL_SETTINGS_UNAVAILABLE;
    BY_HANDLE_FILE_INFORMATION info;
    if (GetFileType(handle) != FILE_TYPE_DISK || !GetFileInformationByHandle(handle, &info) ||
        info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) ||
        info.nNumberOfLinks != 1) {
        CloseHandle(handle);
        return PANEL_SETTINGS_UNAVAILABLE;
    }
    *size = ((unsigned long long)info.nFileSizeHigh << 32) | info.nFileSizeLow;
    int fd = _open_osfhandle((intptr_t)handle, _O_RDONLY | _O_BINARY);
    if (fd < 0) {
        CloseHandle(handle);
        return PANEL_SETTINGS_UNAVAILABLE;
    }
    *out = _fdopen(fd, "rb");
    if (!*out)
        _close(fd);
#else
    int root = AT_FDCWD;
    if (directory) {
        root = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (root < 0)
            return PANEL_SETTINGS_UNAVAILABLE;
    }
    int fd = openat(root, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    int open_error = errno;
    if (directory)
        close(root);
    if (fd < 0)
        return open_error == ENOENT ? PANEL_SETTINGS_MISSING : PANEL_SETTINGS_UNAVAILABLE;
    struct stat info;
    if (fstat(fd, &info) != 0 || !S_ISREG(info.st_mode) || info.st_nlink != 1 || info.st_size < 0) {
        close(fd);
        return PANEL_SETTINGS_UNAVAILABLE;
    }
    *size = (unsigned long long)info.st_size;
    *out = fdopen(fd, "rb");
    if (!*out)
        close(fd);
#endif
    return *out ? PANEL_SETTINGS_OK : PANEL_SETTINGS_UNAVAILABLE;
}

enum panel_settings_result panel_settings_import_env(const char *env_path)
{
    if (!settings_db || !env_path || !*env_path)
        return PANEL_SETTINGS_INVALID;
    FILE *env;
    unsigned long long size;
    enum panel_settings_result result = panel_settings_open_regular(NULL, env_path, &env, &size);
    if (result != PANEL_SETTINGS_OK)
        return result;
    if (size > ENV_LIMIT) {
        fclose(env);
        return PANEL_SETTINGS_TOO_LARGE;
    }

    bool values[FEATURE_COUNT] = {false};
    bool requested[FEATURE_COUNT] = {false};
    char line[ENV_LINE_LIMIT];
    size_t length = 0, read_count = 0;
    bool first_line = true;
    int byte;
    while ((byte = fgetc(env)) != EOF) {
        if (++read_count > ENV_LIMIT || length == sizeof(line) - 1) {
            result = PANEL_SETTINGS_TOO_LARGE;
            break;
        }
        if (byte == '\0') {
            result = PANEL_SETTINGS_INVALID;
            break;
        }
        if (byte != '\n') {
            line[length++] = (char)byte;
            continue;
        }
        line[length] = '\0';
        char *start = first_line && length >= 3 && memcmp(line, "\xEF\xBB\xBF", 3) == 0 ? line + 3 : line;
        if (!import_line(start, values, requested)) {
            result = PANEL_SETTINGS_INVALID;
            break;
        }
        first_line = false;
        length = 0;
    }
    if (result == PANEL_SETTINGS_OK && ferror(env))
        result = PANEL_SETTINGS_ERROR;
    if (result == PANEL_SETTINGS_OK && length > 0) {
        line[length] = '\0';
        char *start = first_line && length >= 3 && memcmp(line, "\xEF\xBB\xBF", 3) == 0 ? line + 3 : line;
        if (!import_line(start, values, requested))
            result = PANEL_SETTINGS_INVALID;
    }
    fclose(env);
    return result == PANEL_SETTINGS_OK ? apply_settings(values, requested, true) : result;
}

struct config_file {
    const char *key;
    const char *filename;
    const char *title;
    const char *group;
};

static const struct config_file config_files[] = {
    { "include_hosts", "include-hosts.txt", "Включить домены", "hosts" },
    { "exclude_hosts", "exclude-hosts.txt", "Исключить домены", "hosts" },
    { "include_ips", "include-ips.txt", "Включить IP/CIDR", "ips" },
    { "exclude_ips", "exclude-ips.txt", "Исключить IP/CIDR", "ips" },
    { "allow_ips", "allow-ips.txt", "Разрешённые IP", "ips" },
    { "drop_ips", "drop-ips.txt", "Блокировать IP", "ips" },
    { "forward_ips", "forward-ips.txt", "Перенаправлять IP", "ips" },
    { "include_adblock_hosts", "include-adblock-hosts.txt", "Adblock — включить", "adblock" },
    { "exclude_adblock_hosts", "exclude-adblock-hosts.txt", "Adblock — исключить", "adblock" },
    { "remove_hosts", "remove-hosts.txt", "Удалить домены", "hosts" },
    { "deny_ips", "deny-ips.txt", "Запретить входящие IP", "ips" },
    { "include_warp_hosts", "include-warp-hosts.txt", "WARP — включить домены", "warp" },
    { "exclude_warp_hosts", "exclude-warp-hosts.txt", "WARP — исключить домены", "warp" },
    { "deny_rpz", "deny-rpz.txt", "RPZ — блокировка (AntiZapret)", "dns" },
    { "deny2_rpz", "deny2-rpz.txt", "RPZ — блокировка (полный VPN)", "dns" },
    { "deny3_rpz", "deny3-rpz.txt", "RPZ — блокировка (Proxy DNS)", "dns" },
    { "warp_rpz", "warp-rpz.txt", "RPZ — через WARP", "dns" },
    { "proxy_rpz", "proxy-rpz.txt", "RPZ — через AntiZapret", "dns" },
    { "kresd_custom", "custom.lua", "DNS-политики (AntiZapret)", "dns" },
    { "kresd_custom2", "custom2.lua", "DNS-политики (полный VPN)", "dns" },
    { "kresd_custom3", "custom3.lua", "DNS-политики (Proxy DNS)", "dns" }
};

enum { CONFIG_FILE_COUNT = sizeof(config_files) / sizeof(config_files[0]), CONFIG_FILE_LIMIT = 32 * 1024 };

bool panel_edit_files_json(char *out, size_t capacity)
{
    if (!out || capacity == 0)
        return false;
    struct json_buffer json = { out, capacity, 0, true };
    append(&json, "[");
    for (int index = 0; index < CONFIG_FILE_COUNT; ++index) {
        const struct config_file *file = &config_files[index];
        append(&json, "%s{\"key\":\"%s\",\"filename\":\"%s\",\"title\":\"%s\",\"group\":\"%s\"}",
               index ? "," : "", file->key, file->filename, file->title, file->group);
    }
    append(&json, "]");
    return json.ok;
}

static void append_bytes(struct json_buffer *json, const unsigned char *bytes, size_t length)
{
    if (length >= json->capacity - json->size) {
        json->ok = false;
        return;
    }
    memcpy(json->out + json->size, bytes, length);
    json->size += length;
    json->out[json->size] = '\0';
}

static size_t utf8_width(const unsigned char *bytes, size_t remaining)
{
    unsigned char first = bytes[0];
    size_t width = 0;
    if (first >= 0xc2 && first <= 0xdf)
        width = 2;
    else if (first >= 0xe0 && first <= 0xef)
        width = 3;
    else if (first >= 0xf0 && first <= 0xf4)
        width = 4;

    if (!width || width > remaining)
        return 0;
    unsigned char second = bytes[1];
    if ((first == 0xe0 && second < 0xa0) || (first == 0xed && second >= 0xa0) ||
        (first == 0xf0 && second < 0x90) || (first == 0xf4 && second >= 0x90))
        return 0;
    for (size_t index = 1; index < width; ++index)
        if ((bytes[index] & 0xc0) != 0x80)
            return 0;
    return width;
}

static void append_file_text(struct json_buffer *json, const unsigned char *bytes, size_t length)
{
    append(json, "\"");
    for (size_t offset = 0; offset < length && json->ok; ++offset) {
        unsigned char byte = bytes[offset];
        switch (byte) {
        case '\r':
        case '\n':
            if (byte == '\r' && offset + 1 < length && bytes[offset + 1] == '\n')
                ++offset;
            append(json, "\\n");
            break;
        case '\t':
            append(json, "\\t");
            break;
        case '\\':
        case '"':
            append(json, "\\%c", byte);
            break;
        default:
            if (byte < 0x20 || byte == 0x7f) {
                append(json, "\\u%04x", (unsigned int)byte);
            } else if (byte < 0x80) {
                append_bytes(json, &bytes[offset], 1);
            } else {
                size_t width = utf8_width(bytes + offset, length - offset);
                if (width) {
                    append_bytes(json, bytes + offset, width);
                    offset += width - 1;
                } else {
                    append(json, "\\ufffd");
                }
            }
        }
    }
    append(json, "\"");
}

enum panel_settings_result panel_edit_file_json(const char *config_dir, const char *knot_dir,
                                               const char *key, char *out, size_t capacity)
{
    if (!key || !out || capacity == 0)
        return PANEL_SETTINGS_INVALID;
    const struct config_file *file = NULL;
    for (int index = 0; index < CONFIG_FILE_COUNT; ++index) {
        if (strcmp(key, config_files[index].key) == 0) {
            file = &config_files[index];
            break;
        }
    }
    if (!file)
        return PANEL_SETTINGS_INVALID;
    const char *directory = strncmp(file->key, "kresd_", 6) == 0 ? knot_dir : config_dir;
    if (!directory || !*directory)
        return PANEL_SETTINGS_UNAVAILABLE;

    FILE *input = NULL;
    unsigned long long size = 0;
    enum panel_settings_result result = panel_settings_open_regular(directory, file->filename, &input, &size);
    if (result != PANEL_SETTINGS_OK && result != PANEL_SETTINGS_MISSING)
        return result;
    struct json_buffer json = { out, capacity, 0, true };
    append(&json, "{\"key\":\"%s\",\"content\":", file->key);
    if (input) {
        if (size > CONFIG_FILE_LIMIT) {
            fclose(input);
            return PANEL_SETTINGS_TOO_LARGE;
        }
        unsigned char *content = malloc((size_t)size + 1);
        if (!content) {
            fclose(input);
            return PANEL_SETTINGS_ERROR;
        }
        size_t length = fread(content, 1, (size_t)size + 1, input);
        bool read_error = ferror(input) != 0;
        if (fclose(input) != 0)
            read_error = true;
        if (read_error)
            result = PANEL_SETTINGS_ERROR;
        else if (length > size)
            result = PANEL_SETTINGS_CONFLICT;
        else
            append_file_text(&json, content, length);
        free(content);
    } else {
        append(&json, "\"\"");
        result = PANEL_SETTINGS_OK;
    }
    append(&json, "}");
    return result != PANEL_SETTINGS_OK ? result : json.ok ? PANEL_SETTINGS_OK : PANEL_SETTINGS_TOO_LARGE;
}

static bool readable_directory(const char *path)
{
    if (!path || !*path)
        return false;
#ifdef _WIN32
    DWORD attributes = GetFileAttributesA(path);
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) &&
           !(attributes & FILE_ATTRIBUTE_REPARSE_POINT);
#else
    int directory = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0)
        return false;
    close(directory);
    return true;
#endif
}

bool panel_settings_diagnostics_json(bool tls, const char *profiles_dir, const char *config_dir,
                                     const char *knot_dir, char *out, size_t capacity)
{
    if (!out || capacity == 0)
        return false;
    struct check {
        const char *id;
        const char *title;
        const char *category;
        bool ok;
        const char *ok_detail;
        const char *warn_detail;
    } checks[] = {
        { "panel_http", "Доступность панели", "http", true,
          "Веб-сервер обработал запрос.", "" },
        { "panel_tls", "HTTPS", "https", tls,
          "TLS включён во встроенном веб-сервере.", "Встроенный сервер доступен по HTTP. TLS может завершаться на прокси." },
        { "panel_settings", "Хранилище настроек", "files", settings_db != NULL,
          "База настроек SQLite открыта.", "База настроек SQLite недоступна." },
        { "vpn_profiles", "Профили VPN", "files", readable_directory(profiles_dir),
          "Каталог профилей доступен для чтения.", "Каталог профилей не подключён или недоступен." },
        { "antizapret_lists", "Списки AntiZapret", "files", readable_directory(config_dir),
          "Каталог списков доступен для чтения.", "Каталог списков не подключён или недоступен." },
        { "knot_resolver", "Политики Knot Resolver", "files", readable_directory(knot_dir),
          "Каталог политик DNS доступен для чтения.", "Каталог политик DNS не подключён или недоступен." }
    };
    struct json_buffer json = { out, capacity, 0, true };
    append(&json, "{\"results\":[");
    int ok_count = 0;
    for (size_t index = 0; index < sizeof(checks) / sizeof(checks[0]); ++index) {
        const struct check *check = &checks[index];
        ok_count += check->ok;
        append(&json, "%s{\"check_id\":\"%s\",\"title\":\"%s\",\"category\":\"%s\","
                      "\"status\":\"%s\",\"detail\":\"%s\"}",
               index ? "," : "", check->id, check->title, check->category,
               check->ok ? "ok" : "warn", check->ok ? check->ok_detail : check->warn_detail);
    }
    append(&json, "],\"ok_count\":%d,\"warn_count\":%zu,\"fail_count\":0}",
           ok_count, sizeof(checks) / sizeof(checks[0]) - (size_t)ok_count);
    return json.ok;
}
