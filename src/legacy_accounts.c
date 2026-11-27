#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 700
#endif

#include "legacy_accounts.h"
#include "panel_auth_schema.h"

#include <sqlite3.h>

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <io.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

enum { PATH_LIMIT = 4096, MAX_ACCOUNTS = 10000, VM_STEPS = 1000, MAX_VM_INTERVALS = 5000 };

enum snapshot_state { SNAPSHOT_READY, SNAPSHOT_UNREADABLE, SNAPSHOT_NEEDS_CHECKPOINT };

struct assessment {
    unsigned int total;
    unsigned int admins;
    unsigned int users;
    unsigned int malformed_accounts;
    unsigned int inactive;
    unsigned int panel_login_disabled;
    unsigned int password_change_required;
    unsigned int totp_enabled;
    unsigned int totp_material_without_enrollment;
    unsigned int passkeys_enrolled;
    unsigned int telegram_linked;
    unsigned int access_deadline_set;
    unsigned int unrecognized_password_hash;
    unsigned int password_only_admin_candidates;
};

enum row_field {
    ROW_ADMIN, ROW_USER, ROW_MALFORMED, ROW_INACTIVE, ROW_PANEL_DISABLED, ROW_PASSWORD_CHANGE,
    ROW_TOTP, ROW_TOTP_UNENROLLED, ROW_PASSKEY, ROW_TELEGRAM, ROW_DEADLINE, ROW_BCRYPT
};

#define LEGACY_ACCOUNT_VALID \
    "(u.id>0 AND typeof(u.id)='integer' AND typeof(u.role)='text'" \
    " AND u.role COLLATE BINARY IN ('admin','user') AND typeof(u.username)='text'" \
    " AND length(u.username) BETWEEN 1 AND 64 AND length(CAST(u.username AS BLOB))<=256" \
    " AND instr(u.username,char(0))=0" \
    " AND typeof(u.is_active)='integer' AND u.is_active IN (0,1)" \
    " AND typeof(u.panel_login_enabled)='integer' AND u.panel_login_enabled IN (0,1)" \
    " AND typeof(u.must_change_password)='integer' AND u.must_change_password IN (0,1)" \
    " AND typeof(u.totp_enabled)='integer' AND u.totp_enabled IN (0,1)" \
    " AND (u.access_until IS NULL OR (typeof(u.access_until)='text'" \
    " AND length(CAST(u.access_until AS BLOB))<=64 AND instr(u.access_until,char(0))=0)))"

#define LEGACY_PASSKEY \
    "EXISTS(SELECT 1 FROM main.webauthn_credentials AS w WHERE w.user_id=u.id)"

#define LEGACY_BCRYPT \
    "typeof(u.password_hash)='text' AND length(CAST(u.password_hash AS BLOB))=60" \
    " AND instr(u.password_hash,char(0))=0 AND substr(u.password_hash,1,4) IN ('$2a$','$2b$','$2y$')" \
    " AND substr(u.password_hash,5,3) GLOB '[0-9][0-9]$'" \
    " AND CAST(substr(u.password_hash,5,2) AS INTEGER) BETWEEN 4 AND 31" \
    " AND substr(u.password_hash,8) NOT GLOB '*[^./A-Za-z0-9]*'" \
    " AND substr(u.password_hash,29,1) GLOB '[.Oeu]'" \
    " AND substr(u.password_hash,60,1) GLOB '[.CGKOSWaeimquy26]'"

static bool regular_file(const char *path)
{
#ifdef _WIN32
    DWORD attributes = GetFileAttributesA(path);
    return attributes != INVALID_FILE_ATTRIBUTES &&
           !(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_REPARSE_POINT));
#else
    struct stat info;
    return lstat(path, &info) == 0 && S_ISREG(info.st_mode);
#endif
}

static enum snapshot_state check_sidecars(const char *path)
{
    static const char *const suffixes[] = {"-wal", "-shm", "-journal"};
    char sidecar[PATH_LIMIT + sizeof("-journal")];
    for (size_t i = 0; i < sizeof(suffixes) / sizeof(suffixes[0]); ++i) {
        snprintf(sidecar, sizeof(sidecar), "%s%s", path, suffixes[i]);
#ifdef _WIN32
        WIN32_FILE_ATTRIBUTE_DATA info;
        if (!GetFileAttributesExA(sidecar, GetFileExInfoStandard, &info)) {
            DWORD error = GetLastError();
            if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
                return SNAPSHOT_UNREADABLE;
        } else if (info.nFileSizeHigh || info.nFileSizeLow ||
                   (info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT))) {
            return SNAPSHOT_NEEDS_CHECKPOINT;
        }
#else
        struct stat info;
        if (lstat(sidecar, &info) != 0) {
            if (errno != ENOENT)
                return SNAPSHOT_UNREADABLE;
        } else if (!S_ISREG(info.st_mode) || info.st_size != 0) {
            return SNAPSHOT_NEEDS_CHECKPOINT;
        }
#endif
    }
    return SNAPSHOT_READY;
}

static enum snapshot_state open_snapshot(const char *path, sqlite3 **db)
{
    if (!path || !path[0] || strlen(path) >= PATH_LIMIT || !regular_file(path))
        return SNAPSHOT_UNREADABLE;

    char absolute[PATH_LIMIT];
#ifdef _WIN32
    if (!_fullpath(absolute, path, sizeof(absolute)))
        return SNAPSHOT_UNREADABLE;
#else
    char *resolved = realpath(path, NULL);
    if (!resolved)
        return SNAPSHOT_UNREADABLE;
    size_t length = strlen(resolved);
    if (length < sizeof(absolute))
        memcpy(absolute, resolved, length + 1);
    free(resolved);
    if (length >= sizeof(absolute))
        return SNAPSHOT_UNREADABLE;
#endif

    /* An immutable URI keeps SQLite from creating lock files. An offline snapshot must include all committed pages. */
    enum snapshot_state state = check_sidecars(absolute);
    if (state != SNAPSHOT_READY)
        return state;

    static const char hex[] = "0123456789abcdef";
    static const char uri_options[] = "?mode=ro&immutable=1";
    char uri[sizeof("file:/") + 3 * PATH_LIMIT + sizeof(uri_options)];
    memcpy(uri, "file:", sizeof("file:") - 1);
    size_t used = sizeof("file:") - 1;
#ifdef _WIN32
    uri[used++] = '/';
#endif
    for (const unsigned char *next = (const unsigned char *)absolute; *next; ++next) {
        unsigned char ch = *next;
#ifdef _WIN32
        if (ch == '\\')
            ch = '/';
#endif
        if (ch == '/' || ch == ':' || ch == '.' || ch == '-' || ch == '_' ||
            (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z')) {
            uri[used++] = (char)ch;
        } else {
            uri[used++] = '%';
            uri[used++] = hex[ch >> 4];
            uri[used++] = hex[ch & 15];
        }
    }
    memcpy(uri + used, uri_options, sizeof(uri_options));

    int flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_URI;
#ifdef SQLITE_OPEN_NOFOLLOW
    flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    return sqlite3_open_v2(uri, db, flags, NULL) == SQLITE_OK ? SNAPSHOT_READY : SNAPSHOT_UNREADABLE;
}

static int progress_limit(void *context)
{
    unsigned int *remaining = context;
    return *remaining == 0 || --*remaining == 0;
}

static int check_schema(sqlite3 *db)
{
    /* Authentication columns and indexes used by the schema at upstream d6ccd0098. */
    static const char sql[] =
        "SELECT (SELECT count(*) FROM pragma_table_list"
        " WHERE schema='main' AND type='table' AND name IN ('users','webauthn_credentials'))=2"
        " AND (SELECT count(*) FROM pragma_table_xinfo('users','main') WHERE hidden=0 AND name IN ("
        " 'id','username','password_hash','role','is_active','panel_login_enabled','must_change_password',"
        " 'totp_enabled','totp_secret_encrypted','totp_backup_codes_encrypted','telegram_id','access_until'))=12"
        " AND EXISTS(SELECT 1 FROM pragma_table_xinfo('users','main') WHERE name='id' AND upper(type)='INTEGER' AND pk=1)"
        " AND EXISTS(SELECT 1 FROM pragma_index_list('users','main') AS l"
        " JOIN pragma_index_xinfo(l.name,'main') AS x WHERE l.\"unique\" AND NOT l.partial AND x.\"key\""
        " GROUP BY l.name HAVING count(*)=1 AND max(x.name='username' AND x.coll='BINARY'))"
        " AND EXISTS(SELECT 1 FROM pragma_table_xinfo('webauthn_credentials','main')"
        " WHERE name='user_id' AND upper(type)='INTEGER' AND hidden=0)"
        " AND EXISTS(SELECT 1 FROM pragma_foreign_key_list('webauthn_credentials','main')"
        " WHERE \"table\"='users' AND \"from\"='user_id' AND \"to\"='id')"
        " AND EXISTS(SELECT 1 FROM pragma_index_list('webauthn_credentials','main') AS l"
        " JOIN pragma_index_xinfo(l.name,'main') AS x ON x.seqno=0 AND x.name='user_id' AND x.\"key\""
        " WHERE NOT l.partial)";
    sqlite3_stmt *statement = NULL;
    int result = sqlite3_prepare_v2(db, sql, -1, &statement, NULL);
    if (result == SQLITE_OK) {
        result = sqlite3_step(statement);
        if (result == SQLITE_ROW)
            result = sqlite3_column_int(statement, 0) ? SQLITE_OK : SQLITE_SCHEMA;
    }
    sqlite3_finalize(statement);
    return result;
}

static void count_account(sqlite3_stmt *row, struct assessment *stats)
{
    bool admin = sqlite3_column_int(row, ROW_ADMIN) != 0;
    bool malformed = sqlite3_column_int(row, ROW_MALFORMED) != 0;
    bool inactive = sqlite3_column_int(row, ROW_INACTIVE) != 0;
    bool panel_disabled = sqlite3_column_int(row, ROW_PANEL_DISABLED) != 0;
    bool password_change = sqlite3_column_int(row, ROW_PASSWORD_CHANGE) != 0;
    bool totp = sqlite3_column_int(row, ROW_TOTP) != 0;
    bool totp_unenrolled = sqlite3_column_int(row, ROW_TOTP_UNENROLLED) != 0;
    bool passkey = sqlite3_column_int(row, ROW_PASSKEY) != 0;
    bool telegram = sqlite3_column_int(row, ROW_TELEGRAM) != 0;
    bool deadline = sqlite3_column_int(row, ROW_DEADLINE) != 0;
    bool bcrypt = sqlite3_column_int(row, ROW_BCRYPT) != 0;

    stats->admins += admin;
    stats->users += sqlite3_column_int(row, ROW_USER) != 0;
    stats->malformed_accounts += malformed;
    stats->inactive += inactive;
    stats->panel_login_disabled += panel_disabled;
    stats->password_change_required += password_change;
    stats->totp_enabled += totp;
    stats->totp_material_without_enrollment += totp_unenrolled;
    stats->passkeys_enrolled += passkey;
    stats->telegram_linked += telegram;
    stats->access_deadline_set += deadline;
    stats->unrecognized_password_hash += !bcrypt;
    stats->password_only_admin_candidates += admin && bcrypt && !malformed && !inactive && !panel_disabled &&
        !password_change && !totp && !totp_unenrolled && !passkey && !telegram && !deadline;
}

static int assess_rows(sqlite3 *db, struct assessment *stats)
{
    /* Return only policy flags. No credential or identifying data leaves SQLite. */
    static const char sql[] =
        "SELECT u.role COLLATE BINARY='admin', u.role COLLATE BINARY='user',"
        " NOT COALESCE(" LEGACY_ACCOUNT_VALID ",0),"
        " u.is_active=0, u.panel_login_enabled=0, u.must_change_password=1, u.totp_enabled=1,"
        " u.totp_enabled=0 AND (u.totp_secret_encrypted IS NOT NULL OR u.totp_backup_codes_encrypted IS NOT NULL),"
        " " LEGACY_PASSKEY ","
        " u.telegram_id IS NOT NULL, u.access_until IS NOT NULL,"
        " " LEGACY_BCRYPT
        " FROM main.users AS u LIMIT ?";
    sqlite3_stmt *statement = NULL;
    int result = sqlite3_prepare_v2(db, sql, -1, &statement, NULL);
    if (result == SQLITE_OK)
        result = sqlite3_bind_int(statement, 1, MAX_ACCOUNTS + 1);
    if (result == SQLITE_OK) {
        while ((result = sqlite3_step(statement)) == SQLITE_ROW) {
            if (stats->total == MAX_ACCOUNTS) {
                result = SQLITE_TOOBIG;
                break;
            }
            ++stats->total;
            count_account(statement, stats);
        }
    }
    sqlite3_finalize(statement);
    return result;
}

static bool protect_snapshot(sqlite3 *db)
{
    sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 1024 * 1024);
    return sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, NULL) == SQLITE_OK &&
           sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, NULL) == SQLITE_OK;
}

sqlite3 *legacy_accounts_open_readonly(const char *path)
{
    sqlite3 *db = NULL;
    if (open_snapshot(path, &db) == SNAPSHOT_READY && protect_snapshot(db))
        return db;
    sqlite3_close(db);
    return NULL;
}

static int inspect_snapshot(sqlite3 *db, struct assessment *stats)
{
    if (!protect_snapshot(db))
        return SQLITE_ERROR;

    unsigned int remaining = MAX_VM_INTERVALS;
    sqlite3_progress_handler(db, VM_STEPS, progress_limit, &remaining);
    int result = check_schema(db);
    if (result == SQLITE_OK)
        result = assess_rows(db, stats);
    sqlite3_progress_handler(db, 0, NULL, NULL);
    return result;
}

size_t legacy_accounts_inspect_json(char *out, size_t capacity, const char *path)
{
    if (!out || !capacity)
        return 0;

    sqlite3 *db = NULL;
    struct assessment stats = {0};
    enum snapshot_state snapshot = open_snapshot(path, &db);
    int result = snapshot == SNAPSHOT_READY ? inspect_snapshot(db, &stats) : SQLITE_CANTOPEN;
    sqlite3_close(db);

    int size;
    if (result == SQLITE_DONE) {
        size = snprintf(out, capacity,
            "{\"state\":\"assessed\",\"credential_import_supported\":true,\"accounts\":%u,\"admins\":%u,\"users\":%u,"
            "\"malformed_accounts\":%u,\"inactive\":%u,\"panel_login_disabled\":%u,\"password_change_required\":%u,"
            "\"totp_enabled\":%u,\"totp_material_without_enrollment\":%u,\"passkeys_enrolled\":%u,\"telegram_linked\":%u,"
            "\"access_deadline_set\":%u,\"unrecognized_password_hash\":%u,\"password_only_admin_candidates\":%u}",
            stats.total, stats.admins, stats.users, stats.malformed_accounts, stats.inactive,
            stats.panel_login_disabled, stats.password_change_required, stats.totp_enabled,
            stats.totp_material_without_enrollment, stats.passkeys_enrolled, stats.telegram_linked,
            stats.access_deadline_set, stats.unrecognized_password_hash, stats.password_only_admin_candidates);
    } else {
        const char *state = "unreadable";
        if (snapshot == SNAPSHOT_NEEDS_CHECKPOINT)
            state = "requires_offline_snapshot";
        else if (result == SQLITE_SCHEMA)
            state = "unsupported_schema";
        else if (result == SQLITE_TOOBIG || result == SQLITE_INTERRUPT)
            state = "assessment_limit_reached";
        size = snprintf(out, capacity, "{\"state\":\"%s\",\"credential_import_supported\":false}", state);
    }

    if (size < 0 || (size_t)size >= capacity) {
        out[0] = '\0';
        return 0;
    }
    return (size_t)size;
}

enum migration_column {
    MIGRATION_ID, MIGRATION_USERNAME, MIGRATION_BCRYPT, MIGRATION_ROLE, MIGRATION_ACTIVE,
    MIGRATION_PANEL_LOGIN, MIGRATION_PASSWORD_CHANGE, MIGRATION_TOTP, MIGRATION_PASSKEY,
    MIGRATION_ACCESS_UNTIL, MIGRATION_COLUMNS
};

static const char source_accounts[] =
    "SELECT u.id,u.username,CASE WHEN " LEGACY_BCRYPT " THEN u.password_hash ELSE NULL END,"
    " u.role,u.is_active,u.panel_login_enabled,u.must_change_password,u.totp_enabled,"
    LEGACY_PASSKEY ",u.access_until, " LEGACY_ACCOUNT_VALID
    " FROM main.users AS u ORDER BY u.id LIMIT ?";

static bool valid_source_account(sqlite3_stmt *source)
{
    const unsigned char *username = sqlite3_column_text(source, MIGRATION_USERNAME);
    int length = sqlite3_column_bytes(source, MIGRATION_USERNAME);
    return sqlite3_column_int(source, MIGRATION_COLUMNS) == 1 && length > 0 &&
           panel_auth_valid_username(username, (size_t)length);
}

static bool insert_account(sqlite3_stmt *source, sqlite3_stmt *account, sqlite3_stmt *policy)
{
    sqlite3_reset(account);
    if (sqlite3_bind_value(account, 1, sqlite3_column_value(source, MIGRATION_ID)) != SQLITE_OK ||
        sqlite3_bind_value(account, 2, sqlite3_column_value(source, MIGRATION_USERNAME)) != SQLITE_OK ||
        sqlite3_step(account) != SQLITE_DONE)
        return false;

    sqlite3_reset(policy);
    if (sqlite3_bind_value(policy, 1, sqlite3_column_value(source, MIGRATION_ID)) != SQLITE_OK)
        return false;
    for (int field = MIGRATION_BCRYPT; field < MIGRATION_COLUMNS; ++field) {
        if (sqlite3_bind_value(policy, field, sqlite3_column_value(source, field)) != SQLITE_OK)
            return false;
    }
    return sqlite3_step(policy) == SQLITE_DONE;
}

static bool copy_accounts(sqlite3 *target, sqlite3_stmt *source)
{
    static const char account_sql[] = "INSERT INTO panel_accounts VALUES (?,?,zeroblob(16),zeroblob(32),300000)";
    static const char policy_sql[] =
        "INSERT INTO panel_legacy_accounts(account_id,bcrypt_hash,role,is_active,panel_login_enabled,"
        " must_change_password,totp_enabled,has_passkeys,access_until,native_password_set) VALUES (?,?,?,?,?,?,?,?,?,0)";
    sqlite3_stmt *account = NULL;
    sqlite3_stmt *policy = NULL;
    bool success = sqlite3_prepare_v2(target, account_sql, -1, &account, NULL) == SQLITE_OK &&
                   sqlite3_prepare_v2(target, policy_sql, -1, &policy, NULL) == SQLITE_OK;
    unsigned int imported = 0;
    int result = SQLITE_ERROR;
    while (success && (result = sqlite3_step(source)) == SQLITE_ROW) {
        success = ++imported <= MAX_ACCOUNTS && valid_source_account(source) &&
                  insert_account(source, account, policy);
    }
    sqlite3_finalize(policy);
    sqlite3_finalize(account);
    return success && imported > 0 && result == SQLITE_DONE;
}

static bool same_column(sqlite3_stmt *source, sqlite3_stmt *target, int field)
{
    int type = sqlite3_column_type(source, field);
    if (sqlite3_column_type(target, field) != type)
        return false;
    if (type == SQLITE_NULL)
        return true;
    if (type == SQLITE_INTEGER)
        return sqlite3_column_int64(source, field) == sqlite3_column_int64(target, field);
    const unsigned char *left = sqlite3_column_text(source, field);
    const unsigned char *right = sqlite3_column_text(target, field);
    int length = sqlite3_column_bytes(source, field);
    return left && right && length == sqlite3_column_bytes(target, field) && !memcmp(left, right, (size_t)length);
}

static bool same_account(sqlite3_stmt *source, sqlite3_stmt *target)
{
    if (!valid_source_account(source) || sqlite3_column_int(target, MIGRATION_COLUMNS + 1) != 1)
        return false;
    bool upgraded = sqlite3_column_int(target, MIGRATION_COLUMNS) == 1;
    if (upgraded && sqlite3_column_type(target, MIGRATION_BCRYPT) != SQLITE_NULL)
        return false;
    for (int field = MIGRATION_ID; field < MIGRATION_COLUMNS; ++field) {
        if (!(upgraded && (field == MIGRATION_BCRYPT || field == MIGRATION_PASSWORD_CHANGE)) &&
            !same_column(source, target, field))
            return false;
    }
    return true;
}

static bool same_import(const char *destination, sqlite3_stmt *source)
{
    static const char sql[] =
        "SELECT a.id,a.username,l.bcrypt_hash,l.role,l.is_active,l.panel_login_enabled,l.must_change_password,"
        " l.totp_enabled,l.has_passkeys,l.access_until,l.native_password_set,l.from_legacy FROM main.panel_accounts AS a"
        " LEFT JOIN main.panel_legacy_accounts AS l ON l.account_id=a.id ORDER BY a.id LIMIT ?";
    sqlite3 *db = NULL;
    sqlite3_stmt *target = NULL;
    bool success = open_snapshot(destination, &db) == SNAPSHOT_READY && protect_snapshot(db) &&
                   sqlite3_prepare_v2(db, sql, -1, &target, NULL) == SQLITE_OK &&
                   sqlite3_bind_int(target, 1, MAX_ACCOUNTS + 1) == SQLITE_OK;
    unsigned int count = 0;
    int result = SQLITE_ERROR;
    while (success && (result = sqlite3_step(source)) == SQLITE_ROW)
        success = ++count <= MAX_ACCOUNTS && sqlite3_step(target) == SQLITE_ROW && same_account(source, target);
    success = success && count > 0 && result == SQLITE_DONE && sqlite3_step(target) == SQLITE_DONE;
    sqlite3_finalize(target);
    sqlite3_close(db);
    return success;
}

static bool create_staging_file(const char *path)
{
#ifdef _WIN32
    HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    return file != INVALID_HANDLE_VALUE && CloseHandle(file);
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    return fd >= 0 && close(fd) == 0;
#endif
}

static bool publish_staged_file(const char *staged, const char *destination)
{
#ifdef _WIN32
    return MoveFileA(staged, destination) != 0;
#else
    return link(staged, destination) == 0;
#endif
}

static bool stage_import(const char *destination, sqlite3_stmt *source)
{
    unsigned char random[8];
    sqlite3_randomness(sizeof(random), random);
    char staged[PATH_LIMIT + 32];
    snprintf(staged, sizeof(staged), "%s.apaz-accounts-%02x%02x%02x%02x%02x%02x%02x%02x", destination,
             (unsigned int)random[0], (unsigned int)random[1], (unsigned int)random[2], (unsigned int)random[3],
             (unsigned int)random[4], (unsigned int)random[5], (unsigned int)random[6], (unsigned int)random[7]);
    if (!create_staging_file(staged))
        return false;

    sqlite3 *target = NULL;
    int flags = SQLITE_OPEN_READWRITE;
#ifdef SQLITE_OPEN_NOFOLLOW
    flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    bool success = sqlite3_open_v2(staged, &target, flags, NULL) == SQLITE_OK && protect_snapshot(target) &&
        sqlite3_exec(target, "PRAGMA foreign_keys = ON; BEGIN IMMEDIATE;" PANEL_AUTH_SCHEMA,
                     NULL, NULL, NULL) == SQLITE_OK && copy_accounts(target, source) &&
        sqlite3_exec(target, "COMMIT", NULL, NULL, NULL) == SQLITE_OK;
    if (sqlite3_close(target) != SQLITE_OK)
        success = false;
    if (success && !publish_staged_file(staged, destination)) {
        sqlite3_reset(source);
        success = same_import(destination, source);
    }
    remove(staged);
    return success;
}

bool legacy_accounts_import(const char *path, const char *destination)
{
    if (!destination || !destination[0] || strlen(destination) >= PATH_LIMIT)
        return false;
#ifdef _WIN32
    const char *colon = strchr(destination, ':');
    if (colon && (colon != destination + 1 || strchr(colon + 1, ':')))
        return false;
#endif
    sqlite3 *db = NULL;
    sqlite3_stmt *source = NULL;
    unsigned int remaining = MAX_VM_INTERVALS;
    bool success = open_snapshot(path, &db) == SNAPSHOT_READY && protect_snapshot(db);
    if (success) {
        sqlite3_progress_handler(db, VM_STEPS, progress_limit, &remaining);
        success = check_schema(db) == SQLITE_OK &&
                  sqlite3_prepare_v2(db, source_accounts, -1, &source, NULL) == SQLITE_OK &&
                  sqlite3_bind_int(source, 1, MAX_ACCOUNTS + 1) == SQLITE_OK;
    }
    if (success)
        success = regular_file(destination) ? same_import(destination, source) : stage_import(destination, source);
    sqlite3_finalize(source);
    sqlite3_close(db);
    return success;
}
