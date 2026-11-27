#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "panel_telegram.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <sqlite3.h>
#include <string.h>

#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

enum {
    FUTURE_SKEW = 30, BOT_USERNAME_MIN = 5, BOT_TOKEN_SECRET_MIN = 16,
    MAX_IMPORT_ACCOUNTS = 10000, VM_STEPS = 1000, MAX_VM_INTERVALS = 5000
};

static sqlite3 *database;

static bool execute(sqlite3 *db, const char *sql)
{
    return db && sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static sqlite3_stmt *prepare(sqlite3 *db, const char *sql)
{
    sqlite3_stmt *stmt = NULL;
    if (!db || sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        sqlite3_finalize(stmt);
        return NULL;
    }
    return stmt;
}

static bool ensure_private_file(const char *path)
{
#ifndef _WIN32
    if (strcmp(path, ":memory:") != 0) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd >= 0)
            return close(fd) == 0;
        struct stat info;
        return errno == EEXIST && lstat(path, &info) == 0 && S_ISREG(info.st_mode) &&
               !(info.st_mode & (S_IRWXG | S_IRWXO)) && info.st_uid == geteuid();
    }
#else
    (void)path;
#endif
    return true;
}

bool panel_telegram_open(const char *path)
{
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS telegram_settings ("
        " id INTEGER PRIMARY KEY CHECK(id=1), username TEXT NOT NULL DEFAULT '',"
        " token TEXT NOT NULL DEFAULT '', max_age INTEGER NOT NULL DEFAULT 300 CHECK(max_age BETWEEN 30 AND 86400),"
        " legacy_enabled INTEGER NOT NULL DEFAULT 0 CHECK(legacy_enabled IN (0,1)),"
        " mini_enabled INTEGER NOT NULL DEFAULT 0 CHECK(mini_enabled IN (0,1))"
        ");"
        "INSERT INTO telegram_settings(id) VALUES (1) ON CONFLICT(id) DO NOTHING;"
        "CREATE TABLE IF NOT EXISTS telegram_identity ("
        " account_id INTEGER PRIMARY KEY CHECK(account_id > 0),"
        " telegram_id INTEGER NOT NULL UNIQUE CHECK(telegram_id > 0)"
        ");"
        "CREATE TABLE IF NOT EXISTS telegram_proof ("
        " proof BLOB PRIMARY KEY CHECK(length(proof) = 32), expires_at INTEGER NOT NULL"
        ") WITHOUT ROWID;"
        "CREATE INDEX IF NOT EXISTS telegram_proof_expiry ON telegram_proof(expires_at);"
        "CREATE TABLE IF NOT EXISTS telegram_legacy_import (id INTEGER PRIMARY KEY CHECK(id=1),"
        " digest BLOB NOT NULL CHECK(length(digest)=32));";
    if (database || !path || !*path || !ensure_private_file(path))
        return false;

    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
#ifdef SQLITE_OPEN_NOFOLLOW
    flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    if (sqlite3_open_v2(path, &database, flags, NULL) != SQLITE_OK ||
        sqlite3_busy_timeout(database, 75) != SQLITE_OK ||
        !execute(database, "PRAGMA trusted_schema=OFF; PRAGMA cache_size=-64; PRAGMA secure_delete=ON; BEGIN IMMEDIATE") ||
        !execute(database, schema) || !execute(database, "COMMIT")) {
        panel_telegram_close();
        return false;
    }
    return true;
}

void panel_telegram_close(void)
{
    sqlite3_close(database);
    database = NULL;
}

static bool digit(unsigned char ch)
{
    return ch >= '0' && ch <= '9';
}

static bool letter(unsigned char ch)
{
    return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
}

static bool valid_username(const char *name, size_t len)
{
    if (!len)
        return true;
    if (len < BOT_USERNAME_MIN || len > PANEL_TELEGRAM_USERNAME_MAX || !letter((unsigned char)name[0]))
        return false;
    for (size_t i = 1; i < len; ++i) {
        unsigned char ch = (unsigned char)name[i];
        if (!letter(ch) && !digit(ch) && ch != '_')
            return false;
    }
    return (name[len - 3] == 'b' || name[len - 3] == 'B') &&
           (name[len - 2] == 'o' || name[len - 2] == 'O') &&
           (name[len - 1] == 't' || name[len - 1] == 'T');
}

static size_t bounded_length(const char *text, size_t capacity)
{
    size_t length = 0;
    while (length < capacity && text[length])
        ++length;
    return length;
}

static bool valid_token(const char *token, size_t len)
{
    if (!len)
        return true;
    if (len > PANEL_TELEGRAM_TOKEN_MAX || token[0] == '0')
        return false;
    size_t colon = 0;
    while (colon < len && digit((unsigned char)token[colon]))
        ++colon;
    if (colon == 0 || colon > 19 || colon == len || token[colon] != ':' ||
        len - colon - 1 < BOT_TOKEN_SECRET_MIN)
        return false;
    for (size_t i = colon + 1; i < len; ++i) {
        unsigned char ch = (unsigned char)token[i];
        if (!letter(ch) && !digit(ch) && ch != '_' && ch != '-')
            return false;
    }
    return true;
}

static bool read_settings(struct panel_telegram_settings *settings,
                          char token[PANEL_TELEGRAM_TOKEN_MAX + 1])
{
    sqlite3_stmt *stmt = prepare(database, "SELECT username,token,max_age,legacy_enabled,mini_enabled"
                                          " FROM telegram_settings WHERE id=1");
    bool success = false;
    if (stmt && sqlite3_step(stmt) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(stmt, 0);
        size_t name_len = (size_t)sqlite3_column_bytes(stmt, 0);
        const char *secret = (const char *)sqlite3_column_text(stmt, 1);
        size_t len = (size_t)sqlite3_column_bytes(stmt, 1);
        if (name && secret && valid_username(name, name_len) && valid_token(secret, len)) {
            memcpy(settings->username, name, name_len + 1);
            if (token)
                memcpy(token, secret, len + 1);
            settings->token_configured = len > 0;
            settings->max_age = (unsigned int)sqlite3_column_int(stmt, 2);
            settings->legacy_enabled = sqlite3_column_int(stmt, 3) != 0;
            settings->mini_enabled = sqlite3_column_int(stmt, 4) != 0;
            success = true;
        }
    }
    sqlite3_finalize(stmt);
    return success;
}

bool panel_telegram_settings_get(struct panel_telegram_settings *settings)
{
    if (!settings)
        return false;
    *settings = (struct panel_telegram_settings){0};
    return read_settings(settings, NULL);
}

enum panel_telegram_result panel_telegram_settings_set(const struct panel_telegram_settings *settings,
                                                      const char *replacement_token)
{
    if (!settings)
        return PANEL_TELEGRAM_INVALID;
    size_t name_len = bounded_length(settings->username, sizeof(settings->username));
    size_t token_len = replacement_token ? bounded_length(replacement_token, PANEL_TELEGRAM_TOKEN_MAX + 1) : 0;
    if (!valid_username(settings->username, name_len) ||
        (replacement_token && !valid_token(replacement_token, token_len)) ||
        settings->max_age < TELEGRAM_AUTH_MIN_TTL || settings->max_age > TELEGRAM_AUTH_MAX_TTL)
        return PANEL_TELEGRAM_INVALID;
    if (settings->legacy_enabled && !name_len)
        return PANEL_TELEGRAM_INVALID;

    sqlite3_stmt *stmt = prepare(database, "UPDATE telegram_settings SET username=?1, token=coalesce(?2,token),"
        " max_age=?3, legacy_enabled=?4, mini_enabled=?5 WHERE id=1"
        " AND ((?4=0 AND ?5=0) OR coalesce(?2,token)<>'')");
    enum panel_telegram_result result = PANEL_TELEGRAM_ERROR;
    if (stmt && sqlite3_bind_text(stmt, 1, settings->username, (int)name_len, SQLITE_STATIC) == SQLITE_OK &&
        (!replacement_token || sqlite3_bind_text(stmt, 2, replacement_token, (int)token_len, SQLITE_STATIC) == SQLITE_OK) &&
        sqlite3_bind_int(stmt, 3, (int)settings->max_age) == SQLITE_OK &&
        sqlite3_bind_int(stmt, 4, settings->legacy_enabled) == SQLITE_OK &&
        sqlite3_bind_int(stmt, 5, settings->mini_enabled) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_DONE)
        result = sqlite3_changes(database) == 1 ? PANEL_TELEGRAM_OK : PANEL_TELEGRAM_INVALID;
    sqlite3_finalize(stmt);
    return result;
}

static bool find_identity(const char *sql, int64_t id, int64_t *other)
{
    *other = 0;
    sqlite3_stmt *stmt = prepare(database, sql);
    int step = stmt && sqlite3_bind_int64(stmt, 1, id) == SQLITE_OK ? sqlite3_step(stmt) : SQLITE_ERROR;
    if (step == SQLITE_ROW)
        *other = sqlite3_column_int64(stmt, 0);
    sqlite3_finalize(stmt);
    return step == SQLITE_DONE || step == SQLITE_ROW;
}

bool panel_telegram_bound(int64_t account_id, uint64_t *telegram_id)
{
    if (!telegram_id)
        return false;
    int64_t id = 0;
    bool success = account_id > 0 && find_identity("SELECT telegram_id FROM telegram_identity WHERE account_id=?",
                                                   account_id, &id);
    *telegram_id = (uint64_t)id;
    return success;
}

bool panel_telegram_unlink(int64_t account_id)
{
    if (account_id <= 0)
        return false;
    sqlite3_stmt *stmt = prepare(database, "DELETE FROM telegram_identity WHERE account_id=?");
    bool success = stmt && sqlite3_bind_int64(stmt, 1, account_id) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    return success;
}

static enum panel_telegram_result check_proof(bool mini, const char *data, size_t size, uint64_t now,
                                             struct telegram_auth_identity *identity)
{
    struct panel_telegram_settings settings;
    char token[PANEL_TELEGRAM_TOKEN_MAX + 1] = {0};
    enum panel_telegram_result result = PANEL_TELEGRAM_ERROR;
    if (read_settings(&settings, token)) {
        if (!settings.token_configured || !(mini ? settings.mini_enabled : settings.legacy_enabled)) {
            result = PANEL_TELEGRAM_DISABLED;
        } else {
            bool valid = mini ? telegram_auth_verify_init_data(data, size, token, now, settings.max_age,
                                                               FUTURE_SKEW, identity)
                              : telegram_auth_verify_widget(data, size, token, now, settings.max_age,
                                                             FUTURE_SKEW, identity);
            result = valid ? PANEL_TELEGRAM_OK : PANEL_TELEGRAM_DENIED;
        }
    }
    OPENSSL_cleanse(token, sizeof(token));
    return result;
}

static enum panel_telegram_result record_proof(const struct telegram_auth_identity *identity, uint64_t now)
{
    sqlite3_stmt *stmt = prepare(database, "DELETE FROM telegram_proof WHERE expires_at<?");
    bool pruned = stmt && sqlite3_bind_int64(stmt, 1, (int64_t)now) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_DONE;
    sqlite3_finalize(stmt);
    if (!pruned)
        return PANEL_TELEGRAM_ERROR;

    /* Use the maximum possible age for retention, including if settings are changed after this login. */
    int64_t expiry = (int64_t)(identity->auth_date + TELEGRAM_AUTH_MAX_TTL);
    stmt = prepare(database, "INSERT INTO telegram_proof(proof,expires_at) VALUES (?,?) ON CONFLICT(proof) DO NOTHING");
    enum panel_telegram_result result = PANEL_TELEGRAM_ERROR;
    if (stmt && sqlite3_bind_blob(stmt, 1, identity->proof, sizeof(identity->proof), SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_int64(stmt, 2, expiry) == SQLITE_OK && sqlite3_step(stmt) == SQLITE_DONE)
        result = sqlite3_changes(database) == 1 ? PANEL_TELEGRAM_OK : PANEL_TELEGRAM_REPLAY;
    sqlite3_finalize(stmt);
    return result;
}

static bool valid_proof_request(const char *data, size_t size, uint64_t now)
{
    return data && size > 0 && size <= TELEGRAM_AUTH_DATA_MAX && now > 0 &&
           now <= INT64_MAX - TELEGRAM_AUTH_MAX_TTL - FUTURE_SKEW;
}

static enum panel_telegram_result write_link(int64_t account_id, uint64_t telegram_id)
{
    sqlite3_stmt *stmt = prepare(database, "INSERT INTO telegram_identity(account_id,telegram_id) VALUES (?,?) "
                                          "ON CONFLICT DO NOTHING");
    int step = stmt && sqlite3_bind_int64(stmt, 1, account_id) == SQLITE_OK &&
                       sqlite3_bind_int64(stmt, 2, (int64_t)telegram_id) == SQLITE_OK ? sqlite3_step(stmt) : SQLITE_ERROR;
    sqlite3_finalize(stmt);
    if (step != SQLITE_DONE)
        return PANEL_TELEGRAM_ERROR;
    if (sqlite3_changes(database) == 1)
        return PANEL_TELEGRAM_OK;

    uint64_t existing;
    if (!panel_telegram_bound(account_id, &existing))
        return PANEL_TELEGRAM_ERROR;
    return existing == telegram_id ? PANEL_TELEGRAM_OK : PANEL_TELEGRAM_CONFLICT;
}

static enum panel_telegram_result finish_claim(enum panel_telegram_result result)
{
    if (result == PANEL_TELEGRAM_OK) {
        if (execute(database, "COMMIT"))
            return result;
        result = PANEL_TELEGRAM_ERROR;
    }
    execute(database, "ROLLBACK");
    return result;
}

enum panel_telegram_result panel_telegram_link(int64_t account_id, bool mini, const char *data, size_t size, uint64_t now)
{
    if (account_id <= 0 || !valid_proof_request(data, size, now))
        return PANEL_TELEGRAM_INVALID;
    if (!execute(database, "BEGIN IMMEDIATE"))
        return PANEL_TELEGRAM_ERROR;
    struct telegram_auth_identity identity;
    enum panel_telegram_result result = check_proof(mini, data, size, now, &identity);
    if (result == PANEL_TELEGRAM_OK)
        result = record_proof(&identity, now);
    if (result == PANEL_TELEGRAM_OK)
        result = write_link(account_id, identity.user_id);
    return finish_claim(result);
}

static enum panel_telegram_result login_proof(bool mini, const char *data, size_t size, uint64_t now,
                                              int64_t *account_id, bool consume)
{
    if (!account_id)
        return PANEL_TELEGRAM_INVALID;
    *account_id = 0;
    if (!valid_proof_request(data, size, now))
        return PANEL_TELEGRAM_INVALID;
    if (!execute(database, consume ? "BEGIN IMMEDIATE" : "BEGIN"))
        return PANEL_TELEGRAM_ERROR;

    struct telegram_auth_identity identity;
    enum panel_telegram_result result = check_proof(mini, data, size, now, &identity);
    int64_t linked = 0;
    if (result == PANEL_TELEGRAM_OK) {
        if (!find_identity("SELECT account_id FROM telegram_identity WHERE telegram_id=?", (int64_t)identity.user_id, &linked))
            result = PANEL_TELEGRAM_ERROR;
        else if (!linked)
            result = PANEL_TELEGRAM_DENIED;
    }
    if (result == PANEL_TELEGRAM_OK && consume)
        result = record_proof(&identity, now);
    if (result == PANEL_TELEGRAM_OK && !consume) {
        sqlite3_stmt *stmt = prepare(database, "SELECT 1 FROM telegram_proof WHERE proof=?");
        int step = stmt && sqlite3_bind_blob(stmt, 1, identity.proof, sizeof(identity.proof), SQLITE_STATIC) == SQLITE_OK
            ? sqlite3_step(stmt) : SQLITE_ERROR;
        if (step != SQLITE_DONE)
            result = step == SQLITE_ROW ? PANEL_TELEGRAM_REPLAY : PANEL_TELEGRAM_ERROR;
        sqlite3_finalize(stmt);
    }
    result = finish_claim(result);
    if (result == PANEL_TELEGRAM_OK)
        *account_id = linked;
    return result;
}

enum panel_telegram_result panel_telegram_claim_login(bool mini, const char *data, size_t size, uint64_t now,
                                                      int64_t *account_id)
{
    return login_proof(mini, data, size, now, account_id, true);
}

enum panel_telegram_result panel_telegram_check_login(bool mini, const char *data, size_t size, uint64_t now,
                                                       int64_t *account_id)
{
    return login_proof(mini, data, size, now, account_id, false);
}

static int limit_snapshot_work(void *remaining)
{
    int *intervals = remaining;
    return --*intervals <= 0;
}

static bool open_snapshot(const char *path, sqlite3 **db, int *work_remaining)
{
    if (!path || !*path)
        return false;
    int flags = SQLITE_OPEN_READONLY;
#ifdef SQLITE_OPEN_NOFOLLOW
    flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    if (sqlite3_open_v2(path, db, flags, NULL) != SQLITE_OK || sqlite3_busy_timeout(*db, 75) != SQLITE_OK)
        return false;
    sqlite3_limit(*db, SQLITE_LIMIT_LENGTH, 1024 * 1024);
    sqlite3_progress_handler(*db, VM_STEPS, limit_snapshot_work, work_remaining);
    return execute(*db, "PRAGMA trusted_schema=OFF; PRAGMA query_only=ON; BEGIN");
}

static bool decimal_id(const unsigned char *text, int length, uint64_t *value)
{
    uint64_t number = 0;
    if (length < 1 || length > 19 || !text)
        return false;
    for (int i = 0; i < length; ++i) {
        if (!digit(text[i]))
            return false;
        unsigned int next = text[i] - '0';
        if (number > (INT64_MAX - next) / UINT64_C(10))
            return false;
        number = 10 * number + next;
    }
    *value = number;
    return true;
}

static bool legacy_settings(sqlite3 *source, struct panel_telegram_settings *settings)
{
    sqlite3_stmt *rows = prepare(source, "SELECT key,value FROM app_settings"
        " WHERE key IN ('telegram_bot_username','telegram_auth_max_age_seconds') ORDER BY key");
    if (!rows)
        return false;
    *settings = (struct panel_telegram_settings){ .max_age = TELEGRAM_AUTH_DEFAULT_TTL };
    int step;
    bool found_username = false;
    bool found_age = false;
    while ((step = sqlite3_step(rows)) == SQLITE_ROW) {
        const unsigned char *key = sqlite3_column_text(rows, 0);
        const unsigned char *value = sqlite3_column_text(rows, 1);
        int length = sqlite3_column_bytes(rows, 1);
        if (!key || !value) {
            step = SQLITE_ERROR;
            break;
        }
        if (!strcmp((const char *)key, "telegram_bot_username")) {
            if (found_username) {
                step = SQLITE_ERROR;
                break;
            }
            found_username = true;
            while (length > 0 && (*value == '@' || *value == ' ')) {
                ++value;
                --length;
            }
            while (length > 0 && value[length - 1] == ' ')
                --length;
            if (!valid_username((const char *)value, (size_t)length)) {
                step = SQLITE_ERROR;
                break;
            }
            memcpy(settings->username, value, (size_t)length);
            settings->username[length] = '\0';
        } else {
            if (found_age) {
                step = SQLITE_ERROR;
                break;
            }
            found_age = true;
            uint64_t age;
            if (decimal_id(value, length, &age)) {
                if (age < TELEGRAM_AUTH_MIN_TTL)
                    age = TELEGRAM_AUTH_MIN_TTL;
                if (age > TELEGRAM_AUTH_MAX_TTL)
                    age = TELEGRAM_AUTH_MAX_TTL;
                settings->max_age = (unsigned int)age;
            }
        }
    }
    sqlite3_finalize(rows);
    return step == SQLITE_DONE;
}

static bool digest_number(EVP_MD_CTX *digest, uint64_t number)
{
    unsigned char encoded[8];
    for (size_t i = 0; i < sizeof(encoded); ++i) {
        encoded[i] = (unsigned char)(number & 0xff);
        number >>= 8;
    }
    return EVP_DigestUpdate(digest, encoded, sizeof(encoded)) == 1;
}

static bool legacy_links(sqlite3 *source, sqlite3 *auth, EVP_MD_CTX *digest, bool insert)
{
    sqlite3_stmt *users = prepare(source, "SELECT id,username,telegram_id FROM users ORDER BY id");
    sqlite3_stmt *native = prepare(auth, "SELECT a.id,a.username FROM panel_accounts AS a JOIN panel_legacy_accounts AS l"
                                         " ON a.id=l.account_id WHERE l.from_legacy=1 ORDER BY a.id");
    bool success = false;
    if (users && native) {
        int user;
        int count = 0;
        while ((user = sqlite3_step(users)) == SQLITE_ROW) {
            if (++count > MAX_IMPORT_ACCOUNTS || sqlite3_step(native) != SQLITE_ROW)
                break;
            int64_t id = sqlite3_column_int64(users, 0);
            const unsigned char *username = sqlite3_column_text(users, 1);
            const unsigned char *native_username = sqlite3_column_text(native, 1);
            int bytes = sqlite3_column_bytes(users, 1);
            if (sqlite3_column_type(users, 0) != SQLITE_INTEGER || id <= 0 || id != sqlite3_column_int64(native, 0) ||
                !username || !native_username || bytes <= 0 || bytes > 256 || bytes != sqlite3_column_bytes(native, 1) ||
                memcmp(username, native_username, (size_t)bytes))
                break;
            uint64_t telegram_id = 0;
            if (sqlite3_column_type(users, 2) != SQLITE_NULL) {
                const unsigned char *telegram = sqlite3_column_text(users, 2);
                int length = sqlite3_column_bytes(users, 2);
                if (!telegram || (length && (*telegram == '0' || !decimal_id(telegram, length, &telegram_id))))
                    break;
            }
            if (!digest_number(digest, (uint64_t)id) || !digest_number(digest, (uint64_t)bytes) ||
                EVP_DigestUpdate(digest, username, (size_t)bytes) != 1 || !digest_number(digest, telegram_id) ||
                (insert && telegram_id && write_link(id, telegram_id) != PANEL_TELEGRAM_OK))
                break;
        }
        success = user == SQLITE_DONE && count > 0 && sqlite3_step(native) == SQLITE_DONE;
    }
    sqlite3_finalize(native);
    sqlite3_finalize(users);
    return success;
}

static bool has_snapshot_tables(sqlite3 *db, const char *query)
{
    sqlite3_stmt *stmt = prepare(db, query);
    bool success = stmt && sqlite3_step(stmt) == SQLITE_ROW && sqlite3_column_int(stmt, 0) == 2;
    sqlite3_finalize(stmt);
    return success;
}

static enum panel_telegram_result import_digest(const unsigned char value[32], bool insert)
{
    sqlite3_stmt *stmt = prepare(database, insert ? "INSERT INTO telegram_legacy_import(id,digest) VALUES (1,?)" :
                                                   "SELECT 1 FROM telegram_legacy_import WHERE id=1 AND digest=?");
    int step = stmt && sqlite3_bind_blob(stmt, 1, value, 32, SQLITE_STATIC) == SQLITE_OK ?
        sqlite3_step(stmt) : SQLITE_ERROR;
    sqlite3_finalize(stmt);
    if (step == (insert ? SQLITE_DONE : SQLITE_ROW))
        return PANEL_TELEGRAM_OK;
    return !insert && step == SQLITE_DONE ? PANEL_TELEGRAM_CONFLICT : PANEL_TELEGRAM_ERROR;
}

enum panel_telegram_result panel_telegram_import_legacy(const char *source_db, const char *native_auth_db)
{
    sqlite3 *source = NULL;
    sqlite3 *auth = NULL;
    int source_work = MAX_VM_INTERVALS;
    int auth_work = MAX_VM_INTERVALS;
    enum panel_telegram_result result = PANEL_TELEGRAM_ERROR;
    if (open_snapshot(source_db, &source, &source_work) && open_snapshot(native_auth_db, &auth, &auth_work) &&
        has_snapshot_tables(source, "SELECT count(*) FROM pragma_table_list"
            " WHERE schema='main' AND type='table' AND name IN ('users','app_settings')") &&
        has_snapshot_tables(auth, "SELECT count(*) FROM pragma_table_list"
            " WHERE schema='main' AND type='table' AND name IN ('panel_accounts','panel_legacy_accounts')") &&
        execute(database, "BEGIN IMMEDIATE")) {
        sqlite3_stmt *fresh = prepare(database, "SELECT 0 FROM telegram_settings WHERE id=1 AND username=''"
            " AND token='' AND legacy_enabled=0 AND mini_enabled=0 AND max_age=300"
            " AND NOT EXISTS (SELECT 1 FROM telegram_identity)"
            " AND NOT EXISTS (SELECT 1 FROM telegram_proof)"
            " AND NOT EXISTS (SELECT 1 FROM telegram_legacy_import)"
            " UNION ALL SELECT 1 FROM telegram_legacy_import WHERE id=1");
        int step = fresh ? sqlite3_step(fresh) : SQLITE_ERROR;
        bool insert = step == SQLITE_ROW && sqlite3_column_int(fresh, 0) == 0;
        sqlite3_finalize(fresh);
        if (step == SQLITE_DONE) {
            result = PANEL_TELEGRAM_CONFLICT;
        } else if (step == SQLITE_ROW) {
            struct panel_telegram_settings settings;
            EVP_MD_CTX *digest = EVP_MD_CTX_new();
            unsigned char value[32];
            unsigned int length;
            if (digest && EVP_DigestInit_ex(digest, EVP_sha256(), NULL) == 1 && legacy_settings(source, &settings) &&
                EVP_DigestUpdate(digest, settings.username, strlen(settings.username) + 1) == 1 &&
                digest_number(digest, settings.max_age) && legacy_links(source, auth, digest, insert) &&
                EVP_DigestFinal_ex(digest, value, &length) == 1 && length == sizeof(value) &&
                (!insert || panel_telegram_settings_set(&settings, NULL) == PANEL_TELEGRAM_OK))
                result = import_digest(value, insert);
            EVP_MD_CTX_free(digest);
        }
        result = finish_claim(result);
    }
    sqlite3_close(auth);
    sqlite3_close(source);
    return result;
}
