#ifndef _WIN32
#define _DEFAULT_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "panel_auth.h"
#include "panel_auth_schema.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef PANEL_AUTH_LEGACY_BCRYPT
#include <crypt.h>
#endif

#ifdef _WIN32
#include <windows.h>
#else
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

enum {
    SALT_SIZE = 16,
    DIGEST_SIZE = 32,
    BCRYPT_HASH_SIZE = 60,
    PASSWORD_ITERATIONS = 300000,
    MAX_STORED_ITERATIONS = 5000000,
    SESSION_SECONDS = 7 * 24 * 60 * 60,
    FAILURE_BURST = 5,
    FAILURE_RESET_MS = 60000,
    MAX_BACKOFF_SECONDS = 30
};

enum lookup_result { LOOKUP_ERROR, LOOKUP_MISSING, LOOKUP_FOUND };

struct password_secret {
    unsigned char salt[SALT_SIZE];
    unsigned char hash[DIGEST_SIZE];
    int iterations;
};

struct account {
    struct panel_auth_identity identity;
    struct password_secret secret;
    char bcrypt_hash[BCRYPT_HASH_SIZE + 1];
    sqlite3_int64 revision;
    bool is_active;
    bool panel_login_enabled;
    bool login_enabled;
    bool has_policy;
    bool legacy_totp;
    bool legacy_passkeys;
    bool native_totp_required;
    bool native_password_set;
};

static sqlite3 *database;
static bool reconciling_native_factors;
static unsigned int failed_attempts;
static uint64_t last_failure_ms;
static uint64_t retry_at_ms;

static size_t bounded_length(const char *text, size_t limit)
{
    if (!text)
        return 0;
    size_t length = 0;
    while (length < limit && text[length])
        ++length;
    return length;
}

static uint64_t monotonic_ms(void)
{
#ifdef _WIN32
    return GetTickCount64();
#else
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
#endif
}

unsigned int panel_auth_retry_after(void)
{
    uint64_t now = monotonic_ms();
    if (!now || retry_at_ms <= now)
        return 0;
    return (unsigned int)((retry_at_ms - now + 999) / 1000);
}

static void record_verification(bool success)
{
    if (success) {
        failed_attempts = 0;
        last_failure_ms = 0;
        retry_at_ms = 0;
        return;
    }

    uint64_t now = monotonic_ms();
    if (!now)
        return;
    if (now - last_failure_ms >= FAILURE_RESET_MS)
        failed_attempts = 0;
    last_failure_ms = now;
    if (failed_attempts < FAILURE_BURST + 5)
        ++failed_attempts;
    if (failed_attempts >= FAILURE_BURST) {
        unsigned int seconds = 1U << (failed_attempts - FAILURE_BURST);
        if (seconds > MAX_BACKOFF_SECONDS)
            seconds = MAX_BACKOFF_SECONDS;
        retry_at_ms = now + seconds * 1000U;
    }
}

static bool current_time(sqlite3_int64 *result)
{
    time_t now = time(NULL);
    if (now < 0 || (uintmax_t)now > INT64_MAX - SESSION_SECONDS)
        return false;
    *result = (sqlite3_int64)now;
    return true;
}

static bool execute(const char *sql)
{
    return sqlite3_exec(database, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static sqlite3_stmt *prepare(const char *sql)
{
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(database, sql, -1, &statement, NULL) != SQLITE_OK) {
        sqlite3_finalize(statement);
        return NULL;
    }
    return statement;
}

static bool bind_secret(sqlite3_stmt *statement, int index, const struct password_secret *secret)
{
    return sqlite3_bind_blob(statement, index, secret->salt, SALT_SIZE, SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_blob(statement, index + 1, secret->hash, DIGEST_SIZE, SQLITE_STATIC) == SQLITE_OK &&
           sqlite3_bind_int(statement, index + 2, secret->iterations) == SQLITE_OK;
}

static bool derive_password(const char *password, size_t length, const struct password_secret *secret,
                            unsigned char hash[DIGEST_SIZE])
{
    return PKCS5_PBKDF2_HMAC(password, (int)length, secret->salt, SALT_SIZE, secret->iterations,
                            EVP_sha256(), DIGEST_SIZE, hash) == 1;
}

static bool new_password_secret(const char *password, size_t length, struct password_secret *secret)
{
    secret->iterations = PASSWORD_ITERATIONS;
    return RAND_bytes(secret->salt, SALT_SIZE) == 1 &&
           derive_password(password, length, secret, secret->hash);
}

static bool verify_password(const char *password, size_t length, const struct password_secret *secret)
{
    unsigned char hash[DIGEST_SIZE];
    bool match = derive_password(password, length, secret, hash) &&
                 CRYPTO_memcmp(hash, secret->hash, sizeof(hash)) == 0;
    OPENSSL_cleanse(hash, sizeof(hash));
    return match;
}

static bool verify_account_password(const char *password, size_t length, const struct account *account)
{
    if (!account->has_policy || account->native_password_set)
        return verify_password(password, length, &account->secret);
#ifdef PANEL_AUTH_LEGACY_BCRYPT
    const char *expected = account->bcrypt_hash;
    if (strlen(expected) == BCRYPT_HASH_SIZE && expected[0] == '$' && expected[1] == '2' &&
        strchr("aby", expected[2]) && expected[3] == '$' && expected[6] == '$' &&
        expected[4] >= '0' && expected[4] <= '1' && expected[5] >= '0' && expected[5] <= '9') {
        /* The pinned upstream emits cost 12. Bound work from imported databases. */
        int cost = 10 * (expected[4] - '0') + expected[5] - '0';
        if (cost >= 4 && cost <= 14) {
            char truncated[73] = {0};
            memcpy(truncated, password, length < sizeof(truncated) ? length : sizeof(truncated) - 1);
            struct crypt_data state = {0};
            const char *actual = crypt_r(truncated, expected, &state);
            bool match = actual && strlen(actual) == BCRYPT_HASH_SIZE &&
                         CRYPTO_memcmp(actual, expected, BCRYPT_HASH_SIZE) == 0;
            OPENSSL_cleanse(truncated, sizeof(truncated));
            OPENSSL_cleanse(&state, sizeof(state));
            return match;
        }
    }
#endif
    (void)verify_password(password, length, &account->secret);
    return false;
}

static bool token_digest(const char *token, unsigned char digest[DIGEST_SIZE])
{
    if (bounded_length(token, PANEL_AUTH_TOKEN_SIZE) != PANEL_AUTH_TOKEN_SIZE - 1)
        return false;
    for (size_t i = 0; i < PANEL_AUTH_TOKEN_SIZE - 1; ++i) {
        char byte = token[i];
        if ((byte < '0' || byte > '9') && (byte < 'a' || byte > 'f'))
            return false;
    }
    unsigned int written;
    return EVP_Digest(token, PANEL_AUTH_TOKEN_SIZE - 1, digest, &written, EVP_sha256(), NULL) == 1 &&
           written == DIGEST_SIZE;
}

static bool new_token(char token[PANEL_AUTH_TOKEN_SIZE], unsigned char digest[DIGEST_SIZE])
{
    static const char hex[] = "0123456789abcdef";
    unsigned char random[DIGEST_SIZE];
    bool generated = RAND_bytes(random, sizeof(random)) == 1;
    if (generated) {
        for (size_t i = 0; i < sizeof(random); ++i) {
            token[2 * i] = hex[random[i] >> 4];
            token[2 * i + 1] = hex[random[i] & 0x0f];
        }
        token[PANEL_AUTH_TOKEN_SIZE - 1] = '\0';
        generated = token_digest(token, digest);
    }
    OPENSSL_cleanse(random, sizeof(random));
    return generated;
}

static bool prune_expired(sqlite3_int64 now)
{
    sqlite3_stmt *statement = prepare("DELETE FROM panel_sessions WHERE expires_at <= ?");
    bool success = statement && sqlite3_bind_int64(statement, 1, now) == SQLITE_OK &&
                   sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    return success;
}

static bool bootstrap_admin(const char *password)
{
    sqlite3_stmt *statement = prepare("SELECT 1 FROM panel_accounts LIMIT 1");
    if (!statement)
        return false;
    int result = sqlite3_step(statement);
    sqlite3_finalize(statement);
    if (result == SQLITE_ROW)
        return true;
    size_t length = bounded_length(password, PANEL_AUTH_PASSWORD_MAX + 1);
    if (result != SQLITE_DONE || length < PANEL_AUTH_PASSWORD_MIN || length > PANEL_AUTH_PASSWORD_MAX)
        return false;

    struct password_secret secret;
    bool success = false;
    if (new_password_secret(password, length, &secret)) {
        statement = prepare("INSERT INTO panel_accounts (username, password_salt, password_hash, iterations)"
                            " VALUES ('admin', ?, ?, ?)");
        success = statement && bind_secret(statement, 1, &secret) && sqlite3_step(statement) == SQLITE_DONE;
        sqlite3_finalize(statement);
    }
    OPENSSL_cleanse(&secret, sizeof(secret));
    return success;
}

static bool prepare_file(const char *path)
{
#ifndef _WIN32
    if (strcmp(path, ":memory:") != 0) {
        int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0)
            return errno == EEXIST;
        return close(fd) == 0;
    }
#else
    (void)path;
#endif
    return true;
}

static bool upgrade_account_policy(bool (*reconcile)(void *), void *context)
{
    static const char initial_policy[] = "CREATE TABLE panel_legacy_accounts" PANEL_LEGACY_ACCOUNTS_COMMON
        " revision INTEGER NOT NULL DEFAULT 1 CHECK(revision > 0))";
    static const char before_marker[] = "CREATE TABLE panel_legacy_accounts" PANEL_LEGACY_ACCOUNTS_PRE_MARKER_COLUMNS;
    static const char current[] = "CREATE TABLE panel_legacy_accounts" PANEL_LEGACY_ACCOUNTS_COLUMNS;
    sqlite3_stmt *statement = prepare("SELECT sql FROM main.sqlite_schema WHERE name='panel_legacy_accounts'");
    int result = statement ? sqlite3_step(statement) : SQLITE_ERROR;
    bool upgrade = false;
    bool recognized = result == SQLITE_DONE;
    if (result == SQLITE_ROW) {
        const unsigned char *sql = sqlite3_column_text(statement, 0);
        upgrade = sql && (!strcmp((const char *)sql, before_marker) || !strcmp((const char *)sql, initial_policy));
        recognized = upgrade || (sql && strcmp((const char *)sql, current) == 0);
    }
    sqlite3_finalize(statement);
    if (!recognized || !upgrade)
        return recognized;

    static const char sql[] =
        "ALTER TABLE panel_legacy_accounts RENAME TO panel_legacy_accounts_upgrade;"
        "CREATE TABLE panel_legacy_accounts" PANEL_LEGACY_ACCOUNTS_COLUMNS ";"
        "INSERT INTO panel_legacy_accounts (account_id,bcrypt_hash,role,is_active,panel_login_enabled,"
        " must_change_password,totp_enabled,has_passkeys,native_password_set,access_until,from_legacy,revision)"
        " SELECT account_id,bcrypt_hash,role,is_active,panel_login_enabled,must_change_password,totp_enabled,"
        " has_passkeys,native_password_set,access_until,from_legacy,revision FROM panel_legacy_accounts_upgrade;"
        "DROP TABLE panel_legacy_accounts_upgrade;";
    if (!reconcile || !execute(sql))
        return false;
    reconciling_native_factors = true;
    bool success = reconcile(context);
    reconciling_native_factors = false;
    if (!success)
        fputs("Cannot upgrade panel authentication without its existing login security database and key.\n", stderr);
    return success;
}

bool panel_auth_open_with_reconciliation(const char *path, const char *initial_password,
                                         bool (*reconcile)(void *), void *context)
{
    if (database || !path || !path[0])
        return false;
    if (!prepare_file(path)) {
        fputs("Cannot create the authentication database file.\n", stderr);
        return false;
    }
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
#ifdef SQLITE_OPEN_NOFOLLOW
    flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    sqlite3_int64 now;
    if (sqlite3_open_v2(path, &database, flags, NULL) != SQLITE_OK ||
        sqlite3_busy_timeout(database, 250) != SQLITE_OK ||
        !execute("PRAGMA foreign_keys = ON") || !current_time(&now) || !execute("BEGIN IMMEDIATE")) {
        fprintf(stderr, "Cannot initialize SQLite authentication: %s\n", sqlite3_errmsg(database));
        panel_auth_close();
        return false;
    }
    if (!upgrade_account_policy(reconcile, context) || !execute(PANEL_AUTH_SCHEMA) || !bootstrap_admin(initial_password) ||
        !prune_expired(now) || !execute("COMMIT")) {
        fprintf(stderr, "Cannot initialize authentication schema: %s\n", sqlite3_errmsg(database));
        execute("ROLLBACK");
        panel_auth_close();
        return false;
    }
    return true;
}

bool panel_auth_open(const char *path, const char *initial_password)
{
    return panel_auth_open_with_reconciliation(path, initial_password, NULL, NULL);
}

void panel_auth_close(void)
{
    if (database) {
        sqlite3_close(database);
        database = NULL;
    }
    record_verification(true);
}

static enum lookup_result read_account(sqlite3_stmt *statement, struct account *account)
{
    int result = sqlite3_step(statement);
    if (result != SQLITE_ROW)
        return result == SQLITE_DONE ? LOOKUP_MISSING : LOOKUP_ERROR;
    OPENSSL_cleanse(account, sizeof(*account));
    const unsigned char *username = sqlite3_column_text(statement, 1);
    int length = sqlite3_column_bytes(statement, 1);
    const void *salt = sqlite3_column_blob(statement, 2);
    const void *hash = sqlite3_column_blob(statement, 3);
    sqlite3_int64 iterations = sqlite3_column_int64(statement, 4);
    if (length <= 0 || !panel_auth_valid_username(username, (size_t)length) ||
        !salt || sqlite3_column_bytes(statement, 2) != SALT_SIZE ||
        !hash || sqlite3_column_bytes(statement, 3) != DIGEST_SIZE ||
        iterations < PASSWORD_ITERATIONS || iterations > MAX_STORED_ITERATIONS)
        return LOOKUP_ERROR;

    account->identity.id = sqlite3_column_int64(statement, 0);
    memcpy(account->identity.username, username, (size_t)length + 1);
    memcpy(account->secret.salt, salt, SALT_SIZE);
    memcpy(account->secret.hash, hash, DIGEST_SIZE);
    account->secret.iterations = (int)iterations;

    account->has_policy = sqlite3_column_type(statement, 5) != SQLITE_NULL;
    account->identity.role = PANEL_AUTH_ROLE_ADMIN;
    account->revision = 1;
    account->is_active = true;
    account->panel_login_enabled = true;
    account->login_enabled = true;
    if (account->has_policy) {
        const unsigned char *role = sqlite3_column_text(statement, 5);
        if (role && sqlite3_column_bytes(statement, 5) == 4 && !memcmp(role, "user", 4))
            account->identity.role = PANEL_AUTH_ROLE_USER;
        else if (!role || sqlite3_column_bytes(statement, 5) != 5 || memcmp(role, "admin", 5))
            return LOOKUP_ERROR;
        const unsigned char *bcrypt_hash = sqlite3_column_text(statement, 6);
        if (bcrypt_hash && sqlite3_column_bytes(statement, 6) == BCRYPT_HASH_SIZE &&
            !memchr(bcrypt_hash, '\0', BCRYPT_HASH_SIZE))
            memcpy(account->bcrypt_hash, bcrypt_hash, sizeof(account->bcrypt_hash));
        account->is_active = sqlite3_column_int(statement, 7) == 1;
        account->panel_login_enabled = sqlite3_column_int(statement, 8) == 1;
        account->login_enabled = account->is_active && account->panel_login_enabled;
        account->legacy_totp = sqlite3_column_int(statement, 10) != 0;
        account->legacy_passkeys = sqlite3_column_int(statement, 11) != 0;
        account->native_password_set = sqlite3_column_int(statement, 12) == 1;
        account->identity.must_change_password = sqlite3_column_int(statement, 9) != 0;
        account->revision = sqlite3_column_int64(statement, 13);
        account->native_totp_required = sqlite3_column_int(statement, 14) != 0;
        if (account->revision <= 0)
            return LOOKUP_ERROR;
    }
    return LOOKUP_FOUND;
}

#define ACCOUNT_SELECT \
    "SELECT a.id, a.username, a.password_salt, a.password_hash, a.iterations, l.role, l.bcrypt_hash," \
    " l.is_active, l.panel_login_enabled, l.must_change_password, l.totp_enabled, l.has_passkeys," \
    " l.native_password_set, l.revision, l.native_totp_required" \
    " FROM panel_accounts AS a LEFT JOIN panel_legacy_accounts AS l ON l.account_id = a.id"

static enum lookup_result find_account(const char *username, const unsigned char *digest,
                                       sqlite3_int64 id, sqlite3_int64 now, struct account *account)
{
    const char *condition = username ? " WHERE a.username = ?" : !digest ? " WHERE a.id = ?" :
        " JOIN panel_sessions AS s ON s.account_id = a.id WHERE s.token_digest = ? AND s.expires_at > ?";
    char sql[sizeof(ACCOUNT_SELECT) + 128];
    snprintf(sql, sizeof(sql), "%s%s", ACCOUNT_SELECT, condition);
    sqlite3_stmt *statement = prepare(sql);
    bool bound;
    if (username) {
        bound = statement && sqlite3_bind_text(statement, 1, username, -1, SQLITE_STATIC) == SQLITE_OK;
    } else if (!digest) {
        bound = statement && sqlite3_bind_int64(statement, 1, id) == SQLITE_OK;
    } else {
        bound = statement && sqlite3_bind_blob(statement, 1, digest, DIGEST_SIZE, SQLITE_STATIC) == SQLITE_OK &&
                sqlite3_bind_int64(statement, 2, now) == SQLITE_OK;
    }
    enum lookup_result result = bound ? read_account(statement, account) : LOOKUP_ERROR;
    sqlite3_finalize(statement);
    return result;
}

static bool store_session(const struct account *account, const unsigned char digest[DIGEST_SIZE], sqlite3_int64 now)
{
    sqlite3_stmt *statement = prepare("INSERT INTO panel_sessions (token_digest, account_id, expires_at)"
                                      " SELECT ?, id, ? FROM panel_accounts"
                                      " WHERE id = ? AND password_salt = ? AND password_hash = ? AND iterations = ?"
                                      " AND NOT EXISTS (SELECT 1 FROM panel_legacy_accounts WHERE account_id = panel_accounts.id"
                                      " AND (is_active != 1 OR panel_login_enabled != 1 OR (totp_enabled = 0 AND has_passkeys != 0)))");
    bool success = statement && sqlite3_bind_blob(statement, 1, digest, DIGEST_SIZE, SQLITE_STATIC) == SQLITE_OK &&
                   sqlite3_bind_int64(statement, 2, now + SESSION_SECONDS) == SQLITE_OK &&
                   sqlite3_bind_int64(statement, 3, account->identity.id) == SQLITE_OK &&
                   bind_secret(statement, 4, &account->secret) &&
                   sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(database) == 1;
    sqlite3_finalize(statement);
    return success;
}

static bool issue_session(const struct account *account, char token[PANEL_AUTH_TOKEN_SIZE])
{
    unsigned char digest[DIGEST_SIZE];
    sqlite3_int64 now;
    bool success = current_time(&now) && prune_expired(now) && new_token(token, digest) &&
                   store_session(account, digest, now);
    OPENSSL_cleanse(digest, sizeof(digest));
    if (!success)
        OPENSSL_cleanse(token, PANEL_AUTH_TOKEN_SIZE);
    return success;
}

enum panel_auth_login_result panel_auth_login_checked(const char *username, const char *password,
        char token[PANEL_AUTH_TOKEN_SIZE], panel_auth_second_factor second_factor, void *context)
{
    if (!token)
        return PANEL_AUTH_LOGIN_DENIED;
    OPENSSL_cleanse(token, PANEL_AUTH_TOKEN_SIZE);
    size_t name_length = bounded_length(username, PANEL_AUTH_USERNAME_MAX + 1);
    size_t password_length = bounded_length(password, PANEL_AUTH_PASSWORD_MAX + 1);
    if (!database || !name_length || name_length > PANEL_AUTH_USERNAME_MAX ||
        !password_length || password_length > PANEL_AUTH_PASSWORD_MAX)
        return PANEL_AUTH_LOGIN_DENIED;

    struct account account = { .secret.iterations = PASSWORD_ITERATIONS };
    enum lookup_result result = find_account(username, NULL, 0, 0, &account);
    enum panel_auth_login_result outcome = PANEL_AUTH_LOGIN_DENIED;
    if (result != LOOKUP_ERROR) {
        bool verified = verify_account_password(password, password_length, &account) && result == LOOKUP_FOUND;
        if (verified && account.login_enabled && (account.legacy_totp || !account.legacy_passkeys)) {
            bool factor_required = account.legacy_totp || account.native_totp_required;
            bool factor_accepted = second_factor ? second_factor(account.identity.id, factor_required, context) :
                                                   !factor_required;
            if (!factor_accepted)
                outcome = PANEL_AUTH_LOGIN_SECOND_FACTOR;
            else if (issue_session(&account, token))
                outcome = PANEL_AUTH_LOGIN_SUCCESS;
        }
    }
    OPENSSL_cleanse(&account, sizeof(account));
    return outcome;
}

bool panel_auth_login(const char *username, const char *password, char token[PANEL_AUTH_TOKEN_SIZE])
{
    if (!token)
        return false;
    if (panel_auth_retry_after()) {
        OPENSSL_cleanse(token, PANEL_AUTH_TOKEN_SIZE);
        return false;
    }
    bool success = panel_auth_login_checked(username, password, token, NULL, NULL) == PANEL_AUTH_LOGIN_SUCCESS;
    record_verification(success);
    return success;
}

static bool read_session(const char *token, struct account *account)
{
    unsigned char digest[DIGEST_SIZE];
    sqlite3_int64 now;
    bool success = database && token_digest(token, digest) && current_time(&now) &&
                   find_account(NULL, digest, 0, now, account) == LOOKUP_FOUND && account->login_enabled &&
                   (account->legacy_totp || !account->legacy_passkeys);
    OPENSSL_cleanse(digest, sizeof(digest));
    return success;
}

bool panel_auth_identify(const char *token, struct panel_auth_identity *out)
{
    struct account account = {0};
    bool success = read_session(token, &account);
    if (out)
        *out = success ? account.identity : (struct panel_auth_identity){0};
    OPENSSL_cleanse(&account, sizeof(account));
    return success;
}

bool panel_auth_session(const char *token, char username[PANEL_AUTH_USERNAME_MAX + 1])
{
    struct panel_auth_identity identity;
    bool success = panel_auth_identify(token, &identity) && !identity.must_change_password;
    if (username) {
        username[0] = '\0';
        if (success)
            memcpy(username, identity.username, strlen(identity.username) + 1);
    }
    return success;
}

bool panel_auth_account(int64_t id, struct panel_auth_identity *out)
{
    struct account account = {0};
    bool success = database && id > 0 && find_account(NULL, NULL, id, 0, &account) == LOOKUP_FOUND;
    if (out)
        *out = success ? account.identity : (struct panel_auth_identity){0};
    OPENSSL_cleanse(&account, sizeof(account));
    return success;
}

static bool totp_required(int64_t id, bool include_native)
{
    struct account account = {0};
    bool known = database && id > 0 && find_account(NULL, NULL, id, 0, &account) == LOOKUP_FOUND;
    bool required = !known || account.legacy_totp || (include_native && account.native_totp_required);
    OPENSSL_cleanse(&account, sizeof(account));
    return required;
}

bool panel_auth_legacy_totp_required(int64_t id)
{
    return totp_required(id, false);
}

bool panel_auth_totp_required(int64_t id)
{
    return totp_required(id, true);
}

bool panel_auth_external_login(int64_t id, char token[PANEL_AUTH_TOKEN_SIZE],
                               panel_auth_second_factor second_factor, void *context)
{
    if (!token)
        return false;
    OPENSSL_cleanse(token, PANEL_AUTH_TOKEN_SIZE);
    struct account account = {0};
    bool success = database && id > 0 && second_factor && find_account(NULL, NULL, id, 0, &account) == LOOKUP_FOUND &&
                   account.login_enabled && !account.legacy_totp && !account.legacy_passkeys &&
                   !account.identity.must_change_password && second_factor(id, account.native_totp_required, context) &&
                   issue_session(&account, token);
    OPENSSL_cleanse(&account, sizeof(account));
    return success;
}

void panel_auth_logout(const char *token)
{
    unsigned char digest[DIGEST_SIZE];
    if (database && token_digest(token, digest)) {
        sqlite3_stmt *statement = prepare("DELETE FROM panel_sessions WHERE token_digest = ?");
        if (statement && sqlite3_bind_blob(statement, 1, digest, DIGEST_SIZE, SQLITE_STATIC) == SQLITE_OK)
            sqlite3_step(statement);
        sqlite3_finalize(statement);
    }
    OPENSSL_cleanse(digest, sizeof(digest));
}

bool panel_auth_revoke_sessions(int64_t account_id)
{
    if (!database || account_id <= 0)
        return false;
    sqlite3_stmt *statement = prepare("DELETE FROM panel_sessions WHERE account_id = ?");
    bool success = statement && sqlite3_bind_int64(statement, 1, account_id) == SQLITE_OK &&
                   sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    return success;
}

bool panel_auth_revoke_other_sessions(int64_t account_id, const char *except_token)
{
    unsigned char digest[DIGEST_SIZE];
    sqlite3_int64 now;
    struct panel_auth_identity retained;
    if (!database || account_id <= 0 || !panel_auth_identify(except_token, &retained) || retained.id != account_id ||
        !current_time(&now) || !token_digest(except_token, digest))
        return false;
    sqlite3_stmt *statement = prepare("DELETE FROM panel_sessions WHERE account_id = ?1 AND token_digest != ?2"
                                      " AND EXISTS (SELECT 1 FROM panel_sessions WHERE account_id = ?1"
                                      " AND token_digest = ?2 AND expires_at > ?3)");
    bool success = statement && sqlite3_bind_int64(statement, 1, account_id) == SQLITE_OK &&
                   sqlite3_bind_blob(statement, 2, digest, DIGEST_SIZE, SQLITE_STATIC) == SQLITE_OK &&
                   sqlite3_bind_int64(statement, 3, now) == SQLITE_OK && sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    OPENSSL_cleanse(digest, sizeof(digest));
    return success;
}

static bool update_password(const struct account *account, const struct password_secret *replacement,
                            const unsigned char digest[DIGEST_SIZE], sqlite3_int64 now)
{
    sqlite3_stmt *statement = prepare("UPDATE panel_accounts SET password_salt = ?, password_hash = ?, iterations = ?"
                                      " WHERE id = ? AND password_salt = ? AND password_hash = ? AND iterations = ?"
                                      " AND EXISTS (SELECT 1 FROM panel_sessions WHERE token_digest = ?"
                                      " AND account_id = panel_accounts.id AND expires_at > ?)"
                                      " AND NOT EXISTS (SELECT 1 FROM panel_legacy_accounts WHERE account_id = panel_accounts.id"
                                      " AND (is_active != 1 OR panel_login_enabled != 1 OR (totp_enabled = 0 AND has_passkeys != 0)))");
    bool success = statement && bind_secret(statement, 1, replacement) &&
                   sqlite3_bind_int64(statement, 4, account->identity.id) == SQLITE_OK &&
                   bind_secret(statement, 5, &account->secret) &&
                   sqlite3_bind_blob(statement, 8, digest, DIGEST_SIZE, SQLITE_STATIC) == SQLITE_OK &&
                   sqlite3_bind_int64(statement, 9, now) == SQLITE_OK &&
                   sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(database) == 1;
    sqlite3_finalize(statement);
    if (!success)
        return false;

    if (account->has_policy) {
        statement = prepare("UPDATE panel_legacy_accounts SET bcrypt_hash = NULL, native_password_set = 1,"
                            " must_change_password = 0, revision = revision + 1 WHERE account_id = ?");
        success = statement && sqlite3_bind_int64(statement, 1, account->identity.id) == SQLITE_OK &&
                  sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(database) == 1;
        sqlite3_finalize(statement);
        if (!success)
            return false;
    }

    return panel_auth_revoke_sessions(account->identity.id);
}

bool panel_auth_change_password(const char *token, const char *old_password, const char *new_password)
{
    size_t old_length = bounded_length(old_password, PANEL_AUTH_PASSWORD_MAX + 1);
    size_t new_length = bounded_length(new_password, PANEL_AUTH_PASSWORD_MAX + 1);
    if (!database || panel_auth_retry_after() || !old_length || old_length > PANEL_AUTH_PASSWORD_MAX ||
        new_length < PANEL_AUTH_PASSWORD_MIN || new_length > PANEL_AUTH_PASSWORD_MAX)
        return false;

    unsigned char digest[DIGEST_SIZE];
    sqlite3_int64 now;
    struct account account = {0};
    struct password_secret replacement;
    bool success = false;
    if (token_digest(token, digest) && current_time(&now) &&
        find_account(NULL, digest, 0, now, &account) == LOOKUP_FOUND && account.login_enabled &&
        (account.legacy_totp || !account.legacy_passkeys)) {
        bool verified = verify_account_password(old_password, old_length, &account);
        record_verification(verified);
        if (verified && new_password_secret(new_password, new_length, &replacement) && execute("BEGIN IMMEDIATE")) {
            success = current_time(&now) && update_password(&account, &replacement, digest, now) && execute("COMMIT");
            if (!success)
                execute("ROLLBACK");
        }
    }
    OPENSSL_cleanse(&replacement, sizeof(replacement));
    OPENSSL_cleanse(&account, sizeof(account));
    OPENSSL_cleanse(digest, sizeof(digest));
    return success;
}

bool panel_auth_users(int64_t after, const char *query, struct panel_auth_user out[PANEL_AUTH_USERS_PAGE],
                      size_t *count, bool *has_more)
{
    if (!database || after < 0 || !out || !count || !has_more)
        return false;
    *count = 0;
    *has_more = false;
    sqlite3_stmt *statement = prepare(ACCOUNT_SELECT
        " WHERE a.id > ? AND (instr(lower(a.username),lower(?2))>0 OR"
        " instr(COALESCE(l.role,'admin'),lower(?2))>0) ORDER BY a.id LIMIT ?");
    bool success = statement && sqlite3_bind_int64(statement, 1, after) == SQLITE_OK &&
                   sqlite3_bind_text(statement, 2, query ? query : "", -1, SQLITE_STATIC) == SQLITE_OK &&
                   sqlite3_bind_int(statement, 3, PANEL_AUTH_USERS_PAGE + 1) == SQLITE_OK;
    struct account account = {0};
    enum lookup_result result = LOOKUP_ERROR;
    while (success && (result = read_account(statement, &account)) == LOOKUP_FOUND) {
        if (*count == PANEL_AUTH_USERS_PAGE) {
            *has_more = true;
            break;
        }
        out[(*count)++] = (struct panel_auth_user){
            .identity = account.identity,
            .settings = { account.identity.role, account.is_active, account.panel_login_enabled,
                          account.identity.must_change_password },
            .revision = account.revision, .legacy_totp = account.legacy_totp, .legacy_passkeys = account.legacy_passkeys,
            .native_totp_required = account.native_totp_required
        };
    }
    OPENSSL_cleanse(&account, sizeof(account));
    sqlite3_finalize(statement);
    return success && (result == LOOKUP_MISSING || *has_more);
}

static bool valid_settings(const struct panel_auth_user_settings *settings)
{
    return settings && (settings->role == PANEL_AUTH_ROLE_ADMIN || settings->role == PANEL_AUTH_ROLE_USER);
}

static bool valid_new_username(const char *username)
{
    size_t length = bounded_length(username, PANEL_AUTH_USERNAME_MAX + 1);
    if (!panel_auth_valid_username((const unsigned char *)username, length) ||
        username[0] == ' ' || username[length - 1] == ' ')
        return false;
    for (size_t i = 0; i < length; ++i) {
        unsigned char value = (unsigned char)username[i];
        if (value < 32 || value == 127)
            return false;
    }
    return true;
}

static enum panel_auth_user_result finish_user_change(enum panel_auth_user_result result)
{
    if (result == PANEL_AUTH_USER_OK && execute("COMMIT"))
        return result;
    execute("ROLLBACK");
    return result == PANEL_AUTH_USER_OK ? PANEL_AUTH_USER_ERROR : result;
}

static bool reserve_account_ids(void)
{
    return execute("INSERT INTO panel_account_ids SELECT 1, max(id) FROM panel_accounts WHERE id > 0 HAVING count(*) > 0"
                   " ON CONFLICT(singleton) DO UPDATE SET high_watermark=max(high_watermark,excluded.high_watermark)");
}

static bool allocate_account_id(int64_t *out)
{
    const char *sql = "UPDATE panel_account_ids SET high_watermark=high_watermark+1"
                      " WHERE singleton=1 AND high_watermark<9223372036854775807 RETURNING high_watermark";
    sqlite3_stmt *statement = prepare(sql);
    bool success = statement && sqlite3_step(statement) == SQLITE_ROW;
    if (success) {
        *out = sqlite3_column_int64(statement, 0);
        success = sqlite3_step(statement) == SQLITE_DONE;
    }
    sqlite3_finalize(statement);
    return success;
}

static enum panel_auth_user_result insert_user(int64_t id, const char *username,
                                               const struct password_secret *secret)
{
    const char *sql = "INSERT INTO panel_accounts (id, username, password_salt, password_hash, iterations)"
                      " VALUES (?,?,?,?,?)";
    sqlite3_stmt *statement = prepare(sql);
    int result = SQLITE_ERROR;
    if (statement && sqlite3_bind_int64(statement, 1, id) == SQLITE_OK &&
        sqlite3_bind_text(statement, 2, username, -1, SQLITE_STATIC) == SQLITE_OK &&
        bind_secret(statement, 3, secret))
        result = sqlite3_step(statement);
    int extended = sqlite3_extended_errcode(database);
    sqlite3_finalize(statement);
    return result == SQLITE_DONE ? PANEL_AUTH_USER_OK : extended == SQLITE_CONSTRAINT_UNIQUE ? PANEL_AUTH_USER_EXISTS :
           PANEL_AUTH_USER_ERROR;
}

static bool apply_user_policy(int64_t id, int64_t revision, const struct panel_auth_user_settings *settings)
{
    const char *sql = "INSERT INTO panel_legacy_accounts (account_id, role, is_active, panel_login_enabled,"
                      " must_change_password, totp_enabled, has_passkeys, native_password_set, from_legacy, revision)"
                      " VALUES (?,?,?,?,?,0,0,1,0,?) ON CONFLICT(account_id) DO UPDATE SET role=excluded.role,"
                      " is_active=excluded.is_active, panel_login_enabled=excluded.panel_login_enabled,"
                      " must_change_password=excluded.must_change_password, revision=excluded.revision";
    const char *role = settings->role == PANEL_AUTH_ROLE_ADMIN ? "admin" : "user";
    sqlite3_stmt *statement = prepare(sql);
    bool success = statement && sqlite3_bind_int64(statement, 1, id) == SQLITE_OK &&
                   sqlite3_bind_text(statement, 2, role, -1, SQLITE_STATIC) == SQLITE_OK &&
                   sqlite3_bind_int(statement, 3, settings->is_active) == SQLITE_OK &&
                   sqlite3_bind_int(statement, 4, settings->panel_login_enabled) == SQLITE_OK &&
                   sqlite3_bind_int(statement, 5, settings->must_change_password) == SQLITE_OK &&
                   sqlite3_bind_int64(statement, 6, revision) == SQLITE_OK && sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    return success;
}

static bool store_native_totp_requirement(const struct account *account, bool required, bool advance_revision)
{
    if (account->native_totp_required == required)
        return true;
    if (account->legacy_totp || (advance_revision && account->revision == INT64_MAX))
        return false;
    int64_t id = account->identity.id;
    if (advance_revision || !account->has_policy) {
        struct panel_auth_user_settings settings = { account->identity.role, account->is_active,
            account->panel_login_enabled, account->identity.must_change_password };
        if (!apply_user_policy(id, account->revision + advance_revision, &settings))
            return false;
    }
    sqlite3_stmt *statement = prepare("UPDATE panel_legacy_accounts SET native_totp_required=? WHERE account_id=?");
    bool success = statement && sqlite3_bind_int(statement, 1, required) == SQLITE_OK &&
                   sqlite3_bind_int64(statement, 2, id) == SQLITE_OK && sqlite3_step(statement) == SQLITE_DONE &&
                   sqlite3_changes(database) == 1;
    sqlite3_finalize(statement);
    return success;
}

bool panel_auth_reconcile_native_factor(int64_t id, void *unused)
{
    (void)unused;
    if (!reconciling_native_factors || id <= 0)
        return false;
    struct account account = {0};
    enum lookup_result found = find_account(NULL, NULL, id, 0, &account);
    bool success = found == LOOKUP_MISSING || (found == LOOKUP_FOUND &&
                  (account.legacy_totp || store_native_totp_requirement(&account, true, false)));
    OPENSSL_cleanse(&account, sizeof(account));
    return success;
}

bool panel_auth_set_native_totp_required(int64_t id, bool required)
{
    if (!database || id <= 0 || !execute("BEGIN IMMEDIATE"))
        return false;
    struct account account = {0};
    bool success = find_account(NULL, NULL, id, 0, &account) == LOOKUP_FOUND &&
                   store_native_totp_requirement(&account, required, true);
    OPENSSL_cleanse(&account, sizeof(account));
    return finish_user_change(success ? PANEL_AUTH_USER_OK : PANEL_AUTH_USER_ERROR) == PANEL_AUTH_USER_OK;
}

static enum panel_auth_user_result check_remaining_admin(panel_auth_factor_ready factor_ready)
{
    const char *sql = "SELECT a.id,(l.totp_enabled=1 OR l.native_totp_required=1)"
                      " FROM panel_accounts a LEFT JOIN panel_legacy_accounts l ON a.id=l.account_id"
                      " WHERE a.id>0 AND (l.account_id IS NULL OR (l.role='admin' AND l.is_active=1 AND"
                      " l.panel_login_enabled=1 AND (l.totp_enabled=1 OR l.has_passkeys=0) AND"
                      " (l.native_password_set=1"
#ifdef PANEL_AUTH_LEGACY_BCRYPT
                      " OR substr(l.bcrypt_hash,5,2) BETWEEN '04' AND '14'"
#endif
                      ")))";
    sqlite3_stmt *statement = prepare(sql);
    int result = SQLITE_ERROR;
    while (statement && (result = sqlite3_step(statement)) == SQLITE_ROW) {
        if (!sqlite3_column_int(statement, 1) || (factor_ready && factor_ready(sqlite3_column_int64(statement, 0))))
            break;
    }
    sqlite3_finalize(statement);
    return result == SQLITE_ROW ? PANEL_AUTH_USER_OK : result == SQLITE_DONE ? PANEL_AUTH_USER_LAST_ADMIN :
           PANEL_AUTH_USER_ERROR;
}

static enum panel_auth_user_result user_for_change(int64_t id, int64_t revision, struct account *account)
{
    if (id <= 0 || revision <= 0 || revision == INT64_MAX)
        return PANEL_AUTH_USER_INVALID;
    enum lookup_result found = find_account(NULL, NULL, id, 0, account);
    if (found != LOOKUP_FOUND)
        return found == LOOKUP_MISSING ? PANEL_AUTH_USER_NOT_FOUND : PANEL_AUTH_USER_ERROR;
    return revision == account->revision ? PANEL_AUTH_USER_OK : PANEL_AUTH_USER_STALE;
}

enum panel_auth_user_result panel_auth_user_create(const char *username, const char *password,
        const struct panel_auth_user_settings *settings, int64_t *id_out)
{
    size_t length = bounded_length(password, PANEL_AUTH_PASSWORD_MAX + 1);
    if (!valid_new_username(username) || length < PANEL_AUTH_PASSWORD_MIN || length > PANEL_AUTH_PASSWORD_MAX ||
        !valid_settings(settings) || !id_out)
        return PANEL_AUTH_USER_INVALID;
    enum panel_auth_user_result result = PANEL_AUTH_USER_ERROR;
    struct password_secret secret;
    int64_t id = 0;
    if (database && new_password_secret(password, length, &secret) && execute("BEGIN IMMEDIATE")) {
        if (reserve_account_ids() && allocate_account_id(&id)) {
            result = insert_user(id, username, &secret);
            if (result == PANEL_AUTH_USER_OK && !apply_user_policy(id, 1, settings))
                result = PANEL_AUTH_USER_ERROR;
        }
        result = finish_user_change(result);
    }
    OPENSSL_cleanse(&secret, sizeof(secret));
    *id_out = result == PANEL_AUTH_USER_OK ? id : 0;
    return result;
}

enum panel_auth_user_result panel_auth_user_update(int64_t id, int64_t revision,
        const struct panel_auth_user_settings *settings, panel_auth_factor_ready factor_ready)
{
    if (!valid_settings(settings))
        return PANEL_AUTH_USER_INVALID;
    if (!database || !execute("BEGIN IMMEDIATE"))
        return PANEL_AUTH_USER_ERROR;
    struct account account = {0};
    enum panel_auth_user_result result = user_for_change(id, revision, &account);
    if (result == PANEL_AUTH_USER_OK) {
        bool changed = settings->role != account.identity.role || settings->is_active != account.is_active ||
                       settings->panel_login_enabled != account.panel_login_enabled ||
                       settings->must_change_password != account.identity.must_change_password;
        if (changed) {
            bool may_remove_admin = account.identity.role == PANEL_AUTH_ROLE_ADMIN && account.login_enabled &&
                (settings->role != PANEL_AUTH_ROLE_ADMIN || !settings->is_active || !settings->panel_login_enabled);
            if (!apply_user_policy(id, revision + 1, settings) || !panel_auth_revoke_sessions(id))
                result = PANEL_AUTH_USER_ERROR;
            else if (may_remove_admin)
                result = check_remaining_admin(factor_ready);
        }
    }
    OPENSSL_cleanse(&account, sizeof(account));
    return finish_user_change(result);
}

static bool replace_user_password(int64_t id, const struct password_secret *secret)
{
    sqlite3_stmt *statement = prepare("UPDATE panel_accounts SET password_salt=?,password_hash=?,iterations=? WHERE id=?");
    bool success = statement && bind_secret(statement, 1, secret) && sqlite3_bind_int64(statement, 4, id) == SQLITE_OK &&
                   sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(database) == 1;
    sqlite3_finalize(statement);
    if (!success)
        return false;
    statement = prepare("UPDATE panel_legacy_accounts SET bcrypt_hash=NULL,native_password_set=1 WHERE account_id=?");
    success = statement && sqlite3_bind_int64(statement, 1, id) == SQLITE_OK &&
              sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(database) == 1;
    sqlite3_finalize(statement);
    return success;
}

enum panel_auth_user_result panel_auth_user_reset(int64_t actor, int64_t id, int64_t revision,
        const char *password, bool must_change)
{
    if (actor == id)
        return PANEL_AUTH_USER_SELF;
    size_t length = bounded_length(password, PANEL_AUTH_PASSWORD_MAX + 1);
    if (actor <= 0 || length < PANEL_AUTH_PASSWORD_MIN || length > PANEL_AUTH_PASSWORD_MAX)
        return PANEL_AUTH_USER_INVALID;
    enum panel_auth_user_result result = PANEL_AUTH_USER_ERROR;
    struct password_secret secret;
    struct account account = {0};
    if (database && new_password_secret(password, length, &secret) && execute("BEGIN IMMEDIATE")) {
        result = user_for_change(id, revision, &account);
        if (result == PANEL_AUTH_USER_OK) {
            struct panel_auth_user_settings settings = { account.identity.role, account.is_active,
                                                         account.panel_login_enabled, must_change };
            if (!apply_user_policy(id, revision + 1, &settings) || !replace_user_password(id, &secret) ||
                !panel_auth_revoke_sessions(id))
                result = PANEL_AUTH_USER_ERROR;
        }
        result = finish_user_change(result);
    }
    OPENSSL_cleanse(&account, sizeof(account));
    OPENSSL_cleanse(&secret, sizeof(secret));
    return result;
}

enum panel_auth_user_result panel_auth_user_delete(int64_t actor, int64_t id, int64_t revision,
                                                  panel_auth_factor_ready factor_ready)
{
    if (actor == id)
        return PANEL_AUTH_USER_SELF;
    if (actor <= 0)
        return PANEL_AUTH_USER_INVALID;
    if (!database || !execute("BEGIN IMMEDIATE"))
        return PANEL_AUTH_USER_ERROR;
    struct account account = {0};
    enum panel_auth_user_result result = user_for_change(id, revision, &account);
    if (result == PANEL_AUTH_USER_OK) {
        sqlite3_stmt *statement = reserve_account_ids() ? prepare("DELETE FROM panel_accounts WHERE id=?") : NULL;
        bool deleted = statement && sqlite3_bind_int64(statement, 1, id) == SQLITE_OK &&
                       sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(database) == 1;
        sqlite3_finalize(statement);
        if (!deleted)
            result = PANEL_AUTH_USER_ERROR;
        else if (account.identity.role == PANEL_AUTH_ROLE_ADMIN && account.login_enabled)
            result = check_remaining_admin(factor_ready);
    }
    OPENSSL_cleanse(&account, sizeof(account));
    return finish_user_change(result);
}
