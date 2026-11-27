#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "panel_auth.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

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
    sqlite3_int64 id;
    char username[PANEL_AUTH_USERNAME_MAX + 1];
    struct password_secret secret;
};

static sqlite3 *database;
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

bool panel_auth_open(const char *path, const char *initial_password)
{
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS panel_accounts ("
        " id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE,"
        " password_salt BLOB NOT NULL CHECK(length(password_salt) = 16),"
        " password_hash BLOB NOT NULL CHECK(length(password_hash) = 32),"
        " iterations INTEGER NOT NULL CHECK(iterations >= 300000)"
        ");"
        "CREATE TABLE IF NOT EXISTS panel_sessions ("
        " token_digest BLOB PRIMARY KEY CHECK(length(token_digest) = 32),"
        " account_id INTEGER NOT NULL REFERENCES panel_accounts(id) ON DELETE CASCADE,"
        " expires_at INTEGER NOT NULL"
        ") WITHOUT ROWID;"
        "CREATE INDEX IF NOT EXISTS panel_sessions_expiry ON panel_sessions(expires_at);";
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
    if (!execute(schema) || !bootstrap_admin(initial_password) || !prune_expired(now) || !execute("COMMIT")) {
        fprintf(stderr, "Cannot initialize authentication schema: %s\n", sqlite3_errmsg(database));
        execute("ROLLBACK");
        panel_auth_close();
        return false;
    }
    return true;
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
    const unsigned char *username = sqlite3_column_text(statement, 1);
    int length = sqlite3_column_bytes(statement, 1);
    const void *salt = sqlite3_column_blob(statement, 2);
    const void *hash = sqlite3_column_blob(statement, 3);
    sqlite3_int64 iterations = sqlite3_column_int64(statement, 4);
    if (!username || length <= 0 || length > PANEL_AUTH_USERNAME_MAX || memchr(username, '\0', (size_t)length) ||
        !salt || sqlite3_column_bytes(statement, 2) != SALT_SIZE ||
        !hash || sqlite3_column_bytes(statement, 3) != DIGEST_SIZE ||
        iterations < PASSWORD_ITERATIONS || iterations > MAX_STORED_ITERATIONS)
        return LOOKUP_ERROR;

    account->id = sqlite3_column_int64(statement, 0);
    memcpy(account->username, username, (size_t)length + 1);
    memcpy(account->secret.salt, salt, SALT_SIZE);
    memcpy(account->secret.hash, hash, DIGEST_SIZE);
    account->secret.iterations = (int)iterations;
    return LOOKUP_FOUND;
}

static enum lookup_result find_account(const char *username, const unsigned char *digest,
                                       sqlite3_int64 now, struct account *account)
{
    sqlite3_stmt *statement;
    bool bound;
    if (username) {
        statement = prepare("SELECT id, username, password_salt, password_hash, iterations"
                            " FROM panel_accounts WHERE username = ?");
        bound = statement && sqlite3_bind_text(statement, 1, username, -1, SQLITE_STATIC) == SQLITE_OK;
    } else {
        statement = prepare("SELECT a.id, a.username, a.password_salt, a.password_hash, a.iterations"
                            " FROM panel_sessions AS s JOIN panel_accounts AS a ON a.id = s.account_id"
                            " WHERE s.token_digest = ? AND s.expires_at > ?");
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
                                      " WHERE id = ? AND password_salt = ? AND password_hash = ? AND iterations = ?");
    bool success = statement && sqlite3_bind_blob(statement, 1, digest, DIGEST_SIZE, SQLITE_STATIC) == SQLITE_OK &&
                   sqlite3_bind_int64(statement, 2, now + SESSION_SECONDS) == SQLITE_OK &&
                   sqlite3_bind_int64(statement, 3, account->id) == SQLITE_OK && bind_secret(statement, 4, &account->secret) &&
                   sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(database) == 1;
    sqlite3_finalize(statement);
    return success;
}

bool panel_auth_login(const char *username, const char *password, char token[PANEL_AUTH_TOKEN_SIZE])
{
    if (!token)
        return false;
    OPENSSL_cleanse(token, PANEL_AUTH_TOKEN_SIZE);
    size_t name_length = bounded_length(username, PANEL_AUTH_USERNAME_MAX + 1);
    size_t password_length = bounded_length(password, PANEL_AUTH_PASSWORD_MAX + 1);
    if (!database || panel_auth_retry_after() || !name_length || name_length > PANEL_AUTH_USERNAME_MAX ||
        !password_length || password_length > PANEL_AUTH_PASSWORD_MAX)
        return false;

    struct account account = { .secret.iterations = PASSWORD_ITERATIONS };
    enum lookup_result result = find_account(username, NULL, 0, &account);
    bool success = false;
    if (result != LOOKUP_ERROR) {
        /* Missing usernames take the same password derivation path. */
        bool verified = verify_password(password, password_length, &account.secret) && result == LOOKUP_FOUND;
        record_verification(verified);
        if (verified) {
            unsigned char digest[DIGEST_SIZE];
            sqlite3_int64 now;
            success = current_time(&now) && prune_expired(now) && new_token(token, digest) &&
                      store_session(&account, digest, now);
            OPENSSL_cleanse(digest, sizeof(digest));
        }
    }
    OPENSSL_cleanse(&account, sizeof(account));
    if (!success)
        OPENSSL_cleanse(token, PANEL_AUTH_TOKEN_SIZE);
    return success;
}

bool panel_auth_session(const char *token, char username[PANEL_AUTH_USERNAME_MAX + 1])
{
    if (username)
        username[0] = '\0';
    unsigned char digest[DIGEST_SIZE];
    sqlite3_int64 now;
    struct account account;
    bool success = database && token_digest(token, digest) && current_time(&now) &&
                   find_account(NULL, digest, now, &account) == LOOKUP_FOUND;
    if (success && username)
        memcpy(username, account.username, strlen(account.username) + 1);
    OPENSSL_cleanse(digest, sizeof(digest));
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

static bool update_password(const struct account *account, const struct password_secret *replacement,
                            const unsigned char digest[DIGEST_SIZE], sqlite3_int64 now)
{
    sqlite3_stmt *statement = prepare("UPDATE panel_accounts SET password_salt = ?, password_hash = ?, iterations = ?"
                                      " WHERE id = ? AND password_salt = ? AND password_hash = ? AND iterations = ?"
                                      " AND EXISTS (SELECT 1 FROM panel_sessions WHERE token_digest = ?"
                                      " AND account_id = panel_accounts.id AND expires_at > ?)");
    bool success = statement && bind_secret(statement, 1, replacement) &&
                   sqlite3_bind_int64(statement, 4, account->id) == SQLITE_OK && bind_secret(statement, 5, &account->secret) &&
                   sqlite3_bind_blob(statement, 8, digest, DIGEST_SIZE, SQLITE_STATIC) == SQLITE_OK &&
                   sqlite3_bind_int64(statement, 9, now) == SQLITE_OK &&
                   sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(database) == 1;
    sqlite3_finalize(statement);
    if (!success)
        return false;

    statement = prepare("DELETE FROM panel_sessions WHERE account_id = ?");
    success = statement && sqlite3_bind_int64(statement, 1, account->id) == SQLITE_OK &&
              sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    return success;
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
    struct account account;
    struct password_secret replacement;
    bool success = false;
    if (token_digest(token, digest) && current_time(&now) &&
        find_account(NULL, digest, now, &account) == LOOKUP_FOUND) {
        bool verified = verify_password(old_password, old_length, &account.secret);
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
