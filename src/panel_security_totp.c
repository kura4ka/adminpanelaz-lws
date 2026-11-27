#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif

#include "panel_security.h"
#include "panel_security_legacy.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#include <stddef.h>
#include <string.h>
#include <time.h>

#ifndef _WIN32
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#endif

enum {
    KEY_SIZE = 32,
    TOTP_SECRET_BYTES = 20,
    TOTP_STEP_SECONDS = 30,
    TOTP_SETUP_SECONDS = 900,
    TOTP_DIGITS = 6,
    NONCE_BYTES = 12,
    TAG_BYTES = 16,
    SEALED_SECRET_BYTES = NONCE_BYTES + TOTP_SECRET_BYTES + TAG_BYTES
};

enum factor_lookup { FACTOR_ERROR, FACTOR_ABSENT, FACTOR_PRESENT };

struct factor {
    unsigned char sealed[SEALED_SECRET_BYTES];
    int64_t pending_until;
    int64_t last_counter;
    bool enabled;
};

static const char hex[] = "0123456789ABCDEF";
static sqlite3 *database;
static unsigned char encryption_key[KEY_SIZE];
static unsigned char recovery_key[KEY_SIZE];
static bool has_key;

static int hex_digit(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'A' && ch <= 'F')
        return ch - 'A' + 10;
    if (ch >= 'a' && ch <= 'f')
        return ch - 'a' + 10;
    return -1;
}

static bool decode_master_key(const char *value, unsigned char key[KEY_SIZE])
{
    for (size_t i = 0; i < KEY_SIZE; ++i) {
        int hi = hex_digit(*value);
        if (hi < 0)
            return false;
        ++value;
        int lo = hex_digit(*value);
        if (lo < 0)
            return false;
        ++value;
        key[i] = (unsigned char)(hi * 16 + lo);
    }
    return !*value;
}

static bool digest(const unsigned char key[KEY_SIZE], const void *payload, size_t size,
                   unsigned char result[KEY_SIZE])
{
    unsigned int written = 0;
    return HMAC(EVP_sha256(), key, KEY_SIZE, payload, size, result, &written) != NULL && written == KEY_SIZE;
}

static bool derive_key(const unsigned char master[KEY_SIZE], const char *label, unsigned char key[KEY_SIZE])
{
    return digest(master, label, strlen(label), key);
}

static bool execute(const char *sql)
{
    return sqlite3_exec(database, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static sqlite3_stmt *prepare(const char *sql)
{
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(database, sql, -1, &statement, NULL) == SQLITE_OK)
        return statement;
    sqlite3_finalize(statement);
    return NULL;
}

static bool prepare_file(const char *path)
{
#ifndef _WIN32
    if (strcmp(path, ":memory:") != 0) {
        int descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (descriptor < 0)
            return errno == EEXIST;
        return close(descriptor) == 0;
    }
#else
    (void)path;
#endif
    return true;
}

static bool finish_transaction(bool success)
{
    if (success && execute("COMMIT"))
        return true;
    execute("ROLLBACK");
    return false;
}

static void store_uint64(unsigned char out[8], uint64_t value)
{
    for (size_t i = 8; i > 0; --i) {
        out[i - 1] = (unsigned char)(value & 0xff);
        value >>= 8;
    }
}

static bool validate_key(const char *hex_key, bool can_store)
{
    unsigned char master[KEY_SIZE];
    unsigned char check[KEY_SIZE];
    bool supplied = hex_key && *hex_key;
    bool success = false;
    if (supplied && (!decode_master_key(hex_key, master) ||
                     !derive_key(master, "AdminPanelAZ TOTP key check v1", check) ||
                     !derive_key(master, "AdminPanelAZ TOTP secret encryption v1", encryption_key) ||
                     !derive_key(master, "AdminPanelAZ recovery code authentication v1", recovery_key)))
        goto done;

    sqlite3_stmt *statement = prepare("SELECT key_check FROM security_key WHERE id = 1");
    int result = statement ? sqlite3_step(statement) : SQLITE_ERROR;
    if (result == SQLITE_ROW) {
        const void *stored = sqlite3_column_blob(statement, 0);
        success = supplied && stored && sqlite3_column_bytes(statement, 0) == KEY_SIZE &&
                  CRYPTO_memcmp(stored, check, KEY_SIZE) == 0;
    }
    sqlite3_finalize(statement);
    if (result == SQLITE_DONE) {
        statement = prepare("SELECT 1 FROM security_factor LIMIT 1");
        success = statement && sqlite3_step(statement) == SQLITE_DONE;
        sqlite3_finalize(statement);
    }
    if (result == SQLITE_DONE && supplied && success && can_store) {
        statement = prepare("INSERT INTO security_key (id, key_check) VALUES (1, ?)");
        success = statement && sqlite3_bind_blob(statement, 1, check, KEY_SIZE, SQLITE_STATIC) == SQLITE_OK &&
                  sqlite3_step(statement) == SQLITE_DONE;
        sqlite3_finalize(statement);
    }
    has_key = success && supplied;
done:
    OPENSSL_cleanse(master, sizeof(master));
    OPENSSL_cleanse(check, sizeof(check));
    return success;
}

bool panel_security_open(const char *path, const char *hex_key)
{
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS security_key ("
        " id INTEGER PRIMARY KEY CHECK(id = 1),"
        " key_check BLOB NOT NULL CHECK(length(key_check) = 32)"
        ");"
        "CREATE TABLE IF NOT EXISTS security_factor ("
        " account_id INTEGER PRIMARY KEY CHECK(account_id > 0),"
        " sealed BLOB NOT NULL CHECK(length(sealed) = 48),"
        " enabled INTEGER NOT NULL CHECK(enabled IN (0, 1)),"
        " pending_until INTEGER NOT NULL,"
        " last_counter INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS security_recovery ("
        " account_id INTEGER NOT NULL REFERENCES security_factor(account_id) ON DELETE CASCADE,"
        " digest BLOB NOT NULL CHECK(length(digest) = 32),"
        " PRIMARY KEY(account_id, digest)"
        ") WITHOUT ROWID;";
    if (database || !path || !*path || !prepare_file(path))
        return false;
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
#ifdef SQLITE_OPEN_NOFOLLOW
    flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    if (sqlite3_open_v2(path, &database, flags, NULL) != SQLITE_OK ||
        sqlite3_busy_timeout(database, 250) != SQLITE_OK ||
        !execute("PRAGMA foreign_keys = ON; PRAGMA secure_delete = ON; PRAGMA trusted_schema = OFF;") ||
        !execute("BEGIN IMMEDIATE") || !finish_transaction(execute(schema) && validate_key(hex_key, true))) {
        panel_security_close();
        return false;
    }
    return true;
}

void panel_security_close(void)
{
    if (database)
        sqlite3_close(database);
    database = NULL;
    OPENSSL_cleanse(encryption_key, sizeof(encryption_key));
    OPENSSL_cleanse(recovery_key, sizeof(recovery_key));
    has_key = false;
}

bool panel_security_can_enroll(void)
{
    return has_key;
}

static bool seal_secret(int64_t account_id, const unsigned char secret[TOTP_SECRET_BYTES],
                        unsigned char out[SEALED_SECRET_BYTES])
{
    unsigned char owner[8];
    store_uint64(owner, (uint64_t)account_id);
    EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
    unsigned char *encrypted = out + NONCE_BYTES;
    int size = 0;
    int final_size = 0;
    bool success = cipher && RAND_bytes(out, NONCE_BYTES) == 1 &&
                   EVP_EncryptInit_ex(cipher, EVP_aes_256_gcm(), NULL, encryption_key, out) == 1 &&
                   EVP_EncryptUpdate(cipher, NULL, &size, owner, sizeof(owner)) == 1 &&
                   EVP_EncryptUpdate(cipher, encrypted, &size, secret, TOTP_SECRET_BYTES) == 1 &&
                   size == TOTP_SECRET_BYTES && EVP_EncryptFinal_ex(cipher, encrypted + size, &final_size) == 1 &&
                   final_size == 0 &&
                   EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_GET_TAG, TAG_BYTES, encrypted + TOTP_SECRET_BYTES) == 1;
    EVP_CIPHER_CTX_free(cipher);
    return success;
}

static bool unseal_secret(int64_t account_id, const unsigned char sealed[SEALED_SECRET_BYTES],
                          unsigned char secret[TOTP_SECRET_BYTES])
{
    unsigned char owner[8];
    unsigned char tag[TAG_BYTES];
    store_uint64(owner, (uint64_t)account_id);
    memcpy(tag, sealed + NONCE_BYTES + TOTP_SECRET_BYTES, sizeof(tag));
    EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
    unsigned char final[EVP_MAX_BLOCK_LENGTH];
    int size = 0;
    int final_size = 0;
    bool success = cipher && EVP_DecryptInit_ex(cipher, EVP_aes_256_gcm(), NULL, encryption_key, sealed) == 1 &&
                   EVP_DecryptUpdate(cipher, NULL, &size, owner, sizeof(owner)) == 1 &&
                   EVP_DecryptUpdate(cipher, secret, &size, sealed + NONCE_BYTES, TOTP_SECRET_BYTES) == 1 &&
                   size == TOTP_SECRET_BYTES && EVP_CIPHER_CTX_ctrl(cipher, EVP_CTRL_GCM_SET_TAG, TAG_BYTES, tag) == 1 &&
                   EVP_DecryptFinal_ex(cipher, final, &final_size) == 1 && final_size == 0;
    EVP_CIPHER_CTX_free(cipher);
    OPENSSL_cleanse(final, sizeof(final));
    return success;
}

bool panel_security_reconcile_native_factors(const char *path, const char *hex_key,
                                            bool (*mark)(int64_t account_id, void *context), void *context)
{
    if (database || !path || !*path || !mark)
        return false;
    int flags = SQLITE_OPEN_READONLY;
#ifdef SQLITE_OPEN_NOFOLLOW
    flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    bool success = sqlite3_open_v2(path, &database, flags, NULL) == SQLITE_OK &&
                   sqlite3_busy_timeout(database, 250) == SQLITE_OK &&
                   execute("PRAGMA trusted_schema = OFF; BEGIN");
    sqlite3_stmt *statement = success ? prepare("SELECT COUNT(*) FROM main.sqlite_schema WHERE type = 'table'"
        " AND name IN ('security_key','security_factor','security_recovery')") : NULL;
    success = statement && sqlite3_step(statement) == SQLITE_ROW && sqlite3_column_int(statement, 0) == 3;
    sqlite3_finalize(statement);
    statement = success && validate_key(hex_key, false) ?
        prepare("SELECT account_id, sealed FROM security_factor WHERE enabled = 1 ORDER BY account_id") : NULL;
    int result = SQLITE_ERROR;
    success = statement != NULL;
    while (success && (result = sqlite3_step(statement)) == SQLITE_ROW) {
        int64_t id = sqlite3_column_int64(statement, 0);
        const unsigned char *sealed = sqlite3_column_blob(statement, 1);
        unsigned char secret[TOTP_SECRET_BYTES];
        success = has_key && id > 0 && sealed && sqlite3_column_bytes(statement, 1) == SEALED_SECRET_BYTES &&
                  unseal_secret(id, sealed, secret);
        OPENSSL_cleanse(secret, sizeof(secret));
        if (success)
            success = mark(id, context);
    }
    sqlite3_finalize(statement);
    panel_security_close();
    return success && result == SQLITE_DONE;
}

static enum factor_lookup lookup_factor(int64_t account_id, struct factor *factor)
{
    sqlite3_stmt *statement = prepare("SELECT sealed, enabled, pending_until, last_counter"
                                      " FROM security_factor WHERE account_id = ?");
    int result = statement && sqlite3_bind_int64(statement, 1, account_id) == SQLITE_OK ?
                 sqlite3_step(statement) : SQLITE_ERROR;
    enum factor_lookup lookup = result == SQLITE_DONE ? FACTOR_ABSENT : FACTOR_ERROR;
    if (result == SQLITE_ROW) {
        const void *sealed = sqlite3_column_blob(statement, 0);
        if (sealed && sqlite3_column_bytes(statement, 0) == SEALED_SECRET_BYTES) {
            memcpy(factor->sealed, sealed, SEALED_SECRET_BYTES);
            factor->enabled = sqlite3_column_int(statement, 1) == 1;
            factor->pending_until = sqlite3_column_int64(statement, 2);
            factor->last_counter = sqlite3_column_int64(statement, 3);
            lookup = FACTOR_PRESENT;
        }
    }
    sqlite3_finalize(statement);
    return lookup;
}

bool panel_security_factor_is_enabled(int64_t account_id)
{
    struct factor factor;
    unsigned char plaintext[TOTP_SECRET_BYTES];
    bool success = has_key && account_id > 0 && lookup_factor(account_id, &factor) == FACTOR_PRESENT && factor.enabled &&
                   unseal_secret(account_id, factor.sealed, plaintext);
    OPENSSL_cleanse(plaintext, sizeof(plaintext));
    return success;
}

bool panel_security_factor_pending(int64_t account_id)
{
    struct factor factor;
    int64_t now = (int64_t)time(NULL);
    return has_key && now >= 0 && account_id > 0 && lookup_factor(account_id, &factor) == FACTOR_PRESENT &&
           !factor.enabled && now <= factor.pending_until;
}

bool panel_security_factor_status(int64_t account_id, bool *enabled, unsigned int *remaining)
{
    if (!database || account_id <= 0 || !enabled || !remaining)
        return false;
    sqlite3_stmt *statement = prepare("SELECT COALESCE((SELECT enabled FROM security_factor WHERE account_id = ?1), 0),"
                                      " (SELECT COUNT(*) FROM security_recovery WHERE account_id = ?1)");
    bool success = statement && sqlite3_bind_int64(statement, 1, account_id) == SQLITE_OK &&
                   sqlite3_step(statement) == SQLITE_ROW;
    if (success) {
        *enabled = sqlite3_column_int(statement, 0) == 1;
        *remaining = (unsigned int)sqlite3_column_int(statement, 1);
    }
    sqlite3_finalize(statement);
    return success;
}

static void encode_base32(const unsigned char raw[TOTP_SECRET_BYTES], char out[PANEL_SECURITY_TOTP_SECRET_SIZE])
{
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    unsigned int bits = 0;
    unsigned int pending = 0;
    size_t written = 0;
    for (size_t i = 0; i < TOTP_SECRET_BYTES; ++i) {
        bits = (bits << 8) | raw[i];
        pending += 8;
        while (pending >= 5) {
            pending -= 5;
            out[written++] = alphabet[(bits >> pending) & 31];
        }
    }
    out[written] = '\0';
}

bool panel_security_factor_setup(int64_t account_id, char secret[PANEL_SECURITY_TOTP_SECRET_SIZE])
{
    if (!secret)
        return false;
    secret[0] = '\0';
    time_t now = time(NULL);
    if (!has_key || account_id <= 0 || now < 0 || (uint64_t)now > INT64_MAX - TOTP_SETUP_SECONDS)
        return false;
    unsigned char raw[TOTP_SECRET_BYTES];
    unsigned char sealed[SEALED_SECRET_BYTES];
    bool success = RAND_bytes(raw, sizeof(raw)) == 1 && seal_secret(account_id, raw, sealed);
    if (success) {
        sqlite3_stmt *statement = prepare("INSERT INTO security_factor"
                                          " (account_id, sealed, enabled, pending_until, last_counter)"
                                          " VALUES (?, ?, 0, ?, -1) ON CONFLICT(account_id) DO UPDATE"
                                          " SET sealed = excluded.sealed, pending_until = excluded.pending_until"
                                          " WHERE enabled = 0");
        success = statement && sqlite3_bind_int64(statement, 1, account_id) == SQLITE_OK &&
                  sqlite3_bind_blob(statement, 2, sealed, sizeof(sealed), SQLITE_STATIC) == SQLITE_OK &&
                  sqlite3_bind_int64(statement, 3, (int64_t)now + TOTP_SETUP_SECONDS) == SQLITE_OK &&
                  sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(database) == 1;
        sqlite3_finalize(statement);
    }
    if (success)
        encode_base32(raw, secret);
    OPENSSL_cleanse(raw, sizeof(raw));
    OPENSSL_cleanse(sealed, sizeof(sealed));
    return success;
}

static size_t normalize_code(const char *input, char code[PANEL_SECURITY_RECOVERY_SIZE])
{
    size_t length = 0;
    if (!input)
        return 0;
    for (size_t i = 0; i < 48 && input[i]; ++i) {
        if (i == 47)
            return 0;
        char ch = input[i];
        if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n')
            continue;
        int digit = hex_digit(ch);
        if (digit < 0 || length == PANEL_SECURITY_RECOVERY_SIZE - 1)
            return 0;
        code[length++] = hex[digit];
    }
    code[length] = '\0';
    return length;
}

static bool verify_totp(const unsigned char secret[TOTP_SECRET_BYTES], uint64_t counter, const char *code)
{
    unsigned char message[8];
    unsigned char hash[20];
    unsigned int hash_length = 0;
    store_uint64(message, counter);
    bool success = HMAC(EVP_sha1(), secret, TOTP_SECRET_BYTES, message, sizeof(message), hash, &hash_length) &&
                   hash_length == sizeof(hash);
    if (success) {
        unsigned int offset = hash[19] & 15U;
        uint32_t truncated = ((uint32_t)(hash[offset] & 0x7f) << 24) | ((uint32_t)hash[offset + 1] << 16) |
                             ((uint32_t)hash[offset + 2] << 8) | hash[offset + 3];
        char expected[TOTP_DIGITS];
        for (size_t i = sizeof(expected); i > 0; --i) {
            expected[i - 1] = (char)('0' + truncated % 10);
            truncated /= 10;
        }
        success = CRYPTO_memcmp(expected, code, sizeof(expected)) == 0;
        OPENSSL_cleanse(expected, sizeof(expected));
    }
    OPENSSL_cleanse(hash, sizeof(hash));
    return success;
}

static int64_t verify_counter(int64_t account_id, const struct factor *factor, const char *code, int64_t now)
{
    if (now < 0 || strspn(code, "0123456789") != TOTP_DIGITS)
        return -1;
    unsigned char secret[TOTP_SECRET_BYTES];
    int64_t matched = -1;
    if (unseal_secret(account_id, factor->sealed, secret)) {
        int64_t counter = now / TOTP_STEP_SECONDS;
        for (int offset = -1; offset <= 1; ++offset) {
            int64_t candidate = counter + offset;
            if (candidate >= 0 && candidate > factor->last_counter &&
                verify_totp(secret, (uint64_t)candidate, code))
                matched = candidate;
        }
    }
    OPENSSL_cleanse(secret, sizeof(secret));
    return matched;
}

static bool code_digest(int64_t account_id, const char *code, unsigned char out[KEY_SIZE])
{
    unsigned char payload[8 + PANEL_SECURITY_RECOVERY_SIZE - 1];
    store_uint64(payload, (uint64_t)account_id);
    memcpy(payload + 8, code, PANEL_SECURITY_RECOVERY_SIZE - 1);
    bool success = digest(recovery_key, payload, sizeof(payload), out);
    OPENSSL_cleanse(payload, sizeof(payload));
    return success;
}

static bool execute_for_account(const char *sql, int64_t account_id)
{
    sqlite3_stmt *statement = prepare(sql);
    bool success = statement && sqlite3_bind_int64(statement, 1, account_id) == SQLITE_OK &&
                   sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    return success;
}

static bool consume_recovery(int64_t account_id, const char *code)
{
    unsigned char check[KEY_SIZE];
    bool success = false;
    if (code_digest(account_id, code, check)) {
        sqlite3_stmt *statement = prepare("DELETE FROM security_recovery WHERE account_id = ? AND digest = ?");
        success = statement && sqlite3_bind_int64(statement, 1, account_id) == SQLITE_OK &&
                  sqlite3_bind_blob(statement, 2, check, KEY_SIZE, SQLITE_STATIC) == SQLITE_OK &&
                  sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(database) == 1;
        sqlite3_finalize(statement);
    }
    OPENSSL_cleanse(check, sizeof(check));
    return success;
}

static bool store_counter(int64_t account_id, int64_t counter)
{
    sqlite3_stmt *statement = prepare("UPDATE security_factor SET enabled = 1, pending_until = 0, last_counter = ?"
                                      " WHERE account_id = ? AND last_counter < ?1");
    bool success = statement && sqlite3_bind_int64(statement, 1, counter) == SQLITE_OK &&
                   sqlite3_bind_int64(statement, 2, account_id) == SQLITE_OK &&
                   sqlite3_step(statement) == SQLITE_DONE && sqlite3_changes(database) == 1;
    sqlite3_finalize(statement);
    return success;
}

static bool use_factor(int64_t account_id, const struct factor *factor, const char *input)
{
    char code[PANEL_SECURITY_RECOVERY_SIZE];
    size_t length = normalize_code(input, code);
    bool success = false;
    if (length == TOTP_DIGITS) {
        int64_t counter = verify_counter(account_id, factor, code, (int64_t)time(NULL));
        success = counter >= 0 && store_counter(account_id, counter);
    } else if (factor->enabled && length == PANEL_SECURITY_RECOVERY_SIZE - 1) {
        success = consume_recovery(account_id, code);
    }
    OPENSSL_cleanse(code, sizeof(code));
    return success;
}

bool panel_security_second_factor(int64_t account_id, bool required, void *code)
{
    if (!database || account_id <= 0)
        return false;
    struct factor factor;
    enum factor_lookup lookup = lookup_factor(account_id, &factor);
    if (lookup != FACTOR_PRESENT || !factor.enabled)
        return !required && lookup != FACTOR_ERROR;
    if (!has_key || !code || !execute("BEGIN IMMEDIATE"))
        return false;
    /* Recheck the factor after acquiring the write transaction. */
    bool success = lookup_factor(account_id, &factor) == FACTOR_PRESENT && factor.enabled &&
                   use_factor(account_id, &factor, code);
    return finish_transaction(success);
}

static bool add_recovery_codes(int64_t account_id,
                               char codes[PANEL_SECURITY_RECOVERY_COUNT][PANEL_SECURITY_RECOVERY_SIZE])
{
    if (!execute_for_account("DELETE FROM security_recovery WHERE account_id = ?", account_id))
        return false;
    sqlite3_stmt *statement = prepare("INSERT INTO security_recovery (account_id, digest) VALUES (?, ?)");
    if (!statement)
        return false;
    unsigned char random[4];
    unsigned char check[KEY_SIZE];
    bool success = true;
    for (size_t i = 0; i < PANEL_SECURITY_RECOVERY_COUNT && success; ++i) {
        success = RAND_bytes(random, sizeof(random)) == 1;
        if (!success)
            break;
        for (size_t j = 0; j < sizeof(random); ++j) {
            codes[i][2 * j] = hex[random[j] >> 4];
            codes[i][2 * j + 1] = hex[random[j] & 15];
        }
        codes[i][PANEL_SECURITY_RECOVERY_SIZE - 1] = '\0';
        success = code_digest(account_id, codes[i], check) && sqlite3_reset(statement) == SQLITE_OK &&
                  sqlite3_bind_int64(statement, 1, account_id) == SQLITE_OK &&
                  sqlite3_bind_blob(statement, 2, check, KEY_SIZE, SQLITE_STATIC) == SQLITE_OK &&
                  sqlite3_step(statement) == SQLITE_DONE;
    }
    sqlite3_finalize(statement);
    OPENSSL_cleanse(random, sizeof(random));
    OPENSSL_cleanse(check, sizeof(check));
    return success;
}

static bool replace_codes(int64_t account_id, const char *code,
                          char codes[PANEL_SECURITY_RECOVERY_COUNT][PANEL_SECURITY_RECOVERY_SIZE],
                          bool (*mark_required)(int64_t account_id, bool required))
{
    if (!codes)
        return false;
    OPENSSL_cleanse(codes, PANEL_SECURITY_RECOVERY_COUNT * PANEL_SECURITY_RECOVERY_SIZE);
    if (!has_key || account_id <= 0 || !execute("BEGIN IMMEDIATE"))
        return false;
    struct factor factor;
    int64_t now = (int64_t)time(NULL);
    bool enable = mark_required != NULL;
    bool success = now >= 0 && lookup_factor(account_id, &factor) == FACTOR_PRESENT &&
                   factor.enabled != enable && (!enable || now <= factor.pending_until) &&
                   use_factor(account_id, &factor, code) && add_recovery_codes(account_id, codes);
    /* Persist the requirement before committing enrollment. Loss of either store then denies password-only login. */
    if (success && enable)
        success = mark_required(account_id, true);
    success = finish_transaction(success);
    if (!success)
        OPENSSL_cleanse(codes, PANEL_SECURITY_RECOVERY_COUNT * PANEL_SECURITY_RECOVERY_SIZE);
    return success;
}

bool panel_security_factor_enable(int64_t account_id, const char *code,
                                  char codes[PANEL_SECURITY_RECOVERY_COUNT][PANEL_SECURITY_RECOVERY_SIZE],
                                  bool (*mark_required)(int64_t account_id, bool required))
{
    return mark_required && replace_codes(account_id, code, codes, mark_required);
}

bool panel_security_factor_recovery(int64_t account_id, const char *code,
                                    char codes[PANEL_SECURITY_RECOVERY_COUNT][PANEL_SECURITY_RECOVERY_SIZE])
{
    return replace_codes(account_id, code, codes, NULL);
}

bool panel_security_factor_disable(int64_t account_id, const char *code)
{
    if (!has_key || account_id <= 0 || !execute("BEGIN IMMEDIATE"))
        return false;
    struct factor factor;
    bool success = lookup_factor(account_id, &factor) == FACTOR_PRESENT && factor.enabled &&
                   use_factor(account_id, &factor, code) &&
                   execute_for_account("DELETE FROM security_factor WHERE account_id = ?", account_id);
    return finish_transaction(success);
}

bool panel_security_factor_forget(int64_t account_id)
{
    return database && account_id > 0 && execute_for_account("DELETE FROM security_factor WHERE account_id = ?", account_id);
}

static bool decode_base32(const char input[PANEL_SECURITY_TOTP_SECRET_SIZE], unsigned char raw[TOTP_SECRET_BYTES])
{
    unsigned int bits = 0;
    unsigned int pending = 0;
    size_t written = 0;
    for (size_t i = 0; i < PANEL_SECURITY_TOTP_SECRET_SIZE - 1; ++i) {
        unsigned int digit;
        if (input[i] >= 'A' && input[i] <= 'Z')
            digit = (unsigned int)(input[i] - 'A');
        else if (input[i] >= '2' && input[i] <= '7')
            digit = (unsigned int)(input[i] - '2') + 26;
        else
            return false;
        bits = (bits << 5) | digit;
        pending += 5;
        if (pending >= 8) {
            pending -= 8;
            raw[written++] = (unsigned char)(bits >> pending);
        }
    }
    return !input[PANEL_SECURITY_TOTP_SECRET_SIZE - 1] && written == TOTP_SECRET_BYTES;
}

static bool copy_recovery_codes(const struct panel_security_legacy_factor *factor)
{
    sqlite3_stmt *statement = prepare("INSERT INTO security_recovery (account_id, digest) VALUES (?, ?)");
    if (!statement)
        return false;
    unsigned char check[KEY_SIZE];
    bool success = sqlite3_bind_int64(statement, 1, factor->account_id) == SQLITE_OK;
    for (size_t i = 0; i < factor->code_count && success; ++i) {
        const char *code = factor->codes[i];
        success = strspn(code, hex) == PANEL_SECURITY_RECOVERY_SIZE - 1 &&
                  code_digest(factor->account_id, code, check) && sqlite3_reset(statement) == SQLITE_OK &&
                  sqlite3_bind_blob(statement, 2, check, KEY_SIZE, SQLITE_STATIC) == SQLITE_OK &&
                  sqlite3_step(statement) == SQLITE_DONE;
    }
    sqlite3_finalize(statement);
    OPENSSL_cleanse(check, sizeof(check));
    return success;
}

static bool copy_legacy_factor(const struct panel_security_legacy_factor *source, bool *added)
{
    if (source->account_id <= 0 || source->code_count > PANEL_SECURITY_RECOVERY_COUNT)
        return false;
    unsigned char secret[TOTP_SECRET_BYTES];
    unsigned char encrypted[SEALED_SECRET_BYTES];
    struct factor previous;
    enum factor_lookup lookup = lookup_factor(source->account_id, &previous);
    bool success = false;
    *added = false;
    if (decode_base32(source->secret, secret)) {
        if (lookup == FACTOR_PRESENT && previous.enabled) {
            unsigned char existing[TOTP_SECRET_BYTES];
            success = unseal_secret(source->account_id, previous.sealed, existing) &&
                      CRYPTO_memcmp(secret, existing, sizeof(secret)) == 0;
            OPENSSL_cleanse(existing, sizeof(existing));
        } else if (lookup == FACTOR_ABSENT && seal_secret(source->account_id, secret, encrypted)) {
            sqlite3_stmt *statement = prepare("INSERT INTO security_factor"
                " (account_id,sealed,enabled,pending_until,last_counter) VALUES (?,?,1,0,-1)");
            success = statement && sqlite3_bind_int64(statement, 1, source->account_id) == SQLITE_OK &&
                      sqlite3_bind_blob(statement, 2, encrypted, sizeof(encrypted), SQLITE_STATIC) == SQLITE_OK &&
                      sqlite3_step(statement) == SQLITE_DONE;
            sqlite3_finalize(statement);
            success = success && copy_recovery_codes(source);
            *added = success;
        }
    }
    OPENSSL_cleanse(secret, sizeof(secret));
    OPENSSL_cleanse(encrypted, sizeof(encrypted));
    return success;
}

bool panel_security_import_factors(panel_security_factor_reader reader, void *context, unsigned int *imported)
{
    if (!has_key || !reader || !imported || !execute("BEGIN IMMEDIATE"))
        return false;
    struct panel_security_legacy_factor factor = {0};
    unsigned int count = 0;
    unsigned int added = 0;
    bool success = true;
    int result = 0;
    while (success && (result = reader(context, &factor)) > 0) {
        bool appended = false;
        success = ++count <= 10000 && copy_legacy_factor(&factor, &appended);
        added += appended;
        OPENSSL_cleanse(&factor, sizeof(factor));
    }
    OPENSSL_cleanse(&factor, sizeof(factor));
    success = finish_transaction(success && result == 0);
    if (success)
        *imported = added;
    return success;
}
