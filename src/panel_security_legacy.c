#include "panel_security_legacy.h"

#include "legacy_accounts.h"
#include "panel_auth_schema.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <string.h>

enum {
    FERNET_KEY_SIZE = 32, FERNET_IV_SIZE = 16, FERNET_BLOCK_SIZE = 16, FERNET_TAG_SIZE = 32,
    FERNET_HEADER_SIZE = 1 + 8 + FERNET_IV_SIZE, FERNET_MIN_SIZE = FERNET_HEADER_SIZE + FERNET_BLOCK_SIZE + FERNET_TAG_SIZE,
    FERNET_TEXT_MAX = 512, FERNET_DECODED_MAX = FERNET_TEXT_MAX * 3 / 4,
    MIGRATION_ROW_MAX = 10000, QUERY_INTERVAL = 1000, QUERY_STEP_LIMIT = 10000
};

struct legacy_reader {
    sqlite3_stmt *source;
    sqlite3_stmt *accounts;
    unsigned char key[FERNET_KEY_SIZE];
};

static bool decode_base64url(const char *encoded, size_t size, unsigned char *out, size_t *length)
{
    unsigned char text[FERNET_TEXT_MAX];
    if (!size || size > sizeof(text) || size % 4)
        return false;
    int padding = 0;
    for (size_t i = 0; i < size; ++i) {
        char ch = encoded[i];
        if (ch == '=') {
            if (i < size - 2)
                return false;
            ++padding;
        } else if (padding) {
            return false;
        } else if (ch == '-') {
            ch = '+';
        } else if (ch == '_') {
            ch = '/';
        } else if (!((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9'))) {
            return false;
        }
        text[i] = (unsigned char)ch;
    }
    int decoded = EVP_DecodeBlock(out, text, (int)size);
    if (decoded <= padding)
        return false;
    *length = (size_t)(decoded - padding);
    return true;
}

static bool open_fernet(const unsigned char key[FERNET_KEY_SIZE], const char *encoded, size_t size,
                        unsigned char cleartext[FERNET_DECODED_MAX], size_t *written)
{
    unsigned char decoded[FERNET_DECODED_MAX], digest[FERNET_TAG_SIZE];
    size_t length;
    unsigned int digest_length = 0;
    if (!decode_base64url(encoded, size, decoded, &length) || length < FERNET_MIN_SIZE || decoded[0] != 0x80)
        return false;
    size_t message_length = length - FERNET_TAG_SIZE;
    size_t cipher_length = message_length - FERNET_HEADER_SIZE;
    bool authenticated = cipher_length % FERNET_BLOCK_SIZE == 0 &&
        HMAC(EVP_sha256(), key, FERNET_KEY_SIZE / 2, decoded, message_length, digest, &digest_length) &&
        digest_length == sizeof(digest) && CRYPTO_memcmp(digest, decoded + message_length, sizeof(digest)) == 0;
    OPENSSL_cleanse(digest, sizeof(digest));
    if (!authenticated)
        return false;

    EVP_CIPHER_CTX *cipher = EVP_CIPHER_CTX_new();
    int bytes = 0;
    int final = 0;
    bool success = cipher && EVP_DecryptInit_ex(cipher, EVP_aes_128_cbc(), NULL, key + FERNET_KEY_SIZE / 2,
                                               decoded + FERNET_HEADER_SIZE - FERNET_IV_SIZE) == 1 &&
                   EVP_DecryptUpdate(cipher, cleartext, &bytes, decoded + FERNET_HEADER_SIZE, (int)cipher_length) == 1 &&
                   EVP_DecryptFinal_ex(cipher, cleartext + bytes, &final) == 1;
    EVP_CIPHER_CTX_free(cipher);
    if (success)
        *written = (size_t)(bytes + final);
    return success;
}

static const unsigned char *skip_space(const unsigned char *cur, const unsigned char *end)
{
    while (cur < end && (*cur == ' ' || *cur == '\t' || *cur == '\r' || *cur == '\n'))
        ++cur;
    return cur;
}

static bool parse_codes(const unsigned char *text, size_t size, struct panel_security_legacy_factor *factor)
{
    const unsigned char *end = text + size;
    const unsigned char *cur = skip_space(text, end);
    if (cur == end || *cur++ != '[')
        return false;
    cur = skip_space(cur, end);
    if (cur < end && *cur == ']')
        return skip_space(cur + 1, end) == end;

    while (factor->code_count < PANEL_SECURITY_RECOVERY_COUNT && end - cur > PANEL_SECURITY_RECOVERY_SIZE && *cur++ == '"') {
        char *code = factor->codes[factor->code_count];
        for (size_t i = 0; i < PANEL_SECURITY_RECOVERY_SIZE - 1; ++i) {
            unsigned char ch = *cur++;
            if (!((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F')))
                return false;
            code[i] = (char)ch;
        }
        code[PANEL_SECURITY_RECOVERY_SIZE - 1] = '\0';
        if (*cur++ != '"')
            return false;
        for (size_t i = 0; i < factor->code_count; ++i) {
            if (!memcmp(code, factor->codes[i], PANEL_SECURITY_RECOVERY_SIZE))
                return false;
        }
        ++factor->code_count;
        cur = skip_space(cur, end);
        if (cur == end)
            return false;
        if (*cur == ']')
            return skip_space(cur + 1, end) == end;
        if (*cur++ != ',')
            return false;
        cur = skip_space(cur, end);
    }
    return false;
}

static bool decrypt_column(struct legacy_reader *reader, int column,
                           unsigned char output[FERNET_DECODED_MAX], size_t *bytes)
{
    if (sqlite3_column_type(reader->source, column) != SQLITE_TEXT)
        return false;
    const char *data = (const char *)sqlite3_column_text(reader->source, column);
    int count = sqlite3_column_bytes(reader->source, column);
    return data && count > 0 && open_fernet(reader->key, data, (size_t)count, output, bytes);
}

static int read_factor(void *value, struct panel_security_legacy_factor *factor)
{
    struct legacy_reader *reader = value;
    int source = sqlite3_step(reader->source);
    int target = sqlite3_step(reader->accounts);
    if (source == SQLITE_DONE && target == SQLITE_DONE)
        return 0;
    if (source != SQLITE_ROW || target != SQLITE_ROW || sqlite3_column_type(reader->source, 0) != SQLITE_INTEGER)
        return -1;
    factor->account_id = sqlite3_column_int64(reader->source, 0);
    const unsigned char *username = sqlite3_column_text(reader->source, 1);
    const unsigned char *target_username = sqlite3_column_text(reader->accounts, 1);
    int username_length = sqlite3_column_bytes(reader->source, 1);
    if (factor->account_id <= 0 || factor->account_id != sqlite3_column_int64(reader->accounts, 0) ||
        sqlite3_column_type(reader->source, 1) != SQLITE_TEXT || sqlite3_column_type(reader->accounts, 1) != SQLITE_TEXT ||
        username_length <= 0 || username_length != sqlite3_column_bytes(reader->accounts, 1) ||
        !panel_auth_valid_username(username, (size_t)username_length) || !target_username ||
        memcmp(username, target_username, (size_t)username_length))
        return -1;

    unsigned char cleartext[FERNET_DECODED_MAX];
    size_t size;
    bool success = decrypt_column(reader, 2, cleartext, &size) && size == PANEL_SECURITY_TOTP_SECRET_SIZE - 1;
    if (success) {
        memcpy(factor->secret, cleartext, size);
        factor->secret[size] = '\0';
        if (sqlite3_column_type(reader->source, 3) != SQLITE_NULL)
            success = decrypt_column(reader, 3, cleartext, &size) && parse_codes(cleartext, size, factor);
    }
    OPENSSL_cleanse(cleartext, sizeof(cleartext));
    return success ? 1 : -1;
}

static int limit_query(void *value)
{
    unsigned int *remaining = value;
    return *remaining == 0 || --*remaining == 0;
}

static bool require_tables(sqlite3 *db, const char *sql, int count)
{
    sqlite3_stmt *statement = NULL;
    bool found = sqlite3_prepare_v2(db, sql, -1, &statement, NULL) == SQLITE_OK &&
                 sqlite3_step(statement) == SQLITE_ROW && sqlite3_column_int(statement, 0) == count;
    sqlite3_finalize(statement);
    return found;
}

bool panel_security_import_legacy_totp(const char *source_path, const char *target_path, const char *upstream_key,
                                       unsigned int *imported)
{
    if (!upstream_key || !*upstream_key || !imported)
        return false;
    sqlite3 *source = legacy_accounts_open_readonly(source_path);
    sqlite3 *target = legacy_accounts_open_readonly(target_path);
    struct legacy_reader reader = {0};
    unsigned int key_length = 0;
    unsigned int source_steps = QUERY_STEP_LIMIT;
    unsigned int target_steps = QUERY_STEP_LIMIT;
    if (source)
        sqlite3_progress_handler(source, QUERY_INTERVAL, limit_query, &source_steps);
    if (target)
        sqlite3_progress_handler(target, QUERY_INTERVAL, limit_query, &target_steps);
    bool success = source && target &&
        require_tables(source, "SELECT count(*) FROM pragma_table_list WHERE schema='main' AND type='table' AND name='users'", 1) &&
        require_tables(target, "SELECT count(*) FROM pragma_table_list WHERE schema='main' AND type='table'"
                                " AND name IN ('panel_legacy_accounts','panel_accounts')", 2) &&
        EVP_Digest(upstream_key, strlen(upstream_key), reader.key, &key_length, EVP_sha256(), NULL) == 1 &&
        key_length == sizeof(reader.key) &&
        sqlite3_prepare_v2(source, "SELECT id, username, totp_secret_encrypted, totp_backup_codes_encrypted"
                                   " FROM main.users WHERE totp_enabled = 1 ORDER BY id LIMIT ?", -1,
                           &reader.source, NULL) == SQLITE_OK &&
        sqlite3_prepare_v2(target, "SELECT a.id, a.username FROM main.panel_accounts AS a"
                                   " JOIN main.panel_legacy_accounts AS l ON a.id = l.account_id"
                                   " WHERE l.from_legacy = 1 AND l.totp_enabled = 1 ORDER BY a.id LIMIT ?", -1,
                           &reader.accounts, NULL) == SQLITE_OK &&
        sqlite3_bind_int(reader.source, 1, MIGRATION_ROW_MAX + 1) == SQLITE_OK &&
        sqlite3_bind_int(reader.accounts, 1, MIGRATION_ROW_MAX + 1) == SQLITE_OK &&
        panel_security_import_factors(read_factor, &reader, imported);
    sqlite3_finalize(reader.source);
    sqlite3_finalize(reader.accounts);
    OPENSSL_cleanse(reader.key, sizeof(reader.key));
    sqlite3_close(source);
    sqlite3_close(target);
    return success;
}
