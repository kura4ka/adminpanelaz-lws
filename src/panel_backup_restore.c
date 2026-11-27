#ifndef _WIN32
#define _GNU_SOURCE
#endif

#include "panel_backup_restore.h"

#include "panel_auth.h"
#include "panel_auth_schema.h"
#include "panel_backup_create.h"

#include <archive.h>
#include <archive_entry.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>
#include <zlib.h>

#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#include <stdint.h>
#include <windows.h>
#define fd_to_file _fdopen
#define close_fd _close
#define sync_fd _commit
#else
#include <unistd.h>
#define fd_to_file fdopen
#define close_fd close
#define sync_fd fsync
#endif

enum {
    PATH_LIMIT = 4096,
    BLOCK_SIZE = 512,
    BUFFER_SIZE = 16 * 1024,
    DATABASE_LIMIT = 64 * 1024 * 1024,
    ARCHIVE_LIMIT = DATABASE_LIMIT + 1024 * 1024,
    UPSTREAM_SOURCE_LIMIT = 200 * 1024 * 1024,
    UPSTREAM_TAR_LIMIT = 256 * 1024 * 1024,
    UPSTREAM_DB_LIMIT = 128 * 1024 * 1024,
    UPSTREAM_AWG_LIMIT = 128 * 1024 * 1024,
    UPSTREAM_ENV_LIMIT = 1024 * 1024,
    UPSTREAM_CONFIG_LIMIT = 16 * 1024 * 1024,
    FERNET_HEADER_SIZE = 25,
    FERNET_TAG_SIZE = 32,
    FERNET_BLOCK_SIZE = 16
};

static const unsigned char encrypted_magic[] = "APAZBK1\n";

struct tar_input {
    FILE *file;
    EVP_CIPHER_CTX *cipher;
    z_stream stream;
    unsigned char compressed[BUFFER_SIZE];
    unsigned char decoded[BUFFER_SIZE];
    size_t source_remaining;
    size_t decoded_limit;
    size_t decoded_total;
    size_t nonzero_end;
    bool gzip;
    bool finished;
    bool cipher_finished;
};

struct schema_entry {
    const char *type;
    const char *name;
    const char *table;
    const char *sql;
};

/* Match the schema created by panel_auth_open. SQLite omits IF NOT EXISTS and the trailing semicolon. */
static const struct schema_entry native_schema[] = {
    { "table", "panel_accounts", "panel_accounts", "CREATE TABLE panel_accounts" PANEL_ACCOUNTS_COLUMNS },
    { "table", "panel_sessions", "panel_sessions", "CREATE TABLE panel_sessions" PANEL_SESSIONS_COLUMNS },
    { "index", "panel_sessions_expiry", "panel_sessions",
      "CREATE INDEX panel_sessions_expiry ON panel_sessions(expires_at)" },
    { "index", "sqlite_autoindex_panel_accounts_1", "panel_accounts", NULL },
    { "table", "panel_legacy_accounts", "panel_legacy_accounts",
      "CREATE TABLE panel_legacy_accounts" PANEL_LEGACY_ACCOUNTS_COLUMNS },
    { "table", "panel_account_ids", "panel_account_ids",
      "CREATE TABLE panel_account_ids" PANEL_ACCOUNT_IDS_COLUMNS }
};

static int open_archive_source(const char *path, size_t size_limit, size_t *length)
{
#ifdef _WIN32
    HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                              FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return -1;

    BY_HANDLE_FILE_INFORMATION info;
    LARGE_INTEGER size;
    int fd = -1;
    if (GetFileType(file) == FILE_TYPE_DISK && GetFileInformationByHandle(file, &info) &&
        !(info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)) &&
        GetFileSizeEx(file, &size) && size.QuadPart > 0 && (unsigned long long)size.QuadPart <= size_limit) {
        fd = _open_osfhandle((intptr_t)file, _O_RDONLY | _O_BINARY);
        if (length)
            *length = (size_t)size.QuadPart;
    }
    if (fd < 0)
        CloseHandle(file);
    return fd;
#else
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    struct stat info;
    if (fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && info.st_size > 0 &&
        (unsigned long long)info.st_size <= size_limit) {
        if (length)
            *length = (size_t)info.st_size;
        return fd;
    }

    close_fd(fd);
    return -1;
#endif
}

static int create_destination(const char *path, bool scratch)
{
#ifdef _WIN32
    const char *colon = strchr(path, ':');
    if (colon && (colon != path + 1 || strchr(colon + 1, ':')))
        return -1;

    int flags = scratch ? _O_RDWR | _O_TEMPORARY : _O_WRONLY;
    int fd = _open(path, flags | _O_CREAT | _O_EXCL | _O_BINARY | _O_NOINHERIT, _S_IREAD | _S_IWRITE);
    if (fd >= 0 && GetFileType((HANDLE)_get_osfhandle(fd)) != FILE_TYPE_DISK) {
        close_fd(fd);
        return -1;
    }
    return fd;
#else
    int flags = scratch ? O_RDWR : O_WRONLY;
    int fd = open(path, flags | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd >= 0 && scratch && unlink(path) != 0) {
        close_fd(fd);
        return -1;
    }
    return fd;
#endif
}

static int read_cipher(struct tar_input *input, unsigned char *buffer)
{
    unsigned char ciphertext[BUFFER_SIZE - EVP_MAX_BLOCK_LENGTH];
    int count = 0;
    while (input->source_remaining && !count) {
        size_t wanted = input->source_remaining < sizeof(ciphertext) ?
                        input->source_remaining : sizeof(ciphertext);
        if (fread(ciphertext, 1, wanted, input->file) != wanted ||
            EVP_DecryptUpdate(input->cipher, buffer, &count, ciphertext, (int)wanted) != 1)
            return -1;
        input->source_remaining -= wanted;
    }
    if (count || input->cipher_finished)
        return count;
    input->cipher_finished = true;
    return EVP_DecryptFinal_ex(input->cipher, buffer, &count) == 1 ? count : -1;
}

static int read_source(struct tar_input *input, unsigned char *buffer)
{
    if (input->cipher)
        return read_cipher(input, buffer);
    if (!input->source_remaining)
        return fgetc(input->file) == EOF && !ferror(input->file) ? 0 : -1;

    size_t wanted = input->source_remaining < BUFFER_SIZE ? input->source_remaining : BUFFER_SIZE;
    size_t count = fread(buffer, 1, wanted, input->file);
    input->source_remaining -= count;
    return count != wanted || ferror(input->file) ? -1 : (int)count;
}

static int read_gzip(struct tar_input *input)
{
    if (input->finished)
        return 0;
    z_stream *stream = &input->stream;
    stream->next_out = input->decoded;
    stream->avail_out = BUFFER_SIZE;
    while (stream->avail_out == BUFFER_SIZE) {
        if (!stream->avail_in) {
            int count = read_source(input, input->compressed);
            if (count < 0)
                return -1;
            stream->next_in = input->compressed;
            stream->avail_in = (uInt)count;
        }
        int status = inflate(stream, Z_NO_FLUSH);
        if (status == Z_STREAM_END) {
            if (stream->avail_in || read_source(input, input->compressed) != 0)
                return -1;
            input->finished = true;
            break;
        }
        if (status != Z_OK)
            return -1;
    }
    return BUFFER_SIZE - (int)stream->avail_out;
}

static la_ssize_t read_tar_block(struct archive *archive, void *context, const void **buffer)
{
    (void)archive;
    struct tar_input *input = context;
    *buffer = input->decoded;
    int count = input->gzip ? read_gzip(input) : read_source(input, input->decoded);
    if (count <= 0)
        return count;
    if ((size_t)count > input->decoded_limit - input->decoded_total)
        return -1;

    /* Keep the offset of the last nonzero byte, including buffered trailing data. */
    for (int i = count; i > 0; --i) {
        if (input->decoded[i - 1]) {
            input->nonzero_end = input->decoded_total + (size_t)i;
            break;
        }
    }
    input->decoded_total += (size_t)count;
    return count;
}

static bool database_header(const unsigned char *buffer, size_t count, bool native)
{
    return count >= 100 && !memcmp(buffer, "SQLite format 3", 16) &&
           (buffer[18] == 1 || (!native && buffer[18] == 2)) && buffer[18] == buffer[19];
}

static bool copy_database(struct archive *archive, FILE *destination, size_t size)
{
    unsigned char buffer[BUFFER_SIZE];
    size_t written = 0;
    while (written < size) {
        size_t wanted = size - written < sizeof(buffer) ? size - written : sizeof(buffer);
        la_ssize_t count = archive_read_data(archive, buffer, wanted);
        if (count <= 0)
            return false;
        if (!written && !database_header(buffer, (size_t)count, true))
            return false;
        if (fwrite(buffer, 1, (size_t)count, destination) != (size_t)count)
            return false;
        written += (size_t)count;
    }
    return true;
}

static size_t stage_member(struct archive *archive, struct tar_input *input, FILE *destination)
{
    struct archive_entry *entry;
    if (archive_read_next_header(archive, &entry) != ARCHIVE_OK ||
        archive_format(archive) != ARCHIVE_FORMAT_TAR_USTAR ||
        archive_filter_bytes(archive, 0) != BLOCK_SIZE)
        return 0;

    const char *name = archive_entry_pathname(entry);
    la_int64_t size = archive_entry_size(entry);
    if (!name || strcmp(name, "data/lws-auth.db") || archive_entry_filetype(entry) != AE_IFREG ||
        archive_entry_symlink(entry) || archive_entry_hardlink(entry) || archive_entry_sparse_count(entry) ||
        !archive_entry_size_is_set(entry) || size < BLOCK_SIZE || size > DATABASE_LIMIT)
        return 0;

    if (!copy_database(archive, destination, (size_t)size) ||
        archive_read_next_header(archive, &entry) != ARCHIVE_EOF)
        return 0;

    const void *block;
    la_ssize_t trailing;
    do {
        trailing = read_tar_block(archive, input, &block);
    } while (trailing > 0);

    size_t member_end = BLOCK_SIZE + ((size_t)size + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE;
    if (trailing < 0 || input->decoded_total < member_end + 2 * BLOCK_SIZE ||
        input->decoded_total % BLOCK_SIZE || input->nonzero_end > member_end)
        return 0;
    return (size_t)size;
}

static size_t stage_archive(FILE *source, FILE *destination, size_t source_size)
{
    unsigned char prefix[2];
    if (fread(prefix, 1, sizeof(prefix), source) != sizeof(prefix) || fseek(source, 0, SEEK_SET) != 0)
        return 0;
    struct tar_input input = { .file = source, .source_remaining = source_size, .decoded_limit = ARCHIVE_LIMIT,
                               .gzip = prefix[0] == 0x1f && prefix[1] == 0x8b };
    if (input.gzip && inflateInit2(&input.stream, MAX_WBITS + 16) != Z_OK)
        return 0;
    struct archive *archive = archive_read_new();
    size_t size = 0;
    if (archive && archive_read_support_filter_none(archive) == ARCHIVE_OK &&
        archive_read_support_format_tar(archive) == ARCHIVE_OK &&
        archive_read_open(archive, &input, NULL, read_tar_block, NULL) == ARCHIVE_OK)
        size = stage_member(archive, &input, destination);
    if (archive)
        archive_read_free(archive);
    if (input.gzip)
        inflateEnd(&input.stream);
    return size;
}

static bool matches_text(sqlite3_stmt *row, int column, const char *expected)
{
    if (!expected)
        return sqlite3_column_type(row, column) == SQLITE_NULL;
    if (sqlite3_column_type(row, column) != SQLITE_TEXT)
        return false;
    const unsigned char *value = sqlite3_column_text(row, column);
    size_t length = strlen(expected);
    return value && sqlite3_column_bytes(row, column) == (int)length && !memcmp(value, expected, length);
}

static bool check_schema(sqlite3 *db, bool *legacy, bool *sequence)
{
    static const size_t entry_count = sizeof(native_schema) / sizeof(native_schema[0]);
    static const unsigned int required = 0x0f;
    sqlite3_stmt *query = NULL;
    if (sqlite3_prepare_v2(db, "SELECT type, name, tbl_name, sql FROM sqlite_schema", -1, &query, NULL) != SQLITE_OK)
        return false;
    unsigned int found = 0;
    int status;
    while ((status = sqlite3_step(query)) == SQLITE_ROW) {
        size_t i = 0;
        for (; i < entry_count; ++i) {
            const struct schema_entry *expected = &native_schema[i];
            if (!(found & (1u << i)) && matches_text(query, 0, expected->type) &&
                matches_text(query, 1, expected->name) && matches_text(query, 2, expected->table) &&
                matches_text(query, 3, expected->sql))
                break;
        }
        if (i == entry_count)
            break;
        found |= 1u << i;
    }
    sqlite3_finalize(query);
    *legacy = (found & (1u << 4)) != 0;
    *sequence = (found & (1u << 5)) != 0;
    return status == SQLITE_DONE && (found & required) == required;
}

static bool check_integrity(sqlite3 *db, size_t size)
{
    sqlite3_stmt *query = NULL;
    static const char sql[] = "SELECT page_count, page_size FROM pragma_page_count(), pragma_page_size()";
    bool valid = sqlite3_prepare_v2(db, sql, -1, &query, NULL) == SQLITE_OK && sqlite3_step(query) == SQLITE_ROW;
    if (valid) {
        sqlite3_int64 pages = sqlite3_column_int64(query, 0);
        sqlite3_int64 page_size = sqlite3_column_int64(query, 1);
        valid = pages > 0 && page_size >= BLOCK_SIZE && page_size <= (sqlite3_int64)size &&
                pages == (sqlite3_int64)size / page_size && size % (size_t)page_size == 0;
    }
    sqlite3_finalize(query);
    if (!valid)
        return false;

    query = NULL;
    valid = sqlite3_prepare_v2(db, "PRAGMA integrity_check(1)", -1, &query, NULL) == SQLITE_OK &&
            sqlite3_step(query) == SQLITE_ROW && matches_text(query, 0, "ok") && sqlite3_step(query) == SQLITE_DONE;
    sqlite3_finalize(query);
    return valid;
}

static bool check_accounts(sqlite3 *db)
{
    static const char sql[] =
        "SELECT EXISTS (SELECT 1 FROM panel_accounts)"
        " AND NOT EXISTS (SELECT 1 FROM panel_sessions)"
        " AND NOT EXISTS (SELECT 1 FROM panel_accounts WHERE"
        " id <= 0 OR typeof(username) != 'text' OR length(CAST(username AS BLOB)) NOT BETWEEN 1 AND ?"
        " OR length(username) NOT BETWEEN 1 AND 64"
        " OR instr(username, char(0)) > 0"
        " OR typeof(password_salt) != 'blob' OR length(password_salt) != 16"
        " OR typeof(password_hash) != 'blob' OR length(password_hash) != 32"
        " OR typeof(iterations) != 'integer' OR iterations NOT BETWEEN 300000 AND 5000000)";
    sqlite3_stmt *query = NULL;
    bool valid = sqlite3_prepare_v2(db, sql, -1, &query, NULL) == SQLITE_OK &&
                 sqlite3_bind_int(query, 1, PANEL_AUTH_USERNAME_MAX) == SQLITE_OK &&
                 sqlite3_step(query) == SQLITE_ROW && sqlite3_column_int(query, 0) == 1;
    sqlite3_finalize(query);
    return valid;
}

static bool check_legacy_accounts(sqlite3 *db)
{
    static const char sql[] =
        "SELECT NOT EXISTS (SELECT 1 FROM pragma_foreign_key_check())"
        " AND NOT EXISTS (SELECT 1 FROM panel_legacy_accounts l JOIN panel_accounts a ON a.id = l.account_id WHERE"
        " l.bcrypt_hash IS NOT NULL AND (typeof(l.bcrypt_hash) != 'text' OR length(CAST(l.bcrypt_hash AS BLOB)) != 60"
        " OR l.bcrypt_hash NOT GLOB '$2[aby]$[0-9][0-9]$*' OR substr(l.bcrypt_hash, 5, 2) NOT BETWEEN '04' AND '31'"
        " OR substr(l.bcrypt_hash, 29, 1) NOT GLOB '[.Oeu]'"
        " OR substr(l.bcrypt_hash, 60, 1) NOT GLOB '[.CGKOSWaeimquy26]'"
        " OR substr(l.bcrypt_hash, 8) GLOB '*[^A-Za-z0-9./]*' OR instr(l.bcrypt_hash, char(0)) > 0)"
        " OR l.access_until IS NOT NULL AND (typeof(l.access_until) != 'text'"
        " OR length(CAST(l.access_until AS BLOB)) > 64 OR instr(l.access_until, char(0)) > 0)"
        " OR l.native_password_set = 1 AND l.bcrypt_hash IS NOT NULL"
        " OR l.from_legacy = 0 AND (l.native_password_set != 1 OR l.totp_enabled != 0 OR l.has_passkeys != 0)"
        " OR l.native_password_set = 0 AND (a.password_salt != zeroblob(16) OR a.password_hash != zeroblob(32)))";
    sqlite3_stmt *query = NULL;
    bool valid = sqlite3_prepare_v2(db, sql, -1, &query, NULL) == SQLITE_OK &&
                 sqlite3_step(query) == SQLITE_ROW && sqlite3_column_int(query, 0) == 1;
    sqlite3_finalize(query);
    return valid;
}

static bool check_account_ids(sqlite3 *db)
{
    static const char sql[] = "SELECT NOT EXISTS (SELECT 1 FROM panel_account_ids"
        " WHERE high_watermark < (SELECT max(id) FROM panel_accounts))";
    sqlite3_stmt *query = NULL;
    bool valid = sqlite3_prepare_v2(db, sql, -1, &query, NULL) == SQLITE_OK &&
                 sqlite3_step(query) == SQLITE_ROW && sqlite3_column_int(query, 0) == 1;
    sqlite3_finalize(query);
    return valid;
}

static bool verify_database(const char *path, size_t size, bool native)
{
    static const char hex[] = "0123456789abcdef";
    static const char options[] = "?mode=ro&immutable=1";
    char uri[sizeof("file:") + 3 * PATH_LIMIT + sizeof(options)] = "file:";
    size_t offset = sizeof("file:") - 1;
    for (const unsigned char *p = (const unsigned char *)path; *p; ++p) {
        uri[offset++] = '%';
        uri[offset++] = hex[*p >> 4];
        uri[offset++] = hex[*p & 15];
    }
    memcpy(uri + offset, options, sizeof(options));

    int flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_URI;
#ifdef SQLITE_OPEN_NOFOLLOW
    flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    sqlite3 *db = NULL;
    bool valid = sqlite3_open_v2(uri, &db, flags, NULL) == SQLITE_OK;
    if (valid) {
        bool legacy = false, sequence = false;
        sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 1024 * 1024);
        valid = sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, NULL) == SQLITE_OK &&
                sqlite3_db_config(db, SQLITE_DBCONFIG_TRUSTED_SCHEMA, 0, NULL) == SQLITE_OK &&
                sqlite3_exec(db, "PRAGMA cache_size = -1024; PRAGMA temp_store = FILE", NULL, NULL, NULL) == SQLITE_OK &&
                (!native || check_schema(db, &legacy, &sequence)) && check_integrity(db, size) &&
                (!native || check_accounts(db)) && (!legacy || check_legacy_accounts(db)) &&
                (!sequence || check_account_ids(db));
    }
    return sqlite3_close(db) == SQLITE_OK && valid;
}

bool panel_backup_stage_auth(const char *archive_path, const char *destination)
{
    if (!archive_path || !archive_path[0] || !destination || !destination[0] ||
        strlen(destination) >= PATH_LIMIT)
        return false;
    size_t source_size;
    int source_fd = open_archive_source(archive_path, ARCHIVE_LIMIT, &source_size);
    if (source_fd < 0)
        return false;
    FILE *source = fd_to_file(source_fd, "rb");
    if (!source) {
        close_fd(source_fd);
        return false;
    }

    int destination_fd = create_destination(destination, false);
    if (destination_fd < 0) {
        fclose(source);
        return false;
    }
    FILE *staged = fd_to_file(destination_fd, "wb");
    size_t size = staged ? stage_archive(source, staged, source_size) : 0;
    bool valid = size && fflush(staged) == 0 && sync_fd(destination_fd) == 0;
    if ((staged ? fclose(staged) : close_fd(destination_fd)) != 0)
        valid = false;
    fclose(source);

    if (valid && verify_database(destination, size, true))
        return true;
    remove(destination);
    return false;
}

static int url_base64_value(unsigned char ch)
{
    if (ch >= 'A' && ch <= 'Z')
        return ch - 'A';
    if (ch >= 'a' && ch <= 'z')
        return ch - 'a' + 26;
    if (ch >= '0' && ch <= '9')
        return ch - '0' + 52;
    if (ch == '-')
        return 62;
    if (ch == '_')
        return 63;
    return -1;
}

static int decode_token_chunk(unsigned char *encoded, size_t size, unsigned char *decoded, bool final)
{
    size_t padding = 0;
    if (final && encoded[size - 1] == '=') {
        padding = encoded[size - 2] == '=' ? 2u : 1u;
        int last_value = url_base64_value(encoded[size - padding - 1]);
        if (last_value < 0 || (last_value & (padding == 2 ? 15 : 3)))
            return -1;
    }
    for (size_t i = 0; i < size - padding; ++i) {
        if (url_base64_value(encoded[i]) < 0)
            return -1;
        if (encoded[i] == '-')
            encoded[i] = '+';
        else if (encoded[i] == '_')
            encoded[i] = '/';
    }
    int count = EVP_DecodeBlock(decoded, encoded, (int)size);
    return count >= 0 ? count - (int)padding : -1;
}

static bool authenticate_token(FILE *source, size_t encoded_size, FILE *ciphertext, EVP_MD_CTX *hmac,
                               unsigned char header[FERNET_HEADER_SIZE], size_t *cipher_size)
{
    unsigned char encoded[BUFFER_SIZE];
    unsigned char decoded[BUFFER_SIZE / 4 * 3];
    unsigned char tail[FERNET_TAG_SIZE];
    size_t tail_size = 0;
    bool first = true;
    while (encoded_size) {
        size_t wanted = encoded_size < sizeof(encoded) ? encoded_size : sizeof(encoded);
        if (fread(encoded, 1, wanted, source) != wanted)
            return false;
        encoded_size -= wanted;
        int count = decode_token_chunk(encoded, wanted, decoded, !encoded_size);
        if (count < 0)
            return false;
        const unsigned char *data = decoded;
        size_t size = (size_t)count;
        if (first) {
            if (size < FERNET_HEADER_SIZE || data[0] != 0x80 ||
                EVP_DigestSignUpdate(hmac, data, FERNET_HEADER_SIZE) != 1)
                return false;
            memcpy(header, data, FERNET_HEADER_SIZE);
            data += FERNET_HEADER_SIZE;
            size -= FERNET_HEADER_SIZE;
            first = false;
        }

        /* Keep the last 32 bytes across chunks. These bytes are the signature. */
        size_t combined = tail_size + size;
        if (combined <= sizeof(tail)) {
            memcpy(tail + tail_size, data, size);
            tail_size = combined;
            continue;
        }
        size_t emit = combined - sizeof(tail);
        size_t from_tail = emit < tail_size ? emit : tail_size;
        size_t from_data = emit - from_tail;
        if ((from_tail && (fwrite(tail, 1, from_tail, ciphertext) != from_tail ||
                           EVP_DigestSignUpdate(hmac, tail, from_tail) != 1)) ||
            (from_data && (fwrite(data, 1, from_data, ciphertext) != from_data ||
                           EVP_DigestSignUpdate(hmac, data, from_data) != 1)))
            return false;
        size_t retained = tail_size - from_tail;
        memmove(tail, tail + from_tail, retained);
        memcpy(tail + retained, data + from_data, sizeof(tail) - retained);
        tail_size = sizeof(tail);
        *cipher_size += emit;
    }

    unsigned char expected[FERNET_TAG_SIZE];
    size_t expected_size = sizeof(expected);
    return !first && tail_size == sizeof(tail) && *cipher_size &&
           *cipher_size % FERNET_BLOCK_SIZE == 0 && fgetc(source) == EOF && !ferror(source) &&
           EVP_DigestSignFinal(hmac, expected, &expected_size) == 1 && expected_size == sizeof(expected) &&
           CRYPTO_memcmp(expected, tail, sizeof(tail)) == 0 && fflush(ciphertext) == 0 &&
           fseek(ciphertext, 0, SEEK_SET) == 0;
}

static EVP_CIPHER_CTX *open_verified_token(FILE *source, size_t size, const char *password,
                                          FILE *ciphertext, size_t *cipher_size)
{
    size_t password_size = password ? strlen(password) : 0;
    if (!password_size || password_size > PANEL_BACKUP_PASSWORD_MAX || size < 100 || size % 4)
        return NULL;

    unsigned char key[32];
    unsigned int key_size = 0;
    EVP_CIPHER_CTX *cipher = NULL;
    EVP_MD_CTX *hmac = EVP_MD_CTX_new();
    EVP_PKEY *signing = NULL;
    unsigned char header[FERNET_HEADER_SIZE];
    // Fernet uses the first half of SHA256(UTF-8 password) for signing, and the second for AES.
    if (hmac && EVP_Digest(password, password_size, key, &key_size, EVP_sha256(), NULL) == 1 &&
        key_size == sizeof(key))
        signing = EVP_PKEY_new_raw_private_key(EVP_PKEY_HMAC, NULL, key, sizeof(key) / 2);
    if (signing && EVP_DigestSignInit(hmac, NULL, EVP_sha256(), NULL, signing) == 1 &&
        authenticate_token(source, size, ciphertext, hmac, header, cipher_size)) {
        cipher = EVP_CIPHER_CTX_new();
        if (cipher && EVP_DecryptInit_ex(cipher, EVP_aes_128_cbc(), NULL, key + sizeof(key) / 2, header + 9) != 1) {
            EVP_CIPHER_CTX_free(cipher);
            cipher = NULL;
        }
    }
    EVP_PKEY_free(signing);
    EVP_MD_CTX_free(hmac);
    OPENSSL_cleanse(key, sizeof(key));
    return cipher;
}

struct upstream_member {
    const char *name;
    const char *file;
    size_t limit;
    unsigned int component;
    bool database;
};

static const struct upstream_member upstream_members[] = {
    { "data/adminpanel.db", "adminpanel.db", UPSTREAM_DB_LIMIT, PANEL_BACKUP_UPSTREAM_DB, true },
    { "data/cidr/cidr.db", "cidr.db", UPSTREAM_DB_LIMIT, PANEL_BACKUP_UPSTREAM_CIDR, true },
    { "env/.env", ".env", UPSTREAM_ENV_LIMIT, PANEL_BACKUP_UPSTREAM_ENV, false },
    { "antizapret/config/include-hosts.txt", "include-hosts.txt", UPSTREAM_CONFIG_LIMIT, PANEL_BACKUP_UPSTREAM_CONFIGS, false },
    { "antizapret/config/exclude-hosts.txt", "exclude-hosts.txt", UPSTREAM_CONFIG_LIMIT, PANEL_BACKUP_UPSTREAM_CONFIGS, false },
    { "antizapret/config/include-ips.txt", "include-ips.txt", UPSTREAM_CONFIG_LIMIT, PANEL_BACKUP_UPSTREAM_CONFIGS, false },
    { "antizapret/config/exclude-ips.txt", "exclude-ips.txt", UPSTREAM_CONFIG_LIMIT, PANEL_BACKUP_UPSTREAM_CONFIGS, false },
    { "antizapret/config/allow-ips.txt", "allow-ips.txt", UPSTREAM_CONFIG_LIMIT, PANEL_BACKUP_UPSTREAM_CONFIGS, false },
    { "awg2/az-awg2-backup.tar.gz", "az-awg2-backup.tar.gz", UPSTREAM_AWG_LIMIT, PANEL_BACKUP_UPSTREAM_AWG2, false }
};

static const size_t upstream_member_count = sizeof(upstream_members) / sizeof(upstream_members[0]);

static const char *const native_state_files[] = {
    "auth.db", "lws-security.db", "lws-history.db", "panel-settings.db",
    "nodes.db", "lws-ha.db", "lws-telegram.db", "lws-cidr.db", "portal.db"
};

static const size_t native_state_count = sizeof(native_state_files) / sizeof(native_state_files[0]);
enum { NATIVE_STATE_AUTH = 0, NATIVE_STATE_SECURITY = 1, NATIVE_STATE_PORTAL = 8 };

struct tar_cursor {
    struct tar_input *input;
    size_t start;
    size_t end;
};

static int read_tar_bytes(struct tar_cursor *tar, unsigned char *buffer, size_t wanted)
{
    size_t read = 0;
    while (read < wanted) {
        if (tar->start == tar->end) {
            const void *block;
            la_ssize_t count = read_tar_block(NULL, tar->input, &block);
            if (count <= 0)
                return count < 0 ? -1 : (int)read;
            tar->start = 0;
            tar->end = (size_t)count;
        }
        size_t available = tar->end - tar->start;
        size_t count = wanted - read < available ? wanted - read : available;
        memcpy(buffer + read, tar->input->decoded + tar->start, count);
        tar->start += count;
        read += count;
    }
    return (int)read;
}

static bool all_zero(const unsigned char *data, size_t size)
{
    for (size_t i = 0; i < size; ++i)
        if (data[i])
            return false;
    return true;
}

static bool skip_tar_padding(struct tar_cursor *tar, size_t size)
{
    unsigned char buffer[BLOCK_SIZE];
    size_t padding = (BLOCK_SIZE - size % BLOCK_SIZE) % BLOCK_SIZE;
    return read_tar_bytes(tar, buffer, padding) == (int)padding && all_zero(buffer, padding);
}

static bool tar_octal(const unsigned char *text, size_t length, size_t *value)
{
    size_t digit = 0;
    while (digit < length && text[digit] == ' ')
        ++digit;
    size_t start = digit;
    *value = 0;
    for (; digit < length && text[digit] >= '0' && text[digit] <= '7'; ++digit) {
        if (*value > UPSTREAM_TAR_LIMIT / 8)
            return false;
        *value = *value * 8 + (size_t)(text[digit] - '0');
    }
    if (digit == start)
        return false;
    while (digit < length && (text[digit] == ' ' || text[digit] == '\0'))
        ++digit;
    return digit == length && *value <= UPSTREAM_TAR_LIMIT;
}

static bool upstream_tar_header(const unsigned char *header, size_t *size)
{
    size_t expected;
    if (memcmp(header + 257, "ustar\0" "00", 8) ||
        !tar_octal(header + 148, 8, &expected) || !tar_octal(header + 124, 12, size) ||
        !all_zero(header + 157, 100) || !all_zero(header + 345, 155))
        return false;
    size_t checksum = 0;
    for (size_t i = 0; i < BLOCK_SIZE; ++i)
        checksum += i >= 148 && i < 156 ? ' ' : header[i];
    return checksum == expected;
}

static bool pax_key(const unsigned char *name, size_t size)
{
    static const char *keys[] = { "mtime", "atime", "ctime", "uid", "gid", "uname", "gname" };
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i)
        if (strlen(keys[i]) == size && !memcmp(name, keys[i], size))
            return true;
    return false;
}

static bool read_pax_metadata(struct tar_cursor *tar, size_t size)
{
    unsigned char buffer[4096];
    if (!size || size > sizeof(buffer) || read_tar_bytes(tar, buffer, size) != (int)size ||
        !skip_tar_padding(tar, size))
        return false;

    // Upstream uses Python's PAX tar format. Only metadata that cannot alter the member is accepted.
    for (size_t offset = 0; offset < size;) {
        size_t cursor = offset;
        size_t record = 0;
        while (cursor < size && buffer[cursor] >= '0' && buffer[cursor] <= '9') {
            record = record * 10 + (buffer[cursor++] - '0');
            if (record > size - offset)
                return false;
        }
        size_t end = offset + record;
        if (cursor == offset || end <= cursor + 2 || buffer[cursor++] != ' ' || buffer[end - 1] != '\n')
            return false;
        const unsigned char *separator = memchr(buffer + cursor, '=', end - cursor - 1);
        if (!separator || !pax_key(buffer + cursor, (size_t)(separator - (buffer + cursor))))
            return false;
        offset = end;
    }
    return true;
}

static bool member_path(char *path, const char *directory, const char *name)
{
    int length = snprintf(path, PATH_LIMIT, "%s/%s", directory, name);
    return length > 0 && length < PATH_LIMIT;
}

static bool stage_upstream_file(struct tar_cursor *tar, const char *directory,
                                const struct upstream_member *member, size_t size)
{
    char path[PATH_LIMIT];
    if (size > member->limit || (member->database && size < BLOCK_SIZE) ||
        (member->component == PANEL_BACKUP_UPSTREAM_AWG2 && size < 18) ||
        !member_path(path, directory, member->file))
        return false;

    int fd = create_destination(path, false);
    if (fd < 0)
        return false;
    FILE *file = fd_to_file(fd, "wb");
    bool valid = file != NULL;
    for (size_t offset = 0; valid && offset < size;) {
        unsigned char buffer[BUFFER_SIZE];
        size_t count = size - offset < sizeof(buffer) ? size - offset : sizeof(buffer);
        valid = read_tar_bytes(tar, buffer, count) == (int)count;
        if (valid && member->database && !offset)
            valid = database_header(buffer, count, false);
        if (valid && member->component == PANEL_BACKUP_UPSTREAM_AWG2 && !offset)
            valid = count >= 3 && !memcmp(buffer, "\x1f\x8b\x08", 3);
        if (valid && !member->database && member->component != PANEL_BACKUP_UPSTREAM_AWG2)
            valid = memchr(buffer, '\0', count) == NULL;
        if (valid)
            valid = fwrite(buffer, 1, count, file) == count;
        offset += count;
    }
    if (valid)
        valid = skip_tar_padding(tar, size) && fflush(file) == 0 && sync_fd(fd) == 0;
    if ((file ? fclose(file) : close_fd(fd)) != 0)
        valid = false;
    return valid && (!member->database || verify_database(path, size, false));
}

static bool stage_upstream_members(struct tar_input *input, const char *directory, unsigned int *components)
{
    struct tar_cursor tar = { .input = input };
    unsigned int seen = 0;
    bool pax_header = false;
    size_t end_blocks = 0;
    unsigned char header[BLOCK_SIZE];
    int count;
    while ((count = read_tar_bytes(&tar, header, sizeof(header))) == sizeof(header)) {
        if (all_zero(header, sizeof(header))) {
            if (pax_header)
                return false;
            ++end_blocks;
            continue;
        }
        size_t size;
        if (end_blocks || !upstream_tar_header(header, &size))
            return false;
        if (header[156] == 'x') {
            if (pax_header || !read_pax_metadata(&tar, size))
                return false;
            pax_header = true;
            continue;
        }
        if (header[156] != '0' && header[156] != '\0')
            return false;
        size_t index = 0;
        while (index < upstream_member_count) {
            const char *name = upstream_members[index].name;
            size_t length = strlen(name);
            if (!memcmp(name, header, length) && all_zero(header + length, 100 - length))
                break;
            ++index;
        }
        if (index == upstream_member_count || (seen & (1u << index)) ||
            !stage_upstream_file(&tar, directory, &upstream_members[index], size))
            return false;
        seen |= 1u << index;
        *components |= upstream_members[index].component;
        pax_header = false;
    }
    return count == 0 && !pax_header && end_blocks >= 2 && seen;
}

static bool stage_parent(char *parent, const char *destination)
{
    const char *leaf = strrchr(destination, '/');
#ifdef _WIN32
    const char *backslash = strrchr(destination, '\\');
    if (backslash && (!leaf || backslash > leaf))
        leaf = backslash;
    if (strchr(leaf ? leaf + 1 : destination, ':'))
        return false;
#endif
    if (leaf) {
        size_t length = (size_t)(leaf + 1 - destination);
        while (length > 1 && (destination[length - 1] == '/'
#ifdef _WIN32
                              || destination[length - 1] == '\\'
#endif
                              )) {
#ifdef _WIN32
            if (length == 3 && destination[1] == ':')
                break;
#endif
            --length;
        }
        memcpy(parent, destination, length);
        parent[length] = '\0';
        ++leaf;
    } else {
        strcpy(parent, ".");
        leaf = destination;
    }
    if (!*leaf || !strcmp(leaf, ".") || !strcmp(leaf, ".."))
        return false;
#ifdef _WIN32
    DWORD attributes = GetFileAttributesA(parent);
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_DIRECTORY) &&
           !(attributes & FILE_ATTRIBUTE_REPARSE_POINT) && GetFileAttributesA(destination) == INVALID_FILE_ATTRIBUTES &&
           GetLastError() == ERROR_FILE_NOT_FOUND;
#else
    struct stat info;
    return lstat(parent, &info) == 0 && S_ISDIR(info.st_mode) && info.st_uid == geteuid() &&
           (info.st_mode & 077) == 0 && lstat(destination, &info) != 0 && errno == ENOENT;
#endif
}

static bool create_stage_directory(char *out, const char *parent)
{
    unsigned char suffix[8];
    if (RAND_bytes(suffix, sizeof(suffix)) != 1)
        return false;
    int written = snprintf(out, PATH_LIMIT, "%s/.apaz-stage-%02x%02x%02x%02x%02x%02x%02x%02x", parent,
                           suffix[0], suffix[1], suffix[2], suffix[3], suffix[4], suffix[5], suffix[6], suffix[7]);
    if (written < 0 || written >= PATH_LIMIT - 64)
        return false;
#ifdef _WIN32
    return _mkdir(out) == 0;
#else
    return mkdir(out, 0700) == 0;
#endif
}

static void discard_stage_directory(const char *directory)
{
    char path[PATH_LIMIT];
    for (size_t i = 0; i < upstream_member_count; ++i)
        if (member_path(path, directory, upstream_members[i].file))
            remove(path);
    static const char *const sqlite_suffixes[] = { "", "-journal", "-wal", "-shm" };
    for (size_t i = 0; i < native_state_count; ++i) {
        for (size_t j = 0; j < sizeof(sqlite_suffixes) / sizeof(sqlite_suffixes[0]); ++j) {
            int length = snprintf(path, sizeof(path), "%s/%s%s", directory, native_state_files[i], sqlite_suffixes[j]);
            if (length > 0 && (size_t)length < sizeof(path))
                remove(path);
        }
    }
#ifdef _WIN32
    _rmdir(directory);
#else
    rmdir(directory);
#endif
}

static bool publish_stage_directory(const char *directory, const char *destination)
{
#ifdef _WIN32
    return MoveFileExA(directory, destination, MOVEFILE_WRITE_THROUGH) != 0;
#elif defined(__linux__)
    int fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return false;
    bool synced = fsync(fd) == 0;
    close_fd(fd);
    return synced && renameat2(AT_FDCWD, directory, AT_FDCWD, destination, RENAME_NOREPLACE) == 0;
#else
    (void)directory;
    (void)destination;
    return false;
#endif
}

static bool stage_upstream_archive(FILE *source, size_t size, const char *password,
                                   const char *directory, unsigned int *components)
{
    unsigned char magic[sizeof(encrypted_magic) - 1];
    if (fread(magic, 1, sizeof(magic), source) != sizeof(magic))
        return false;

    FILE *scratch = NULL;
    struct tar_input input = { .file = source, .source_remaining = size,
                               .decoded_limit = UPSTREAM_TAR_LIMIT, .gzip = true };
    bool encrypted = !memcmp(magic, encrypted_magic, sizeof(magic));
    bool valid;
    if (encrypted) {
        char path[PATH_LIMIT];
        int fd = member_path(path, directory, "token.tmp") ? create_destination(path, true) : -1;
        scratch = fd >= 0 ? fd_to_file(fd, "w+b") : NULL;
        if (!scratch && fd >= 0)
            close_fd(fd);
        input.file = scratch;
        input.source_remaining = 0;
        input.cipher = scratch ? open_verified_token(source, size - sizeof(magic), password,
                                                     scratch, &input.source_remaining) : NULL;
        valid = input.cipher != NULL;
    } else {
        valid = magic[0] == 0x1f && magic[1] == 0x8b && fseek(source, 0, SEEK_SET) == 0;
    }

    if (valid && inflateInit2(&input.stream, MAX_WBITS + 16) == Z_OK) {
        valid = stage_upstream_members(&input, directory, components);
        inflateEnd(&input.stream);
    } else {
        valid = false;
    }
    EVP_CIPHER_CTX_free(input.cipher);
    if (scratch && fclose(scratch) != 0)
        valid = false;
    return valid;
}

bool panel_backup_stage_upstream(const char *archive_path, const char *destination_directory,
                                 const char *password, unsigned int *components)
{
    if (components)
        *components = 0;
    if (!archive_path || !archive_path[0] || !destination_directory || !destination_directory[0] ||
        strlen(destination_directory) >= PATH_LIMIT)
        return false;
    char parent[PATH_LIMIT];
    if (!stage_parent(parent, destination_directory))
        return false;

    size_t size;
    int fd = open_archive_source(archive_path, UPSTREAM_SOURCE_LIMIT, &size);
    if (fd < 0)
        return false;
    FILE *source = fd_to_file(fd, "rb");
    char staging[PATH_LIMIT];
    if (!source) {
        close_fd(fd);
        return false;
    }
    if (!create_stage_directory(staging, parent)) {
        fclose(source);
        return false;
    }

    unsigned int found = 0;
    bool valid = stage_upstream_archive(source, size, password, staging, &found);
    if (fclose(source) != 0)
        valid = false;
    if (!valid || !publish_stage_directory(staging, destination_directory)) {
        discard_stage_directory(staging);
        return false;
    }
    if (components)
        *components = found;
    return true;
}

enum backup_database_state { BACKUP_DATABASE_ABSENT, BACKUP_DATABASE_REGULAR, BACKUP_DATABASE_INVALID };

static enum backup_database_state database_state(const char *path)
{
#ifdef _WIN32
    DWORD attributes = GetFileAttributesA(path);
    if (attributes == INVALID_FILE_ATTRIBUTES)
        return GetLastError() == ERROR_FILE_NOT_FOUND ? BACKUP_DATABASE_ABSENT : BACKUP_DATABASE_INVALID;
    return attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_DEVICE)
           ? BACKUP_DATABASE_INVALID : BACKUP_DATABASE_REGULAR;
#else
    struct stat info;
    if (lstat(path, &info) != 0)
        return errno == ENOENT ? BACKUP_DATABASE_ABSENT : BACKUP_DATABASE_INVALID;
    return S_ISREG(info.st_mode) ? BACKUP_DATABASE_REGULAR : BACKUP_DATABASE_INVALID;
#endif
}

static bool copy_native_state(const char *directory, const char *auth, const char *portal, const char *stage)
{
    char source[PATH_LIMIT];
    char destination[PATH_LIMIT];
    for (size_t i = 0; i < native_state_count; ++i) {
        enum panel_backup_database kind = PANEL_BACKUP_DATABASE_COPY;
        const char *path = source;
        const char *name = native_state_files[i];
        if (i == NATIVE_STATE_AUTH) {
            path = auth;
            kind = PANEL_BACKUP_DATABASE_AUTH;
        } else if (i == NATIVE_STATE_PORTAL) {
            if (!portal)
                continue;
            path = portal;
        } else {
            if (!member_path(source, directory, name))
                return false;
            if (i == NATIVE_STATE_SECURITY)
                kind = PANEL_BACKUP_DATABASE_SECURITY;
        }

        enum backup_database_state state = database_state(path);
        if (state == BACKUP_DATABASE_ABSENT && path == source)
            continue;
        if (state != BACKUP_DATABASE_REGULAR || !member_path(destination, stage, name) ||
            !panel_backup_snapshot_database(path, destination, kind))
            return false;
        if (kind == PANEL_BACKUP_DATABASE_AUTH) {
            size_t size;
            int fd = open_archive_source(destination, DATABASE_LIMIT, &size);
            if (fd < 0)
                return false;
            close_fd(fd);
            if (!verify_database(destination, size, true))
                return false;
        }
    }
    return true;
}

bool panel_backup_stage_native_state(const char *data_directory, const char *auth_database,
                                     const char *portal_database, const char *destination_directory)
{
    if (!data_directory || !*data_directory || !auth_database || !*auth_database ||
        !destination_directory || !*destination_directory || strlen(destination_directory) >= PATH_LIMIT)
        return false;
#ifdef _WIN32
    DWORD attributes = GetFileAttributesA(data_directory);
    if (attributes == INVALID_FILE_ATTRIBUTES || !(attributes & FILE_ATTRIBUTE_DIRECTORY) ||
        (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
        return false;
#else
    struct stat info;
    if (lstat(data_directory, &info) != 0 || !S_ISDIR(info.st_mode))
        return false;
#endif
    char parent[PATH_LIMIT];
    char staging[PATH_LIMIT];
    if (!stage_parent(parent, destination_directory) || !create_stage_directory(staging, parent))
        return false;

    bool valid = copy_native_state(data_directory, auth_database, portal_database, staging) &&
                 publish_stage_directory(staging, destination_directory);
    if (!valid)
        discard_stage_directory(staging);
    return valid;
}
