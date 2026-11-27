#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "panel_nodes.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <io.h>
#include <process.h>
#include <windows.h>
#define fd_close _close
#define fd_read _read
#define fd_write _write
#define fd_unlink _unlink
#define FD_BINARY (_O_BINARY | _O_NOINHERIT)
#define FD_PRIVATE (S_IREAD | S_IWRITE)
#else
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#define fd_close close
#define fd_read read
#define fd_write write
#define fd_unlink unlink
#define FD_BINARY (O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
#define FD_PRIVATE 0600
#endif

enum {
    NODE_LIMIT = 48,
    PATH_LIMIT = 4096,
    NODE_KEY_LIMIT = 512,
    SECRET_SIZE = 32,
    NONCE_SIZE = 12,
    TAG_SIZE = 16,
    BLOB_SIZE = NODE_KEY_LIMIT + NONCE_SIZE + TAG_SIZE,
    AGENT_BODY_LIMIT = 16 * 1024,
    AGENT_MAPPINGS_LIMIT = 64 * 1024,
    THREAD_STACK = 256 * 1024
};

struct panel_nodes_job {
    struct node_transport_config config;
    struct node_health_result result;
    enum node_operation operation;
    int64_t id;
    int64_t version;
    bool detached;
    bool recorded;
    size_t capacity;
    char destination[16];
    char endpoint[PANEL_NODE_ENDPOINT_LIMIT + 1];
    char key[NODE_KEY_LIMIT + 1];
    char tls_paths[3][PATH_LIMIT];
#ifdef _WIN32
    HANDLE thread;
    volatile LONG done;
    volatile LONG cancelled;
#else
    pthread_t thread;
    atomic_bool done;
    atomic_bool cancelled;
#endif
    char response[];
};

static sqlite3 *database;
static char tls_dir[PATH_LIMIT];
static unsigned char credential_secret[SECRET_SIZE];
static struct panel_nodes_job *current_job;
static bool deny_internal;

static const char *const kinds[] = { "vpn", "proxy" };
static const char *const transports[] = { "local", "http", "https", "mtls" };
static void reap_job(void);
static void sql_health_name(sqlite3_context *context, int argc, sqlite3_value **arguments);

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

static bool bind_id(sqlite3_stmt *statement, int index, int64_t id)
{
    return sqlite3_bind_int64(statement, index, id) == SQLITE_OK;
}

static bool bind_text(sqlite3_stmt *statement, int index, const char *value)
{
    return sqlite3_bind_text(statement, index, value ? value : "", -1, SQLITE_TRANSIENT) == SQLITE_OK;
}

static enum panel_nodes_result commit(enum panel_nodes_result outcome)
{
    if (outcome == PANEL_NODES_OK && execute("COMMIT"))
        return outcome;
    execute("ROLLBACK");
    return outcome == PANEL_NODES_OK ? PANEL_NODES_ERROR : outcome;
}

static bool join_path(char *out, const char *base, const char *name)
{
    int count = snprintf(out, PATH_LIMIT, "%s/%s", base, name);
    return count > 0 && count < PATH_LIMIT;
}

static bool private_file(int fd)
{
    if (fd < 0)
        return false;
#ifdef _WIN32
    struct _stat info;
    return _fstat(fd, &info) == 0 && (info.st_mode & _S_IFMT) == _S_IFREG;
#else
    struct stat info;
    return fstat(fd, &info) == 0 && S_ISREG(info.st_mode) && (info.st_mode & 077) == 0 &&
           info.st_uid == geteuid() && info.st_nlink == 1;
#endif
}

static bool read_secret(const char *path)
{
    int fd = open(path, O_RDONLY | FD_BINARY);
    if (fd < 0)
        return false;
    unsigned char extra;
    bool ok = private_file(fd) && fd_read(fd, credential_secret, SECRET_SIZE) == SECRET_SIZE &&
              fd_read(fd, &extra, 1) == 0;
    fd_close(fd);
    if (!ok)
        errno = EINVAL;
    return ok;
}

static bool load_secret(const char *path, bool allow_create)
{
    if (read_secret(path))
        return true;
    if (errno != ENOENT || !allow_create || RAND_bytes(credential_secret, SECRET_SIZE) != 1)
        return false;

    unsigned char random_suffix[8];
    char temporary[PATH_LIMIT];
    if (RAND_bytes(random_suffix, sizeof(random_suffix)) != 1)
        return false;
    int count = snprintf(temporary, sizeof(temporary), "%s.%02x%02x%02x%02x%02x%02x%02x%02x.tmp", path,
        random_suffix[0], random_suffix[1], random_suffix[2], random_suffix[3],
        random_suffix[4], random_suffix[5], random_suffix[6], random_suffix[7]);
    if (count < 0 || (size_t)count >= sizeof(temporary))
        return false;
    int fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | FD_BINARY, FD_PRIVATE);
    if (fd < 0)
        return false;
    bool ok = fd_write(fd, credential_secret, SECRET_SIZE) == SECRET_SIZE;
#ifdef _WIN32
    ok = ok && _commit(fd) == 0;
#else
    ok = ok && fsync(fd) == 0;
#endif
    ok = fd_close(fd) == 0 && ok;
#ifdef _WIN32
    bool installed = ok && MoveFileExA(temporary, path, MOVEFILE_WRITE_THROUGH);
    bool exists = ok && !installed && GetLastError() == ERROR_ALREADY_EXISTS;
#else
    bool installed = ok && link(temporary, path) == 0;
    bool exists = ok && !installed && errno == EEXIST;
#endif
    fd_unlink(temporary);
    return installed || (exists && read_secret(path));
}

static bool setup_database(void)
{
    return execute("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;"
        "PRAGMA cache_size=-192; PRAGMA secure_delete=ON; BEGIN IMMEDIATE;"
        "CREATE TABLE IF NOT EXISTS panel_nodes ("
        "id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,"
        "endpoint TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind IN ('vpn','proxy')),"
        "transport TEXT NOT NULL CHECK(transport IN ('local','http','https','mtls')),"
        "secret BLOB NOT NULL, ca_file TEXT NOT NULL, client_cert TEXT NOT NULL, client_key TEXT NOT NULL,"
        "linked_vpn_id INTEGER REFERENCES panel_nodes(id) ON DELETE SET NULL,"
        "health INTEGER NOT NULL, health_checked_at INTEGER, antizapret_version TEXT NOT NULL DEFAULT '',"
        "agent_version TEXT NOT NULL DEFAULT '', version INTEGER NOT NULL DEFAULT 1);"
        "CREATE UNIQUE INDEX IF NOT EXISTS panel_nodes_remote_endpoint "
        "ON panel_nodes(endpoint) WHERE id>0;"
        "CREATE TABLE IF NOT EXISTS panel_nodes_active ("
        "id INTEGER PRIMARY KEY CHECK(id=1), node_id INTEGER NOT NULL REFERENCES panel_nodes(id),"
        "revision INTEGER NOT NULL);") &&
        /* Explicit IDs preserve the local node across restarts without consuming a remote ID. */
        execute("INSERT OR IGNORE INTO panel_nodes"
        "(id,name,endpoint,kind,transport,secret,ca_file,client_cert,client_key,health) "
        "VALUES(0,'Локальный узел','','vpn','local',x'','','','',0);"
        "INSERT OR IGNORE INTO panel_nodes_active(id,node_id,revision) VALUES(1,0,0); COMMIT;");
}

bool panel_nodes_open(const char *data_directory)
{
    char path[PATH_LIMIT];
    char key_path[PATH_LIMIT];
    if (database || !data_directory || !join_path(path, data_directory, "nodes.db") ||
        !join_path(key_path, data_directory, "nodes.key") ||
        !join_path(tls_dir, data_directory, "node-tls") || !node_transport_init())
        return false;
    const char *allow = getenv("APAZ_ALLOW_INTERNAL_NODES");
    deny_internal = !allow || (strcmp(allow, "true") && strcmp(allow, "1"));

    int fd = open(path, O_RDWR | O_CREAT | FD_BINARY, FD_PRIVATE);
    bool ok = private_file(fd);
    if (fd >= 0)
        fd_close(fd);
    int flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_NOFOLLOW;
    if (ok && sqlite3_open_v2(path, &database, flags, NULL) == SQLITE_OK && setup_database() &&
        sqlite3_create_function_v2(database, "health_name", 1, SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                                  NULL, sql_health_name, NULL, NULL, NULL) == SQLITE_OK) {
        sqlite3_stmt *statement = prepare("SELECT NOT EXISTS(SELECT 1 FROM panel_nodes WHERE id>0)");
        bool read = statement && sqlite3_step(statement) == SQLITE_ROW;
        bool allow_create = read && sqlite3_column_int(statement, 0) != 0;
        sqlite3_finalize(statement);
        if (read && load_secret(key_path, allow_create))
            return true;
    }
    sqlite3_close(database);
    database = NULL;
    OPENSSL_cleanse(credential_secret, sizeof(credential_secret));
    node_transport_cleanup();
    return false;
}

static bool bounded_text(const char *value, size_t limit)
{
    if (!value || !*value || *value == ' ')
        return false;
    size_t length = 0;
    for (; value[length] && length <= limit; ++length) {
        unsigned char byte = (unsigned char)value[length];
        if (byte < 0x20 || byte == 0x7f)
            return false;
    }
    return length <= limit && value[length - 1] != ' ';
}

static bool utf8_text(const char *value)
{
    const unsigned char *bytes = (const unsigned char *)value;
    while (*bytes) {
        unsigned char lead = *bytes++;
        if (lead < 0x80)
            continue;
        if (lead < 0xc2 || lead > 0xf4)
            return false;
        unsigned int tails = lead < 0xe0 ? 1U : (lead < 0xf0 ? 2U : 3U);
        unsigned char first = *bytes;
        if ((lead == 0xe0 && first < 0xa0) || (lead == 0xed && first >= 0xa0) ||
            (lead == 0xf0 && first < 0x90) || (lead == 0xf4 && first >= 0x90))
            return false;
        for (unsigned int i = 0; i < tails; ++i) {
            if (*bytes < 0x80 || *bytes > 0xbf)
                return false;
            ++bytes;
        }
    }
    return true;
}

static bool tls_name(const char *value)
{
    if (!value || !*value)
        return true;
    size_t length = strlen(value);
    if (length > PANEL_NODE_FILE_LIMIT || value[0] == '.' || value[length - 1] == '.')
        return false;
    return strspn(value, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._-") == length;
}

static bool column_string(sqlite3_stmt *statement, int index, char *out, size_t capacity)
{
    const unsigned char *value = sqlite3_column_text(statement, index);
    int count = sqlite3_column_bytes(statement, index);
    if (!value || (size_t)count >= capacity || memchr(value, 0, (size_t)count))
        return false;
    memcpy(out, value, (size_t)count + 1);
    return true;
}

static int index_of(const char *name, const char *const *names, size_t count)
{
    if (name) {
        for (size_t i = 0; i < count; ++i)
            if (!strcmp(name, names[i]))
                return (int)i;
    }
    return -1;
}

static int column_index(sqlite3_stmt *statement, int column, const char *const *names, size_t count)
{
    return index_of((const char *)sqlite3_column_text(statement, column), names, count);
}

static sqlite3_stmt *select_node(const char *sql, int64_t id)
{
    sqlite3_stmt *statement = prepare(sql);
    if (!statement || bind_id(statement, 1, id))
        return statement;
    sqlite3_finalize(statement);
    return NULL;
}

enum panel_nodes_result panel_nodes_get(int64_t id, struct panel_node *node)
{
    if (!database || !node || id < 0)
        return PANEL_NODES_INVALID;
    sqlite3_stmt *statement = select_node("SELECT name,endpoint,kind,transport,health,linked_vpn_id,"
                                          "antizapret_version,agent_version FROM panel_nodes WHERE id=?1", id);
    int step = statement ? sqlite3_step(statement) : SQLITE_ERROR;
    enum panel_nodes_result outcome = step == SQLITE_DONE ? PANEL_NODES_MISSING : PANEL_NODES_ERROR;
    if (step == SQLITE_ROW) {
        int kind = column_index(statement, 2, kinds, sizeof(kinds) / sizeof(kinds[0]));
        int transport = column_index(statement, 3, transports, sizeof(transports) / sizeof(transports[0]));
        int health = sqlite3_column_int(statement, 4);
        if (kind >= 0 && transport >= 0 && health >= NODE_HEALTH_AVAILABLE && health <= NODE_HEALTH_UNKNOWN &&
            column_string(statement, 0, node->name, sizeof(node->name)) &&
            column_string(statement, 1, node->endpoint, sizeof(node->endpoint)) &&
            column_string(statement, 6, node->antizapret_version, sizeof(node->antizapret_version)) &&
            column_string(statement, 7, node->agent_version, sizeof(node->agent_version))) {
            node->id = id;
            node->linked_vpn_node_id = sqlite3_column_type(statement, 5) == SQLITE_NULL ?
                                      -1 : sqlite3_column_int64(statement, 5);
            node->kind = (enum panel_node_kind)kind;
            node->transport = (enum panel_node_transport)transport;
            node->health = (enum node_health_state)health;
            outcome = PANEL_NODES_OK;
        }
    }
    sqlite3_finalize(statement);
    return outcome;
}

static void sql_health_name(sqlite3_context *context, int argc, sqlite3_value **arguments)
{
    (void)argc;
    const char *name = node_health_state_name((enum node_health_state)sqlite3_value_int(arguments[0]));
    sqlite3_result_text(context, name, -1, SQLITE_STATIC);
}

static const char node_json_sql[] =
    "SELECT json_object('id',n.id,'name',n.name,'endpoint',n.endpoint,'kind',n.kind,"
    "'transport',n.transport,'health',health_name(n.health),'health_checked_at',n.health_checked_at,"
    "'antizapret_version',n.antizapret_version,'agent_version',n.agent_version,"
    "'linked_vpn_node_id',n.linked_vpn_id,'active',json(CASE WHEN a.node_id=n.id THEN 'true' ELSE 'false' END),"
    "'ca_file',n.ca_file,'client_cert',n.client_cert,'client_key',n.client_key) "
    "FROM panel_nodes n CROSS JOIN panel_nodes_active a ";

static sqlite3_stmt *prepare_node_json(const char *tail)
{
    char sql[sizeof(node_json_sql) + 80];
    int count = snprintf(sql, sizeof(sql), "%s%s", node_json_sql, tail);
    return count > 0 && (size_t)count < sizeof(sql) ? prepare(sql) : NULL;
}

enum panel_nodes_result panel_nodes_get_json(int64_t id, char *out, size_t capacity)
{
    if (!database || !out || !capacity || id < 0)
        return PANEL_NODES_INVALID;
    sqlite3_stmt *statement = prepare_node_json("WHERE n.id=?1");
    int step = statement && bind_id(statement, 1, id) ? sqlite3_step(statement) : SQLITE_ERROR;
    enum panel_nodes_result outcome = step == SQLITE_DONE ? PANEL_NODES_MISSING : PANEL_NODES_ERROR;
    if (step == SQLITE_ROW && column_string(statement, 0, out, capacity))
        outcome = PANEL_NODES_OK;
    sqlite3_finalize(statement);
    return outcome;
}

enum panel_nodes_result panel_nodes_active(int64_t *id, int64_t *revision)
{
    if (!database || !id || !revision)
        return PANEL_NODES_INVALID;
    sqlite3_stmt *statement = prepare("SELECT node_id,revision FROM panel_nodes_active WHERE id=1");
    bool ok = statement && sqlite3_step(statement) == SQLITE_ROW;
    if (ok) {
        *id = sqlite3_column_int64(statement, 0);
        *revision = sqlite3_column_int64(statement, 1);
    }
    sqlite3_finalize(statement);
    return ok ? PANEL_NODES_OK : PANEL_NODES_ERROR;
}

enum panel_nodes_result panel_nodes_list_json(char *out, size_t capacity)
{
    if (!database || !out || !capacity)
        return PANEL_NODES_INVALID;
    int64_t id, revision;
    if (panel_nodes_active(&id, &revision) != PANEL_NODES_OK)
        return PANEL_NODES_ERROR;
    int start = snprintf(out, capacity, "{\"active_node_id\":%" PRId64 ",\"revision\":%" PRId64 ",\"nodes\":[",
                         id, revision);
    if (start < 0 || (size_t)start >= capacity)
        return PANEL_NODES_ERROR;
    size_t used = (size_t)start;
    sqlite3_stmt *statement = prepare_node_json("ORDER BY (n.id<>0),n.kind,n.name COLLATE NOCASE");
    if (!statement)
        return PANEL_NODES_ERROR;
    int step;
    while ((step = sqlite3_step(statement)) == SQLITE_ROW) {
        if (used > (size_t)start) {
            if (capacity - used < 2)
                break;
            out[used++] = ',';
        }
        if (!column_string(statement, 0, out + used, capacity - used))
            break;
        used += (size_t)sqlite3_column_bytes(statement, 0);
    }
    sqlite3_finalize(statement);
    if (step != SQLITE_DONE || capacity - used < 3)
        return PANEL_NODES_ERROR;
    memcpy(out + used, "]}", 3);
    return PANEL_NODES_OK;
}

enum panel_nodes_result panel_nodes_activate(int64_t id, int64_t expected_revision)
{
    if (!database || id < 0 || expected_revision < 0)
        return PANEL_NODES_INVALID;
    if (!execute("BEGIN IMMEDIATE"))
        return PANEL_NODES_ERROR;
    int64_t active, revision;
    enum panel_nodes_result outcome = panel_nodes_active(&active, &revision);
    if (outcome != PANEL_NODES_OK)
        return commit(outcome);
    if (expected_revision != revision)
        return commit(PANEL_NODES_CONFLICT);
    struct panel_node node;
    outcome = panel_nodes_get(id, &node);
    if (outcome != PANEL_NODES_OK || id == active)
        return commit(outcome);
    if (node.kind != PANEL_NODE_VPN)
        return commit(PANEL_NODES_INVALID);
    sqlite3_stmt *statement = select_node("UPDATE panel_nodes_active "
                                          "SET node_id=?1,revision=revision+1 WHERE id=1", id);
    bool ok = statement && sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    return commit(ok ? PANEL_NODES_OK : PANEL_NODES_ERROR);
}

static bool key_cipher(bool encrypt, const unsigned char *data, int length,
                       const char *endpoint, unsigned char *out, unsigned char *nonce, unsigned char *tag)
{
    EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
    int written = 0;
    bool ok = context && EVP_CipherInit_ex(context, EVP_aes_256_gcm(), NULL,
                                           credential_secret, nonce, encrypt) == 1 &&
              EVP_CipherUpdate(context, NULL, &written, (const unsigned char *)endpoint,
                               (int)strlen(endpoint)) == 1 &&
              EVP_CipherUpdate(context, out, &written, data, length) == 1 && written == length &&
              (encrypt || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) == 1) &&
              EVP_CipherFinal_ex(context, out + written, &written) == 1 && !written &&
              (!encrypt || EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) == 1);
    EVP_CIPHER_CTX_free(context);
    return ok;
}

static bool decrypt_key(sqlite3_stmt *statement, int column, const char *endpoint, char *key)
{
    const unsigned char *blob = sqlite3_column_blob(statement, column);
    int count = sqlite3_column_bytes(statement, column);
    int length = count - NONCE_SIZE - TAG_SIZE;
    if (!blob || length <= 0 || length > NODE_KEY_LIMIT)
        return false;
    unsigned char nonce[NONCE_SIZE], tag[TAG_SIZE];
    memcpy(nonce, blob, sizeof(nonce));
    memcpy(tag, blob + NONCE_SIZE + length, sizeof(tag));
    bool ok = key_cipher(false, blob + NONCE_SIZE, length, endpoint, (unsigned char *)key, nonce, tag);
    key[length] = '\0';
    return ok;
}

static bool read_existing_secret(int64_t id, const char *endpoint, char *key)
{
    sqlite3_stmt *statement = select_node("SELECT secret FROM panel_nodes WHERE id=?1 AND endpoint=?2", id);
    bool ok = statement && bind_text(statement, 2, endpoint) && sqlite3_step(statement) == SQLITE_ROW &&
              decrypt_key(statement, 0, endpoint, key);
    sqlite3_finalize(statement);
    return ok;
}

static enum panel_nodes_result valid_link(int kind, int64_t linked_vpn_node_id, int64_t self)
{
    if (linked_vpn_node_id == -1)
        return PANEL_NODES_OK;
    if (kind != PANEL_NODE_PROXY || linked_vpn_node_id < 0 || linked_vpn_node_id == self)
        return PANEL_NODES_INVALID;
    struct panel_node linked;
    enum panel_nodes_result outcome = panel_nodes_get(linked_vpn_node_id, &linked);
    if (outcome == PANEL_NODES_MISSING || (outcome == PANEL_NODES_OK && linked.kind != PANEL_NODE_VPN))
        return PANEL_NODES_INVALID;
    return outcome;
}

static size_t normalized_endpoint(const char *endpoint)
{
    size_t length = strlen(endpoint);
    return endpoint[length - 1] == '/' ? length - 1 : length;
}

static bool valid_node_input(const struct panel_node_input *input, int transport)
{
    if (!bounded_text(input->name, PANEL_NODE_NAME_LIMIT) || !utf8_text(input->name) ||
        !bounded_text(input->endpoint, PANEL_NODE_ENDPOINT_LIMIT) || transport <= PANEL_NODE_LOCAL ||
        !tls_name(input->ca_file) || !tls_name(input->client_cert) || !tls_name(input->client_key))
        return false;
    bool ca = input->ca_file && *input->ca_file;
    bool cert = input->client_cert && *input->client_cert;
    bool key = input->client_key && *input->client_key;
    if (transport == PANEL_NODE_HTTP)
        return !strncmp(input->endpoint, "http://", 7) && !ca && !cert && !key;
    return !strncmp(input->endpoint, "https://", 8) &&
           (transport == PANEL_NODE_MTLS ? ca && cert && key : !cert && !key);
}

static enum panel_nodes_result save_node(int64_t id, const struct panel_node_input *input,
                                        const char *endpoint, const char *key)
{
    int length = (int)strlen(key);
    unsigned char blob[BLOB_SIZE];
    bool encrypted = RAND_bytes(blob, NONCE_SIZE) == 1 &&
        key_cipher(true, (const unsigned char *)key, length, endpoint, blob + NONCE_SIZE, blob,
                   blob + NONCE_SIZE + length);
    if (!encrypted)
        return PANEL_NODES_ERROR;

    sqlite3_stmt *statement = prepare(id < 0 ?
        "INSERT INTO panel_nodes(name,endpoint,kind,transport,secret,ca_file,client_cert,client_key,"
        "linked_vpn_id,health) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)" :
        "UPDATE panel_nodes SET name=?1,endpoint=?2,kind=?3,transport=?4,secret=?5,ca_file=?6,"
        "client_cert=?7,client_key=?8,linked_vpn_id=?9,health=?10,health_checked_at=NULL,"
        "antizapret_version='',agent_version='',version=version+1 WHERE id=?11");
    bool bound = statement && bind_text(statement, 1, input->name) && bind_text(statement, 2, endpoint) &&
        bind_text(statement, 3, input->kind) && bind_text(statement, 4, input->transport) &&
        sqlite3_bind_blob(statement, 5, blob, NONCE_SIZE + length + TAG_SIZE, SQLITE_TRANSIENT) == SQLITE_OK &&
        bind_text(statement, 6, input->ca_file) && bind_text(statement, 7, input->client_cert) &&
        bind_text(statement, 8, input->client_key) &&
        (input->linked_vpn_node_id < 0 ? sqlite3_bind_null(statement, 9) == SQLITE_OK :
                                       bind_id(statement, 9, input->linked_vpn_node_id)) &&
        sqlite3_bind_int(statement, 10, NODE_HEALTH_UNKNOWN) == SQLITE_OK &&
        (id < 0 || bind_id(statement, 11, id));
    int step = bound ? sqlite3_step(statement) : SQLITE_ERROR;
    sqlite3_finalize(statement);
    OPENSSL_cleanse(blob, sizeof(blob));
    if (step == SQLITE_DONE)
        return PANEL_NODES_OK;
    return step == SQLITE_CONSTRAINT ? PANEL_NODES_CONFLICT : PANEL_NODES_ERROR;
}

static enum panel_nodes_result check_update(int64_t id, int kind)
{
    if (id < 0) {
        sqlite3_stmt *statement = prepare("SELECT count(*) FROM panel_nodes WHERE id>0");
        int count = statement && sqlite3_step(statement) == SQLITE_ROW ? sqlite3_column_int(statement, 0) : -1;
        sqlite3_finalize(statement);
        if (count < 0)
            return PANEL_NODES_ERROR;
        return count >= NODE_LIMIT ? PANEL_NODES_LIMIT : PANEL_NODES_OK;
    }

    struct panel_node node;
    enum panel_nodes_result outcome = panel_nodes_get(id, &node);
    return outcome == PANEL_NODES_OK && (int)node.kind != kind ? PANEL_NODES_CONFLICT : outcome;
}

enum panel_nodes_result panel_nodes_save(int64_t id, const struct panel_node_input *input, int64_t *saved_id)
{
    if (!database || id < -1 || !id || !input || !saved_id)
        return PANEL_NODES_INVALID;
    int kind = index_of(input->kind, kinds, sizeof(kinds) / sizeof(kinds[0]));
    int transport = index_of(input->transport, transports, sizeof(transports) / sizeof(transports[0]));
    if (kind < 0 || !valid_node_input(input, transport))
        return PANEL_NODES_INVALID;
    reap_job();
    if (current_job && current_job->id == id && !current_job->recorded)
        return PANEL_NODES_BUSY;
    char endpoint[PANEL_NODE_ENDPOINT_LIMIT + 1];
    size_t endpoint_length = normalized_endpoint(input->endpoint);
    memcpy(endpoint, input->endpoint, endpoint_length);
    endpoint[endpoint_length] = '\0';

    if (!execute("BEGIN IMMEDIATE"))
        return PANEL_NODES_ERROR;
    enum panel_nodes_result outcome = check_update(id, kind);
    if (outcome == PANEL_NODES_OK)
        outcome = valid_link(kind, input->linked_vpn_node_id, id);
    if (outcome != PANEL_NODES_OK)
        return commit(outcome);

    char old_key[NODE_KEY_LIMIT + 1] = {0};
    const char *key = input->node_key;
    if ((!key || !*key) && id > 0 && read_existing_secret(id, endpoint, old_key))
        key = old_key;
    struct node_transport_config config = {
        .endpoint = endpoint, .node_key = key, .deny_internal = deny_internal
    };
    outcome = node_transport_validate(&config) ? save_node(id, input, endpoint, key) : PANEL_NODES_INVALID;
    OPENSSL_cleanse(old_key, sizeof(old_key));
    int64_t result_id = id > 0 ? id : sqlite3_last_insert_rowid(database);
    outcome = commit(outcome);
    if (outcome == PANEL_NODES_OK)
        *saved_id = result_id;
    return outcome;
}

enum panel_nodes_result panel_nodes_delete(int64_t id)
{
    if (!database || id <= 0)
        return PANEL_NODES_INVALID;
    reap_job();
    if (current_job && current_job->id == id && !current_job->recorded)
        return PANEL_NODES_BUSY;
    if (!execute("BEGIN IMMEDIATE"))
        return PANEL_NODES_ERROR;
    sqlite3_stmt *statement = select_node("UPDATE panel_nodes_active "
        "SET node_id=0,revision=revision+1 WHERE id=1 AND node_id=?1", id);
    bool ok = statement && sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    enum panel_nodes_result outcome = PANEL_NODES_ERROR;
    if (ok) {
        statement = select_node("DELETE FROM panel_nodes WHERE id=?1", id);
        if (statement && sqlite3_step(statement) == SQLITE_DONE)
            outcome = sqlite3_changes(database) ? PANEL_NODES_OK : PANEL_NODES_MISSING;
        sqlite3_finalize(statement);
    }
    return commit(outcome);
}

static bool job_store_health(struct panel_nodes_job *job)
{
    sqlite3_stmt *statement = prepare(
        "UPDATE panel_nodes SET health=?1,health_checked_at=unixepoch(),"
        "antizapret_version=CASE WHEN ?2='' THEN antizapret_version ELSE ?2 END,"
        "agent_version=CASE WHEN ?3='' THEN agent_version ELSE ?3 END WHERE id=?4 AND version=?5");
    char antizapret[PANEL_NODE_VERSION_LIMIT + 1] = {0};
    char agent[PANEL_NODE_VERSION_LIMIT + 1] = {0};
    if (job->result.state == NODE_HEALTH_AVAILABLE && job->response[0]) {
        sqlite3_stmt *version = prepare("SELECT CAST(json_extract(?1,'$.antizapret_version') AS TEXT), "
                                        "CAST(json_extract(?1,'$.agent_version') AS TEXT)");
        if (version && bind_text(version, 1, job->response) && sqlite3_step(version) == SQLITE_ROW) {
            column_string(version, 0, antizapret, sizeof(antizapret));
            column_string(version, 1, agent, sizeof(agent));
        }
        sqlite3_finalize(version);
    }
    bool ok = statement && sqlite3_bind_int(statement, 1, job->result.state) == SQLITE_OK &&
        bind_text(statement, 2, antizapret) && bind_text(statement, 3, agent) &&
        bind_id(statement, 4, job->id) && bind_id(statement, 5, job->version) &&
        sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    return ok;
}

#ifdef _WIN32
static unsigned int __stdcall run_job(void *context)
#else
static void *run_job(void *context)
#endif
{
    struct panel_nodes_job *job = context;
    job->result = node_transport_request(&job->config, job->operation, job->destination,
                                         job->response, job->capacity);
    OPENSSL_cleanse(job->key, sizeof(job->key));
#ifdef _WIN32
    InterlockedExchange(&job->done, 1);
    return 0;
#else
    atomic_store_explicit(&job->done, true, memory_order_release);
    return NULL;
#endif
}

static bool job_done(struct panel_nodes_job *job)
{
#ifdef _WIN32
    return InterlockedCompareExchange(&job->done, 0, 0) != 0;
#else
    return atomic_load_explicit(&job->done, memory_order_acquire);
#endif
}

static bool job_cancelled(void *context)
{
    struct panel_nodes_job *job = context;
#ifdef _WIN32
    return InterlockedCompareExchange(&job->cancelled, 0, 0) != 0;
#else
    return atomic_load_explicit(&job->cancelled, memory_order_acquire);
#endif
}

static void cancel_job(struct panel_nodes_job *job)
{
#ifdef _WIN32
    InterlockedExchange(&job->cancelled, 1);
#else
    atomic_store_explicit(&job->cancelled, true, memory_order_release);
#endif
}

static bool launch_job(struct panel_nodes_job *job)
{
#ifdef _WIN32
    job->thread = (HANDLE)_beginthreadex(NULL, THREAD_STACK, run_job, job, STACK_SIZE_PARAM_IS_A_RESERVATION, NULL);
    return job->thread != NULL;
#else
    pthread_attr_t attributes;
    atomic_init(&job->done, false);
    atomic_init(&job->cancelled, false);
    if (pthread_attr_init(&attributes) != 0)
        return false;
    bool ok = pthread_attr_setstacksize(&attributes, THREAD_STACK) == 0 &&
              pthread_create(&job->thread, &attributes, run_job, job) == 0;
    pthread_attr_destroy(&attributes);
    return ok;
#endif
}

static void free_job(struct panel_nodes_job *job)
{
    OPENSSL_cleanse(job, sizeof(*job) + job->capacity);
    free(job);
}

static void finish_job(struct panel_nodes_job *job)
{
#ifdef _WIN32
    WaitForSingleObject(job->thread, INFINITE);
    CloseHandle(job->thread);
#else
    pthread_join(job->thread, NULL);
#endif
    if (!job->recorded && job->operation == NODE_OPERATION_HEALTH && !job_cancelled(job))
        job_store_health(job);
    current_job = NULL;
    free_job(job);
}

static void reap_job(void)
{
    if (current_job && current_job->detached && job_done(current_job))
        finish_job(current_job);
}

static bool trusted_tls_file(const char *path, bool holds_private_key)
{
#ifdef _WIN32
    (void)holds_private_key;
    DWORD directory = GetFileAttributesA(tls_dir);
    DWORD file = GetFileAttributesA(path);
    return directory != INVALID_FILE_ATTRIBUTES && (directory & FILE_ATTRIBUTE_DIRECTORY) &&
           !(directory & FILE_ATTRIBUTE_REPARSE_POINT) && file != INVALID_FILE_ATTRIBUTES &&
           !(file & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
#else
    struct stat directory, file;
    mode_t forbidden = holds_private_key ? 077 : 022;
    return lstat(tls_dir, &directory) == 0 && S_ISDIR(directory.st_mode) &&
           !(directory.st_mode & 022) && lstat(path, &file) == 0 && S_ISREG(file.st_mode) &&
           !(file.st_mode & forbidden);
#endif
}

static enum panel_nodes_result load_job_config(struct panel_nodes_job *job)
{
    sqlite3_stmt *statement = select_node("SELECT endpoint,secret,ca_file,client_cert,client_key,kind,version "
                                          "FROM panel_nodes WHERE id=?1", job->id);
    int step = statement ? sqlite3_step(statement) : SQLITE_ERROR;
    enum panel_nodes_result outcome = step == SQLITE_DONE ? PANEL_NODES_MISSING : PANEL_NODES_ERROR;
    if (step != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return outcome;
    }

    int kind = column_index(statement, 5, kinds, sizeof(kinds) / sizeof(kinds[0]));
    job->version = sqlite3_column_int64(statement, 6);
    if (kind < 0 || (job->operation != NODE_OPERATION_HEALTH && kind != PANEL_NODE_PROXY)) {
        sqlite3_finalize(statement);
        return PANEL_NODES_INVALID;
    }

    const char **paths[] = { &job->config.ca_file, &job->config.client_cert, &job->config.client_key };
    bool ok = column_string(statement, 0, job->endpoint, sizeof(job->endpoint)) &&
              decrypt_key(statement, 1, job->endpoint, job->key);
    for (size_t i = 0; ok && i < sizeof(paths) / sizeof(paths[0]); ++i) {
        char filename[PANEL_NODE_FILE_LIMIT + 1];
        ok = column_string(statement, (int)i + 2, filename, sizeof(filename)) && tls_name(filename);
        if (ok && filename[0]) {
            if (!join_path(job->tls_paths[i], tls_dir, filename) ||
                !trusted_tls_file(job->tls_paths[i], i == 2)) {
                sqlite3_finalize(statement);
                return PANEL_NODES_INVALID;
            }
            *paths[i] = job->tls_paths[i];
        }
    }
    sqlite3_finalize(statement);
    job->config.endpoint = job->endpoint;
    job->config.node_key = job->key;
    job->config.deny_internal = deny_internal;
    job->config.should_cancel = job_cancelled;
    job->config.cancel_context = job;
    return ok ? PANEL_NODES_OK : PANEL_NODES_ERROR;
}

enum panel_nodes_result panel_nodes_job_start(int64_t id, enum node_operation operation,
    const char *destination, struct panel_nodes_job **job)
{
    if (!database || !job || id <= 0 || (unsigned int)operation > NODE_OPERATION_PROXY_MAPPINGS ||
        (operation == NODE_OPERATION_PROXY_DESTINATION && !node_transport_valid_proxy_destination(destination)))
        return PANEL_NODES_INVALID;
    *job = NULL;
    reap_job();
    if (current_job)
        return PANEL_NODES_BUSY;
    size_t capacity = (operation == NODE_OPERATION_PROXY_MAPPINGS ? AGENT_MAPPINGS_LIMIT : AGENT_BODY_LIMIT) + 1;
    struct panel_nodes_job *task = calloc(1, sizeof(*task) + capacity);
    if (!task)
        return PANEL_NODES_ERROR;
    task->capacity = capacity;
    task->id = id;
    task->operation = operation;
    if (operation == NODE_OPERATION_PROXY_DESTINATION)
        snprintf(task->destination, sizeof(task->destination), "%s", destination);
    enum panel_nodes_result outcome = load_job_config(task);
    if (outcome != PANEL_NODES_OK || !launch_job(task)) {
        free_job(task);
        return outcome == PANEL_NODES_OK ? PANEL_NODES_ERROR : outcome;
    }
    *job = current_job = task;
    return PANEL_NODES_OK;
}

bool panel_nodes_job_poll(struct panel_nodes_job *job, struct node_health_result *result, const char **data)
{
    if (!job || job != current_job || !result || !data || !job_done(job))
        return false;
    if (!job->recorded && job->operation == NODE_OPERATION_HEALTH)
        job->recorded = job_store_health(job);
    *result = job->result;
    *data = job->response[0] ? job->response : NULL;
    return true;
}

void panel_nodes_job_release(struct panel_nodes_job *job)
{
    if (job && job == current_job) {
        job->detached = true;
        reap_job();
    }
}

void panel_nodes_close(void)
{
    if (!database)
        return;
    if (current_job) {
        cancel_job(current_job);
        finish_job(current_job);
    }
    sqlite3_close(database);
    database = NULL;
    OPENSSL_cleanse(credential_secret, sizeof(credential_secret));
    node_transport_cleanup();
}
