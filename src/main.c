#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif

#include <libwebsockets.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#include <io.h>
#define make_dir(path) _mkdir(path)
#define open_upload(path) _open(path, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _S_IREAD | _S_IWRITE)
#define fd_to_file _fdopen
#define close_fd _close
#define resolve_path(path, out) _fullpath(out, path, PATH_CAP)
#define is_directory(mode) (((mode) & _S_IFMT) == _S_IFDIR)
#define is_regular(mode) (((mode) & _S_IFMT) == _S_IFREG)
#else
#include <unistd.h>
#define make_dir(path) mkdir(path, 0700)
#define open_upload(path) open(path, O_WRONLY | O_CREAT | O_EXCL, 0600)
#define fd_to_file fdopen
#define close_fd close
#define is_directory S_ISDIR
#define is_regular S_ISREG
#endif

enum { PATH_CAP = 4096, TOKEN_CAP = 129, MAX_STREAMS = 12, MAX_INDEX = 32 * 1024 };
static const unsigned long long upload_limit = 200ULL * 1024 * 1024;
static const lws_usec_t sample_interval = 2 * LWS_US_PER_SEC;

struct config {
    const char *bind;
    const char *ui;
    const char *data;
    const char *cert;
    const char *key;
    const char *token;
    int port;
};

struct upload {
    FILE *file;
    char id[33];
    unsigned long long length;
    unsigned long long received;
#ifdef __linux__
    unsigned long long flushed;
#endif
};

struct session {
    struct upload *upload;
    char response[256];
    unsigned int status;
    bool close_after_reply;
    bool headers_sent;
    bool subscribed;
    bool head;
    bool ui_index;
    size_t offset;
};

static struct config config = { .bind = "127.0.0.1", .data = "data", .port = 8000 };
static char ui_root[PATH_CAP];
static char *ui_index;
static size_t ui_index_size;
static char backups[PATH_CAP];
static time_t started;
static unsigned int subscribers;
static unsigned long long uploaded_bytes;
static volatile sig_atomic_t stopping;

static bool join_path(char *out, const char *base, const char *name)
{
    int written = snprintf(out, PATH_CAP, "%s/%s", base, name);
    return written >= 0 && written < PATH_CAP;
}

#ifndef _WIN32
static char *resolve_path(const char *path, char *out)
{
    char *resolved = realpath(path, NULL);
    if (!resolved)
        return NULL;
    size_t size = strlen(resolved) + 1;
    if (size <= PATH_CAP)
        memcpy(out, resolved, size);
    free(resolved);
    return size <= PATH_CAP ? out : NULL;
}
#endif

static bool directory_exists(const char *path)
{
    struct stat info;
    return stat(path, &info) == 0 && is_directory(info.st_mode);
}

static bool ensure_directory(const char *path)
{
    return make_dir(path) == 0 || (errno == EEXIST && directory_exists(path));
}

static bool authorized(struct lws *wsi)
{
    char authorization[TOKEN_CAP + sizeof("Bearer ")];
    int size = lws_hdr_copy(wsi, authorization, sizeof(authorization), WSI_TOKEN_HTTP_AUTHORIZATION);
    size_t token_size = strlen(config.token);
    if (size < 0 || (size_t)size != 7 + token_size || memcmp(authorization, "Bearer ", 7))
        return false;

    volatile unsigned int difference = 0;
    for (size_t i = 0; i < token_size; ++i)
        difference |= (unsigned char)authorization[7 + i] ^ (unsigned char)config.token[i];
    return difference == 0;
}

static void metrics(char *out, size_t capacity)
{
    time_t now = time(NULL);
    long long uptime = now >= started ? (long long)(now - started) : 0;
    snprintf(out, capacity,
             "{\"timestamp\":%lld,\"uptime_seconds\":%lld,\"streams\":%u,\"uploaded_bytes\":%llu}",
             (long long)now, uptime, subscribers, uploaded_bytes);
}

static int reply(struct lws *wsi, struct session *session, unsigned int status, const char *body)
{
    session->status = status;
    if (body != session->response)
        snprintf(session->response, sizeof(session->response), "%s", body);
    lws_callback_on_writable(wsi);
    return 0;
}

static int error_reply(struct lws *wsi, struct session *session, unsigned int status, const char *reason)
{
    session->close_after_reply = true;
    snprintf(session->response, sizeof(session->response), "{\"error\":\"%s\"}", reason);
    return reply(wsi, session, status, session->response);
}

static bool upload_path(char *out, const struct upload *upload, const char *suffix)
{
    char name[48];
    snprintf(name, sizeof(name), "%s%s", upload->id, suffix);
    return join_path(out, backups, name);
}

static void discard_upload(struct session *session)
{
    struct upload *upload = session->upload;
    if (!upload)
        return;
    char partial[PATH_CAP];
    if (upload->file)
        fclose(upload->file);
    if (upload->id[0] && upload_path(partial, upload, ".part"))
        remove(partial);
    free(upload);
    session->upload = NULL;
}

static int begin_upload(struct lws *wsi, struct session *session)
{
    char length[32];
    char type[64];
    if (lws_hdr_copy(wsi, length, sizeof(length), WSI_TOKEN_HTTP_CONTENT_LENGTH) <= 0)
        return error_reply(wsi, session, 411, "content_length_required");

    unsigned long long expected = 0;
    for (const char *p = length; *p; ++p) {
        if (*p < '0' || *p > '9')
            return error_reply(wsi, session, 400, "invalid_content_length");
        expected = expected * 10 + (unsigned int)(*p - '0');
        if (expected > upload_limit)
            return error_reply(wsi, session, 413, "backup_too_large");
    }
    if (!expected)
        return error_reply(wsi, session, 400, "empty_backup");
    if (lws_hdr_copy(wsi, type, sizeof(type), WSI_TOKEN_HTTP_CONTENT_TYPE) <= 0 ||
        strcmp(type, "application/octet-stream"))
        return error_reply(wsi, session, 415, "expected_application_octet_stream");

    unsigned char random[16];
    if (lws_get_random(lws_get_context(wsi), random, sizeof(random)) != (int)sizeof(random))
        return error_reply(wsi, session, 500, "random_id_unavailable");

    struct upload *upload = calloc(1, sizeof(*upload));
    if (!upload)
        return error_reply(wsi, session, 503, "out_of_memory");
    char partial[PATH_CAP];
    for (size_t i = 0; i < sizeof(random); ++i)
        snprintf(upload->id + 2 * i, 3, "%02x", (unsigned int)random[i]);
    int fd = upload_path(partial, upload, ".part") ? open_upload(partial) : -1;
    if (fd < 0) {
        free(upload);
        return error_reply(wsi, session, 500, "cannot_create_backup");
    }
    upload->file = fd_to_file(fd, "wb");
    if (!upload->file) {
        close_fd(fd);
        remove(partial);
        free(upload);
        return error_reply(wsi, session, 500, "cannot_open_backup");
    }
    upload->length = expected;
    session->upload = upload;
    return 0;
}

static int receive_upload(struct lws *wsi, struct session *session, const void *data, size_t len)
{
    struct upload *upload = session->upload;
    if (!upload)
        return 0;
    if (len > upload->length - upload->received || fwrite(data, 1, len, upload->file) != len) {
        discard_upload(session);
        return error_reply(wsi, session, 500, "backup_write_failed");
    }
    upload->received += len;
#ifdef __linux__
    // Bound dirty file-cache pages charged to the service's cgroup.
    const unsigned long long batch_size = 1024 * 1024;
    unsigned long long boundary = upload->received - upload->received % batch_size;
    if (boundary > upload->flushed) {
        int fd = fileno(upload->file);
        if (fflush(upload->file) != 0 || fdatasync(fd) != 0) {
            discard_upload(session);
            return error_reply(wsi, session, 500, "backup_write_failed");
        }
        (void)posix_fadvise(fd, (off_t)upload->flushed, (off_t)(boundary - upload->flushed), POSIX_FADV_DONTNEED);
        upload->flushed = boundary;
    }
#endif
    return 0;
}

static int finish_upload(struct lws *wsi, struct session *session)
{
    struct upload *upload = session->upload;
    if (!upload)
        return 0;
    if (upload->received != upload->length) {
        discard_upload(session);
        return error_reply(wsi, session, 400, "incomplete_backup");
    }
    int close_result = fclose(upload->file);
    upload->file = NULL;
    char partial[PATH_CAP];
    char final[PATH_CAP];
    if (close_result || !upload_path(partial, upload, ".part") ||
        !upload_path(final, upload, ".backup") || rename(partial, final) != 0) {
        discard_upload(session);
        return error_reply(wsi, session, 500, "cannot_commit_backup");
    }
    uploaded_bytes += upload->received;
    snprintf(session->response, sizeof(session->response), "{\"name\":\"%s.backup\",\"size\":%llu}",
             upload->id, upload->received);
    free(upload);
    session->upload = NULL;
    return reply(wsi, session, 201, session->response);
}

static const char *mime_type(const char *path)
{
    const char *extension = strrchr(path, '.');
    static const struct { const char *extension, *type; } types[] = {
        {".html", "text/html; charset=utf-8"}, {".js", "text/javascript"}, {".mjs", "text/javascript"},
        {".css", "text/css"}, {".svg", "image/svg+xml"}, {".png", "image/png"},
        {".webp", "image/webp"}, {".ico", "image/x-icon"}, {".woff2", "font/woff2"},
        {".woff", "font/woff"}, {".json", "application/json"}, {".webmanifest", "application/manifest+json"}
    };
    if (extension)
        for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); ++i)
            if (!strcmp(extension, types[i].extension))
                return types[i].type;
    return NULL;
}

static bool safe_ui_path(const char *uri)
{
    if (uri[0] != '/')
        return false;
    for (const char *p = uri + 1; *p; ++p) {
        if (*p != '/' && *p != '-' && *p != '_' && *p != '.' &&
            !isalnum((unsigned char)*p))
            return false;
        if (p[-1] == '/' && (*p == '.' || *p == '/'))
            return false;
    }
    return true;
}

static bool ui_file(const char *relative, char *resolved)
{
    char path[PATH_CAP];
    struct stat info;
    size_t root_size = strlen(ui_root);
    return join_path(path, ui_root, relative) && resolve_path(path, resolved) &&
        !strncmp(ui_root, resolved, root_size) && (resolved[root_size] == '/' || resolved[root_size] == '\\') &&
        stat(resolved, &info) == 0 && is_regular(info.st_mode);
}

static bool load_index(void)
{
    char resolved[PATH_CAP];
    FILE *index = ui_file("index.html", resolved) ? fopen(resolved, "rb") : NULL;
    if (!index)
        return false;
    ui_index = malloc(MAX_INDEX + 1);
    ui_index_size = ui_index ? fread(ui_index, 1, MAX_INDEX + 1, index) : 0;
    bool valid = ui_index_size && ui_index_size <= MAX_INDEX && !ferror(index) &&
        !memchr(ui_index, '\0', ui_index_size);
    fclose(index);
    if (!valid)
        return false;

    // Vite builds relative asset URLs. Resolve them at root even on a deep SPA route.
    ui_index[ui_index_size] = '\0';
    char *write = ui_index;
    for (const char *read = ui_index; *read; ++read) {
        *write++ = *read;
        if ((*read == '"' || *read == '\'') && !strncmp(read + 1, "./assets/", 9))
            ++read;
    }
    ui_index_size = (size_t)(write - ui_index);
    return true;
}

static int serve_ui(struct lws *wsi, struct session *session, const char *uri)
{
    if (!ui_root[0] || !safe_ui_path(uri))
        return error_reply(wsi, session, 404, "not_found");

    const char *name = strrchr(uri, '/');
    if (!strcmp(uri, "/index.html") || (!strchr(name, '.') && strncmp(uri, "/assets/", 8))) {
        session->ui_index = true;
        return reply(wsi, session, 200, "");
    }

    const char *type = mime_type(uri);
    char resolved[PATH_CAP];
    if (!type || !ui_file(uri + 1, resolved))
        return error_reply(wsi, session, 404, "not_found");

    const char *headers = "cache-control: no-cache\r\nx-content-type-options: nosniff\r\n";
    int result = lws_serve_http_file(wsi, resolved, type, headers, (int)strlen(headers));
    if (result < 0)
        return -1;
    return result > 0 ? lws_http_transaction_completed(wsi) : 0;
}

static int request(struct lws *wsi, struct session *session)
{
    char *uri;
    int uri_len;
    int method = lws_http_get_uri_and_method(wsi, &uri, &uri_len);
    if (method < 0 || uri_len < 1)
        return error_reply(wsi, session, 400, "invalid_request");
    session->head = method == LWSHUMETH_HEAD;
    if (!strcmp(uri, "/api/health") && method == LWSHUMETH_GET)
        return reply(wsi, session, 200, "{\"status\":\"ok\"}");
    if (!strcmp(uri, "/api/monitor") || !strcmp(uri, "/api/monitor/events") ||
        !strcmp(uri, "/api/backups/upload")) {
        if (!authorized(wsi))
            return error_reply(wsi, session, 401, "unauthorized");
        if (!strcmp(uri, "/api/backups/upload"))
            return method == LWSHUMETH_POST ? begin_upload(wsi, session) :
                error_reply(wsi, session, 405, "method_not_allowed");
        if (method != LWSHUMETH_GET)
            return error_reply(wsi, session, 405, "method_not_allowed");
        if (!strcmp(uri, "/api/monitor")) {
            metrics(session->response, sizeof(session->response));
            return reply(wsi, session, 200, session->response);
        }
        if (subscribers >= MAX_STREAMS)
            return error_reply(wsi, session, 503, "too_many_streams");
        session->subscribed = true;
        ++subscribers;
        lws_set_timeout(wsi, NO_PENDING_TIMEOUT, 0);
        lws_callback_on_writable(wsi);
        return 0;
    }
    if (!strcmp(uri, "/api") || !strncmp(uri, "/api/", 5))
        return error_reply(wsi, session, 404, "not_found");
    if (method != LWSHUMETH_GET && method != LWSHUMETH_HEAD)
        return error_reply(wsi, session, 405, "method_not_allowed");
    return serve_ui(wsi, session, uri);
}

static int write_headers(struct lws *wsi, const struct session *session)
{
    unsigned char buffer[LWS_PRE + 512];
    unsigned char *start = buffer + LWS_PRE;
    unsigned char *p = start;
    unsigned char *end = buffer + sizeof(buffer);
    unsigned int status = session->subscribed ? 200 : session->status;
    const char *type = session->ui_index ? "text/html; charset=utf-8" : "application/json";
    lws_filepos_t length = session->ui_index ? ui_index_size : strlen(session->response);
    if (session->subscribed) {
        type = "text/event-stream";
        length = LWS_ILLEGAL_HTTP_CONTENT_LEN;
    }

    if (lws_add_http_common_headers(wsi, status, type, length, &p, end) ||
        lws_add_http_header_by_name(wsi, (const unsigned char *)"cache-control:",
                                   (const unsigned char *)"no-store", 8, &p, end) ||
        lws_add_http_header_by_name(wsi, (const unsigned char *)"x-content-type-options:",
                                   (const unsigned char *)"nosniff", 7, &p, end) ||
        ((session->subscribed || session->close_after_reply) &&
         lws_add_http_header_by_name(wsi, (const unsigned char *)"connection:",
                                    (const unsigned char *)"close", 5, &p, end)) ||
        lws_finalize_write_http_header(wsi, start, &p, end))
        return -1;
    return 0;
}

static int write_http(struct lws *wsi, struct session *session)
{
    unsigned char output[LWS_PRE + 4096];
    unsigned char *body = output + LWS_PRE;
    if (!session->headers_sent) {
        if (write_headers(wsi, session))
            return -1;
        if (session->head)
            return session->close_after_reply ? -1 : lws_http_transaction_completed(wsi);
        session->headers_sent = true;
        lws_callback_on_writable(wsi);
        return 0;
    }
    if (session->subscribed) {
        char sample[160];
        metrics(sample, sizeof(sample));
        int size = snprintf((char *)body, sizeof(output) - LWS_PRE, "event: sample\ndata: %s\n\n", sample);
        if (size < 0 || (size_t)size >= sizeof(output) - LWS_PRE ||
            lws_write(wsi, body, (size_t)size, LWS_WRITE_HTTP) < size)
            return -1;
        lws_set_timer_usecs(wsi, sample_interval);
        return 0;
    }
    const char *payload = session->ui_index ? ui_index : session->response;
    size_t remaining = (session->ui_index ? ui_index_size : strlen(payload)) - session->offset;
    size_t capacity = sizeof(output) - LWS_PRE;
    size_t size = remaining < capacity ? remaining : capacity;
    bool last = size == remaining;
    memcpy(body, payload + session->offset, size);
    if (lws_write(wsi, body, size, last ? LWS_WRITE_HTTP_FINAL : LWS_WRITE_HTTP) < (int)size)
        return -1;
    if (last)
        return session->close_after_reply ? -1 : lws_http_transaction_completed(wsi);
    session->offset += size;
    lws_callback_on_writable(wsi);
    return 0;
}

static void cleanup(struct session *session)
{
    if (session->subscribed) {
        --subscribers;
        session->subscribed = false;
    }
    discard_upload(session);
}

static int callback(struct lws *wsi, enum lws_callback_reasons event, void *user, void *in, size_t len)
{
    struct session *session = user;
    switch (event) {
    case LWS_CALLBACK_HTTP_BIND_PROTOCOL:
        memset(session, 0, sizeof(*session));
        break;
    case LWS_CALLBACK_HTTP:
        return request(wsi, session);
    case LWS_CALLBACK_HTTP_BODY:
        return receive_upload(wsi, session, in, len);
    case LWS_CALLBACK_HTTP_BODY_COMPLETION:
        return finish_upload(wsi, session);
    case LWS_CALLBACK_HTTP_WRITEABLE:
        if (session->status || session->subscribed)
            return write_http(wsi, session);
        break;
    case LWS_CALLBACK_HTTP_FILE_COMPLETION:
        return lws_http_transaction_completed(wsi);
    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION: {
        char path[64];
        unsigned int status = 0;
        if (lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_GET_URI) <= 0 || strcmp(path, "/api/monitor/ws"))
            status = 404;
        else if (!authorized(wsi))
            status = 401;
        else if (subscribers >= MAX_STREAMS)
            status = 503;
        if (status) {
            lws_return_http_status(wsi, status, NULL);
            return 1;
        }
        break;
    }
    case LWS_CALLBACK_ESTABLISHED:
        session->subscribed = true;
        ++subscribers;
        lws_callback_on_writable(wsi);
        break;
    case LWS_CALLBACK_SERVER_WRITEABLE: {
        unsigned char buffer[LWS_PRE + 160];
        char *sample = (char *)buffer + LWS_PRE;
        metrics(sample, sizeof(buffer) - LWS_PRE);
        size_t size = strlen(sample);
        if (lws_write(wsi, (unsigned char *)sample, size, LWS_WRITE_TEXT) < (int)size)
            return -1;
        lws_set_timer_usecs(wsi, sample_interval);
        break;
    }
    case LWS_CALLBACK_TIMER:
        if (session->subscribed)
            lws_callback_on_writable(wsi);
        break;
    case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
    case LWS_CALLBACK_CLOSED_HTTP:
    case LWS_CALLBACK_CLOSED:
        if (session)
            cleanup(session);
        break;
    default:
        break;
    }
    return lws_callback_http_dummy(wsi, event, user, in, len);
}

static const struct lws_protocols protocols[] = {
    { .name = "http", .callback = callback, .per_session_data_size = sizeof(struct session), .rx_buffer_size = 4096 },
    { .name = "adminpanel-monitor", .callback = callback, .per_session_data_size = sizeof(struct session), .rx_buffer_size = 4096 },
    { 0 }
};

static void stop(int sig)
{
    (void)sig;
    stopping = 1;
}

static void usage(void)
{
    puts("adminpanelaz-lws [--bind IP] [--port N] [--ui-dir PATH] [--data-dir PATH]\n"
         "                 [--tls-cert PEM --tls-key PEM]\n"
         "Set APAZ_AUTH_TOKEN to a random token of 32 to 128 URL-safe ASCII characters.");
}

static bool parse_options(int argc, char **argv)
{
    for (int i = 1; i < argc; ++i) {
        const char *option = argv[i];
        if (++i == argc)
            return false;
        const char *value = argv[i];
        if (!strcmp(option, "--port")) {
            char *end;
            long port = strtol(value, &end, 10);
            if (!*value || *end || port < 1 || port > 65535)
                return false;
            config.port = (int)port;
        } else if (!strcmp(option, "--bind")) {
            config.bind = value;
        } else if (!strcmp(option, "--ui-dir")) {
            config.ui = value;
        } else if (!strcmp(option, "--data-dir")) {
            config.data = value;
        } else if (!strcmp(option, "--tls-cert")) {
            config.cert = value;
        } else if (!strcmp(option, "--tls-key")) {
            config.key = value;
        } else {
            return false;
        }
    }
    return (!!config.cert == !!config.key) && (config.cert || !strcmp(config.bind, "127.0.0.1"));
}

int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "--help")) {
        usage();
        return 0;
    }
    if (!parse_options(argc, argv)) {
        usage();
        return 2;
    }
    config.token = getenv("APAZ_AUTH_TOKEN");
    if (!config.token || strlen(config.token) < 32 || strlen(config.token) >= TOKEN_CAP ||
        strspn(config.token, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.~") != strlen(config.token)) {
        fputs("Set APAZ_AUTH_TOKEN to 32–128 URL-safe characters.\n", stderr);
        return 2;
    }
    if (config.ui && (!resolve_path(config.ui, ui_root) || !directory_exists(ui_root) || !load_index())) {
        fputs("Cannot load UI index.html (limit 32 KiB).\n", stderr);
        free(ui_index);
        return 2;
    }
    if (!ensure_directory(config.data) || !join_path(backups, config.data, "backups") || !ensure_directory(backups)) {
        fputs("Cannot create backup directory.\n", stderr);
        free(ui_index);
        return 2;
    }

    struct lws_context_creation_info info = {0};
    info.iface = config.bind;
    info.port = config.port;
    info.protocols = protocols;
    info.alpn = "http/1.1";
    info.fd_limit_per_thread = 48;
    info.max_http_header_pool = 16;
    info.max_http_header_data = 4096;
    info.pt_serv_buf_size = 4096;
    info.timeout_secs = 20;
    if (config.cert) {
        info.options = LWS_SERVER_OPTION_DO_SSL_GLOBAL_INIT;
        info.ssl_cert_filepath = config.cert;
        info.ssl_private_key_filepath = config.key;
    }
    signal(SIGINT, stop);
    signal(SIGTERM, stop);
    started = time(NULL);
    struct lws_context *context = lws_create_context(&info);
    if (!context) {
        free(ui_index);
        return 1;
    }
    int status = 0;
    while (!stopping && status >= 0)
        status = lws_service(context, 0);
    lws_context_destroy(context);
    free(ui_index);
    return status < 0 && !stopping ? 1 : 0;
}
