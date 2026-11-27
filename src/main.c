#if !defined(_WIN32)
#define _XOPEN_SOURCE 700
#endif

#include <libwebsockets.h>

#include "dashboard.h"
#include "portal_page.h"
#include "host_metrics.h"
#include "vpn_status.h"
#include "wireguard_status.h"
#include "panel_auth.h"
#include "panel_backups.h"
#include "panel_backup_create.h"
#include "panel_profiles.h"
#include "panel_security.h"
#include "panel_client.h"
#include "panel_history.h"
#include "panel_nodes.h"
#include "panel_settings.h"
#include "panel_ha.h"
#include "panel_portal.h"
#include "panel_telegram.h"
#include "cidr_routes.h"
#include "panel_cidr_job.h"
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
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

enum { PATH_CAP = 4096, TOKEN_CAP = 129, MAX_STREAMS = 12, MAX_INDEX = 32 * 1024,
       MAX_OPENVPN_PATHS = 8, CONNECTIONS_CAP = 16 * 1024, METRICS_CAP = CONNECTIONS_CAP * 2 + 4096,
       FORM_LIMIT = 16384, FORM_FIELDS = 24, ACCESS_PATH_CAP = 97 };
static const unsigned long long upload_limit = 200ULL * 1024 * 1024;
static const lws_usec_t sample_interval = 2 * LWS_US_PER_SEC;

struct web_asset {
    const char *path;
    const char *type;
    const unsigned char *data;
    size_t size;
};

#include "web_assets.h"

struct config {
    const char *bind;
    const char *ui;
    const char *data;
    const char *cert;
    const char *key;
    const char *token;
    const char *openvpn[MAX_OPENVPN_PATHS];
    size_t openvpn_count;
    const char *wireguard;
    const char *auth_db;
    const char *profiles;
    const char *client_socket;
    const char *portal_db;
    const char *portal_profiles;
    const char *config_dir;
    const char *knot_dir;
    const char *antizapret_setup;
    const char *public_origin;
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

struct form {
    size_t count;
    struct { const char *name; const char *value; } fields[FORM_FIELDS];
};

struct cidr_request_body {
    FILE *input;
    size_t expected;
    size_t received;
    size_t flushed;
    char source[104];
};

struct session {
    struct upload *upload;
    char *dashboard_response;
    char *form;
    size_t form_length;
    size_t form_received;
    int (*finish_form)(struct lws *, struct session *, const struct form *);
    const char *content_type;
    const char *admin_feature;
    bool admin_form;
    const unsigned char *asset;
    size_t asset_size;
    int64_t resource_id;
    struct panel_nodes_job *node_job;
    struct panel_cidr_job *cidr_job;
    struct cidr_request_body *cidr_body;
    bool cidr_export;
    bool cidr_mutation;
    bool portal;
    char remote_ip[PANEL_SECURITY_IP_SIZE];
    char current_token[65];
    char cookie[65];
    bool clear_cookie;
    unsigned int retry_after;
    FILE *profile;
    size_t profile_size;
    char filename[129];
    char response[512];
    unsigned int status;
    bool close_after_reply;
    bool headers_sent;
    bool subscribed;
    bool stream_bearer;
    bool head;
    bool ui_index;
    size_t offset;
};

static struct config config = { .bind = "127.0.0.1", .data = "data", .port = 8000 };
static char access_path[ACCESS_PATH_CAP];
static char ui_root[PATH_CAP];
static char *ui_index;
static size_t ui_index_size;
static char backups[PATH_CAP];
static char cidr_db[PATH_CAP];
static time_t started;
static unsigned int subscribers;
static unsigned long long uploaded_bytes;
static volatile sig_atomic_t stopping;
static lws_sorted_usec_list_t history_timer;
static struct lws_context *server_context;

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

static bool bearer_authorized(struct lws *wsi)
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

static bool session_token(struct lws *wsi, char token[65])
{
    const char name[] = "apaz_session=";
    char header[2048];
    if (!config.auth_db || lws_hdr_copy(wsi, header, sizeof(header), WSI_TOKEN_HTTP_COOKIE) <= 0)
        return false;
    for (char *p = header; p; ) {
        while (*p == ' ')
            ++p;
        char *end = strchr(p, ';');
        if (end)
            *end = '\0';
        if (!strncmp(p, name, sizeof(name) - 1) && strlen(p + sizeof(name) - 1) == 64 &&
            strspn(p + sizeof(name) - 1, "0123456789abcdef") == 64) {
            memcpy(token, p + sizeof(name) - 1, 65);
            return true;
        }
        p = end ? end + 1 : NULL;
    }
    return false;
}

static bool current_identity(struct lws *wsi, struct panel_auth_identity *identity)
{
    char token[65];
    const struct session *session = lws_wsi_user(wsi);
    if (session && session->current_token[0])
        return panel_auth_identify(session->current_token, identity);
    return session_token(wsi, token) && panel_auth_identify(token, identity);
}

static bool authorized(struct lws *wsi)
{
    struct panel_auth_identity identity;
    return bearer_authorized(wsi) || (current_identity(wsi, &identity) &&
        !identity.must_change_password && identity.role == PANEL_AUTH_ROLE_ADMIN);
}

static bool request_ip(struct lws *wsi, char out[PANEL_SECURITY_IP_SIZE])
{
    const struct session *session = lws_wsi_user(wsi);
    if (session && session->remote_ip[0]) {
        if (out != session->remote_ip)
            strcpy(out, session->remote_ip);
        return true;
    }
    char peer[PANEL_SECURITY_IP_SIZE], forwarded[PANEL_SECURITY_FORWARDED_MAX + 1];
    if (!lws_get_peer_simple(wsi, peer, sizeof(peer)))
        return false;
    int length = lws_hdr_total_length(wsi, WSI_TOKEN_X_FORWARDED_FOR);
    if (length > PANEL_SECURITY_FORWARDED_MAX)
        return false;
    int size = lws_hdr_copy(wsi, forwarded, sizeof(forwarded), WSI_TOKEN_X_FORWARDED_FOR);
    if (length > 0 && size <= 0)
        return false;
    return panel_security_client_ip(peer, size > 0 ? forwarded : NULL, out);
}

static void audit_actor(int64_t id, enum panel_history_action action, bool success)
{
    if (panel_settings_enabled("action_logs"))
        panel_history_audit((int64_t)time(NULL), id, action, success);
}

static void audit(struct lws *wsi, enum panel_history_action action, bool success)
{
    struct panel_auth_identity identity;
    int64_t id = current_identity(wsi, &identity) ? identity.id : 0;
    audit_actor(id, action, success);
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

static bool same_origin(struct lws *wsi)
{
    char origin[300], host[256], expected[300];
    if (!lws_hdr_total_length(wsi, WSI_TOKEN_ORIGIN))
        return true;
    if (lws_hdr_copy(wsi, origin, sizeof(origin), WSI_TOKEN_ORIGIN) < 1 ||
        lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HOST) < 1)
        return false;
    if (config.public_origin && !strcmp(config.public_origin + sizeof("https://") - 1, host))
        return !strcmp(config.public_origin, origin);
    snprintf(expected, sizeof(expected), "%s://%s", lws_is_ssl(wsi) ? "https" : "http", host);
    return !strcmp(expected, origin);
}

static bool secure_session_cookie(struct lws *wsi)
{
    if (lws_is_ssl(wsi))
        return true;
    char host[256];
    return config.public_origin && lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HOST) > 0 &&
        !strcmp(config.public_origin + sizeof("https://") - 1, host);
}

static int begin_form(struct lws *wsi, struct session *session,
                      int (*handler)(struct lws *, struct session *, const struct form *))
{
    char type[80], length[16];
    if (lws_hdr_copy(wsi, type, sizeof(type), WSI_TOKEN_HTTP_CONTENT_TYPE) <= 0 ||
        (strcmp(type, "application/x-www-form-urlencoded") && strcmp(type, "application/x-www-form-urlencoded;charset=UTF-8")))
        return error_reply(wsi, session, 415, "unsupported_content_type");
    if (lws_hdr_copy(wsi, length, sizeof(length), WSI_TOKEN_HTTP_CONTENT_LENGTH) <= 0 ||
        strspn(length, "0123456789") != strlen(length))
        return error_reply(wsi, session, 411, "content_length_required");
    unsigned long size = strtoul(length, NULL, 10);
    if (!size || size > FORM_LIMIT)
        return error_reply(wsi, session, 413, "invalid_form_size");
    session->form = malloc(size + 1);
    if (!session->form)
        return error_reply(wsi, session, 503, "out_of_memory");
    session->finish_form = handler;
    session->form_length = size;
    if (!session->current_token[0])
        session_token(wsi, session->current_token);
    return 0;
}

static int hex_value(unsigned char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    ch = (unsigned char)tolower(ch);
    return ch >= 'a' && ch <= 'f' ? ch - 'a' + 10 : -1;
}

static bool decode_form_value(char *text)
{
    char *put = text;
    while (*text) {
        if (*text == '%') {
            if (!text[1] || !text[2])
                return false;
            int hi = hex_value((unsigned char)text[1]), lo = hex_value((unsigned char)text[2]);
            if (hi < 0 || lo < 0 || !(hi || lo))
                return false;
            *put++ = (char)((hi << 4) | lo);
            text += 3;
        } else {
            *put++ = *text == '+' ? ' ' : *text;
            ++text;
        }
    }
    *put = '\0';
    return true;
}

static const char *form_value(const struct form *form, const char *name)
{
    for (size_t i = 0; i < form->count; ++i)
        if (!strcmp(form->fields[i].name, name))
            return form->fields[i].value;
    return NULL;
}

static bool parse_form(struct session *session, struct form *form)
{
    if (session->form_received != session->form_length || memchr(session->form, 0, session->form_length))
        return false;
    session->form[session->form_length] = '\0';
    for (char *pair = session->form; pair; ) {
        char *next = strchr(pair, '&');
        if (next)
            *next++ = '\0';
        char *value = strchr(pair, '=');
        if (!value || form->count == FORM_FIELDS)
            return false;
        *value++ = '\0';
        if (!decode_form_value(pair) || !*pair || form_value(form, pair) || !decode_form_value(value))
            return false;
        form->fields[form->count].name = pair;
        form->fields[form->count++].value = value;
        pair = next;
    }
    return true;
}

static void discard_form(struct session *session)
{
    if (session->form) {
        OPENSSL_cleanse(session->form, session->form_length + 1);
        free(session->form);
        session->form = NULL;
    }
}

static int reply_identity(struct lws *wsi, struct session *session, const struct panel_auth_identity *identity)
{
    char username[PANEL_AUTH_USERNAME_MAX * 6 + 1];
    char *write = username;
    for (const unsigned char *read = (const unsigned char *)identity->username; *read; ++read) {
        if (*read < 32) {
            snprintf(write, 7, "\\u%04x", (unsigned int)*read);
            write += 6;
        } else {
            if (*read == '"' || *read == '\\')
                *write++ = '\\';
            *write++ = (char)*read;
        }
    }
    *write = '\0';
    char *payload = malloc(sizeof(username) + 100);
    if (!payload)
        return error_reply(wsi, session, 503, "out_of_memory");
    int size = snprintf(payload, sizeof(username) + 100,
        "{\"username\":\"%s\",\"method\":\"session\",\"role\":\"%s\",\"must_change_password\":%s}",
        username, identity->role == PANEL_AUTH_ROLE_ADMIN ? "admin" : "user",
        identity->must_change_password ? "true" : "false");
    if (size < 0 || (size_t)size >= sizeof(username) + 100) {
        free(payload);
        return error_reply(wsi, session, 500, "identity_error");
    }
    session->dashboard_response = payload;
    return reply(wsi, session, 200, "");
}

static int login_form(struct lws *wsi, struct session *session, const struct form *form)
{
    const char *username = form_value(form, "username"), *password = form_value(form, "password");
    const char *code = form_value(form, "code");
    const char *captcha_id = form_value(form, "captcha_id"), *captcha_answer = form_value(form, "captcha_answer");
    if (form->count != (code ? 3U : 2U) + (captcha_id ? 1U : 0U) + (captcha_answer ? 1U : 0U) || !username || !password)
        return error_reply(wsi, session, 400, "invalid_auth_form");
    char ip[PANEL_SECURITY_IP_SIZE];
    if (!request_ip(wsi, ip))
        return error_reply(wsi, session, 403, "unrecognized_peer");
    session->retry_after = panel_security_retry_after(ip);
    if (session->retry_after)
        return error_reply(wsi, session, 429, "too_many_attempts");
    if (panel_security_login_needs_captcha(ip) && !panel_security_captcha_verify(ip, captcha_id, captcha_answer)) {
        if (captcha_id && *captcha_id && captcha_answer && *captcha_answer)
            panel_security_record_login(ip, false);
        return error_reply(wsi, session, 401, "captcha_required");
    }
    struct panel_auth_identity identity;
    enum panel_auth_login_result login = panel_auth_login_checked(username, password, session->cookie,
        panel_security_second_factor, (void *)code);
    if (login == PANEL_AUTH_LOGIN_SECOND_FACTOR && (!code || !*code))
        return error_reply(wsi, session, 401, "second_factor_required");
    panel_security_record_login(ip, login == PANEL_AUTH_LOGIN_SUCCESS);
    if (login != PANEL_AUTH_LOGIN_SUCCESS) {
        audit_actor(0, PANEL_HISTORY_LOGIN, false);
        if (login == PANEL_AUTH_LOGIN_SECOND_FACTOR)
            return error_reply(wsi, session, 401, "second_factor_required");
        return error_reply(wsi, session, 401, "invalid_credentials");
    }
    if (!panel_auth_identify(session->cookie, &identity)) {
        panel_auth_logout(session->cookie);
        session->cookie[0] = '\0';
        return error_reply(wsi, session, 500, "identity_error");
    }
    audit_actor(identity.id, PANEL_HISTORY_LOGIN, true);
    int response = reply_identity(wsi, session, &identity);
    if (session->status != 200) {
        panel_auth_logout(session->cookie);
        OPENSSL_cleanse(session->cookie, sizeof(session->cookie));
    }
    return response;
}

static int password_form(struct lws *wsi, struct session *session, const struct form *form)
{
    const char *old_password = form_value(form, "old_password"), *new_password = form_value(form, "new_password");
    if (form->count != 2 || !old_password || !new_password)
        return error_reply(wsi, session, 400, "invalid_auth_form");
    if (strlen(new_password) < PANEL_AUTH_PASSWORD_MIN)
        return error_reply(wsi, session, 400, "new_password_too_short");
    session->retry_after = panel_auth_retry_after();
    if (session->retry_after)
        return error_reply(wsi, session, 429, "too_many_attempts");
    struct panel_auth_identity identity;
    if (!panel_auth_identify(session->current_token, &identity))
        return error_reply(wsi, session, 401, "unauthorized");
    bool changed = panel_auth_change_password(session->current_token, old_password, new_password);
    audit_actor(identity.id, PANEL_HISTORY_PASSWORD_CHANGE, changed);
    if (!changed)
        return error_reply(wsi, session, 401, "invalid_credentials");
    session->clear_cookie = true;
    return reply(wsi, session, 200, "{\"status\":\"ok\"}");
}

static int auth_request(struct lws *wsi, struct session *session, const char *uri, int method)
{
    const char *route = uri + sizeof("/api/auth/") - 1;
    struct panel_auth_identity identity;
    if (!strcmp(route, "me")) {
        if (method != LWSHUMETH_GET)
            return error_reply(wsi, session, 405, "method_not_allowed");
        if (current_identity(wsi, &identity))
            return reply_identity(wsi, session, &identity);
        if (bearer_authorized(wsi))
            return reply(wsi, session, 200, "{\"username\":\"admin\",\"method\":\"token\",\"role\":\"monitor\"}");
        return error_reply(wsi, session, 401, "unauthorized");
    }
    if (!config.auth_db || (strcmp(route, "login") && strcmp(route, "change-password") && strcmp(route, "logout")))
        return error_reply(wsi, session, 404, "not_found");
    if (method != LWSHUMETH_POST)
        return error_reply(wsi, session, 405, "method_not_allowed");
    if (!same_origin(wsi))
        return error_reply(wsi, session, 403, "unexpected_origin");
    if (!strcmp(route, "logout")) {
        char token[65];
        audit(wsi, PANEL_HISTORY_LOGOUT, true);
        if (session_token(wsi, token))
            panel_auth_logout(token);
        session->clear_cookie = true;
        return reply(wsi, session, 200, "{\"status\":\"ok\"}");
    }
    if (!strcmp(route, "change-password")) {
        if (!session_token(wsi, session->current_token) || !panel_auth_identify(session->current_token, &identity))
            return error_reply(wsi, session, 401, "unauthorized");
        return begin_form(wsi, session, password_form);
    }
    return begin_form(wsi, session, login_form);
}

static bool upload_path(char *out, const struct upload *upload, const char *suffix)
{
    char name[48];
    snprintf(name, sizeof(name), "%s%s", upload->id, suffix);
    return join_path(out, backups, name);
}

static bool backup_id(char out[33])
{
    unsigned char random[16];
    if (RAND_bytes(random, sizeof(random)) != 1)
        return false;
    for (size_t i = 0; i < sizeof(random); ++i)
        snprintf(out + 2 * i, 3, "%02x", (unsigned int)random[i]);
    return true;
}

static bool publish_upload(const char *partial, const char *final)
{
#ifdef _WIN32
    return rename(partial, final) == 0;
#else
    if (link(partial, final) != 0)
        return false;
    (void)unlink(partial);
    return true;
#endif
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

    struct upload *upload = calloc(1, sizeof(*upload));
    if (!upload)
        return error_reply(wsi, session, 503, "out_of_memory");
    char partial[PATH_CAP];
    if (!backup_id(upload->id)) {
        free(upload);
        return error_reply(wsi, session, 500, "random_id_unavailable");
    }
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
        !upload_path(final, upload, ".backup") || !publish_upload(partial, final)) {
        discard_upload(session);
        return error_reply(wsi, session, 500, "cannot_commit_backup");
    }
    uploaded_bytes += upload->received;
    audit(wsi, PANEL_HISTORY_BACKUP_UPLOAD, true);
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

static const char *index_payload(void)
{
    return ui_index ? ui_index : (const char *)dashboard;
}

static size_t index_length(void)
{
    return ui_index ? ui_index_size : sizeof(dashboard);
}

static bool embed_access_path(void)
{
    const char *markers[] = {"name=\"apaz-base\" content=\"", "<base href=\""};
    size_t prefix = strlen(access_path);
    ui_index_size = sizeof(dashboard) + 2 * prefix;
    ui_index = malloc(ui_index_size);
    if (!ui_index)
        return false;
    size_t source = 0, destination = 0;
    for (size_t i = 0; i < sizeof(markers) / sizeof(markers[0]); ++i) {
        size_t marker_size = strlen(markers[i]), position = source;
        while (position + marker_size <= sizeof(dashboard) &&
               memcmp(dashboard + position, markers[i], marker_size))
            ++position;
        if (position + marker_size > sizeof(dashboard)) {
            free(ui_index);
            ui_index = NULL;
            return false;
        }
        position += marker_size;
        memcpy(ui_index + destination, dashboard + source, position - source);
        destination += position - source;
        memcpy(ui_index + destination, access_path, prefix);
        destination += prefix;
        source = position;
    }
    memcpy(ui_index + destination, dashboard + source, sizeof(dashboard) - source);
    return true;
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
    if (!safe_ui_path(uri))
        return error_reply(wsi, session, 404, "not_found");

    if (!ui_root[0]) {
        for (const struct web_asset *asset = web_assets; asset->path; ++asset) {
            if (strcmp(uri, asset->path))
                continue;
            session->asset = asset->data;
            session->asset_size = asset->size;
            session->content_type = asset->type;
            return reply(wsi, session, 200, "");
        }
        if (strcmp(uri, "/") && strcmp(uri, "/index.html") && strcmp(uri, "/login") &&
            strcmp(uri, "/monitoring") && strcmp(uri, "/nodes") && strcmp(uri, "/proxy") &&
            strcmp(uri, "/routing") && strcmp(uri, "/edit-files") && strcmp(uri, "/telegram") &&
            strcmp(uri, "/protocols/antizapret") && strcmp(uri, "/protocols/openvpn") && strcmp(uri, "/antizapret") &&
            strcmp(uri, "/settings") && strncmp(uri, "/settings/", sizeof("/settings/") - 1))
            return error_reply(wsi, session, 404, "not_found");
        session->ui_index = true;
        return reply(wsi, session, 200, "");
    }

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

static int reply_dashboard_metrics(struct lws *wsi, struct session *session)
{
    char *payload = malloc(METRICS_CAP);
    if (!payload)
        return error_reply(wsi, session, 503, "out_of_memory");

    metrics(payload, METRICS_CAP);
    size_t size = strlen(payload) - 1;
    memcpy(payload + size, ",\"host\":", 8);
    size += 8;
    size_t host = panel_settings_enabled("server_monitor") ? host_metrics_json(payload + size, 4096 - size, config.data) : 2;
    if (!panel_settings_enabled("server_monitor"))
        memcpy(payload + size, "{}", 2);
    size += host;
    memcpy(payload + size, ",\"vpn\":", 7);
    size += 7;
    size_t vpn = vpn_statuses_json(payload + size, CONNECTIONS_CAP, config.openvpn, config.openvpn_count);
    size += vpn;
    memcpy(payload + size, ",\"wireguard\":", 13);
    size += 13;
    size_t wireguard = wireguard_status_json(payload + size, METRICS_CAP - size - 1, config.wireguard);
    size += wireguard;
    if (!host || !vpn || !wireguard) {
        free(payload);
        return error_reply(wsi, session, 503, "monitoring_data_unavailable");
    }
    payload[size] = '}';
    payload[size + 1] = '\0';
    session->dashboard_response = payload;
    return reply(wsi, session, 200, "");
}

static int file_download(struct lws *wsi, struct session *session, FILE *file, size_t size)
{
    if (!file)
        return error_reply(wsi, session, 404, "not_found");
    session->profile = file;
    session->profile_size = size;
    return reply(wsi, session, 200, "");
}

static bool admin_authorized(struct lws *wsi)
{
    struct panel_auth_identity identity;
    return config.auth_db ? (current_identity(wsi, &identity) && !identity.must_change_password &&
        identity.role == PANEL_AUTH_ROLE_ADMIN) : bearer_authorized(wsi);
}

static bool require_admin(struct lws *wsi, struct session *session, int method, const char *feature)
{
    struct panel_auth_identity identity;
    if (!current_identity(wsi, &identity))
        error_reply(wsi, session, 401, "unauthorized");
    else if (identity.role != PANEL_AUTH_ROLE_ADMIN || identity.must_change_password)
        error_reply(wsi, session, 403, "forbidden");
    else if (feature && !panel_settings_enabled(feature))
        error_reply(wsi, session, 403, "module_disabled");
    else if (method != LWSHUMETH_GET && method != LWSHUMETH_HEAD && !same_origin(wsi))
        error_reply(wsi, session, 403, "unexpected_origin");
    else {
        if (method == LWSHUMETH_POST || method == LWSHUMETH_PUT || method == LWSHUMETH_PATCH) {
            session_token(wsi, session->current_token);
            session->admin_form = true;
            session->admin_feature = feature;
        }
        return true;
    }
    return false;
}

static bool parse_resource_id(const char *text, int64_t *number, const char **rest)
{
    if (!text || *text < '0' || *text > '9')
        return false;
    char *end;
    errno = 0;
    intmax_t value = strtoimax(text, &end, 10);
    if (errno || value > INT64_MAX || (*end && (!rest || *end != '/')))
        return false;
    *number = (int64_t)value;
    if (rest)
        *rest = end;
    return true;
}

static int allocated_reply(struct lws *wsi, struct session *session, unsigned int status, char *json)
{
    session->dashboard_response = json;
    return reply(wsi, session, status, "");
}

static int file_reply(struct lws *wsi, struct session *session, FILE *file, unsigned int status, const char *type)
{
    if (!file)
        return error_reply(wsi, session, 503, "response_unavailable");
    long size = fseek(file, 0, SEEK_END) ? -1 : ftell(file);
    if (size < 0 || fseek(file, 0, SEEK_SET)) {
        fclose(file);
        return error_reply(wsi, session, 503, "response_unavailable");
    }
    session->profile = file;
    session->profile_size = (size_t)size;
    session->content_type = type;
    return reply(wsi, session, status, "");
}

static int node_error(struct lws *wsi, struct session *session, enum panel_nodes_result result)
{
    switch (result) {
    case PANEL_NODES_INVALID: return error_reply(wsi, session, 400, "invalid_node");
    case PANEL_NODES_MISSING: return error_reply(wsi, session, 404, "node_not_found");
    case PANEL_NODES_CONFLICT: return error_reply(wsi, session, 409, "node_conflict");
    case PANEL_NODES_LIMIT: return error_reply(wsi, session, 409, "node_limit");
    case PANEL_NODES_BUSY: return error_reply(wsi, session, 503, "node_busy");
    default: return error_reply(wsi, session, 503, "nodes_unavailable");
    }
}

static enum panel_nodes_result effective_active_node(int64_t *id, int64_t *revision)
{
    enum panel_nodes_result result = panel_nodes_active(id, revision);
    if (result == PANEL_NODES_OK && !panel_settings_enabled("nodes"))
        *id = 0;
    return result;
}

static int node_active_reply(struct lws *wsi, struct session *session)
{
    int64_t id, revision;
    if (effective_active_node(&id, &revision) != PANEL_NODES_OK)
        return error_reply(wsi, session, 503, "nodes_unavailable");
    char *json = malloc(4096);
    if (!json)
        return error_reply(wsi, session, 503, "out_of_memory");
    enum panel_nodes_result result = panel_nodes_get_json(id, json, 3968);
    if (result != PANEL_NODES_OK) {
        free(json);
        return node_error(wsi, session, result);
    }
    size_t size = strlen(json);
    if (size < 2 || json[size - 1] != '}') {
        free(json);
        return error_reply(wsi, session, 503, "nodes_unavailable");
    }
    snprintf(json + size - 1, 4097 - size, ",\"active_node_id\":%" PRId64 ",\"revision\":%" PRId64 "}", id, revision);
    return allocated_reply(wsi, session, 200, json);
}

static int node_activate_form(struct lws *wsi, struct session *session, const struct form *form)
{
    int64_t revision;
    if (!parse_resource_id(form_value(form, "revision"), &revision, NULL))
        return error_reply(wsi, session, 400, "invalid_revision");
    if (session->resource_id != 0) {
        if (!panel_settings_enabled("nodes"))
            return error_reply(wsi, session, 403, "module_disabled");
        enum panel_ha_node_role role = panel_ha_node_role(session->resource_id);
        if (role == PANEL_HA_REPLICA)
            return error_reply(wsi, session, 409, "replica_is_managed_by_primary");
        if (role == PANEL_HA_LOOKUP_FAILED)
            return error_reply(wsi, session, 503, "ha_unavailable");
    }
    enum panel_nodes_result result = panel_nodes_activate(session->resource_id, revision);
    return result != PANEL_NODES_OK ? node_error(wsi, session, result) : node_active_reply(wsi, session);
}

static int node_save_form(struct lws *wsi, struct session *session, const struct form *form)
{
    struct panel_node_input input = {
        .name = form_value(form, "name"), .endpoint = form_value(form, "endpoint"),
        .kind = form_value(form, "kind"), .transport = form_value(form, "transport"),
        .node_key = form_value(form, "node_key"), .ca_file = form_value(form, "ca_file"),
        .client_cert = form_value(form, "client_cert"), .client_key = form_value(form, "client_key"),
        .linked_vpn_node_id = -1
    };
    const char *linked = form_value(form, "linked_vpn_node_id");
    if (input.kind && !strcmp(input.kind, "proxy") && !panel_settings_enabled("proxy_nodes"))
        return error_reply(wsi, session, 403, "module_disabled");
    if (linked && *linked && strcmp(linked, "-1") && !parse_resource_id(linked, &input.linked_vpn_node_id, NULL))
        return error_reply(wsi, session, 400, "invalid_linked_node");
    if (session->resource_id > 0) {
        enum panel_ha_node_role role = panel_ha_node_role(session->resource_id);
        if (role != PANEL_HA_STANDALONE)
            return error_reply(wsi, session, 409, "node_in_sync_group");
    }
    int64_t id;
    enum panel_nodes_result result = panel_nodes_save(session->resource_id, &input, &id);
    audit(wsi, PANEL_HISTORY_NODE_CHANGE, result == PANEL_NODES_OK);
    if (result != PANEL_NODES_OK)
        return node_error(wsi, session, result);
    snprintf(session->response, sizeof(session->response), "{\"id\":%" PRId64 "}", id);
    return reply(wsi, session, session->resource_id < 0 ? 201 : 200, session->response);
}

static int node_job_begin(struct lws *wsi, struct session *session, enum node_operation operation,
                          const char *destination)
{
    enum panel_nodes_result result = panel_nodes_job_start(session->resource_id, operation, destination, &session->node_job);
    if (result != PANEL_NODES_OK)
        return node_error(wsi, session, result);
    lws_set_timer_usecs(wsi, LWS_US_PER_SEC / 10);
    return 0;
}

static int node_job_poll(struct lws *wsi, struct session *session)
{
    struct node_health_result result;
    const char *data;
    if (!panel_nodes_job_poll(session->node_job, &result, &data)) {
        lws_set_timer_usecs(wsi, LWS_US_PER_SEC / 10);
        return 0;
    }
    const char *body = data ? data : "null";
    size_t capacity = strlen(body) + 160;
    char *json = malloc(capacity);
    if (json)
        snprintf(json, capacity, "{\"state\":\"%s\",\"http_status\":%ld,\"data\":%s}",
                 node_health_state_name(result.state), result.http_status, body);
    panel_nodes_job_release(session->node_job);
    session->node_job = NULL;
    return json ? allocated_reply(wsi, session, 200, json) : error_reply(wsi, session, 503, "out_of_memory");
}

static int node_proxy_form(struct lws *wsi, struct session *session, const struct form *form)
{
    const char *destination = form_value(form, "destination_ip");
    if (!destination || !*destination)
        return error_reply(wsi, session, 400, "invalid_proxy_destination");
    return node_job_begin(wsi, session, NODE_OPERATION_PROXY_DESTINATION, destination);
}

static int nodes_request(struct lws *wsi, struct session *session, const char *uri, int method)
{
    const char *path = uri + sizeof("/api/nodes") - 1;
    if (!strcmp(path, "/active") && method == LWSHUMETH_GET)
        return node_active_reply(wsi, session);
    if (!panel_settings_enabled("nodes") && !panel_settings_enabled("proxy_nodes"))
        return error_reply(wsi, session, 403, "module_disabled");
    if (!*path && method == LWSHUMETH_POST) {
        session->resource_id = -1;
        return begin_form(wsi, session, node_save_form);
    }
    if (*path && !parse_resource_id(path + 1, &session->resource_id, &path))
        return error_reply(wsi, session, 404, "not_found");
    if (!*path && method == LWSHUMETH_GET) {
        char *json = malloc(PANEL_NODES_JSON_LIMIT);
        if (!json)
            return error_reply(wsi, session, 503, "out_of_memory");
        enum panel_nodes_result result = !strcmp(uri, "/api/nodes") ? panel_nodes_list_json(json, PANEL_NODES_JSON_LIMIT) :
            panel_nodes_get_json(session->resource_id, json, PANEL_NODES_JSON_LIMIT);
        if (result == PANEL_NODES_OK)
            return allocated_reply(wsi, session, 200, json);
        free(json);
        return node_error(wsi, session, result);
    }
    if (!*path && !strcmp(uri, "/api/nodes"))
        return error_reply(wsi, session, 405, "method_not_allowed");
    if (!*path && method == LWSHUMETH_PUT)
        return begin_form(wsi, session, node_save_form);
    if (!*path && method == LWSHUMETH_DELETE) {
        if (panel_ha_node_role(session->resource_id) != PANEL_HA_STANDALONE)
            return error_reply(wsi, session, 409, "node_in_sync_group");
        enum panel_nodes_result result = panel_nodes_delete(session->resource_id);
        audit(wsi, PANEL_HISTORY_NODE_CHANGE, result == PANEL_NODES_OK);
        return result != PANEL_NODES_OK ? node_error(wsi, session, result) : reply(wsi, session, 200, "{\"status\":\"ok\"}");
    }
    if (!strcmp(path, "/activate") && method == LWSHUMETH_POST)
        return begin_form(wsi, session, node_activate_form);
    if (!strcmp(path, "/health") && method == LWSHUMETH_POST)
        return node_job_begin(wsi, session, NODE_OPERATION_HEALTH, NULL);
    if (!strncmp(path, "/proxy/", sizeof("/proxy/") - 1) && !panel_settings_enabled("proxy_nodes"))
        return error_reply(wsi, session, 403, "module_disabled");
    if (!strcmp(path, "/proxy/status") && method == LWSHUMETH_GET)
        return node_job_begin(wsi, session, NODE_OPERATION_PROXY_STATUS, NULL);
    if (!strcmp(path, "/proxy/mappings") && method == LWSHUMETH_GET)
        return node_job_begin(wsi, session, NODE_OPERATION_PROXY_MAPPINGS, NULL);
    if (!strcmp(path, "/proxy/destination") && method == LWSHUMETH_PUT)
        return begin_form(wsi, session, node_proxy_form);
    return error_reply(wsi, session, 404, "not_found");
}

static int client_reply(struct lws *wsi, struct session *session, enum panel_client_result result)
{
    unsigned int status = result == PANEL_CLIENT_RUNNING ? 202 : result == PANEL_CLIENT_INVALID ? 400 :
        result == PANEL_CLIENT_CONFLICT ? 409 : 200;
    snprintf(session->response, sizeof(session->response), "{\"status\":\"%s\"}", panel_client_result_name(result));
    return reply(wsi, session, status, session->response);
}

static int client_operation_form(struct lws *wsi, struct session *session, const struct form *form)
{
    int64_t expected, active, revision;
    if (!parse_resource_id(form_value(form, "revision"), &expected, NULL))
        return error_reply(wsi, session, 400, "invalid_revision");
    if (effective_active_node(&active, &revision) != PANEL_NODES_OK)
        return error_reply(wsi, session, 503, "nodes_unavailable");
    if (revision != expected)
        return error_reply(wsi, session, 409, "node_context_changed");
    if (active != 0)
        return client_reply(wsi, session, PANEL_CLIENT_UNAVAILABLE);
    enum panel_client_result result = panel_client_start(config.client_socket, form_value(form, "operation"),
        form_value(form, "name"), form_value(form, "days"));
    audit(wsi, PANEL_HISTORY_CLIENT_CHANGE, result == PANEL_CLIENT_RUNNING);
    return client_reply(wsi, session, result);
}

static int client_request(struct lws *wsi, struct session *session, int method)
{
    if (method == LWSHUMETH_GET)
        return client_reply(wsi, session, panel_client_poll(config.client_socket));
    if (method == LWSHUMETH_POST)
        return begin_form(wsi, session, client_operation_form);
    return error_reply(wsi, session, 405, "method_not_allowed");
}

static int settings_form(struct lws *wsi, struct session *session, const struct form *form)
{
    const char *key = form_value(form, "key"), *enabled = form_value(form, "enabled");
    if (!key || !enabled || (strcmp(enabled, "true") && strcmp(enabled, "false") && strcmp(enabled, "1") && strcmp(enabled, "0")))
        return error_reply(wsi, session, 400, "invalid_feature");
    enum panel_settings_result result = panel_settings_set(key, !strcmp(enabled, "true") || !strcmp(enabled, "1"));
    audit(wsi, PANEL_HISTORY_SETTINGS_CHANGE, result == PANEL_SETTINGS_OK);
    if (result == PANEL_SETTINGS_CONFLICT)
        return error_reply(wsi, session, 409, "feature_conflict");
    if (result == PANEL_SETTINGS_INVALID || result == PANEL_SETTINGS_MISSING)
        return error_reply(wsi, session, 400, "invalid_feature");
    return result == PANEL_SETTINGS_OK ? reply(wsi, session, 200, "{\"status\":\"ok\"}") :
        error_reply(wsi, session, 503, "settings_unavailable");
}

static int settings_request(struct lws *wsi, struct session *session, const char *uri, int method)
{
    const char *path = uri + sizeof("/api/settings/") - 1;
    if (!strcmp(path, "features") && method == LWSHUMETH_POST)
        return begin_form(wsi, session, settings_form);
    if (method != LWSHUMETH_GET)
        return error_reply(wsi, session, 405, "method_not_allowed");
    bool editor = !strcmp(path, "edit-files") || !strncmp(path, "edit-files/", sizeof("edit-files/") - 1);
    if (editor && !panel_settings_enabled("edit_files"))
        return error_reply(wsi, session, 403, "module_disabled");
    if (!strcmp(path, "diagnostics") && !panel_settings_enabled("diagnostics_tests"))
        return error_reply(wsi, session, 403, "module_disabled");
    size_t capacity = editor ? PANEL_EDIT_FILE_JSON_CAP : PANEL_SETTINGS_JSON_CAP;
    char *json = malloc(capacity);
    if (!json)
        return error_reply(wsi, session, 503, "out_of_memory");
    unsigned int status = 503;
    if (!strcmp(path, "features"))
        status = panel_settings_json(json, capacity) ? 200 : 503;
    else if (!strcmp(path, "diagnostics"))
        status = panel_settings_diagnostics_json(!!config.cert, config.profiles, config.config_dir, config.knot_dir, json, capacity) ? 200 : 503;
    else if (!strcmp(path, "edit-files"))
        status = panel_edit_files_json(json, capacity) ? 200 : 503;
    else if (editor) {
        enum panel_settings_result result = panel_edit_file_json(config.config_dir, config.knot_dir,
            path + sizeof("edit-files/") - 1, json, capacity);
        status = result == PANEL_SETTINGS_OK ? 200 : result == PANEL_SETTINGS_TOO_LARGE ? 413 : result == PANEL_SETTINGS_CONFLICT ? 409 :
            result == PANEL_SETTINGS_MISSING || result == PANEL_SETTINGS_INVALID ? 404 : 503;
    } else
        status = 404;
    if (status == 200)
        return allocated_reply(wsi, session, status, json);
    free(json);
    return error_reply(wsi, session, status, status == 404 ? "not_found" : status == 413 ? "config_too_large" : "settings_unavailable");
}

static int history_request(struct lws *wsi, struct session *session, int method)
{
    if (method != LWSHUMETH_GET)
        return error_reply(wsi, session, 405, "method_not_allowed");
    char kind_argument[40], days_argument[24], client_argument[PANEL_HISTORY_CLIENT_MAX + 16];
    const char *kind = lws_get_urlarg_by_name(wsi, "kind=", kind_argument, sizeof(kind_argument));
    const char *days = lws_get_urlarg_by_name(wsi, "days=", days_argument, sizeof(days_argument));
    enum panel_history_kind selected;
    if (!kind || !strcmp(kind, "resources")) selected = PANEL_HISTORY_RESOURCES;
    else if (!strcmp(kind, "connections")) selected = PANEL_HISTORY_CONNECTIONS;
    else if (!strcmp(kind, "traffic")) selected = PANEL_HISTORY_TRAFFIC;
    else if (!strcmp(kind, "audit")) selected = PANEL_HISTORY_AUDIT;
    else return error_reply(wsi, session, 400, "invalid_history_kind");
    const char *feature = selected == PANEL_HISTORY_AUDIT ? "action_logs" : selected == PANEL_HISTORY_TRAFFIC ? "traffic_sync" :
        selected == PANEL_HISTORY_CONNECTIONS ? "connection_history" : "panel_resource_metrics";
    if (!panel_settings_enabled("logs_dashboard") || !panel_settings_enabled(feature))
        return error_reply(wsi, session, 403, "module_disabled");
    int64_t period = selected == PANEL_HISTORY_AUDIT ? 30 : 1;
    if (days && (!parse_resource_id(days, &period, NULL) || (period != 1 && period != 7 && period != 30)))
        return error_reply(wsi, session, 400, "invalid_history_period");
    char *json = malloc(PANEL_HISTORY_JSON_CAP);
    if (!json)
        return error_reply(wsi, session, 503, "out_of_memory");
    const char *client = lws_get_urlarg_by_name(wsi, "client=", client_argument, sizeof(client_argument));
    if (client && (selected != PANEL_HISTORY_TRAFFIC || !*client || strlen(client) > PANEL_HISTORY_CLIENT_MAX)) {
        free(json);
        return error_reply(wsi, session, 400, "invalid_history_client");
    }
    int64_t now = (int64_t)time(NULL);
    size_t size = client ? panel_history_client_json(json, PANEL_HISTORY_JSON_CAP, client, (unsigned int)period, now) :
        panel_history_json(json, PANEL_HISTORY_JSON_CAP, selected, (unsigned int)period, now);
    if (size)
        return allocated_reply(wsi, session, 200, json);
    free(json);
    return error_reply(wsi, session, 503, "history_unavailable");
}

static int cidr_start(struct lws *wsi, struct session *session, const char *action, const char *source,
                      const char *format, size_t budget, FILE *input)
{
    if (!panel_cidr_job_start(cidr_db, action, source, format, budget, input, &session->cidr_job)) {
        if (input)
            fclose(input);
        return error_reply(wsi, session, 503, "routing_busy");
    }
    session->cidr_export = !strcmp(action, "export");
    session->cidr_mutation = !strcmp(action, "import") || !strcmp(action, "publish") || !strcmp(action, "rollback");
    lws_set_timer_usecs(wsi, LWS_US_PER_SEC / 10);
    return 0;
}

static int cidr_poll(struct lws *wsi, struct session *session)
{
    int status;
    FILE *output;
    if (!panel_cidr_job_poll(session->cidr_job, &status, &output)) {
        lws_set_timer_usecs(wsi, LWS_US_PER_SEC / 10);
        return 0;
    }
    panel_cidr_job_release(session->cidr_job);
    session->cidr_job = NULL;
    if (session->cidr_mutation)
        audit(wsi, PANEL_HISTORY_ROUTING_CHANGE, status < 300);
    bool attachment = session->cidr_export && status < 300;
    if (!attachment)
        session->filename[0] = '\0';
    return file_reply(wsi, session, output, (unsigned int)status,
                      attachment ? "text/plain; charset=utf-8" : "application/json");
}

static void cidr_discard_body(struct session *session)
{
    if (!session->cidr_body)
        return;
    if (session->cidr_body->input)
        fclose(session->cidr_body->input);
    free(session->cidr_body);
    session->cidr_body = NULL;
}

static int cidr_receive(struct lws *wsi, struct session *session, const void *data, size_t size)
{
    struct cidr_request_body *body = session->cidr_body;
    if (size > body->expected - body->received || fwrite(data, 1, size, body->input) != size) {
        cidr_discard_body(session);
        return error_reply(wsi, session, 400, "invalid_routing_upload");
    }
    body->received += size;
#ifdef __linux__
    const size_t batch = 1024 * 1024;
    size_t boundary = body->received - body->received % batch;
    if (boundary > body->flushed) {
        int fd = fileno(body->input);
        if (fflush(body->input) || fdatasync(fd)) {
            cidr_discard_body(session);
            return error_reply(wsi, session, 503, "cannot_stage_route_input");
        }
        (void)posix_fadvise(fd, (off_t)body->flushed, (off_t)(boundary - body->flushed), POSIX_FADV_DONTNEED);
        body->flushed = boundary;
    }
#endif
    return 0;
}

static int cidr_finish(struct lws *wsi, struct session *session)
{
    struct cidr_request_body *body = session->cidr_body;
    if (body->expected != body->received || fseek(body->input, 0, SEEK_SET)) {
        cidr_discard_body(session);
        return error_reply(wsi, session, 400, "invalid_routing_upload");
    }
    FILE *input = body->input;
    body->input = NULL;
    int result = cidr_start(wsi, session, "import", body->source, NULL, 0, input);
    cidr_discard_body(session);
    return result;
}

static int cidr_request(struct lws *wsi, struct session *session, const char *uri, int method)
{
    const char *action = uri + sizeof("/api/cidr/") - 1;
    bool import = !strcmp(action, "import"), export = !strcmp(action, "export");
    bool read = export || !strcmp(action, "status");
    if (!read && !import && strcmp(action, "preview") && strcmp(action, "publish") && strcmp(action, "rollback"))
        return error_reply(wsi, session, 404, "not_found");
    if (method != (read ? LWSHUMETH_GET : LWSHUMETH_POST))
        return error_reply(wsi, session, 405, "method_not_allowed");
    char source_buffer[100], format_buffer[40], budget_buffer[32];
    const char *source = lws_get_urlarg_by_name(wsi, "source=", source_buffer, sizeof(source_buffer));
    const char *format = lws_get_urlarg_by_name(wsi, "format=", format_buffer, sizeof(format_buffer));
    const char *text = lws_get_urlarg_by_name(wsi, "budget=", budget_buffer, sizeof(budget_buffer));
    int64_t budget = 0;
    if (text && (!parse_resource_id(text, &budget, NULL) || budget > CIDR_ROUTES_MAX_BUDGET))
        return error_reply(wsi, session, 400, "invalid_route_budget");
    if (export)
        strcpy(session->filename, "antizapret-routes.txt");
    if (!import)
        return cidr_start(wsi, session, action, source, format, (size_t)budget, NULL);
    if (!source || !*source)
        return error_reply(wsi, session, 400, "source_required");
    char length[24], type[80];
    int64_t expected;
    if (lws_hdr_copy(wsi, length, sizeof(length), WSI_TOKEN_HTTP_CONTENT_LENGTH) <= 0 ||
        !parse_resource_id(length, &expected, NULL))
        return error_reply(wsi, session, 411, "content_length_required");
    if (expected < 1 || expected > CIDR_ROUTES_MAX_IMPORT)
        return error_reply(wsi, session, 413, "invalid_route_upload_size");
    if (lws_hdr_copy(wsi, type, sizeof(type), WSI_TOKEN_HTTP_CONTENT_TYPE) <= 0 ||
        (strcmp(type, "text/plain") && strcmp(type, "text/plain;charset=UTF-8") && strcmp(type, "application/octet-stream")))
        return error_reply(wsi, session, 415, "expected_text_or_octet_stream");
    struct cidr_request_body *body = calloc(1, sizeof(*body));
    if (!body)
        return error_reply(wsi, session, 503, "out_of_memory");
    session->cidr_body = body;
#ifdef _WIN32
    body->input = tmpfile();
#else
    char path[PATH_CAP];
    if (join_path(path, config.data, ".cidr-XXXXXX")) {
        int fd = mkstemp(path);
        if (fd >= 0) {
            if (!unlink(path))
                body->input = fdopen(fd, "w+b");
            if (!body->input)
                close(fd);
        }
    }
#endif
    if (!body->input) {
        cidr_discard_body(session);
        return error_reply(wsi, session, 503, "cannot_stage_route_input");
    }
    body->expected = (size_t)expected;
    strcpy(body->source, source);
    return 0;
}

static int portal_request(struct lws *wsi, struct session *session, const char *host, const char *uri, int method)
{
    session->portal = true;
    if (method != LWSHUMETH_GET && method != LWSHUMETH_HEAD)
        return error_reply(wsi, session, 405, "method_not_allowed");
    if (!strncmp(uri, "/p/", 3) && panel_portal_token_valid(uri + 3)) {
        session->asset = portal_page;
        session->asset_size = sizeof(portal_page);
        session->content_type = "text/html; charset=utf-8";
        return reply(wsi, session, 200, "");
    }
    const char base[] = "/api/public/portal/";
    if (strncmp(uri, base, sizeof(base) - 1))
        return error_reply(wsi, session, 404, "not_found");
    if (!panel_portal_allow_request(session->remote_ip)) {
        session->retry_after = 60;
        return error_reply(wsi, session, 429, "too_many_requests");
    }
    const char *value = uri + sizeof(base) - 1;
    const char *tail = strchr(value, '/');
    size_t size = tail ? (size_t)(tail - value) : strlen(value);
    char token[PANEL_PORTAL_TOKEN_MAX + 1];
    if (!size || size >= sizeof(token))
        return error_reply(wsi, session, 404, "not_found");
    memcpy(token, value, size);
    token[size] = '\0';
    if (!panel_portal_token_valid(token))
        return error_reply(wsi, session, 404, "not_found");
    if (!tail) {
        size_t capacity = 64 * 1024;
        char *json = malloc(capacity);
        if (!json)
            return error_reply(wsi, session, 503, "out_of_memory");
        int status = panel_portal_meta(host, token, config.portal_profiles, !!lws_is_ssl(wsi), json, capacity);
        if (status == 200)
            return allocated_reply(wsi, session, (unsigned int)status, json);
        free(json);
        return error_reply(wsi, session, (unsigned int)status, "portal_unavailable");
    }
    if (strcmp(tail, "/download"))
        return error_reply(wsi, session, 404, "not_found");
    char file_id[40], legacy_path[PANEL_PORTAL_PATH_MAX + 16];
    const char *file_arg = lws_get_urlarg_by_name(wsi, "file_id=", file_id, sizeof(file_id));
    const char *legacy_arg = lws_get_urlarg_by_name(wsi, "path=", legacy_path, sizeof(legacy_path));
    FILE *file = NULL;
    size_t length = 0;
    int status = panel_portal_download(host, token, config.portal_profiles, file_arg, legacy_arg,
        &file, session->filename, &length);
    if (status != 200)
        return error_reply(wsi, session, (unsigned int)status, "profile_unavailable");
    return file_download(wsi, session, file, length);
}

#include "http_ha.inc"
#include "http_telegram.inc"
#include "http_security.inc"
#include "http_accounts.inc"
#include "http_protocols.inc"

static int inventory_request(struct lws *wsi, struct session *session, const char *uri, int method, bool profiles)
{
    if (!admin_authorized(wsi))
        return error_reply(wsi, session, 401, "unauthorized");
    if (!profiles && !panel_settings_enabled("backups"))
        return error_reply(wsi, session, 403, "module_disabled");
    if (method == LWSHUMETH_POST && !strcmp(uri, "/api/backups/upload")) {
        if (!same_origin(wsi))
            return error_reply(wsi, session, 403, "unexpected_origin");
        return begin_upload(wsi, session);
    }
    if (method == LWSHUMETH_POST && !strcmp(uri, "/api/backups/create")) {
        char id[33];
        if (!same_origin(wsi))
            return error_reply(wsi, session, 403, "unexpected_origin");
        if (!config.auth_db)
            return error_reply(wsi, session, 503, "backup_source_unavailable");
        bool created = backup_id(id) && panel_backup_create(backups, config.auth_db, id);
        audit(wsi, PANEL_HISTORY_BACKUP_CREATE, created);
        if (!created)
            return error_reply(wsi, session, 500, "backup_create_failed");
        snprintf(session->response, sizeof(session->response), "{\"name\":\"%s.backup\"}", id);
        return reply(wsi, session, 201, session->response);
    }
    if (!profiles && method == LWSHUMETH_DELETE) {
        const char *name = uri + sizeof("/api/backups") - 1;
        if (*name != '/' || !name[1])
            return error_reply(wsi, session, 404, "not_found");
        if (!same_origin(wsi))
            return error_reply(wsi, session, 403, "unexpected_origin");
        enum panel_backup_delete_result result = panel_backup_delete(backups, name + 1);
        audit(wsi, PANEL_HISTORY_BACKUP_DELETE, result == PANEL_BACKUP_DELETED);
        if (result == PANEL_BACKUP_DELETED)
            return reply(wsi, session, 200, "{\"status\":\"ok\"}");
        return result == PANEL_BACKUP_NOT_FOUND ? error_reply(wsi, session, 404, "not_found") :
            error_reply(wsi, session, 503, "backup_delete_failed");
    }
    if (method != LWSHUMETH_GET)
        return error_reply(wsi, session, 405, "method_not_allowed");
    if (profiles) {
        int64_t active, revision;
        if (effective_active_node(&active, &revision) != PANEL_NODES_OK)
            return error_reply(wsi, session, 503, "nodes_unavailable");
        if (active != 0 && strcmp(uri, "/api/profiles"))
            return error_reply(wsi, session, 409, "remote_profiles_unavailable");
        if (active != 0)
            return reply(wsi, session, 200, "{\"state\":\"remote\",\"profiles\":[],\"offset\":0,\"next_offset\":null,\"next_cursor\":null}");
    }

    const char *root = profiles ? "/api/profiles" : "/api/backups";
    const char *rest = uri + strlen(root);
    if (!*rest) {
        char cursor_arg[180], query_arg[180], protocol_arg[48], offset_arg[32];
        const char *cursor = NULL, *query = NULL, *protocol = NULL;
        int64_t offset = 0;
        if (profiles) {
            cursor = lws_get_urlarg_by_name(wsi, "cursor=", cursor_arg, sizeof(cursor_arg));
            query = lws_get_urlarg_by_name(wsi, "query=", query_arg, sizeof(query_arg));
            protocol = lws_get_urlarg_by_name(wsi, "protocol=", protocol_arg, sizeof(protocol_arg));
            const char *text = lws_get_urlarg_by_name(wsi, "offset=", offset_arg, sizeof(offset_arg));
            if (text && (!parse_resource_id(text, &offset, NULL) || (uint64_t)offset > SIZE_MAX))
                return error_reply(wsi, session, 400, "invalid_profile_offset");
        }
        char *payload = malloc(METRICS_CAP);
        if (!payload)
            return error_reply(wsi, session, 503, "out_of_memory");
        size_t size = profiles ? panel_profiles_json_page(payload, METRICS_CAP, config.profiles, (size_t)offset,
            cursor, query, protocol) :
            panel_backups_json(payload, METRICS_CAP, backups);
        if (!size) {
            free(payload);
            return error_reply(wsi, session, 503, "inventory_unavailable");
        }
        session->dashboard_response = payload;
        return reply(wsi, session, 200, "");
    }

    ++rest;
    const char *action = strchr(rest, '/');
    char id[135];
    if (!action || action == rest || (size_t)(action - rest) >= sizeof(id))
        return error_reply(wsi, session, 404, "not_found");
    size_t length = (size_t)(action - rest);
    memcpy(id, rest, length);
    id[length] = '\0';
    if (profiles) {
        if (strcmp(action, "/download"))
            return error_reply(wsi, session, 404, "not_found");
        size_t size = 0;
        FILE *file = panel_profile_open(config.profiles, id, session->filename, &size);
        return file_download(wsi, session, file, size);
    }

    char path[PATH_CAP];
    if (!panel_backup_path(path, sizeof(path), backups, id))
        return error_reply(wsi, session, 404, "not_found");
    if (!strcmp(action, "/inspect")) {
        size_t size = panel_backup_inspect_json(session->response, sizeof(session->response), path);
        return size ? reply(wsi, session, 200, session->response) :
            error_reply(wsi, session, 503, "inspection_unavailable");
    }
    if (strcmp(action, "/download") || strlen(id) >= sizeof(session->filename))
        return error_reply(wsi, session, 404, "not_found");
    struct stat info;
    if (stat(path, &info) || !is_regular(info.st_mode) || info.st_size <= 0 ||
        (unsigned long long)info.st_size > upload_limit)
        return error_reply(wsi, session, 404, "not_found");
    strcpy(session->filename, id);
    return file_download(wsi, session, fopen(path, "rb"), (size_t)info.st_size);
}

static const char *panel_path(const char *uri)
{
    size_t length = strlen(access_path);
    if (strncmp(uri, access_path, length))
        return NULL;
    if (!uri[length])
        return "/";
    return uri[length] == '/' ? uri + length : NULL;
}

static void remember_stream_auth(struct lws *wsi, struct session *session)
{
    session->stream_bearer = bearer_authorized(wsi);
    if (!session->stream_bearer)
        session_token(wsi, session->current_token);
}

static bool stream_authorized(const struct session *session)
{
    struct panel_auth_identity identity;
    return panel_settings_enabled("logs_dashboard") && (session->stream_bearer ||
        (panel_auth_identify(session->current_token, &identity) && !identity.must_change_password &&
         identity.role == PANEL_AUTH_ROLE_ADMIN));
}

static int request(struct lws *wsi, struct session *session)
{
    char *incoming;
    int uri_len;
    int method = lws_http_get_uri_and_method(wsi, &incoming, &uri_len);
    if (method < 0 || uri_len < 1)
        return error_reply(wsi, session, 400, "invalid_request");
    session->head = method == LWSHUMETH_HEAD;
    char host[256];
    if (!request_ip(wsi, session->remote_ip))
        return error_reply(wsi, session, 403, "unrecognized_peer");
    if (config.portal_db && lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HOST) > 0 && panel_portal_host_matches(host))
        return portal_request(wsi, session, host, incoming, method);
    if (!panel_security_ip_allowed(session->remote_ip))
        return error_reply(wsi, session, 403, "ip_not_allowed");
    const char *uri = panel_path(incoming);
    if (!uri)
        return error_reply(wsi, session, 404, "not_found");
    if (!strcmp(uri, "/api/health") && method == LWSHUMETH_GET)
        return reply(wsi, session, 200, "{\"status\":\"ok\"}");
    if (!strncmp(uri, "/api/telegram/", sizeof("/api/telegram/") - 1) || !strcmp(uri, "/api/auth/telegram/config"))
        return panel_settings_enabled("telegram") ? telegram_request(wsi, session, uri, method) :
            error_reply(wsi, session, 404, "not_found");
    if (!strcmp(uri, "/api/auth/captcha") || !strcmp(uri, "/api/auth/totp") ||
        !strncmp(uri, "/api/auth/totp/", sizeof("/api/auth/totp/") - 1))
        return security_request(wsi, session, uri, method);
    if (!strncmp(uri, "/api/auth/", sizeof("/api/auth/") - 1))
        return auth_request(wsi, session, uri, method);
    if (!strcmp(uri, "/api/nodes/sync-groups") || !strncmp(uri, "/api/nodes/sync-groups/", sizeof("/api/nodes/sync-groups/") - 1))
        return require_admin(wsi, session, method, "nodes") ? ha_request(wsi, session, uri, method) : 0;
    if (!strcmp(uri, "/api/nodes") || !strncmp(uri, "/api/nodes/", sizeof("/api/nodes/") - 1))
        return require_admin(wsi, session, method, NULL) ? nodes_request(wsi, session, uri, method) : 0;
    if (!strcmp(uri, "/api/clients/operation"))
        return require_admin(wsi, session, method, NULL) ? client_request(wsi, session, method) : 0;
    if (!strncmp(uri, "/api/settings/", sizeof("/api/settings/") - 1))
        return (!strcmp(uri, "/api/settings/users") || !strncmp(uri, "/api/settings/users/", sizeof("/api/settings/users/") - 1)) ?
            accounts_request(wsi, session, uri, method) :
            require_admin(wsi, session, method, NULL) ? settings_request(wsi, session, uri, method) : 0;
    if (!strncmp(uri, "/api/cidr/", sizeof("/api/cidr/") - 1))
        return require_admin(wsi, session, method, "routing") ? cidr_request(wsi, session, uri, method) : 0;
    if (!strcmp(uri, "/api/protocols/antizapret"))
        return require_admin(wsi, session, method, "antizapret_config") ? protocol_settings_request(wsi, session, method, false) : 0;
    if (!strcmp(uri, "/api/protocols/openvpn"))
        return require_admin(wsi, session, method, "openvpn") ? protocol_settings_request(wsi, session, method, true) : 0;
    if (!strcmp(uri, "/api/monitor/history"))
        return require_admin(wsi, session, method, NULL) ? history_request(wsi, session, method) : 0;
    if (!strcmp(uri, "/api/profiles") || !strncmp(uri, "/api/profiles/", sizeof("/api/profiles/") - 1))
        return inventory_request(wsi, session, uri, method, true);
    if (!strcmp(uri, "/api/backups") || !strncmp(uri, "/api/backups/", sizeof("/api/backups/") - 1))
        return inventory_request(wsi, session, uri, method, false);
    if (!strcmp(uri, "/api/monitor") || !strcmp(uri, "/api/monitor/events")) {
        if (!authorized(wsi))
            return error_reply(wsi, session, 401, "unauthorized");
        if (!panel_settings_enabled("logs_dashboard"))
            return error_reply(wsi, session, 403, "module_disabled");
        if (method != LWSHUMETH_GET)
            return error_reply(wsi, session, 405, "method_not_allowed");
        if (!strcmp(uri, "/api/monitor"))
            return reply_dashboard_metrics(wsi, session);
        if (subscribers >= MAX_STREAMS)
            return error_reply(wsi, session, 503, "too_many_streams");
        remember_stream_auth(wsi, session);
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

static const char *response_payload(const struct session *session)
{
    if (session->ui_index)
        return index_payload();
    if (session->asset)
        return (const char *)session->asset;
    return session->dashboard_response ? session->dashboard_response : session->response;
}

static size_t response_length(const struct session *session)
{
    if (session->profile)
        return session->profile_size;
    if (session->asset)
        return session->asset_size;
    return session->ui_index ? index_length() : strlen(response_payload(session));
}

static int write_headers(struct lws *wsi, const struct session *session)
{
    unsigned char buffer[LWS_PRE + 768];
    unsigned char *start = buffer + LWS_PRE;
    unsigned char *p = start;
    unsigned char *end = buffer + sizeof(buffer);
    unsigned int status = session->subscribed ? 200 : session->status;
    const char *type = session->content_type ? session->content_type : session->ui_index ?
        "text/html; charset=utf-8" : session->profile ? "application/octet-stream" : "application/json";
    lws_filepos_t length = response_length(session);
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
                                    (const unsigned char *)"close", 5, &p, end)))
        return -1;
    if (session->portal && lws_add_http_header_by_name(wsi, (const unsigned char *)"referrer-policy:",
                                    (const unsigned char *)"no-referrer", 11, &p, end))
        return -1;
    if (session->cookie[0] || session->clear_cookie) {
        char cookie[192 + ACCESS_PATH_CAP];
        int size = snprintf(cookie, sizeof(cookie), "apaz_session=%s; Path=%s; Max-Age=%d; HttpOnly; SameSite=Strict%s",
                            session->clear_cookie ? "" : session->cookie, access_path[0] ? access_path : "/",
                            session->clear_cookie ? 0 : 604800,
                            secure_session_cookie(wsi) ? "; Secure" : "");
        if (lws_add_http_header_by_name(wsi, (const unsigned char *)"set-cookie:",
                                       (const unsigned char *)cookie, size, &p, end))
            return -1;
    }
    if (session->retry_after) {
        char delay[16];
        int size = snprintf(delay, sizeof(delay), "%u", session->retry_after);
        if (lws_add_http_header_by_name(wsi, (const unsigned char *)"retry-after:",
                                       (const unsigned char *)delay, size, &p, end))
            return -1;
    }
    if (session->profile && session->filename[0]) {
        char disposition[160];
        int size = snprintf(disposition, sizeof(disposition), "attachment; filename=\"%s\"", session->filename);
        if (lws_add_http_header_by_name(wsi, (const unsigned char *)"content-disposition:",
                                       (const unsigned char *)disposition, size, &p, end))
            return -1;
    }
    return lws_finalize_write_http_header(wsi, start, &p, end) ? -1 : 0;
}

static int write_http(struct lws *wsi, struct session *session)
{
    unsigned char output[LWS_PRE + 4096];
    unsigned char *body = output + LWS_PRE;
    if (session->subscribed && !stream_authorized(session))
        return -1;
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
    size_t remaining = response_length(session) - session->offset;
    size_t capacity = sizeof(output) - LWS_PRE;
    size_t size = remaining < capacity ? remaining : capacity;
    bool last = size == remaining;
    if (session->profile) {
        if (fread(body, 1, size, session->profile) != size)
            return -1;
#ifdef __linux__
        const size_t batch = 1024 * 1024;
        size_t begin = session->offset - session->offset % batch;
        size_t end = session->offset + size;
        end -= end % batch;
        if (end > begin)
            (void)posix_fadvise(fileno(session->profile), (off_t)begin, (off_t)(end - begin), POSIX_FADV_DONTNEED);
#endif
    } else {
        memcpy(body, response_payload(session) + session->offset, size);
    }
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
    discard_form(session);
    cidr_discard_body(session);
    if (session->cidr_job) {
        panel_cidr_job_release(session->cidr_job);
        session->cidr_job = NULL;
    }
    if (session->node_job) {
        panel_nodes_job_release(session->node_job);
        session->node_job = NULL;
    }
    if (session->profile) {
        fclose(session->profile);
        session->profile = NULL;
    }
    free(session->dashboard_response);
    session->dashboard_response = NULL;
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
        if (session->cidr_body)
            return cidr_receive(wsi, session, in, len);
        if (session->form) {
            if (len > session->form_length - session->form_received) {
                discard_form(session);
                return error_reply(wsi, session, 400, "invalid_auth_form");
            }
            memcpy(session->form + session->form_received, in, len);
            session->form_received += len;
            return 0;
        }
        return receive_upload(wsi, session, in, len);
    case LWS_CALLBACK_HTTP_BODY_COMPLETION:
        if ((session->form || session->cidr_body) && session->admin_form &&
            (!admin_authorized(wsi) || (session->admin_feature && !panel_settings_enabled(session->admin_feature)))) {
            discard_form(session);
            cidr_discard_body(session);
            return error_reply(wsi, session, 403, "forbidden");
        }
        if (session->cidr_body)
            return cidr_finish(wsi, session);
        if (session->form) {
            struct form form = {0};
            int status = parse_form(session, &form) ? session->finish_form(wsi, session, &form) :
                error_reply(wsi, session, 400, "invalid_form");
            discard_form(session);
            return status;
        }
        return finish_upload(wsi, session);
    case LWS_CALLBACK_HTTP_WRITEABLE:
        if (session->status || session->subscribed)
            return write_http(wsi, session);
        break;
    case LWS_CALLBACK_HTTP_FILE_COMPLETION:
        return lws_http_transaction_completed(wsi);
    case LWS_CALLBACK_FILTER_PROTOCOL_CONNECTION: {
        char path[64 + ACCESS_PATH_CAP], ip[PANEL_SECURITY_IP_SIZE], host[256];
        unsigned int status = 0;
        const char *route = lws_hdr_copy(wsi, path, sizeof(path), WSI_TOKEN_GET_URI) > 0 ? panel_path(path) : NULL;
        if (!route || strcmp(route, "/api/monitor/ws"))
            status = 404;
        else if (config.portal_db && lws_hdr_copy(wsi, host, sizeof(host), WSI_TOKEN_HOST) > 0 && panel_portal_host_matches(host))
            status = 404;
        else if (!request_ip(wsi, ip) || !panel_security_ip_allowed(ip))
            status = 403;
        else if (!same_origin(wsi))
            status = 403;
        else if (!authorized(wsi))
            status = 401;
        else if (!panel_settings_enabled("logs_dashboard"))
            status = 403;
        else if (subscribers >= MAX_STREAMS)
            status = 503;
        if (status) {
            lws_return_http_status(wsi, status, NULL);
            return 1;
        }
        remember_stream_auth(wsi, session);
        break;
    }
    case LWS_CALLBACK_ESTABLISHED:
        session->subscribed = true;
        ++subscribers;
        lws_callback_on_writable(wsi);
        break;
    case LWS_CALLBACK_SERVER_WRITEABLE: {
        if (!stream_authorized(session))
            return -1;
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
        else if (session->node_job)
            return node_job_poll(wsi, session);
        else if (session->cidr_job)
            return cidr_poll(wsi, session);
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

static void sample_history(lws_sorted_usec_list_t *timer)
{
    if (panel_settings_enabled("logs_dashboard") && (panel_settings_enabled("panel_resource_metrics") ||
        panel_settings_enabled("traffic_sync") || panel_settings_enabled("connection_history")))
        panel_history_sample(config.data, config.openvpn, config.openvpn_count, config.wireguard, (int64_t)time(NULL));
    lws_sul_schedule(server_context, 0, timer, sample_history, 60 * LWS_US_PER_SEC);
}

static bool reconcile_native_factors(void *context)
{
    char path[PATH_CAP];
    return join_path(path, config.data, "lws-security.db") &&
        panel_security_reconcile_native_factors(path, getenv("APAZ_SECURITY_KEY"), panel_auth_reconcile_native_factor, context);
}

static bool open_modules(void)
{
    char path[PATH_CAP];
    if (!join_path(cidr_db, config.data, "lws-cidr.db") || !join_path(path, config.data, "lws-security.db") ||
        !panel_security_configure(getenv("APAZ_IP_ALLOWLIST"), getenv("APAZ_TRUSTED_PROXY_IPS")) ||
        !panel_security_open(path, getenv("APAZ_SECURITY_KEY"))) {
        fputs("Cannot initialize panel login security.\n", stderr);
        return false;
    }
    if (!panel_history_open(config.data) || !panel_settings_open(config.data) || !panel_nodes_open(config.data) ||
        !join_path(path, config.data, "lws-ha.db") || !panel_ha_open(path) ||
        !join_path(path, config.data, "lws-telegram.db") || !panel_telegram_open(path)) {
        fputs("Cannot initialize panel data.\n", stderr);
        return false;
    }
    if (config.portal_db && (!directory_exists(config.portal_profiles) || !panel_portal_open(config.portal_db))) {
        fputs("Cannot open portal snapshot and profile directory.\n", stderr);
        return false;
    }
    return true;
}

static void close_modules(void)
{
    panel_cidr_job_close();
    panel_portal_close();
    panel_telegram_close();
    panel_ha_close();
    panel_nodes_close();
    panel_settings_close();
    panel_history_close();
    panel_security_close();
}

static void usage(void)
{
    puts("adminpanelaz-lws [--bind IP] [--port N] [--ui-dir PATH] [--data-dir PATH]\n"
         "                 [--access-path /prefix]\n"
         "                 [--auth-db PATH] [--profiles-dir PATH]\n"
         "                 [--client-socket PATH] [--config-dir PATH] [--knot-dir PATH]\n"
         "                 [--antizapret-setup PATH]\n"
         "                 [--public-origin https://HOST[:PORT]]\n"
         "                 [--portal-db PATH --portal-profiles-dir PATH]\n"
         "                 [--openvpn-status PATH ...] [--wireguard-status PATH]\n"
         "                 [--tls-cert PEM --tls-key PEM]\n"
         "Set APAZ_AUTH_TOKEN to a random token of 32 to 128 URL-safe ASCII characters.");
}

static bool set_access_path(const char *value)
{
    size_t length = strlen(value);
    if (!strcmp(value, "/")) {
        access_path[0] = '\0';
        return true;
    }
    if (length < 2 || length >= sizeof(access_path) || value[0] != '/' || value[length - 1] == '/' ||
        strstr(value, "//") || strspn(value, "/abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") != length)
        return false;
    memcpy(access_path, value, length + 1);
    return true;
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
        } else if (!strcmp(option, "--access-path")) {
            if (!set_access_path(value))
                return false;
        } else if (!strcmp(option, "--data-dir")) {
            config.data = value;
        } else if (!strcmp(option, "--auth-db")) {
            config.auth_db = value;
        } else if (!strcmp(option, "--profiles-dir")) {
            config.profiles = value;
        } else if (!strcmp(option, "--client-socket")) {
            config.client_socket = value;
        } else if (!strcmp(option, "--config-dir")) {
            config.config_dir = value;
        } else if (!strcmp(option, "--knot-dir")) {
            config.knot_dir = value;
        } else if (!strcmp(option, "--antizapret-setup")) {
            config.antizapret_setup = value;
        } else if (!strcmp(option, "--public-origin")) {
            if (strncmp(value, "https://", sizeof("https://") - 1))
                return false;
            const char *host = value + sizeof("https://") - 1;
            size_t length = strlen(host);
            if (!length || length >= 250 || strspn(host, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-.:") != length)
                return false;
            const char *port = strchr(host, ':');
            int64_t port_number;
            if (port && (port == host || !parse_resource_id(port + 1, &port_number, NULL) || port_number < 1 || port_number > 65535))
                return false;
            config.public_origin = value;
        } else if (!strcmp(option, "--portal-db")) {
            config.portal_db = value;
        } else if (!strcmp(option, "--portal-profiles-dir")) {
            config.portal_profiles = value;
        } else if (!strcmp(option, "--openvpn-status")) {
            if (config.openvpn_count == MAX_OPENVPN_PATHS)
                return false;
            config.openvpn[config.openvpn_count++] = value;
        } else if (!strcmp(option, "--wireguard-status")) {
            config.wireguard = value;
        } else if (!strcmp(option, "--tls-cert")) {
            config.cert = value;
        } else if (!strcmp(option, "--tls-key")) {
            config.key = value;
        } else {
            return false;
        }
    }
    return (!!config.cert == !!config.key) && (config.cert || !strcmp(config.bind, "127.0.0.1")) &&
        (!access_path[0] || !config.ui) && (!!config.portal_db == !!config.portal_profiles);
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
#ifndef _WIN32
    umask(0077);
#endif
    if (!config.client_socket)
        config.client_socket = getenv("APAZ_CLIENT_SOCKET");
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
    if (access_path[0] && !embed_access_path()) {
        fputs("Cannot initialize the embedded panel access path.\n", stderr);
        return 2;
    }
    if (!ensure_directory(config.data) || !join_path(backups, config.data, "backups") || !ensure_directory(backups)) {
        fputs("Cannot create backup directory.\n", stderr);
        free(ui_index);
        return 2;
    }
    if (config.auth_db && !panel_auth_open_with_reconciliation(config.auth_db, config.token, reconcile_native_factors, NULL)) {
        fputs("Cannot open panel auth database.\n", stderr);
        free(ui_index);
        return 2;
    }
    if (!open_modules()) {
        close_modules();
        panel_auth_close();
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
    server_context = lws_create_context(&info);
    if (!server_context) {
        close_modules();
        panel_auth_close();
        free(ui_index);
        return 1;
    }
    lws_sul_schedule(server_context, 0, &history_timer, sample_history, LWS_US_PER_SEC);
    int status = 0;
    while (!stopping && status >= 0)
        status = lws_service(server_context, 0);
    lws_sul_cancel(&history_timer);
    lws_context_destroy(server_context);
    close_modules();
    panel_auth_close();
    free(ui_index);
    return status < 0 && !stopping ? 1 : 0;
}
