#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "node_transport.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#define inet_pton InetPtonA
#else
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <curl/curl.h>

#include <stddef.h>
#include <stdio.h>
#include <string.h>

enum {
    ENDPOINT_LIMIT = 2048,
    NODE_KEY_LIMIT = 512,
    TLS_PATH_LIMIT = 4096,
    BODY_LIMIT = 16 * 1024,
    MAX_BODY_LIMIT = 64 * 1024,
    HEADER_LIMIT = 16 * 1024,
    JSON_DEPTH_LIMIT = 32,
    CONNECT_TIMEOUT_MS = 2000,
    REQUEST_TIMEOUT_MS = 5000
};

static const struct agent_route {
    const char *path;
    long timeout_ms;
} routes[] = {
    [NODE_OPERATION_HEALTH] = { "/health", REQUEST_TIMEOUT_MS },
    [NODE_OPERATION_PROXY_STATUS] = { "/proxy/status", 35000 },
    [NODE_OPERATION_PROXY_DESTINATION] = { "/proxy/destination", 75000 },
    [NODE_OPERATION_PROXY_MAPPINGS] = { "/proxy/mappings", 20000 }
};

struct response_limit {
    size_t received;
    size_t limit;
    char *data;
    bool exceeded;
};

struct json_reader {
    const unsigned char *next;
    const unsigned char *end;
};

bool node_transport_init(void)
{
    if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK)
        return false;
    const curl_version_info_data *version = curl_version_info(CURLVERSION_NOW);
    if (version && (version->features & CURL_VERSION_ASYNCHDNS))
        return true;

    curl_global_cleanup();
    return false;
}

void node_transport_cleanup(void)
{
    curl_global_cleanup();
}

static bool visible_ascii(const char *text, size_t limit)
{
    if (!text || !text[0])
        return false;
    size_t i = 0;
    for (; text[i] && i < limit; ++i) {
        unsigned char value = (unsigned char)text[i];
        if (value <= 0x20 || value >= 0x7f)
            return false;
    }
    return text[i] == '\0';
}

static bool valid_tls_path(const char *path)
{
    if (!path)
        return true;
    if (!path[0])
        return false;
    size_t i = 0;
    for (; path[i] && i < TLS_PATH_LIMIT; ++i) {
        unsigned char value = (unsigned char)path[i];
        if (value < 0x20 || value == 0x7f)
            return false;
    }
    return path[i] == '\0';
}

static bool valid_config(const struct node_transport_config *config)
{
    return config && visible_ascii(config->node_key, NODE_KEY_LIMIT) &&
           valid_tls_path(config->ca_file) && valid_tls_path(config->client_cert) && valid_tls_path(config->client_key) &&
           !!config->client_cert == !!config->client_key;
}

static bool public_ipv4(const unsigned char *ip)
{
    unsigned int first = ip[0], second = ip[1], third = ip[2];
    switch (first) {
    case 0:
    case 10:
    case 127:
        return false;
    case 100:
        return second < 64 || second >= 128;
    case 169:
        return second != 254;
    case 172:
        return second < 16 || second >= 32;
    case 192:
        if (second == 0 && third == 0)
            return ip[3] == 9 || ip[3] == 10;
        return second != 168 && !(second == 0 && third == 2) && !(second == 88 && third == 99);
    case 198:
        return second != 18 && second != 19 && !(second == 51 && third == 100);
    case 203:
        return second != 0 || third != 113;
    default:
        return first < 224;
    }
}

static bool public_ipv6(const unsigned char *ip)
{
    static const unsigned char mapped_prefix[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 255, 255};
    if (!memcmp(ip, mapped_prefix, sizeof(mapped_prefix)))
        return public_ipv4(ip + sizeof(mapped_prefix));
    if ((ip[0] & 0xe0) != 0x20 || (ip[0] == 0x20 && ip[1] == 0x02))
        return false;
    if (ip[0] == 0x20 && ip[1] == 0x01 && (ip[2] < 2 || (ip[2] == 0x0d && ip[3] == 0xb8)))
        return false;
    return ip[0] != 0x3f || ip[1] != 0xff || (ip[2] & 0xf0) != 0;
}

static bool public_hostname(char *host)
{
    size_t length = strlen(host);
    unsigned char address[16];
    if (!length)
        return false;
    if (host[0] == '[' && host[length - 1] == ']') {
        host[length - 1] = '\0';
        return inet_pton(AF_INET6, host + 1, address) == 1 && public_ipv6(address);
    }
    if (inet_pton(AF_INET, host, address) == 1)
        return public_ipv4(address);
    if (host[length - 1] == '.')
        host[--length] = '\0';
    for (size_t i = 0; i < length; ++i)
        if (host[i] >= 'A' && host[i] <= 'Z')
            host[i] += 'a' - 'A';
    size_t suffix = sizeof(".localhost") - 1;
    return length && strcmp(host, "localhost") &&
           (length < suffix || strcmp(host + length - suffix, ".localhost"));
}

static bool configure_url(CURLU *url, const struct node_transport_config *config, const char *route)
{
    if (!visible_ascii(config->endpoint, ENDPOINT_LIMIT) || strpbrk(config->endpoint, "?#\\"))
        return false;
    const char *separator = strstr(config->endpoint, "://");
    if (!separator || !separator[3] || separator[3] == '/' ||
        curl_url_set(url, CURLUPART_URL, config->endpoint, CURLU_DISALLOW_USER | CURLU_PATH_AS_IS) != CURLUE_OK)
        return false;

    char *scheme = NULL;
    char *path = NULL;
    char *host = NULL;
    bool valid = curl_url_get(url, CURLUPART_SCHEME, &scheme, 0) == CURLUE_OK &&
                 curl_url_get(url, CURLUPART_PATH, &path, 0) == CURLUE_OK && !strcmp(path, "/");
    if (valid) {
        bool tls = config->ca_file || config->client_cert || config->client_key;
        valid = (!strcmp(scheme, "https") || (!strcmp(scheme, "http") && !tls)) &&
                curl_url_set(url, CURLUPART_PATH, route, 0) == CURLUE_OK;
    }
    if (valid && config->deny_internal)
        valid = curl_url_get(url, CURLUPART_HOST, &host, 0) == CURLUE_OK && public_hostname(host);
    curl_free(scheme);
    curl_free(path);
    curl_free(host);
    return valid;
}

bool node_transport_validate(const struct node_transport_config *config)
{
    CURLU *url = valid_config(config) ? curl_url() : NULL;
    bool valid = url && configure_url(url, config, routes[NODE_OPERATION_HEALTH].path);
    if (url)
        curl_url_cleanup(url);
    return valid;
}

const char *node_health_state_name(enum node_health_state state)
{
    switch (state) {
    case NODE_HEALTH_AVAILABLE: return "available";
    case NODE_HEALTH_INVALID_CONFIG: return "invalid_config";
    case NODE_HEALTH_AUTH_FAILED: return "auth_failed";
    case NODE_HEALTH_TIMEOUT: return "timeout";
    case NODE_HEALTH_TLS_FAILED: return "tls_failed";
    case NODE_HEALTH_RESPONSE_TOO_LARGE: return "response_too_large";
    case NODE_HEALTH_UNEXPECTED_RESPONSE: return "unexpected_response";
    case NODE_HEALTH_UNAVAILABLE: return "unavailable";
    case NODE_HEALTH_UNKNOWN: return "unknown";
    }
    return "unavailable";
}

bool node_transport_valid_proxy_destination(const char *destination)
{
    if (!destination)
        return false;
    unsigned int first = 0;
    bool nonzero = false;
    for (unsigned int octet = 0; octet < 4; ++octet) {
        unsigned int value = 0, length = 0;
        if (*destination == '0' && destination[1] >= '0' && destination[1] <= '9')
            return false;
        while (*destination >= '0' && *destination <= '9' && length < 3) {
            value = value * 10 + (unsigned int)(*destination++ - '0');
            ++length;
        }
        if (!length || value > 255 || *destination != (octet == 3 ? '\0' : '.'))
            return false;
        if (!octet)
            first = value;
        nonzero = nonzero || value != 0;
        ++destination;
    }
    return nonzero && first != 127 && (first < 224 || first > 239);
}

static size_t count_response(char *data, size_t size, size_t count, void *context)
{
    struct response_limit *response = context;
    if (size && count > (response->limit - response->received) / size) {
        response->exceeded = true;
        return 0;
    }
    size_t length = size * count;
    if (length && response->data)
        memcpy(response->data + response->received, data, length);
    response->received += length;
    return length;
}

static int transfer_progress(void *context, curl_off_t download_total, curl_off_t download_now,
    curl_off_t upload_total, curl_off_t upload_now)
{
    (void)download_total;
    (void)download_now;
    (void)upload_total;
    (void)upload_now;
    const struct node_transport_config *config = context;
    return config->should_cancel(config->cancel_context);
}

static curl_socket_t open_public_socket(void *context, curlsocktype purpose, struct curl_sockaddr *address)
{
    (void)context;
    if (purpose != CURLSOCKTYPE_IPCXN)
        return CURL_SOCKET_BAD;
    const void *remote = &address->addr;
    bool allowed = false;
    if (address->family == AF_INET && address->addrlen >= sizeof(struct sockaddr_in)) {
        struct sockaddr_in addr;
        memcpy(&addr, remote, sizeof(addr));
        allowed = public_ipv4((const unsigned char *)&addr.sin_addr);
    } else if (address->family == AF_INET6 && address->addrlen >= sizeof(struct sockaddr_in6)) {
        struct sockaddr_in6 addr;
        memcpy(&addr, remote, sizeof(addr));
        allowed = public_ipv6((const unsigned char *)&addr.sin6_addr);
    }
    if (!allowed)
        return CURL_SOCKET_BAD;
#ifdef _WIN32
    return WSASocketW(address->family, address->socktype, address->protocol, NULL, 0,
                      WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
#else
    curl_socket_t fd = socket(address->family, address->socktype, address->protocol);
    if (fd != CURL_SOCKET_BAD && fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
        close(fd);
        return CURL_SOCKET_BAD;
    }
    return fd;
#endif
}

static bool configure_transfer(CURL *easy, CURLU *url, const struct curl_slist *headers,
                               struct response_limit *body, struct response_limit *header,
                               const struct node_transport_config *config,
                               const struct agent_route *route, const char *payload)
{
    return curl_easy_setopt(easy, CURLOPT_CURLU, url) == CURLE_OK &&
#if LIBCURL_VERSION_NUM >= 0x075500
           curl_easy_setopt(easy, CURLOPT_PROTOCOLS_STR, "http,https") == CURLE_OK &&
#else
           curl_easy_setopt(easy, CURLOPT_PROTOCOLS, (long)(CURLPROTO_HTTP | CURLPROTO_HTTPS)) == CURLE_OK &&
#endif
           (payload ? (curl_easy_setopt(easy, CURLOPT_CUSTOMREQUEST, "PUT") == CURLE_OK &&
                       curl_easy_setopt(easy, CURLOPT_POSTFIELDS, payload) == CURLE_OK &&
                       curl_easy_setopt(easy, CURLOPT_POSTFIELDSIZE, (long)strlen(payload)) == CURLE_OK)
                    : curl_easy_setopt(easy, CURLOPT_HTTPGET, 1L) == CURLE_OK) &&
           curl_easy_setopt(easy, CURLOPT_HTTPHEADER, headers) == CURLE_OK &&
           curl_easy_setopt(easy, CURLOPT_PROXY, "") == CURLE_OK &&
           curl_easy_setopt(easy, CURLOPT_FOLLOWLOCATION, 0L) == CURLE_OK &&
           curl_easy_setopt(easy, CURLOPT_NOSIGNAL, 1L) == CURLE_OK &&
           curl_easy_setopt(easy, CURLOPT_CONNECTTIMEOUT_MS, (long)CONNECT_TIMEOUT_MS) == CURLE_OK &&
           curl_easy_setopt(easy, CURLOPT_TIMEOUT_MS, route->timeout_ms) == CURLE_OK &&
           curl_easy_setopt(easy, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)body->limit) == CURLE_OK &&
           curl_easy_setopt(easy, CURLOPT_WRITEFUNCTION, count_response) == CURLE_OK &&
           curl_easy_setopt(easy, CURLOPT_WRITEDATA, body) == CURLE_OK &&
           curl_easy_setopt(easy, CURLOPT_HEADERFUNCTION, count_response) == CURLE_OK &&
           curl_easy_setopt(easy, CURLOPT_HEADERDATA, header) == CURLE_OK &&
           curl_easy_setopt(easy, CURLOPT_SSL_VERIFYPEER, 1L) == CURLE_OK &&
           curl_easy_setopt(easy, CURLOPT_SSL_VERIFYHOST, 2L) == CURLE_OK &&
           (!config->deny_internal || curl_easy_setopt(easy, CURLOPT_OPENSOCKETFUNCTION, open_public_socket) == CURLE_OK) &&
           (!config->should_cancel ||
            (curl_easy_setopt(easy, CURLOPT_NOPROGRESS, 0L) == CURLE_OK &&
             curl_easy_setopt(easy, CURLOPT_XFERINFOFUNCTION, transfer_progress) == CURLE_OK &&
             curl_easy_setopt(easy, CURLOPT_XFERINFODATA, config) == CURLE_OK)) &&
           (!config->ca_file || curl_easy_setopt(easy, CURLOPT_CAINFO, config->ca_file) == CURLE_OK) &&
           (!config->client_cert ||
            (curl_easy_setopt(easy, CURLOPT_SSLCERTTYPE, "PEM") == CURLE_OK &&
             curl_easy_setopt(easy, CURLOPT_SSLKEYTYPE, "PEM") == CURLE_OK &&
             curl_easy_setopt(easy, CURLOPT_SSLCERT, config->client_cert) == CURLE_OK &&
             curl_easy_setopt(easy, CURLOPT_SSLKEY, config->client_key) == CURLE_OK));
}

static bool json_content_type(const char *type)
{
    if (!type)
        return false;
    static const char expected[] = "application/json";
    for (size_t i = 0; i < sizeof(expected) - 1; ++i) {
        char value = *type++;
        if (value >= 'A' && value <= 'Z')
            value += 'a' - 'A';
        if (value != expected[i])
            return false;
    }
    while (*type == ' ' || *type == '\t')
        ++type;
    return !*type || *type == ';';
}

static void skip_whitespace(struct json_reader *json)
{
    while (json->next < json->end) {
        unsigned char byte = *json->next;
        if (byte != ' ' && byte != '\t' && byte != '\n' && byte != '\r')
            break;
        ++json->next;
    }
}

static bool consume(struct json_reader *json, unsigned char token)
{
    if (json->next == json->end || *json->next != token)
        return false;
    ++json->next;
    return true;
}

static bool consume_hex(struct json_reader *json)
{
    for (unsigned int i = 0; i < 4; ++i) {
        if (json->next == json->end)
            return false;
        unsigned char byte = *json->next++;
        if ((byte < '0' || byte > '9') && (byte < 'a' || byte > 'f') && (byte < 'A' || byte > 'F'))
            return false;
    }
    return true;
}

static bool consume_utf8(struct json_reader *json, unsigned char lead)
{
    if (lead < 0xc2 || lead > 0xf4)
        return false;
    size_t tail = lead < 0xe0 ? 1 : (lead < 0xf0 ? 2 : 3);
    if ((size_t)(json->end - json->next) < tail)
        return false;
    unsigned char first = *json->next;
    if ((lead == 0xe0 && first < 0xa0) || (lead == 0xed && first >= 0xa0) ||
        (lead == 0xf0 && first < 0x90) || (lead == 0xf4 && first >= 0x90))
        return false;
    for (size_t i = 0; i < tail; ++i) {
        unsigned char byte = *json->next++;
        if (byte < 0x80 || byte > 0xbf)
            return false;
    }
    return true;
}

static bool consume_string(struct json_reader *json)
{
    if (!consume(json, '"'))
        return false;
    while (json->next < json->end) {
        unsigned char byte = *json->next++;
        if (byte == '"')
            return true;
        if (byte < 0x20 || (byte >= 0x80 && !consume_utf8(json, byte)))
            return false;
        if (byte == '\\') {
            if (json->next == json->end)
                return false;
            unsigned char escape = *json->next++;
            if (escape == 'u' ? !consume_hex(json) : (!escape || !strchr("\"\\/bfnrt", escape)))
                return false;
        }
    }
    return false;
}

static bool consume_digits(struct json_reader *json)
{
    const unsigned char *start = json->next;
    while (json->next < json->end && *json->next >= '0' && *json->next <= '9')
        ++json->next;
    return json->next > start;
}

static bool consume_number(struct json_reader *json)
{
    consume(json, '-');
    if (!(consume(json, '0') || consume_digits(json)) || (consume(json, '.') && !consume_digits(json)))
        return false;
    if (consume(json, 'e') || consume(json, 'E')) {
        if (!consume(json, '+'))
            consume(json, '-');
        return consume_digits(json);
    }
    return true;
}

static bool consume_value(struct json_reader *json, unsigned int depth);

static bool consume_collection(struct json_reader *json, unsigned char close, unsigned int depth)
{
    if (depth == JSON_DEPTH_LIMIT)
        return false;
    skip_whitespace(json);
    if (consume(json, close))
        return true;
    for (;;) {
        skip_whitespace(json);
        if (close == '}') {
            if (!consume_string(json))
                return false;
            skip_whitespace(json);
            if (!consume(json, ':'))
                return false;
        }
        if (!consume_value(json, depth + 1))
            return false;
        skip_whitespace(json);
        if (consume(json, close))
            return true;
        if (!consume(json, ','))
            return false;
    }
}

static bool consume_keyword(struct json_reader *json, const char *name, size_t length)
{
    if ((size_t)(json->end - json->next) < length || memcmp(json->next, name, length))
        return false;
    json->next += length;
    return true;
}

static bool consume_value(struct json_reader *json, unsigned int depth)
{
    skip_whitespace(json);
    if (json->next == json->end)
        return false;
    switch (*json->next) {
    case '{':
        ++json->next;
        return consume_collection(json, '}', depth);
    case '[':
        ++json->next;
        return consume_collection(json, ']', depth);
    case '"':
        return consume_string(json);
    case 't':
        return consume_keyword(json, "true", sizeof("true") - 1);
    case 'f':
        return consume_keyword(json, "false", sizeof("false") - 1);
    case 'n':
        return consume_keyword(json, "null", sizeof("null") - 1);
    default:
        return consume_number(json);
    }
}

static bool is_json_object(const struct response_limit *body)
{
    const unsigned char *start = (const unsigned char *)body->data;
    struct json_reader json = { .next = start, .end = start + body->received };
    skip_whitespace(&json);
    if (!consume(&json, '{') || !consume_collection(&json, '}', 0))
        return false;
    skip_whitespace(&json);
    return json.next == json.end;
}

static enum node_health_state classify(const struct node_health_result *result, CURLcode transfer,
                                       const struct response_limit *body, const struct response_limit *header,
                                       const char *content_type)
{
    if (body->exceeded || header->exceeded || transfer == CURLE_FILESIZE_EXCEEDED)
        return NODE_HEALTH_RESPONSE_TOO_LARGE;
    if (transfer == CURLE_OPERATION_TIMEDOUT)
        return NODE_HEALTH_TIMEOUT;
    if (transfer == CURLE_BAD_FUNCTION_ARGUMENT)
        return NODE_HEALTH_INVALID_CONFIG;
#if LIBCURL_VERSION_NUM >= 0x074d00
    if (transfer == CURLE_SSL_CLIENTCERT)
        return NODE_HEALTH_TLS_FAILED;
#endif
    if (transfer == CURLE_PEER_FAILED_VERIFICATION || transfer == CURLE_SSL_CONNECT_ERROR ||
        transfer == CURLE_SSL_CERTPROBLEM || transfer == CURLE_SSL_CACERT_BADFILE ||
        transfer == CURLE_SSL_ISSUER_ERROR || transfer == CURLE_SSL_CIPHER || transfer == CURLE_SSL_CRL_BADFILE)
        return NODE_HEALTH_TLS_FAILED;
    if (transfer != CURLE_OK)
        return NODE_HEALTH_UNAVAILABLE;
    if (result->http_status == 401 || result->http_status == 403)
        return NODE_HEALTH_AUTH_FAILED;
    if (result->http_status == 200 && json_content_type(content_type) && is_json_object(body))
        return NODE_HEALTH_AVAILABLE;
    return NODE_HEALTH_UNEXPECTED_RESPONSE;
}

static void erase(char *text, size_t length)
{
    volatile char *cursor = text;
    while (length--)
        *cursor++ = '\0';
}

struct node_health_result node_transport_request(const struct node_transport_config *config,
    enum node_operation operation, const char *destination, char *response, size_t capacity)
{
    struct node_health_result result = { .state = NODE_HEALTH_INVALID_CONFIG };
    if (!response || capacity < 2)
        return result;
    response[0] = '\0';
    if (!valid_config(config) || (unsigned int)operation >= sizeof(routes) / sizeof(routes[0]))
        return result;

    char payload[sizeof("{\"destination_ip\":\"255.255.255.255\"}")];
    const char *request_payload = NULL;
    if (operation == NODE_OPERATION_PROXY_DESTINATION) {
        if (!node_transport_valid_proxy_destination(destination))
            return result;
        snprintf(payload, sizeof(payload), "{\"destination_ip\":\"%s\"}", destination);
        request_payload = payload;
    }

    const struct agent_route *route = &routes[operation];
    CURLU *url = curl_url();
    if (!url) {
        result.state = NODE_HEALTH_UNAVAILABLE;
        return result;
    }
    if (!configure_url(url, config, route->path)) {
        curl_url_cleanup(url);
        return result;
    }

    char authorization[sizeof("X-Node-Key: ") + NODE_KEY_LIMIT] = "X-Node-Key: ";
    memcpy(authorization + sizeof("X-Node-Key: ") - 1, config->node_key, strlen(config->node_key) + 1);
    struct curl_slist *headers = curl_slist_append(NULL, authorization);
    erase(authorization, sizeof(authorization));
    struct curl_slist *complete_headers = headers;
    if (headers && request_payload)
        complete_headers = curl_slist_append(headers, "Content-Type: application/json");
    CURL *easy = complete_headers ? curl_easy_init() : NULL;
    size_t limit = operation == NODE_OPERATION_PROXY_MAPPINGS ? MAX_BODY_LIMIT : BODY_LIMIT;
    if (limit >= capacity)
        limit = capacity - 1;
    struct response_limit body = { .limit = limit, .data = response };
    struct response_limit header = { .limit = HEADER_LIMIT };
    result.state = NODE_HEALTH_UNAVAILABLE;
    bool preserve = false;
    if (easy && configure_transfer(easy, url, headers, &body, &header, config, route, request_payload)) {
        CURLcode transfer = curl_easy_perform(easy);
        char *content_type = NULL;
        curl_easy_getinfo(easy, CURLINFO_RESPONSE_CODE, &result.http_status);
        curl_easy_getinfo(easy, CURLINFO_CONTENT_TYPE, &content_type);
        result.state = classify(&result, transfer, &body, &header, content_type);
        preserve = transfer == CURLE_OK && json_content_type(content_type) && is_json_object(&body);
    }
    if (!preserve)
        erase(response, body.received);
    response[body.received] = '\0';
    if (easy)
        curl_easy_cleanup(easy);
    if (headers) {
        erase(headers->data, strlen(headers->data));
        curl_slist_free_all(headers);
    }
    curl_url_cleanup(url);
    return result;
}

struct node_health_result node_transport_health(const struct node_transport_config *config)
{
    char response[BODY_LIMIT + 1];
    struct node_health_result result = node_transport_request(config, NODE_OPERATION_HEALTH, NULL,
                                                              response, sizeof(response));
    erase(response, sizeof(response));
    return result;
}
