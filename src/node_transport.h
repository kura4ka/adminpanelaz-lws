#ifndef NODE_TRANSPORT_H
#define NODE_TRANSPORT_H

#include <stdbool.h>
#include <stddef.h>

struct node_transport_config {
    const char *endpoint; /* Administrative origin, for example https://agent.example:8443. */
    const char *node_key;  /* X-Node-Key token. HTTP sends it without encryption. */
    const char *ca_file;   /* Optional HTTPS trust roots in PEM format. */
    const char *client_cert;
    const char *client_key; /* Optional HTTPS client certificate and private key in PEM format. */
    bool deny_internal;
    bool (*should_cancel)(void *context);
    void *cancel_context;
};

enum node_health_state {
    NODE_HEALTH_AVAILABLE,
    NODE_HEALTH_INVALID_CONFIG,
    NODE_HEALTH_AUTH_FAILED,
    NODE_HEALTH_TIMEOUT,
    NODE_HEALTH_TLS_FAILED,
    NODE_HEALTH_RESPONSE_TOO_LARGE,
    NODE_HEALTH_UNEXPECTED_RESPONSE,
    NODE_HEALTH_UNAVAILABLE,
    NODE_HEALTH_UNKNOWN
};

enum node_operation {
    NODE_OPERATION_HEALTH,
    NODE_OPERATION_PROXY_STATUS,
    NODE_OPERATION_PROXY_DESTINATION,
    NODE_OPERATION_PROXY_MAPPINGS
};

struct node_health_result {
    enum node_health_state state;
    long http_status; /* Zero when no HTTP response was received. */
};

/* Call once before any probes or worker threads. Requires libcurl with asynchronous DNS. */
bool node_transport_init(void);
/* Call after all probes have finished. */
void node_transport_cleanup(void);

bool node_transport_validate(const struct node_transport_config *config);
const char *node_health_state_name(enum node_health_state state);
bool node_transport_valid_proxy_destination(const char *destination);

/* Performs GET /health with a two-second connection limit and a five-second total deadline.
 * Success requires HTTP 200 and one JSON object, with at most 16 KiB each for headers and body.
 * TLS files are used with HTTPS, and client certificate and key must be paired.
 * The result consists of the state and HTTP status. */
struct node_health_result node_transport_health(const struct node_transport_config *config);

/* Typed agent API. For validated JSON responses, response is NUL terminated
 * and includes non-success JSON when an agent supplied a diagnostic. */
struct node_health_result node_transport_request(const struct node_transport_config *config,
    enum node_operation operation, const char *destination, char *response, size_t capacity);

#endif
