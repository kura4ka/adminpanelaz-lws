#ifndef PANEL_NODES_H
#define PANEL_NODES_H

#include "node_transport.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    PANEL_NODE_NAME_LIMIT = 96,
    PANEL_NODE_ENDPOINT_LIMIT = 320,
    PANEL_NODE_FILE_LIMIT = 96,
    PANEL_NODE_VERSION_LIMIT = 64,
    PANEL_NODES_JSON_LIMIT = 64 * 1024
};

enum panel_node_kind { PANEL_NODE_VPN, PANEL_NODE_PROXY };
enum panel_node_transport { PANEL_NODE_LOCAL, PANEL_NODE_HTTP, PANEL_NODE_HTTPS, PANEL_NODE_MTLS };

enum panel_nodes_result {
    PANEL_NODES_OK,
    PANEL_NODES_INVALID,
    PANEL_NODES_MISSING,
    PANEL_NODES_CONFLICT,
    PANEL_NODES_LIMIT,
    PANEL_NODES_BUSY,
    PANEL_NODES_ERROR
};

struct panel_node {
    int64_t id;
    int64_t linked_vpn_node_id; /* -1 means no association. */
    enum panel_node_kind kind;
    enum panel_node_transport transport;
    enum node_health_state health;
    char name[PANEL_NODE_NAME_LIMIT + 1];
    char endpoint[PANEL_NODE_ENDPOINT_LIMIT + 1];
    char antizapret_version[PANEL_NODE_VERSION_LIMIT + 1];
    char agent_version[PANEL_NODE_VERSION_LIMIT + 1];
};

struct panel_node_input {
    const char *name;
    const char *endpoint;
    const char *kind;
    const char *transport;
    const char *node_key; /* On update, NULL or empty keeps the current key. */
    const char *ca_file;
    const char *client_cert;
    const char *client_key;
    int64_t linked_vpn_node_id;
};

/* The containing data directory and node-tls/ files must be private to the panel.
 * Call database and job lifecycle functions from the server event loop. */
bool panel_nodes_open(const char *data_directory);
void panel_nodes_close(void);
enum panel_nodes_result panel_nodes_get(int64_t id, struct panel_node *node);
enum panel_nodes_result panel_nodes_get_json(int64_t id, char *out, size_t capacity);
enum panel_nodes_result panel_nodes_list_json(char *out, size_t capacity);
enum panel_nodes_result panel_nodes_active(int64_t *id, int64_t *revision);
enum panel_nodes_result panel_nodes_activate(int64_t id, int64_t expected_revision);
/* An id of -1 creates a new remote node. The local VPN node has id 0. */
enum panel_nodes_result panel_nodes_save(int64_t id, const struct panel_node_input *input, int64_t *saved_id);
enum panel_nodes_result panel_nodes_delete(int64_t id);

struct panel_nodes_job;

/* Only one agent request may be in flight. Destination is set only for a proxy
 * destination change. Polling writes cached health once a result is available.
 * Response views belong to the job and remain valid through release. */
enum panel_nodes_result panel_nodes_job_start(int64_t id, enum node_operation operation,
    const char *destination, struct panel_nodes_job **job);
bool panel_nodes_job_poll(struct panel_nodes_job *job, struct node_health_result *result, const char **data);
void panel_nodes_job_release(struct panel_nodes_job *job);

#endif
