#ifndef ADMINPANELAZ_PANEL_HA_H
#define ADMINPANELAZ_PANEL_HA_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

enum {
    PANEL_HA_MAX_REPLICAS = 16,
    PANEL_HA_VERSION_MAX = 64,
    PANEL_HA_NODE_NAME_MAX = 96,
    PANEL_HA_NODE_HOST_MAX = 320
};

struct panel_ha_fields {
    const char *name;
    const char *shared_domain;
    const char *shared_domain_wireguard;
    const char *sync_mode;
    int64_t primary_node_id;
    const int64_t *replica_node_ids;
    size_t replica_count;
};

struct panel_ha_node_info {
    bool vpn;
    bool online;
    bool health_unknown;
    char antizapret_version[PANEL_HA_VERSION_MAX + 1];
    char agent_version[PANEL_HA_VERSION_MAX + 1];
    char name[PANEL_HA_NODE_NAME_MAX + 1];
    char host[PANEL_HA_NODE_HOST_MAX + 1];
};

typedef bool (*panel_ha_node_lookup)(int64_t id, struct panel_ha_node_info *info, void *context);

enum panel_ha_node_role {
    PANEL_HA_LOOKUP_FAILED = -1,
    PANEL_HA_STANDALONE,
    PANEL_HA_PRIMARY,
    PANEL_HA_REPLICA
};

/* Initialize the schema before serving requests. The DB connection is opened on demand. */
bool panel_ha_open(const char *path);
void panel_ha_close(void);
enum panel_ha_node_role panel_ha_node_role(int64_t node_id);

/* The caller handles HTTP authentication and CSRF. Returns an HTTP status and JSON in output.
 * Create requires all nonoptional fields. Null fields, 0 for primary and a null replica list
 * leave the corresponding fields unchanged during update. Empty WG domain clears its override.
 * Actions: list, get, status, create, update, delete, preflight, verify, setup, push-full,
 * apply-shared-domain. Preflight uses cached member status and never touches VPN state. */
int panel_ha_request(const char *action, int64_t group_id, const struct panel_ha_fields *fields,
                     const char *panel_host, panel_ha_node_lookup lookup, void *context, FILE *output);

#endif
