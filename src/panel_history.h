#ifndef PANEL_HISTORY_H
#define PANEL_HISTORY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum { PANEL_HISTORY_JSON_CAP = 32 * 1024, PANEL_HISTORY_CLIENT_MAX = 128 };

enum panel_history_kind {
    PANEL_HISTORY_RESOURCES,
    PANEL_HISTORY_CONNECTIONS,
    PANEL_HISTORY_TRAFFIC,
    PANEL_HISTORY_AUDIT
};

enum panel_history_action {
    PANEL_HISTORY_LOGIN,
    PANEL_HISTORY_LOGOUT,
    PANEL_HISTORY_PASSWORD_CHANGE,
    PANEL_HISTORY_BACKUP_CREATE,
    PANEL_HISTORY_BACKUP_UPLOAD,
    PANEL_HISTORY_BACKUP_DELETE,
    PANEL_HISTORY_BACKUP_RESTORE,
    PANEL_HISTORY_CLIENT_CHANGE,
    PANEL_HISTORY_NODE_CHANGE,
    PANEL_HISTORY_ROUTING_CHANGE,
    PANEL_HISTORY_SETTINGS_CHANGE
};

/* Called from the server event loop. All timestamps are Unix seconds. */
bool panel_history_open(const char *data_dir);
void panel_history_close(void);
bool panel_history_sample(const char *data_dir, const char *const *openvpn_paths,
                          size_t openvpn_count, const char *wireguard_path, int64_t now);
size_t panel_history_json(char *out, size_t capacity, enum panel_history_kind kind,
                          unsigned int days, int64_t now);
/* Client labels are OpenVPN common names or WireGuard's "interface · peer prefix". */
size_t panel_history_client_json(char *out, size_t capacity, const char *client,
                                 unsigned int days, int64_t now);
bool panel_history_audit(int64_t now, int64_t actor_id, enum panel_history_action action,
                         bool success);

#ifdef PANEL_HISTORY_MIGRATION
struct panel_history_import_count {
    size_t resources;
    size_t connections;
    size_t traffic;
    size_t audit;
};

bool panel_history_import_legacy(const char *source_path, int64_t local_node_id, int64_t now,
                                 struct panel_history_import_count *count);
#endif

#endif
