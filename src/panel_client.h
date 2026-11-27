#ifndef ADMINPANELAZ_PANEL_CLIENT_H
#define ADMINPANELAZ_PANEL_CLIENT_H

enum panel_client_result {
    PANEL_CLIENT_UNAVAILABLE,
    PANEL_CLIENT_IDLE,
    PANEL_CLIENT_RUNNING,
    PANEL_CLIENT_OK,
    PANEL_CLIENT_INVALID,
    PANEL_CLIENT_CONFLICT,
    PANEL_CLIENT_FAILED,
    PANEL_CLIENT_TIMEOUT,
    PANEL_CLIENT_NOT_CONFIGURED
};

enum panel_client_result panel_client_start(const char *socket_path, const char *operation, const char *name,
                                            const char *days);
enum panel_client_result panel_client_poll(const char *socket_path);
const char *panel_client_result_name(enum panel_client_result result);

#endif
