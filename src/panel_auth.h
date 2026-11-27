#ifndef PANEL_AUTH_H
#define PANEL_AUTH_H

#include <stdbool.h>

enum {
    PANEL_AUTH_USERNAME_MAX = 64,
    PANEL_AUTH_PASSWORD_MIN = 12,
    PANEL_AUTH_PASSWORD_MAX = 1024,
    PANEL_AUTH_TOKEN_SIZE = 65
};

/* Call from the panel's server event loop. */
bool panel_auth_open(const char *path, const char *initial_password);
void panel_auth_close(void);
bool panel_auth_login(const char *username, const char *password, char token[PANEL_AUTH_TOKEN_SIZE]);
bool panel_auth_session(const char *token, char username[PANEL_AUTH_USERNAME_MAX + 1]);
void panel_auth_logout(const char *token);
bool panel_auth_change_password(const char *token, const char *old_password, const char *new_password);
unsigned int panel_auth_retry_after(void);

#endif
