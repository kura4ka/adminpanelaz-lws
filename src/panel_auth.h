#ifndef PANEL_AUTH_H
#define PANEL_AUTH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    PANEL_AUTH_USERNAME_CHARACTERS = 64,
    PANEL_AUTH_USERNAME_MAX = PANEL_AUTH_USERNAME_CHARACTERS * 4,
    PANEL_AUTH_PASSWORD_MIN = 12,
    PANEL_AUTH_PASSWORD_MAX = 1024,
    PANEL_AUTH_TOKEN_SIZE = 65,
    PANEL_AUTH_USERS_PAGE = 25
};

enum panel_auth_role { PANEL_AUTH_ROLE_USER, PANEL_AUTH_ROLE_ADMIN };

struct panel_auth_identity {
    int64_t id;
    char username[PANEL_AUTH_USERNAME_MAX + 1];
    enum panel_auth_role role;
    bool must_change_password;
};

enum panel_auth_login_result {
    PANEL_AUTH_LOGIN_DENIED, PANEL_AUTH_LOGIN_SUCCESS, PANEL_AUTH_LOGIN_SECOND_FACTOR
};

typedef bool (*panel_auth_second_factor)(int64_t account_id, bool totp_required, void *context);
typedef bool (*panel_auth_factor_ready)(int64_t account_id);

struct panel_auth_user_settings {
    enum panel_auth_role role;
    bool is_active;
    bool panel_login_enabled;
    bool must_change_password;
};

struct panel_auth_user {
    struct panel_auth_identity identity;
    struct panel_auth_user_settings settings;
    int64_t revision;
    bool legacy_totp;
    bool legacy_passkeys;
    bool native_totp_required;
};

enum panel_auth_user_result {
    PANEL_AUTH_USER_OK, PANEL_AUTH_USER_INVALID, PANEL_AUTH_USER_NOT_FOUND,
    PANEL_AUTH_USER_EXISTS, PANEL_AUTH_USER_STALE, PANEL_AUTH_USER_LAST_ADMIN,
    PANEL_AUTH_USER_SELF, PANEL_AUTH_USER_ERROR
};

/* Call from the panel's server event loop. */
bool panel_auth_open(const char *path, const char *initial_password);
/* The callback must reconcile the existing paired factor DB for a pre-marker policy schema. */
bool panel_auth_open_with_reconciliation(const char *path, const char *initial_password,
                                         bool (*reconcile)(void *), void *context);
bool panel_auth_reconcile_native_factor(int64_t account_id, void *unused);
void panel_auth_close(void);
bool panel_auth_login(const char *username, const char *password, char token[PANEL_AUTH_TOKEN_SIZE]);
enum panel_auth_login_result panel_auth_login_checked(const char *username, const char *password,
        char token[PANEL_AUTH_TOKEN_SIZE], panel_auth_second_factor second_factor, void *context);
bool panel_auth_identify(const char *token, struct panel_auth_identity *out);
bool panel_auth_account(int64_t id, struct panel_auth_identity *out);
bool panel_auth_legacy_totp_required(int64_t id);
bool panel_auth_totp_required(int64_t id);
bool panel_auth_set_native_totp_required(int64_t id, bool required);
bool panel_auth_external_login(int64_t id, char token[PANEL_AUTH_TOKEN_SIZE],
                               panel_auth_second_factor second_factor, void *context);
bool panel_auth_session(const char *token, char username[PANEL_AUTH_USERNAME_MAX + 1]);
void panel_auth_logout(const char *token);
bool panel_auth_revoke_sessions(int64_t account_id);
bool panel_auth_revoke_other_sessions(int64_t account_id, const char *except_token);
bool panel_auth_change_password(const char *token, const char *old_password, const char *new_password);
unsigned int panel_auth_retry_after(void);

bool panel_auth_users(int64_t after, const char *query, struct panel_auth_user out[PANEL_AUTH_USERS_PAGE],
                      size_t *count, bool *has_more);
enum panel_auth_user_result panel_auth_user_create(const char *username, const char *password,
        const struct panel_auth_user_settings *settings, int64_t *id_out);
enum panel_auth_user_result panel_auth_user_update(int64_t id, int64_t revision,
        const struct panel_auth_user_settings *settings, panel_auth_factor_ready factor_ready);
enum panel_auth_user_result panel_auth_user_reset(int64_t actor, int64_t id, int64_t revision,
        const char *password, bool must_change);
enum panel_auth_user_result panel_auth_user_delete(int64_t actor, int64_t id, int64_t revision,
                                                  panel_auth_factor_ready factor_ready);

#endif
