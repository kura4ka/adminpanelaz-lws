#ifndef PANEL_TELEGRAM_H
#define PANEL_TELEGRAM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "telegram_auth.h"

enum { PANEL_TELEGRAM_USERNAME_MAX = 32, PANEL_TELEGRAM_TOKEN_MAX = 256 };

struct panel_telegram_settings {
    char username[PANEL_TELEGRAM_USERNAME_MAX + 1];
    unsigned int max_age;
    bool legacy_enabled;
    bool mini_enabled;
    bool token_configured;
};

enum panel_telegram_result {
    PANEL_TELEGRAM_OK,
    PANEL_TELEGRAM_DISABLED,
    PANEL_TELEGRAM_DENIED,
    PANEL_TELEGRAM_CONFLICT,
    PANEL_TELEGRAM_REPLAY,
    PANEL_TELEGRAM_INVALID,
    PANEL_TELEGRAM_ERROR
};

/* All functions are called from the web event loop (or by an offline importer). */
bool panel_telegram_open(const char *path);
void panel_telegram_close(void);
bool panel_telegram_settings_get(struct panel_telegram_settings *settings);

/* NULL keeps the token; an empty string clears it. Get never returns the token. */
enum panel_telegram_result panel_telegram_settings_set(const struct panel_telegram_settings *settings,
                                                      const char *replacement_token);

/* A zero Telegram ID indicates an unlinked account. */
bool panel_telegram_bound(int64_t account_id, uint64_t *telegram_id);

/* The caller must authenticate the account before linking or unlinking it. */
enum panel_telegram_result panel_telegram_link(int64_t account_id, bool mini, const char *data,
                                               size_t size, uint64_t now);
bool panel_telegram_unlink(int64_t account_id);

/* A successful claim consumes the verified proof. The caller must still enforce
 * account permissions and any login factors before issuing a session. */
enum panel_telegram_result panel_telegram_claim_login(bool mini, const char *data, size_t size,
                                                      uint64_t now, int64_t *account_id);

/* Used to determine whether a second factor is needed before consuming the proof. */
enum panel_telegram_result panel_telegram_check_login(bool mini, const char *data, size_t size,
                                                       uint64_t now, int64_t *account_id);

/* Offline import into a fresh Telegram database, after accounts have been
 * migrated from the same snapshot. Copies links, bot username and max age.
 * Repeating the same import retains subsequent changes to the destination.
 * The bot secret and the login-mode switches require separate configuration. */
enum panel_telegram_result panel_telegram_import_legacy(const char *source_db, const char *native_auth_db);

#endif
