#ifndef PANEL_SECURITY_H
#define PANEL_SECURITY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

enum {
    PANEL_SECURITY_IP_SIZE = 46,
    PANEL_SECURITY_FORWARDED_MAX = 2048,
    PANEL_SECURITY_CAPTCHA_ID_SIZE = 33,
    PANEL_SECURITY_CAPTCHA_PNG_MAX = 4096,
    PANEL_SECURITY_TOTP_SECRET_SIZE = 33,
    PANEL_SECURITY_RECOVERY_COUNT = 8,
    PANEL_SECURITY_RECOVERY_SIZE = 9
};

/* Configuration takes comma-separated CIDRs and exact proxy IPs, respectively. */
bool panel_security_configure(const char *allowlist, const char *trusted_proxies);
bool panel_security_client_ip(const char *peer, const char *forwarded_for, char out[PANEL_SECURITY_IP_SIZE]);
bool panel_security_ip_allowed(const char *ip);
unsigned int panel_security_retry_after(const char *ip);
void panel_security_record_login(const char *ip, bool success);
bool panel_security_login_needs_captcha(const char *ip);
bool panel_security_captcha_create(const char *ip, char id[PANEL_SECURITY_CAPTCHA_ID_SIZE],
                                  unsigned char *png, size_t capacity, size_t *size);
bool panel_security_captcha_verify(const char *ip, const char *id, const char *answer);

/* Call from the panel event loop. A null key leaves fresh stores unenrolled. */
bool panel_security_open(const char *path, const char *hex_key);
void panel_security_close(void);
/* Read the pre-existing factor store without creating or changing it. */
bool panel_security_reconcile_native_factors(const char *path, const char *hex_key,
                                            bool (*mark)(int64_t account_id, void *context), void *context);
bool panel_security_can_enroll(void);
bool panel_security_factor_is_enabled(int64_t account_id);
bool panel_security_factor_pending(int64_t account_id);
bool panel_security_factor_status(int64_t account_id, bool *enabled, unsigned int *remaining);
bool panel_security_factor_setup(int64_t account_id, char secret[PANEL_SECURITY_TOTP_SECRET_SIZE]);
bool panel_security_factor_enable(int64_t account_id, const char *code,
                                  char codes[PANEL_SECURITY_RECOVERY_COUNT][PANEL_SECURITY_RECOVERY_SIZE],
                                  bool (*mark_required)(int64_t account_id, bool required));
bool panel_security_factor_disable(int64_t account_id, const char *code);
bool panel_security_factor_forget(int64_t account_id);
bool panel_security_factor_recovery(int64_t account_id, const char *code,
                                    char codes[PANEL_SECURITY_RECOVERY_COUNT][PANEL_SECURITY_RECOVERY_SIZE]);
bool panel_security_second_factor(int64_t account_id, bool required, void *code);

#endif
