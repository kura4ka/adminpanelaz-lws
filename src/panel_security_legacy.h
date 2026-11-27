#ifndef PANEL_SECURITY_LEGACY_H
#define PANEL_SECURITY_LEGACY_H

#include "panel_security.h"

struct panel_security_legacy_factor {
    int64_t account_id;
    char secret[PANEL_SECURITY_TOTP_SECRET_SIZE];
    size_t code_count;
    char codes[PANEL_SECURITY_RECOVERY_COUNT][PANEL_SECURITY_RECOVERY_SIZE];
};

/* The offline reader returns one row, end of input, or corruption (1, 0, -1). */
typedef int (*panel_security_factor_reader)(void *context, struct panel_security_legacy_factor *factor);
bool panel_security_import_factors(panel_security_factor_reader reader, void *context, unsigned int *imported);
bool panel_security_import_legacy_totp(const char *source, const char *migrated, const char *upstream_key,
                                       unsigned int *imported);

#endif
