#ifndef PANEL_BACKUP_RESTORE_H
#define PANEL_BACKUP_RESTORE_H

#include <stdbool.h>

/* Stages a native account backup at a new path in a private local directory.
 * The destination must not exist. A failed restore removes its staging file.
 * Archives containing sessions or any additional members are rejected. */
bool panel_backup_stage_auth(const char *archive_path, const char *destination);

enum { PANEL_BACKUP_PASSWORD_MAX = 4096 };

enum panel_backup_upstream_component {
    PANEL_BACKUP_UPSTREAM_DB = 1u << 0,
    PANEL_BACKUP_UPSTREAM_CIDR = 1u << 1,
    PANEL_BACKUP_UPSTREAM_ENV = 1u << 2,
    PANEL_BACKUP_UPSTREAM_CONFIGS = 1u << 3,
    PANEL_BACKUP_UPSTREAM_AWG2 = 1u << 4
};

/* Verifies an upstream tar.gz or APAZBK1 archive and publishes its staged files
 * as a new directory under a private parent. Never replaces an existing path.
 * The optional component bitmask is set only when staging succeeds.
 * Passwords must be passed as UTF-8, without the input line terminator. */
bool panel_backup_stage_upstream(const char *archive_path, const char *destination_directory,
                                const char *password, unsigned int *components);

/* Creates a private offline snapshot of a stopped panel, including the auth
 * database and recognized module databases. The optional portal database is
 * supplied separately because its configured location varies. The external
 * APAZ_SECURITY_KEY is required to reopen an enrolled MFA database. */
bool panel_backup_stage_native_state(const char *data_directory, const char *auth_database,
                                     const char *portal_database, const char *destination_directory);

#endif
