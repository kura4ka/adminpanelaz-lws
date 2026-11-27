#ifndef PANEL_BACKUP_CREATE_H
#define PANEL_BACKUP_CREATE_H

#include <stdbool.h>

/* Creates <backup_dir>/<id>.backup, where id is 32 lowercase hexadecimal digits. */
bool panel_backup_create(const char *backup_dir, const char *auth_db, const char *id);

enum panel_backup_database {
    PANEL_BACKUP_DATABASE_COPY,
    PANEL_BACKUP_DATABASE_AUTH,
    PANEL_BACKUP_DATABASE_SECURITY
};

/* Copies a SQLite database to a newly created file in a private directory. */
bool panel_backup_snapshot_database(const char *source, const char *destination, enum panel_backup_database kind);

#endif
