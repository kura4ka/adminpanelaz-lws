#ifndef PANEL_BACKUP_CREATE_H
#define PANEL_BACKUP_CREATE_H

#include <stdbool.h>

/* Creates <backup_dir>/<id>.backup, where id is 32 lowercase hexadecimal digits. */
bool panel_backup_create(const char *backup_dir, const char *auth_db, const char *id);

#endif
