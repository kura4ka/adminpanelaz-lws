#ifndef PANEL_BACKUPS_H
#define PANEL_BACKUPS_H

#include <stdbool.h>
#include <stddef.h>

size_t panel_backups_json(char *out, size_t capacity, const char *directory);
bool panel_backup_path(char *out, size_t capacity, const char *directory, const char *name);
size_t panel_backup_inspect_json(char *out, size_t capacity, const char *path);

enum panel_backup_delete_result {
    PANEL_BACKUP_DELETED,
    PANEL_BACKUP_NOT_FOUND,
    PANEL_BACKUP_DELETE_ERROR
};

enum panel_backup_delete_result panel_backup_delete(const char *directory, const char *name);

#endif
