#ifndef LEGACY_ACCOUNTS_H
#define LEGACY_ACCOUNTS_H

#include <stdbool.h>
#include <stddef.h>
#include <sqlite3.h>

/* Reports aggregate migration candidates from an offline SQLite snapshot.
 * Returns the JSON length or zero if out is unavailable or too small. */
size_t legacy_accounts_inspect_json(char *out, size_t capacity, const char *path);

/* Stage an auth DB from an offline snapshot without replacing an existing file.
 * An identical repeat succeeds without writing; conflicting destinations fail. */
bool legacy_accounts_import(const char *path, const char *destination);
sqlite3 *legacy_accounts_open_readonly(const char *path);

#endif
