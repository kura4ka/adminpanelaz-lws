#ifndef PANEL_SETTINGS_H
#define PANEL_SETTINGS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

enum {
    PANEL_SETTINGS_JSON_CAP = 24 * 1024,
    PANEL_EDIT_FILE_JSON_CAP = 64 * 1024
};

enum panel_settings_result {
    PANEL_SETTINGS_OK,
    PANEL_SETTINGS_INVALID,
    PANEL_SETTINGS_CONFLICT,
    PANEL_SETTINGS_MISSING,
    PANEL_SETTINGS_UNAVAILABLE,
    PANEL_SETTINGS_TOO_LARGE,
    PANEL_SETTINGS_ERROR
};

/* The panel event loop owns this settings state. */
bool panel_settings_open(const char *data_dir);
void panel_settings_close(void);
bool panel_settings_enabled(const char *key);
bool panel_settings_json(char *out, size_t capacity);
enum panel_settings_result panel_settings_set(const char *key, bool enabled);

/* Offline import of recognized module flags only. Existing settings take priority. */
enum panel_settings_result panel_settings_import_env(const char *env_path);

/* Takes a server-trusted directory and fixed filename, or an operator-configured
 * path with directory set to NULL. Does not accept HTTP-supplied paths. */
enum panel_settings_result panel_settings_open_regular(const char *directory, const char *name, FILE **out,
                                                       unsigned long long *size);

bool panel_edit_files_json(char *out, size_t capacity);
enum panel_settings_result panel_edit_file_json(const char *config_dir, const char *knot_dir,
                                               const char *key, char *out, size_t capacity);
bool panel_settings_diagnostics_json(bool tls, const char *profiles_dir, const char *config_dir,
                                     const char *knot_dir, char *out, size_t capacity);

#endif
