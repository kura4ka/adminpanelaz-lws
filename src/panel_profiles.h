#ifndef ADMINPANELAZ_PANEL_PROFILES_H
#define ADMINPANELAZ_PANEL_PROFILES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

size_t panel_profiles_json(char *out, size_t capacity, const char *directory);
size_t panel_profiles_json_page(char *out, size_t capacity, const char *directory, size_t offset, const char *cursor,
                                const char *query, const char *protocol);
FILE *panel_profile_open(const char *directory, const char *id, char filename[129], size_t *size);
FILE *panel_profile_open_variant(const char *directory, const char *protocol, const char *variant,
                                 const char *client_name, char filename[129], size_t *size);
/* The visitor owns each file and returns false to stop. A missing variant or file returns false. */
bool panel_profile_visit_variant(const char *directory, const char *protocol, const char *variant,
                                  const char *client_name,
                                  bool (*visitor)(void *context, const char *filename, FILE *file, size_t size),
                                  void *context);

#endif
