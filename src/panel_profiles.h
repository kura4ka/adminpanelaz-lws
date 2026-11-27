#ifndef ADMINPANELAZ_PANEL_PROFILES_H
#define ADMINPANELAZ_PANEL_PROFILES_H

#include <stddef.h>
#include <stdio.h>

size_t panel_profiles_json(char *out, size_t capacity, const char *directory);
FILE *panel_profile_open(const char *directory, const char *id, char filename[129], size_t *size);

#endif
