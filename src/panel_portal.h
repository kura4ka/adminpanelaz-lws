#ifndef ADMINPANELAZ_PANEL_PORTAL_H
#define ADMINPANELAZ_PANEL_PORTAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

enum { PANEL_PORTAL_TOKEN_MAX = 64, PANEL_PORTAL_PATH_MAX = 512 };

/* The portal reads its own local copy of the legacy database. */
bool panel_portal_open(const char *path);
void panel_portal_close(void);
bool panel_portal_host_matches(const char *host);
bool panel_portal_token_valid(const char *token);
/* Call once per metadata/download request with the direct peer IP. */
bool panel_portal_allow_request(const char *peer_address);

/* Functions return an HTTP status. Output is initialized only on success. */
int panel_portal_meta(const char *host, const char *token, const char *profiles_dir,
                      bool secure, char *out, size_t capacity);
int panel_portal_download(const char *host, const char *token, const char *profiles_dir,
                          const char *file_id, const char *legacy_path,
                          FILE **file, char filename[129], size_t *size);

#endif
