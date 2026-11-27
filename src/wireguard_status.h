#ifndef ADMINPANELAZ_WIREGUARD_STATUS_H
#define ADMINPANELAZ_WIREGUARD_STATUS_H

#include <stddef.h>

size_t wireguard_status_json(char *out, size_t capacity, const char *path);

#endif
