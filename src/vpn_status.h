#ifndef VPN_STATUS_H
#define VPN_STATUS_H

#include <stddef.h>

/* Combines complete snapshots. Returns the JSON length, or zero on overflow. */
size_t vpn_statuses_json(char *out, size_t capacity, const char *const *paths, size_t count);

#endif
