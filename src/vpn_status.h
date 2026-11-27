#ifndef VPN_STATUS_H
#define VPN_STATUS_H

#include <stddef.h>
#include "vpn_counter.h"

/* Combines complete snapshots. Returns the JSON length, or zero on overflow. */
size_t vpn_statuses_json(char *out, size_t capacity, const char *const *paths, size_t count);

/* Returns true for a complete single snapshot. Discard callbacks if it fails. */
bool vpn_status_counters(const char *path, vpn_counter_fn read_counter, void *context);

#endif
