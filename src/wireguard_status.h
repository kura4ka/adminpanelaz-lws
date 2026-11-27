#ifndef ADMINPANELAZ_WIREGUARD_STATUS_H
#define ADMINPANELAZ_WIREGUARD_STATUS_H

#include <stddef.h>
#include <stdint.h>
#include "vpn_counter.h"

size_t wireguard_status_json(char *out, size_t capacity, const char *path);

/* Returns true for a complete snapshot. Discard callbacks if it fails. */
bool wireguard_status_counters(const char *path, int64_t now,
                               vpn_counter_fn read_counter, void *context);

#endif
