#ifndef VPN_COUNTER_H
#define VPN_COUNTER_H

#include <stdbool.h>

/* Borrowed strings exist only during the callback. Counter fields are decimal. */
struct vpn_counter {
    const char *name;
    const char *remote;
    const char *virtual_ip;
    const char *since;
    const char *rx;
    const char *tx;
    bool connected;
};

typedef bool (*vpn_counter_fn)(const struct vpn_counter *record, void *context);

#endif
