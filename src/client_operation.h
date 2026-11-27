#ifndef ADMINPANELAZ_CLIENT_OPERATION_H
#define ADMINPANELAZ_CLIENT_OPERATION_H

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

enum {
    CLIENT_INVALID = 2,
    CLIENT_SCRIPT_FAILED = 4,
    CLIENT_CONFLICT = 5,
    CLIENT_UNAVAILABLE = 6,
    CLIENT_TEMPORARY = 75,
    CLIENT_DEADLINE = 124,
    CLIENT_REQUEST_CAP = 64
};

static const struct client_operation {
    const char *name;
    const char *code;
    size_t argument_count;
    int timeout;
    bool creation;
} client_operations[] = {
    {"openvpn-add", "1", 2, 120, true},
    {"openvpn-remove", "2", 1, 120, false},
    {"wireguard-add", "4", 1, 120, true},
    {"wireguard-remove", "5", 1, 120, false},
    {"profiles-regenerate", "7", 0, 300, false},
};

static const struct client_operation *find_operation(const char *name, bool web)
{
    for (size_t i = 0; name && i < sizeof(client_operations) / sizeof(client_operations[0]); ++i)
        if (!strcmp(name, client_operations[i].name) && (!web || client_operations[i].argument_count))
            return &client_operations[i];
    return NULL;
}

static bool valid_operation_arguments(const struct client_operation *operation, const char *name, const char *days)
{
    if (!operation)
        return false;
    if (!operation->argument_count)
        return !name && !days;
    if (!name || !name[0] || name[0] == '-' || strlen(name) > 32 ||
        name[strspn(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-")] ||
        !strcasecmp(name, "antizapret-server") ||
        (operation->creation && (!strncasecmp(name, "vpn-", 4) || !strncasecmp(name, "antizapret-", 11))))
        return false;
    if (operation->argument_count == 1)
        return !days;
    if (!days || days[0] < '1' || days[0] > '9' || strlen(days) > 4 || days[strspn(days, "0123456789")])
        return false;
    return strtol(days, NULL, 10) <= 3650;
}

#endif
