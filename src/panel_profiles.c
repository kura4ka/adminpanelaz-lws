#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif

#include "panel_profiles.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifdef __linux__
#include <dirent.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

enum { MAX_PROFILES = 128, MAX_PROFILE_BYTES = 512 * 1024 };

static const struct profile_variant {
    const char *protocol;
    const char *variant;
    const char *suffix;
} variants[] = {
    {"openvpn", "antizapret", ".ovpn"}, {"openvpn", "antizapret-udp", "-udp.ovpn"},
    {"openvpn", "antizapret-tcp", "-tcp.ovpn"}, {"openvpn", "vpn", ".ovpn"},
    {"openvpn", "vpn-udp", "-udp.ovpn"}, {"openvpn", "vpn-tcp", "-tcp.ovpn"},
    {"wireguard", "antizapret", "-wg.conf"}, {"wireguard", "vpn", "-wg.conf"},
    {"amneziawg", "antizapret", "-am.conf"}, {"amneziawg", "vpn", "-am.conf"}
};

static bool allowed_name(const char *name, const struct profile_variant *variant)
{
    size_t length = strlen(name), suffix = strlen(variant->suffix);
    return length > suffix && length <= 128 && name[0] != '.' &&
        strspn(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-()") == length &&
        !strcmp(name + length - suffix, variant->suffix);
}

static int open_variant(int root, const struct profile_variant *variant)
{
    int protocol = openat(root, variant->protocol, O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (protocol < 0)
        return -1;
    int dir = openat(protocol, variant->variant, O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    close(protocol);
    return dir;
}

static bool profile_size(const struct stat *info)
{
    return S_ISREG(info->st_mode) && info->st_size > 0 && info->st_size <= MAX_PROFILE_BYTES;
}
#endif

size_t panel_profiles_json(char *out, size_t capacity, const char *directory)
{
    if (!out || capacity < 96)
        return 0;
#ifdef __linux__
    int root = directory ? open(directory, O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW) : -1;
    if (root >= 0) {
        size_t used = (size_t)snprintf(out, capacity, "{\"state\":\"available\",\"profiles\":[");
        size_t total = 0, shown = 0;
        for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); ++i) {
            const struct profile_variant *variant = &variants[i];
            int fd = open_variant(root, variant);
            if (fd < 0)
                continue;
            DIR *stream = fdopendir(fd);
            if (!stream) {
                close(fd);
                continue;
            }
            struct dirent *entry;
            while ((entry = readdir(stream))) {
                struct stat info;
                if (!allowed_name(entry->d_name, variant) ||
                    fstatat(fd, entry->d_name, &info, AT_SYMLINK_NOFOLLOW) || !profile_size(&info) ||
                    faccessat(fd, entry->d_name, R_OK, 0))
                    continue;
                ++total;
                if (shown == MAX_PROFILES)
                    continue;
                char row[512];
                int size = snprintf(row, sizeof(row),
                    "%s{\"id\":\"%zu-%s\",\"name\":\"%s\",\"protocol\":\"%s\",\"variant\":\"%s\",\"size_bytes\":%lld}",
                    shown ? "," : "", i, entry->d_name, entry->d_name, variant->protocol, variant->variant,
                    (long long)info.st_size);
                if (size > 0 && (size_t)size < sizeof(row) && (size_t)size + 64 < capacity - used) {
                    memcpy(out + used, row, (size_t)size);
                    used += (size_t)size;
                    ++shown;
                }
            }
            closedir(stream);
        }
        close(root);
        int size = snprintf(out + used, capacity - used, "],\"total\":%zu,\"truncated\":%s}",
                            total, total > shown ? "true" : "false");
        return size > 0 && (size_t)size < capacity - used ? used + (size_t)size : 0;
    }
#else
    (void)directory;
#endif
    return (size_t)snprintf(out, capacity, "{\"state\":\"unavailable\",\"profiles\":[],\"total\":0,\"truncated\":false}");
}

FILE *panel_profile_open(const char *directory, const char *id, char filename[129], size_t *size)
{
#ifdef __linux__
    if (!directory || id[0] < '0' || id[0] > '9' || id[1] != '-')
        return NULL;
    const struct profile_variant *variant = &variants[id[0] - '0'];
    const char *name = id + 2;
    if (!allowed_name(name, variant))
        return NULL;
    int root = open(directory, O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (root < 0)
        return NULL;
    int dir = open_variant(root, variant);
    close(root);
    if (dir < 0)
        return NULL;
    int fd = openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    close(dir);
    if (fd < 0)
        return NULL;
    struct stat info;
    FILE *file = NULL;
    if (fstat(fd, &info) == 0 && profile_size(&info))
        file = fdopen(fd, "rb");
    if (!file) {
        close(fd);
        return NULL;
    }
    strcpy(filename, name);
    *size = (size_t)info.st_size;
    return file;
#else
    (void)directory; (void)id; (void)filename; (void)size;
    return NULL;
#endif
}
