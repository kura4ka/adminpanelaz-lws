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
#include <stdint.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

enum { PROFILES_PER_PAGE = 64, MAX_OWNED_PROFILES = 128, MAX_PROFILE_BYTES = 512 * 1024,
    PROFILE_TRAILER_SIZE = 244 };

static const struct profile_variant {
    const char *protocol;
    const char *variant;
    const char *prefix;
    const char *suffix;
} variants[] = {
    {"openvpn", "antizapret", "antizapret-", ".ovpn"},
    {"openvpn", "antizapret-udp", "antizapret-", "-udp.ovpn"},
    {"openvpn", "antizapret-tcp", "antizapret-", "-tcp.ovpn"},
    {"openvpn", "vpn", "vpn-", ".ovpn"},
    {"openvpn", "vpn-udp", "vpn-", "-udp.ovpn"},
    {"openvpn", "vpn-tcp", "vpn-", "-tcp.ovpn"},
    {"wireguard", "antizapret", "antizapret-", "-wg.conf"},
    {"wireguard", "vpn", "vpn-", "-wg.conf"},
    {"amneziawg", "antizapret", "antizapret-", "-am.conf"},
    {"amneziawg", "vpn", "vpn-", "-am.conf"}
};

static bool allowed_name(const char *name, const struct profile_variant *variant)
{
    size_t length = strlen(name), suffix = strlen(variant->suffix);
    return length > suffix && length <= 128 && name[0] != '.' &&
        strspn(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-()") == length &&
        !strcmp(name + length - suffix, variant->suffix);
}

static int profile_index(const char *id)
{
    if (!id || id[0] < '0' || id[0] > '9' || id[1] != '-')
        return -1;
    int index = id[0] - '0';
    return allowed_name(id + 2, &variants[index]) ? index : -1;
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

static FILE *open_file(int dir, const char *name, size_t *size)
{
    int fd = openat(dir, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
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
    *size = (size_t)info.st_size;
    return file;
}

static void profile_client(const struct profile_variant *variant, const char *filename, char name[33])
{
    const char *end = filename + strlen(filename) - strlen(variant->suffix);
    size_t prefix = strlen(variant->prefix);
    const char *start = filename;
    if (end - filename >= (ptrdiff_t)prefix && !strncmp(filename, variant->prefix, prefix))
        start += prefix;
    const char *host = strstr(start, "-(");
    if (host) {
        if (host + 3 >= end || end[-1] != ')')
            return;
        end = host;
    }
    size_t length = (size_t)(end - start);
    if (length > 0 && length < 33 &&
        strspn(start, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-") >= length) {
        memcpy(name, start, length);
        name[length] = '\0';
    }
}

struct listing_row {
    char name[129];
    off_t size;
    size_t variant;
};

static bool matches_query(const char *name, const char *query)
{
    if (!query || !*query)
        return true;
    size_t length = strlen(query);
    for (const char *position = name; *position; ++position)
        if (!strncasecmp(position, query, length))
            return true;
    return false;
}

static void queue_profile(struct listing_row page[PROFILES_PER_PAGE], size_t *count, size_t variant,
                          const char *name, off_t size)
{
    size_t position = *count;
    while (position > 0 && page[position - 1].variant == variant && strcmp(page[position - 1].name, name) > 0)
        --position;
    if (position < PROFILES_PER_PAGE) {
        if (*count < PROFILES_PER_PAGE)
            ++*count;
        memmove(page + position + 1, page + position, (*count - position - 1) * sizeof(*page));
        strcpy(page[position].name, name);
        page[position].size = size;
        page[position].variant = variant;
    }
}
#endif

size_t panel_profiles_json(char *out, size_t capacity, const char *directory)
{
    return panel_profiles_json_page(out, capacity, directory, 0, NULL, NULL, NULL);
}

size_t panel_profiles_json_page(char *out, size_t capacity, const char *directory, size_t offset, const char *cursor,
                                const char *query, const char *protocol)
{
    if (!out || capacity < 160)
        return 0;
#ifdef __linux__
    int first_variant = cursor && cursor[0] ? profile_index(cursor) : -1;
    if ((cursor && cursor[0] && first_variant < 0) || offset > SIZE_MAX - PROFILES_PER_PAGE)
        return 0;
    int root = directory ? open(directory, O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW) : -1;
    if (root >= 0) {
        struct listing_row page[PROFILES_PER_PAGE];
        size_t total = 0, remaining = 0, count = 0;
        for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); ++i) {
            const struct profile_variant *variant = &variants[i];
            if (protocol && *protocol && strcmp(protocol, variant->protocol))
                continue;
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
                if (!allowed_name(entry->d_name, variant) || !matches_query(entry->d_name, query) ||
                    fstatat(fd, entry->d_name, &info, AT_SYMLINK_NOFOLLOW) || !profile_size(&info) ||
                    faccessat(fd, entry->d_name, R_OK, 0))
                    continue;
                ++total;
                if ((int)i < first_variant || ((int)i == first_variant && strcmp(entry->d_name, cursor + 2) <= 0))
                    continue;
                ++remaining;
                queue_profile(page, &count, i, entry->d_name, info.st_size);
            }
            closedir(stream);
        }
        close(root);
        size_t used = (size_t)snprintf(out, capacity, "{\"state\":\"available\",\"profiles\":[");
        size_t shown = 0;
        while (shown < count) {
            const struct listing_row *item = &page[shown];
            const struct profile_variant *variant = &variants[item->variant];
            char row[512], client[33] = {0};
            profile_client(variant, item->name, client);
            int size = snprintf(row, sizeof(row),
                "%s{\"id\":\"%zu-%s\",\"name\":\"%s\",\"client_name\":\"%s\",\"protocol\":\"%s\",\"variant\":\"%s\",\"size_bytes\":%lld}",
                shown ? "," : "", item->variant, item->name, item->name, client, variant->protocol, variant->variant,
                (long long)item->size);
            if (size < 0 || (size_t)size >= sizeof(row) || (size_t)size + PROFILE_TRAILER_SIZE >= capacity - used)
                break;
            memcpy(out + used, row, (size_t)size);
            used += (size_t)size;
            ++shown;
        }
        if (!shown && remaining)
            return 0;
        int size;
        if (remaining > shown) {
            const struct listing_row *last = &page[shown - 1];
            size = snprintf(out + used, capacity - used,
                "],\"total\":%zu,\"truncated\":true,\"offset\":%zu,\"next_offset\":%zu,\"next_cursor\":\"%zu-%s\"}",
                total, offset, offset + shown, last->variant, last->name);
        } else {
            size = snprintf(out + used, capacity - used,
                "],\"total\":%zu,\"truncated\":false,\"offset\":%zu,\"next_offset\":null,\"next_cursor\":null}", total, offset);
        }
        return size > 0 && (size_t)size < capacity - used ? used + (size_t)size : 0;
    }
#else
    (void)directory; (void)cursor; (void)query; (void)protocol;
#endif
    int size = snprintf(out, capacity, "{\"state\":\"unavailable\",\"profiles\":[],\"total\":0,\"truncated\":false,"
                        "\"offset\":%zu,\"next_offset\":null,\"next_cursor\":null}", offset);
    return size > 0 && (size_t)size < capacity ? (size_t)size : 0;
}

FILE *panel_profile_open(const char *directory, const char *id, char filename[129], size_t *size)
{
#ifdef __linux__
    int index = profile_index(id);
    if (!directory || !filename || !size || index < 0)
        return NULL;
    const struct profile_variant *variant = &variants[index];
    const char *name = id + 2;
    int root = open(directory, O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (root < 0)
        return NULL;
    int dir = open_variant(root, variant);
    close(root);
    if (dir < 0)
        return NULL;
    FILE *file = open_file(dir, name, size);
    close(dir);
    if (file)
        strcpy(filename, name);
    return file;
#else
    (void)directory; (void)id; (void)filename; (void)size;
    return NULL;
#endif
}

bool panel_profile_visit_variant(const char *directory, const char *protocol, const char *variant,
                                  const char *client_name,
                                  bool (*visitor)(void *context, const char *filename, FILE *file, size_t size),
                                  void *context)
{
#ifdef __linux__
    if (!directory || !protocol || !variant || !client_name || !*client_name || !visitor)
        return false;
    const struct profile_variant *profile = NULL;
    for (size_t i = 0; i < sizeof(variants) / sizeof(variants[0]); ++i)
        if (!strcmp(protocol, variants[i].protocol) && !strcmp(variant, variants[i].variant)) {
            profile = &variants[i];
            break;
        }
    if (!profile)
        return false;
    int root = open(directory, O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (root < 0)
        return false;
    int dir = open_variant(root, profile);
    close(root);
    if (dir < 0)
        return false;
    DIR *stream = fdopendir(dir);
    if (!stream) {
        close(dir);
        return false;
    }
    size_t matches = 0;
    struct dirent *entry;
    while (matches < MAX_OWNED_PROFILES && (entry = readdir(stream))) {
        char client[33] = {0};
        if (!allowed_name(entry->d_name, profile))
            continue;
        profile_client(profile, entry->d_name, client);
        if (strcmp(client, client_name))
            continue;
        size_t size;
        FILE *file = open_file(dir, entry->d_name, &size);
        if (!file)
            continue;
        ++matches;
        if (!visitor(context, entry->d_name, file, size))
            break;
    }
    closedir(stream);
    return matches != 0;
#else
    (void)directory; (void)protocol; (void)variant; (void)client_name; (void)visitor; (void)context;
    return false;
#endif
}

struct first_profile {
    FILE *file;
    char *filename;
    size_t *size;
};

static bool select_profile(void *context, const char *filename, FILE *file, size_t size)
{
    struct first_profile *first = context;
    if (first->file && strcmp(first->filename, filename) <= 0) {
        fclose(file);
        return true;
    }
    if (first->file)
        fclose(first->file);
    first->file = file;
    strcpy(first->filename, filename);
    *first->size = size;
    return true;
}

FILE *panel_profile_open_variant(const char *directory, const char *protocol, const char *variant,
                                 const char *client_name, char filename[129], size_t *size)
{
    if (!filename || !size)
        return NULL;
    struct first_profile first = {.filename = filename, .size = size};
    panel_profile_visit_variant(directory, protocol, variant, client_name, select_profile, &first);
    return first.file;
}
