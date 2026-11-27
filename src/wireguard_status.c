#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "wireguard_status.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

enum { ROW_OFFSET = 128, MAX_PEERS = 64, ACTIVE_SECONDS = 180, MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024 };

static size_t status_only(char *out, size_t capacity, const char *state)
{
    int count = snprintf(out, capacity, "{\"state\":\"%s\",\"total\":0,\"active\":0,\"clients\":[]}", state);
    return count >= 0 && (size_t)count < capacity ? (size_t)count : 0;
}

static bool split_row(char *line, char **fields)
{
    for (size_t col = 0; col < 7; ++col) {
        fields[col] = line;
        char *separator = strchr(line, '\t');
        if (!separator)
            return col == 6;
        *separator = '\0';
        line = separator + 1;
    }
    return false;
}

static bool text_field(const char *text, size_t limit)
{
    size_t length = strlen(text);
    if (!length || length > limit)
        return false;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p)
        if (*p < 32 || *p > 126 || *p == '"' || *p == '\\')
            return false;
    return true;
}

static bool number(const char *text, unsigned long long *value)
{
    if (!*text || text[strspn(text, "0123456789")])
        return false;
    errno = 0;
    *value = strtoull(text, NULL, 10);
    return errno == 0;
}

static FILE *open_snapshot(const char *path)
{
#ifdef _WIN32
    int fd = _open(path, _O_RDONLY | _O_BINARY | _O_NOINHERIT);
    if (fd < 0)
        return NULL;
    struct _stat info;
    FILE *file = _fstat(fd, &info) == 0 && (info.st_mode & _S_IFMT) == _S_IFREG &&
        info.st_size <= MAX_SNAPSHOT_BYTES ? _fdopen(fd, "rb") : NULL;
    if (!file)
        _close(fd);
#else
    int fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0)
        return NULL;
    struct stat info;
    FILE *file = fstat(fd, &info) == 0 && S_ISREG(info.st_mode) &&
        info.st_size <= MAX_SNAPSHOT_BYTES ? fdopen(fd, "rb") : NULL;
    if (!file)
        close(fd);
#endif
    return file;
}

static bool read_line(FILE *file, char *line, int capacity, size_t *remaining)
{
    if (!fgets(line, capacity, file))
        return false;
    size_t length = strlen(line);
    if (!length || length > *remaining || line[length - 1] != '\n')
        return false;
    *remaining -= length;
    line[--length] = '\0';
    if (length && line[length - 1] == '\r')
        line[length - 1] = '\0';
    return true;
}

typedef bool (*read_peer_fn)(char *const field[7], unsigned long long rx,
                            unsigned long long tx, unsigned long long handshake,
                            bool active, void *context);

static bool read_snapshot(const char *path, int64_t now, read_peer_fn read_peer, void *context)
{
    FILE *file = open_snapshot(path);
    if (!file)
        return false;

    char line[1024];
    size_t remaining = MAX_SNAPSHOT_BYTES;
    bool valid = read_line(file, line, sizeof(line), &remaining) && !strcmp(line, "WIREGUARD_STATUS_V1");
    bool complete = false;
    while (valid && read_line(file, line, sizeof(line), &remaining)) {
        if (!strcmp(line, "END")) {
            complete = true;
            break;
        }
        char *field[7];
        unsigned long long rx, tx, handshake;
        valid = split_row(line, field) && text_field(field[0], 15) && text_field(field[1], 12) &&
            text_field(field[2], 100) && text_field(field[3], 512) &&
            number(field[4], &rx) && number(field[5], &tx) && number(field[6], &handshake);
        if (!valid)
            break;

        bool active = handshake && now > 0 && handshake <= (uint64_t)now &&
            (uint64_t)now - handshake <= ACTIVE_SECONDS;
        if (!read_peer(field, rx, tx, handshake, active, context))
            break;
    }
    fclose(file);
    return complete;
}

struct json_state {
    char *out;
    size_t capacity;
    size_t size;
    size_t count;
    size_t online;
    size_t shown;
};

static bool write_peer_json(char *const field[7], unsigned long long rx,
                            unsigned long long tx, unsigned long long handshake,
                            bool active, void *context)
{
    struct json_state *json = context;
    ++json->count;
    json->online += active;
    if (json->shown == MAX_PEERS)
        return true;

    char since[32] = "null";
    if (handshake)
        snprintf(since, sizeof(since), "%llu", handshake);
    int width = snprintf(json->out + json->size, json->capacity - json->size,
        "%s{\"name\":\"%s · %s\",\"remote\":\"%s\",\"virtual_ip\":\"%s\","
        "\"rx_bytes\":%llu,\"tx_bytes\":%llu,\"since\":%s,\"online\":%s}",
        json->shown ? "," : "", field[0], field[1], field[2], field[3], rx, tx, since, active ? "true" : "false");
    if (width >= 0 && (size_t)width + 24 < json->capacity - json->size) {
        json->size += (size_t)width;
        ++json->shown;
    }
    return true;
}

size_t wireguard_status_json(char *out, size_t capacity, const char *path)
{
    if (!out || !capacity)
        return 0;
    if (!path)
        return status_only(out, capacity, "not_configured");
    if (capacity <= ROW_OFFSET + 32)
        return status_only(out, capacity, "unavailable");

    struct json_state json = { .out = out, .capacity = capacity, .size = ROW_OFFSET };
    if (!read_snapshot(path, time(NULL), write_peer_json, &json))
        return status_only(out, capacity, "unavailable");

    char prefix[ROW_OFFSET];
    int head = snprintf(prefix, sizeof(prefix), "{\"state\":\"available\",\"total\":%zu,\"active\":%zu,\"clients\":[",
                        json.count, json.online);
    if (head < 0 || (size_t)head >= sizeof(prefix))
        return 0;
    memmove(out + head, out + ROW_OFFSET, json.size - ROW_OFFSET);
    memcpy(out, prefix, (size_t)head);
    size_t size = (size_t)head + json.size - ROW_OFFSET;
    const char *end = json.count > json.shown ? "],\"truncated\":true}" : "]}";
    memcpy(out + size, end, strlen(end) + 1);
    return size + strlen(end);
}

struct counter_context {
    vpn_counter_fn read_counter;
    void *context;
};

static bool visit_counter(char *const field[7], unsigned long long rx,
                          unsigned long long tx, unsigned long long handshake,
                          bool active, void *context)
{
    (void)rx;
    (void)tx;
    (void)handshake;
    struct counter_context *visitor = context;
    struct vpn_counter counter = {
        .name = field[1], .remote = field[0], .virtual_ip = field[3],
        .since = field[6], .rx = field[4], .tx = field[5], .connected = active
    };
    return visitor->read_counter(&counter, visitor->context);
}

bool wireguard_status_counters(const char *path, int64_t now,
                               vpn_counter_fn read_counter, void *context)
{
    struct counter_context visitor = { .read_counter = read_counter, .context = context };
    return path && read_counter && read_snapshot(path, now, visit_counter, &visitor);
}
