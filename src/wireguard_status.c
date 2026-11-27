#include "wireguard_status.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

enum { ROW_OFFSET = 128, MAX_PEERS = 64, ACTIVE_SECONDS = 180 };

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

static bool read_line(FILE *file, char *line, int capacity)
{
    if (!fgets(line, capacity, file))
        return false;
    size_t length = strcspn(line, "\r\n");
    if (!line[length])
        return false;
    line[length] = '\0';
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

    FILE *file = fopen(path, "rb");
    if (!file)
        return status_only(out, capacity, "unavailable");

    char line[1024];
    bool valid = read_line(file, line, sizeof(line)) && !strcmp(line, "WIREGUARD_STATUS_V1");
    bool complete = false;
    size_t count = 0, online = 0, shown = 0, size = ROW_OFFSET;
    time_t now = time(NULL);
    while (valid && read_line(file, line, sizeof(line))) {
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

        bool active = handshake && now > 0 && handshake <= (unsigned long long)now &&
            (unsigned long long)now - handshake <= ACTIVE_SECONDS;
        ++count;
        online += active;
        if (shown == MAX_PEERS)
            continue;

        char since[32] = "null";
        if (handshake)
            snprintf(since, sizeof(since), "%llu", handshake);
        int width = snprintf(out + size, capacity - size,
            "%s{\"name\":\"%s · %s\",\"remote\":\"%s\",\"virtual_ip\":\"%s\","
            "\"rx_bytes\":%llu,\"tx_bytes\":%llu,\"since\":%s,\"online\":%s}",
            shown ? "," : "", field[0], field[1], field[2], field[3], rx, tx, since, active ? "true" : "false");
        if (width >= 0 && (size_t)width + 24 < capacity - size) {
            size += (size_t)width;
            ++shown;
        }
    }
    fclose(file);
    if (!complete)
        return status_only(out, capacity, "unavailable");

    char prefix[ROW_OFFSET];
    int head = snprintf(prefix, sizeof(prefix), "{\"state\":\"available\",\"total\":%zu,\"active\":%zu,\"clients\":[", count, online);
    if (head < 0 || (size_t)head >= sizeof(prefix))
        return 0;
    memmove(out + head, out + ROW_OFFSET, size - ROW_OFFSET);
    memcpy(out, prefix, (size_t)head);
    size = (size_t)head + size - ROW_OFFSET;
    const char *end = count > shown ? "],\"truncated\":true}" : "]}";
    memcpy(out + size, end, strlen(end) + 1);
    return size + strlen(end);
}
