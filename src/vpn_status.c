#ifndef _WIN32
#define _POSIX_C_SOURCE 200809L
#endif

#include "vpn_status.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <io.h>
#define open_read_only(path) _open(path, _O_RDONLY | _O_BINARY | _O_NOINHERIT)
#define status_stat struct _stat
#define status_fstat _fstat
#define regular_file(mode) (((mode) & _S_IFMT) == _S_IFREG)
#define stream_from_fd _fdopen
#define close_fd _close
#else
#include <unistd.h>
#define open_read_only(path) open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
#define status_stat struct stat
#define status_fstat fstat
#define regular_file(mode) S_ISREG(mode)
#define stream_from_fd fdopen
#define close_fd close
#endif

enum {
    MAX_CLIENTS = 64,
    MAX_FIELDS = 64,
    MAX_LINE = 4096,
    MAX_STATUS_BYTES = 4 * 1024 * 1024,
    JSON_SUFFIX_SPACE = sizeof("],\"total\":,\"truncated\":false}") + 3 * sizeof(size_t)
};

struct status_reader {
    FILE *file;
    char buffer[4096];
    size_t offset;
    size_t end;
    size_t remaining;
};

enum line_result { LINE_END, LINE_VALID, LINE_INVALID };

struct json_buffer {
    char *text;
    size_t capacity;
    size_t used;
    bool overflow;
};

struct client_columns {
    size_t name;
    size_t remote;
    size_t virtual_ipv4;
    size_t virtual_ipv6;
    size_t received;
    size_t sent;
    size_t since;
};

struct client_list {
    size_t total;
    size_t shown;
    bool full;
};

static FILE *open_status_file(const char *path)
{
    int fd = open_read_only(path);
    if (fd < 0)
        return NULL;

    status_stat info;
    FILE *file = NULL;
    if (status_fstat(fd, &info) == 0 && regular_file(info.st_mode))
        file = stream_from_fd(fd, "rb");
    if (!file)
        close_fd(fd);
    return file;
}

static enum line_result read_line(struct status_reader *reader, char line[MAX_LINE])
{
    size_t used = 0;
    bool invalid = false;
    for (;;) {
        if (reader->offset == reader->end) {
            if (!reader->remaining)
                return LINE_END;
            size_t requested = reader->remaining < sizeof(reader->buffer)
                                   ? reader->remaining : sizeof(reader->buffer);
            reader->offset = 0;
            reader->end = fread(reader->buffer, 1, requested, reader->file);
            if (!reader->end) {
                if (!used || ferror(reader->file))
                    return LINE_END;
                break;
            }
            reader->remaining -= reader->end;
        }

        const char *begin = reader->buffer + reader->offset;
        size_t available = reader->end - reader->offset;
        const char *newline = memchr(begin, '\n', available);
        size_t length = newline ? (size_t)(newline - begin) : available;
        size_t room = MAX_LINE - used - 1;
        size_t copied = length < room ? length : room;
        if (copied < length || memchr(begin, '\0', copied))
            invalid = true;
        memcpy(line + used, begin, copied);
        used += copied;
        reader->offset += length;
        if (newline) {
            ++reader->offset;
            break;
        }
    }

    if (used && line[used - 1] == '\r')
        --used;
    line[used] = '\0';
    return invalid ? LINE_INVALID : LINE_VALID;
}

static size_t split_fields(char *line, char separator, char *fields[MAX_FIELDS])
{
    size_t count = 0;
    while (count < MAX_FIELDS) {
        fields[count++] = line;
        char *next = strchr(line, separator);
        if (!next)
            break;
        *next = '\0';
        line = next + 1;
    }
    return count;
}

static size_t find_column(char *const fields[], size_t count, const char *name)
{
    for (size_t i = 0; i < count; ++i) {
        if (!strcmp(fields[i], name))
            return i;
    }
    return MAX_FIELDS;
}

static bool map_columns(struct client_columns *columns, char *const fields[], size_t count)
{
    *columns = (struct client_columns) {
        .name = find_column(fields, count, "Common Name"),
        .remote = find_column(fields, count, "Real Address"),
        .virtual_ipv4 = find_column(fields, count, "Virtual Address"),
        .virtual_ipv6 = find_column(fields, count, "Virtual IPv6 Address"),
        .received = find_column(fields, count, "Bytes Received"),
        .sent = find_column(fields, count, "Bytes Sent"),
        .since = find_column(fields, count, "Connected Since")
    };
    return columns->name < count && columns->remote < count &&
           columns->received < count && columns->sent < count && columns->since < count;
}

static const char *field_value(char *const fields[], size_t count, size_t index)
{
    return index < count && fields[index][0] ? fields[index] : NULL;
}

static void append_bytes(struct json_buffer *out, const char *value, size_t length)
{
    if (length >= out->capacity - out->used)
        out->overflow = true;
    if (!out->overflow) {
        memcpy(out->text + out->used, value, length);
        out->used += length;
    }
}

static void append_text(struct json_buffer *out, const char *value)
{
    append_bytes(out, value, strlen(value));
}

static size_t utf8_length(const unsigned char *text, size_t remaining)
{
    unsigned char lead = text[0];
    if (lead < 0xc2 || lead > 0xf4)
        return 0;
    size_t length = lead < 0xe0 ? 2 : (lead < 0xf0 ? 3 : 4);
    if (remaining < length)
        return 0;
    for (size_t i = 1; i < length; ++i) {
        if (text[i] < 0x80 || text[i] > 0xbf)
            return 0;
    }
    if ((lead == 0xe0 && text[1] < 0xa0) || (lead == 0xed && text[1] >= 0xa0) ||
        (lead == 0xf0 && text[1] < 0x90) || (lead == 0xf4 && text[1] >= 0x90))
        return 0;
    return length;
}

static void append_string(struct json_buffer *out, const char *value)
{
    if (!value) {
        append_text(out, "null");
        return;
    }
    static const char hex[] = "0123456789abcdef";
    append_text(out, "\"");
    size_t length = strlen(value);
    for (size_t i = 0; i < length && !out->overflow;) {
        unsigned char c = (unsigned char)value[i];
        if (c == '"' || c == '\\') {
            char escaped[] = { '\\', (char)c };
            append_bytes(out, escaped, sizeof(escaped));
        } else if (c < 0x20) {
            char escaped[] = { '\\', 'u', '0', '0', hex[c >> 4], hex[c & 0xf] };
            append_bytes(out, escaped, sizeof(escaped));
        } else if (c < 0x80) {
            append_bytes(out, value + i, 1);
        } else {
            size_t size = utf8_length((const unsigned char *)value + i, length - i);
            if (size) {
                append_bytes(out, value + i, size);
                i += size;
                continue;
            }
            append_text(out, "\\ufffd");
        }
        ++i;
    }
    append_text(out, "\"");
}

static void append_counter(struct json_buffer *out, const char *value)
{
    if (value && value[strspn(value, "0123456789")] == '\0') {
        errno = 0;
        unsigned long long parsed = strtoull(value, NULL, 10);
        if (!errno) {
            char decimal[3 * sizeof(parsed) + 1];
            snprintf(decimal, sizeof(decimal), "%llu", parsed);
            append_text(out, decimal);
            return;
        }
    }
    append_text(out, "null");
}

static void append_client(struct json_buffer *out, struct client_list *clients,
                          const struct client_columns *columns, char *const fields[], size_t count)
{
    if (clients->full || clients->shown == MAX_CLIENTS || columns->name >= count ||
        columns->remote >= count || columns->received >= count || columns->sent >= count ||
        columns->since >= count)
        return;

    size_t previous = out->used;
    append_text(out, clients->shown ? ",{\"name\":" : "{\"name\":");
    append_string(out, field_value(fields, count, columns->name));
    append_text(out, ",\"remote\":");
    append_string(out, field_value(fields, count, columns->remote));
    append_text(out, ",\"virtual_ip\":");
    const char *virtual_ip = field_value(fields, count, columns->virtual_ipv4);
    append_string(out, virtual_ip ? virtual_ip : field_value(fields, count, columns->virtual_ipv6));
    append_text(out, ",\"rx_bytes\":");
    append_counter(out, field_value(fields, count, columns->received));
    append_text(out, ",\"tx_bytes\":");
    append_counter(out, field_value(fields, count, columns->sent));
    append_text(out, ",\"since\":");
    append_string(out, field_value(fields, count, columns->since));
    append_text(out, "}");

    if (out->overflow || out->capacity - out->used < JSON_SUFFIX_SPACE) {
        out->used = previous;
        out->overflow = false;
        clients->full = true;
        return;
    }
    ++clients->shown;
}

static bool read_snapshot(FILE *file, struct json_buffer *out, struct client_list *clients)
{
    struct status_reader reader = { .file = file, .remaining = MAX_STATUS_BYTES };
    struct client_columns columns;
    char line[MAX_LINE];
    char *fields[MAX_FIELDS];
    char delimiter = '\0';
    bool version_one = false;
    bool valid_header = false;
    bool in_client_list = false;

    for (;;) {
        enum line_result result = read_line(&reader, line);
        if (result == LINE_END)
            return false;
        if (result == LINE_VALID && !strcmp(line, "END"))
            return valid_header;

        if (!valid_header) {
            if (result != LINE_VALID)
                continue;
            if (!strcmp(line, "OpenVPN CLIENT LIST")) {
                version_one = true;
                delimiter = ',';
            } else if (version_one && !strncmp(line, "Common Name,", 12)) {
                size_t count = split_fields(line, delimiter, fields);
                valid_header = map_columns(&columns, fields, count);
            } else if (!version_one && !strncmp(line, "HEADER", 6) &&
                       (line[6] == ',' || line[6] == '\t')) {
                delimiter = line[6];
                size_t count = split_fields(line, delimiter, fields);
                if (count > 2 && !strcmp(fields[1], "CLIENT_LIST"))
                    valid_header = map_columns(&columns, fields + 2, count - 2);
            }
            in_client_list = valid_header;
            continue;
        }

        if (version_one && result == LINE_VALID &&
            (!strcmp(line, "ROUTING TABLE") || !strcmp(line, "GLOBAL STATS")))
            in_client_list = false;
        if (!in_client_list || !line[0] ||
            (!version_one && (strncmp(line, "CLIENT_LIST", 11) || line[11] != delimiter)))
            continue;

        ++clients->total;
        if (result == LINE_VALID && !clients->full && clients->shown < MAX_CLIENTS) {
            size_t count = split_fields(version_one ? line : line + 12, delimiter, fields);
            append_client(out, clients, &columns, fields, count);
        }
    }
}

size_t vpn_statuses_json(char *out, size_t capacity, const char *const *paths, size_t count)
{
    if (!out || !capacity)
        return 0;

    struct json_buffer json = { .text = out, .capacity = capacity };
    struct client_list clients = { 0 };
    bool configured = false;
    bool available = false;
    append_text(&json, "{\"state\":\"available\",\"clients\":[");
    for (size_t i = 0; paths && i < count && !json.overflow; ++i) {
        if (!paths[i])
            continue;
        configured = true;
        FILE *file = open_status_file(paths[i]);
        if (!file)
            continue;
        struct json_buffer previous_json = json;
        struct client_list previous_clients = clients;
        if (read_snapshot(file, &json, &clients)) {
            available = true;
        } else {
            json = previous_json;
            clients = previous_clients;
        }
        fclose(file);
    }

    if (available) {
        char suffix[JSON_SUFFIX_SPACE];
        snprintf(suffix, sizeof(suffix), "],\"total\":%zu,\"truncated\":%s}",
                 clients.total, clients.shown < clients.total ? "true" : "false");
        append_text(&json, suffix);
    } else {
        json.used = 0;
        json.overflow = false;
        append_text(&json, configured ? "{\"state\":\"unavailable\"" : "{\"state\":\"not_configured\"");
        append_text(&json, ",\"clients\":[],\"total\":0,\"truncated\":false}");
    }

    if (json.overflow)
        json.used = 0;
    out[json.used] = '\0';
    return json.used;
}
