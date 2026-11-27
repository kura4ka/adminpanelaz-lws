#if defined(__linux__) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "host_metrics.h"

#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

#ifdef __linux__
#include <errno.h>
#include <string.h>
#include <sys/statvfs.h>
#include <time.h>
#endif

struct json_writer {
    char *out;
    size_t capacity;
    size_t used;
    bool failed;
};

struct metric {
    uint64_t value;
    bool present;
};

static void append_json(struct json_writer *json, const char *format, ...)
{
    if (json->failed)
        return;

    size_t remaining = json->capacity - json->used;
    va_list args;
    va_start(args, format);
    int length = vsnprintf(json->out + json->used, remaining, format, args);
    va_end(args);
    if (length < 0 || (size_t)length >= remaining)
        json->failed = true;
    else
        json->used += (size_t)length;
}

static void append_metric(struct json_writer *json, const char *key, struct metric metric)
{
    append_json(json, ",\"%s\":", key);
    if (metric.present)
        append_json(json, "%" PRIu64, metric.value);
    else
        append_json(json, "null");
}

#ifdef __linux__
struct cpu_times {
    uint64_t total;
    uint64_t idle;
};

static bool read_cpu_times(struct cpu_times *times)
{
    FILE *file = fopen("/proc/stat", "r");
    if (!file)
        return false;

    uint64_t ticks[8] = {0};
    char line[512];
    int fields = 0;
    if (fgets(line, sizeof(line), file)) {
        fields = sscanf(line, "cpu %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64
                              " %" SCNu64 " %" SCNu64 " %" SCNu64 " %" SCNu64,
                        &ticks[0], &ticks[1], &ticks[2], &ticks[3], &ticks[4],
                        &ticks[5], &ticks[6], &ticks[7]);
    }
    fclose(file);
    if (fields < 4)
        return false;

    uint64_t total = 0;
    for (size_t i = 0; i < sizeof(ticks) / sizeof(ticks[0]); ++i) {
        if (ticks[i] > UINT64_MAX - total)
            return false;
        total += ticks[i];
    }
    *times = (struct cpu_times){ .total = total, .idle = ticks[3] + ticks[4] };
    return true;
}

static struct metric read_cpu_percent_tenths(void)
{
    static struct timespec last_attempt;
    static struct cpu_times previous;
    static struct metric cached;
    static bool attempted;
    static bool have_previous;

    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        return (struct metric){0};

    if (attempted) {
        time_t seconds = now.tv_sec - last_attempt.tv_sec;
        if (seconds < 2 || (seconds == 2 && now.tv_nsec < last_attempt.tv_nsec))
            return cached;
    }
    last_attempt = now;
    attempted = true;
    cached = (struct metric){0};

    struct cpu_times current;
    if (!read_cpu_times(&current))
        return cached;

    if (have_previous && current.total > previous.total && current.idle >= previous.idle) {
        uint64_t total = current.total - previous.total;
        uint64_t idle = current.idle - previous.idle;
        if (idle <= total) {
            long double busy = (long double)(total - idle) / total;
            cached = (struct metric){ (uint64_t)(busy * 1000 + 0.5L), true };
        }
    }
    previous = current;
    have_previous = true;
    return cached;
}

static void read_memory(struct metric *total, struct metric *used)
{
    FILE *file = fopen("/proc/meminfo", "r");
    if (!file)
        return;

    struct metric available = {0};
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        uint64_t kb;
        if (sscanf(line, "MemTotal: %" SCNu64, &kb) == 1 && kb <= UINT64_MAX / 1024)
            *total = (struct metric){ kb * 1024, true };
        else if (sscanf(line, "MemAvailable: %" SCNu64, &kb) == 1 && kb <= UINT64_MAX / 1024)
            available = (struct metric){ kb * 1024, true };
        if (total->present && available.present)
            break;
    }
    fclose(file);

    if (total->present && available.present && available.value <= total->value)
        *used = (struct metric){ total->value - available.value, true };
}

static void read_disk(const char *path, struct metric *total, struct metric *used)
{
    struct statvfs fs;
    if (!path || statvfs(path, &fs) != 0)
        return;

    uint64_t block_size = fs.f_frsize ? fs.f_frsize : fs.f_bsize;
    if (!block_size || fs.f_blocks > UINT64_MAX / block_size)
        return;

    *total = (struct metric){ fs.f_blocks * block_size, true };
    if (fs.f_bfree <= fs.f_blocks)
        *used = (struct metric){ (fs.f_blocks - fs.f_bfree) * block_size, true };
}

static struct metric read_uptime(void)
{
    struct metric uptime = {0};
    FILE *file = fopen("/proc/uptime", "r");
    if (file) {
        uptime.present = fscanf(file, "%" SCNu64, &uptime.value) == 1;
        fclose(file);
    }
    return uptime;
}

static struct metric read_tcp_established(void)
{
    struct metric result = {0};
    FILE *file = fopen("/proc/net/snmp", "r");
    if (!file)
        return result;

    char header[1024];
    char values[1024];
    while (fgets(header, sizeof(header), file)) {
        if (strncmp(header, "Tcp:", 4) != 0)
            continue;
        if (!fgets(values, sizeof(values), file) || strncmp(values, "Tcp:", 4) != 0)
            break;

        const char *space = " \t\r\n";
        char *header_state;
        char *value_state;
        char *key = strtok_r(header + 4, space, &header_state);
        char *value = strtok_r(values + 4, space, &value_state);
        while (key && value) {
            if (strcmp(key, "CurrEstab") == 0) {
                char *end;
                errno = 0;
                uintmax_t count = strtoumax(value, &end, 10);
                if (value[0] >= '0' && value[0] <= '9' && *end == '\0' &&
                    errno != ERANGE && count <= UINT64_MAX)
                    result = (struct metric){ (uint64_t)count, true };
                break;
            }
            key = strtok_r(NULL, space, &header_state);
            value = strtok_r(NULL, space, &value_state);
        }
        break;
    }
    fclose(file);
    return result;
}

static void append_interfaces(struct json_writer *json)
{
    static const char name_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-+@";
    FILE *file = fopen("/proc/net/dev", "r");
    if (!file)
        return;

    char line[512];
    unsigned int count = 0;
    while (count < 16 && !json->failed && fgets(line, sizeof(line), file)) {
        char *separator = strrchr(line, ':');
        if (!separator)
            continue;

        char *name = line + strspn(line, " \t");
        char *end = separator;
        while (end > name && (end[-1] == ' ' || end[-1] == '\t'))
            --end;
        *end = '\0';
        size_t length = (size_t)(end - name);
        if (!length || length > 15 || strspn(name, name_chars) != length)
            continue;

        uint64_t rx;
        uint64_t tx;
        if (sscanf(separator + 1, "%" SCNu64 " %*s %*s %*s %*s %*s %*s %*s %" SCNu64,
                   &rx, &tx) != 2)
            continue;

        append_json(json, "%s{\"name\":\"%s\",\"rx_bytes\":%" PRIu64 ",\"tx_bytes\":%" PRIu64 "}",
                    count ? "," : "", name, rx, tx);
        ++count;
    }
    fclose(file);
}
#endif

size_t host_metrics_json(char *out, size_t capacity, const char *data_path)
{
    if (!out || !capacity)
        return 0;

    struct json_writer json = { .out = out, .capacity = capacity };
    struct metric cpu = {0};
    struct metric memory_total = {0};
    struct metric memory_used = {0};
    struct metric disk_total = {0};
    struct metric disk_used = {0};
    struct metric uptime = {0};
    struct metric tcp_established = {0};

#ifdef __linux__
    cpu = read_cpu_percent_tenths();
    read_memory(&memory_total, &memory_used);
    read_disk(data_path, &disk_total, &disk_used);
    uptime = read_uptime();
    tcp_established = read_tcp_established();
#else
    (void)data_path;
#endif

    if (cpu.present)
        append_json(&json, "{\"cpu_percent\":%" PRIu64 ".%" PRIu64, cpu.value / 10, cpu.value % 10);
    else
        append_json(&json, "{\"cpu_percent\":null");
    append_metric(&json, "memory_total_bytes", memory_total);
    append_metric(&json, "memory_used_bytes", memory_used);
    append_metric(&json, "disk_total_bytes", disk_total);
    append_metric(&json, "disk_used_bytes", disk_used);
    append_metric(&json, "uptime_seconds", uptime);
    append_metric(&json, "tcp_established", tcp_established);
    append_json(&json, ",\"interfaces\":[");
#ifdef __linux__
    append_interfaces(&json);
#endif
    append_json(&json, "]}");

    if (json.failed) {
        out[0] = '\0';
        return 0;
    }
    return json.used;
}
