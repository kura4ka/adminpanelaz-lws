#ifndef HOST_METRICS_H
#define HOST_METRICS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct host_metric {
    uint64_t value;
    bool present;
};

struct host_resources {
    struct host_metric cpu_tenths;
    struct host_metric memory_total;
    struct host_metric memory_used;
    struct host_metric disk_total;
    struct host_metric disk_used;
};

void host_metrics_resources(const char *data_path, struct host_resources *out);

/* Writes a NUL-terminated JSON object and returns its length, or 0 on failure.
 * Call from the server event loop, which shares the CPU sampler across clients. */
size_t host_metrics_json(char *out, size_t capacity, const char *data_path);

#endif
