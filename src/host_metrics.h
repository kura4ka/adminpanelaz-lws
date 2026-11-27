#ifndef HOST_METRICS_H
#define HOST_METRICS_H

#include <stddef.h>

/* Writes a NUL-terminated JSON object and returns its length, or 0 on failure.
 * Call from the server event loop, which shares the CPU sampler across clients. */
size_t host_metrics_json(char *out, size_t capacity, const char *data_path);

#endif
