#ifndef CIDR_INPUT_H
#define CIDR_INPUT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

typedef struct sqlite3 sqlite3;

enum { CIDR_INPUT_ADDRESS_SIZE = 16, CIDR_INPUT_TEXT_SIZE = 64 };

struct cidr_input_network {
    unsigned char address[CIDR_INPUT_ADDRESS_SIZE];
    unsigned int family; /* 4 or 6 */
    unsigned int prefix;
};

enum cidr_input_status {
    CIDR_INPUT_OK,
    CIDR_INPUT_EOF,
    CIDR_INPUT_SKIP,
    CIDR_INPUT_INVALID,
    CIDR_INPUT_TRUNCATED,
    CIDR_INPUT_READ_ERROR,
    CIDR_INPUT_LIMIT,
    CIDR_INPUT_EMPTY,
    CIDR_INPUT_CANCELLED,
    CIDR_INPUT_DATABASE_ERROR
};

enum cidr_input_policy { CIDR_INPUT_DUAL_STACK, CIDR_INPUT_UPSTREAM_IPV4 };

struct cidr_input_report {
    size_t lines;
    size_t ignored;
    size_t policy_skipped;
    size_t duplicates;
    size_t published;
    size_t error_line;
};

typedef bool (*cidr_input_cancel_fn)(void *context);

/* Creates the table shared by the input CLI and controller. */
bool cidr_input_prepare(sqlite3 *db);

bool cidr_input_parse(const char *text, struct cidr_input_network *network);
bool cidr_input_format(const struct cidr_input_network *network, char *out, size_t capacity);

/* Reads one line. After a fatal status, the stream may be partway through that line. */
enum cidr_input_status cidr_input_next(FILE *stream, struct cidr_input_network *network);

/* Replaces one source's rows in main.cidr_input_networks. Empty or rejected
 * input leaves the source intact. The caller owns both handles, opens the
 * stream in binary mode, and serializes access to db. A cancel callback must
 * not access db. */
enum cidr_input_status cidr_input_import(sqlite3 *db, const char *source, FILE *stream,
                                        enum cidr_input_policy policy, cidr_input_cancel_fn cancel,
                                        void *context, struct cidr_input_report *report);

#endif
