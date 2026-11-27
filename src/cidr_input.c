#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "cidr_input.h"

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
#include <sqlite3.h>

#include <string.h>

enum { MAX_LINE = 4096, MAX_LINES = 1000000, MAX_BYTES = 128 * 1024 * 1024, MAX_SOURCE = 64 };

static bool is_space(char ch)
{
    return ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' || ch == '\v' || ch == '\f';
}

static bool is_digit(char ch)
{
    return ch >= '0' && ch <= '9';
}

static bool dotted_address(const char *text, unsigned char out[4])
{
    for (const char *part = text; part; ) {
        if (part[0] == '0' && is_digit(part[1]))
            return false;
        part = strchr(part, '.');
        if (part)
            ++part;
    }
    return inet_pton(AF_INET, text, out) == 1;
}

static bool dotted_prefix(const char *text, unsigned int *prefix)
{
    unsigned char mask[4];
    if (!dotted_address(text, mask))
        return false;

    /* A nonzero mask starting with a zero bit can only be a host mask. */
    bool any_bit = mask[0] || mask[1] || mask[2] || mask[3];
    unsigned int invert = !(mask[0] & 0x80) && any_bit ? 0xffU : 0;
    unsigned int bits = 0;
    bool zero_seen = false;
    for (size_t i = 0; i < sizeof(mask); ++i) {
        unsigned int byte = mask[i] ^ invert;
        for (unsigned int bit = 0x80; bit; bit >>= 1) {
            if (!(byte & bit))
                zero_seen = true;
            else if (zero_seen)
                return false;
            else
                ++bits;
        }
    }
    *prefix = bits;
    return true;
}

static bool numeric_prefix(const char *text, unsigned int max, unsigned int *prefix)
{
    if (!*text)
        return false;
    unsigned int value = 0;
    for (; *text; ++text) {
        if (!is_digit(*text))
            return false;
        value = value * 10 + (unsigned int)(*text - '0');
        if (value > max)
            return false;
    }
    *prefix = value;
    return true;
}

static void mask_network(struct cidr_input_network *network)
{
    unsigned int byte = network->prefix / 8;
    unsigned int tail = network->prefix % 8;
    if (tail) {
        network->address[byte] &= (unsigned char)(0xffU << (8 - tail));
        ++byte;
    }
    memset(network->address + byte, 0, sizeof(network->address) - byte);
}

bool cidr_input_parse(const char *text, struct cidr_input_network *network)
{
    if (!text || !network)
        return false;
    while (is_space(*text))
        ++text;
    size_t length = strlen(text);
    while (length && is_space(text[length - 1]))
        --length;
    if (!length || length >= CIDR_INPUT_TEXT_SIZE)
        return false;

    char copy[CIDR_INPUT_TEXT_SIZE];
    memcpy(copy, text, length);
    copy[length] = '\0';
    char *prefix = strchr(copy, '/');
    if (prefix)
        *prefix++ = '\0';

    struct cidr_input_network parsed = {0};
    if (dotted_address(copy, parsed.address)) {
        parsed.family = 4;
        parsed.prefix = 32;
        if (prefix && !numeric_prefix(prefix, 32, &parsed.prefix) && !dotted_prefix(prefix, &parsed.prefix))
            return false;
    } else {
        if (strchr(copy, '%') || inet_pton(AF_INET6, copy, parsed.address) != 1)
            return false;
        const char *tail = strrchr(copy, ':');
        unsigned char ignored[4];
        if (strchr(copy, '.') && (!tail || !dotted_address(tail + 1, ignored)))
            return false;
        parsed.family = 6;
        parsed.prefix = 128;
        if (prefix && !numeric_prefix(prefix, 128, &parsed.prefix))
            return false;
    }
    mask_network(&parsed);
    *network = parsed;
    return true;
}

bool cidr_input_format(const struct cidr_input_network *network, char *out, size_t capacity)
{
    if (!out || !capacity)
        return false;
    out[0] = '\0';
    if (!network || (network->family != 4 && network->family != 6) ||
        network->prefix > (network->family == 4 ? 32U : 128U))
        return false;

    struct cidr_input_network masked = *network;
    mask_network(&masked);
    char address[CIDR_INPUT_TEXT_SIZE];
    if (!inet_ntop(masked.family == 4 ? AF_INET : AF_INET6, masked.address, address, sizeof(address)))
        return false;
    if (masked.family == 6 && strchr(address, '.')) {
        /* Render any dotted IPv6 suffix in hex, as upstream's ipaddress does. */
        char *tail = strrchr(address, ':') + 1;
        unsigned int high = (unsigned int)masked.address[12] << 8 | masked.address[13];
        unsigned int low = (unsigned int)masked.address[14] << 8 | masked.address[15];
        size_t space = sizeof(address) - (size_t)(tail - address);
        if (tail == address + 2 && high == 0)
            snprintf(tail, space, "%x", low);
        else
            snprintf(tail, space, "%x:%x", high, low);
    }
    int size = snprintf(out, capacity, "%s/%u", address, masked.prefix);
    if (size < 0 || (size_t)size >= capacity) {
        out[0] = '\0';
        return false;
    }
    return true;
}

static enum cidr_input_status read_network(FILE *stream, struct cidr_input_network *network, size_t *bytes)
{
    char line[MAX_LINE + 1];
    size_t length = 0;
    int ch;
    *bytes = 0;
    while ((ch = fgetc(stream)) != EOF) {
        ++*bytes;
        if (ch == '\n')
            break;
        if (length == MAX_LINE)
            return CIDR_INPUT_TRUNCATED;
        if (!ch)
            return CIDR_INPUT_INVALID;
        line[length++] = (char)ch;
    }
    if (ch == EOF) {
        if (ferror(stream))
            return CIDR_INPUT_READ_ERROR;
        if (!length)
            return CIDR_INPUT_EOF;
    }

    line[length] = '\0';
    char *comment = strchr(line, '#');
    if (comment)
        *comment = '\0';
    const char *text = line;
    while (is_space(*text))
        ++text;
    if (!*text)
        return CIDR_INPUT_SKIP;
    return cidr_input_parse(text, network) ? CIDR_INPUT_OK : CIDR_INPUT_INVALID;
}

enum cidr_input_status cidr_input_next(FILE *stream, struct cidr_input_network *network)
{
    size_t bytes;
    return stream && network ? read_network(stream, network, &bytes) : CIDR_INPUT_INVALID;
}

static bool execute(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

bool cidr_input_prepare(sqlite3 *db)
{
    static const char schema[] =
        "CREATE TABLE IF NOT EXISTS main.cidr_input_networks ("
        " source TEXT NOT NULL, family INTEGER NOT NULL, address BLOB NOT NULL, prefix INTEGER NOT NULL,"
        " CHECK(typeof(address)='blob' AND typeof(family)='integer' AND typeof(prefix)='integer'"
        " AND ((family=4 AND length(address)=4 AND prefix BETWEEN 0 AND 32)"
        " OR (family=6 AND length(address)=16 AND prefix BETWEEN 0 AND 128))),"
        " PRIMARY KEY(source, family, address, prefix)) WITHOUT ROWID";
    return db && execute(db, schema);
}

static bool publish_source(sqlite3 *db, const char *source)
{
    static const char *const statements[] = {
        "DELETE FROM main.cidr_input_networks WHERE source=?",
        "INSERT INTO main.cidr_input_networks (source, family, address, prefix)"
        " SELECT ?, family, address, prefix FROM temp.apaz_cidr_input_stage"
    };
    if (!cidr_input_prepare(db))
        return false;
    for (size_t i = 0; i < sizeof(statements) / sizeof(statements[0]); ++i) {
        sqlite3_stmt *statement = NULL;
        bool success = sqlite3_prepare_v2(db, statements[i], -1, &statement, NULL) == SQLITE_OK &&
                       sqlite3_bind_text(statement, 1, source, -1, SQLITE_STATIC) == SQLITE_OK &&
                       sqlite3_step(statement) == SQLITE_DONE;
        sqlite3_finalize(statement);
        if (!success)
            return false;
    }
    return true;
}

static enum cidr_input_status stage_source(sqlite3 *db, FILE *stream, enum cidr_input_policy policy,
                                           cidr_input_cancel_fn cancel, void *context,
                                           struct cidr_input_report *report, size_t *unique)
{
    static const char stage_sql[] =
        "CREATE TEMP TABLE apaz_cidr_input_stage (family INTEGER NOT NULL, address BLOB NOT NULL,"
        " prefix INTEGER NOT NULL, PRIMARY KEY(family, address, prefix)) WITHOUT ROWID";
    static const char insert_sql[] =
        "INSERT INTO temp.apaz_cidr_input_stage (family, address, prefix) VALUES (?, ?, ?)"
        " ON CONFLICT(family, address, prefix) DO NOTHING";
    sqlite3_stmt *insert = NULL;
    enum cidr_input_status status = CIDR_INPUT_DATABASE_ERROR;
    if (!execute(db, stage_sql) || sqlite3_prepare_v2(db, insert_sql, -1, &insert, NULL) != SQLITE_OK) {
        sqlite3_finalize(insert);
        return status;
    }

    size_t total_bytes = 0;
    for (;;) {
        if (cancel && cancel(context)) {
            status = CIDR_INPUT_CANCELLED;
            break;
        }
        struct cidr_input_network network;
        size_t bytes;
        status = read_network(stream, &network, &bytes);
        if (status == CIDR_INPUT_EOF) {
            status = *unique ? CIDR_INPUT_OK : CIDR_INPUT_EMPTY;
            break;
        }
        ++report->lines;
        total_bytes += bytes;
        if (report->lines > MAX_LINES || total_bytes > MAX_BYTES) {
            status = CIDR_INPUT_LIMIT;
            break;
        }
        if (status == CIDR_INPUT_SKIP) {
            ++report->ignored;
            continue;
        }
        if (status != CIDR_INPUT_OK)
            break;
        if (policy == CIDR_INPUT_UPSTREAM_IPV4 && (network.family != 4 || !network.prefix)) {
            ++report->policy_skipped;
            continue;
        }
        if (sqlite3_reset(insert) != SQLITE_OK ||
            sqlite3_bind_int(insert, 1, (int)network.family) != SQLITE_OK ||
            sqlite3_bind_blob(insert, 2, network.address, network.family == 4 ? 4 : 16, SQLITE_TRANSIENT) != SQLITE_OK ||
            sqlite3_bind_int(insert, 3, (int)network.prefix) != SQLITE_OK ||
            sqlite3_step(insert) != SQLITE_DONE) {
            status = CIDR_INPUT_DATABASE_ERROR;
            break;
        }
        if (sqlite3_changes(db))
            ++*unique;
        else
            ++report->duplicates;
    }
    if (status != CIDR_INPUT_OK && status != CIDR_INPUT_EMPTY && status != CIDR_INPUT_CANCELLED)
        report->error_line = report->lines;
    sqlite3_finalize(insert);
    return status;
}

enum cidr_input_status cidr_input_import(sqlite3 *db, const char *source, FILE *stream,
                                        enum cidr_input_policy policy, cidr_input_cancel_fn cancel,
                                        void *context, struct cidr_input_report *report)
{
    struct cidr_input_report local = {0};
    if (!report)
        report = &local;
    else
        *report = local;
    if (!db || !source || !source[0] || strlen(source) > MAX_SOURCE || !stream ||
        (policy != CIDR_INPUT_DUAL_STACK && policy != CIDR_INPUT_UPSTREAM_IPV4))
        return CIDR_INPUT_INVALID;
    if (cancel && cancel(context))
        return CIDR_INPUT_CANCELLED;
    if (!execute(db, "SAVEPOINT apaz_cidr_input_import"))
        return CIDR_INPUT_DATABASE_ERROR;

    size_t unique = 0;
    enum cidr_input_status status = stage_source(db, stream, policy, cancel, context, report, &unique);
    if (status == CIDR_INPUT_OK) {
        if (cancel && cancel(context))
            status = CIDR_INPUT_CANCELLED;
        else if (!publish_source(db, source) || !execute(db, "DROP TABLE temp.apaz_cidr_input_stage"))
            status = CIDR_INPUT_DATABASE_ERROR;
        else if (cancel && cancel(context))
            status = CIDR_INPUT_CANCELLED;
        else if (!execute(db, "RELEASE apaz_cidr_input_import"))
            status = CIDR_INPUT_DATABASE_ERROR;
    }
    if (status == CIDR_INPUT_OK) {
        report->published = unique;
    } else {
        execute(db, "ROLLBACK TO apaz_cidr_input_import; RELEASE apaz_cidr_input_import");
    }
    return status;
}
