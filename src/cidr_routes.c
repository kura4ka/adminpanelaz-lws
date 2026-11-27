#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif

#include "cidr_routes.h"
#include "cidr_input.h"

#include <sqlite3.h>

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#include <fcntl.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

enum {
    SOURCE_LENGTH = 64, MAX_SOURCES = 256, MAX_BUILD_ROWS = 1000000,
    MAX_RESULT_FILE = 8 * 1024 * 1024
};

struct route_source {
    char name[SOURCE_LENGTH + 1];
    size_t input_rows;
    size_t routes;
    size_t selected;
    double fractional;
    bool default_route;
};

struct route_plan {
    struct route_source sources[MAX_SOURCES];
    size_t count;
    size_t input_rows;
    size_t routes;
    size_t budget;
};

struct route_builder {
    sqlite3_stmt *insert;
    struct route_plan *plan;
    struct route_source *source;
    uint64_t *heap;
    size_t buffered;
};

static const char schema[] =
    "CREATE TABLE IF NOT EXISTS main.cidr_route_snapshots ("
    " id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL, budget INTEGER NOT NULL);"
    "CREATE TABLE IF NOT EXISTS main.cidr_route_lists ("
    " revision INTEGER NOT NULL REFERENCES cidr_route_snapshots(id) ON DELETE CASCADE,"
    " source TEXT NOT NULL, address INTEGER NOT NULL, prefix INTEGER NOT NULL,"
    " CHECK(address BETWEEN 0 AND 4294967295 AND prefix BETWEEN 0 AND 32),"
    " PRIMARY KEY(revision, source, address, prefix)) WITHOUT ROWID;";

static bool execute(sqlite3 *db, const char *sql)
{
    return sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK;
}

static bool safe_source(const char *source)
{
    if (!source || !source[0] || strlen(source) > SOURCE_LENGTH)
        return false;
    static const char letters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    return strchr(letters, source[0]) &&
           source[strspn(source, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-.")] == '\0';
}

static bool open_database(const char *path, bool write, sqlite3 **db)
{
    int flags = write ? SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE : SQLITE_OPEN_READONLY;
#ifdef SQLITE_OPEN_NOFOLLOW
    flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    return sqlite3_open_v2(path, db, flags, NULL) == SQLITE_OK &&
           sqlite3_busy_timeout(*db, 100) == SQLITE_OK &&
           execute(*db, "PRAGMA trusted_schema=OFF; PRAGMA foreign_keys=ON; PRAGMA cache_size=-256;"
                        " PRAGMA temp_store=FILE; PRAGMA temp.cache_size=-256;");
}

static size_t configured_limit(const char *name, size_t fallback)
{
    const char *setting = getenv(name);
    if (!setting || !*setting || setting[strspn(setting, "0123456789")])
        return fallback;
    size_t limit = 0;
    for (; *setting; ++setting) {
        limit = limit * 10 + (size_t)(*setting - '0');
        if (limit > CIDR_ROUTES_MAX_BUDGET)
            return CIDR_ROUTES_MAX_BUDGET;
    }
    return limit ? limit : fallback;
}

static size_t default_budget(void)
{
    size_t configured = configured_limit("OPENVPN_ROUTE_TOTAL_CIDR_LIMIT", 1500);
    size_t ios = configured_limit("OPENVPN_ROUTE_TOTAL_CIDR_LIMIT_MAX_IOS", 900);
    return configured < ios ? configured : ios;
}

static int error_reply(FILE *output, int status, const char *reason)
{
    fprintf(output, "{\"state\":\"error\",\"error\":\"%s\"}\n", reason);
    return status;
}

static int database_failure(sqlite3 *db, FILE *output)
{
    int code = db ? sqlite3_errcode(db) : SQLITE_ERROR;
    if (code == SQLITE_BUSY || code == SQLITE_LOCKED)
        return error_reply(output, 409, "operation_in_progress");
    return error_reply(output, 500, "cidr_database_error");
}

static bool bind_source(sqlite3_stmt *statement, int parameter, const char *source)
{
    return (source ? sqlite3_bind_text(statement, parameter, source, -1, SQLITE_STATIC)
                   : sqlite3_bind_null(statement, parameter)) == SQLITE_OK;
}

/* SQLite database errors roll back whenever an operation exits with its
 * transaction still open and the request closes the connection. */
static int import_source(sqlite3 *db, const char *source, FILE *input, FILE *output)
{
    if (!source || !input)
        return error_reply(output, 400, "invalid_source");
    if (fseek(input, 0L, SEEK_END) != 0)
        return error_reply(output, 500, "cannot_read_import");
    long size = ftell(input);
    if (size < 0 || fseek(input, 0L, SEEK_SET) != 0)
        return error_reply(output, 500, "cannot_read_import");
    if (size > CIDR_ROUTES_MAX_IMPORT)
        return error_reply(output, 413, "import_limit");
    if (!execute(db, "BEGIN IMMEDIATE"))
        return database_failure(db, output);

    static const char capacity_sql[] =
        "SELECT count(*) FROM (SELECT DISTINCT source FROM main.cidr_input_networks WHERE source <> ?1)";
    sqlite3_stmt *capacity = NULL;
    bool counted = sqlite3_prepare_v2(db, capacity_sql, -1, &capacity, NULL) == SQLITE_OK &&
                   bind_source(capacity, 1, source) && sqlite3_step(capacity) == SQLITE_ROW;
    int sources = counted ? sqlite3_column_int(capacity, 0) : 0;
    sqlite3_finalize(capacity);
    if (!counted)
        return database_failure(db, output);
    if (sources >= MAX_SOURCES)
        return error_reply(output, 409, "source_limit");

    struct cidr_input_report report;
    enum cidr_input_status imported = cidr_input_import(db, source, input, CIDR_INPUT_UPSTREAM_IPV4,
                                                        NULL, NULL, &report);
    switch (imported) {
    case CIDR_INPUT_OK:
        if (!execute(db, "COMMIT"))
            return database_failure(db, output);
        break;
    case CIDR_INPUT_LIMIT:
        return error_reply(output, 413, "import_limit");
    case CIDR_INPUT_DATABASE_ERROR:
        return database_failure(db, output);
    case CIDR_INPUT_READ_ERROR:
        return error_reply(output, 500, "cannot_read_import");
    default:
        break;
    }
    const char *state = imported == CIDR_INPUT_OK ? "ok" :
                        imported == CIDR_INPUT_EMPTY ? "empty" : "invalid";
    fprintf(output, "{\"state\":\"%s\",\"source\":\"%s\",\"lines\":%zu,\"ignored\":%zu,"
                    "\"policy_skipped\":%zu,\"duplicates\":%zu,\"published\":%zu,\"error_line\":%zu}\n",
            state, source, report.lines, report.ignored, report.policy_skipped,
            report.duplicates, report.published, report.error_line);
    return imported == CIDR_INPUT_OK ? 200 : 422;
}

static bool stage_route(sqlite3_stmt *insert, const char *source, uint64_t key)
{
    return sqlite3_reset(insert) == SQLITE_OK && bind_source(insert, 1, source) &&
           sqlite3_bind_int64(insert, 2, (sqlite3_int64)(uint32_t)key) == SQLITE_OK &&
           sqlite3_bind_int(insert, 3, (int)(key >> 32)) == SQLITE_OK && sqlite3_step(insert) == SQLITE_DONE;
}

/* Keep the worst retained route at the root. Selecting the broadest routes
 * then uses memory proportional to the configured budget. */
static void choose_route(struct route_builder *builder, uint64_t key)
{
    uint64_t *heap = builder->heap;
    size_t index;
    if (builder->buffered < builder->source->selected) {
        index = builder->buffered++;
        while (index && heap[(index - 1) / 2] < key) {
            heap[index] = heap[(index - 1) / 2];
            index = (index - 1) / 2;
        }
    } else {
        if (key >= heap[0])
            return;
        index = 0;
        while (index * 2 + 1 < builder->buffered) {
            size_t child = index * 2 + 1;
            if (child + 1 < builder->buffered && heap[child] < heap[child + 1])
                ++child;
            if (heap[child] <= key)
                break;
            heap[index] = heap[child];
            index = child;
        }
    }
    heap[index] = key;
}

static bool insert_range(struct route_builder *builder, uint64_t start, uint64_t end)
{
    /* Emit the largest aligned block at each offset of the exact union. Use
     * 64-bit lengths so full IPv4 space is representable without wraparound. */
    while (start <= end) {
        unsigned int prefix = 32;
        uint64_t length = 1;
        while (prefix && (start & ((length << 1) - 1)) == 0 && (length << 1) <= end - start + 1) {
            --prefix;
            length <<= 1;
        }
        uint64_t key = (uint64_t)prefix << 32 | start;
        if (!builder->insert) {
            ++builder->source->routes;
            ++builder->plan->routes;
            builder->source->default_route = builder->source->default_route || !prefix;
        } else if (builder->source->selected == builder->source->routes) {
            if (!stage_route(builder->insert, builder->source->name, key))
                return false;
        } else if (builder->source->selected) {
            choose_route(builder, key);
        }
        start += length;
    }
    return true;
}

static bool finish_source(struct route_builder *builder, uint64_t start, uint64_t end)
{
    if (!builder->source)
        return true;
    if (!insert_range(builder, start, end))
        return false;
    for (size_t i = 0; i < builder->buffered; ++i) {
        if (!stage_route(builder->insert, builder->source->name, builder->heap[i]))
            return false;
    }
    builder->buffered = 0;
    return true;
}

enum plan_result { PLAN_OK, PLAN_DATABASE_ERROR, PLAN_TOO_LARGE, PLAN_INVALID_DATA };

static enum plan_result build_plan(sqlite3 *db, const char *source, bool stage, struct route_plan *plan)
{
    static const char select_all[] =
        "SELECT source, address, prefix FROM main.cidr_input_networks WHERE family=4 AND prefix>0"
        " ORDER BY source, address, prefix";
    static const char select_source[] =
        "SELECT source, address, prefix FROM main.cidr_input_networks WHERE source=?1 AND family=4 AND prefix>0"
        " ORDER BY source, address, prefix";
    static const char stage_sql[] =
        "CREATE TEMP TABLE cidr_route_stage (source TEXT NOT NULL, address INTEGER NOT NULL, prefix INTEGER NOT NULL,"
        " PRIMARY KEY(source, address, prefix)) WITHOUT ROWID;";
    sqlite3_stmt *query = NULL;
    struct route_builder builder = {.plan = plan};
    enum plan_result result = PLAN_DATABASE_ERROR;
    if (sqlite3_prepare_v2(db, source ? select_source : select_all, -1, &query, NULL) != SQLITE_OK ||
        (source && !bind_source(query, 1, source)) ||
        (stage && (!execute(db, stage_sql) || sqlite3_prepare_v2(db,
         "INSERT INTO temp.cidr_route_stage VALUES (?, ?, ?)", -1, &builder.insert, NULL) != SQLITE_OK)))
        goto finish;
    if (stage) {
        builder.heap = malloc(plan->budget * sizeof(*builder.heap));
        if (!builder.heap)
            goto finish;
    }

    size_t source_index = 0, seen_rows = 0;
    uint64_t start = 0, end = 0;
    int step;
    while ((step = sqlite3_step(query)) == SQLITE_ROW) {
        if (++seen_rows > MAX_BUILD_ROWS) {
            result = PLAN_TOO_LARGE;
            goto finish;
        }
        const char *name = (const char *)sqlite3_column_text(query, 0);
        const unsigned char *address = sqlite3_column_blob(query, 1);
        int prefix = sqlite3_column_int(query, 2);
        if (!safe_source(name) || sqlite3_column_bytes(query, 0) != (int)strlen(name) ||
            !address || sqlite3_column_bytes(query, 1) != 4 || prefix < 1 || prefix > 32) {
            result = PLAN_INVALID_DATA;
            goto finish;
        }
        uint64_t next = (uint64_t)address[0] << 24 | (uint64_t)address[1] << 16 |
                        (uint64_t)address[2] << 8 | address[3];
        uint64_t length = UINT64_C(1) << (32 - prefix);
        if (next & (length - 1)) {
            result = PLAN_INVALID_DATA;
            goto finish;
        }
        uint64_t last = next + length - 1;
        if (!builder.source || strcmp(builder.source->name, name)) {
            if (!finish_source(&builder, start, end))
                goto finish;
            if (source_index == MAX_SOURCES) {
                result = PLAN_TOO_LARGE;
                goto finish;
            }
            builder.source = &plan->sources[source_index++];
            if (!stage)
                memcpy(builder.source->name, name, strlen(name) + 1);
            else if (strcmp(builder.source->name, name))
                goto finish;
            start = next;
            end = last;
        } else if (next > end + 1) {
            if (!insert_range(&builder, start, end))
                goto finish;
            start = next;
            end = last;
        } else if (last > end) {
            end = last;
        }
        if (!stage)
            ++builder.source->input_rows;
    }
    if (step != SQLITE_DONE || !finish_source(&builder, start, end))
        goto finish;
    if (stage && (source_index != plan->count || seen_rows != plan->input_rows))
        goto finish;
    if (!stage) {
        plan->count = source_index;
        plan->input_rows = seen_rows;
    }
    result = PLAN_OK;

finish:
    sqlite3_finalize(query);
    sqlite3_finalize(builder.insert);
    free(builder.heap);
    return result;
}

static int compare_sizes(const void *left, const void *right)
{
    const struct route_source *a = *(const struct route_source *const *)left;
    const struct route_source *b = *(const struct route_source *const *)right;
    if (a->routes != b->routes)
        return a->routes > b->routes ? -1 : 1;
    return strcmp(a->name, b->name);
}

static int compare_remainders(const void *left, const void *right)
{
    const struct route_source *a = *(const struct route_source *const *)left;
    const struct route_source *b = *(const struct route_source *const *)right;
    if (a->fractional != b->fractional)
        return a->fractional > b->fractional ? -1 : 1;
    return strcmp(a->name, b->name);
}

static void select_routes(struct route_plan *plan, size_t quota)
{
    struct route_source *ordered[MAX_SOURCES];
    if (quota >= plan->routes) {
        for (size_t i = 0; i < plan->count; ++i)
            plan->sources[i].selected = plan->sources[i].routes;
        return;
    }

    for (size_t i = 0; i < plan->count; ++i)
        ordered[i] = &plan->sources[i];
    if (quota < plan->count) {
        qsort(ordered, plan->count, sizeof(ordered[0]), compare_sizes);
        for (size_t i = 0; i < quota; ++i)
            ordered[i]->selected = 1;
        return;
    }

    /* Matches upstream's proportional allocation without DPI priorities. */
    size_t used = 0;
    for (size_t i = 0; i < plan->count; ++i) {
        struct route_source *source = ordered[i];
        double share = (double)((uint64_t)source->routes * quota) / (double)plan->routes;
        source->selected = (size_t)share;
        source->fractional = share - (double)source->selected;
        used += source->selected;
    }
    qsort(ordered, plan->count, sizeof(ordered[0]), compare_remainders);
    for (size_t i = 0; i < plan->count && used < quota; ++i) {
        struct route_source *source = ordered[i];
        size_t remaining = quota - used;
        size_t capacity = source->routes - source->selected;
        size_t addition = remaining < capacity ? remaining : capacity;
        source->selected += addition;
        used += addition;
    }
}

static bool get_revisions(sqlite3 *db, sqlite3_int64 revisions[2])
{
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(db, "SELECT id FROM main.cidr_route_snapshots ORDER BY id DESC LIMIT 2",
                           -1, &statement, NULL) != SQLITE_OK) {
        sqlite3_finalize(statement);
        return false;
    }
    size_t count = 0;
    revisions[0] = 0;
    revisions[1] = 0;
    int step;
    while ((step = sqlite3_step(statement)) == SQLITE_ROW)
        revisions[count++] = sqlite3_column_int64(statement, 0);
    sqlite3_finalize(statement);
    return step == SQLITE_DONE;
}

static bool commit_plan(sqlite3 *db, const struct route_plan *plan, const char *source,
                        bool preserve_empty, sqlite3_int64 *revision)
{
    sqlite3_int64 revisions[2];
    if (!get_revisions(db, revisions))
        return false;
    sqlite3_stmt *statement = NULL;
    bool success = sqlite3_prepare_v2(db, "INSERT INTO main.cidr_route_snapshots(created_at, budget)"
                                        " VALUES (CAST(strftime('%s','now') AS INTEGER), ?)",
                                     -1, &statement, NULL) == SQLITE_OK &&
                   sqlite3_bind_int64(statement, 1, (sqlite3_int64)plan->budget) == SQLITE_OK &&
                   sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    if (!success)
        return false;
    *revision = sqlite3_last_insert_rowid(db);

    static const char insert_sql[] =
        "INSERT INTO main.cidr_route_lists SELECT ?1, source, address, prefix FROM temp.cidr_route_stage"
        " UNION ALL SELECT ?1, source, address, prefix FROM main.cidr_route_lists"
        " WHERE revision=?2 AND (?3 OR (?4 IS NOT NULL AND source<>?4))"
        " AND source NOT IN (SELECT source FROM temp.cidr_route_stage)";
    statement = NULL;
    success = sqlite3_prepare_v2(db, insert_sql, -1, &statement, NULL) == SQLITE_OK &&
              sqlite3_bind_int64(statement, 1, *revision) == SQLITE_OK &&
              sqlite3_bind_int64(statement, 2, revisions[0]) == SQLITE_OK &&
              sqlite3_bind_int(statement, 3, preserve_empty ? 1 : 0) == SQLITE_OK &&
              bind_source(statement, 4, source) && sqlite3_step(statement) == SQLITE_DONE;
    sqlite3_finalize(statement);
    if (!success)
        return false;
    if (revisions[0]) {
        static const char comparison_sql[] =
            "SELECT NOT EXISTS (SELECT source, address, prefix FROM main.cidr_route_lists WHERE revision=?1"
            " EXCEPT SELECT source, address, prefix FROM main.cidr_route_lists WHERE revision=?2)"
            " AND NOT EXISTS (SELECT source, address, prefix FROM main.cidr_route_lists WHERE revision=?2"
            " EXCEPT SELECT source, address, prefix FROM main.cidr_route_lists WHERE revision=?1)";
        statement = NULL;
        success = sqlite3_prepare_v2(db, comparison_sql, -1, &statement, NULL) == SQLITE_OK &&
                  sqlite3_bind_int64(statement, 1, *revision) == SQLITE_OK &&
                  sqlite3_bind_int64(statement, 2, revisions[0]) == SQLITE_OK && sqlite3_step(statement) == SQLITE_ROW;
        bool unchanged = success && sqlite3_column_int(statement, 0) == 1;
        sqlite3_finalize(statement);
        if (!success)
            return false;
        if (unchanged) {
            *revision = revisions[0];
            return execute(db, "DELETE FROM main.cidr_route_snapshots WHERE id="
                               " (SELECT max(id) FROM main.cidr_route_snapshots)") && execute(db, "COMMIT");
        }
    }
    return execute(db, "DELETE FROM main.cidr_route_snapshots WHERE id IN ("
                       " SELECT id FROM main.cidr_route_snapshots ORDER BY id DESC LIMIT -1 OFFSET 2)") &&
           execute(db, "COMMIT");
}

static bool existing_routes(sqlite3 *db, const char *source, size_t *count)
{
    static const char sql[] =
        "SELECT count(*) FROM main.cidr_route_lists WHERE revision="
        " (SELECT max(id) FROM main.cidr_route_snapshots) AND source<>?1";
    sqlite3_stmt *statement = NULL;
    bool found = sqlite3_prepare_v2(db, sql, -1, &statement, NULL) == SQLITE_OK &&
                 bind_source(statement, 1, source) && sqlite3_step(statement) == SQLITE_ROW;
    if (found)
        *count = (size_t)sqlite3_column_int64(statement, 0);
    sqlite3_finalize(statement);
    return found;
}

static bool routes_to_preserve(sqlite3 *db, const struct route_plan *plan, size_t *count)
{
    static const char sql[] =
        "SELECT source, count(*) FROM main.cidr_route_lists WHERE revision="
        " (SELECT max(id) FROM main.cidr_route_snapshots) GROUP BY source";
    sqlite3_stmt *statement = NULL;
    if (sqlite3_prepare_v2(db, sql, -1, &statement, NULL) != SQLITE_OK) {
        sqlite3_finalize(statement);
        return false;
    }
    *count = 0;
    int step;
    while ((step = sqlite3_step(statement)) == SQLITE_ROW) {
        const char *source = (const char *)sqlite3_column_text(statement, 0);
        if (!source) {
            sqlite3_finalize(statement);
            return false;
        }
        size_t index = 0;
        while (index < plan->count && strcmp(plan->sources[index].name, source))
            ++index;
        if (index == plan->count || !plan->sources[index].selected)
            *count += (size_t)sqlite3_column_int64(statement, 1);
    }
    sqlite3_finalize(statement);
    return step == SQLITE_DONE;
}

static int compile_routes(sqlite3 *db, const char *source, size_t budget, FILE *output,
                          bool publish, bool trim_requested)
{
    if (!execute(db, publish ? "BEGIN IMMEDIATE" : "BEGIN"))
        return database_failure(db, output);
    struct route_plan *plan = calloc(1, sizeof(*plan));
    if (!plan)
        return error_reply(output, 500, "out_of_memory");
    plan->budget = budget ? budget : default_budget();
    enum plan_result built = build_plan(db, source, false, plan);
    size_t existing = 0;
    if (built == PLAN_OK && source && !existing_routes(db, source, &existing))
        built = PLAN_DATABASE_ERROR;
    if (built != PLAN_OK || !plan->count) {
        free(plan);
        if (built == PLAN_TOO_LARGE)
            return error_reply(output, 413, "build_limit");
        if (built == PLAN_INVALID_DATA)
            return error_reply(output, 422, "invalid_stored_network");
        if (built == PLAN_DATABASE_ERROR)
            return database_failure(db, output);
        return error_reply(output, 404, "no_source_routes");
    }

    size_t original_total = plan->routes + existing;
    bool trim = trim_requested && original_total > plan->budget;
    size_t available = existing < plan->budget ? plan->budget - existing : 0;
    select_routes(plan, trim ? available : plan->routes);
    size_t kept = 0;
    for (size_t i = 0; i < plan->count; ++i) {
        struct route_source *stats = &plan->sources[i];
        if (trim && stats->default_route)
            stats->selected = 0;
        kept += stats->selected;
    }
    if (trim && !routes_to_preserve(db, plan, &existing)) {
        free(plan);
        return database_failure(db, output);
    }
    size_t total = kept + existing;
    bool over_budget = total > plan->budget;
    sqlite3_int64 revision = 0;
    if (publish && !over_budget) {
        if (!total) {
            free(plan);
            return error_reply(output, 409, "no_routes_within_budget");
        }
        if (build_plan(db, source, true, plan) != PLAN_OK || !commit_plan(db, plan, source, trim, &revision)) {
            free(plan);
            return database_failure(db, output);
        }
    }
    fprintf(output, "{\"state\":\"%s\",\"revision\":%lld,\"budget\":%zu,\"input_routes\":%zu,"
                    "\"routes\":%zu,\"retained_routes\":%zu,\"total_routes\":%zu,\"original_routes\":%zu,"
                    "\"trimmed\":%s,\"over_budget\":%s,\"sources\":[",
            publish && over_budget ? "over_budget" : "ok", (long long)revision, plan->budget,
            plan->input_rows, kept, existing, total, original_total, trim ? "true" : "false", over_budget ? "true" : "false");
    for (size_t i = 0; i < plan->count; ++i) {
        const struct route_source *stats = &plan->sources[i];
        fprintf(output, "%s{\"name\":\"%s\",\"input_routes\":%zu,\"routes\":%zu,\"original_routes\":%zu}",
                i ? "," : "", stats->name, stats->input_rows, stats->selected, stats->routes);
    }
    fputs("]}\n", output);
    free(plan);
    return publish && over_budget ? 409 : 200;
}

static int rollback_routes(sqlite3 *db, FILE *output)
{
    sqlite3_int64 revisions[2];
    if (!execute(db, "BEGIN IMMEDIATE") || !get_revisions(db, revisions))
        return database_failure(db, output);
    if (!revisions[1])
        return error_reply(output, 404, "no_previous_revision");
    if (!execute(db, "DELETE FROM main.cidr_route_snapshots WHERE id="
                     " (SELECT max(id) FROM main.cidr_route_snapshots)") || !execute(db, "COMMIT"))
        return database_failure(db, output);
    fprintf(output, "{\"state\":\"ok\",\"revision\":%lld}\n", (long long)revisions[1]);
    return 200;
}

static int status_routes(sqlite3 *db, FILE *output)
{
    static const char select[] =
        "WITH inputs AS (SELECT source, count(*) AS qty FROM main.cidr_input_networks"
        " WHERE family=4 AND prefix>0 GROUP BY source),"
        " artifacts AS (SELECT source, count(*) AS qty FROM main.cidr_route_lists WHERE revision=?1 GROUP BY source),"
        " names AS (SELECT source FROM inputs UNION SELECT source FROM artifacts)"
        " SELECT names.source, coalesce(inputs.qty, 0), coalesce(artifacts.qty, 0)"
        " FROM names LEFT JOIN inputs USING (source) LEFT JOIN artifacts USING (source) ORDER BY names.source LIMIT 257";
    sqlite3_int64 revisions[2];
    sqlite3_stmt *statement = NULL;
    if (!execute(db, "BEGIN") || !get_revisions(db, revisions) ||
        sqlite3_prepare_v2(db, select, -1, &statement, NULL) != SQLITE_OK ||
        sqlite3_bind_int64(statement, 1, revisions[0]) != SQLITE_OK) {
        sqlite3_finalize(statement);
        return database_failure(db, output);
    }
    struct route_source *sources = calloc(MAX_SOURCES, sizeof(*sources));
    if (!sources) {
        sqlite3_finalize(statement);
        return error_reply(output, 500, "out_of_memory");
    }
    size_t count = 0, total = 0;
    int step;
    while ((step = sqlite3_step(statement)) == SQLITE_ROW) {
        const char *source = (const char *)sqlite3_column_text(statement, 0);
        if (count == MAX_SOURCES || !safe_source(source) || sqlite3_column_bytes(statement, 0) != (int)strlen(source)) {
            free(sources);
            sqlite3_finalize(statement);
            return error_reply(output, 422, "invalid_stored_source");
        }
        struct route_source *stats = &sources[count++];
        memcpy(stats->name, source, strlen(source) + 1);
        stats->input_rows = (size_t)sqlite3_column_int64(statement, 1);
        stats->routes = (size_t)sqlite3_column_int64(statement, 2);
        total += stats->routes;
    }
    sqlite3_finalize(statement);
    if (step != SQLITE_DONE) {
        free(sources);
        return database_failure(db, output);
    }
    fprintf(output, "{\"state\":\"ok\",\"revision\":%lld,\"previous_revision\":%lld,"
                    "\"budget\":%zu,\"routes\":%zu,\"sources\":[",
            (long long)revisions[0], (long long)revisions[1], default_budget(), total);
    for (size_t i = 0; i < count; ++i)
        fprintf(output, "%s{\"name\":\"%s\",\"input_routes\":%zu,\"routes\":%zu}",
                i ? "," : "", sources[i].name, sources[i].input_rows, sources[i].routes);
    fputs("]}\n", output);
    free(sources);
    return 200;
}

static int export_routes(sqlite3 *db, const char *source, const char *format, FILE *output)
{
    bool artifact = format && !strcmp(format, "artifact");
    if ((format && strcmp(format, "cidr") && !artifact) || (artifact && !source))
        return error_reply(output, 400, "invalid_export_format");
    sqlite3_stmt *statement = NULL;
    static const char all_sql[] =
        "SELECT DISTINCT address, prefix FROM main.cidr_route_lists WHERE revision="
        " (SELECT max(id) FROM main.cidr_route_snapshots) ORDER BY address, prefix";
    static const char source_sql[] =
        "SELECT address, prefix FROM main.cidr_route_lists WHERE revision="
        " (SELECT max(id) FROM main.cidr_route_snapshots) AND source=?1 ORDER BY address, prefix";
    bool prepared = sqlite3_prepare_v2(db, source ? source_sql : all_sql, -1, &statement, NULL) == SQLITE_OK &&
                    (!source || bind_source(statement, 1, source));
    int step = prepared ? sqlite3_step(statement) : SQLITE_ERROR;
    if (step != SQLITE_ROW) {
        sqlite3_finalize(statement);
        return step == SQLITE_DONE ? error_reply(output, 404, "no_published_routes") : database_failure(db, output);
    }
    if (artifact)
        fprintf(output, "# Auto-generated CIDR list for %s\n# Source: db:%s\n\n", source, source);
    do {
        uint32_t address = (uint32_t)sqlite3_column_int64(statement, 0);
        int prefix = sqlite3_column_int(statement, 1);
        fprintf(output, "%u.%u.%u.%u/%d\n", (unsigned int)(address >> 24),
                (unsigned int)((address >> 16) & 255U), (unsigned int)((address >> 8) & 255U),
                (unsigned int)(address & 255U), prefix);
    } while ((step = sqlite3_step(statement)) == SQLITE_ROW);
    sqlite3_finalize(statement);
    return step == SQLITE_DONE && !ferror(output) ? 200 : 500;
}

int cidr_routes_request(const char *database_path, const char *action, const char *source,
                        const char *format, size_t budget, FILE *input, FILE *output)
{
    if (!output)
        return 500;
    if (source && !source[0])
        source = NULL;
    if (!database_path || !action || (source && !safe_source(source)) || budget > CIDR_ROUTES_MAX_BUDGET)
        return error_reply(output, 400, "invalid_request");

    sqlite3 *db = NULL;
    int status;
    if (!open_database(database_path, true, &db) || !cidr_input_prepare(db) || !execute(db, schema))
        status = database_failure(db, output);
    else if (!strcmp(action, "status"))
        status = status_routes(db, output);
    else if (!strcmp(action, "import"))
        status = import_source(db, source, input, output);
    else if (!strcmp(action, "preview") || !strcmp(action, "publish")) {
        if (format && strcmp(format, "trim"))
            status = error_reply(output, 400, "invalid_build_format");
        else
            status = compile_routes(db, source, budget, output, !strcmp(action, "publish"), format != NULL);
    }
    else if (!strcmp(action, "rollback"))
        status = rollback_routes(db, output);
    else if (!strcmp(action, "export"))
        status = export_routes(db, source, format, output);
    else
        status = error_reply(output, 404, "unknown_operation");
    sqlite3_close(db);
    return fflush(output) == 0 ? status : 500;
}

static bool legacy_table(sqlite3 *db, bool *found)
{
    sqlite3_stmt *statement = NULL;
    int step = SQLITE_ERROR;
    if (sqlite3_prepare_v2(db, "SELECT 1 FROM pragma_table_list('provider_cidr')"
                              " WHERE schema='main' AND type='table'", -1, &statement, NULL) == SQLITE_OK)
        step = sqlite3_step(statement);
    sqlite3_finalize(statement);
    *found = step == SQLITE_ROW;
    return *found || step == SQLITE_DONE;
}

static bool upstream_field(sqlite3_stmt *statement, int column, int maximum, bool nullable)
{
    int type = sqlite3_column_type(statement, column);
    if (type == SQLITE_NULL)
        return nullable;
    if (type != SQLITE_TEXT)
        return false;
    const char *value = (const char *)sqlite3_column_text(statement, column);
    int size = sqlite3_column_bytes(statement, column);
    return value && size <= maximum && (size_t)size == strlen(value);
}

static bool stage_legacy_row(sqlite3_stmt *insert, sqlite3_stmt *read, struct cidr_input_network *network)
{
    if (sqlite3_reset(insert) != SQLITE_OK)
        return false;
    for (int column = 0; column < 6; ++column) {
        if (sqlite3_bind_value(insert, column + 1, sqlite3_column_value(read, column)) != SQLITE_OK)
            return false;
    }
    bool usable = network->family == 4 && network->prefix != 0;
    return (usable ? sqlite3_bind_blob(insert, 7, network->address, 4, SQLITE_TRANSIENT)
                   : sqlite3_bind_null(insert, 7)) == SQLITE_OK &&
           (usable ? sqlite3_bind_int(insert, 8, (int)network->prefix)
                   : sqlite3_bind_null(insert, 8)) == SQLITE_OK &&
           sqlite3_step(insert) == SQLITE_DONE;
}

static int migrate_pools(sqlite3 *db, sqlite3 *legacy, FILE *output)
{
    static const char stage_schema[] =
        "CREATE TEMP TABLE cidr_legacy_stage (id INTEGER PRIMARY KEY, source TEXT NOT NULL, cidr TEXT NOT NULL,"
        " region_scope TEXT, country_codes TEXT, refreshed_at TEXT, address BLOB, prefix INTEGER);"
        "CREATE TABLE IF NOT EXISTS main.cidr_legacy_metadata (id INTEGER PRIMARY KEY, source TEXT NOT NULL,"
        " cidr TEXT NOT NULL, region_scope TEXT, country_codes TEXT, refreshed_at TEXT);";
    static const char legacy_query[] =
        "SELECT id, provider_key, cidr, region_scope, country_codes, refreshed_at FROM main.provider_cidr ORDER BY id";
    static const char publish[] =
        "DELETE FROM main.cidr_input_networks WHERE source IN"
        " (SELECT source FROM temp.cidr_legacy_stage WHERE address IS NOT NULL);"
        "INSERT INTO main.cidr_input_networks"
        " SELECT DISTINCT source, 4, address, prefix FROM temp.cidr_legacy_stage WHERE address IS NOT NULL;"
        "DELETE FROM main.cidr_legacy_metadata;"
        "INSERT INTO main.cidr_legacy_metadata"
        " SELECT id, source, cidr, region_scope, country_codes, refreshed_at FROM temp.cidr_legacy_stage;";
    sqlite3_stmt *read = NULL;
    sqlite3_stmt *insert = NULL;
    size_t rows = 0, skipped = 0;
    int status;
    if (sqlite3_prepare_v2(legacy, legacy_query, -1, &read, NULL) != SQLITE_OK) {
        status = error_reply(output, 422, "invalid_legacy_schema");
        goto finish;
    }
    if (!execute(db, "BEGIN IMMEDIATE") || !cidr_input_prepare(db) || !execute(db, stage_schema) ||
        sqlite3_prepare_v2(db, "INSERT INTO temp.cidr_legacy_stage VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                           -1, &insert, NULL) != SQLITE_OK) {
        status = database_failure(db, output);
        goto finish;
    }
    int step;
    while ((step = sqlite3_step(read)) == SQLITE_ROW) {
        if (++rows > MAX_BUILD_ROWS) {
            status = error_reply(output, 413, "import_limit");
            goto finish;
        }
        struct cidr_input_network network;
        if (sqlite3_column_type(read, 0) != SQLITE_INTEGER || sqlite3_column_int64(read, 0) <= 0 ||
            !upstream_field(read, 1, SOURCE_LENGTH, false) || !upstream_field(read, 2, 50, false) ||
            !upstream_field(read, 3, 64, true) || !upstream_field(read, 4, 255, true) ||
            !upstream_field(read, 5, 64, true) ||
            !safe_source((const char *)sqlite3_column_text(read, 1)) ||
            !cidr_input_parse((const char *)sqlite3_column_text(read, 2), &network)) {
            fprintf(output, "{\"state\":\"error\",\"error\":\"invalid_legacy_row\",\"row\":%zu}\n", rows);
            status = 422;
            goto finish;
        }
        if (network.family != 4 || network.prefix == 0)
            ++skipped;
        if (!stage_legacy_row(insert, read, &network)) {
            status = database_failure(db, output);
            goto finish;
        }
    }
    if (step != SQLITE_DONE) {
        status = database_failure(legacy, output);
        goto finish;
    }
    if (!rows || rows == skipped) {
        status = error_reply(output, 422, "no_legacy_ipv4_routes");
        goto finish;
    }
    sqlite3_stmt *capacity = NULL;
    int count = -1;
    if (sqlite3_prepare_v2(db, "SELECT count(*) FROM (SELECT source FROM main.cidr_input_networks"
                              " UNION SELECT source FROM temp.cidr_legacy_stage WHERE address IS NOT NULL)",
                           -1, &capacity, NULL) == SQLITE_OK && sqlite3_step(capacity) == SQLITE_ROW)
        count = sqlite3_column_int(capacity, 0);
    sqlite3_finalize(capacity);
    if (count < 0 || (count <= MAX_SOURCES && (!execute(db, publish) || !execute(db, "COMMIT")))) {
        status = database_failure(db, output);
        goto finish;
    }
    if (count > MAX_SOURCES) {
        status = error_reply(output, 409, "source_limit");
        goto finish;
    }
    fprintf(output, "{\"state\":\"ok\",\"legacy_rows\":%zu,\"policy_skipped\":%zu,\"sources\":%d}\n", rows, skipped, count);
    status = 200;

finish:
    sqlite3_finalize(insert);
    sqlite3_finalize(read);
    return status;
}

int cidr_routes_import_legacy(const char *database_path, const char *legacy_path, FILE *output)
{
    if (!output)
        return 500;
    if (!database_path || !legacy_path || !database_path[0] || !legacy_path[0])
        return error_reply(output, 400, "invalid_request");
    sqlite3 *legacy = NULL;
    sqlite3 *db = NULL;
    bool legacy_found = false, target_legacy = false;
    int status;
    if (!open_database(legacy_path, false, &legacy) || !legacy_table(legacy, &legacy_found) || !legacy_found)
        status = error_reply(output, 422, "invalid_legacy_schema");
    else if (!open_database(database_path, true, &db) || !legacy_table(db, &target_legacy))
        status = database_failure(db, output);
    else if (target_legacy)
        status = error_reply(output, 400, "invalid_native_destination");
    else
        status = migrate_pools(db, legacy, output);
    sqlite3_close(db);
    sqlite3_close(legacy);
    return fflush(output) == 0 ? status : 500;
}

FILE *cidr_routes_open_result(const char *directory, const char *format,
                              const char **filename, size_t *size)
{
    static const struct { const char *format; const char *filename; } results[] = {
        {"keenetic", "keenetic-wireguard-routes.txt"},
        {"mikrotik", "mikrotik-wireguard-routes.txt"},
        {"tplink", "tp-link-openvpn-routes.txt"},
        {"route_ips", "route-ips.txt"}
    };
    if (!directory || !format || !filename || !size)
        return NULL;
    const char *name = NULL;
    for (size_t i = 0; i < sizeof(results) / sizeof(results[0]); ++i) {
        if (!strcmp(results[i].format, format)) {
            name = results[i].filename;
            break;
        }
    }
    if (!name)
        return NULL;

#ifdef _WIN32
    char path[4096];
    int length = snprintf(path, sizeof(path), "%s/%s", directory, name);
    if (length < 0 || (size_t)length >= sizeof(path))
        return NULL;
    DWORD attributes = GetFileAttributesA(path);
    if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)))
        return NULL;
    HANDLE handle = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL, OPEN_EXISTING, FILE_FLAG_OPEN_REPARSE_POINT, NULL);
    if (handle == INVALID_HANDLE_VALUE)
        return NULL;
    BY_HANDLE_FILE_INFORMATION info;
    if (GetFileType(handle) != FILE_TYPE_DISK || !GetFileInformationByHandle(handle, &info) ||
        (info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) ||
        info.nFileSizeHigh || info.nFileSizeLow > MAX_RESULT_FILE) {
        CloseHandle(handle);
        return NULL;
    }
    int fd = _open_osfhandle((intptr_t)handle, _O_RDONLY | _O_BINARY);
    if (fd < 0) {
        CloseHandle(handle);
        return NULL;
    }
    FILE *file = _fdopen(fd, "rb");
    if (!file) {
        _close(fd);
        return NULL;
    }
    *size = (size_t)info.nFileSizeLow;
#else
    int root = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0)
        return NULL;
    int fd = openat(root, name, O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOFOLLOW);
    close(root);
    if (fd < 0)
        return NULL;
    struct stat info;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size < 0 || info.st_size > MAX_RESULT_FILE) {
        close(fd);
        return NULL;
    }
    FILE *file = fdopen(fd, "rb");
    if (!file) {
        close(fd);
        return NULL;
    }
    *size = (size_t)info.st_size;
#endif
    *filename = name;
    return file;
}
