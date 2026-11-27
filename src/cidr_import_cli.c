#include "cidr_input.h"
#include "cidr_routes.h"

#include <sqlite3.h>

#include <string.h>

static const char *status_name(enum cidr_input_status status)
{
    switch (status) {
    case CIDR_INPUT_OK: return "ok";
    case CIDR_INPUT_INVALID: return "invalid";
    case CIDR_INPUT_TRUNCATED: return "truncated";
    case CIDR_INPUT_READ_ERROR: return "read_error";
    case CIDR_INPUT_LIMIT: return "limit";
    case CIDR_INPUT_EMPTY: return "empty";
    case CIDR_INPUT_CANCELLED: return "cancelled";
    case CIDR_INPUT_DATABASE_ERROR: return "database_error";
    case CIDR_INPUT_EOF:
    case CIDR_INPUT_SKIP: return "empty";
    }
    return "unknown";
}

int main(int argc, char **argv)
{
    if (argc == 4 && !strcmp(argv[1], "--legacy"))
        return cidr_routes_import_legacy(argv[2], argv[3], stdout) == 200 ? 0 : 1;
    if (argc != 5 || (strcmp(argv[4], "ipv4") && strcmp(argv[4], "dual"))) {
        fputs("usage: adminpanelaz-cidr-import STAGING_DB SOURCE INPUT ipv4|dual\n"
              "       adminpanelaz-cidr-import --legacy NATIVE_DB LEGACY_CIDR_DB\n", stderr);
        return 2;
    }
    FILE *input = fopen(argv[3], "rb");
    if (!input) {
        fputs("Cannot read the CIDR input.\n", stderr);
        return 1;
    }
    sqlite3 *database = NULL;
    int open_flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE;
#ifdef SQLITE_OPEN_NOFOLLOW
    open_flags |= SQLITE_OPEN_NOFOLLOW;
#endif
    if (sqlite3_open_v2(argv[1], &database, open_flags, NULL) != SQLITE_OK || sqlite3_busy_timeout(database, 250) != SQLITE_OK) {
        sqlite3_close(database);
        fclose(input);
        fputs("Cannot open the CIDR staging database.\n", stderr);
        return 1;
    }
    struct cidr_input_report report = {0};
    enum cidr_input_policy policy = !strcmp(argv[4], "ipv4") ? CIDR_INPUT_UPSTREAM_IPV4 : CIDR_INPUT_DUAL_STACK;
    enum cidr_input_status result = cidr_input_import(database, argv[2], input, policy, NULL, NULL, &report);
    sqlite3_close(database);
    fclose(input);
    printf("{\"state\":\"%s\",\"lines\":%zu,\"ignored\":%zu,\"policy_skipped\":%zu,"
           "\"duplicates\":%zu,\"published\":%zu,\"error_line\":%zu}\n",
           status_name(result), report.lines, report.ignored, report.policy_skipped,
           report.duplicates, report.published, report.error_line);
    return result == CIDR_INPUT_OK ? 0 : 1;
}
