#include "panel_history.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(int argc, char **argv)
{
    if (argc != 4) {
        fputs("Usage: adminpanelaz-history-migration OFFLINE_ADMINPANEL_DB DATA_DIR LEGACY_LOCAL_NODE_ID\n", stderr);
        return 2;
    }
    const char *input = argv[3];
    errno = 0;
    intmax_t node = strtoimax(input, NULL, 10);
    if (!*input || input[strspn(input, "0123456789")] || !node || node > INT64_MAX || errno) {
        fputs("The legacy local node ID must be a positive integer.\n", stderr);
        return 2;
    }
    if (!panel_history_open(argv[2])) {
        fputs("Could not open the destination history database.\n", stderr);
        return 1;
    }
    struct panel_history_import_count count;
    bool ok = panel_history_import_legacy(argv[1], (int64_t)node, (int64_t)time(NULL), &count);
    panel_history_close();
    if (!ok) {
        fputs("Could not import history for the selected local VPN node.\n", stderr);
        return 1;
    }
    printf("{\"resources\":%zu,\"connections\":%zu,\"traffic\":%zu,\"audit\":%zu}\n",
           count.resources, count.connections, count.traffic, count.audit);
    return 0;
}
