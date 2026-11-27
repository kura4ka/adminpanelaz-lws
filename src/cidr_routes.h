#ifndef ADMINPANELAZ_CIDR_ROUTES_H
#define ADMINPANELAZ_CIDR_ROUTES_H

#include <stddef.h>
#include <stdio.h>

enum { CIDR_ROUTES_MAX_IMPORT = 8 * 1024 * 1024, CIDR_ROUTES_MAX_BUDGET = 10000 };

/* JSON output, except for successful exports. Imports use a seekable input file.
 * NULL or an empty source selects all providers for build and export. A zero
 * budget uses OPENVPN_ROUTE_TOTAL_CIDR_LIMIT capped by the iOS setting.
 * Pass trim as the build format to omit smaller routes when over budget. */
int cidr_routes_request(const char *database_path, const char *action, const char *source,
                        const char *format, size_t budget, FILE *input, FILE *output);

/* Imports the pinned upstream provider_cidr table with its metadata. Each
 * provider with usable IPv4 entries replaces that provider's stored input.
 * Existing published revisions are untouched. Writes a JSON import report. */
int cidr_routes_import_legacy(const char *database_path, const char *legacy_path, FILE *output);

/* An authenticated caller may serve the node's own router files by enabling a
 * trusted result directory. The returned filename is static. */
FILE *cidr_routes_open_result(const char *directory, const char *format,
                              const char **filename, size_t *size);

#endif
