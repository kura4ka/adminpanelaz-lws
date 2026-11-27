#include "panel_ha.h"

#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void expect(int condition, const char *description)
{
    if (!condition) {
        fprintf(stderr, "HA test failed: %s\n", description);
        exit(EXIT_FAILURE);
    }
}

struct fake_inventory {
    int64_t offline;
    int64_t other_version;
    int64_t old_agent;
};

static bool lookup(int64_t id, struct panel_ha_node_info *out, void *context)
{
    struct fake_inventory *inventory = context;
    out->vpn = id != 19;
    out->online = inventory->offline != id;
    strcpy(out->antizapret_version, inventory->other_version == id ? "5.1" : "5.0");
    strcpy(out->agent_version, inventory->old_agent == id ? "1.5.0-beta" : "1.18.0");
    return id == 11 || id == 12 || id == 13 || id == 14 || id == 18 || id == 19;
}

static void request(struct fake_inventory *inventory, const char *action, int64_t id,
                    const struct panel_ha_fields *fields, int status, const char *pattern)
{
    FILE *out = tmpfile();
    expect(out != NULL, "temporary response file");
    int actual = panel_ha_request(action, id, fields, "https://Panel.Example.:443/panel",
                                  lookup, inventory, out);
    rewind(out);
    char body[8192];
    body[fread(body, 1, sizeof(body) - 1, out)] = '\0';
    fclose(out);
    if (actual != status || !strstr(body, pattern)) {
        fprintf(stderr, "%s returned %d: %s\n", action, actual, body);
        expect(false, pattern);
    }
}

static void fixture_sql(const char *path, const char *sql)
{
    sqlite3 *db = NULL;
    expect(sqlite3_open_v2(path, &db, SQLITE_OPEN_READWRITE, NULL) == SQLITE_OK, "open fixture DB");
    expect(sqlite3_exec(db, sql, NULL, NULL, NULL) == SQLITE_OK, "fixture SQL");
    expect(sqlite3_close(db) == SQLITE_OK, "close fixture DB");
}

int main(int argc, char **argv)
{
    expect(argc == 2, "pass path to a fresh HA database");
    const char *path = argv[1];
    expect(panel_ha_open(path), "initialize HA schema");
    struct fake_inventory inventory = {0};
    int64_t replicas[] = {13, 12, 13};
    struct panel_ha_fields fields = {
        .name = " VPN \"A\" ",
        .shared_domain = "OpenVPN.Example.",
        .primary_node_id = 11,
        .replica_node_ids = replicas,
        .replica_count = sizeof(replicas) / sizeof(replicas[0])
    };

    request(&inventory, "list", 0, NULL, 200, "[]");
    request(&inventory, "preflight", 0, &fields, 200, "\"effective_wireguard_domain\":\"openvpn.example\"");
    request(&inventory, "create", 0, &fields, 201, "\"replica_node_ids\":[12,13]");
    request(&inventory, "get", 1, NULL, 200, "\"name\":\"VPN \\\"A\\\"\"");
    request(&inventory, "list", 0, NULL, 200, "\"sync_status\":\"unknown\"");
    request(&inventory, "setup", 1, NULL, 501, "\"error\"");
    request(&inventory, "apply-shared-domain", 1, NULL, 501, "\"error\"");
    request(&inventory, "push-full", 1, NULL, 501, "\"error\"");
    expect(panel_ha_node_role(11) == PANEL_HA_PRIMARY, "primary membership");
    expect(panel_ha_node_role(12) == PANEL_HA_REPLICA, "replica membership");
    request(&inventory, "create", 0, &fields, 422, "\"error\"");

    request(&inventory, "verify", 1, NULL, 200, "\"ready\":false");
    request(&inventory, "status", 1, NULL, 200, "\"last_verify_at\":\"");
    const struct panel_ha_fields rename = {.name = "Renamed"};
    request(&inventory, "update", 1, &rename, 200, "\"ready\":false");
    const struct panel_ha_fields settings = {.shared_domain_wireguard = "wg.example", .sync_mode = "auto"};
    request(&inventory, "update", 1, &settings, 200, "\"ready\":null");
    request(&inventory, "get", 1, NULL, 200, "\"shared_domain_wireguard\":\"wg.example\"");
    const struct panel_ha_fields clear_wg = {.shared_domain_wireguard = ""};
    request(&inventory, "update", 1, &clear_wg, 200, "\"shared_domain_wireguard\":null");

    const struct panel_ha_fields conflict = {.shared_domain_wireguard = "Panel.Example."};
    request(&inventory, "update", 1, &conflict, 400, "\"error\"");
    const struct panel_ha_fields invalid = {.shared_domain = "x.example\nOPENVPN_HOST=example.net"};
    request(&inventory, "update", 1, &invalid, 422, "\"error\"");
    const struct panel_ha_fields same_node = {.primary_node_id = 12};
    request(&inventory, "update", 1, &same_node, 422, "\"error\"");
    const struct panel_ha_fields proxy = {.primary_node_id = 19};
    request(&inventory, "update", 1, &proxy, 422, "\"error\"");

    inventory.offline = 12;
    request(&inventory, "preflight", 1, NULL, 422, "\"error\"");
    request(&inventory, "verify", 1, NULL, 200, "\"ready\":false");
    inventory.offline = 0;
    inventory.other_version = 13;
    request(&inventory, "preflight", 1, NULL, 422, "\"error\"");
    inventory.other_version = 0;
    inventory.old_agent = 13;
    request(&inventory, "preflight", 1, NULL, 422, "1.5.0");
    inventory.old_agent = 0;

    fixture_sql(path, "CREATE TRIGGER reject_insert BEFORE INSERT ON sync_group_members "
                      "WHEN new.node_id=18 BEGIN SELECT RAISE(ABORT,'fixture'); END;");
    int64_t broken_replicas[] = {14, 18};
    const struct panel_ha_fields broken = {
        .name = "Failed change",
        .replica_node_ids = broken_replicas,
        .replica_count = sizeof(broken_replicas) / sizeof(broken_replicas[0])
    };
    request(&inventory, "update", 1, &broken, 500, "\"error\"");
    request(&inventory, "get", 1, NULL, 200, "\"name\":\"Renamed\"");
    expect(panel_ha_node_role(12) == PANEL_HA_REPLICA, "preserved old membership after failed replacement");
    expect(panel_ha_node_role(14) == PANEL_HA_STANDALONE, "rolled back new membership after failed replacement");

    panel_ha_close();
    expect(panel_ha_open(path), "restart with existing DB");
    request(&inventory, "get", 1, NULL, 200, "\"replica_node_ids\":[12,13]");
    request(&inventory, "delete", 1, NULL, 200, "\"message\"");
    request(&inventory, "get", 1, NULL, 404, "\"error\"");
    expect(panel_ha_node_role(11) == PANEL_HA_STANDALONE, "deleted primary membership");
    expect(panel_ha_node_role(12) == PANEL_HA_STANDALONE, "deleted replica membership");
    request(&inventory, "list", 0, NULL, 200, "[]");
    panel_ha_close();
    puts("HA group storage and preflight passed");
    return EXIT_SUCCESS;
}
