#include "panel_history.h"

#include <inttypes.h>
#include <sqlite3.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "Line %d: %s\n", __LINE__, #condition); \
        exit(EXIT_FAILURE); \
    } \
} while (0)

static const int64_t start = INT64_C(1700000400);
static const int64_t day = INT64_C(86400);

static void write_ovpn(const char *path, int64_t rx, int64_t tx, int64_t since, bool complete)
{
    FILE *file = fopen(path, "wb");
    CHECK(file);
    CHECK(fprintf(file, "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\t"
        "Bytes Received\tBytes Sent\tConnected Since\tConnected Since (time_t)\n"
        "CLIENT_LIST\ttest\t192.0.2.1:4352\t10.0.0.2\t%" PRId64 "\t%" PRId64 "\ttime\t%" PRId64 "\n%s",
        rx, tx, since, complete ? "END\n" : "") > 0);
    CHECK(fclose(file) == 0);
}

static void write_wg(const char *path, int64_t rx, int64_t tx, int64_t handshake)
{
    FILE *file = fopen(path, "wb");
    CHECK(file);
    CHECK(fprintf(file, "WIREGUARD_STATUS_V1\nwg0\tkey000000000\t192.0.2.2:4352\t10.0.0.3/32\t"
        "%" PRId64 "\t%" PRId64 "\t%" PRId64 "\nEND\n", rx, tx, handshake) > 0);
    CHECK(fclose(file) == 0);
}

int main(int argc, char **argv)
{
    CHECK(argc == 2);
    const char *data_dir = argv[1];
    char openvpn[4096], wireguard[4096], db_path[4096];
    CHECK(snprintf(openvpn, sizeof(openvpn), "%s/openvpn.status", data_dir) < (int)sizeof(openvpn));
    CHECK(snprintf(wireguard, sizeof(wireguard), "%s/wireguard.status", data_dir) < (int)sizeof(wireguard));
    CHECK(snprintf(db_path, sizeof(db_path), "%s/lws-history.db", data_dir) < (int)sizeof(db_path));
    const char *paths[] = { openvpn, openvpn };
    char json[PANEL_HISTORY_JSON_CAP];

    CHECK(panel_history_open(data_dir));
    write_ovpn(openvpn, 100, 200, start - 5, true);
    write_wg(wireguard, 500, 700, start - 10);
    CHECK(panel_history_sample(data_dir, paths, 2, wireguard, start));
    CHECK(panel_history_sample(data_dir, paths, 2, wireguard, start + 30));
    CHECK(panel_history_json(json, sizeof(json), PANEL_HISTORY_CONNECTIONS, 1, start + 30));
    CHECK(strstr(json, "\"openvpn\":1,\"wireguard\":1,\"total\":2"));
    CHECK(strstr(json, "\"sample_count\":1"));

    write_ovpn(openvpn, 160, 300, start - 5, true);
    write_wg(wireguard, 10, 740, start + 60);
    CHECK(panel_history_sample(data_dir, paths, 2, wireguard, start + 60));
    write_ovpn(openvpn, 200, 400, start - 5, false);
    CHECK(remove(wireguard) == 0);
    CHECK(panel_history_sample(data_dir, paths, 2, wireguard, start + 120));
    write_ovpn(openvpn, 210, 450, start - 5, true);
    write_wg(wireguard, 14, 800, start + 180);
    CHECK(panel_history_sample(data_dir, paths, 2, wireguard, start + 180));
    CHECK(panel_history_json(json, sizeof(json), PANEL_HISTORY_TRAFFIC, 1, start + 180));
    CHECK(strstr(json, "\"rx_bytes\":224,\"tx_bytes\":550,\"complete\":false"));
    CHECK(strstr(json, "\"sample_count\":4"));
    /* A malformed record followed by END must not advance a traffic baseline. */
    write_ovpn(openvpn, 990, 990, start - 5, false);
    FILE *invalid = fopen(openvpn, "ab");
    CHECK(invalid);
    CHECK(fwrite("bad\0row\nEND\n", 1, 12, invalid) == 12);
    CHECK(fclose(invalid) == 0);
    CHECK(panel_history_sample(data_dir, paths, 2, wireguard, start + 240));

    panel_history_close();
    CHECK(panel_history_open(data_dir));
    CHECK(panel_history_sample(data_dir, paths, 2, wireguard, start + 241));
    write_ovpn(openvpn, 20, 100, start + 245, true);
    write_wg(wireguard, 20, 810, start + 599);
    CHECK(panel_history_sample(data_dir, paths, 2, wireguard, start + 600));
    CHECK(panel_history_json(json, sizeof(json), PANEL_HISTORY_TRAFFIC, 7, start + 600));
    CHECK(strstr(json, "\"rx_bytes\":250,\"tx_bytes\":660,\"complete\":false"));
    CHECK(strstr(json, "\"sample_count\":6"));
    CHECK(panel_history_client_json(json, sizeof(json), "test", 1, start + 600));
    CHECK(strstr(json, "\"rx_bytes\":230,\"tx_bytes\":550,\"complete\":false"));
    CHECK(panel_history_client_json(json, sizeof(json), "wg0 · key000000000", 1, start + 600));
    CHECK(strstr(json, "\"rx_bytes\":20,\"tx_bytes\":110,\"complete\":false"));
    CHECK(panel_history_client_json(json, sizeof(json), "' OR 1=1 --", 1, start + 600));
    CHECK(strstr(json, "\"sample_count\":0"));

    int64_t later = start + 31 * day;
    CHECK(panel_history_audit(start + 600, 7, PANEL_HISTORY_BACKUP_CREATE, true));
    CHECK(panel_history_audit(start + 650, 0, PANEL_HISTORY_LOGIN, false));
    CHECK(panel_history_json(json, sizeof(json), PANEL_HISTORY_AUDIT, 1, start + 670));
    CHECK(strstr(json, "\"actor_id\":7,\"action\":\"backup_create\",\"success\":true"));
    CHECK(strstr(json, "\"actor_id\":null,\"action\":\"login\",\"success\":false"));
    CHECK(panel_history_sample(data_dir, NULL, 0, NULL, later));
    CHECK(panel_history_json(json, sizeof(json), PANEL_HISTORY_AUDIT, 30, later));
    CHECK(strstr(json, "\"sample_count\":0"));
    CHECK(!panel_history_json(json, sizeof(json), PANEL_HISTORY_TRAFFIC, 2, later));
    CHECK(!panel_history_json(json, 16, PANEL_HISTORY_RESOURCES, 1, later) && !json[0]);
    panel_history_close();

    sqlite3 *db = NULL;
    sqlite3_stmt *statement = NULL;
    CHECK(sqlite3_open_v2(db_path, &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK);
    CHECK(sqlite3_prepare_v2(db, "SELECT ts,rx,tx FROM observation", -1, &statement, NULL) == SQLITE_OK);
    CHECK(sqlite3_step(statement) == SQLITE_ROW);
    CHECK(sqlite3_column_int64(statement, 0) == later);
    CHECK(sqlite3_column_type(statement, 1) == SQLITE_NULL && sqlite3_column_type(statement, 2) == SQLITE_NULL);
    CHECK(sqlite3_step(statement) == SQLITE_DONE);
    sqlite3_finalize(statement);
    sqlite3_close(db);
    return EXIT_SUCCESS;
}
