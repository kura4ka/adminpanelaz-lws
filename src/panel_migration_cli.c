#include "legacy_accounts.h"
#include "panel_backup_restore.h"
#include "panel_security_legacy.h"
#include "panel_settings.h"
#include "panel_telegram.h"

#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif

static bool read_password(char *out, size_t capacity)
{
#ifdef _WIN32
    if (_setmode(_fileno(stdin), _O_BINARY) == -1)
        return false;
#endif
    size_t size = 0;
    int ch;
    while ((ch = fgetc(stdin)) != EOF && ch != '\n') {
        if (ch == 0 || size == capacity - 1)
            return false;
        out[size++] = (char)ch;
    }
    if (ch == '\n' && size && out[size - 1] == '\r')
        --size;
    out[size] = '\0';
    return size && !ferror(stdin);
}

int main(int argc, char *argv[])
{
    if (argc == 3 && !strcmp(argv[1], "inspect-legacy-accounts")) {
        char result[4096];
        if (!legacy_accounts_inspect_json(result, sizeof(result), argv[2])) {
            fputs("Could not inspect the legacy account database.\n", stderr);
            return 1;
        }
        puts(result);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "import-legacy-accounts")) {
        if (!legacy_accounts_import(argv[2], argv[3])) {
            fputs("Could not stage account migration from the offline database.\n", stderr);
            return 1;
        }
        return 0;
    }
    if (argc == 5 && !strcmp(argv[1], "import-legacy-totp")) {
        char upstream_key[1026] = {0};
        const char *native_key = getenv("APAZ_SECURITY_KEY");
        unsigned int imported = 0;
        bool valid = native_key && *native_key && read_password(upstream_key, sizeof(upstream_key)) &&
                     panel_security_open(argv[4], native_key) &&
                     panel_security_import_legacy_totp(argv[2], argv[3], upstream_key, &imported);
        OPENSSL_cleanse(upstream_key, sizeof(upstream_key));
        panel_security_close();
        if (!valid) {
            fputs("Could not import two-factor settings from the offline database.\n", stderr);
            return 1;
        }
        printf("{\"imported\":%u}\n", imported);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "import-legacy-modules")) {
        if (!panel_settings_open(argv[3])) {
            fputs("Could not open the target settings database.\n", stderr);
            return 1;
        }
        enum panel_settings_result result = panel_settings_import_env(argv[2]);
        panel_settings_close();
        if (result != PANEL_SETTINGS_OK) {
            fputs("Could not import the module flags from the offline environment file.\n", stderr);
            return 1;
        }
        return 0;
    }
    if (argc == 5 && !strcmp(argv[1], "import-legacy-telegram")) {
        if (!panel_telegram_open(argv[4])) {
            fputs("Could not open the private Telegram database.\n", stderr);
            return 1;
        }
        enum panel_telegram_result result = panel_telegram_import_legacy(argv[2], argv[3]);
        panel_telegram_close();
        if (result == PANEL_TELEGRAM_CONFLICT)
            fputs("The destination Telegram database already has settings, a link or a completed import.\n", stderr);
        else if (result != PANEL_TELEGRAM_OK)
            fputs("Could not match Telegram settings and links to the migrated accounts.\n", stderr);
        return result == PANEL_TELEGRAM_OK ? 0 : 1;
    }
    if (argc == 4 && !strcmp(argv[1], "stage-native-auth")) {
        if (!panel_backup_stage_auth(argv[2], argv[3])) {
            fputs("Could not stage a verified native account archive.\n", stderr);
            return 1;
        }
        return 0;
    }
    if ((argc == 5 || (argc == 7 && !strcmp(argv[5], "--portal-db"))) &&
        !strcmp(argv[1], "stage-native-state")) {
        if (!panel_backup_stage_native_state(argv[2], argv[3], argc == 7 ? argv[6] : NULL, argv[4])) {
            fputs("Could not stage the native state from the offline data directory.\n", stderr);
            return 1;
        }
        return 0;
    }
    if ((argc == 4 || (argc == 5 && !strcmp(argv[4], "--password-stdin"))) &&
        !strcmp(argv[1], "stage-upstream")) {
        char password[PANEL_BACKUP_PASSWORD_MAX + 2] = {0};
        unsigned int components = 0;
        bool valid = (argc == 4 || read_password(password, sizeof(password))) &&
                     panel_backup_stage_upstream(argv[2], argv[3], argc == 5 ? password : NULL, &components);
        OPENSSL_cleanse(password, sizeof(password));
        if (!valid) {
            fputs("Could not stage the upstream backup for offline migration.\n", stderr);
            return 1;
        }
        printf("{\"components\":%u}\n", components);
        return 0;
    }
    fputs("usage: adminpanelaz-migration inspect-legacy-accounts OFFLINE_DB\n"
          "       adminpanelaz-migration import-legacy-accounts OFFLINE_DB NEW_AUTH_DB\n"
          "       adminpanelaz-migration import-legacy-totp OFFLINE_DB MIGRATED_AUTH_DB SECURITY_DB\n"
          "       adminpanelaz-migration import-legacy-modules OFFLINE_ENV NEW_DATA_DIR\n"
          "       adminpanelaz-migration import-legacy-telegram OFFLINE_DB MIGRATED_AUTH_DB TELEGRAM_DB\n"
          "       adminpanelaz-migration stage-native-auth ARCHIVE NEW_DB\n"
          "       adminpanelaz-migration stage-native-state STOPPED_DATA_DIR AUTH_DB NEW_DIR [--portal-db PORTAL_DB]\n"
          "       adminpanelaz-migration stage-upstream ARCHIVE NEW_DIR [--password-stdin]\n", stderr);
    return 2;
}
