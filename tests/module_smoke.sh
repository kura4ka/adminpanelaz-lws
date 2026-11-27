#!/bin/sh
set -eu

build=${1:?usage: sh tests/module_smoke.sh build-directory}
panel=$build/adminpanelaz-lws
migration=$build/adminpanelaz-migration
cc=${CC:-cc}
fixtures=$(mktemp -d)
trap 'rm -rf -- "$fixtures"' EXIT

python3 tests/legacy_accounts.py "$migration" --panel "$panel"
python3 tests/backup_restore.py "$migration"
python3 tests/cidr_migration.py "$build/adminpanelaz-cidr-import"
python3 tests/cidr_http.py "$panel"
python3 tests/local_vpn.py "$build/adminpanelaz-client" "$panel"
python3 tests/nodes.py "$panel"
python3 tests/portal.py "$panel"
python3 tests/security_http.py "$panel"
python3 tests/security_migration.py "$migration" "$panel"
python3 tests/telegram_http.py "$panel"
python3 tests/settings_smoke.py "$panel" "$migration"
python3 tests/history_migration.py "$build/adminpanelaz-history-migration"

mkdir "$fixtures/history"
"$cc" -std=c11 -Wall -Wextra -Wpedantic -Isrc tests/panel_history.c src/panel_history.c \
    src/host_metrics.c src/vpn_status.c src/wireguard_status.c -lsqlite3 -lcrypto -o "$fixtures/history-test"
"$fixtures/history-test" "$fixtures/history"

"$cc" -std=c11 -Wall -Wextra -Wpedantic -Isrc tests/panel_ha.c src/panel_ha.c \
    -lsqlite3 -lcrypto -o "$fixtures/ha-test"
"$fixtures/ha-test" "$fixtures/ha.db"

"$cc" -std=c11 -Wall -Wextra -Wpedantic -Isrc -fPIC -shared src/panel_telegram.c src/telegram_auth.c \
    -lsqlite3 -lcrypto -o "$fixtures/telegram-test.so"
python3 tests/telegram_store.py "$fixtures/telegram-test.so"
