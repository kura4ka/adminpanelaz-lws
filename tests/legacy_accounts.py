#!/usr/bin/env python3
"""Exercise offline account migration and native authentication with synthetic users."""

import argparse
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from urllib.parse import urlencode

from smoke import AUTH, HOST, TOKEN, PanelClient, choose_port, require, run_panel, wait_for_server


PASSWORD = "fixture-password-for-accounts"
LONG_PASSWORD = "Straße" * 20
BCRYPT = "$2b$04$abcdefghijklmnopqrstuumPIjZJKFz2gzaI6P/gNy.XHYlNtm4Ia"
BCRYPT_LONG = "$2b$04$abcdefghijklmnopqrstuukeGAOcfCyYeZs0K.hOadhNJsuONVRwW"
USERNAME = 'пользователь "тест"'


def source_fixture(path):
    with closing(sqlite3.connect(path)) as db, db:
        db.executescript("""
            CREATE TABLE users (
                id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, role TEXT,
                is_active INTEGER, panel_login_enabled INTEGER, must_change_password INTEGER,
                totp_enabled INTEGER, totp_secret_encrypted TEXT, totp_backup_codes_encrypted TEXT,
                telegram_id TEXT, access_until TEXT
            );
            CREATE TABLE webauthn_credentials (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id));
            CREATE INDEX credential_user ON webauthn_credentials(user_id);
        """)
        db.executemany("INSERT INTO users VALUES (?,?,?,?,?,?,?,?,NULL,NULL,NULL,?)", [
            (7, "fixture-admin", BCRYPT, "admin", 1, 1, 0, 0, None),
            (18, USERNAME, BCRYPT_LONG, "user", 1, 1, 0, 0, "2039-01-01 00:00:00.123456"),
            (19, "inactive", BCRYPT, "user", 0, 1, 0, 0, None),
            (20, "disabled", BCRYPT, "admin", 1, 0, 0, 0, None),
            (21, "rotate", BCRYPT, "admin", 1, 1, 1, 0, None),
            (22, "totp", BCRYPT, "admin", 1, 1, 0, 1, None),
            (23, "passkey", BCRYPT, "admin", 1, 1, 0, 0, None),
            (24, "passwordless", "!", "user", 1, 1, 0, 0, None),
        ])
        db.execute("INSERT INTO webauthn_credentials VALUES (1,23)")


def migration_command(executable, source, destination, succeeds=True):
    result = subprocess.run([executable, "import-legacy-accounts", source, destination],
                            capture_output=True, timeout=10)
    require((result.returncode == 0) == succeeds, f"Unexpected migration exit {result.returncode}")
    require(BCRYPT.encode() not in result.stdout + result.stderr, "Migration exposed a password hash")


def check_migration(executable, root):
    source = root / "upstream fixture.db"
    destination = root / "staged auth.db"
    source_fixture(source)
    migration_command(executable, source, destination)
    original = destination.read_bytes()
    migration_command(executable, source, destination)
    require(destination.read_bytes() == original, "Repeated import rewrote the staged database")
    with closing(sqlite3.connect(destination)) as db:
        rows = db.execute("SELECT id, username, role, is_active, panel_login_enabled, must_change_password,"
                          " totp_enabled, has_passkeys FROM panel_accounts JOIN panel_legacy_accounts"
                          " ON id=account_id ORDER BY id").fetchall()
        require(rows[0] == (7, "fixture-admin", "admin", 1, 1, 0, 0, 0), "Admin identity changed")
        require(rows[1] == (18, USERNAME, "user", 1, 1, 0, 0, 0), "User identity changed")
        require(rows[2][3:5] == (0, 1) and rows[3][3:5] == (1, 0), "Disabled accounts changed")
        require(rows[4][5] == 1 and rows[5][6] == 1 and rows[6][7] == 1, "Login policy changed")
        require(db.execute("SELECT bcrypt_hash FROM panel_legacy_accounts WHERE account_id=24").fetchone() == (None,),
                "An unsupported password placeholder became a password hash")
        require(db.execute("SELECT access_until FROM panel_legacy_accounts WHERE account_id=18").fetchone() ==
                ("2039-01-01 00:00:00.123456",), "Access deadline changed")
        require(db.execute("SELECT count(*) FROM panel_sessions").fetchone() == (0,), "Migration preserved sessions")

    untrusted = root / "unrelated.db"
    untrusted.write_bytes(b"preserve this file")
    migration_command(executable, source, untrusted, succeeds=False)
    require(untrusted.read_bytes() == b"preserve this file", "Conflicting file was overwritten")
    with closing(sqlite3.connect(source)) as db, db:
        db.execute("UPDATE users SET role='user' WHERE id=7")
    migration_command(executable, source, destination, succeeds=False)
    require(destination.read_bytes() == original, "Conflicting source changed the staged database")
    with closing(sqlite3.connect(source)) as db, db:
        db.execute("UPDATE users SET role=CASE id WHEN 7 THEN 'admin' ELSE 'invalid' END WHERE id IN (7,24)")
    rejected = root / "rejected.db"
    migration_command(executable, source, rejected, succeeds=False)
    require(not rejected.exists(), "Malformed account published a partial database")
    return destination


def auth_form(client, path, fields, cookie=None, method="POST"):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    if cookie:
        headers.update(cookie)
    with closing(client.connection()) as connection:
        connection.request(method, path, urlencode(fields), headers)
        with connection.getresponse() as response:
            set_cookie = response.getheader("Set-Cookie")
            return response.status, json.loads(response.read()), {"Cookie": set_cookie.split(";", 1)[0]} if set_cookie else {}


def check_login(binary, root, database):
    port = choose_port()
    client = PanelClient(port, tls=False)
    command = [binary, "--port", str(port), "--bind", HOST, "--data-dir", root, "--auth-db", database]

    def login(username, password=PASSWORD):
        return auth_form(client, "/api/auth/login", {"username": username, "password": password})

    log = root / "migration-panel.log"
    with run_panel(command, log) as process:
        wait_for_server(process, client)
        status, identity, admin = login("fixture-admin")
        require(status == 200 and admin and identity["role"] == "admin", "Imported admin could not sign in")
        status, identity, user = login(USERNAME, LONG_PASSWORD)
        require(status == 200 and user and identity["username"] == USERNAME and identity["role"] == "user",
                "Imported user or bcrypt's 72-byte compatibility failed")
        status, body = client.request("GET", "/api/auth/me", headers=user)
        require(status == 200 and json.loads(body)["role"] == "user", "Session role was lost")
        require(client.request("GET", "/api/backups", headers=user)[0] in (401, 403), "A user can list all backups")
        require(client.request("GET", "/api/backups", headers=admin)[0] == 200, "Admin cannot list backups")
        for username in ("inactive", "disabled", "totp", "passkey", "passwordless"):
            status, _, cookie = login(username)
            require(status == 401 and not cookie, f"Blocked login incorrectly succeeded for {username}")

    with run_panel(command, log) as process:
        wait_for_server(process, client)
        status, identity, cookie = login("rotate")
        require(status == 200 and identity["must_change_password"], "Forced password change was lost")
        require(client.request("GET", "/api/auth/me", headers=cookie)[0] == 200, "Restricted session lost its identity")
        require(client.request("GET", "/api/backups", headers=cookie)[0] in (401, 403),
                "Forced-change session can list backups")
        replacement = "fixture-new-password-for-accounts"
        status, _, _ = auth_form(client, "/api/auth/change-password",
                                 {"old_password": PASSWORD, "new_password": replacement}, cookie)
        require(status == 200, "Imported bcrypt password could not be changed")
        require(client.request("GET", "/api/auth/me", headers=cookie)[0] == 401, "Old session survived password change")
        require(login("rotate")[0] == 401, "Old bcrypt password was retained")
        status, identity, cookie = login("rotate", replacement)
        require(status == 200 and cookie and not identity["must_change_password"], "New password could not sign in")
        require(client.request("GET", "/api/monitor", headers=AUTH)[0] == 200, "Monitoring token became unusable")


def check_users(binary, root):
    root.mkdir()
    database = root / "users.db"
    port = choose_port()
    client = PanelClient(port, tls=False)
    command = [binary, "--port", str(port), "--bind", HOST, "--data-dir", root, "--auth-db", database]
    users_path = "/api/settings/users"
    settings = {"role": "user", "is_active": 1, "panel_login_enabled": 1, "must_change_password": 0}

    def login(username, password):
        return auth_form(client, "/api/auth/login", {"username": username, "password": password})

    def list_users(cookie, query=None):
        path = users_path + ("?" + urlencode({"q": query}) if query else "")
        status, raw = client.request("GET", path, headers=cookie)
        require(status == 200, f"List users returned {status}")
        return json.loads(raw)["users"]

    log = root / "users-panel.log"
    with run_panel(command, log) as process:
        wait_for_server(process, client)
        status, asset = client.request("GET", "/assets/users.js")
        require(status == 200 and b".users = { mount }" in asset, "Users view module was not embedded")
        status, _, admin = login("admin", TOKEN)
        require(status == 200 and admin, "Native administrator could not sign in")
        feature = "/api/settings/features"
        toggle = {"key": "user_management", "enabled": 0}
        require(auth_form(client, feature, toggle, admin)[0] == 200, "Could not disable account management module")
        require(client.request("GET", users_path, headers=admin)[0] == 403, "Disabled module still exposes user data")
        require(auth_form(client, feature, {**toggle, "enabled": 1}, admin)[0] == 200, "Could not re-enable module")
        native = list_users(admin)[0]
        rm = f"{users_path}/{native['id']}?revision={native['revision']}"
        require(client.request("DELETE", rm, headers=admin)[0] == 403, "Current administrator could delete itself")
        status, body, _ = auth_form(client, f"{users_path}/{native['id']}",
                                    {**settings, "revision": native["revision"]}, admin, method="PUT")
        require(status == 409 and body["error"] == "last_admin", "Panel allowed demoting its last administrator")
        created = {**settings, "username": USERNAME, "password": PASSWORD}
        status, body, _ = auth_form(client, users_path, created, admin)
        require(status == 201, f"Could not create a native user ({status}, {body})")
        account_id = body["id"]
        user = next(user for user in list_users(admin) if user["id"] == account_id)
        require(user["username"] == USERNAME and user["role"] == "user", "New user list identity differs")
        require(list_users(admin, '"тест"') == [user] and list_users(admin, "missing-account") == [],
                "Unicode username search did not filter records")
        status, body, _ = auth_form(client, users_path, created, admin)
        require(status == 409 and body["error"] == "username_taken", "Duplicate username was allowed")
        status, _, member = login(USERNAME, PASSWORD)
        require(status == 200 and member, "New native user could not sign in")
        require(client.request("GET", users_path, headers=member)[0] == 403, "User can list all accounts")
        user_route = f"{users_path}/{account_id}"
        update = {**settings, "is_active": 0, "revision": user["revision"]}
        require(auth_form(client, user_route, update, admin, method="PUT")[0] == 200, "Could not disable account")
        require(client.request("GET", "/api/auth/me", headers=member)[0] == 401,
                "Disabled account kept an old session")
        require(login(USERNAME, PASSWORD)[0] == 401, "Disabled account could start a session")
        require(auth_form(client, user_route, update, admin, method="PUT")[0] == 409, "Stale edit was accepted")
        user = next(user for user in list_users(admin) if user["id"] == account_id)
        update = {**settings, "panel_login_enabled": 0, "revision": user["revision"]}
        require(auth_form(client, user_route, update, admin, method="PUT")[0] == 200, "Could not disable panel login")
        require(login(USERNAME, PASSWORD)[0] == 401, "Panel login was allowed despite policy")
        user = next(user for user in list_users(admin) if user["id"] == account_id)
        update = {**settings, "role": "admin", "revision": user["revision"]}
        require(auth_form(client, user_route, update, admin, method="PUT")[0] == 200, "Could not promote a user")
        user = next(user for user in list_users(admin) if user["id"] == account_id)
        status, body, member = login(USERNAME, PASSWORD)
        require(status == 200 and body["role"] == "admin" and member, "Updated role was not applied")
        replacement = "fixture-password-reset-by-admin"
        body = {"password": replacement, "revision": user["revision"], "must_change_password": 1}
        require(auth_form(client, user_route + "/reset-password", body, admin)[0] == 200, "Admin reset failed")
        require(client.request("GET", "/api/auth/me", headers=member)[0] == 401, "Admin reset retained old session")
        status, body, member = login(USERNAME, replacement)
        require(status == 200 and body["must_change_password"] and member, "Admin reset did not require change")
        require(client.request("GET", users_path, headers=member)[0] == 403, "Forced-change session can list users")
        user = next(user for user in list_users(admin) if user["id"] == account_id)
        remove_route = f"{user_route}?revision={user['revision']}"
        require(client.request("DELETE", remove_route, headers=admin)[0] == 200, "Could not delete account")
        require(client.request("DELETE", remove_route, headers=admin)[0] == 200, "Delete is not safe to repeat")
        require(client.request("GET", "/api/auth/me", headers=member)[0] == 401, "Deleted account kept its session")

    with run_panel(command, log) as process:
        wait_for_server(process, client)
        status, body, _ = auth_form(client, users_path, created, admin)
        require(status == 201 and int(body["id"]) > int(account_id), "Deleted account ID was recycled after restart")


def check_auth_upgrade(binary, root, pre_marker, early_revision=False):
    root.mkdir()
    database = root / "auth.db"
    security = root / "lws-security.db"
    saved_security = root / "paired-security.db"
    port = choose_port()
    client = PanelClient(port, tls=False)
    command = [binary, "--port", str(port), "--bind", HOST, "--data-dir", root, "--auth-db", database]
    log = root / "upgrade-panel.log"

    with run_panel(command, log) as process:
        wait_for_server(process, client)
        status, _, cookie = auth_form(client, "/api/auth/login", {"username": "admin", "password": TOKEN})
        require(status == 200 and cookie, "Could not create a session for the old auth store")
        if pre_marker:
            fields = {"username": "previous-user", "password": PASSWORD, "role": "user", "is_active": 0,
                      "panel_login_enabled": 0, "must_change_password": 1}
            require(auth_form(client, "/api/settings/users", fields, cookie)[0] == 201,
                    "Could not create a policy row for the old auth store")

    with closing(sqlite3.connect(database)) as db, db:
        if pre_marker:
            db.execute("ALTER TABLE panel_legacy_accounts DROP COLUMN native_totp_required")
            if early_revision:
                schema, = db.execute("SELECT sql FROM sqlite_schema WHERE name='panel_legacy_accounts'").fetchone()
                early_schema = schema.replace("CHECK(typeof(revision) = 'integer' AND revision > 0)", "CHECK(revision > 0)")
                require(early_schema != schema, "Could not reproduce the initial revision constraint")
                db.execute("ALTER TABLE panel_legacy_accounts RENAME TO panel_policy_fixture")
                db.execute(early_schema)
                db.execute("INSERT INTO panel_legacy_accounts SELECT * FROM panel_policy_fixture")
                db.execute("DROP TABLE panel_policy_fixture")
        else:
            db.executescript("DROP TABLE panel_legacy_accounts; DROP TABLE panel_account_ids;")
    if not pre_marker:
        security.rename(saved_security)

    with run_panel(command, log) as process:
        wait_for_server(process, client)
        status, body = client.request("GET", "/api/auth/me", headers=cookie)
        require(status == 200 and json.loads(body)["username"] == "admin",
                "Existing sessions did not survive the auth schema upgrade")
        if pre_marker:
            status, body = client.request("GET", "/api/settings/users", headers=cookie)
            users = json.loads(body)["users"] if status == 200 else []
            require(len(users) == 2 and users[1]["username"] == "previous-user" and users[1]["role"] == "user" and
                    not users[1]["is_active"] and not users[1]["panel_login_enabled"] and users[1]["must_change_password"],
                    "Account policy changed during upgrade")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("migration", type=Path)
    parser.add_argument("--panel", type=Path, help="Linux panel binary to test imported bcrypt logins")
    arguments = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="apaz-account-migration-") as temporary:
        root = Path(temporary)
        database = check_migration(arguments.migration.resolve(), root)
        if arguments.panel:
            check_login(arguments.panel.resolve(), root, database)
            check_users(arguments.panel.resolve(), root / "user-management")
            check_auth_upgrade(arguments.panel.resolve(), root / "pre-marker", pre_marker=True)
            check_auth_upgrade(arguments.panel.resolve(), root / "initial-policy", pre_marker=True, early_revision=True)
            check_auth_upgrade(arguments.panel.resolve(), root / "baseline-auth", pre_marker=False)
    print("Legacy account migration checks passed")


if __name__ == "__main__":
    sys.exit(main())
