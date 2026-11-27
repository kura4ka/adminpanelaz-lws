#!/usr/bin/env python3
"""Check persisted modules and safe config reads through the panel and migration CLI."""

import argparse
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import tempfile
from urllib.parse import urlencode

from smoke import AUTH, HOST, TOKEN, PanelClient, choose_port, require, run_panel, wait_for_server


PREFIX = "/test/panel"
FEATURES = "/api/settings/features"
DIAGNOSTICS = "/api/settings/diagnostics"
FILES = "/api/settings/edit-files"


class SettingsClient(PanelClient):
    def request(self, method, path, body=None, headers=None):
        return super().request(method, PREFIX + path, body=body, headers=headers)


def login(client):
    with closing(client.connection()) as conn:
        conn.request("POST", PREFIX + "/api/auth/login", urlencode({"username": "admin", "password": TOKEN}),
                     {"Content-Type": "application/x-www-form-urlencoded"})
        with conn.getresponse() as response:
            response.read()
            cookie = response.getheader("Set-Cookie")
            require(response.status == 200 and cookie, f"Login returned {response.status}")
            return {"Cookie": cookie.split(";", 1)[0]}


def fetch(client, path, cookie, expected=200):
    status, body = client.request("GET", path, headers=cookie)
    require(status == expected, f"{path} returned {status}, expected {expected}")
    return json.loads(body)


def toggle(client, cookie, key, enabled, expected=200):
    status, _ = client.request("POST", FEATURES, urlencode({"key": key, "enabled": str(int(enabled))}),
                               {**cookie, "Content-Type": "application/x-www-form-urlencoded"})
    require(status == expected, f"{key} toggle returned {status}, expected {expected}")


def migrate(binary, source, data, expected=0):
    result = subprocess.run([str(binary), "import-legacy-modules", str(source), str(data)],
                            check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    require(result.returncode == expected, f"Module flag migration exited with {result.returncode}")


def suite(panel, migration, root):
    data = root / "data"
    config = root / "config"
    knot = root / "knot"
    for directory in (data, config, knot):
        directory.mkdir()
    text = 'example.org\n\"список\"\\\n'
    (config / "include-hosts.txt").write_bytes(text.replace("\n", "\r\n").encode() + b"\xff")
    (config / "allow-ips.txt").write_bytes(b"X" * (32 * 1024 + 1))
    (knot / "custom.lua").write_text("-- DNS\n", encoding="utf-8")
    secret = root / "not-allowlisted"
    secret.write_text("not-visible", encoding="utf-8")
    hardlink = config / "drop-ips.txt"
    os.link(secret, hardlink)
    symlink = config / "exclude-hosts.txt"
    if os.name != "nt":
        symlink.symlink_to(secret)

    dotenv = root / ".env"
    dotenv.write_text("FEATURE_ROUTING_ENABLED='off'\nFEATURE_PROXY_NODES_ENABLED=ON\n"
                      "THIS_IS_NOT_A_FLAG=not-stored\n", encoding="utf-8")
    migrate(migration, dotenv, data)
    invalid = root / "invalid.env"
    invalid.write_text("FEATURE_NODES_ENABLED=false\nFEATURE_TELEGRAM_ENABLED=invalid\n", encoding="utf-8")
    migrate(migration, invalid, data, expected=1)
    with closing(sqlite3.connect(data / "panel-settings.db")) as db:
        flags = dict(db.execute("SELECT key, enabled FROM feature_flags"))
    require(flags == {"routing": 0, "proxy_nodes": 1}, f"Unexpected imported keys or partial writes: {flags}")

    port = choose_port()
    client = SettingsClient(port, tls=False)
    log = root / "panel.log"
    command = [str(panel), "--port", str(port), "--bind", HOST, "--access-path", PREFIX,
               "--data-dir", str(data), "--auth-db", str(data / "auth.db"),
               "--config-dir", str(config), "--knot-dir", str(knot)]

    with run_panel(command, log) as process:
        wait_for_server(process, client)
        for headers in ({}, AUTH):
            require(client.request("GET", FILES, headers=headers)[0] in (401, 403),
                    "Config list was exposed without a password session")
        cookie = login(client)
        items = fetch(client, FEATURES, cookie)
        require(items["features"]["routing"] is False and items["features"]["proxy_nodes"] is True,
                "Imported flags not applied")
        require(len(items["items"]) == items["total"] and len(items["features"]) == items["total"],
                "Feature registry did not round trip to JSON")
        report = fetch(client, DIAGNOSTICS, cookie)
        results = {entry["check_id"]: entry["status"] for entry in report["results"]}
        require(results.get("panel_http") == "ok" and results.get("panel_tls") == "warn" and
                results.get("antizapret_lists") == "ok" and results.get("knot_resolver") == "ok",
                "Unexpected diagnostics")
        files = fetch(client, FILES, cookie)
        require(len(files) == 21 and files[0]["key"] == "include_hosts", "Editor allowlist changed")
        require(fetch(client, FILES + "/include_hosts", cookie)["content"] == text + "\ufffd",
                "Editor did not preserve escaped text and UTF-8")
        require(fetch(client, FILES + "/kresd_custom", cookie)["content"] == "-- DNS\n",
                "Editor resolved a Knot policy outside the designated root")
        require(fetch(client, FILES + "/deny_rpz", cookie)["content"] == "", "Missing list should be empty")
        fetch(client, FILES + "/unknown", cookie, expected=404)
        fetch(client, FILES + "/allow_ips", cookie, expected=413)
        fetch(client, FILES + "/drop_ips", cookie, expected=503)
        if symlink.is_symlink():
            fetch(client, FILES + "/exclude_hosts", cookie, expected=503)
        toggle(client, cookie, "nonexistent", False, expected=400)
        toggle(client, cookie, "clients_page", False, expected=409)
        toggle(client, cookie, "edit_files", False)
        fetch(client, FILES, cookie, expected=403)
        fetch(client, FILES + "/include_hosts", cookie, expected=403)
        toggle(client, cookie, "routing", True)

    migrate(migration, dotenv, data)
    with run_panel(command, log) as process:
        wait_for_server(process, client)
        cookie = login(client)
        flags = fetch(client, FEATURES, cookie)["features"]
        require(flags["routing"] is True and flags["edit_files"] is False,
                "Settings changed after restart or replayed migration")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("panel", type=Path)
    parser.add_argument("migration", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="apaz-settings-") as directory:
        suite(args.panel.resolve(), args.migration.resolve(), Path(directory))
    print("Settings smoke test passed")


if __name__ == "__main__":
    main()
