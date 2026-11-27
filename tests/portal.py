#!/usr/bin/env python3
"""Check legacy public portal links, files and host isolation on a local panel."""

import argparse
from contextlib import closing
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
from urllib.parse import urlencode

from smoke import HOST, TOKEN, PanelClient, json_object, require


PORTAL_HOST = "portal.example.test"
ADMIN_HOST = "panel.example.test"
PORTAL_HEADERS = {"Host": PORTAL_HOST}
ADMIN_HEADERS = {"Host": ADMIN_HOST}
BASE = "/api/public/portal/"
ALICE = b"client\nremote alice.example.test 1194\n"
BOB = b"client\nremote bob.example.test 1194\n"
ALICE_ALT = b"client\nremote other.example.test 1194\n"


def make_fixture(path):
    with closing(sqlite3.connect(path)) as db, db:
        db.executescript("""
            CREATE TABLE app_settings(key TEXT PRIMARY KEY, value TEXT);
            CREATE TABLE users(id INTEGER PRIMARY KEY, role TEXT, is_active INTEGER,
              visible_vpn_profiles TEXT, access_until TEXT, suspended_at TEXT,
              suspend_reason_visible INTEGER, suspend_reason TEXT, traffic_limit_blocked INTEGER,
              portal_banner_text TEXT, portal_banner_at TEXT);
            CREATE TABLE nodes(id INTEGER PRIMARY KEY, name TEXT, portal_label TEXT, is_local INTEGER, status TEXT);
            CREATE TABLE vpn_configs(id INTEGER PRIMARY KEY, node_id INTEGER, client_name TEXT,
              vpn_type TEXT, owner_id INTEGER, expires_at TEXT, cert_expires_at TEXT, ha_primary_config_id INTEGER);
            CREATE TABLE client_portal_tokens(token TEXT PRIMARY KEY, node_id INTEGER, client_name TEXT,
              created_at TEXT, revoked_at TEXT);
            CREATE TABLE user_portal_tokens(token TEXT PRIMARY KEY, user_id INTEGER, created_at TEXT, revoked_at TEXT);
            CREATE TABLE user_traffic_stat_protocol(node_id INTEGER, common_name TEXT, protocol_type TEXT,
              total_received INTEGER, total_sent INTEGER);
        """)
        for table, deadline in [
            ("openvpn_access_policy", "access_until"), ("wg_access_policy", "expires_at"),
            ("amneziawg2_access_policies", "access_until"),
        ]:
            db.execute(f"""CREATE TABLE {table}(node_id INTEGER, client_name TEXT, {deadline} TEXT,
              is_temp_blocked INTEGER, is_permanent_blocked INTEGER, block_until TEXT, traffic_limit_bytes INTEGER)""")
        policy = json.dumps({"routes": ["vpn"], "protocols": ["openvpn"], "openvpn_groups": ["udp_tcp"]})
        links = json.dumps({"openvpn": {"windows": "https://example.test/openvpn", "linux": "javascript:alert(1)"}})
        db.executemany("INSERT INTO app_settings VALUES (?,?)", [
            ("portal_domain", PORTAL_HOST), ("portal_title", 'Подключение "тест"'),
            ("portal_link_ttl_days", "30"), ("portal_app_links", links),
        ])
        db.executemany("INSERT INTO users(id,role,is_active,visible_vpn_profiles) VALUES (?,?,?,?)",
                       [(1, "user", 1, policy), (2, "admin", 1, None), (3, "user", 0, None)])
        db.executemany("INSERT INTO nodes VALUES (?,?,?,?,?)", [(1, "Local", "Дом", 1, "online"), (2, "Remote", "", 0, "online")])
        db.executemany("INSERT INTO vpn_configs VALUES (?,?,?,?,?,?,?,?)", [
            (1, 1, "alice", "openvpn", 1, None, None, None),
            (2, 1, "bob", "openvpn", 2, None, None, None),
            (3, 2, "alice", "openvpn", 1, None, None, None),
            (4, 1, "alice", "wireguard", 2, None, None, None),
            (5, 1, "expired", "openvpn", 2, None, "2020-02-01", None),
            (6, 1, "blocked", "openvpn", 2, None, None, None),
        ])
        db.execute("INSERT INTO openvpn_access_policy(node_id,client_name,is_permanent_blocked) VALUES (1,'blocked',1)")
        db.execute("INSERT INTO user_traffic_stat_protocol VALUES (1,'alice','openvpn',1024,2048)")
        now = datetime.now(timezone.utc).isoformat()
        db.executemany("INSERT INTO client_portal_tokens VALUES (?,?,?,?,?)", [
            ("c_alice", 1, "alice", now, None), ("c_bob", 1, "bob", now, None),
            ("c_old", 1, "alice", "2020-01-01 00:00:00", None),
            ("c_revoked", 1, "alice", now, now), ("c_remote", 2, "alice", now, None),
            ("c_expired", 1, "expired", now, None), ("c_blocked", 1, "blocked", now, None),
            ("collision", 1, "alice", now, None),
        ])
        db.executemany("INSERT INTO user_portal_tokens VALUES (?,?,?,?)", [
            ("u_alice", 1, now, None), ("u_disabled", 3, now, None), ("collision", 1, now, None),
        ])


def make_profiles(root):
    for path, value in [
        ("openvpn/vpn/vpn-alice.ovpn", ALICE), ("openvpn/antizapret/antizapret-alice.ovpn", b"restricted"),
        ("openvpn/vpn/vpn-alice-(other.example.test).ovpn", ALICE_ALT),
        ("openvpn/vpn/vpn-expired.ovpn", b"expired"), ("openvpn/vpn/vpn-blocked.ovpn", b"blocked"),
        ("openvpn/vpn/vpn-bob.ovpn", BOB), ("openvpn/vpn/vpn-alice-2.ovpn", b"different-client"),
        ("wireguard/vpn/vpn-alice-wg.conf", b"different-protocol-owner"),
    ]:
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(value)
    if sys.platform.startswith("linux"):
        (root / "openvpn/vpn/vpn-alice-(symlink.example.test).ovpn").symlink_to("vpn-bob.ovpn")


def request(client, path, expected, headers=PORTAL_HEADERS, method="GET"):
    status, body = client.request(method, path, headers=headers)
    require(status == expected, f"{method} {path} returned {status}, expected {expected}")
    return body


def wait_for_server(process, client):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and process.poll() is None:
        try:
            status, _ = client.request("GET", "/panel14/api/health", headers=ADMIN_HEADERS)
            if status == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        time.sleep(0.05)
    raise AssertionError(f"Panel did not become ready ({process.returncode})")


def test_panel(client):
    request(client, "/api/health", 404)
    request(client, "/panel14/api/health", 200, ADMIN_HEADERS)
    request(client, "/p/c_alice", 404, ADMIN_HEADERS)
    require(b"<title>" in request(client, "/p/c_alice", 200), "Portal page is not HTML")
    request(client, "/panel14/p/c_alice", 404)
    request(client, BASE + "c_alice", 404, ADMIN_HEADERS)
    upgrade = {**PORTAL_HEADERS, "Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Version": "13",
               "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==", "Sec-WebSocket-Protocol": "adminpanel-monitor",
               "Authorization": f"Bearer {TOKEN}"}
    request(client, "/panel14/api/monitor/ws", 404, upgrade)
    for token in ["c_missing", "c_old", "c_revoked", "u_disabled", "c_remote", "collision"]:
        request(client, BASE + token, 404)
    entry = json_object(request(client, BASE + "c_alice", 200), "Client portal")
    require(entry["kind"] == "client" and entry["brand_title"] == 'Подключение "тест"', "Incorrect client metadata")
    require(entry["status"]["traffic_used_bytes"] == 3072, "Traffic totals are incorrect")
    require(entry["app_links"] == {"openvpn": {"windows": "https://example.test/openvpn"}}, "Application links were not filtered")
    for state in ["expired", "blocked"]:
        current = json_object(request(client, BASE + "c_" + state, 200), "Client portal access")
        require(current["status"]["status"] == state, "Client access status is incorrect")
    user = json_object(request(client, BASE + "u_alice", 200), "User portal")
    require(user["kind"] == "user", "Wrong token type for owner portal")
    if not sys.platform.startswith("linux"):
        return
    legacy_path = "/root/antizapret/client/openvpn/vpn/vpn-alice.ovpn"
    alternative = "/root/antizapret/client/openvpn/vpn/vpn-alice-(other.example.test).ovpn"
    file_id = "f_" + hashlib.sha256(legacy_path.encode()).hexdigest()[:24]
    alternate_id = "f_" + hashlib.sha256(alternative.encode()).hexdigest()[:24]
    files = user["nodes"][0]["clients"][0]["files"]
    require({item["file_id"] for item in files} == {file_id, alternate_id}, "Unexpected files from another variant, user or protocol")
    if client.tls:
        require(all(item.get("openvpn_import_url", "").startswith(f"openvpn://import-profile/https://{PORTAL_HOST}/")
                    for item in files), "HTTPS OpenVPN import URLs are incorrect")
    for key, value in [("file_id", file_id), ("path", legacy_path)]:
        args = urlencode({key: value, "node_id": 2, "client_name": "bob"})
        require(request(client, BASE + "u_alice/download?" + args, 200) == ALICE, "Legacy file lookup did not match")
    require(request(client, BASE + "u_alice/download?file_id=" + alternate_id, 200) == ALICE_ALT,
            "The second file of the same destination variant was unavailable")
    for token, foreign in [("u_alice", "vpn-bob.ovpn"), ("c_alice", "vpn-alice-2.ovpn"), ("c_bob", "vpn-alice.ovpn")]:
        path = "/root/antizapret/client/openvpn/vpn/" + foreign
        request(client, BASE + token + "/download?" + urlencode({"path": path}), 404)
    request(client, BASE + "u_alice/download?path=../../password", 400)


def test_rate_limit(client):
    for _ in range(31):
        status, _ = client.request("GET", BASE + "c_alice", headers=PORTAL_HEADERS)
        if status == 429:
            break
        require(status == 200, "Unexpected status during rate-limit test")
    else:
        raise AssertionError("Public download rate limit did not activate")
    request(client, "/panel14/api/health", 200, ADMIN_HEADERS)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--tls-cert", type=Path)
    parser.add_argument("--tls-key", type=Path)
    args = parser.parse_args()
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("--tls-cert and --tls-key must be used together")
    with TemporaryDirectory(prefix="apaz-portal-") as temporary:
        root = Path(temporary)
        database = root / "adminpanel.db"
        profiles = root / "profiles"
        make_fixture(database)
        make_profiles(profiles)
        with socket.socket() as sock:
            sock.bind((HOST, 0))
            port = sock.getsockname()[1]
        env = {**os.environ, "APAZ_AUTH_TOKEN": TOKEN, "FEATURE_CLIENT_PORTAL_ENABLED": "1"}
        env.pop("APAZ_PORTAL_LEGACY_PROFILE_ROOT", None)
        command = [str(args.binary.resolve()), "--bind", HOST, "--port", str(port), "--data-dir", str(root / "state"),
                   "--access-path", "/panel14", "--portal-db", str(database), "--portal-profiles-dir", str(profiles)]
        if args.tls_cert:
            command.extend(["--tls-cert", str(args.tls_cert.resolve()), "--tls-key", str(args.tls_key.resolve())])
        with subprocess.Popen(command, env=env) as process:
            try:
                client = PanelClient(port, bool(args.tls_cert))
                wait_for_server(process, client)
                unchanged = database.read_bytes()
                test_panel(client)
                test_rate_limit(client)
                require(database.read_bytes() == unchanged, "Portal updated the legacy database")
            finally:
                process.terminate()
                process.wait(timeout=10)
    print("portal passed")


if __name__ == "__main__":
    main()
