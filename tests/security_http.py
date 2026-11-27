#!/usr/bin/env python3
"""Exercise authentication controls through the panel with synthetic credentials."""

import argparse
import base64
from contextlib import closing
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sqlite3
import struct
import subprocess
import tempfile
import time
from unittest.mock import patch
from urllib.parse import urlencode
import zlib

from smoke import HOST, TOKEN, PanelClient, choose_port, json_object, require, run_panel, wait_for_server


AUTH = "/api/auth"
TOTP = AUTH + "/totp"
TYPE = {"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"}


def post(client, path, fields, headers=None):
    with closing(client.connection()) as connection:
        connection.request("POST", path, body=urlencode(fields), headers={**TYPE, **(headers or {})})
        with connection.getresponse() as response:
            payload = json_object(response.read(), path)
            return response.status, payload, response.getheader("Set-Cookie"), response.getheader("Retry-After")


def code(secret, counter):
    key = base64.b32decode(secret)
    digest = hmac.digest(key, struct.pack(">Q", counter), "sha1")
    start = digest[-1] & 15
    value = struct.unpack(">I", digest[start : start + 4])[0] & 0x7FFFFFFF
    return f"{value % 1_000_000:06d}"


def login(client, *, password=TOKEN, headers=None, **fields):
    return post(client, AUTH + "/login", {"username": "admin", "password": password, **fields}, headers)


def cookie_header(cookie):
    require(cookie is not None, "Successful login did not set a cookie")
    return {"Cookie": cookie.split(";", 1)[0]}


def check_png(data):
    prefix = "data:image/png;base64,"
    require(data.startswith(prefix), "CAPTCHA did not return a PNG data URI")
    png = base64.b64decode(data[len(prefix) :], validate=True)
    require(8 < len(png) <= 4096 and png.startswith(b"\x89PNG\r\n\x1a\n"), "CAPTCHA PNG signature or size invalid")
    position = 8
    chunks = {}
    while position + 12 <= len(png):
        length, kind = struct.unpack_from(">I4s", png, position)
        body = png[position + 8 : position + 8 + length]
        expected = struct.unpack_from(">I", png, position + 8 + length)[0]
        require(zlib.crc32(kind + body) == expected, "CAPTCHA PNG chunk checksum invalid")
        chunks[kind] = body
        position += length + 12
    require(position == len(png) and b"IEND" in chunks, "CAPTCHA PNG is truncated")
    width, height, bits = struct.unpack_from(">IIB", chunks[b"IHDR"])
    packed = zlib.decompress(chunks[b"IDAT"])
    require(len(packed) == height * ((width * bits + 7) // 8 + 1), "CAPTCHA pixels do not fit dimensions")


def check_captcha(client):
    ip = {"X-Forwarded-For": "192.0.2.20, 10.23.0.8"}
    require(client.request("GET", AUTH + "/captcha", headers=ip)[0] == 404, "Challenge exposed before failures")
    for _ in range(3):
        status, payload, cookie, _ = login(client, password="incorrect", headers=ip)
        require(status == 401 and payload.get("error") == "invalid_credentials" and not cookie,
                "Bad credentials unexpectedly passed")

    status, data = client.request("GET", AUTH + "/captcha", headers=ip)
    require(status == 200, "Three failures did not issue a CAPTCHA")
    challenge = json_object(data, "CAPTCHA")
    require(len(challenge["id"]) == 32, "Invalid CAPTCHA ID")
    check_png(challenge["image"])
    require(login(client, headers=ip)[1].get("error") == "captcha_required", "Missing CAPTCHA allowed login")
    fields = {"captcha_id": challenge["id"], "captcha_answer": "------"}
    for _ in range(7):
        require(login(client, headers=ip, **fields)[0] == 401, "Bad CAPTCHA unexpectedly allowed login")
    status, _, cookie, retry = login(client, headers=ip)
    require(status == 429 and not cookie and retry and 1 <= int(retry) <= 300, "IP rate limit did not engage")
    require(client.request("GET", AUTH + "/captcha", headers=ip)[0] == 429, "Blocked IP issued more CAPTCHAs")
    require(login(client, headers={"X-Forwarded-For": "192.0.2.21"})[0] == 200, "Limit affected an unrelated IP")


def enroll(client):
    require(client.request("GET", TOTP)[0] == 401, "Anonymous user could read TOTP settings")
    status, _, cookie, _ = login(client)
    require(status == 200, "Initial admin login failed")
    session = cookie_header(cookie)
    _, _, other, _ = login(client)
    other_session = cookie_header(other)
    status, payload, _, _ = post(client, TOTP + "/setup", {}, {**session, "Origin": "http://example.invalid"})
    require(status == 403 and "secret" not in payload, "Cross-origin enrollment exposed the secret")
    status, payload, _, _ = post(client, TOTP + "/setup", {}, session)
    require(status == 200 and len(payload["secret"]) == 32, "TOTP setup omitted its Base32 secret")
    secret = payload["secret"]
    current = code(secret, int(time.time()) // 30)
    status, payload, _, _ = post(client, TOTP + "/enable", {"code": current}, session)
    require(status == 200 and payload["sessions_revoked"], "TOTP enable or session revocation failed")
    require(client.request("GET", AUTH + "/me", headers=other_session)[0] == 401, "Other session survived factor enable")
    codes = payload["recovery_codes"]
    require(len(set(codes)) == 8 and all(len(value) == 8 for value in codes), "Recovery code set incomplete")
    require(login(client)[1].get("error") == "second_factor_required", "Password-only login bypassed TOTP")
    status, _, cookie, _ = login(client, code=current)
    require(status == 401 and not cookie, "TOTP confirmation code could be replayed")
    status, _, cookie, _ = login(client, code=codes[0].lower())
    require(status == 200 and cookie, "Recovery code did not complete login")
    require(login(client, code=codes[0])[0] == 401, "Recovery code could be replayed")
    status, _, _, _ = post(client, TOTP + "/setup", {}, session)
    require(status == 409, "Enrolled factor was overwritten without a valid code")
    return secret, codes, session


def check_persistence(client, codes):
    require(login(client, code=codes[0])[0] == 401, "Consumed recovery code reappeared after restart")
    status, _, cookie, _ = login(client, code=codes[1])
    require(status == 200, "Unused code did not persist through restart")
    session = cookie_header(cookie)
    status, raw = client.request("GET", TOTP, headers=session)
    payload = json_object(raw, "TOTP status")
    require(status == 200 and payload["enabled"] and payload["recovery_codes_remaining"] == 6,
            "Factor or consumed codes did not persist")
    status, payload, _, _ = post(client, TOTP + "/recovery", {"code": codes[2]}, session)
    require(status == 200 and len(payload["recovery_codes"]) == 8 and not set(codes) & set(payload["recovery_codes"]),
            "Recovery code rotation failed")
    require(login(client, code=codes[3])[0] == 401, "Recovery rotation retained previous codes")
    status, _, _, _ = post(client, TOTP + "/disable", {"code": payload["recovery_codes"][0]}, session)
    require(status == 200 and login(client)[0] == 200, "Verified disable did not restore password-only login")


def stage_auth_only(client, data, session, migration):
    status, payload, _, _ = post(client, "/api/backups/create", {}, session)
    require(status == 201, "Could not create an auth-only backup")
    restored = data / "restored"
    restored.mkdir()
    result = subprocess.run([migration, "stage-native-auth", data / "backups" / payload["name"], restored / "auth.db"],
                            capture_output=True, timeout=10)
    require(result.returncode == 0, "Could not restore auth-only backup with MFA flags")
    return restored


def check_missing_store(binary, restored, codes):
    port = choose_port()
    command = [binary, "--port", str(port), "--bind", HOST,
               "--data-dir", str(restored), "--auth-db", str(restored / "auth.db")]
    client = PanelClient(port, tls=False)
    with run_panel(command, restored / "test.log") as process:
        wait_for_server(process, client)
        for offered_factor in ({}, {"code": codes[1]}):
            status, payload, cookie, _ = login(client, **offered_factor)
            require(status == 401 and payload["error"] == "second_factor_required" and not cookie,
                    "Auth-only restore without the second-factor store allowed login")


def check_pre_marker_upgrade(data, command, log, client, session):
    auth = data / "auth.db"
    factors = data / "lws-security.db"
    held_factors = data / "existing-security.db"
    with closing(sqlite3.connect(auth)) as db, db:
        db.execute("ALTER TABLE panel_legacy_accounts DROP COLUMN native_totp_required")

    factors.rename(held_factors)
    with run_panel(command, log) as process:
        require(process.wait(timeout=3) != 0, "Pre-marker schema upgraded without the paired factor store")
    require(not factors.exists(), "Failed upgrade created an empty factor store")
    held_factors.rename(factors)
    original_factors = factors.read_bytes()
    with patch.dict(os.environ, {"APAZ_SECURITY_KEY": secrets.token_hex(32)}), run_panel(command, log) as process:
        require(process.wait(timeout=3) != 0, "Pre-marker schema upgraded without the original factor key")
    with closing(sqlite3.connect(auth)) as db:
        old_columns = {column[1] for column in db.execute("PRAGMA table_info(panel_legacy_accounts)")}
    require("native_totp_required" not in old_columns, "Failed upgrade committed an incomplete auth schema")
    with run_panel(command, log) as process:
        wait_for_server(process, client)
        require(client.request("GET", AUTH + "/me", headers=session)[0] == 200, "Upgrade revoked an existing session")
        require(login(client)[1]["error"] == "second_factor_required", "Upgraded user did not require the existing factor")
    require(factors.read_bytes() == original_factors, "Schema reconciliation rewrote MFA codes or replay counters")
    with closing(sqlite3.connect(auth)) as db:
        require(db.execute("SELECT native_totp_required FROM panel_legacy_accounts").fetchall() == [(1,)],
                "Upgrade did not persist the second-factor requirement")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--migration", type=Path, help="path to the native migration executable")
    args = parser.parse_args()
    binary = args.binary.resolve()
    migration = args.migration or binary.with_name("adminpanelaz-migration" + binary.suffix)
    env = {
        "APAZ_SECURITY_KEY": secrets.token_hex(32),
        "APAZ_IP_ALLOWLIST": "127.0.0.1, 192.0.2.0/24, 2001:db8::/32",
        "APAZ_TRUSTED_PROXY_IPS": "127.0.0.1, 10.23.0.8",
    }
    with tempfile.TemporaryDirectory(prefix="apaz-security-test-") as temporary, patch.dict(os.environ, env):
        data = Path(temporary)
        port = choose_port()
        client = PanelClient(port, tls=False)
        command = [str(binary), "--port", str(port), "--bind", HOST,
                   "--data-dir", str(data), "--auth-db", str(data / "auth.db")]
        log = data / "test.log"
        with run_panel(command, log) as process:
            wait_for_server(process, client)
            for allowed in ("203.0.113.2, 192.0.2.23, 10.23.0.8", "2001:db8:1::3"):
                require(client.request("GET", "/api/health", headers={"X-Forwarded-For": allowed})[0] == 200,
                        "Allowed client rejected")
            for denied in ("192.0.2.23, 203.0.113.2, 10.23.0.8", "malformed-forwarded-address"):
                require(client.request("GET", "/api/health", headers={"X-Forwarded-For": denied})[0] == 403,
                        "Forwarded address escaped the allowlist")
            check_captcha(client)
            secret, codes, session = enroll(client)
            restored = stage_auth_only(client, data, session, migration)
        check_missing_store(binary, restored, codes)
        security_db = data / "lws-security.db"
        require(secret.encode() not in security_db.read_bytes() and base64.b32decode(secret) not in security_db.read_bytes(),
                "Enrollment secret was stored in plaintext")
        check_pre_marker_upgrade(data, command, log, client, session)
        with run_panel(command, log) as process:
            wait_for_server(process, client)
            check_persistence(client, codes)
        with patch.dict(os.environ, {"APAZ_SECURITY_KEY": secrets.token_hex(32)}), run_panel(command, log) as process:
            require(process.wait(timeout=3) != 0, "Wrong encryption key did not fail service startup")
    print("Security HTTP checks passed: proxy IP, CIDR, rate limit, CAPTCHA, TOTP, replay, recovery and key persistence")


if __name__ == "__main__":
    main()
