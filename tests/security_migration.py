#!/usr/bin/env python3
"""Exercise legacy Fernet/TOTP import, rollback, and recovery-code consumption."""

import argparse
import base64
from contextlib import closing
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import tempfile
import time
from unittest.mock import patch

from legacy_accounts import BCRYPT, PASSWORD, migration_command, source_fixture
from security_http import TOTP, code, cookie_header, post
from smoke import HOST, PanelClient, choose_port, require, run_panel, wait_for_server


def fernet(plaintext, legacy_key):
    key = hashlib.sha256(legacy_key).digest()
    iv = secrets.token_bytes(16)
    encrypted = subprocess.run(["openssl", "enc", "-aes-128-cbc", "-K", key[16:].hex(), "-iv", iv.hex()],
                               input=plaintext, check=True, capture_output=True, timeout=5).stdout
    message = b"\x80" + int(time.time()).to_bytes(8, "big") + iv + encrypted
    return base64.urlsafe_b64encode(message + hmac.digest(key[:16], message, "sha256")).decode()


def fixture(path, key):
    source_fixture(path)
    secret = base64.b32encode(secrets.token_bytes(20)).decode()
    second_secret = base64.b32encode(secrets.token_bytes(20))
    codes = [secrets.token_hex(4).upper(), secrets.token_hex(4).upper()]
    with closing(sqlite3.connect(path)) as db, db:
        db.execute("UPDATE users SET totp_secret_encrypted=?, totp_backup_codes_encrypted=? WHERE id=22",
                   (fernet(secret.encode(), key), fernet(json.dumps(codes).encode(), key)))
        db.execute("INSERT INTO webauthn_credentials VALUES (2,22)")
        db.execute("INSERT INTO users VALUES(25,'second-totp',?,'user',1,1,0,1,'invalid-token',NULL,NULL,NULL)",
                   (BCRYPT,))
    return secret, second_secret, codes


def migrate(executable, source, auth, security, key, result):
    command = [executable, "import-legacy-totp", source, auth, security]
    report = subprocess.run(command, input=key + b"\n", capture_output=True, timeout=10)
    require(key not in report.stdout + report.stderr, "Import exposed legacy encryption key")
    if result is None:
        require(report.returncode != 0 and not report.stdout, "Invalid legacy TOTP database was accepted")
    else:
        require(report.returncode == 0 and json.loads(report.stdout) == {"imported": result},
                f"Import report was incomplete (exit {report.returncode})")


def login(client, username="totp", **extra):
    return post(client, "/api/auth/login", {"username": username, "password": PASSWORD, **extra})


def check_app(command, client, log, secret, codes):
    with run_panel(command, log) as process:
        wait_for_server(process, client)
        require(login(client)[1]["error"] == "second_factor_required", "Password bypassed imported factor")
        require(login(client, username="passkey")[0] == 401, "Unmigrated passkey-only account authenticated")
        status, _, cookie, _ = login(client, code=code(secret, int(time.time()) // 30))
        require(status == 200 and cookie, "Original authenticator no longer completes login")
        headers = cookie_header(cookie)
        status, payload, _, _ = post(client, TOTP + "/disable", {"code": codes[0]}, headers)
        require(status == 409 and payload["error"] == "legacy_totp_required", "Legacy policy could be disabled")
        status, _, cookie, _ = login(client, code=codes[0])
        require(status == 200 and cookie, "Original recovery code did not complete login")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("migration", type=Path)
    parser.add_argument("panel", type=Path)
    args = parser.parse_args()
    key = secrets.token_hex(32).encode()
    with tempfile.TemporaryDirectory(prefix="apaz-totp-migration-") as temporary, \
            patch.dict(os.environ, {"APAZ_SECURITY_KEY": secrets.token_hex(32)}):
        data = Path(temporary)
        source = data / "upstream.db"
        auth = data / "auth.db"
        security = data / "lws-security.db"
        secret, second_secret, codes = fixture(source, key)
        migration_command(args.migration.resolve(), source, auth)
        port = choose_port()
        client = PanelClient(port, tls=False)
        command = [str(args.panel.resolve()), "--port", str(port), "--bind", HOST,
                   "--data-dir", str(data), "--auth-db", str(auth)]
        log = data / "panel.log"
        if sys.platform.startswith("linux"):
            with run_panel(command, log) as process:
                wait_for_server(process, client)
                status, _, cookie, _ = login(client, code=codes[0])
                require(status == 401 and not cookie, "Unstaged legacy factor did not fail closed")
        migrate(args.migration.resolve(), source, auth, security, key, None)
        with closing(sqlite3.connect(security)) as db:
            require(db.execute("SELECT COUNT(*) FROM security_factor").fetchone() == (0,),
                    "Partial legacy factor import was committed")
        with closing(sqlite3.connect(source)) as db, db:
            db.execute("UPDATE users SET totp_secret_encrypted=? WHERE id=25", (fernet(second_secret, key),))
        migrate(args.migration.resolve(), source, auth, security, b"wrong-key", None)
        migrate(args.migration.resolve(), source, auth, security, key, 2)
        if sys.platform.startswith("linux"):
            check_app(command, client, log, secret, codes)
        restore = security.read_bytes()
        migrate(args.migration.resolve(), source, auth, security, key, 0)
        require(security.read_bytes() == restore, "Repeat migration changed factor or recovery state")
        if sys.platform.startswith("linux"):
            with run_panel(command, log) as process:
                wait_for_server(process, client)
                require(login(client, code=codes[0])[0] == 401, "Repeat import revived a consumed recovery code")
                require(login(client, code=codes[1])[0] == 200, "Repeat import replaced an active recovery code")
    print("Legacy TOTP checks passed: authenticated import, rollback, source identity and repeat-safe recovery")


if __name__ == "__main__":
    main()
