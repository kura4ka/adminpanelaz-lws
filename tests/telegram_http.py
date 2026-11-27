#!/usr/bin/env python3
"""Test the panel's Telegram endpoints on loopback with generated proofs."""

import argparse
import base64
from contextlib import closing
import hmac
import os
from pathlib import Path
import tempfile
import time
from urllib.parse import urlencode

import smoke
from telegram_store import TOKEN, proof


def test(binary, directory, cert, key):
    port = smoke.choose_port()
    client = smoke.PanelClient(port, tls=cert is not None)
    prefix = "/panel-fixture"
    origin = f"{'https' if cert else 'http'}://127.0.0.1:{port}"
    command = [str(binary), "--port", str(port), "--data-dir", str(directory),
               "--auth-db", str(directory / "auth.db"), "--access-path", prefix]
    if cert:
        command += ["--tls-cert", str(cert), "--tls-key", str(key)]

    def call(method, path, fields=None, cookie=None, expected=200, origin_header=origin):
        headers = {}
        if cookie:
            headers["Cookie"] = cookie
        if origin_header is not None:
            headers["Origin"] = origin_header
        body = None
        if fields is not None:
            body = urlencode(fields)
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        with closing(client.connection()) as connection:
            connection.request(method, prefix + path, body, headers)
            with connection.getresponse() as response:
                data = response.read()
                assert response.status == expected, (method, path, response.status, data)
                value = smoke.json_object(data, path)
                set_cookie = response.getheader("Set-Cookie")
                return value, set_cookie.split(";", 1)[0] if set_cookie else None

    with smoke.run_panel(command, directory / "server.log") as process:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                call("GET", "/api/health")
            except OSError:
                if process.poll() is not None:
                    raise AssertionError("Telegram test panel exited during startup") from None
                time.sleep(0.05)
            else:
                break
        else:
            raise AssertionError("Telegram test panel did not start")

        call("GET", "/api/telegram/config", expected=404)
        login, cookie = call("POST", "/api/auth/login", {"username": "admin", "password": smoke.TOKEN})
        assert login["role"] == "admin" and cookie is not None
        call("POST", "/api/settings/features", {"key": "telegram", "enabled": "true"}, cookie)
        assert not call("GET", "/api/auth/telegram/config")[0]["enabled"]
        call("GET", "/api/telegram/settings", expected=403)
        settings = {"bot_username": "SyntheticBot", "auth_max_age_seconds": "300", "bot_token": TOKEN,
                    "legacy_login_enabled": "true", "mini_enabled": "true"}
        call("POST", "/api/telegram/settings", settings, cookie, 403, "https://invalid.example")
        saved, _ = call("POST", "/api/telegram/settings", settings, cookie)
        assert saved["bot_token_set"] and "bot_token" not in saved
        assert call("GET", "/api/telegram/config")[0]["enabled"]

        now = int(time.time())
        link = {"mode": "widget", "data": proof(111, now - 2)}
        first = {"mode": "widget", "data": proof(111, now - 1)}
        mini = {"mode": "mini", "data": proof(111, now, mini=True)}
        assert call("POST", "/api/telegram/link", link, cookie)[0]["telegram_id"] == "111"
        call("POST", "/api/telegram/login", link, expected=401)
        call("GET", "/api/telegram/login", expected=404)
        call("POST", "/api/telegram/login", first, expected=403, origin_header=None)
        identity, external_cookie = call("POST", "/api/telegram/login", first)
        assert identity["username"] == "admin" and external_cookie and external_cookie != cookie
        call("POST", "/api/telegram/login", first, expected=401)
        _, mini_cookie = call("POST", "/api/telegram/login", mini)
        assert mini_cookie and mini_cookie != external_cookie
        call("POST", "/api/telegram/login", mini, expected=401)
        assert call("POST", "/api/telegram/unlink", cookie=cookie)[0]["telegram_id"] is None
        call("GET", "/api/auth/me", cookie=external_cookie, expected=401)
        call("GET", "/api/auth/me", cookie=mini_cookie, expected=401)
        assert call("GET", "/api/auth/me", cookie=cookie)[0]["username"] == "admin"

        setup, _ = call("POST", "/api/auth/totp/setup", cookie=cookie)
        totp_key = base64.b32decode(setup["secret"])
        counter = int(time.time()) // 30
        digest = hmac.digest(totp_key, counter.to_bytes(8, "big"), "sha1")
        offset = digest[-1] & 0x0f
        code = (int.from_bytes(digest[offset:offset + 4], "big") & 0x7fffffff) % 1000000
        factor, _ = call("POST", "/api/auth/totp/enable", {"code": f"{code:06d}"}, cookie)
        relink = {"mode": "widget", "data": proof(111, now + 1)}
        assert call("POST", "/api/telegram/link", relink, cookie)[0]["telegram_id"] == "111"
        fresh = {"mode": "widget", "data": proof(111, now + 2)}
        assert call("POST", "/api/telegram/login", fresh, expected=401)[0]["error"] == "second_factor_required"
        _, recovered = call("POST", "/api/telegram/login", {**fresh, "code": factor["recovery_codes"][0]})
        assert recovered and recovered != cookie

        for i in range(3):
            unbound = {"mode": "widget", "data": proof(222 + i, now + 3)}
            assert call("POST", "/api/telegram/login", unbound, expected=401)[0]["error"] == "telegram_login_failed"
        gated = {"mode": "widget", "data": proof(111, now + 4), "code": factor["recovery_codes"][1]}
        assert call("POST", "/api/telegram/login", gated, expected=401)[0]["error"] == "captcha_required"
        captcha, _ = call("GET", "/api/auth/captcha")
        assert len(captcha["id"]) == 32 and captcha["image"].startswith("data:image/png;base64,")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--tls-cert", type=Path)
    parser.add_argument("--tls-key", type=Path)
    args = parser.parse_args()
    if bool(args.tls_cert) != bool(args.tls_key):
        parser.error("supply a TLS certificate and key together")
    # The test process inherits this synthetic key. The panel creates a separate, temporary store.
    os.environ["APAZ_SECURITY_KEY"] = "54" * 32
    with tempfile.TemporaryDirectory() as directory:
        test(args.binary.resolve(), Path(directory), args.tls_cert, args.tls_key)
    print("Telegram HTTP flow passed")


if __name__ == "__main__":
    main()
