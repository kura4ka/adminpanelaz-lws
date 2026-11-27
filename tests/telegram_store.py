#!/usr/bin/env python3
"""Exercise the native Telegram store through a shared library with synthetic SQLite data."""

import argparse
import ctypes
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import tempfile
from urllib.parse import urlencode


TOKEN = b"123456789:synthetic_bot_secret-only"
NOW = 1700000000
OK, DISABLED, DENIED, CONFLICT, REPLAY, INVALID, ERROR = range(7)


class Settings(ctypes.Structure):
    _fields_ = [
        ("username", ctypes.c_char * 33),
        ("max_age", ctypes.c_uint),
        ("legacy_enabled", ctypes.c_bool),
        ("mini_enabled", ctypes.c_bool),
        ("token_configured", ctypes.c_bool),
    ]


def proof(telegram_id, when=NOW, mini=False, reordered=False):
    fields = {"auth_date": str(when)}
    if mini:
        fields["user"] = json.dumps({"id": telegram_id, "first_name": "Тест"}, ensure_ascii=False)
        fields["signature"] = "synthetic-data"
        secret = hmac.digest(b"WebAppData", TOKEN, "sha256")
    else:
        fields.update(id=str(telegram_id), first_name="Test User")
        secret = hashlib.sha256(TOKEN).digest()
    canonical = "\n".join(f"{key}={value}" for key, value in sorted(fields.items()))
    digest = hmac.digest(secret, canonical.encode(), "sha256").hex()
    fields["hash"] = digest.upper() if reordered else digest
    if reordered:
        return urlencode(list(reversed(fields.items()))).replace("Test+User", "%54est%20User").encode()
    return urlencode(fields).encode()


def configure_library(path):
    lib = ctypes.CDLL(str(path))
    functions = {
        "open": ([ctypes.c_char_p], ctypes.c_bool),
        "close": ([], None),
        "settings_get": ([ctypes.POINTER(Settings)], ctypes.c_bool),
        "settings_set": ([ctypes.POINTER(Settings), ctypes.c_char_p], ctypes.c_int),
        "bound": ([ctypes.c_int64, ctypes.POINTER(ctypes.c_uint64)], ctypes.c_bool),
        "link": ([ctypes.c_int64, ctypes.c_bool, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint64], ctypes.c_int),
        "unlink": ([ctypes.c_int64], ctypes.c_bool),
        "claim_login": ([ctypes.c_bool, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint64,
                         ctypes.POINTER(ctypes.c_int64)], ctypes.c_int),
        "check_login": ([ctypes.c_bool, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_uint64,
                         ctypes.POINTER(ctypes.c_int64)], ctypes.c_int),
        "import_legacy": ([ctypes.c_char_p, ctypes.c_char_p], ctypes.c_int),
    }
    for name, (parameters, result) in functions.items():
        function = getattr(lib, "panel_telegram_" + name)
        function.argtypes = parameters
        function.restype = result
        setattr(lib, name, function)
    return lib


def assert_binding(lib, account_id, expected):
    telegram_id = ctypes.c_uint64()
    assert lib.bound(account_id, telegram_id) and telegram_id.value == expected


def test_store(lib, directory):
    path = os.fsencode(directory / "telegram.db")
    assert lib.open(path)
    if os.name != "nt":
        assert os.stat(path).st_mode & 0o077 == 0

    def check(data, expected, account=0, *, mini=False, now=NOW, consume=True):
        result_id = ctypes.c_int64(123)
        login = lib.claim_login if consume else lib.check_login
        assert login(mini, data, len(data), now, result_id) == expected
        assert result_id.value == account

    first = proof(111)
    second = proof(111, NOW + 1)
    mini = proof(222, mini=True)
    check(first, DISABLED)
    settings = Settings(b"SyntheticBot", 300, True, True)
    assert lib.settings_set(settings, b"too-short") == INVALID
    assert lib.settings_set(settings, None) == INVALID
    assert lib.settings_set(settings, TOKEN) == OK
    actual = Settings()
    assert lib.settings_get(actual) and actual.token_configured and actual.username == b"SyntheticBot"
    check(first, DENIED)
    assert lib.link(7, False, first, len(first), NOW) == OK
    assert_binding(lib, 7, 111)
    assert lib.link(8, False, second, len(second), NOW + 1) == CONFLICT
    assert lib.link(8, True, mini, len(mini), NOW) == OK
    assert_binding(lib, 8, 222)
    check(first, REPLAY)
    check(second, OK, 7, consume=False)
    check(second, OK, 7)
    check(proof(111, NOW + 1, reordered=True), REPLAY)
    check(proof(111, NOW + 31), DENIED)
    check(proof(111, NOW - 301), DENIED)
    check(proof(222, NOW + 1, mini=True), OK, 8, mini=True)
    check(proof(222, NOW + 1, mini=True), REPLAY, mini=True)
    assert lib.settings_set(settings, b"") == INVALID

    lib.close()
    assert lib.open(path)
    check(second, REPLAY)
    settings.max_age = 1800
    assert lib.settings_set(settings, None) == OK
    check(second, REPLAY, now=NOW + 400)
    assert lib.unlink(7)
    assert_binding(lib, 7, 0)
    check(proof(111, NOW + 3), DENIED)
    assert_binding(lib, 8, 222)
    lib.close()


def test_import(lib, directory):
    source = directory / "offline.db"
    auth = directory / "staged-auth.db"
    target = directory / "fresh-telegram.db"
    with sqlite3.connect(source) as db:
        db.executescript("""
            CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT NOT NULL, telegram_id TEXT UNIQUE);
            INSERT INTO users VALUES(9,'alice','12344555522'),(13,'bob',NULL);
            CREATE TABLE app_settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            INSERT INTO app_settings VALUES('telegram_bot_username','@ImportedBot'),
                ('telegram_auth_max_age_seconds','600'),('telegram_bot_token','a fake secret');
        """)
    with sqlite3.connect(auth) as db:
        db.executescript("""
            CREATE TABLE panel_accounts(id INTEGER PRIMARY KEY, username TEXT NOT NULL);
            CREATE TABLE panel_legacy_accounts(account_id INTEGER PRIMARY KEY, from_legacy INTEGER NOT NULL);
            INSERT INTO panel_accounts VALUES(9,'alice'),(13,'someone-else');
            INSERT INTO panel_legacy_accounts VALUES(9,1),(13,1);
        """)

    assert lib.open(os.fsencode(target))
    assert lib.import_legacy(os.fsencode(source), os.fsencode(auth)) == ERROR
    assert_binding(lib, 9, 0)
    with sqlite3.connect(auth) as db:
        db.execute("UPDATE panel_accounts SET username='bob' WHERE id=13")
    assert lib.import_legacy(os.fsencode(source), os.fsencode(auth)) == OK
    settings = Settings()
    assert lib.settings_get(settings)
    assert settings.username == b"ImportedBot" and settings.max_age == 600
    assert not settings.token_configured and not settings.mini_enabled and not settings.legacy_enabled
    assert_binding(lib, 9, 12344555522)
    assert_binding(lib, 13, 0)
    assert lib.unlink(9)
    assert lib.import_legacy(os.fsencode(source), os.fsencode(auth)) == OK
    assert_binding(lib, 9, 0)
    with sqlite3.connect(source) as db:
        db.execute("UPDATE users SET telegram_id='333' WHERE id=9")
    assert lib.import_legacy(os.fsencode(source), os.fsencode(auth)) == CONFLICT
    assert_binding(lib, 9, 0)
    lib.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("library", type=Path)
    args = parser.parse_args()
    lib = configure_library(args.library.resolve())
    with tempfile.TemporaryDirectory() as path:
        directory = Path(path)
        test_store(lib, directory)
        test_import(lib, directory)
    print("Telegram settings, replay protection, link isolation and offline import passed")


if __name__ == "__main__":
    main()
