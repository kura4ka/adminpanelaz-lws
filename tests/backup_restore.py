import base64
import gzip
import hashlib
import hmac
import io
import os
from pathlib import Path
import random
import sqlite3
import subprocess
import sys
import tarfile
import tempfile


PANEL_DB = "data/adminpanel.db"
CIDR_DB = "data/cidr/cidr.db"
DOTENV = "env/.env"
CONFIG = "antizapret/config/allow-ips.txt"
AWG2 = "awg2/az-awg2-backup.tar.gz"
PASSWORD = "синтетический пароль с пробелом ".encode()


def sqlite_fixture(path, wal=False):
    with sqlite3.connect(path) as db:
        if wal:
            assert db.execute("PRAGMA journal_mode=WAL").fetchone()[0] == "wal"
        db.execute("CREATE TABLE example (name)")
        db.execute("INSERT INTO example VALUES ('synthetic')")
    db.close()
    return path.read_bytes()


def tar_bytes(entries, tar_format=tarfile.PAX_FORMAT):
    result = io.BytesIO()
    with tarfile.open(fileobj=result, mode="w", format=tar_format) as tar:
        for name, value in entries:
            entry = tarfile.TarInfo(name)
            entry.mtime = 1734000123.456789  # Python emits an upstream-style PAX timestamp.
            if isinstance(value, tuple):
                (entry.type,) = value
                entry.linkname = "ignored"
                tar.addfile(entry)
            else:
                entry.size = len(value)
                tar.addfile(entry, io.BytesIO(value))
    return result.getvalue()


def encrypt_fernet(data, valid_tag=True):
    # Same key derivation and wire format as backup_telegram_privacy in AdminPanelAZ.
    key = hashlib.sha256(PASSWORD).digest()
    iv = bytes.fromhex("6bf7be42d4dc0fbede9698cfe1ed4990")
    ciphertext = subprocess.run(
        [
            os.environ.get("OPENSSL_EXECUTABLE", "openssl"), "enc", "-aes-128-cbc",
            "-K", key[16:].hex(), "-iv", iv.hex(),
        ],
        input=data, capture_output=True, check=True,
    ).stdout
    signed = b"\x80" + (1734000123).to_bytes(8, "big") + iv + ciphertext
    signature = bytearray(hmac.digest(key[:16], signed, "sha256"))
    if not valid_tag:
        signature[-1] ^= 1
    return b"APAZBK1\n" + base64.urlsafe_b64encode(signed + signature)


def stage(archive, destination, password=None):
    arguments = [sys.argv[1], "stage-upstream", str(archive), str(destination)]
    if password is not None:
        arguments.append("--password-stdin")
    return subprocess.run(arguments, input=password, capture_output=True, timeout=20)


def rejects(root, archive, destination, data, password=None):
    archive.write_bytes(data)
    result = stage(archive, destination, password)
    assert result.returncode == 1, result
    assert not destination.exists(), destination
    assert not list(root.glob(".apaz-stage-*"))


def verify_migrated_native_backup(root):
    legacy = root / "legacy-users.sqlite"
    # A canonical placeholder hash, only used to exercise database migration and staging.
    password_hash = "$2b$12$" + "." * 53
    with sqlite3.connect(legacy) as db:
        db.executescript(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY, username TEXT UNIQUE, password_hash TEXT, role TEXT,
                is_active INTEGER, panel_login_enabled INTEGER, must_change_password INTEGER,
                totp_enabled INTEGER, totp_secret_encrypted TEXT, totp_backup_codes_encrypted TEXT,
                telegram_id INTEGER, access_until TEXT
            );
            CREATE TABLE webauthn_credentials (id INTEGER PRIMARY KEY, user_id INTEGER REFERENCES users(id));
            CREATE INDEX credential_owner ON webauthn_credentials(user_id);
            """
        )
        db.execute(
            "INSERT INTO users VALUES(313, 'synthetic', ?, 'admin', 1, 1, 0, 0, NULL, NULL, NULL, '')",
            (password_hash,),
        )
    db.close()
    migrated = root / "migrated.sqlite"
    imported = subprocess.run(
        [sys.argv[1], "import-legacy-accounts", str(legacy), str(migrated)],
        capture_output=True, timeout=20,
    )
    assert imported.returncode == 0, imported
    snapshot = root / "native.backup"
    staged = root / "native.sqlite"

    def stage_native():
        snapshot.write_bytes(gzip.compress(
            tar_bytes([("data/lws-auth.db", migrated.read_bytes())], tarfile.USTAR_FORMAT)
        ))
        return subprocess.run(
            [sys.argv[1], "stage-native-auth", str(snapshot), str(staged)], capture_output=True, timeout=20,
        )

    result = stage_native()
    assert result.returncode == 0 and staged.read_bytes() == migrated.read_bytes(), result
    staged.unlink()
    verify_native_state(root, migrated)
    with sqlite3.connect(migrated) as db:
        db.execute("UPDATE panel_legacy_accounts SET bcrypt_hash = ? WHERE account_id = 313", ("x" * 60,))
    db.close()
    result = stage_native()
    assert result.returncode == 1 and not staged.exists(), result


def verify_native_state(root, migrated):
    with sqlite3.connect(migrated) as db:
        db.execute("INSERT INTO panel_sessions VALUES(zeroblob(32), 313, 9999999999)")
    db.close()
    data = root / "data"
    data.mkdir()
    security = data / "lws-security.db"
    with sqlite3.connect(security) as db:
        db.executescript(
            """
            CREATE TABLE security_key (id INTEGER PRIMARY KEY, key_check BLOB);
            CREATE TABLE security_factor (account_id INTEGER PRIMARY KEY, sealed BLOB,
                enabled INTEGER, pending_until INTEGER, last_counter INTEGER);
            CREATE TABLE security_recovery (account_id INTEGER, digest BLOB,
                FOREIGN KEY(account_id) REFERENCES security_factor(account_id) ON DELETE CASCADE);
            INSERT INTO security_key VALUES(1, zeroblob(32));
            INSERT INTO security_factor VALUES (313, zeroblob(48), 1, 0, 314);
            INSERT INTO security_factor VALUES (314, zeroblob(48), 0, 9999999999, 0);
            INSERT INTO security_recovery VALUES (313, zeroblob(32)), (314, zeroblob(32));
            """
        )
    db.close()
    sqlite_fixture(data / "panel-settings.db", wal=True)
    portal = root / "portal-snapshot.sqlite"
    sqlite_fixture(portal)
    unrelated = data / "arbitrary-secret"
    unrelated.write_bytes(b"unrelated")
    destination = root / "native state"
    arguments = [
        sys.argv[1], "stage-native-state", str(data), str(migrated), str(destination),
        "--portal-db", str(portal),
    ]
    result = subprocess.run(arguments, capture_output=True, timeout=20)
    assert result.returncode == 0, result
    assert {file.name for file in destination.iterdir()} == {
        "auth.db", "lws-security.db", "panel-settings.db", "portal.db",
    }
    with sqlite3.connect(destination / "panel-settings.db") as db:
        assert db.execute("SELECT name FROM example").fetchall() == [("synthetic",)]
    db.close()
    with sqlite3.connect(destination / "auth.db") as db:
        assert db.execute("SELECT COUNT(*) FROM panel_sessions").fetchone() == (0,)
        assert db.execute("SELECT id FROM panel_accounts").fetchall() == [(313,)]
    db.close()
    with sqlite3.connect(destination / "lws-security.db") as db:
        assert db.execute("SELECT account_id, last_counter FROM security_factor").fetchall() == [(313, 314)]
        assert db.execute("SELECT account_id FROM security_recovery").fetchall() == [(313,)]
        assert db.execute("SELECT id FROM security_key").fetchall() == [(1,)]
    db.close()
    with sqlite3.connect(migrated) as db:
        assert db.execute("SELECT COUNT(*) FROM panel_sessions").fetchone() == (1,)
        db.execute("DELETE FROM panel_sessions")
    db.close()
    with sqlite3.connect(security) as db:
        assert db.execute("SELECT COUNT(*) FROM security_factor").fetchone() == (2,)
    db.close()
    assert subprocess.run(arguments, capture_output=True, timeout=20).returncode == 1

    (data / "lws-telegram.db").write_bytes(b"damaged")
    failed_destination = root / "invalid native state"
    arguments[4] = str(failed_destination)
    assert subprocess.run(arguments, capture_output=True, timeout=20).returncode == 1
    assert not failed_destination.exists() and not list(root.glob(".apaz-stage-*"))


def main():
    with tempfile.TemporaryDirectory(prefix="apaz-backups-") as directory:
        root = Path(directory)
        archive = root / "archive.backup"
        destination = root / "stage & details"
        panel_db = sqlite_fixture(root / "panel.sqlite", wal=True)
        cidr_db = sqlite_fixture(root / "cidr.sqlite")
        env = b"PANEL_SECRET=" + base64.b64encode(random.Random(231).randbytes(128 * 1024)) + b"\n"
        ips = b"192.0.2.0/24\n"
        awg2 = gzip.compress(tar_bytes([("fixture", b"nested")]))
        entries = [(PANEL_DB, panel_db), (CIDR_DB, cidr_db), (DOTENV, env), (CONFIG, ips), (AWG2, awg2)]
        plain_tar = tar_bytes(entries)
        compressed = gzip.compress(plain_tar)
        encrypted = encrypt_fernet(compressed)
        for index, (data, password) in enumerate(((compressed, None), (encrypted, PASSWORD + b"\r\n"))):
            archive.write_bytes(data)
            destination = root / f"stage & details {index}"
            result = stage(archive, destination, password)
            assert result.returncode == 0 and result.stdout.strip() == b'{"components":31}', result
            assert {file.name: file.read_bytes() for file in destination.iterdir()} == {
                "adminpanel.db": panel_db, "cidr.db": cidr_db, ".env": env,
                "allow-ips.txt": ips, "az-awg2-backup.tar.gz": awg2,
            }
            assert archive.read_bytes() == data
            if os.name != "nt":
                assert destination.stat().st_mode & 0o777 == 0o700
                assert all(file.stat().st_mode & 0o777 == 0o600 for file in destination.iterdir())
            retry = stage(archive, destination, password)
            assert retry.returncode == 1 and (destination / ".env").read_bytes() == env, retry

        destination = root / "rejected stage"
        malformed_entries = {
            "duplicate": [*entries, (DOTENV, env)],
            "traversal": [*entries, ("env/../.env", b"bad")],
            "link": [(DOTENV, (tarfile.SYMTYPE,))],
            "hardlink": [(DOTENV, (tarfile.LNKTYPE,))],
            "unknown": [*entries, ("custom/remote_key", b"bad")],
            "bad sqlite": [(DOTENV, env), (PANEL_DB, b"SQLite format 3" + bytes(4096))],
            "bad AWG2 signature": [(AWG2, b"not a compressed backup")],
            "binary env": [(DOTENV, b"ENV=bad\x00text\n")],
        }
        for label, malformed in malformed_entries.items():
            archive = root / f"{label}.backup"
            rejects(root, archive, destination, gzip.compress(tar_bytes(malformed)))
        archive = root / "archive.backup"
        rejects(root, archive, destination, compressed[:-1])
        rejects(root, archive, destination, compressed + gzip.compress(b""))
        rejects(root, archive, destination, gzip.compress(plain_tar + tar_bytes([(DOTENV, env)])))
        rejects(root, archive, destination, encrypted)
        rejects(root, archive, destination, encrypted, b"wrong\n")
        rejects(root, archive, destination, encrypted + b"\n", PASSWORD)
        rejects(root, archive, destination, encrypt_fernet(compressed, valid_tag=False), PASSWORD)

        archive.write_bytes(compressed)
        arguments = [sys.argv[1], "stage-upstream", str(archive), str(destination)]
        first = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        second = subprocess.Popen(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        first.communicate(timeout=20)
        second.communicate(timeout=20)
        assert sorted((first.returncode, second.returncode)) == [0, 1]
        assert (destination / ".env").read_bytes() == env
        assert not list(root.glob(".apaz-stage-*"))
        verify_migrated_native_backup(root)

    print("Upstream PAX, APAZBK1, migrated native backup, and offline native state staging passed")


if __name__ == "__main__":
    main()
