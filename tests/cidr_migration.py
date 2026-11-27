#!/usr/bin/env python3
"""Exercise the offline migration against the pinned provider_cidr schema."""

from contextlib import closing
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile


def migrate(binary, native, legacy):
    process = subprocess.run([binary, "--legacy", native, legacy], check=False,
                             capture_output=True, text=True, timeout=10)
    return process.returncode, json.loads(process.stdout)


def main(binary):
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        native = root / "lws-cidr.db"
        legacy = root / "cidr.db"
        rows = [
            (5, "custom-ips.txt", "203.0.113.9/24", "all", None, "2026-01-01 10:01:02"),
            (7, "cloudflare-ips.txt", "198.51.100.2", None, "US,CA", "2026-01-02 10:01:02"),
            (8, "custom-ips.txt", "2001:db8::/32", None, None, "2026-01-03 10:01:02"),
        ]
        with closing(sqlite3.connect(legacy)) as source:
            source.execute("""CREATE TABLE provider_cidr (
                id INTEGER PRIMARY KEY, provider_key VARCHAR(64) NOT NULL, cidr VARCHAR(50) NOT NULL,
                region_scope VARCHAR(64), country_codes VARCHAR(255), refreshed_at DATETIME,
                UNIQUE (provider_key, cidr))""")
            source.executemany("INSERT INTO provider_cidr VALUES (?, ?, ?, ?, ?, ?)", rows)
            source.commit()

            assert migrate(binary, legacy, legacy)[1]["error"] == "invalid_native_destination"
            expected = {"state": "ok", "legacy_rows": 3, "policy_skipped": 1, "sources": 2}
            assert migrate(binary, native, legacy) == (0, expected)
            assert migrate(binary, native, legacy) == (0, expected)
            with closing(sqlite3.connect(native)) as result:
                assert result.execute("SELECT * FROM cidr_legacy_metadata ORDER BY id").fetchall() == rows
                networks = result.execute("""SELECT source, family, hex(address), prefix
                    FROM cidr_input_networks ORDER BY source""").fetchall()
                assert networks == [("cloudflare-ips.txt", 4, "C6336402", 32),
                                    ("custom-ips.txt", 4, "CB007100", 24)]

                source.execute("UPDATE provider_cidr SET cidr='192.0.2.0/24' WHERE id=5")
                source.execute("UPDATE provider_cidr SET cidr='malformed' WHERE id=8")
                source.commit()
                assert migrate(binary, native, legacy) == (
                    1, {"state": "error", "error": "invalid_legacy_row", "row": 3})
                assert result.execute("SELECT * FROM cidr_legacy_metadata ORDER BY id").fetchall() == rows
                assert result.execute("""SELECT source, family, hex(address), prefix
                    FROM cidr_input_networks ORDER BY source""").fetchall() == networks


if __name__ == "__main__":
    main(sys.argv[1])
