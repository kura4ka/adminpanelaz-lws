"""Verify offline migration of the pinned upstream history tables."""

import datetime as dt
from contextlib import closing, contextmanager
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile


@contextmanager
def database(path):
    with closing(sqlite3.connect(path)) as db, db:
        yield db


def query_tables(path):
    with database(path) as db:
        return [
            db.execute(f"SELECT * FROM {table} ORDER BY 1, 2").fetchall()
            for table in ("legacy_observation", "legacy_client_traffic", "legacy_audit_event")
        ]


def fixture(source):
    now = int(dt.datetime.now(dt.timezone.utc).timestamp())
    early = now - now % 3600 - 3600

    def stamp(ts):
        return dt.datetime.fromtimestamp(ts, dt.timezone.utc).replace(tzinfo=None).isoformat(" ")

    with database(source) as db:
        db.executescript(
            """
            CREATE TABLE nodes(id INTEGER PRIMARY KEY, is_local BOOLEAN, node_kind TEXT);
            INSERT INTO nodes VALUES (1,1,'vpn'),(2,0,'vpn'),(3,1,'vpn');
            CREATE TABLE node_resource_sample(
                id INTEGER PRIMARY KEY,node_id INTEGER,created_at DATETIME,cpu_percent REAL,
                memory_used_mb INTEGER,memory_total_mb INTEGER,disk_percent REAL);
            CREATE TABLE connection_count_samples(
                id INTEGER PRIMARY KEY,node_id INTEGER,created_at DATETIME,
                openvpn_count INTEGER,wireguard_count INTEGER,amneziawg2_count INTEGER);
            CREATE TABLE user_traffic_sample(
                id INTEGER PRIMARY KEY,node_id INTEGER,created_at DATETIME,common_name TEXT,
                delta_received INTEGER,delta_sent INTEGER);
            CREATE TABLE user_action_logs(
                id INTEGER PRIMARY KEY,user_id INTEGER,created_at DATETIME,action TEXT);
            """
        )
        db.executemany(
            "INSERT INTO node_resource_sample VALUES (?,?,?,?,?,?,?)",
            [
                (1, 1, stamp(early + 15), 21.2, 17, 100, 12.5),
                (2, 2, stamp(early + 15), 99, 70, 100, 99),
                (3, 1, stamp(now - 31 * 86400), 44, 70, 100, 44),
                (4, 1, stamp(early + 120), None, None, None, None),
            ],
        )
        db.execute(
            "INSERT INTO connection_count_samples VALUES(1,1,?,1,2,3)", (stamp(early + 18),)
        )
        db.executemany(
            "INSERT INTO user_traffic_sample VALUES(?,?,?,?,?,?)",
            [
                (1, 1, stamp(early + 30), "profile", 17, 25),
                (2, 1, stamp(early + 51), "profile", 13, 65),
                (3, 2, stamp(early + 58), "profile", 600, 600),
                (4, 1, stamp(early + 63), "another", 100, 150),
            ],
        )
        db.executemany(
            "INSERT INTO user_action_logs VALUES(?,?,?,?)",
            [(1, 12, stamp(early + 40), "login_success"), (2, None, stamp(early + 90), "node_online")],
        )
    return early


def check(cli):
    with tempfile.TemporaryDirectory(prefix="apaz-legacy-history-") as temporary:
        path = Path(temporary)
        source = path / "adminpanel.db"
        target = path / "data"
        target.mkdir()
        ts = fixture(source)

        def invoke(node_id):
            return subprocess.run(
                [str(cli), str(source), str(target), str(node_id)],
                capture_output=True,
                text=True,
                timeout=10,
            )

        def successful():
            result = invoke(1)
            assert result.returncode == 0, (result.stderr, result.stdout)
            assert json.loads(result.stdout) == {"resources": 2, "connections": 1, "traffic": 3, "audit": 2}

        initial_source = source.read_bytes()
        successful()
        assert source.read_bytes() == initial_source
        destination = target / "lws-history.db"
        expected = [
            [
                (ts, 212, 17 * 1048576, 100 * 1048576, 125, 1, 2, 3, 30, 90),
                (ts + 60, None, None, None, None, None, None, None, 100, 150),
                (ts + 120, None, None, None, None, None, None, None, None, None),
            ],
            [(ts, "another", 100, 150), (ts, "profile", 30, 90)],
            [(1, ts + 40, 12, "login_success", 1), (2, ts + 90, None, "node_online", None)],
        ]
        assert query_tables(destination) == expected
        successful()
        assert query_tables(destination) == expected
        assert invoke(2).returncode == 1 and invoke(3).returncode == 1
        assert query_tables(destination) == expected

        with database(source) as db:
            db.execute("UPDATE user_traffic_sample SET delta_received=-5 WHERE id=2")
        assert invoke(1).returncode == 1
        assert query_tables(destination) == expected
        with database(source) as db:
            db.execute("UPDATE user_traffic_sample SET delta_received=13 WHERE id=2")
        with database(destination) as db:
            db.execute("INSERT INTO observation(ts,cpu,traffic_complete) VALUES(?,123,1)", (ts + 60,))
        result = invoke(1)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {"resources": 1, "connections": 1, "traffic": 2, "audit": 2}
        assert query_tables(destination)[0] == [expected[0][0]]
        with database(destination) as db:
            assert db.execute("SELECT ts,cpu FROM observation").fetchone() == (ts + 60, 123)


if __name__ == "__main__":
    check(Path(sys.argv[1]).resolve())
