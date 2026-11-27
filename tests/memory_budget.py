#!/usr/bin/env python3
"""Exercise the TLS prototype under a systemd cgroup v2 memory limit."""

import argparse
from contextlib import ExitStack, closing
import hashlib
import http.client
import os
from pathlib import Path
import subprocess
import tempfile
import time

import smoke


LIMIT_MIB = 20
UPLOAD_MIB = 48
CHUNK = bytes(range(256)) * 256


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def upload(client, data):
    length = UPLOAD_MIB * 1024 * 1024
    expected = hashlib.sha256()
    with closing(client.connection()) as connection:
        connection.putrequest("POST", "/api/backups/upload")
        connection.putheader("Authorization", smoke.AUTH["Authorization"])
        connection.putheader("Content-Type", "application/octet-stream")
        connection.putheader("Content-Length", str(length))
        connection.endheaders()
        for offset in range(0, length, len(CHUNK)):
            connection.send(CHUNK)
            expected.update(CHUNK)
            if offset % (4 * 1024 * 1024) == 0:
                smoke.check_health(client)
        with connection.getresponse() as response:
            smoke.require(response.status == 201, f"Upload returned {response.status}")
            result = smoke.json_object(response.read(smoke.MAX_TEST_RESPONSE), "Backup")
    with (data / "backups" / result["name"]).open("rb") as file:
        smoke.require(hashlib.file_digest(file, "sha256").digest() == expected.digest(), "Upload hash mismatch")


def exercise(client, data):
    status, _ = client.request("GET", "/")
    smoke.require(status == 200, f"SPA returned {status}")
    with ExitStack() as stack:
        events = []
        for _ in range(3):
            connection = stack.enter_context(closing(client.connection()))
            connection.request("GET", "/api/monitor/events", headers=smoke.AUTH)
            response = stack.enter_context(connection.getresponse())
            smoke.require(response.status == 200, f"SSE returned {response.status}")
            smoke.read_event_sample(response)
            events.append(response)
        sockets = []
        for _ in range(2):
            sock = stack.enter_context(client.socket())
            stream = stack.enter_context(sock.makefile("rb"))
            smoke.websocket_request(sock, client.port, authorized=True, subprotocol=True)
            status, _ = smoke.read_websocket_headers(stream)
            smoke.require(status == 101, f"WebSocket upgrade returned {status}")
            smoke.read_websocket_sample(stream, sock)
            sockets.append((stream, sock))
        upload(client, data)
        for response in events:
            smoke.read_event_sample(response)
        for stream, sock in sockets:
            smoke.read_websocket_sample(stream, sock)
        smoke.check_health(client)


def wait_for_health(client):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            smoke.check_health(client)
        except (OSError, http.client.HTTPException):
            time.sleep(0.1)
        else:
            return
    raise AssertionError("Panel failed to start under the cgroup limit")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("tls_cert", type=Path)
    parser.add_argument("tls_key", type=Path)
    args = parser.parse_args()
    unit = f"apaz-memory-{os.getpid()}.service"
    smoke.TIMEOUT = 15
    port = smoke.choose_port()
    client = smoke.PanelClient(port, tls=True)
    with tempfile.TemporaryDirectory(prefix="apaz-memory-") as temporary:
        root = Path(temporary)
        ui = root / "ui"
        ui.mkdir()
        (ui / "index.html").write_bytes(smoke.INDEX)
        data = root / "data"
        run("sudo", "systemd-run", "--quiet", "--unit", unit, "--uid", str(os.getuid()),
            "--property", f"MemoryMax={LIMIT_MIB}M", "--property", "MemorySwapMax=0",
            "--setenv", f"APAZ_AUTH_TOKEN={smoke.TOKEN}", str(args.binary.resolve()),
            "--port", str(port), "--ui-dir", str(ui), "--data-dir", str(data),
            "--tls-cert", str(args.tls_cert.resolve()), "--tls-key", str(args.tls_key.resolve()))
        try:
            wait_for_health(client)
            path = run("systemctl", "show", "--value", "-p", "ControlGroup", unit, capture_output=True).stdout.strip()
            group = Path("/sys/fs/cgroup") / path.lstrip("/")
            limit = LIMIT_MIB * 1024 * 1024
            smoke.require((group / "memory.max").read_text().strip() == str(limit), "Cgroup memory cap was not applied")
            smoke.require((group / "memory.swap.max").read_text().strip() == "0", "Cgroup swap cap was not applied")
            print(f"Initial memory.current: {(group / 'memory.current').read_text().strip()} bytes", flush=True)
            exercise(client, data)
            peak = int((group / "memory.peak").read_text())
            events = dict(line.split() for line in (group / "memory.events").read_text().splitlines())
            print(f"TLS, 3 SSE, 2 WebSockets, {UPLOAD_MIB} MiB upload. Peak: {peak / (1024 * 1024):.2f} MiB. Events: {events}")
            smoke.require(peak <= limit and events["oom"] == "0", "Panel went over the memory budget")
        except Exception:
            subprocess.run(["sudo", "journalctl", "-u", unit, "--lines", "30", "--no-pager"], check=False)
            raise
        finally:
            run("sudo", "systemctl", "stop", unit)


if __name__ == "__main__":
    main()
