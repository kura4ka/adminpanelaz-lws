#!/usr/bin/env python3
"""Exercise the installed-service workload under a systemd cgroup v2 limit."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
import hashlib
import http.client
import os
from pathlib import Path
import statistics
import subprocess
import tempfile
from threading import Event
import time
from urllib.parse import urlencode

import smoke


LIMIT_MIB = 20
UPLOAD_MIB = 48
UPLOAD_SECONDS = 8
SSE_COUNT = 3
SOCKET_COUNT = 2
PEER_COUNT = 32
CHUNK = bytes(range(256)) * 256


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def upload(client, cookie):
    length = UPLOAD_MIB * 1024 * 1024
    expected = hashlib.sha256()
    started = time.monotonic()
    with closing(client.connection()) as connection:
        connection.putrequest("POST", "/api/backups/upload")
        connection.putheader("Cookie", cookie["Cookie"])
        connection.putheader("Content-Type", "application/octet-stream")
        connection.putheader("Content-Length", str(length))
        connection.endheaders()
        for offset in range(0, length, len(CHUNK)):
            delay = started + UPLOAD_SECONDS * offset / length - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            connection.send(CHUNK)
            expected.update(CHUNK)
        with connection.getresponse() as response:
            smoke.require(response.status == 201, f"Upload returned {response.status}")
            result = smoke.json_object(response.read(smoke.MAX_TEST_RESPONSE), "Backup")
    smoke.require(result["size"] == length, "Recorded backup size does not match the upload")
    return result["name"], length, expected.digest()


def check_download(client, cookie, name, length, expected_hash):
    with closing(client.connection()) as connection:
        connection.request("GET", f"/api/backups/{name}/download", headers=cookie)
        with connection.getresponse() as response:
            smoke.require(response.status == 200, f"Download returned {response.status}")
            smoke.require(response.length == length, "Download length differs from the upload")
            actual = hashlib.sha256()
            for chunk in iter(lambda: response.read(len(CHUNK)), b""):
                actual.update(chunk)
    smoke.require(actual.digest() == expected_hash, "Downloaded backup hash differs from the upload")


def login(client):
    form = urlencode({"username": "admin", "password": smoke.TOKEN})
    with closing(client.connection()) as connection:
        connection.request("POST", "/api/auth/login", body=form,
                           headers={"Content-Type": "application/x-www-form-urlencoded"})
        with connection.getresponse() as response:
            cookie = response.getheader("Set-Cookie")
            smoke.require(response.status == 200 and cookie, f"Login returned {response.status}")
            response.read(smoke.MAX_TEST_RESPONSE)
    return {"Cookie": cookie.split(";", 1)[0]}


def profiles_fixture(directory):
    variant = directory / "openvpn" / "vpn"
    variant.mkdir(parents=True)
    for peer in range(1, PEER_COUNT + 1):
        (variant / f"load-{peer}.ovpn").write_text("client\nremote 192.0.2.1 1194\n", encoding="ascii")


def update_status(openvpn, wireguard, revision):
    now = int(time.time())
    status = ["TITLE,OpenVPN load fixture",
              "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Bytes Received,Bytes Sent,Connected Since,Connected Since (time_t)"]
    peers = ["WIREGUARD_STATUS_V1"]
    for peer in range(1, PEER_COUNT + 1):
        incoming = peer * 1000 + revision * 1000
        outgoing = peer * 2000 + revision * 3000
        status.append(f"CLIENT_LIST,load-{peer},192.0.2.{peer}:1000,10.0.0.{peer},"
                      f"{incoming},{outgoing},2026-01-01 00:00:00,{now - 60}")
        peers.append(f"vpn\tpeer-{peer}\t198.51.100.{peer}:1200\t10.1.0.{peer}/32\t{incoming}\t{outgoing}\t{now}")
    for path, content in ((openvpn, status), (wireguard, peers)):
        staged = path.with_suffix(".tmp")
        staged.write_text("\n".join([*content, "END", ""]), encoding="ascii")
        staged.replace(path)


def check_monitor(client, headers, streams, revision):
    status, body = client.request("GET", "/api/monitor", headers=headers)
    smoke.require(status == 200, f"Monitoring returned {status}")
    sample = smoke.json_object(body, "Monitoring")
    smoke.require(isinstance(sample["host"]["interfaces"], list), "Host metrics are missing")
    smoke.require(sample["vpn"]["total"] == PEER_COUNT, "OpenVPN client count is incorrect")
    smoke.require(sample["wireguard"]["active"] == PEER_COUNT, "WireGuard active peer count is incorrect")
    smoke.require(sample["streams"] == streams, "Unexpected number of concurrent streams")
    expected_rx = 1000 + revision * 1000
    for protocol in ("vpn", "wireguard"):
        smoke.require(sample[protocol]["clients"][0]["rx_bytes"] == expected_rx,
                      f"{protocol} did not read the updated counters")


def create_archive(client, cookie):
    status, body = client.request("POST", "/api/backups/create", headers=cookie)
    smoke.require(status == 201, f"Native backup creation returned {status}: {body!r}")
    return smoke.json_object(body, "Native backup")["name"]


def count_samples(read_sample, finished):
    count = 0
    while not finished.is_set():
        read_sample()
        count += 1
    return count


def exercise(client, openvpn, wireguard):
    status, _ = client.request("GET", "/")
    smoke.require(status == 200, f"SPA returned {status}")
    cookie = login(client)
    status, body = client.request("GET", "/api/profiles", headers=cookie)
    smoke.require(status == 200, f"Profile list returned {status}")
    smoke.require(smoke.json_object(body, "Profiles")["total"] == PEER_COUNT, "Profile fixture is incomplete")
    check_monitor(client, cookie, 0, 0)
    with ExitStack() as stack:
        readers = []
        for _ in range(SSE_COUNT):
            connection = stack.enter_context(closing(client.connection()))
            connection.request("GET", "/api/monitor/events", headers=smoke.AUTH)
            response = stack.enter_context(connection.getresponse())
            smoke.require(response.status == 200, f"SSE returned {response.status}")
            smoke.read_event_sample(response)
            readers.append(lambda response=response: smoke.read_event_sample(response))
        for _ in range(SOCKET_COUNT):
            sock = stack.enter_context(client.socket())
            stream = stack.enter_context(sock.makefile("rb"))
            expected = smoke.websocket_request(sock, client.port, authorized=True, subprotocol=True)
            status, headers = smoke.read_websocket_headers(stream)
            smoke.require(status == 101, f"WebSocket upgrade returned {status}")
            smoke.require(headers.get("Sec-WebSocket-Accept") == expected, "Incorrect WebSocket accept hash")
            smoke.read_websocket_sample(stream, sock)
            readers.append(lambda stream=stream, sock=sock: smoke.read_websocket_sample(stream, sock))

        finished = Event()
        latency = []
        with ThreadPoolExecutor(max_workers=len(readers) + 2) as executor:
            samples = [executor.submit(count_samples, reader, finished) for reader in readers]
            transfer = executor.submit(upload, client, cookie)
            backup = None
            try:
                while not transfer.done():
                    revision = len(latency) + 1
                    update_status(openvpn, wireguard, revision)
                    started = time.monotonic()
                    check_monitor(client, cookie, len(readers), revision)
                    latency.append(1000 * (time.monotonic() - started))
                    if backup is None and len(latency) >= 4:
                        backup = executor.submit(create_archive, client, cookie)
                    time.sleep(0.25)
                archive = transfer.result()
                smoke.require(backup is not None, "Archive creation did not run during the transfer")
                created = backup.result()
                check_download(client, cookie, *archive)
            finally:
                finished.set()
            counts = [sample.result() for sample in samples]

        status, body = client.request("GET", f"/api/backups/{created}/inspect", headers=cookie)
        smoke.require(status == 200, f"Native archive inspection returned {status}")
        smoke.require("lws_auth" in smoke.json_object(body, "Native archive inspection")["components"],
                      "Native archive did not preserve the panel account database")
        smoke.require(all(count >= 2 for count in counts), "A stream stopped producing updates under load")
        smoke.require(len(latency) >= 8, "Too few monitoring requests ran during the transfer")
        print(f"Monitoring TLS requests: {len(latency)}, median {statistics.median(latency):.1f} ms, "
              f"max {max(latency):.1f} ms. SSE samples: {counts[:SSE_COUNT]}. "
              f"WebSocket samples: {counts[SSE_COUNT:]}.", flush=True)
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
    parser.add_argument("--state-parent", type=Path, default=Path.cwd(),
                        help="disk-backed directory for the temporary service state")
    args = parser.parse_args()
    state_parent = args.state_parent.resolve()
    filesystem = run("stat", "--file-system", "--format=%T", str(state_parent), capture_output=True).stdout.strip()
    if filesystem in {"tmpfs", "ramfs"}:
        parser.error("choose --state-parent on a disk-backed filesystem, as used by the systemd StateDirectory")
    unit = f"apaz-memory-{os.getpid()}.service"
    smoke.TIMEOUT = 15
    port = smoke.choose_port()
    client = smoke.PanelClient(port, tls=True)
    with tempfile.TemporaryDirectory(prefix="apaz-memory-", dir=state_parent) as temporary:
        root = Path(temporary)
        data = root / "data"
        profiles = root / "profiles"
        openvpn = root / "openvpn.status"
        wireguard = root / "wireguard.status"
        profiles_fixture(profiles)
        update_status(openvpn, wireguard, 0)
        sudo = [] if os.getuid() == 0 else ["sudo"]
        run(*sudo, "systemd-run", "--quiet", "--unit", unit, "--uid", str(os.getuid()),
            "--property", "MemoryAccounting=yes", "--property", f"MemoryMax={LIMIT_MIB}M",
            "--property", "MemorySwapMax=0",
            "--setenv", f"APAZ_AUTH_TOKEN={smoke.TOKEN}", str(args.binary.resolve()),
            "--port", str(port), "--data-dir", str(data), "--auth-db", str(data / "auth.db"),
            "--profiles-dir", str(profiles), "--openvpn-status", str(openvpn), "--wireguard-status", str(wireguard),
            "--tls-cert", str(args.tls_cert.resolve()), "--tls-key", str(args.tls_key.resolve()))
        try:
            wait_for_health(client)
            path = run("systemctl", "show", "--value", "-p", "ControlGroup", unit, capture_output=True).stdout.strip()
            smoke.require(path.startswith("/") and path != "/", "Service cgroup is unavailable")
            group = Path("/sys/fs/cgroup") / path.lstrip("/")
            limit = LIMIT_MIB * 1024 * 1024
            smoke.require((group / "memory.max").read_text().strip() == str(limit), "Cgroup memory cap was not applied")
            smoke.require((group / "memory.swap.max").read_text().strip() == "0", "Cgroup swap cap was not applied")
            print(f"Initial memory.current: {(group / 'memory.current').read_text().strip()} bytes", flush=True)
            exercise(client, openvpn, wireguard)
            peak = int((group / "memory.peak").read_text())
            events = dict(line.split() for line in (group / "memory.events").read_text().splitlines())
            print(f"TLS, {PEER_COUNT} OpenVPN clients, {PEER_COUNT} WireGuard peers, {UPLOAD_MIB} MiB upload and download, "
                  f"native archive creation. Peak: {peak / (1024 * 1024):.2f} MiB. Events: {events}")
            smoke.require(peak <= limit and events["oom"] == "0" and events["oom_kill"] == "0",
                          "Panel went over the memory budget")
        except Exception:
            subprocess.run([*sudo, "journalctl", "-u", unit, "--lines", "30", "--no-pager"], check=False)
            raise
        finally:
            run(*sudo, "systemctl", "stop", unit)


if __name__ == "__main__":
    main()
