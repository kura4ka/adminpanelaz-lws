#!/usr/bin/env python3
"""Exercise the running C panel using only the Python standard library."""

import argparse
import base64
from contextlib import closing, contextmanager
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode


HOST = "127.0.0.1"
TOKEN = "adminpanel-smoke-token-with-at-least-32-characters"
AUTH = {"Authorization": f"Bearer {TOKEN}"}
TIMEOUT = 3
MAX_TEST_RESPONSE = 64 * 1024
MAX_BACKUP_SIZE = 200 * 1024 * 1024
INDEX = b'<!doctype html><title>AdminPanelAZ smoke fixture</title><script src="./assets/app.js"></script>'
SERVED_INDEX = INDEX.replace(b"./assets/", b"/assets/")
ASSET = b"console.log('AdminPanelAZ smoke fixture');\n"


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class PanelClient:
    def __init__(self, port, tls):
        self.port = port
        # The runner supplies the test certificate. It can be self-signed.
        self.tls = None
        if tls:
            self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            self.tls.check_hostname = False
            self.tls.verify_mode = ssl.CERT_NONE

    def connection(self):
        if self.tls is not None:
            return http.client.HTTPSConnection(
                HOST, self.port, timeout=TIMEOUT, context=self.tls
            )
        return http.client.HTTPConnection(HOST, self.port, timeout=TIMEOUT)

    def socket(self):
        sock = socket.create_connection((HOST, self.port), timeout=TIMEOUT)
        if self.tls is None:
            return sock
        try:
            return self.tls.wrap_socket(sock, server_hostname=HOST)
        except BaseException:
            sock.close()
            raise

    def request(self, method, path, body=None, headers=None):
        with closing(self.connection()) as conn:
            conn.request(method, path, body=body, headers=headers or {})
            with conn.getresponse() as response:
                return response.status, response.read(MAX_TEST_RESPONSE)


def json_object(data, label):
    try:
        decoded = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssertionError(f"{label} returned invalid JSON: {error}") from error
    require(isinstance(decoded, dict), f"{label} must return a JSON object")
    return decoded


def check_health(client):
    status, body = client.request("GET", "/api/health")
    require(status == 200, f"GET /api/health returned {status}")
    require(json_object(body, "Health").get("status") == "ok", "Health status is not ok")


def wait_for_server(process, client):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError(f"Panel exited on startup ({process.returncode})")
        try:
            check_health(client)
        except (OSError, http.client.HTTPException):
            time.sleep(0.05)
        else:
            return
    raise AssertionError("Panel did not start within ten seconds")


def check_static(client):
    for path, expected in (("/", SERVED_INDEX), ("/settings/modules", SERVED_INDEX), ("/assets/app.js", ASSET)):
        status, body = client.request("GET", path)
        require(status == 200 and body == expected, f"Incorrect static response at {path}")
    status, body = client.request("GET", "/api/smoke-nonexistent", headers=AUTH)
    require(status == 404 and body != SERVED_INDEX, "Missing API route did not return an API 404")
    status, body = client.request("HEAD", "/settings/modules")
    require(status == 200 and not body, "SPA shell did not support HEAD")


def check_monitor(client):
    for path in ("/api/monitor", "/api/monitor/events"):
        status, _ = client.request("GET", path)
        require(status in (401, 403), f"Unauthenticated GET {path} returned {status}")
    status, body = client.request("GET", "/api/monitor", headers=AUTH)
    require(status == 200, f"GET /api/monitor returned {status}")
    monitor = json_object(body, "Monitor")
    require(isinstance(monitor["host"]["interfaces"], list), "Missing host interfaces")
    require(monitor["vpn"]["state"] == "not_configured", "Unexpected OpenVPN source")
    require(monitor["wireguard"]["state"] == "not_configured", "Unexpected WireGuard source")


def check_bundled_dashboard(command, data, log, tls):
    openvpn = data / "openvpn.status"
    openvpn.write_text(
        "TITLE,OpenVPN test fixture\n"
        "HEADER,CLIENT_LIST,Common Name,Real Address,Virtual Address,Bytes Received,Bytes Sent,Connected Since\n"
        "CLIENT_LIST,client-a,192.0.2.2:1000,10.0.0.2,100,200,2026-01-01 00:00:00\nEND\n",
        encoding="utf-8",
    )
    wireguard = data / "wireguard.status"
    wireguard.write_text(
        f"WIREGUARD_STATUS_V1\nvpn\tpeer\t192.0.2.3:1200\t10.0.0.3/32\t300\t400\t{int(time.time())}\nEND\n",
        encoding="utf-8",
    )
    port = choose_port()
    client = PanelClient(port, tls=tls)
    command = [command[0], "--port", str(port), "--data-dir", str(data),
               "--openvpn-status", str(openvpn), "--wireguard-status", str(wireguard), *command[9:]]
    with run_panel(command, log) as process:
        wait_for_server(process, client)
        status, body = client.request("GET", "/")
        require(status == 200 and "Мониторинг".encode() in body, "Embedded monitoring page did not load")
        status, body = client.request("GET", "/api/monitor", headers=AUTH)
        require(status == 200, f"Monitor returned {status}")
        metrics = json_object(body, "Monitor")
        require(metrics["vpn"]["clients"][0]["name"] == "client-a", "OpenVPN status missing")
        require(metrics["wireguard"]["active"] == 1 and metrics["wireguard"]["clients"][0]["rx_bytes"] == 300,
                "WireGuard status missing")


def check_events(client):
    with closing(client.connection()) as conn:
        conn.request("GET", "/api/monitor/events", headers={**AUTH, "Accept": "text/event-stream"})
        with conn.getresponse() as response:
            require(response.status == 200, f"SSE returned {response.status}")
            content_type = response.getheader("Content-Type", "").split(";", 1)[0].strip()
            require(content_type == "text/event-stream", f"Incorrect SSE content type {content_type!r}")
            read_event_sample(response)


def read_event_sample(response):
    event = b""
    data = []
    for _ in range(32):
        line = response.readline(MAX_TEST_RESPONSE)
        require(line and line.endswith(b"\n"), "SSE closed or emitted an overlong line")
        line = line.rstrip(b"\r\n")
        if not line:
            if data:
                require(event == b"sample", f"Incorrect SSE event {event!r}")
                return json_object(b"\n".join(data), "SSE sample")
            event = b""
        elif line.startswith(b"event:"):
            event = line[6:].lstrip(b" ")
        elif line.startswith(b"data:"):
            data.append(line[5:].removeprefix(b" "))
    raise AssertionError("No SSE sample received")


def websocket_request(sock, port, authorized, subprotocol):
    key = base64.b64encode(os.urandom(16)).decode("ascii")
    lines = [
        "GET /api/monitor/ws HTTP/1.1",
        f"Host: {HOST}:{port}",
        "Connection: Upgrade",
        "Upgrade: websocket",
        "Sec-WebSocket-Version: 13",
        f"Sec-WebSocket-Key: {key}",
    ]
    if subprotocol:
        lines.append("Sec-WebSocket-Protocol: adminpanel-monitor")
    if authorized:
        lines.append(f"Authorization: {AUTH['Authorization']}")
    sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
    accept = hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii"))
    return base64.b64encode(accept.digest()).decode("ascii")


def read_websocket_headers(stream):
    status_line = stream.readline(4096).decode("ascii").split()
    require(len(status_line) >= 2, "WebSocket returned no HTTP status")
    headers = http.client.parse_headers(stream)
    return int(status_line[1]), headers


def read_exact(stream, length):
    data = stream.read(length)
    require(len(data) == length, "WebSocket closed mid-frame")
    return data


def read_websocket_sample(stream, sock):
    message = bytearray()
    started = False
    for _ in range(32):
        flags, size = read_exact(stream, 2)
        require(not size & 0x80, "Server sent a masked WebSocket frame")
        opcode = flags & 0x0F
        final = bool(flags & 0x80)
        if size == 126:
            size = struct.unpack("!H", read_exact(stream, 2))[0]
        elif size == 127:
            size = struct.unpack("!Q", read_exact(stream, 8))[0]
        require(len(message) + size <= MAX_TEST_RESPONSE, "WebSocket sample is too large")
        data = read_exact(stream, size)
        if opcode == 0x9:
            require(size <= 125, "Oversized WebSocket ping")
            mask = os.urandom(4)
            masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(data))
            sock.sendall(bytes([0x8A, 0x80 | size]) + mask + masked)
            continue
        if opcode == 0xA:
            continue
        require(opcode == (0x0 if started else 0x1), f"Unexpected WebSocket opcode {opcode}")
        started = True
        message.extend(data)
        if final:
            return json_object(message, "WebSocket sample")
    raise AssertionError("No complete WebSocket sample received")


def check_websocket(client):
    with client.socket() as sock, sock.makefile("rb") as stream:
        websocket_request(sock, client.port, authorized=False, subprotocol=True)
        status, _ = read_websocket_headers(stream)
        require(status in (401, 403), f"Unauthenticated WebSocket returned {status}")

    for subprotocol in (False, True):
        with client.socket() as sock, sock.makefile("rb") as stream:
            expected = websocket_request(sock, client.port, authorized=True, subprotocol=subprotocol)
            status, headers = read_websocket_headers(stream)
            require(status == 101, f"WebSocket handshake returned {status}")
            require(headers.get("Sec-WebSocket-Accept") == expected, "Incorrect WebSocket accept hash")
            if subprotocol:
                require(
                    headers.get("Sec-WebSocket-Protocol") == "adminpanel-monitor",
                    "WebSocket subprotocol was not negotiated",
                )
            read_websocket_sample(stream, sock)


def check_backup(client, data_dir):
    path = "/api/backups/upload"
    body = bytes(range(256)) * 1024
    content_type = {"Content-Type": "application/octet-stream"}
    status, _ = client.request("POST", path, body=b"x", headers=content_type)
    require(status in (401, 403), f"Unauthenticated backup upload returned {status}")

    status, reply = client.request("POST", path, body=body, headers={**AUTH, **content_type})
    require(status == 201, f"Backup upload returned {status}")
    backup = json_object(reply, "Backup upload")
    name = backup.get("name")
    require(isinstance(name, str) and name and Path(name).name == name, "Invalid backup name")
    require(backup.get("size") == len(body), "Backup response has the wrong size")
    stored = data_dir / "backups" / name
    require(stored.is_file() and stored.read_bytes() == body, "Stored backup did not match upload")

    with closing(client.connection()) as conn:
        conn.putrequest("POST", path)
        for header, value in {**AUTH, **content_type}.items():
            conn.putheader(header, value)
        conn.putheader("Content-Length", str(MAX_BACKUP_SIZE + 1))
        conn.endheaders()
        with conn.getresponse() as response:
            require(response.status == 413, f"Oversized backup headers returned {response.status}")
    require(list(stored.parent.iterdir()) == [stored], "Rejected requests left backup files behind")


def check_admin(command, data, log, tls):
    profiles = data / "profiles"
    names = profiles / "wireguard" / "vpn"
    names.mkdir(parents=True)
    profile = b"# test profile\n"
    (names / "vpn-test-wg.conf").write_bytes(profile)
    if os.name == "posix":
        (names / "vpn-hidden-wg.conf").symlink_to(names / "vpn-test-wg.conf")
    port = choose_port()
    client = PanelClient(port, tls=tls)
    command = [command[0], "--port", str(port), "--data-dir", str(data),
               "--auth-db", str(data / "auth.db"), "--profiles-dir", str(profiles), *command[9:]]

    def post(path, payload, headers=None):
        with closing(client.connection()) as conn:
            conn.request("POST", path, urlencode(payload),
                         {"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8", **(headers or {})})
            with conn.getresponse() as response:
                return response.status, response.getheader("Set-Cookie"), response.read()

    def login(password):
        status, cookie, _ = post("/api/auth/login", {"username": "admin", "password": password})
        require(status == 200 and cookie, f"Login returned {status}")
        require("HttpOnly" in cookie and "SameSite=Strict" in cookie and (not tls or "; Secure" in cookie),
                "Session cookie attributes are missing")
        return {"Cookie": cookie.split(";", 1)[0]}

    with run_panel(command, log) as process:
        wait_for_server(process, client)
        status, _, _ = post("/api/auth/login", {"username": "admin", "password": TOKEN},
                            {"Origin": "https://example.invalid"})
        require(status == 403, "Accepted a cross-origin login request")
        require(client.request("GET", "/api/profiles", headers=AUTH)[0] == 401,
                "Legacy monitor token could read profiles")
        cookie = login(TOKEN)
        second_session = login(TOKEN)
        status, body = client.request("GET", "/api/auth/me", headers=cookie)
        require(status == 200 and json_object(body, "Session")["method"] == "session", "Session was not retained")
        status, body = client.request("GET", "/api/profiles", headers=cookie)
        require(status == 200, f"Profiles returned {status}")
        if os.name == "posix":
            available = json_object(body, "Profiles")
            require(available["total"] == 1, "Profile listing included a symlink or omitted the profile")
            item = available["profiles"][0]
            require(client.request("GET", f"/api/profiles/{item['id']}/download", headers=cookie) == (200, profile),
                    "Profile download differs from original bytes")
        status, body = client.request("GET", "/api/backups", headers=cookie)
        require(status == 200 and isinstance(json_object(body, "Backups")["archives"], list), "Backup list failed")
        status, body = client.request("POST", "/api/backups/upload", body=b"APAZBK1\nfixture",
                                      headers={**cookie, "Content-Type": "application/octet-stream"})
        require(status == 201, f"Protected backup upload returned {status}: {body!r}")
        name = json_object(body, "Protected upload")["name"]
        status, body = client.request("GET", f"/api/backups/{name}/inspect", headers=cookie)
        require(status == 200 and json_object(body, "Inspection")["encrypted"], "Legacy encrypted format not recognized")
        require(client.request("GET", f"/api/backups/{name}/download", headers=cookie) == (200, b"APAZBK1\nfixture"),
                "Backup download differs from original bytes")
        status, body = client.request("POST", "/api/backups/create", headers=cookie)
        require(status == 201, f"Native backup creation returned {status}: {body!r}")
        name = json_object(body, "Native backup")["name"]
        status, body = client.request("GET", f"/api/backups/{name}/inspect", headers=cookie)
        require(status == 200 and "lws_auth" in json_object(body, "Native inspection")["components"],
                "Native backup component not recognized")
        new_password = "Смена пароля 1 + & % !"
        status, cleared, _ = post("/api/auth/change-password", {"old_password": TOKEN, "new_password": new_password}, cookie)
        require(status == 200 and cleared and "Max-Age=0" in cleared, f"Password change returned {status}")
        require(client.request("GET", "/api/auth/me", headers=cookie)[0] == 401 and
                client.request("GET", "/api/auth/me", headers=second_session)[0] == 401, "Old sessions still work")
        cookie = login(new_password)
        require(client.request("POST", "/api/auth/logout", headers=cookie)[0] == 200, "Logout failed")
        require(client.request("GET", "/api/auth/me", headers=cookie)[0] == 401, "Revoked session still works")


def choose_port():
    with socket.socket() as sock:
        sock.bind((HOST, 0))
        return sock.getsockname()[1]


@contextmanager
def run_panel(command, log):
    with log.open("w+b") as output:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            env={**os.environ, "APAZ_AUTH_TOKEN": TOKEN},
        )
        try:
            yield process
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=TIMEOUT)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path, help="path to the compiled panel binary")
    parser.add_argument("--port", type=int, help="loopback test port (default: automatically selected)")
    parser.add_argument("--tls-cert", type=Path, help="certificate for an HTTPS smoke run")
    parser.add_argument("--tls-key", type=Path, help="private key for an HTTPS smoke run")
    args = parser.parse_args()
    if (args.tls_cert is None) != (args.tls_key is None):
        parser.error("--tls-cert and --tls-key must be supplied together")
    if args.port is not None and not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    if not args.binary.is_file():
        parser.error(f"binary not found: {args.binary}")

    port = args.port or choose_port()
    with tempfile.TemporaryDirectory(prefix="apaz-smoke-") as temporary:
        root = Path(temporary)
        ui = root / "ui"
        data = root / "data"
        assets = ui / "assets"
        assets.mkdir(parents=True)
        data.mkdir()
        (ui / "index.html").write_bytes(INDEX)
        (assets / "app.js").write_bytes(ASSET)
        log = root / "panel.log"

        command = [
            str(args.binary.resolve()), "--port", str(port), "--bind", HOST,
            "--ui-dir", str(ui), "--data-dir", str(data),
        ]
        if args.tls_cert:
            command += ["--tls-cert", str(args.tls_cert.resolve()), "--tls-key", str(args.tls_key.resolve())]

        client = PanelClient(port, tls=args.tls_cert is not None)
        try:
            with run_panel(command, log) as process:
                wait_for_server(process, client)
                check_static(client)
                check_monitor(client)
                check_events(client)
                check_websocket(client)
                check_backup(client, data)
                check_health(client)
            check_bundled_dashboard(command, data, log, tls=args.tls_cert is not None)
            check_admin(command, data, log, tls=args.tls_cert is not None)
        except (AssertionError, OSError, ValueError, http.client.HTTPException) as error:
            print(f"Smoke test failed: {error}", file=sys.stderr)
            if log.is_file():
                with log.open("rb") as output:
                    output.seek(max(0, log.stat().st_size - MAX_TEST_RESPONSE))
                    print(output.read().decode("utf-8", errors="replace"), file=sys.stderr, end="")
            return 1

    print("Smoke test passed: health, SPA, monitor, SSE, WebSocket, sessions, profiles, and backups")
    return 0


if __name__ == "__main__":
    sys.exit(main())
