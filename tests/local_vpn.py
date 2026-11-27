#!/usr/bin/env python3
"""Exercise the Linux VPN helper, socket client and scoped profile resolution with synthetic state."""

import ctypes
from contextlib import closing
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlencode

from smoke import PanelClient, TOKEN, choose_port, run_panel, wait_for_server


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def build_shared_library(directory):
    root = Path(__file__).resolve().parent.parent
    library = directory / "panel-client.so"
    subprocess.run([os.environ.get("CC", "cc"), "-shared", "-fPIC", "-Wall", "-Wextra", "-Werror", "-o", library,
                    root / "src/panel_client.c", root / "src/panel_profiles.c"], check=True)
    client = ctypes.CDLL(str(library))
    text = ctypes.c_char_p
    client.panel_client_start.argtypes = [text, text, text, text]
    client.panel_client_poll.argtypes = [text]
    client.panel_client_result_name.argtypes = [ctypes.c_int]
    client.panel_client_result_name.restype = text
    client.panel_profile_open_variant.argtypes = [text, text, text, text, text, ctypes.POINTER(ctypes.c_size_t)]
    client.panel_profile_open_variant.restype = ctypes.c_void_p
    client.panel_profiles_json_page.argtypes = [text, ctypes.c_size_t, text, ctypes.c_size_t, text, text, text]
    client.panel_profiles_json_page.restype = ctypes.c_size_t
    return client


def create_fixtures(directory):
    pki = directory / "openvpn/easyrsa3/pki"
    issued = pki / "issued"
    private = pki / "private"
    wireguard = directory / "wireguard"
    for subdir in (issued, private, wireguard):
        subdir.mkdir(parents=True)
    (pki / "ca.crt").write_text("CA\n")
    (issued / "antizapret-server.crt").write_text("Server certificate\n")
    (private / "antizapret-server.key").write_text("Server key\n")
    (wireguard / "key").write_text("WireGuard key\n")
    for tunnel in ("antizapret", "vpn"):
        (wireguard / f"{tunnel}.conf").write_text("[Interface]\n# Client = Neighbor-2\n")
    script = directory / "client.sh"
    script.write_text('''#!/bin/sh
set -eu
cd "$(dirname "$0")"
case "$1" in
    1) sleep 0.25; printf '%s\\n' "$3" > "openvpn/easyrsa3/pki/issued/$2.crt" ;;
    2) rm "openvpn/easyrsa3/pki/issued/$2.crt" ;;
    4) for tunnel in antizapret vpn; do printf '# Client = %s\\n' "$2" >> "wireguard/$tunnel.conf"; done ;;
    5) sed -i "/^# Client = $2$/d" wireguard/antizapret.conf wireguard/vpn.conf ;;
    *) exit 1 ;;
esac
''')
    script.chmod(0o700)
    profiles = directory / "profiles"
    variant = profiles / "openvpn/vpn-udp"
    variant.mkdir(parents=True)
    payload = "# synthetic test profile\n"
    (variant / "vpn-Alice-2-(panel.example.org)-udp.ovpn").write_text(payload)
    (variant / "vpn-Alice-(panel.example.org)-udp.ovpn").write_text(payload)
    (variant / "vpn-Symlink-(panel.example.org)-udp.ovpn").symlink_to(variant / "vpn-Alice-(panel.example.org)-udp.ovpn")
    return script, profiles, payload


def check_scoped_profiles(client, profiles, payload):
    dismiss = ctypes.CDLL(None).fclose
    dismiss.argtypes = [ctypes.c_void_p]
    raw = ctypes.create_string_buffer(129)
    size = ctypes.c_size_t()

    def profile(name):
        handle = client.panel_profile_open_variant(os.fsencode(profiles), b"openvpn", b"vpn-udp", name, raw,
                                                   ctypes.byref(size))
        if handle:
            dismiss(handle)
            return raw.value, size.value

    require(profile(b"Alice") == (b"vpn-Alice-(panel.example.org)-udp.ovpn", len(payload)), "Wrong scoped file")
    require(profile(b"Alice-2") == (b"vpn-Alice-2-(panel.example.org)-udp.ovpn", len(payload)), "Missing exact suffix")
    require(profile(b"Ali") is None, "A partial client name matched another profile")
    require(profile(b"Symlink") is None, "Accepted a symbolic link")
    require(profile(b"alice") is None, "Case-insensitive profile lookup crossed client scope")


def check_pagination(client, profiles, payload):
    directory = profiles / "wireguard/vpn"
    directory.mkdir(parents=True)
    for index in reversed(range(100)):
        (directory / f"vpn-Client{index:03}-(panel.example.org)-wg.conf").write_text(payload)
    buffer = ctypes.create_string_buffer(32768)

    def page(offset=0, cursor=None, query=None, protocol=b"wireguard"):
        size = client.panel_profiles_json_page(buffer, len(buffer), os.fsencode(profiles), offset, cursor, query, protocol)
        require(size > 0, "Could not serialize paged profiles")
        return json.loads(buffer.raw[:size])

    first = page()
    require(first["offset"] == 0 and first["total"] == 100, "Wrong initial pagination metadata")
    ordered = [row["id"] for row in first["profiles"]]
    require(len(ordered) < 100 and ordered == sorted(ordered), "Profiles were not ordered on the first page")
    (directory / first["profiles"][0]["name"]).unlink()
    (directory / "vpn-AddedBeforeCursor-(panel.example.org)-wg.conf").write_text(payload)
    second = page(first["next_offset"], first["next_cursor"].encode())
    require(second["offset"] == len(ordered) and second["next_cursor"] is None, "Wrong final pagination metadata")
    ordered.extend(item["id"] for item in second["profiles"])
    require(len(ordered) == 100 and ordered == sorted(set(ordered)), "A cursor skipped or duplicated a later profile")
    searched = page(query=b"client098")
    require(searched["total"] == 1 and searched["profiles"][0]["client_name"] == "Client098", "Catalog search missed a later page")
    empty = page(query=b"client098", protocol=b"openvpn")
    require(empty["total"] == 0, "Protocol filter searched another protocol")


def workers(listener, arguments):
    while True:
        try:
            connection, _ = listener.accept()
        except OSError:
            return
        with connection:
            subprocess.run(arguments, stdin=connection, stdout=connection, check=True, timeout=10)


def check_operations(worker, client, directory, script):
    path = directory / "client.sock"
    raw_path = os.fsencode(path)
    require(client.panel_client_result_name(client.panel_client_poll(raw_path)) == b"unavailable", "Socket does not exist")
    arguments = [worker, script, directory / "client.lock", "--socket", directory]
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path))
        listener.listen(4)
        thread = threading.Thread(target=workers, args=(listener, arguments), daemon=True)
        thread.start()

        def start(operation, name=None, days=None):
            return client.panel_client_result_name(client.panel_client_start(raw_path, operation, name, days))

        def terminal_state():
            until = time.monotonic() + 5
            while time.monotonic() < until:
                status = client.panel_client_result_name(client.panel_client_poll(raw_path))
                if status != b"running":
                    return status
                time.sleep(0.02)
            raise AssertionError("The worker failed to return a status")

        def execute(operation, name, days=None):
            status = start(operation, name, days)
            return terminal_state() if status == b"running" else status

        require(terminal_state() == b"idle", "Unexpected initial worker status")
        for name in (b"--help", b"antizapret-server", b"../escape", b"vpn-Alice", b"Alice\nunexpected"):
            require(start(b"openvpn-add", name, b"30") == b"invalid", "Accepted invalid client name")
        require(start(b"openvpn-add", b"Alice", b"070") == b"invalid", "Accepted ambiguous days")
        require(start(b"profiles-regenerate") == b"invalid", "Accepted bulk profile regeneration from web")
        lock = directory / "client.lock"
        lock.touch(mode=0o600)
        with lock.open("r+") as competing_client:
            fcntl.flock(competing_client, fcntl.LOCK_EX)
            require(execute(b"openvpn-add", b"Alice", b"30") == b"conflict", "The worker did not respect its lock")
        require(start(b"openvpn-add", b"Alice", b"30") == b"running", "Creation failed to start")
        require(start(b"wireguard-add", b"Bob") == b"conflict", "Accepted concurrent mutation")
        require(terminal_state() == b"ok", "OpenVPN creation failed")
        certificate = directory / "openvpn/easyrsa3/pki/issued/Alice.crt"
        require(certificate.read_text() == "30\n", "Wrong script certificate argument")
        require(execute(b"openvpn-add", b"Alice", b"31") == b"conflict", "Creation renewed an existing certificate")
        require(certificate.read_text() == "30\n", "Certificate changed on duplicate creation")
        require(execute(b"openvpn-add", b"alice", b"31") == b"conflict", "Case-only OpenVPN duplicate")
        require(execute(b"openvpn-remove", b"Alice") == b"ok" and not certificate.exists(), "OpenVPN removal failed")
        require(execute(b"openvpn-remove", b"Alice") == b"ok", "Repeated OpenVPN removal failed")
        require(execute(b"wireguard-remove", b"Neighbor") == b"ok", "Removal did not use an exact peer name")
        require(execute(b"wireguard-add", b"Bob") == b"ok", "WireGuard creation failed")
        require(execute(b"wireguard-add", b"bob") == b"conflict", "Case-only WireGuard duplicate")
        require(execute(b"wireguard-remove", b"Bob") == b"ok", "WireGuard removal failed")
        require(execute(b"wireguard-remove", b"Bob") == b"ok", "Repeated WireGuard removal failed")
        require("Neighbor-2" in (directory / "wireguard/vpn.conf").read_text(), "Unrelated peer disappeared")
        with socket.socket(socket.AF_UNIX) as connection:
            connection.connect(str(path))
            connection.sendall(b"profiles-regenerate\n")
            require(connection.recv(16) == b"2\n", "Worker accepted a forbidden socket command")
        (directory / "wireguard/key").unlink()
        require(execute(b"wireguard-add", b"Bob") == b"not_configured", "Absent setup was implicitly initialized")


def check_http(panel, worker, directory, script, profiles):
    path = directory / "http.sock"
    data = directory / "panel-data"
    data.mkdir()
    port = choose_port()
    client = PanelClient(port, tls=False)
    log = directory / "panel.log"
    command = [panel, "--port", str(port), "--data-dir", data, "--auth-db", data / "auth.db",
               "--client-socket", path, "--profiles-dir", profiles]
    arguments = [worker, script, directory / "client.lock", "--socket", directory]
    operation_path = "/api/clients/operation"
    form_header = {"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"}
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path))
        listener.listen(4)
        threading.Thread(target=workers, args=(listener, arguments), daemon=True).start()
        with run_panel(command, log) as process:
            wait_for_server(process, client)
            status, _ = client.request("GET", operation_path)
            require(status == 401, "Client operation was visible to an unauthenticated request")
            with closing(client.connection()) as connection:
                connection.request("POST", "/api/auth/login", urlencode({"username": "admin", "password": TOKEN}), form_header)
                with connection.getresponse() as response:
                    require(response.status == 200, "Synthetic admin could not sign in")
                    authorization = {"Cookie": response.getheader("Set-Cookie").split(";", 1)[0]}
            status, body = client.request("GET", "/api/nodes/active", headers=authorization)
            require(status == 200, "Local node context was unavailable")
            revision = json.loads(body)["revision"]
            data = {"operation": "openvpn-add", "name": "HttpClient", "days": "30", "revision": revision + 1}
            headers = {**authorization, **form_header}
            status, body = client.request("POST", operation_path, urlencode(data), headers)
            require(status == 409 and json.loads(body)["error"] == "node_context_changed", "Old node context was accepted")
            data["revision"] = revision
            status, _ = client.request("POST", operation_path, urlencode(data), {**headers, "Origin": "https://other.invalid"})
            require(status == 403, "Cross-site client mutation was accepted")
            status, body = client.request("POST", operation_path, urlencode(data), headers)
            require(status == 202 and json.loads(body)["status"] == "running", "Panel did not start the worker")
            until = time.monotonic() + 5
            terminal = None
            while time.monotonic() < until:
                _, body = client.request("GET", operation_path, headers=authorization)
                terminal = json.loads(body)["status"]
                if terminal != "running":
                    break
                time.sleep(0.05)
            require(terminal == "ok", f"Panel did not receive worker status: {terminal}")
            status, body = client.request("GET", "/api/profiles?query=alice&protocol=openvpn", headers=authorization)
            require(status == 200 and json.loads(body)["total"] == 2, "Panel inventory query missed scoped profiles")


def main():
    if sys.platform != "linux" or len(sys.argv) not in (2, 3):
        raise SystemExit("Usage on Linux: python3 tests/local_vpn.py /path/to/adminpanelaz-client [/path/to/adminpanelaz-lws]")
    worker = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="apaz-client-") as location:
        directory = Path(location)
        client = build_shared_library(directory)
        script, profiles, payload = create_fixtures(directory)
        check_scoped_profiles(client, profiles, payload)
        check_pagination(client, profiles, payload)
        check_operations(worker, client, directory, script)
        if len(sys.argv) == 3:
            check_http(Path(sys.argv[2]).resolve(), worker, directory, script, profiles)
    print("Local VPN helper operations, paginated catalog and scoped profiles passed")


if __name__ == "__main__":
    main()
