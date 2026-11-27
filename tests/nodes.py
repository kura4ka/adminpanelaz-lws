#!/usr/bin/env python3
"""Exercise node persistence and existing HTTP, HTTPS, and mTLS agent contracts."""

import argparse
from contextlib import ExitStack, closing, contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import subprocess
import tempfile
from threading import Thread
from urllib.parse import urlencode

from smoke import HOST, TOKEN, PanelClient, choose_port, run_panel, wait_for_server


AGENT_KEY = "synthetic-agent-key-for-node-tests"


class AgentHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_json(self, status, payload, headers=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
            pass

    def authenticated(self):
        if self.headers.get("X-Node-Key") == AGENT_KEY:
            return True
        self.send_json(401, {"detail": "Wrong synthetic agent key"})
        return False

    def proxy_status(self):
        return {"installed": True, "destination_ip": self.server.destination, "detail": "ok"}

    def do_GET(self):
        if not self.authenticated():
            return
        if self.path == "/health":
            if self.server.redirect_health:
                self.send_json(307, {}, {"Location": self.server.redirect_health})
            else:
                self.send_json(200, {"status": "online", "agent_version": "1.18.0",
                                     "antizapret_version": "1.14.0"})
        elif self.path == "/proxy/status":
            self.send_json(200, self.proxy_status())
        elif self.path == "/proxy/mappings":
            data = {"client_ip": "198.51.100.23", "client_port": 15801,
                    "dest_ip": self.server.destination, "dest_port": 443}
            self.send_json(200, {"mappings": [data] * (1000 if self.server.large_mappings else 1)})
        else:
            self.send_json(404, {})

    def do_PUT(self):
        if not self.authenticated():
            return
        if self.path != "/proxy/destination" or self.headers.get_content_type() != "application/json":
            self.send_json(400, {})
            return
        payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        if set(payload) != {"destination_ip"}:
            self.send_json(422, {})
            return
        self.server.destination = payload["destination_ip"]
        self.send_json(200, self.proxy_status())


@contextmanager
def fake_agent(tls_dir=None, require_client=False):
    server = ThreadingHTTPServer((HOST, 0), AgentHandler)
    server.destination = "192.0.2.10"
    server.redirect_health = None
    server.large_mappings = False
    scheme = "http"
    if tls_dir:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(tls_dir / "server.pem", tls_dir / "server.key")
        if require_client:
            context.load_verify_locations(tls_dir / "ca.pem")
            context.verify_mode = ssl.CERT_REQUIRED
        server.socket = context.wrap_socket(server.socket, server_side=True)
        scheme = "https"
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"{scheme}://{HOST}:{server.server_port}", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def generate_certs(openssl, directory):
    directory.mkdir(mode=0o700)

    def invoke(*args):
        subprocess.run([openssl, *args], cwd=directory, check=True, capture_output=True)

    invoke("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
           "-subj", "/CN=Panel Test CA", "-keyout", "ca.key", "-out", "ca.pem")
    for key, ext in (("server", "subjectAltName=IP:127.0.0.1\nextendedKeyUsage=serverAuth\n"),
                     ("client", "extendedKeyUsage=clientAuth\n")):
        (directory / f"{key}.ext").write_text(ext, encoding="ascii")
        invoke("req", "-new", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=Panel Test " + key,
               "-keyout", f"{key}.key", "-out", f"{key}.csr")
        invoke("x509", "-req", "-days", "1", "-in", f"{key}.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
               "-CAcreateserial", "-extfile", f"{key}.ext", "-out", f"{key}.pem")
    for name in ("ca.pem", "server.pem", "client.pem"):
        (directory / name).chmod(0o644)
    for name in ("ca.key", "server.key", "client.key"):
        (directory / name).chmod(0o600)


class NodesClient:
    def __init__(self, client):
        self.client = client
        self.cookie = self.request("POST", "/api/auth/login",
                                   {"username": "admin", "password": TOKEN}, expected=200)[1]
        assert self.cookie, "Login returned no session cookie"

    def request(self, method, path, fields=None, expected=200):
        headers = getattr(self, "cookie", None)
        headers = {"Cookie": headers.split(";", 1)[0]} if headers else {}
        body = None
        if fields is not None:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            body = urlencode(fields)
        with closing(self.client.connection()) as connection:
            connection.request(method, path, body, headers)
            with connection.getresponse() as response:
                payload = response.read()
                assert response.status == expected, (method, path, response.status, payload)
                return json.loads(payload), response.getheader("Set-Cookie")

    def node(self, method, path="", fields=None, expected=200):
        data, _ = self.request(method, "/api/nodes" + path, fields, expected=expected)
        assert AGENT_KEY not in json.dumps(data), "The response exposed an agent credential"
        return data


def test_internal_refusal(binary):
    with tempfile.TemporaryDirectory(prefix="apaz-node-guard-") as temporary:
        root = Path(temporary)
        port = choose_port()
        transport = PanelClient(port, tls=False)
        command = [str(binary.resolve()), "--port", str(port), "--data-dir", str(root),
                   "--auth-db", str(root / "auth.db")]
        with run_panel(command, root / "panel.log") as process:
            wait_for_server(process, transport)
            client = NodesClient(transport)
            for endpoint in ("http://127.0.0.1:9100", "http://127.1", "http://unit.localhost.",
                             "http://[::ffff:127.0.0.1]", "http://169.254.169.254"):
                client.node("POST", fields={"name": "Blocked", "endpoint": endpoint, "kind": "vpn",
                                           "transport": "http", "node_key": AGENT_KEY}, expected=400)


def test_roundtrips(binary, openssl):
    with tempfile.TemporaryDirectory(prefix="apaz-nodes-") as temporary, ExitStack() as stack:
        root = Path(temporary)
        data_dir = root / "data"
        data_dir.mkdir()
        tls_dir = data_dir / "node-tls"
        generate_certs(openssl, tls_dir)
        vpn_origin, vpn_agent = stack.enter_context(fake_agent())
        proxy_origin, proxy_agent = stack.enter_context(fake_agent())
        https_origin, _ = stack.enter_context(fake_agent(tls_dir))
        mtls_origin, _ = stack.enter_context(fake_agent(tls_dir, require_client=True))
        port = choose_port()
        transport = PanelClient(port, tls=False)
        command = [str(binary.resolve()), "--port", str(port), "--data-dir", str(data_dir),
                   "--auth-db", str(data_dir / "auth.db")]
        log = root / "panel.log"
        with run_panel(command, log) as process:
            wait_for_server(process, transport)
            anonymous, _ = transport.request("GET", "/api/nodes")
            assert anonymous in (401, 403)
            client = NodesClient(transport)
            assert client.node("GET", "/active")["active_node_id"] == 0
            initial = client.node("GET")
            assert [(n["id"], n["transport"]) for n in initial["nodes"]] == [(0, "local")]
            assert client.request("POST", "/api/settings/features", {"key": "proxy_nodes", "enabled": "true"})[0]
            vpn = {"name": "Тестовый VPN", "endpoint": vpn_origin, "kind": "vpn",
                   "transport": "http", "node_key": AGENT_KEY}
            proxy = {**vpn, "name": "Тестовый прокси", "endpoint": proxy_origin, "kind": "proxy"}
            vpn_id = client.node("POST", fields=vpn, expected=201)["id"]
            proxy_id = client.node("POST", fields={**proxy, "linked_vpn_node_id": vpn_id}, expected=201)["id"]
            vpn_path = f"/{vpn_id}"
            proxy_path = f"/{proxy_id}"
            client.node("POST", fields={**vpn, "name": "Duplicate"}, expected=409)
            client.node("PUT", vpn_path, {**vpn, "node_key": "", "endpoint": vpn_origin + "/"})
            client.node("PUT", vpn_path, {**vpn, "node_key": "", "endpoint": proxy_origin}, expected=400)
            client.node("POST", fields={**vpn, "name": "With userinfo", "endpoint": "http://a@localhost"}, expected=400)
            active = client.node("POST", vpn_path + "/activate", {"revision": initial["revision"]})
            assert active["active_node_id"] == vpn_id
            client.node("POST", "/0/activate", {"revision": initial["revision"]}, expected=409)
            client.node("POST", proxy_path + "/activate", {"revision": active["revision"]}, expected=400)
            assert client.node("POST", vpn_path + "/health")["state"] == "available"
            saved = client.node("GET", vpn_path)
            assert saved["health"] == "available" and saved["agent_version"] == "1.18.0"
            assert saved["antizapret_version"] == "1.14.0" and int(saved["health_checked_at"]) > 0
            vpn_agent.redirect_health = proxy_origin + "/health"
            assert client.node("POST", vpn_path + "/health")["state"] == "unexpected_response"
            vpn_agent.redirect_health = None
            client.node("PUT", vpn_path, {**vpn, "node_key": "different-key"})
            assert client.node("POST", vpn_path + "/health")["state"] == "auth_failed"
            client.node("PUT", vpn_path, vpn)
            assert client.node("GET", proxy_path + "/proxy/status")["data"]["destination_ip"] == "192.0.2.10"
            proxy_destination = proxy_path + "/proxy/destination"
            client.node("PUT", proxy_destination, {"destination_ip": "127.0.0.1"}, expected=400)
            assert client.node("PUT", proxy_destination, {"destination_ip": "198.51.100.3"})["state"] == "available"
            mappings = proxy_path + "/proxy/mappings"
            assert client.node("GET", mappings)["data"]["mappings"][0]["dest_ip"] == "198.51.100.3"
            proxy_agent.large_mappings = True
            assert client.node("GET", mappings)["state"] == "response_too_large"

            https = {**vpn, "name": "TLS", "endpoint": https_origin, "transport": "https"}
            https_id = client.node("POST", fields=https, expected=201)["id"]
            https_path = f"/{https_id}"
            assert client.node("POST", https_path + "/health")["state"] == "tls_failed"
            client.node("PUT", https_path, {**https, "ca_file": "ca.pem", "node_key": ""})
            assert client.node("POST", https_path + "/health")["state"] == "available"
            mtls = {**vpn, "name": "mTLS", "endpoint": mtls_origin, "transport": "mtls",
                    "ca_file": "ca.pem", "client_cert": "client.pem", "client_key": "client.key"}
            mtls_id = client.node("POST", fields=mtls, expected=201)["id"]
            assert client.node("POST", f"/{mtls_id}/health")["state"] == "available"
            client.node("PUT", f"/{mtls_id}", {**mtls, "client_cert": "../client.pem"}, expected=400)
        assert AGENT_KEY.encode() not in (data_dir / "nodes.db").read_bytes()
        with run_panel(command, log) as process:
            wait_for_server(process, transport)
            client = NodesClient(transport)
            assert client.node("GET", "/active")["active_node_id"] == vpn_id
            assert client.node("POST", vpn_path + "/health")["state"] == "available"
            client.node("DELETE", vpn_path)
            assert client.node("GET", "/active")["active_node_id"] == 0
            assert client.node("GET", proxy_path)["linked_vpn_node_id"] is None
            client.node("GET", vpn_path, expected=404)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--openssl", default="openssl")
    args = parser.parse_args()
    os.environ.pop("APAZ_ALLOW_INTERNAL_NODES", None)
    test_internal_refusal(args.binary)
    os.environ["APAZ_ALLOW_INTERNAL_NODES"] = "true"
    test_roundtrips(args.binary, args.openssl)
    print("Nodes tests passed: inventory, activation, HTTP, HTTPS, mTLS, and proxy compatibility")
