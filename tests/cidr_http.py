#!/usr/bin/env python3
"""Check CIDR authorization, compilation, integrity and revision rollback."""

import argparse
from contextlib import closing
import http.client
from ipaddress import collapse_addresses, ip_network
from pathlib import Path
import tempfile
import time
from urllib.parse import urlencode

from smoke import AUTH, HOST, TOKEN, PanelClient, choose_port, json_object, run_panel


def login(client, prefix):
    with closing(client.connection()) as connection:
        connection.request("POST", prefix + "/api/auth/login", urlencode({"username": "admin", "password": TOKEN}),
                           {"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"})
        with connection.getresponse() as response:
            assert response.status == 200, (response.status, response.read())
            return {"Cookie": response.getheader("Set-Cookie").split(";", 1)[0]}


def check_routes(client, prefix):
    routing = prefix + "/api/cidr/"
    assert client.request("GET", routing + "status")[0] == 401
    assert client.request("GET", routing + "status", headers=AUTH)[0] == 401
    cookie = login(client, prefix)
    text = {**cookie, "Content-Type": "text/plain"}

    def call(action, *, method="GET", body=None, headers=cookie, expected=200):
        status, response = client.request(method, routing + action, body=body, headers=headers)
        assert status == expected, (action, status, response)
        return response if action.startswith("export") else json_object(response, action)

    def upload(source, rows, **options):
        return call("import?" + urlencode({"source": source}), method="POST", body=rows, headers=text, **options)

    def publish(query="", **options):
        return call("publish" + query, method="POST", **options)

    assert call("status")["sources"] == []
    source = "custom-ips.txt"
    packed = ["192.0.2.0/25", "192.0.2.128/25", "192.0.2.10/32", "198.51.100.0/24", "203.0.113.15/32"]
    expected = [str(block) for block in collapse_addresses([ip_network(cidr) for cidr in packed])]
    payload = "\n".join(["# fixture", *packed, packed[0], "2001:db8::/32", "0.0.0.0/0"]).encode()
    assert call("import?source=blocked", method="POST", body=payload,
                headers={**text, "Origin": "https://example.invalid"}, expected=403)["error"]
    result = upload(source, payload)
    assert result["published"] == len(packed) and result["policy_skipped"] == 2
    assert upload(source, b"198.51.100.0/24\nmalformed", expected=422)["error_line"] == 2
    style = call("preview?budget=2", method="POST")
    assert style["over_budget"] and style["routes"] == len(expected)
    assert publish("?budget=2", expected=409)["state"] == "over_budget"
    assert call("status")["revision"] == 0
    first = publish()["revision"]
    assert first > 0
    assert call("export?source=custom-ips.txt").decode().splitlines() == expected
    assert publish()["revision"] == first
    assert call("status")["previous_revision"] == 0

    upload("secondary-ips.txt", b"203.0.113.255/32\n")
    subset = publish("?source=secondary-ips.txt")
    assert subset["retained_routes"] == len(expected) and subset["total_routes"] == len(expected) + 1
    all_before = call("export").decode().splitlines()
    assert all_before == [*expected, "203.0.113.255/32"]
    assert call("status")["previous_revision"] == first
    assert call("rollback", method="POST")["revision"] == first
    assert call("export").decode().splitlines() == expected
    assert call("rollback", method="POST", expected=404)["error"] == "no_previous_revision"

    trim_query = "?budget=2&format=trim"
    preview = call("preview" + trim_query, method="POST")
    assert preview["trimmed"] and not preview["over_budget"]
    assert preview["original_routes"] == 4 and preview["routes"] == 2
    assert [item["routes"] for item in preview["sources"]] == [2, 0]
    assert publish(trim_query)["sources"] == preview["sources"]
    assert call("export").decode().splitlines() == expected[:2]
    assert call("rollback", method="POST")["revision"] == first

    upload(source, b"192.0.2.5/32\n198.51.100.0/25\n203.0.113.0/24\n")
    assert publish(trim_query)["routes"] == 2
    assert call("export").decode().splitlines() == ["198.51.100.0/25", "203.0.113.0/24"]
    assert call("rollback", method="POST")["revision"] == first
    bundle = client.request("GET", prefix + "/assets/cidr.js")[1]
    assert b"window.apazModules.cidr" in bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=Path)
    parser.add_argument("--tls-cert", type=Path)
    parser.add_argument("--tls-key", type=Path)
    options = parser.parse_args()
    if bool(options.tls_cert) != bool(options.tls_key):
        parser.error("supply both TLS options")
    port = choose_port()
    prefix = "/test-panel"
    with tempfile.TemporaryDirectory(prefix="apaz-cidr-") as temporary:
        root = Path(temporary)
        command = [str(options.binary.resolve()), "--bind", HOST, "--port", str(port), "--data-dir", str(root),
                   "--auth-db", str(root / "auth.db"), "--access-path", prefix]
        if options.tls_cert:
            command.extend(["--tls-cert", str(options.tls_cert.resolve()), "--tls-key", str(options.tls_key.resolve())])
        client = PanelClient(port, tls=bool(options.tls_cert))
        log = root / "panel.log"
        try:
            with run_panel(command, log) as process:
                deadline = time.monotonic() + 10
                while True:
                    try:
                        assert client.request("GET", prefix + "/api/health")[0] == 200
                        break
                    except (OSError, http.client.HTTPException):
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise
                        time.sleep(0.05)
                check_routes(client, prefix)
        except BaseException:
            print(log.read_text(encoding="utf-8", errors="replace"))
            raise


if __name__ == "__main__":
    main()
