#!/usr/bin/env python3
"""Bounded loopback integration tests for HTTPS Node's real transport chain.

Runs actual nginx TLS + Xray server/client binaries, one client at a time.
The test's synthetic HTTP destination is on loopback. Its Xray fixture therefore
intentionally permits private egress; this does not alter the production policy.
The temporary self-signed certificate is explicitly trusted, never allowInsecure.
Only worker_processes auto is changed to 1 in the rendered nginx fixture.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from typing import Any


PROJECT = Path(__file__).resolve().parents[1]
DOMAIN = "node.example.test"
TUNNEL_PATH = "/api/94b75e5e93884f6fb9788b92f80b546d/"
CLIENT_ID = "3561a16b-9499-4bac-a7a6-dd12c4b15e31"
PAYLOAD = hashlib.shake_256(b"HTTPS Node local integration fixture v1").digest(2 * 1024 * 1024)
PAYLOAD_HASH = hashlib.sha256(PAYLOAD).hexdigest()


def free_ports(count: int) -> list[int]:
    sockets: list[socket.socket] = []
    try:
        for _ in range(count):
            item = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            item.bind(("127.0.0.1", 0))
            sockets.append(item)
        return [item.getsockname()[1] for item in sockets]
    finally:
        for item in sockets:
            item.close()


def wait_port(port: int, process: subprocess.Popen | None = None, timeout: float = 10) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise AssertionError(f"Process exited before listener became ready: rc={process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.25):
                return
        except OSError:
            time.sleep(.05)
    raise AssertionError(f"Loopback port {port} did not become ready")


class FixtureHTTP(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    receipts: list[dict[str, Any]] = []

    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:
        if self.path != "/download":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()
        self.wfile.write(PAYLOAD)
        self.receipts.append({"method": "GET", "bytes": len(PAYLOAD), "sha256": PAYLOAD_HASH})

    def do_POST(self) -> None:
        if self.path != "/upload":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", "-1"))
        if length != len(PAYLOAD):
            self.send_error(400, "Unexpected fixture body size")
            return
        self.connection.settimeout(20)
        body = self.rfile.read(length)
        receipt = {"method": "POST", "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
        self.receipts.append(receipt)
        response = json.dumps(receipt).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


class Harness:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.start = time.monotonic()
        self.results: list[dict[str, Any]] = []
        self.commands: list[str] = []
        self.environment = dict(os.environ)
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            self.environment.pop(name, None)
        self.environment["XRAY_LOCATION_ASSET"] = str(args.xray.parent)
        args.results.mkdir(parents=True, exist_ok=True)
        self.work = Path(tempfile.mkdtemp(prefix="transport-", dir=args.results)).resolve()
        self.payload_file = self.work / "payload.bin"
        self.payload_file.write_bytes(PAYLOAD)
        self.cert = self.work / "cert.pem"
        self.key = self.work / "key.pem"
        spec = importlib.util.spec_from_file_location("https_node_test_subject", args.module)
        assert spec is not None and spec.loader is not None
        self.module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.module
        spec.loader.exec_module(self.module)

    def run(self, command: list[str], *, timeout: float = 20, check: bool = True) -> subprocess.CompletedProcess:
        self.commands.append(shlex.join(command))
        result = subprocess.run(command, cwd=self.work, env=self.environment, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
        if check and result.returncode:
            raise AssertionError(f"Command failed rc={result.returncode}: {shlex.join(command)}\n{result.stdout}\n{result.stderr}")
        return result

    @contextlib.contextmanager
    def process(self, name: str, command: list[str]):
        self.commands.append(shlex.join(command))
        with (self.work / (name + ".log")).open("w") as log:
            process = subprocess.Popen(command, cwd=self.work, env=self.environment,
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                yield process
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=3)

    def record(self, name: str, **facts: Any) -> None:
        item = {"name": name, "status": "PASS", **facts}
        self.results.append(item)
        print(json.dumps(item), flush=True)

    def cert_setup(self) -> None:
        self.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                  "-subj", f"/CN={DOMAIN}", "-addext", f"subjectAltName=DNS:{DOMAIN}",
                  "-keyout", str(self.key), "-out", str(self.cert)])
        self.key.chmod(0o600)

    def nginx_config(self, transport: str, backend_port: int, http_port: int, tls_port: int) -> Path:
        folder = self.work / transport
        folder.mkdir()
        site = folder / "site"
        site.mkdir()
        profile = self.module.generate_site_profile(
            "94b75e5e93884f6fb9788b92f80b546d" * 2, "journal", "Transport fixture",
            "Local verification of HTTPS Node.")
        self.site_files = self.module.render_generated_site(DOMAIN, profile)
        for name, text in self.site_files.items():
            (site / name).parent.mkdir(parents=True, exist_ok=True)
            (site / name).write_text(text)
        acme = site / ".well-known" / "acme-challenge"
        acme.mkdir(parents=True)
        (acme / "fixture-token").write_text("fixture-acme-proof")
        for name in ("runtime", "logs", "cache"):
            (folder / name).mkdir()
        text = self.module.render_nginx(
            domain=DOMAIN, bind_ip="127.0.0.1", transport=transport,
            inbound_port=backend_port, path=TUNNEL_PATH, site_root=str(site),
            cert_path=str(self.cert), key_path=str(self.key), http_port=http_port,
            https_port=tls_port, runtime_root=str(folder / "runtime"),
            log_root=str(folder / "logs"), cache_root=str(folder / "cache"), worker_user=None)
        text = text.replace("worker_processes auto;", "worker_processes 1;")
        config = folder / "nginx.conf"
        config.write_text(text)
        self.run([str(self.args.nginx), "-t", "-p", str(folder) + "/", "-c", str(config)])
        return config

    def server_config(self, transport: str, backend_port: int) -> Path:
        transport_settings = {"path": TUNNEL_PATH, "host": DOMAIN}
        if transport == "xhttp":
            transport_settings["mode"] = "auto"
        body = {
            "log": {"loglevel": "debug"},
            "inbounds": [{"listen": "127.0.0.1", "port": backend_port, "protocol": "vless",
                          "settings": {"clients": [{"id": CLIENT_ID}], "decryption": "none"},
                          "streamSettings": {"network": transport, "security": "none",
                                             transport + "Settings": transport_settings,
                                             "sockopt": {"trustedXForwardedFor": ["X-Https-Node"]}}}],
            # TEST ONLY: the synthetic target is on loopback; production blocks private egress.
            "outbounds": [{"protocol": "freedom", "tag": "test-local-only",
                           "settings": {"finalRules": [{"action": "allow"}]}}]
        }
        path = self.work / f"server-{transport}.json"
        path.write_text(json.dumps(body, indent=2))
        self.run([str(self.args.xray), "run", "-test", "-config", str(path)])
        return path

    def client_config(self, transport: str, mode: str, tls_port: int, proxy_port: int) -> Path:
        transport_settings = {"path": TUNNEL_PATH, "host": DOMAIN}
        if transport == "xhttp":
            transport_settings["mode"] = mode
        body = {
            "log": {"loglevel": "debug"},
            "inbounds": [{"listen": "127.0.0.1", "port": proxy_port, "protocol": "socks",
                          "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [{"protocol": "vless", "settings": {
                "vnext": [{"address": "127.0.0.1", "port": tls_port,
                           "users": [{"id": CLIENT_ID, "encryption": "none"}]}]},
                "streamSettings": {"network": transport, "security": "tls",
                                   transport + "Settings": transport_settings,
                                   "tlsSettings": {"serverName": DOMAIN, "fingerprint": "chrome",
                                                   "certificates": [{"certificateFile": str(self.cert), "usage": "verify"}]}}}]
        }
        assert "allowInsecure" not in json.dumps(body)
        path = self.work / f"client-{transport}-{mode}.json"
        path.write_text(json.dumps(body, indent=2))
        self.run([str(self.args.xray), "run", "-test", "-config", str(path)])
        return path

    def raw_request(self, port: int, path: str, *, host: str | None = DOMAIN,
                    sni: str | None = DOMAIN, tls: bool = True) -> tuple[int, dict[str, str], bytes]:
        context = ssl.create_default_context(cafile=str(self.cert))
        context.check_hostname = sni == DOMAIN
        raw = socket.create_connection(("127.0.0.1", port), timeout=5)
        connection = context.wrap_socket(raw, server_hostname=sni) if tls else raw
        try:
            headers = [f"GET {path} HTTP/1.1" if host is not None else f"GET {path} HTTP/1.0"]
            if host is not None:
                headers.append(f"Host: {host}")
            headers.append("Connection: close")
            connection.sendall(("\r\n".join(headers) + "\r\n\r\n").encode())
            response = bytearray()
            while True:
                part = connection.recv(65536)
                if not part:
                    break
                response.extend(part)
                if len(response) > 1024 * 1024:
                    raise AssertionError("Unexpectedly large control response")
            raw_headers, body = bytes(response).split(b"\r\n\r\n", 1)
            lines = raw_headers.decode("iso-8859-1").split("\r\n")
            status = int(lines[0].split()[1])
            parsed = {k.lower(): v.strip() for k, v in (line.split(":", 1) for line in lines[1:] if ":" in line)}
            return status, parsed, body
        finally:
            connection.close()

    def control_checks(self, transport: str, http_port: int, tls_port: int) -> None:
        status, headers, body = self.raw_request(tls_port, "/")
        assert status == 200 and b"Transport fixture" in body
        assert headers.get("server") == "nginx", headers
        self.record(f"{transport}: valid SNI/certificate/site", http=status, certificate_verification=True)
        for name, expected in self.site_files.items():
            if name == "404.html":
                continue  # Deliberately internal in the production nginx configuration.
            status, headers, body = self.raw_request(tls_port, "/" + name)
            assert status == 200 and body == expected.encode("utf-8"), (name, status)
            if name.endswith(".svg"):
                assert headers["content-type"].startswith("image/svg+xml"), headers
            if name.endswith(".css"):
                assert headers["content-type"].startswith("text/css"), headers
        status, _, body = self.raw_request(tls_port, "/missing-generated-page")
        assert status == 404 and body == self.site_files["404.html"].encode("utf-8")
        self.record(f"{transport}: generated site pages/assets/404", files=len(self.site_files), exact_bytes=True)
        for wrong_sni in (None, "unknown.example.test"):
            try:
                self.raw_request(tls_port, "/", sni=wrong_sni)
            except ssl.SSLError as error:
                assert "UNRECOGNIZED_NAME" in str(error).upper() or "HANDSHAKE_FAILURE" in str(error).upper(), str(error)
                self.record(f"{transport}: reject {'no' if wrong_sni is None else 'wrong'} SNI", error=str(error))
            else:
                raise AssertionError(f"TLS handshake accepted unexpected SNI {wrong_sni!r}")
        for wrong_host in (None, "unknown.example.test"):
            status, _, _ = self.raw_request(tls_port, "/", host=wrong_host)
            assert status == 404, status
            self.record(f"{transport}: reject {'missing' if wrong_host is None else 'wrong'} Host", http=status)
        for path in ("/panel/api/inbounds/list", "/a93e7b5a9c9143ddb710bd46ac28f834/", "/.env", "/site-profile.json"):
            status, _, _ = self.raw_request(tls_port, path)
            assert status == 404, (path, status)
            self.record(f"{transport}: no public panel/file {path}", http=status)
        status, headers, _ = self.raw_request(http_port, "/", tls=False)
        assert status == 301 and headers.get("location") == f"https://{DOMAIN}:{tls_port}/"
        self.record(f"{transport}: HTTP redirect", http=status)
        status, _, body = self.raw_request(http_port, "/.well-known/acme-challenge/fixture-token", tls=False)
        assert status == 200 and body == b"fixture-acme-proof"
        self.record(f"{transport}: ACME webroot", http=status)
        status, _, _ = self.raw_request(http_port, "/", host="unknown.example.test", tls=False)
        assert status == 404
        self.record(f"{transport}: HTTP unknown host", http=status)

    def transfer_checks(self, transport: str, mode: str, proxy_port: int, target_port: int) -> None:
        stem = f"{transport}-{mode}"
        download = self.work / (stem + "-download.bin")
        common = ["curl", "--silent", "--show-error", "--fail", "--max-time", "30",
                  "--proxy", f"socks5h://127.0.0.1:{proxy_port}", "--noproxy", ""]
        self.run(common + [f"http://127.0.0.1:{target_port}/download", "-o", str(download)], timeout=35)
        received = download.read_bytes()
        digest = hashlib.sha256(received).hexdigest()
        assert len(received) == len(PAYLOAD) and digest == PAYLOAD_HASH
        self.record(f"{stem}: GET 2 MiB through nginx + Xray", bytes=len(received), sha256=digest)
        uploaded = self.run(common + [f"http://127.0.0.1:{target_port}/upload",
                                     "--data-binary", "@" + str(self.payload_file)], timeout=35)
        receipt = json.loads(uploaded.stdout)
        assert receipt["bytes"] == len(PAYLOAD) and receipt["sha256"] == PAYLOAD_HASH, receipt
        self.record(f"{stem}: POST 2 MiB through nginx + Xray", **receipt)

    def test_transport(self, transport: str, target_port: int) -> None:
        backend_port, http_port, tls_port, proxy_port = free_ports(4)
        config = self.nginx_config(transport, backend_port, http_port, tls_port)
        server_config = self.server_config(transport, backend_port)
        with self.process("server-" + transport, [str(self.args.xray), "run", "-config", str(server_config)]) as server:
            wait_port(backend_port, server)
            with self.process("nginx-" + transport, [str(self.args.nginx), "-p", str(config.parent) + "/",
                                                     "-c", str(config), "-g", "daemon off;"]) as nginx:
                wait_port(tls_port, nginx)
                self.control_checks(transport, http_port, tls_port)
                for mode in (["auto", "stream-up"] if transport == "xhttp" else ["websocket"]):
                    client_config = self.client_config(transport, mode, tls_port, proxy_port)
                    with self.process(f"client-{transport}-{mode}", [str(self.args.xray), "run", "-config", str(client_config)]) as client:
                        wait_port(proxy_port, client)
                        self.transfer_checks(transport, mode, proxy_port, target_port)

    def report(self, error: str | None = None) -> None:
        data = {"module": str(self.args.module),
                "module_sha256": hashlib.sha256(self.args.module.read_bytes()).hexdigest(),
                "nginx": str(self.args.nginx), "xray": str(self.args.xray),
                "uid": os.getuid(), "loopback_only": True, "parallel_clients": 1,
                "payload_bytes": len(PAYLOAD), "payload_sha256": PAYLOAD_HASH,
                "elapsed_seconds": round(time.monotonic() - self.start, 3),
                "fixture_directory": str(self.work), "results": self.results, "error": error,
                "commands": self.commands}
        (self.work / "result.json").write_text(json.dumps(data, indent=2))
        lines = ["HTTPS Node bounded transport integration", "", f"Outcome: {'FAIL' if error else 'PASS'}",
                 f"Test subject: {self.args.module}", f"UID: {os.getuid()}; all traffic is loopback",
                 f"Subject SHA256: {data['module_sha256']}",
                 "Certificate: temporary self-signed cert explicitly trusted by Python controls and Xray; no allowInsecure",
                 "Transfers: curl through a loopback SOCKS5 client; TLS verification occurs in Xray",
                 "Fixture-only changes: nginx worker_processes=1; Xray freedom permits the synthetic loopback HTTP target",
                 "Production private-egress policy is not modified or evaluated by this transport fixture.",
                 f"Payload: {len(PAYLOAD)} bytes; SHA256 {PAYLOAD_HASH}",
                 f"Elapsed: {data['elapsed_seconds']} s", f"Logs/results: {self.work}", "", "RESULTS"]
        lines.extend(json.dumps(item) for item in self.results)
        if error:
            lines.extend(["", "ERROR", error])
        lines.extend(["", "EXACT COMMANDS", *self.commands, "", "SYNTHETIC HTTP RECEIPTS",
                      json.dumps(FixtureHTTP.receipts, indent=2), ""])
        self.args.report.write_text("\n".join(lines))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=Path, default=PROJECT / "src/rendering.py")
    parser.add_argument("--nginx", type=Path, default=PROJECT / "tools/nginx/usr/sbin/nginx")
    parser.add_argument("--xray", type=Path, default=PROJECT / "upstream/release/x-ui/bin/xray-linux-amd64")
    parser.add_argument("--results", type=Path, default=PROJECT / "tests/integration-results")
    parser.add_argument("--report", type=Path, default=PROJECT / "tests/INTEGRATION.txt")
    args = parser.parse_args()
    for name in ("module", "nginx", "xray", "results", "report"):
        setattr(args, name, getattr(args, name).resolve())
    harness = Harness(args)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FixtureHTTP)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    error = None
    try:
        harness.cert_setup()
        harness.test_transport("xhttp", server.server_address[1])
        harness.test_transport("ws", server.server_address[1])
    except Exception:
        error = traceback.format_exc()
        print(error, file=sys.stderr)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
        harness.report(error)
    print(f"Report: {args.report}", flush=True)
    return 1 if error else 0


if __name__ == "__main__":
    raise SystemExit(main())
