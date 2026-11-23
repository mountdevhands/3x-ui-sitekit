#!/usr/bin/env python3
"""Small real-nginx panel-routing/ACL acceptance fixture, on loopback only.

No services are installed, no ACME/network download is performed, and no VDS is
touched. The local TLS certificate is explicitly trusted by the client. Backend
HTTP/WebSocket receipts prove routing and header behavior; they do not simulate
3x-ui authentication or a full VLESS connection.

Usage:
  python3 tests/integration_panel_access.py --nginx /absolute/path/to/nginx
  Add --module dist/https-node.py to exercise the standalone renderer.
  Add --report /outside/project/panel-integration.json to retain a report.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import http.client
import http.server
import importlib.util
import json
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from typing import Optional
from unittest import mock


sys.dont_write_bytecode = True
PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
DOMAIN = "node.example.test"
PANEL_PATH = "/6b38e0c216a54c77be94b08db6cb600a/"
TRANSPORT_PATH = "/api/81e25848e02c41b99ac4b0025a354447/"


def load_installer(path: Optional[Path]):
    if path is None:
        import installer_core
        return installer_core
    spec = importlib.util.spec_from_file_location("sitekit_panel_fixture_module", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load the supplied standalone module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def unused_ports(count: int) -> list[int]:
    with contextlib.ExitStack() as stack:
        held = [stack.enter_context(socket.socket()) for _ in range(count)]
        for listener in held:
            listener.bind(("127.0.0.1", 0))
        return [listener.getsockname()[1] for listener in held]


class Backend(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, label: str):
        self.label = label
        self.receipts = []
        super().__init__(("127.0.0.1", 0), BackendHandler)


class BackendHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args):
        pass

    def do_POST(self):
        self.do_GET()

    def do_GET(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else b""
        self.server.receipts.append({
            "method": self.command,
            "path": self.path,
            "headers": {key.lower(): value for key, value in self.headers.items()},
            "body": body.decode("utf-8"),
        })
        if self.headers.get("Upgrade", "").lower() == "websocket":
            key = self.headers.get("Sec-WebSocket-Key", "")
            accept = base64.b64encode(hashlib.sha1(
                (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
            ).digest()).decode("ascii")
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            if self.headers.get("X-Fixture-Hold") == "1":
                self.connection.settimeout(15)
                with contextlib.suppress(OSError):
                    self.rfile.read(1)
            self.close_connection = True
            return
        if self.server.label == "panel" and self.path == PANEL_PATH[:-1]:
            self.send_response(308)
            self.send_header("Location", PANEL_PATH)
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        payload = json.dumps({"backend": self.server.label, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(payload)
        self.close_connection = True


class PanelRoutingFixture:
    def __init__(self, root: Path, nginx: Path, installer):
        self.root, self.nginx, self.installer = root, nginx, installer
        self.checks = []
        self.http_port, self.https_port = unused_ports(2)
        self.panel = Backend("panel")
        self.transport = Backend("transport")
        self.threads = []
        self.started_backends = []
        self.process = None
        self.process_log = None
        self.config_path = root / "nginx.conf"
        for folder in ("runtime", "logs", "cache", "site"):
            (root / folder).mkdir()
        (root / "site/index.html").write_text("public-site-fixture\n", encoding="utf-8")
        (root / "site/404.html").write_text("not-found-fixture\n", encoding="utf-8")
        self.cert, self.key = root / "fixture.crt", root / "fixture.key"

    def start(self):
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(self.key), "-out", str(self.cert), "-days", "1",
            "-subj", "/CN=" + DOMAIN, "-addext", "subjectAltName=DNS:" + DOMAIN,
        ], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, check=True, timeout=15)
        self.context = ssl.create_default_context(cafile=str(self.cert))
        for backend in (self.panel, self.transport):
            thread = threading.Thread(target=backend.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
            thread.start()
            self.threads.append(thread)
            self.started_backends.append(backend)

    def close_nginx(self):
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGQUIT)
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=3)
        self.process = None
        if self.process_log:
            self.process_log.close()
            self.process_log = None

    def close(self):
        self.close_nginx()
        for backend in (self.panel, self.transport):
            if backend in self.started_backends:
                backend.shutdown()
            backend.server_close()
        for thread in self.threads:
            thread.join(timeout=2)

    def configuration(self, mode: str, allow: list[str]):
        return self.installer.render_nginx(
            DOMAIN, "127.0.0.1", "ws", self.transport.server_port,
            TRANSPORT_PATH, str(self.root / "site"), str(self.cert), str(self.key),
            http_port=self.http_port, https_port=self.https_port,
            runtime_root=str(self.root / "runtime"), log_root=str(self.root / "logs"),
            cache_root=str(self.root / "cache"), worker_user=None,
            panel_access=mode, panel_allow=allow, panel_path=PANEL_PATH,
            panel_port=self.panel.server_port,
        ).replace("worker_processes auto;", "worker_processes 1;")

    def configure(self, mode: str, allow: list[str]):
        self.close_nginx()
        config = self.configuration(mode, allow)
        self.config_path.write_text(config, encoding="utf-8")
        subprocess.run([str(self.nginx), "-t", "-c", str(self.config_path)],
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=5)
        self.process_log = (self.root / "process.log").open("ab")
        self.process = subprocess.Popen(
            [str(self.nginx), "-c", str(self.config_path), "-g", "daemon off;"],
            stdout=self.process_log, stderr=self.process_log,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise AssertionError("nginx stopped: " + (self.root / "process.log").read_text())
            try:
                with socket.create_connection(("127.0.0.1", self.https_port), timeout=0.2):
                    return
            except (ConnectionRefusedError, TimeoutError):
                time.sleep(0.025)
        raise AssertionError("nginx TLS listener did not become ready")

    def request(self, path: str, *, source="127.0.0.1", host=DOMAIN,
                headers=None, method="GET", body=b""):
        request_headers = {"Host": host, "Connection": "close", **(headers or {})}
        if body:
            request_headers["Content-Length"] = str(len(body))
        message = (f"{method} {path} HTTP/1.1\r\n" + "".join(
            f"{key}: {value}\r\n" for key, value in request_headers.items()
        ) + "\r\n").encode("ascii") + body
        with socket.create_connection(("127.0.0.1", self.https_port), timeout=3,
                                      source_address=(source, 0)) as raw:
            with self.context.wrap_socket(raw, server_hostname=DOMAIN) as secure:
                secure.sendall(message)
                response = http.client.HTTPResponse(secure)
                response.begin()
                payload = response.read(65537)
                if len(payload) > 65536:
                    raise AssertionError("Unexpectedly large fixture response")
                return response.status, dict(response.getheaders()), payload

    def check(self, name: str, condition: bool, **evidence):
        self.checks.append({"check": name, "result": "PASS" if condition else "FAIL", **evidence})
        if not condition:
            raise AssertionError(name + ": " + json.dumps(evidence, sort_keys=True))

    def rejected_sni(self, name):
        context = ssl.create_default_context(cafile=str(self.cert))
        context.check_hostname = False
        try:
            with socket.create_connection(("127.0.0.1", self.https_port), timeout=3) as raw:
                with context.wrap_socket(raw, server_hostname=name):
                    pass
        except (ssl.SSLError, ConnectionResetError):
            return True
        return False

    def graceful_reload_with_open_websocket(self):
        """Exercise the actual /proc ACK while an old worker drains a live WS."""
        master_pid = self.process.pid
        with contextlib.ExitStack() as stack:
            raw = stack.enter_context(socket.create_connection(("127.0.0.1", self.https_port), timeout=3))
            secure = stack.enter_context(self.context.wrap_socket(raw, server_hostname=DOMAIN))
            secure.sendall((
                f"GET {PANEL_PATH}held-socket HTTP/1.1\r\nHost: {DOMAIN}\r\n"
                "Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nX-Fixture-Hold: 1\r\n\r\n"
            ).encode("ascii"))
            response = http.client.HTTPResponse(secure)
            stack.callback(response.close)
            response.begin()
            self.check("reload_fixture_has_live_old_websocket", response.status == 101, status=response.status)
            original_workers = set()
            for process_dir in Path("/proc").iterdir():
                if not process_dir.name.isdigit():
                    continue
                try:
                    fields = (process_dir / "stat").read_text().rsplit(")", 1)[1].split()
                    if int(fields[1]) == master_pid and (process_dir / "cmdline").read_bytes().startswith(b"nginx: worker process"):
                        original_workers.add(int(process_dir.name))
                except (FileNotFoundError, ProcessLookupError):
                    continue
            if not original_workers:
                raise AssertionError("No old nginx worker found for the reload fixture")
            self.config_path.write_text(self.configuration("ssh", []), encoding="utf-8")
            reload_calls = []

            def signal_reload(argv, **_kwargs):
                if argv != ["systemctl", "reload", self.installer.NGINX_SERVICE]:
                    raise AssertionError("Unexpected command inside reload helper: " + repr(argv))
                reload_calls.append(argv)
                self.process.send_signal(signal.SIGHUP)
                return subprocess.CompletedProcess(argv, 0, "", "")

            started = time.monotonic()
            with mock.patch.object(self.installer, "managed_nginx_pid", return_value=master_pid), \
                    mock.patch.object(self.installer, "command", side_effect=signal_reload):
                self.installer.reload_managed_nginx(seconds=3)
            elapsed = time.monotonic() - started
            draining = []
            for pid in original_workers:
                path = Path(f"/proc/{pid}/cmdline")
                if path.exists() and b"worker process is shutting down" in path.read_bytes():
                    draining.append(pid)
            self.check("reload_ack_completes_while_old_websocket_worker_drains", bool(draining)
                       and len(reload_calls) == 1 and elapsed < 3, elapsed_seconds=round(elapsed, 3))
            status, _, _ = self.request(PANEL_PATH)
            self.check("new_connection_observes_ssh_mode_after_reload_ack", status == 404, status=status)
            # The fixture backend waits for this byte. Closing the established
            # stream also lets the old nginx worker finish its graceful drain.
            secure.sendall(b"x")
            response.close()

    def run(self, *, reload_only=False):
        self.start()
        if reload_only:
            self.configure("https", ["127.0.0.1/32"])
            self.graceful_reload_with_open_websocket()
            return
        self.configure("ssh", [])
        start_receipts = len(self.panel.receipts)
        statuses = [self.request(path)[0] for path in (
            PANEL_PATH[:-1], PANEL_PATH, PANEL_PATH + "panel/api/inbounds/list",
        )]
        self.check("ssh_mode_has_no_public_panel", statuses == [404, 404, 404]
                   and len(self.panel.receipts) == start_receipts, statuses=statuses)

        self.configure("https", [])
        status, _, payload = self.request(PANEL_PATH, source="127.0.0.2")
        self.check("https_without_allowlist_accepts_other_source", status == 200
                   and json.loads(payload)["backend"] == "panel", status=status)

        self.configure("https", ["127.0.0.1/32"])
        for suffix in ("", "assets/app.js", "panel/api/inbounds/list?fixture=1"):
            target = PANEL_PATH + suffix
            status, _, payload = self.request(target)
            self.check("allowed_panel_" + (suffix or "ui"), status == 200
                       and json.loads(payload)["path"] == target, status=status)
        status, headers, _ = self.request(PANEL_PATH[:-1])
        self.check("allowed_bare_panel_reaches_backend_redirect", status == 308
                   and headers.get("Location") == PANEL_PATH, status=status)

        status, _, _ = self.request(PANEL_PATH + "login", method="POST",
                                    body=b"fixture=not-real-credentials",
                                    headers={"Content-Type": "application/x-www-form-urlencoded"})
        receipt = self.panel.receipts[-1]
        self.check("allowed_panel_post_preserves_method_body_and_path", status == 200
                   and receipt["method"] == "POST" and receipt["path"] == PANEL_PATH + "login"
                   and receipt["body"] == "fixture=not-real-credentials", status=status)
        self.check("panel_proxy_reports_tls_and_real_peer", receipt["headers"].get("x-forwarded-proto") == "https"
                   and receipt["headers"].get("x-forwarded-for") == "127.0.0.1"
                   and receipt["headers"].get("x-real-ip") == "127.0.0.1")

        websocket_headers = {"Connection": "Upgrade", "Upgrade": "websocket",
                             "Sec-WebSocket-Version": "13",
                             "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ=="}
        status, headers, _ = self.request(PANEL_PATH + "fixture-socket", headers=websocket_headers)
        self.check("panel_websocket_upgrade_passes", status == 101
                   and headers.get("Sec-WebSocket-Accept") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", status=status)

        count_before = len(self.panel.receipts)
        denied_paths = (PANEL_PATH[:-1], PANEL_PATH, PANEL_PATH + "panel/api/inbounds/list",
                        PANEL_PATH + "assets/app.js")
        statuses = [self.request(path, source="127.0.0.2")[0] for path in denied_paths]
        self.check("allowlist_denies_bare_nested_api_and_asset_paths", statuses == [403] * len(denied_paths)
                   and len(self.panel.receipts) == count_before, statuses=statuses)
        status, _, _ = self.request(PANEL_PATH + "panel/api/inbounds/list", source="127.0.0.2", headers={
            "X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1",
            "Forwarded": "for=127.0.0.1;proto=https", "X-Https-Node": "1",
        })
        self.check("forged_forwarding_headers_cannot_bypass_allowlist", status == 403
                   and len(self.panel.receipts) == count_before, status=status)

        status, _, payload = self.request("/", source="127.0.0.2")
        self.check("panel_allowlist_keeps_site_public", status == 200
                   and payload == b"public-site-fixture\n", status=status)
        status, _, _ = self.request(TRANSPORT_PATH, source="127.0.0.2", headers=websocket_headers)
        self.check("panel_allowlist_does_not_block_ws_transport_route", status == 101
                   and self.transport.receipts[-1]["path"] == TRANSPORT_PATH
                   and self.transport.receipts[-1]["headers"].get("x-forwarded-for") == "127.0.0.2", status=status)
        count_before = len(self.panel.receipts)
        status, _, _ = self.request(PANEL_PATH, host="unrelated.example.test")
        self.check("wrong_host_cannot_reach_panel", status == 404
                   and len(self.panel.receipts) == count_before, status=status)
        self.check("wrong_sni_is_rejected_during_tls", self.rejected_sni("unrelated.example.test"))
        self.check("missing_sni_is_rejected_during_tls", self.rejected_sni(None))
        status, _, _ = self.request(PANEL_PATH[:-1] + "-other/")
        self.check("panel_route_does_not_capture_adjacent_paths", status == 404, status=status)
        self.graceful_reload_with_open_websocket()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", type=Path, required=True)
    parser.add_argument("--module", type=Path)
    parser.add_argument("--report", type=Path)
    parser.add_argument("--reload-only", action="store_true", help="Only exercise the actual nginx worker-generation ACK.")
    args = parser.parse_args()
    nginx = args.nginx.resolve(strict=True)
    version = subprocess.run([str(nginx), "-V"], text=True, capture_output=True, check=True, timeout=5)
    report = {
        "scope": "Local nginx TLS routing/ACL with mock HTTP/WebSocket backends; no 3x-ui login, VLESS payload or VDS deployment",
        "nginx_binary_sha256": hashlib.sha256(nginx.read_bytes()).hexdigest(),
        "nginx_version": (version.stderr + version.stdout).splitlines()[0],
        "module": "standalone" if args.module else "src/installer_core.py + rendering.py",
        "reload_only": args.reload_only,
        "checks": [],
        "result": "FAIL",
    }
    if args.module:
        report["module_sha256"] = hashlib.sha256(args.module.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="sitekit-panel-fixture-") as directory:
        fixture = PanelRoutingFixture(Path(directory), nginx, load_installer(args.module))
        try:
            fixture.run(reload_only=args.reload_only)
            report["result"] = "PASS"
        except Exception as exc:
            report["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            report["checks"] = fixture.checks
            fixture.close()
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0 if report["result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
