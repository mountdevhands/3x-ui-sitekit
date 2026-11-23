#!/usr/bin/env python3
"""Exercise the installer's real bootstrap_panel() using pinned panel/Xray binaries.

All paths are relocated into one private scratch directory. Only systemctl start
is replaced by a managed non-root subprocess; CLI, SQLite, API, ss and Xray
commands are real. This does not test root ownership, apt, or systemd sandboxing.
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
import pwd
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse


PROJECT = Path(__file__).resolve().parents[1]


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_port(port: int, process: subprocess.Popen) -> None:
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise AssertionError("Fixture process exited before opening its port")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return
        except OSError:
            time.sleep(.05)
    raise AssertionError("Fixture port did not become ready")


def stop(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    os.killpg(process.pid, signal.SIGTERM)
    try:
        process.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        process.wait(timeout=3)


class PrivateDestination(http.server.BaseHTTPRequestHandler):
    requests = 0

    def do_GET(self) -> None:
        type(self).requests += 1
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"PRIVATE TARGET MUST NOT BE REACHED")

    def log_message(self, *_args) -> None:
        pass


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=Path, default=PROJECT / "src/installer_core.py")
    parser.add_argument("--release", type=Path, default=PROJECT / "upstream/release/x-ui")
    parser.add_argument("--results", type=Path, default=PROJECT / "tests/bootstrap-results")
    parser.add_argument("--report", type=Path, default=PROJECT / "tests/BOOTSTRAP.txt")
    args = parser.parse_args()
    args.module = args.module.resolve()
    args.release = args.release.resolve()
    args.results.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="bootstrap-", dir=args.results)).resolve()
    work.chmod(0o700)
    started = time.monotonic()
    results = []
    command_records = []
    panel = None
    client = None
    panel_log = None
    client_log = None
    private_server = None
    private_thread = None
    error = None
    module = None
    real_getpwnam = pwd.getpwnam
    process_account = pwd.getpwuid(os.getuid())
    state = {}

    def record(name, **facts):
        item = {"name": name, "status": "PASS", **facts}
        results.append(item)
        print(json.dumps(item), flush=True)

    def deadline(_signum, _frame):
        raise TimeoutError("The bootstrap integration test exceeded its 60-second deadline")

    old_alarm = signal.signal(signal.SIGALRM, deadline)
    signal.alarm(60)
    try:
        sys.path.insert(0, str(args.module.parent))
        spec = importlib.util.spec_from_file_location("https_node_bootstrap_subject", args.module)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        for name, suffix in {"ETC": "etc", "OPT": "opt", "DATA": "data", "LOG": "log",
                             "SITE": "site", "CACHE": "cache", "UNIT_DIR": "units"}.items():
            path = work / suffix
            path.mkdir(mode=0o700)
            setattr(module, name, path)
        module.STATE_FILE = module.ETC / "state.json"
        module.ACCESS = work / "access.txt"
        module.HOOK = work / "hook"
        for path in (module.DATA / "panel", module.DATA / "xray", module.LOG / "panel"):
            path.mkdir(mode=0o700)
        shutil.copy2(args.release / "x-ui", module.OPT / "x-ui")
        for name in ("xray-linux-amd64", "geoip.dat", "geosite.dat"):
            shutil.copy2(args.release / "bin" / name, module.DATA / "xray" / name)
        pwd.getpwnam = lambda name: process_account if name == module.USER else real_getpwnam(name)
        real_command = module.command

        def command(argv, **kwargs):
            nonlocal panel, panel_log
            parts = [str(item) for item in argv]
            if parts == ["systemctl", "start", module.PANEL_SERVICE]:
                assert panel is None
                panel_log = (work / "panel.log").open("w")
                env = {**os.environ, **module.panel_env()}
                panel = subprocess.Popen([str(module.OPT / "x-ui")], cwd=work, env=env,
                                         stdout=panel_log, stderr=subprocess.STDOUT, start_new_session=True)
                command_records.append("systemctl start: replaced by managed unprivileged x-ui subprocess")
                return subprocess.CompletedProcess(parts, 0, "", "")
            assert not parts or parts[0] != "systemctl", "Unexpected systemctl command"
            if kwargs.get("secret"):
                command_records.append(Path(parts[0]).name + " setting [secret arguments/output suppressed]")
            else:
                command_records.append(" ".join(parts))
            return real_command(argv, **kwargs)

        module.command = command
        fixture_args = argparse.Namespace(transport="xhttp", email="fixture@example.test",
                                          site_title="Fixture", site_description="Local test")
        state = module.new_state({"domain": "node.example.test", "bind_ip": "127.0.0.1"}, fixture_args)
        # Keep new_state()'s actual API/metrics/inbound choices. Only the fixed panel
        # port is relocated if the shared test environment already occupies it.
        try:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", state["panel_port"]))
        except OSError:
            state["panel_port"] = free_port()
        module.bootstrap_panel(state)
        record("actual bootstrap_panel completed", uid=os.getuid(), panel_port=state["panel_port"],
               inbound_port=state["inbound_port"], api_port=state["api_port"], metrics_port=state["metrics_port"])

        db = sqlite3.connect(module.DATA / "panel/x-ui.db")
        try:
            users = db.execute("SELECT username, password FROM users").fetchall()
            assert len(users) == 1 and users[0][0] == state["username"]
            assert users[0][1].startswith(("$2a$", "$2b$", "$2y$")) and users[0][1] != state["password"]
            settings = dict(db.execute("SELECT key, value FROM settings"))
            assert settings["subEnable"] == settings["subJsonEnable"] == "false"
            assert settings["subListen"] == settings["webListen"] == "127.0.0.1"
            assert db.execute("SELECT COUNT(*) FROM inbounds").fetchone()[0] == 1
            assert db.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 1
        finally:
            db.close()
        record("real SQLite user/password/subscription/inbound/host checks")

        api = module.PanelAPI(state["panel_port"], state["panel_path"], state["api_token"])
        inbounds = api.call("inbounds/list")
        assert len(inbounds) == 1 and inbounds[0]["port"] == state["inbound_port"]
        inbound_settings = inbounds[0]["settings"]
        if isinstance(inbound_settings, str):
            inbound_settings = json.loads(inbound_settings)
        clients = inbound_settings["clients"]
        assert len(clients) == 1 and clients[0]["id"] == state["uuid"]
        hosts = api.call("hosts/list")
        assert len(hosts) == 1
        links = api.call("inbounds/allLinks")
        assert len(links) == 1
        link = urllib.parse.urlsplit(links[0])
        query = urllib.parse.parse_qs(link.query)
        assert link.username == state["uuid"] and link.hostname == state["domain"] and link.port == 443
        assert query["security"] == ["tls"] and query["sni"] == [state["domain"]]
        assert query["type"] == ["xhttp"] and query["path"] == [state["transport_path"]]
        record("real panel APIs and generated TLS client link")

        generated = json.loads((module.DATA / "xray/config.json").read_text())
        api_inbound = next(item for item in generated["inbounds"] if item.get("tag") == "api")
        assert api_inbound["port"] == state["api_port"] and api_inbound["listen"] == "127.0.0.1"
        assert generated["metrics"]["listen"] == f"127.0.0.1:{state['metrics_port']}"
        rule = generated["routing"]["rules"][0]
        assert rule["inboundTag"] == ["api"] and rule["outboundTag"] == "api"
        direct = next(item for item in generated["outbounds"] if item["tag"] == "direct")
        assert direct["settings"]["finalRules"][0] == {"action": "block", "ip": ["geoip:private"]}
        assert any(item.get("ip") == ["geoip:private"] and item.get("outboundTag") == "blocked"
                   for item in generated["routing"]["rules"])
        ss = real_command(["ss", "-H", "-ltnp"]).stdout
        for key in ("panel_port", "inbound_port", "api_port", "metrics_port"):
            assert f"127.0.0.1:{state[key]} " in ss, key
        assert "*:2096 " not in ss
        module.ensure_private_listeners()
        record("generated config and actual randomized loopback listeners", api_first=True, private_policy=True)

        xray = module.DATA / "xray/xray-linux-amd64"
        xenv = {**os.environ, "XRAY_LOCATION_ASSET": str(module.DATA / "xray")}

        def stats():
            response = real_command([xray, "api", "statsquery", "--server=127.0.0.1:" + str(state["api_port"])],
                                    env=xenv, timeout=8)
            return json.loads(response.stdout)

        initial_stats = stats()
        assert "stat" in initial_stats
        record("actual Xray API works on randomized API port", api_port=state["api_port"])

        private_server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), PrivateDestination)
        private_server.daemon_threads = True
        private_thread = threading.Thread(target=private_server.serve_forever, daemon=True)
        private_thread.start()
        proxy_port = free_port()
        client_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"listen": "127.0.0.1", "port": proxy_port, "protocol": "socks",
                          "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [{"protocol": "vless", "settings": {"vnext": [
                {"address": "127.0.0.1", "port": state["inbound_port"],
                 "users": [{"id": state["uuid"], "encryption": "none"}]}]},
                "streamSettings": {"network": "xhttp", "security": "none", "xhttpSettings": {
                    "path": state["transport_path"], "host": state["domain"], "mode": "auto"}}}]
        }
        client_path = work / "private-egress-client.json"
        client_path.write_text(json.dumps(client_config))
        client_path.chmod(0o600)
        client_log = (work / "client.log").open("w")
        client = subprocess.Popen([str(xray), "run", "-config", str(client_path)], cwd=work, env=xenv,
                                  stdout=client_log, stderr=subprocess.STDOUT, start_new_session=True)
        wait_port(proxy_port, client)
        curl = real_command(["curl", "--silent", "--show-error", "--fail", "--max-time", "2",
                             "--proxy", f"socks5h://127.0.0.1:{proxy_port}", "--noproxy", "",
                             f"http://127.0.0.1:{private_server.server_address[1]}/"], timeout=5, check=False)
        assert curl.returncode != 0 and PrivateDestination.requests == 0
        inbound_tag = inbounds[0]["tag"]
        after = stats()
        traffic = {item["name"]: item.get("value", 0) for item in after["stat"]}
        assert traffic.get(f"inbound>>>{inbound_tag}>>>traffic>>>uplink", 0) > 0, traffic
        record("actual authenticated VLESS traffic cannot reach loopback destination",
               curl_exit=curl.returncode, private_destination_requests=PrivateDestination.requests,
               authenticated_inbound_uplink_bytes=traffic[f"inbound>>>{inbound_tag}>>>traffic>>>uplink"])
    except Exception:
        error = traceback.format_exc()
        # All tests use generated credentials, but do not print whole API/DB/log dumps.
        print(error, file=sys.stderr)
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_alarm)
        stop(client)
        stop(panel)
        if panel_log:
            panel_log.close()
        if client_log:
            client_log.close()
        if private_server:
            private_server.shutdown()
            private_server.server_close()
        if private_thread:
            private_thread.join(timeout=2)
        pwd.getpwnam = real_getpwnam
        report = {"outcome": "FAIL" if error else "PASS", "module": str(args.module),
                  "module_sha256": hashlib.sha256(args.module.read_bytes()).hexdigest(),
                  "uid": os.getuid(), "elapsed_seconds": round(time.monotonic() - started, 3),
                  "results": results, "fixture_directory": str(work), "error": error,
                  "commands": command_records,
                  "scope": "Real bootstrap_panel CLI/SQLite/API/Xray/listeners; systemctl start replaced with non-root Popen; root ownership, apt, systemd sandbox and ACME not tested"}
        (work / "result.json").write_text(json.dumps(report, indent=2))
        args.report.write_text("HTTPS Node actual bootstrap integration\n\n" + json.dumps(report, indent=2) + "\n")
        print(f"Report: {args.report}", flush=True)
    return 1 if error else 0


if __name__ == "__main__":
    raise SystemExit(main())
