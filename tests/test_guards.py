#!/usr/bin/env python3
"""Focused safety guards for the HTTPS Node installer (standard library only).

All filesystem writes are temporary, except the requested GUARDS.txt report.
HTTP fixtures listen exclusively on 127.0.0.1.  No package manager, systemd,
real installer, or public network is invoked.
"""

from __future__ import annotations

import contextlib
import hashlib
import http.server
import importlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT / "src"
sys.dont_write_bytecode = True
sys.path.insert(0, str(SOURCE))
core = importlib.import_module("installer_core")
rendering = importlib.import_module("rendering")


def make_archive(path, additions=()):
    """Make a tiny release with real tar headers and all required paths."""
    base = [
        ("x-ui", tarfile.DIRTYPE, b"", "", 0o755),
        ("x-ui/bin", tarfile.DIRTYPE, b"", "", 0o755),
        ("x-ui/x-ui", tarfile.REGTYPE, b"panel fixture\n", "", 0o755),
        ("x-ui/bin/xray-linux-amd64", tarfile.REGTYPE, b"xray fixture\n", "", 0o755),
        ("x-ui/bin/geoip.dat", tarfile.REGTYPE, b"geoip fixture\n", "", 0o644),
        ("x-ui/bin/geosite.dat", tarfile.REGTYPE, b"geosite fixture\n", "", 0o644),
    ]
    with tarfile.open(path, "w:gz") as archive:
        for name, kind, data, link, mode in [*base, *additions]:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.mode = mode
            member.linkname = link
            member.size = len(data) if kind == tarfile.REGTYPE else 0
            archive.addfile(member, io.BytesIO(data) if member.isfile() else None)


@contextlib.contextmanager
def http_fixture(responder):
    """Run one bounded loopback HTTP observer, recording received credentials."""
    requests = []

    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *args):
            pass

        def handle_request(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length else b""
            requests.append({
                "path": self.path,
                "authorization": self.headers.get("Authorization"),
                "method": self.command,
                "body": body,
            })
            status, headers, payload = responder(self.path)
            self.send_response(status)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            self.wfile.write(payload)

        do_GET = handle_request
        do_POST = handle_request

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True)
    thread.start()
    try:
        yield server.server_port, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


class DigestAndExtractionGuards(unittest.TestCase):
    def test_sha256_mismatch_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="https-node-digest-") as temporary:
            file = Path(temporary) / "download.tar.gz"
            file.write_bytes(b"a locally controlled release fixture")
            correct = hashlib.sha256(file.read_bytes()).hexdigest()
            self.assertEqual(core.verify_digest(file, correct), correct)
            file.write_bytes(file.read_bytes() + b" tampered")
            with self.assertRaises(core.NodeError):
                core.verify_digest(file, correct)

    def test_unsafe_tar_members_are_rejected_before_any_file_extraction(self):
        cases = {
            "parent traversal": ("x-ui/../../escaped", tarfile.REGTYPE, b"bad", "", 0o644),
            "absolute path": ("/tmp/https-node-escaped-guard", tarfile.REGTYPE, b"bad", "", 0o644),
            "symbolic link": ("x-ui/linked", tarfile.SYMTYPE, b"", "/tmp", 0o777),
            "hard link": ("x-ui/linked", tarfile.LNKTYPE, b"", "x-ui/x-ui", 0o644),
            "duplicate path": ("x-ui/x-ui", tarfile.REGTYPE, b"overwrite", "", 0o644),
            "normalized duplicate path": ("x-ui/./x-ui", tarfile.REGTYPE, b"overwrite", "", 0o644),
            "backslash name": ("x-ui/bin\\escaped", tarfile.REGTYPE, b"bad", "", 0o644),
            "special file": ("x-ui/fifo", tarfile.FIFOTYPE, b"", "", 0o644),
            "file as parent": ("x-ui/x-ui/child", tarfile.REGTYPE, b"bad", "", 0o644),
        }
        for name, addition in cases.items():
            with self.subTest(case=name), tempfile.TemporaryDirectory(prefix="https-node-tar-") as temporary:
                root = Path(temporary)
                archive = root / "release.tar.gz"
                destination = root / "extracted"
                if name == "absolute path":
                    addition = (str(root / "outside-extraction"), *addition[1:])
                make_archive(archive, [addition])
                with self.assertRaises(core.NodeError):
                    core.extract_release(archive, destination)
                self.assertFalse(destination.exists() and list(destination.iterdir()),
                                 "An invalid member was discovered only after files had been written")
                self.assertFalse((root / "escaped").exists())
                self.assertFalse((root / "outside-extraction").exists())

    def test_valid_synthetic_release_extracts_expected_bytes_and_modes(self):
        with tempfile.TemporaryDirectory(prefix="https-node-valid-tar-") as temporary:
            root = Path(temporary)
            archive = root / "release.tar.gz"
            destination = root / "extracted"
            make_archive(archive)
            core.extract_release(archive, destination)
            self.assertEqual((destination / "x-ui/x-ui").read_bytes(), b"panel fixture\n")
            self.assertEqual((destination / "x-ui/bin/xray-linux-amd64").read_bytes(), b"xray fixture\n")
            self.assertEqual(stat.S_IMODE((destination / "x-ui/x-ui").stat().st_mode), 0o755)
            self.assertEqual(stat.S_IMODE((destination / "x-ui/bin/geoip.dat").stat().st_mode), 0o644)


class PublicDNSGuards(unittest.TestCase):
    def test_explicit_and_automatic_ipv4_ignore_local_hostname_synthesis(self):
        address = "198.51.100.10"
        replies = {"A": {address}, "AAAA": set()}
        interfaces = [{"addr_info": [{"family": "inet", "local": item}]}
                      for item in (address, "172.17.0.1")]
        ip_output = subprocess.CompletedProcess([], 0, json.dumps(interfaces), "")
        absent_account = subprocess.CompletedProcess([], 2, "", "")
        with mock.patch.object(core.shutil, "which", side_effect=lambda name: name if name != "nginx" else None), \
                mock.patch.object(core.platform, "machine", return_value="x86_64"), \
                mock.patch.object(core, "os_info", return_value={"ID": "ubuntu", "VERSION_ID": "26.04"}), \
                mock.patch.object(core, "verify_apt_trust"), \
                mock.patch.object(core.Path, "is_dir", return_value=True), \
                mock.patch.object(core.Path, "exists", return_value=False), \
                mock.patch.object(core.Path, "is_symlink", return_value=False), \
                mock.patch.object(core, "require_free_port"), \
                mock.patch.object(core.ipaddress.IPv4Address, "is_global", new_callable=mock.PropertyMock, return_value=True), \
                mock.patch.object(core, "command", side_effect=[absent_account, absent_account, ip_output] * 2), \
                mock.patch.object(core, "dig_records", side_effect=lambda _, __, kind: replies[kind]), \
                mock.patch.object(core.socket, "getaddrinfo", side_effect=AssertionError("NSS used")):
            self.assertEqual(core.preflight("example.com", address)["bind_ip"], address)
            self.assertEqual(core.preflight("example.com")["bind_ip"], address)

    def test_any_complete_public_reply_can_reject_mismatched_records(self):
        address = "198.51.100.10"
        valid_reply = [{address}, set()]
        for reply, error in (([{"198.51.100.11"}, set()], "A records"),
                             ([{address}, {"2001:db8::1"}], "AAAA record")):
            with self.subTest(error=error), \
                    mock.patch.object(core.shutil, "which", return_value="/usr/bin/dig"), \
                    mock.patch.object(core, "dig_records", side_effect=valid_reply + reply), \
                    self.assertRaisesRegex(core.NodeError, error):
                core.verify_public_dns("example.com", address)

    def test_automatic_ipv4_rejects_multicast_dns_record(self):
        with mock.patch.object(core.shutil, "which", return_value="/usr/bin/dig"), \
                mock.patch.object(core, "dig_records", side_effect=[{"224.1.2.3"}, set()]), \
                self.assertRaisesRegex(ValueError, "unicast"):
            core.verify_public_dns("example.com")

    def test_doh_fallback_verifies_both_types_without_dig(self):
        address = "198.51.100.10"
        reply_a = {"Status": 0, "Question": [{"name": "example.com", "type": 1}],
                   "Answer": [{"type": 1, "data": address}]}
        reply_aaaa = {"Status": 0, "Question": [{"name": "example.com.", "type": 28}]}
        responses = [io.BytesIO(json.dumps(reply).encode()) for reply in (reply_a, reply_aaaa)]
        truncated = mock.MagicMock()
        truncated.__enter__.return_value.read.side_effect = http.client.IncompleteRead(b"")
        with mock.patch.object(core.shutil, "which", return_value=None), \
                mock.patch.object(core.urllib.request, "urlopen", side_effect=[truncated, *responses]):
            self.assertEqual(core.verify_public_dns("example.com"), address)


class AcmeStartupGuards(unittest.TestCase):
    state = {"bind_ip": "127.0.0.1", "domain": "example.com"}

    def test_probe_waits_for_nginx_before_checking_the_webroot(self):
        connection = mock.Mock()
        connection.connect.side_effect = [ConnectionRefusedError, None]
        connection.getresponse.return_value = mock.Mock(status=200, read=mock.Mock(return_value=b"probe-body"))
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(core, "SITE", Path(temp)), \
                mock.patch.object(core.http.client, "HTTPConnection", return_value=connection), \
                mock.patch.object(core.secrets, "token_hex", side_effect=["probe-body", "probe-name"]), \
                mock.patch.object(core.time, "sleep") as sleep:
            core.local_http_probe(self.state)
            self.assertEqual(list(Path(temp).rglob("https-node-probe-name")), [])
        self.assertEqual(connection.connect.call_count, 2)
        sleep.assert_called_once_with(0.25)
        connection.request.assert_called_once_with("GET", "/.well-known/acme-challenge/https-node-probe-name",
                                                   headers={"Host": "example.com"})
        connection.close.assert_called_once()

    def test_persistent_connection_refusal_stops_and_removes_the_probe(self):
        connection = mock.Mock()
        connection.connect.side_effect = ConnectionRefusedError
        with tempfile.TemporaryDirectory() as temp, \
                mock.patch.object(core, "SITE", Path(temp)), \
                mock.patch.object(core.http.client, "HTTPConnection", return_value=connection), \
                mock.patch.object(core.time, "monotonic", side_effect=[0, 10]):
            with self.assertRaisesRegex(core.NodeError, "did not listen"):
                core.local_http_probe(self.state)
            self.assertEqual(list(Path(temp).rglob("https-node-*")), [])
        connection.request.assert_not_called()
        connection.close.assert_called_once()


class SecretFileGuards(unittest.TestCase):
    def test_secret_is_private_before_first_write_and_after_atomic_replace(self):
        with tempfile.TemporaryDirectory(prefix="https-node-secret-") as temporary:
            target = Path(temporary) / "access.txt"
            target.write_text("previous content", encoding="utf-8")
            target.chmod(0o644)
            original_fdopen = os.fdopen
            observed_modes = []

            def checked_fdopen(fd, *args, **kwargs):
                observed_modes.append(stat.S_IMODE(os.fstat(fd).st_mode))
                return original_fdopen(fd, *args, **kwargs)

            previous_umask = os.umask(0)
            try:
                with mock.patch.object(core.os, "fdopen", side_effect=checked_fdopen):
                    core.write_file(target, "guard-test-secret")
            finally:
                os.umask(previous_umask)
            self.assertEqual(observed_modes, [0o600])
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
            self.assertEqual(target.read_text(), "guard-test-secret")
            self.assertEqual([item.name for item in target.parent.iterdir()], ["access.txt"])

    def test_secret_target_symlink_is_rejected_without_changing_referent(self):
        with tempfile.TemporaryDirectory(prefix="https-node-link-") as temporary:
            root = Path(temporary)
            referent = root / "unchanged.txt"
            referent.write_text("do not replace")
            target = root / "access.txt"
            target.symlink_to(referent)
            with self.assertRaises(core.NodeError):
                core.write_file(target, "guard-test-secret")
            self.assertEqual(referent.read_text(), "do not replace")
            self.assertTrue(target.is_symlink())


class LoopbackAPIGuards(unittest.TestCase):
    def test_proxy_environment_is_ignored_and_redirects_never_forward_token(self):
        successful = (200, {"Content-Type": "application/json"}, b'{"success":true,"obj":{"ok":true}}')
        with http_fixture(lambda path: successful) as (target_port, target_requests), \
                http_fixture(lambda path: successful) as (proxy_port, proxy_requests):

            def api_response(path):
                operation = path.rsplit("/", 1)[-1]
                if operation.startswith("redirect"):
                    code = int(operation[len("redirect"):])
                    return code, {"Location": f"http://127.0.0.1:{target_port}/capture"}, b""
                return successful

            with http_fixture(api_response) as (api_port, api_requests):
                proxy_url = f"http://127.0.0.1:{proxy_port}"
                environment = {
                    "HTTP_PROXY": proxy_url, "http_proxy": proxy_url,
                    "HTTPS_PROXY": proxy_url, "https_proxy": proxy_url,
                    "ALL_PROXY": proxy_url, "all_proxy": proxy_url,
                    "NO_PROXY": "", "no_proxy": "",
                }
                with mock.patch.dict(os.environ, environment):
                    api = core.PanelAPI(api_port, "/managed-guard/", "guard-test-token")
                    self.assertEqual(api.call("inbounds/list"), {"ok": True})
                    for status in (301, 302, 303, 307, 308):
                        for payload in (None, {"fixture": True}):
                            with self.subTest(status=status, method="GET" if payload is None else "POST"):
                                with self.assertRaises(core.NodeError):
                                    api.call("redirect" + str(status), payload)
                self.assertEqual(len(api_requests), 11)
                self.assertTrue(all(item["authorization"] == "Bearer guard-test-token" for item in api_requests))
                self.assertEqual(target_requests, [], "API redirect leaked credentials to its target")
                self.assertEqual(proxy_requests, [], "Loopback API traffic was sent to an environment proxy")

    def test_hostile_endpoint_does_not_make_an_http_request(self):
        response = (200, {"Content-Type": "application/json"}, b'{"success":true,"obj":null}')
        with http_fixture(lambda path: response) as (port, received):
            api = core.PanelAPI(port, "/guard/", "guard-test-token")
            for endpoint in ("http://127.0.0.1/", "../outside", "ok\r\nX-Injected: yes", "operation?token=x"):
                with self.subTest(endpoint=endpoint), self.assertRaises(core.NodeError):
                    api.call(endpoint)
            self.assertEqual(received, [])


class RenderingInputGuards(unittest.TestCase):
    def test_hostile_domain_names_and_addresses_are_rejected(self):
        self.assertEqual(rendering.validate_domain("Example.COM"), "example.com")
        self.assertEqual(rendering.validate_domain("xn--e1afmkfd.xn--p1ai"), "xn--e1afmkfd.xn--p1ai")
        for domain in ("example.com;", "example.com\n", "a.example.com/", "*.example.com",
                       "user@example.com", "127.0.0.1", "local", "пример.рф", "-host.com",
                       "a..com", "example.com.", "xn--a.com", "a" * 64 + ".com"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                rendering.validate_domain(domain)
        for address in ("0.0.0.0", "224.0.0.1", "255.255.255.255", "example.com", "127.0.0.1;", "127.0.0.1\n", True):
            with self.subTest(address=address), self.assertRaises(ValueError):
                rendering.validate_ipv4(address)

    def test_site_title_and_description_cannot_inject_html(self):
        title = '<script id="injected">alert(1)</script>'
        description = '\"><img src=x onerror=alert(2)>'
        site = rendering.render_site("example.com", title, description)
        for name in ("index.html", "about.html", "404.html"):
            with self.subTest(file=name):
                self.assertNotIn('<script id="injected">', site[name])
                self.assertNotIn('<img src=x', site[name])
                self.assertIn("&lt;script", site[name])
                self.assertIn("&lt;img", site[name])

    def test_paths_cannot_interpolate_variables_or_escape_nginx_directives(self):
        base = {
            "domain": "example.com", "bind_ip": "127.0.0.1", "transport": "xhttp",
            "inbound_port": 28081, "path": "/api/" + "a" * 32 + "/",
            "site_root": "/tmp/site", "http_port": 28080, "https_port": 28443,
            "runtime_root": "/tmp/run", "log_root": "/tmp/log", "cache_root": "/tmp/cache",
            "worker_user": None,
        }
        for field in ("site_root", "runtime_root", "log_root", "cache_root"):
            for path in ("/tmp/$host", "/tmp/../etc", "/tmp/site\ninclude /etc/passwd;", "/", "/./", "relative/path"):
                with self.subTest(field=field, path=path), self.assertRaises(ValueError):
                    rendering.render_nginx(**{**base, field: path})
        for path in ("/api/../etc/", "/api/short/", "/api/" + "a" * 32 + "/; return 200;", "/api/$host/", "/api/a\n/"):
            with self.subTest(tunnel=path), self.assertRaises(ValueError):
                rendering.render_nginx(**{**base, "path": path})


class ImportGuards(unittest.TestCase):
    def test_import_does_not_install_write_spawn_connect_or_parse_cli(self):
        child = r'''
import argparse, contextlib, hashlib, hmac, http.client, importlib, io, ipaddress
import json, os, pathlib, platform, pwd, re, secrets, shutil, signal, socket
import sqlite3, ssl, stat, subprocess, sys, tarfile, tempfile, time
import urllib.error, urllib.parse, urllib.request, uuid
from unittest import mock
sys.dont_write_bytecode = True
sys.path.insert(0, sys.argv[1])
sys.argv = ['installer_core.py', 'install', '--domain', 'should-not-run.example']
original_open, original_io_open, original_os_open = open, io.open, os.open
def text_open(original):
    def guarded(file, mode='r', *args, **kwargs):
        if any(flag in mode for flag in 'wax+'):
            raise AssertionError('import tried a file write')
        return original(file, mode, *args, **kwargs)
    return guarded
def os_open(path, flags, *args, **kwargs):
    if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_TRUNC):
        raise AssertionError('import tried an os.open write')
    return original_os_open(path, flags, *args, **kwargs)
def forbidden(*args, **kwargs):
    raise AssertionError('import invoked an operational side effect')
with contextlib.ExitStack() as stack:
    for target in ('subprocess.run','subprocess.Popen','os.mkdir','os.makedirs',
                   'os.remove','os.unlink','os.replace','os.chmod','os.chown',
                   'socket.create_connection','urllib.request.OpenerDirector.open',
                   'signal.signal','argparse.ArgumentParser.parse_args'):
        stack.enter_context(mock.patch(target, side_effect=forbidden))
    stack.enter_context(mock.patch('builtins.open', side_effect=text_open(original_open)))
    stack.enter_context(mock.patch('io.open', side_effect=text_open(original_io_open)))
    stack.enter_context(mock.patch('os.open', side_effect=os_open))
    stack.enter_context(mock.patch.object(socket.socket, 'connect', side_effect=forbidden))
    stack.enter_context(mock.patch.object(socket.socket, 'bind', side_effect=forbidden))
    importlib.import_module('installer_core')
print('IMPORT_SAFE')
'''
        result = subprocess.run([sys.executable, "-B", "-c", child, str(SOURCE)], capture_output=True,
                                text=True, timeout=20, env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "IMPORT_SAFE")


if __name__ == "__main__":
    report = io.StringIO()
    report.write("HTTPS Node installation guard tests\n")
    report.write("UTC: " + time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()) + "\n")
    report.write("Scope: temporary files, synthetic archives, loopback HTTP only.\n\n")
    result = unittest.TextTestRunner(stream=report, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__]))
    text = report.getvalue()
    (Path(__file__).parent / "GUARDS.txt").write_text(text, encoding="utf-8")
    print(text, end="")
    raise SystemExit(0 if result.wasSuccessful() else 1)
