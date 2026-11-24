#!/usr/bin/env python3
"""Bounded panel exposure regressions; all system commands/probes are mocked.

The companion integration_panel_access.py runs actual nginx on loopback. These
unit tests exercise validation, CLI selection, state compatibility, and the
transaction that changes access without reinstallation or identity rotation.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import importlib
import io
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


sys.dont_write_bytecode = True
PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT / "src"))
core = importlib.import_module("installer_core")
rendering = importlib.import_module("rendering")
DOMAIN = "node.example.test"
PANEL_PATH = "/manage-6b38e0c216a54c77be94b08db6cb600a/"
TRANSPORT_PATH = "/api/81e25848e02c41b99ac4b0025a354447/"


def new_install_args(**changes):
    return argparse.Namespace(
        **{"transport": "xhttp", "email": None, "site_dir": None,
           "site_theme": "auto", "site_title": None, "site_description": None,
           **changes}
    )


class PanelSelectionAndValidation(unittest.TestCase):
    def test_default_and_literal_cidr_normalization(self):
        self.assertEqual(rendering.normalize_panel_access(), ("ssh", []))
        self.assertEqual(rendering.normalize_panel_access("https"), ("https", []))
        entries = ["192.0.2.9/24", "192.0.2.0/24", "198.51.100.2", "2001:0db8::1"]
        before = entries.copy()
        self.assertEqual(rendering.normalize_panel_access("https", entries), (
            "https", ["192.0.2.0/24", "198.51.100.2", "2001:db8::1"]))
        self.assertEqual(entries, before, "Caller-owned inputs must not be mutated")

    def test_malformed_or_injected_acl_and_ssh_with_acl_are_rejected(self):
        for entries in ("192.0.2.1", [None], [True], [""], ["example.test"],
                        ["0.0.0.0/33"], ["192.0.2.1; allow all;"],
                        ["192.0.2.1\nallow all"], ["192.0.2.1 "],
                        ["fe80::1%eth0"], ["unix:"], ["all"], ["0.0.0.0"] * 129):
            with self.subTest(entries=repr(entries)[:80]), self.assertRaises(ValueError):
                rendering.normalize_panel_access("https", entries)
        for mode in (None, True, [], "public", "HTTPS"):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                rendering.normalize_panel_access(mode, [])
        with self.assertRaises(ValueError):
            rendering.normalize_panel_access("ssh", ["192.0.2.1"])

    def test_legacy_state_stays_ssh_and_invalid_saved_settings_fail_closed(self):
        legacy = {"format": "https-node-v1", "domain": DOMAIN}
        before = copy.deepcopy(legacy)
        self.assertEqual(core.panel_settings(legacy), ("ssh", []))
        self.assertEqual(legacy, before)
        for change in ({"panel_access": "internet"}, {"panel_allow": None},
                       {"panel_allow": "192.0.2.1"}, {"panel_allow": ("192.0.2.1",)},
                       {"panel_access": "ssh", "panel_allow": ["192.0.2.1"]},
                       {"panel_access": "https", "panel_allow": ["192.0.2.1;deny all;"]}):
            with self.subTest(change=change), self.assertRaises(core.NodeError):
                core.panel_settings({**legacy, **change})

    def test_new_install_defaults_to_ssh_and_creates_a_new_persistable_panel_path(self):
        facts = {"domain": DOMAIN, "bind_ip": "192.0.2.10", "cert_name": DOMAIN}
        with mock.patch.object(core, "free_port", side_effect=[18181, 18182, 18183] * 2):
            first = core.new_state(facts, new_install_args())
            second = core.new_state(facts, new_install_args(panel_access="https", panel_allow=["198.51.100.9/24"]))
        self.assertEqual((first["panel_access"], first["panel_allow"]), ("ssh", []))
        self.assertEqual((second["panel_access"], second["panel_allow"]), ("https", ["198.51.100.0/24"]))
        for state in (first, second):
            self.assertRegex(state["panel_path"], r"^/[0-9a-f]{32}/$")
            self.assertEqual(json.loads(json.dumps(state))["panel_path"], state["panel_path"])
        self.assertNotEqual(first["panel_path"], second["panel_path"])

    def test_renderer_requires_unambiguous_panel_path_and_separate_port(self):
        base = dict(domain=DOMAIN, bind_ip="127.0.0.1", transport="ws", inbound_port=18181,
                    path=TRANSPORT_PATH, site_root="/var/www/https-node", panel_access="https",
                    panel_path=PANEL_PATH, panel_port=2053)
        for change in ({"panel_path": None}, {"panel_port": None}, {"panel_port": 18181},
                       {"panel_port": 443}, {"panel_port": True},
                       {"panel_path": TRANSPORT_PATH},
                       {"panel_path": TRANSPORT_PATH + "nested-secret-path/"},
                       {"panel_path": "/x;return-200-secret-path/"}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                rendering.render_nginx(**{**base, **change})
        acme = rendering.render_nginx(**base)
        private = rendering.render_nginx(**{**base, "panel_access": "ssh"})
        self.assertEqual(acme, private, "No panel route may exist before TLS is configured")

    def test_cli_selects_explicit_options_and_keeps_install_default_private(self):
        with mock.patch.object(core, "install") as install:
            core.main(["install", "--domain", DOMAIN, "--acme-no-email", "--agree-tos"])
            args = install.call_args.args[0]
            self.assertEqual(args.panel_access, "ssh")
            self.assertFalse(args.panel_allow)
            core.main(["install", "--domain", DOMAIN, "--acme-no-email", "--agree-tos",
                       "--panel-access", "https", "--panel-allow", "192.0.2.1",
                       "--panel-allow", "198.51.100.0/24"])
            args = install.call_args.args[0]
            self.assertEqual(args.panel_access, "https")
            self.assertEqual(args.panel_allow, ["192.0.2.1", "198.51.100.0/24"])
        with mock.patch.object(core, "panel_access") as change:
            core.main(["panel-access", "--mode", "https", "--allow", "192.0.2.1", "--confirm-domain", DOMAIN])
            args = change.call_args.args[0]
            self.assertEqual((args.mode, args.allow, args.confirm_domain), ("https", ["192.0.2.1"], DOMAIN))


class PanelTransactionFixture:
    """Real temporary files, strict mock commands, and observable loaded config."""

    def __init__(self, root: Path, *, legacy=True):
        root = root.resolve()
        self.root = root
        self.etc, self.site, self.data = root / "etc", root / "site", root / "data"
        for directory in (self.etc, self.site, self.data):
            directory.mkdir(mode=0o700)
        self.state_file = self.etc / "state.json"
        self.config = self.etc / "nginx.conf"
        self.access = root / "access.txt"
        self.checkpoints = root / "checkpoints"
        self.calls = []
        self.reloaded = []
        self.fail_next = None
        self.rollback_reload_fails = False
        self.failed_once = False
        self.bad_owner = None
        self.state = {
            "format": "https-node-v1", "app_version": "0.3.0-rc2", "domain": DOMAIN,
            "status": "ready", "stage": "complete", "bind_ip": "192.0.2.10",
            "transport": "xhttp", "inbound_port": 18181, "api_port": 18182,
            "metrics_port": 18183, "panel_port": 2053, "panel_path": PANEL_PATH,
            "transport_path": TRANSPORT_PATH, "cert_name": "https-node-0123456789abcdef", "certificate_issued": True,
            "username": "fixture-owner", "password": "fixture-private-password",
            "client_name": "SiteKit fixture",
            "uuid": "db65a01f-8317-42ed-9a34-d704fbdf3489", "sub_id": "fixture-sub-id",
            "site_profile": {"seed": "a" * 64, "theme": "journal"},
            "release_version": core.RELEASE_VERSION, "release_sha256": core.RELEASE_SHA256,
        }
        if not legacy:
            self.state.update(panel_access="ssh", panel_allow=[])
        self._write(self.state_file, json.dumps(self.state, indent=2) + "\n")
        self._write(self.access, core.make_access_text(self.state))
        with mock.patch.object(core, "SITE", self.site):
            self._write(self.config, core.nginx_config(self.state, True))
        self.loaded_config = self.config.read_bytes()
        self.protected_files = {
            self.site / "index.html": b"existing generated website\n",
            self.site / "site-profile.json": b"private-profile-fixture\n",
            self.data / "x-ui.db": b"database bytes must not be rewritten by panel-access\n",
            self.data / "fullchain.pem": b"existing production certificate fixture\n",
            self.data / "privkey.pem": b"existing production key fixture\n",
        }
        for path, body in self.protected_files.items():
            path.write_bytes(body)
        self.initial_identity = {key: self.state[key] for key in (
            "panel_path", "transport_path", "uuid", "username", "password", "sub_id",
            "site_profile", "cert_name", "release_version", "release_sha256",
        )}
        self.initial = self.snapshot()

    @staticmethod
    def _write(path, text):
        path.write_text(text, encoding="utf-8")
        path.chmod(0o600)

    def snapshot(self):
        return {path: path.read_bytes() for path in (self.state_file, self.access, self.config)}

    def command(self, argv, **kwargs):
        argv = [str(item) for item in argv]
        self.calls.append(argv)
        if argv == ["systemctl", "is-active", core.NGINX_SERVICE]:
            return subprocess.CompletedProcess(argv, 0, "active\n", "")
        if argv == ["/usr/sbin/nginx", "-t", "-c", str(self.config)]:
            if self.fail_next == "syntax" and not self.failed_once and self.config.read_bytes() != self.loaded_config:
                self.failed_once = True
                raise core.NodeError("fixture candidate syntax failure")
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv == ["systemctl", "reload", core.NGINX_SERVICE]:
            if self.fail_next == "reload" and not self.failed_once:
                self.failed_once = True
                raise core.NodeError("fixture candidate reload failure")
            if self.rollback_reload_fails and self.failed_once:
                raise core.NodeError("fixture rollback reload failure")
            self.loaded_config = self.config.read_bytes()
            self.reloaded.append(self.loaded_config)
            return subprocess.CompletedProcess(argv, 0, "", "")
        raise AssertionError("Unexpected system command: " + repr(argv))

    def reload_ack(self, seconds=15):
        self.command(["systemctl", "reload", core.NGINX_SERVICE])
        if self.fail_next == "ack" and not self.failed_once:
            self.failed_once = True
            raise core.NodeError("fixture worker-generation acknowledgement timeout")

    @contextlib.contextmanager
    def active(self):
        original_stat = Path.stat
        original_lstat = os.lstat
        original_fstat = os.fstat

        def fixture_owner(path, info):
            path = Path(path)
            if path == self.root or self.root in path.parents:
                values = list(info)
                values[4] = 1000 if path == self.bad_owner else 0
                return os.stat_result(values)
            return info

        def fixture_stat(path, *args, **kwargs):
            return fixture_owner(path, original_stat(path, *args, **kwargs))

        def fixture_lstat(path, *args, **kwargs):
            return fixture_owner(path, original_lstat(path, *args, **kwargs))

        def fixture_fd_owner(fd):
            # Model root-owned managed files without needing to run this suite
            # as root. All file descriptors opened during this fixture are local.
            values = list(original_fstat(fd))
            values[4] = 0
            return os.stat_result(values)

        with contextlib.ExitStack() as stack:
            for name, value in {"ETC": self.etc, "STATE_FILE": self.state_file, "ACCESS": self.access,
                                "SITE": self.site, "DATA": self.data,
                                "CHECKPOINT_ROOT": self.checkpoints,
                                "MAINTENANCE_LOCK": self.root / "maintenance.lock"}.items():
                stack.enter_context(mock.patch.object(core, name, value))
            stack.enter_context(mock.patch.object(Path, "stat", fixture_stat))
            stack.enter_context(mock.patch.object(os, "lstat", side_effect=fixture_lstat))
            stack.enter_context(mock.patch.object(core.os, "fstat", side_effect=fixture_fd_owner))
            stack.enter_context(mock.patch.object(core.os, "geteuid", return_value=0))
            stack.enter_context(mock.patch.object(core, "command", side_effect=self.command))
            stack.enter_context(mock.patch.object(core, "make_saved_access_text", side_effect=core.make_access_text))
            self.reload_probe = stack.enter_context(mock.patch.object(core, "reload_managed_nginx", side_effect=self.reload_ack))
            stack.enter_context(mock.patch.object(core.subprocess, "run", side_effect=AssertionError("Real subprocess prohibited")))
            stack.enter_context(mock.patch.object(core.urllib.request, "urlopen", side_effect=AssertionError("Real network prohibited")))
            self.tls_probe = stack.enter_context(mock.patch.object(core, "final_tls_probe"))
            self.private_probe = stack.enter_context(mock.patch.object(core, "ensure_private_listeners"))
            self.database_probe = stack.enter_context(mock.patch.object(core, "verify_panel_database"))
            for name in ("new_state", "populate_site", "bootstrap_panel", "install_units", "extract_release", "refresh_apt"):
                stack.enter_context(mock.patch.object(core, name, side_effect=AssertionError("Reinstall/package work prohibited: " + name)))
            self.output = io.StringIO()
            stack.enter_context(contextlib.redirect_stdout(self.output))
            yield self

    def change(self, mode, allow=None, domain=DOMAIN):
        core.panel_access(argparse.Namespace(mode=mode, allow=allow, confirm_domain=domain))

    def assert_identity_and_files(self, test):
        state = json.loads(self.state_file.read_text())
        test.assertEqual(
            {key: value for key, value in state.items() if key not in {"panel_access", "panel_allow"}},
            {key: value for key, value in self.state.items() if key not in {"panel_access", "panel_allow"}},
            "Only the selected panel exposure settings may change",
        )
        for key, value in self.initial_identity.items():
            test.assertEqual(state[key], value, key)
        for path, body in self.protected_files.items():
            test.assertEqual(path.read_bytes(), body, str(path))
        for path in (self.state_file, self.access, self.config):
            test.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600, str(path))


class NginxReloadAcknowledgement(unittest.TestCase):
    def test_unchanged_generation_times_out_and_replaced_master_is_rejected(self):
        previous = (1000, frozenset({(102, 1001)}))
        for current, message in ((previous, "acknowledge"), ((2000, frozenset({(103, 2001)})), "master")):
            with self.subTest(current=current), \
                    mock.patch.object(core, "managed_nginx_pid", return_value=101), \
                    mock.patch.object(core, "nginx_worker_snapshot", side_effect=[previous, current]), \
                    mock.patch.object(core, "command") as command, \
                    mock.patch.object(core.time, "monotonic", side_effect=[0, 2]), \
                    mock.patch.object(core.time, "sleep"):
                with self.assertRaisesRegex(core.NodeError, message):
                    core.reload_managed_nginx(seconds=1)
                command.assert_called_once_with(["systemctl", "reload", core.NGINX_SERVICE], timeout=60)


class PanelAccessTransaction(unittest.TestCase):
    def fixture(self, **kwargs):
        directory = tempfile.TemporaryDirectory(prefix="sitekit-panel-unit-")
        self.addCleanup(directory.cleanup)
        return PanelTransactionFixture(Path(directory.name), **kwargs)

    def test_https_ssh_https_switch_keeps_existing_url_identity_database_site_and_certificate(self):
        fixture = self.fixture()
        with fixture.active():
            for mode, allow in (("https", ["198.51.100.9/24"]), ("ssh", []), ("https", [])):
                fixture.change(mode, allow)
                state = json.loads(fixture.state_file.read_text())
                self.assertEqual(core.panel_settings(state), rendering.normalize_panel_access(mode, allow))
                self.assertEqual(fixture.loaded_config, core.nginx_config(state, True).encode())
                self.assertEqual(fixture.access.read_text(), core.make_access_text(state))
                fixture.assert_identity_and_files(self)
        self.assertEqual(len(fixture.reloaded), 3)
        self.assertEqual(fixture.reload_probe.call_count, 3)
        self.assertEqual(len(list(fixture.checkpoints.iterdir())), 3)
        self.assertEqual(fixture.initial_identity["panel_path"], json.loads(fixture.state_file.read_text())["panel_path"])

    def test_noop_legacy_ssh_does_not_rewrite_state_access_or_config(self):
        fixture = self.fixture()
        with fixture.active():
            fixture.change("ssh")
        self.assertEqual(fixture.snapshot(), fixture.initial)
        self.assertEqual(fixture.reloaded, [])
        fixture.reload_probe.assert_not_called()
        self.assertFalse(fixture.checkpoints.exists())

    def test_failed_candidate_syntax_reload_or_postcheck_restores_files_and_active_config(self):
        for failure in ("syntax", "reload", "ack", "postcheck"):
            with self.subTest(failure=failure):
                fixture = self.fixture()
                original_config = fixture.loaded_config
                fixture.fail_next = failure
                with fixture.active():
                    if failure == "postcheck":
                        fixture.tls_probe.side_effect = [None, core.NodeError("fixture post-change TLS failure"), None]
                    with self.assertRaises(core.NodeError):
                        fixture.change("https", ["192.0.2.1"])
                    fixture.assert_identity_and_files(self)
                self.assertEqual(fixture.snapshot(), fixture.initial)
                self.assertEqual(fixture.loaded_config, original_config)
                self.assertEqual(len(list(fixture.checkpoints.iterdir())), 1)

    def test_bad_confirmation_invalid_acl_and_manual_config_fail_before_reload_or_checkpoint(self):
        for failure in ("confirmation", "acl", "manual", "saved-state", "ownership"):
            with self.subTest(failure=failure):
                fixture = self.fixture()
                if failure == "manual":
                    fixture.config.write_text(fixture.config.read_text() + "# unexpected local override\n")
                elif failure == "saved-state":
                    fixture.state_file.write_text(json.dumps({**fixture.state, "panel_access": "https", "panel_allow": "all"}))
                elif failure == "ownership":
                    fixture.bad_owner = fixture.access
                before = fixture.snapshot()
                with fixture.active(), self.assertRaises((core.NodeError, ValueError)):
                    fixture.change("https", ["192.0.2.1;allow all;"] if failure == "acl" else [],
                                   domain="different.example.test" if failure == "confirmation" else DOMAIN)
                self.assertEqual(fixture.snapshot(), before)
                self.assertEqual(fixture.reloaded, [])
                self.assertFalse(fixture.checkpoints.exists())

    def test_rollback_failure_is_reported_without_claiming_success_or_losing_checkpoint(self):
        fixture = self.fixture()
        fixture.fail_next = "reload"
        fixture.rollback_reload_fails = True
        with fixture.active(), self.assertRaises(core.NodeError) as raised:
            fixture.change("https", [])
        self.assertIn("rollback", str(raised.exception).lower())
        self.assertEqual(fixture.snapshot(), fixture.initial)
        checkpoints = list(fixture.checkpoints.iterdir())
        self.assertEqual(len(checkpoints), 1)
        records = "\n".join(path.read_text() for path in checkpoints[0].iterdir() if path.suffix == ".json")
        self.assertIn("rollback", records.lower())


if __name__ == "__main__":
    unittest.main()
