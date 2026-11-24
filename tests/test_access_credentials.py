#!/usr/bin/env python3
"""QR transport and private access refresh tests; no real service or network.

QR fixtures below test the text/command contract, not QR encoding itself.
Independent acceptance can decode a real qrencode result with a QR reader.
"""

from __future__ import annotations

import contextlib
import copy
import io
import json
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
import installer_core as core
from test_panel_access import PanelTransactionFixture


QR_ROW = "████" + "▀▄" * 10 + " " + "████"
TEXT_QR = ("█" * 29 + "\n") * 2 + (QR_ROW + "\n") * 11 + ("█" * 29 + "\n") * 2


def access_state(**changes):
    return {
        "domain": "node.example.test", "bind_ip": "192.0.2.10", "transport": "xhttp",
        "panel_port": 2053, "panel_path": "/0123456789abcdef0123456789abcdef/",
        "transport_path": "/api/abcdef0123456789abcdef0123456789/",
        "username": "fixture-owner", "password": "fixture-password",
        "uuid": "db65a01f-8317-42ed-9a34-d704fbdf3489", "client_name": "QR fixture",
        "panel_access": "ssh", "panel_allow": [], **changes,
    }


class AccessQRRendering(unittest.TestCase):
    def test_qr_receives_exact_link_on_stdin_with_no_escape_sequences(self):
        state = access_state()
        expected = core.client_link(state)
        with mock.patch.object(core, "command", return_value=subprocess.CompletedProcess([], 0, TEXT_QR, "")) as run:
            self.assertEqual(core.render_vless_qr(state), TEXT_QR)
        run.assert_called_once_with(["qrencode", "-t", "UTF8", "-m", "4"],
                                    input_text=expected, timeout=10, secret=True)
        self.assertNotIn(expected, run.call_args.args[0])
        self.assertFalse(run.call_args.kwargs["input_text"].endswith("\n"))
        text = core.make_access_text(state, qr_text=TEXT_QR)
        self.assertIn(expected, text)
        self.assertEqual(text.count("VLESS QR code ("), 1)
        self.assertNotIn("\x1b", text)
        self.assertIn("light text on a dark background", text)

    def test_malformed_qr_is_rejected_without_echoing_private_output(self):
        state = access_state()
        secret = core.client_link(state)
        for output in ("", secret, TEXT_QR + "\x1b[0m", TEXT_QR.replace("▀", "x", 1),
                       TEXT_QR + "\n", TEXT_QR * 10):
            with self.subTest(length=len(output)), \
                    mock.patch.object(core, "command", return_value=subprocess.CompletedProcess([], 0, output, secret)):
                with self.assertRaises(core.NodeError) as raised:
                    core.render_vless_qr(state)
                self.assertNotIn(secret, str(raised.exception))
        with mock.patch.object(core, "command", side_effect=UnicodeError("private-output")):
            with self.assertRaisesRegex(core.NodeError, "could not be decoded") as raised:
                core.render_vless_qr(state)
            self.assertNotIn("private-output", str(raised.exception))

    def test_optional_saved_qr_failure_retains_credentials_and_explicit_retry(self):
        state = access_state()
        original = copy.deepcopy(state)
        output = io.StringIO()
        with mock.patch.object(core, "render_vless_qr", side_effect=core.NodeError("fixture failure")), \
                contextlib.redirect_stdout(output):
            text = core.make_saved_access_text(state)
        self.assertIn("VLESS QR code: unavailable", text)
        self.assertIn("credentials --refresh-file", text)
        self.assertIn(core.client_link(state), text)
        self.assertIn(state["password"], text)
        self.assertIn("WARNING", output.getvalue())
        self.assertNotIn(state["password"], output.getvalue())
        self.assertNotIn(state["uuid"], output.getvalue())
        self.assertEqual(state, original)
        with mock.patch.object(core, "command", side_effect=UnicodeError("private-output")), \
                contextlib.redirect_stdout(io.StringIO()):
            text = core.make_saved_access_text(state)
        self.assertIn("VLESS QR code: unavailable", text)
        self.assertIn(core.client_link(state), text)
        self.assertNotIn("private-output", text)

    def test_access_instructions_explain_current_panel_mode(self):
        ssh_state = access_state()
        ssh = core.make_access_text(ssh_state)
        self.assertIn("public HTTPS URL is disabled", ssh)
        self.assertIn("panel-access --mode https --confirm-domain node.example.test", ssh)
        self.assertNotIn("Public panel: https://", ssh)
        https = core.make_access_text(access_state(panel_access="https", panel_allow=["198.51.100.4"]))
        self.assertIn("Public panel: https://node.example.test" + ssh_state["panel_path"], https)
        self.assertIn("no SSH tunnel is needed", https)
        self.assertIn("Username: fixture-owner", https)
        self.assertIn("Password: fixture-password", https)
        self.assertIn("198.51.100.4", https)


class AccessFileRefresh(unittest.TestCase):
    def test_default_read_is_unchanged_and_qr_read_is_explicit(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PanelTransactionFixture(Path(temporary))
            with fixture.active(), mock.patch.object(core, "render_vless_qr", return_value=TEXT_QR) as qr:
                before = fixture.snapshot()
                core.main(["credentials"])
                qr.assert_not_called()
                self.assertEqual(fixture.snapshot(), before)
                self.assertFalse((fixture.root / "maintenance.lock").exists())
                fixture.output.seek(0)
                fixture.output.truncate(0)
                core.main(["credentials", "--qr"])
                qr.assert_called_once()
                self.assertEqual(fixture.output.getvalue().count("VLESS QR code ("), 1)
                self.assertEqual(fixture.snapshot(), before)
                self.assertEqual(fixture.calls, [])

    def test_refresh_writes_private_qr_file_and_preserves_installation(self):
        for show in (False, True):
            with self.subTest(show=show), tempfile.TemporaryDirectory() as temporary:
                fixture = PanelTransactionFixture(Path(temporary))
                before = fixture.snapshot()
                with fixture.active(), mock.patch.object(core, "render_vless_qr", return_value=TEXT_QR) as qr:
                    core.main(["credentials", "--refresh-file", *(["--qr"] if show else [])])
                    qr.assert_called_once_with(fixture.state)
                    fixture.assert_identity_and_files(self)
                    self.assertEqual(fixture.state_file.read_bytes(), before[fixture.state_file])
                    self.assertEqual(fixture.config.read_bytes(), before[fixture.config])
                    self.assertEqual(fixture.calls, [], "Refresh must not call systemd, apt or ACME")
                    self.assertEqual(stat.S_IMODE(fixture.access.stat().st_mode), 0o600)
                    self.assertEqual(fixture.access.stat().st_uid, 0)
                    self.assertFalse(fixture.checkpoints.exists())
                    self.assertIn(TEXT_QR, fixture.access.read_text())
                    printed = fixture.output.getvalue()
                    if show:
                        self.assertEqual(printed.count("VLESS QR code ("), 1)
                    else:
                        self.assertNotIn(fixture.state["password"], printed)
                        self.assertNotIn(fixture.state["uuid"], printed)
                        self.assertIn(str(fixture.access), printed)

    def test_refresh_can_recreate_missing_file_but_render_failure_preserves_old_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = PanelTransactionFixture(Path(temporary))
            with fixture.active(), mock.patch.object(core, "render_vless_qr", side_effect=core.NodeError("fixture failure")):
                before = fixture.snapshot()
                with self.assertRaisesRegex(core.NodeError, "fixture failure"):
                    core.main(["credentials", "--refresh-file"])
                self.assertEqual(fixture.snapshot(), before)
                self.assertEqual(fixture.calls, [])
            with fixture.active(), mock.patch.object(core, "command", side_effect=UnicodeError("private-output")):
                with self.assertRaisesRegex(core.NodeError, "could not be decoded"):
                    core.main(["credentials", "--refresh-file"])
                self.assertEqual(fixture.snapshot(), before)
            fixture.access.unlink()
            with fixture.active(), mock.patch.object(core, "render_vless_qr", return_value=TEXT_QR):
                core.main(["credentials", "--refresh-file"])
                self.assertIn(TEXT_QR, fixture.access.read_text())
                self.assertEqual(stat.S_IMODE(fixture.access.stat().st_mode), 0o600)

    def test_refresh_rejects_unsafe_target_before_qr_or_write(self):
        for problem in ("symlink", "hardlink", "mode", "owner"):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as temporary:
                fixture = PanelTransactionFixture(Path(temporary))
                outside = fixture.root / "another-file"
                if problem == "symlink":
                    outside.write_text("do not modify\n")
                    fixture.access.unlink()
                    fixture.access.symlink_to(outside)
                elif problem == "hardlink":
                    outside.hardlink_to(fixture.access)
                elif problem == "mode":
                    fixture.access.chmod(0o644)
                else:
                    fixture.bad_owner = fixture.access
                expected = fixture.access.read_bytes()
                with fixture.active(), mock.patch.object(core, "render_vless_qr", return_value=TEXT_QR) as qr:
                    with self.assertRaises(core.NodeError):
                        core.main(["credentials", "--refresh-file"])
                    qr.assert_not_called()
                    self.assertEqual(fixture.access.read_bytes(), expected)
                    self.assertEqual(fixture.calls, [])

    def test_refresh_refuses_state_or_access_drift_during_qr_generation(self):
        for changed in ("state", "access"):
            with self.subTest(changed=changed), tempfile.TemporaryDirectory() as temporary:
                fixture = PanelTransactionFixture(Path(temporary))
                old_access = fixture.access.read_bytes()
                def concurrent_edit(_state):
                    if changed == "state":
                        fixture.state_file.write_text(json.dumps({**fixture.state, "username": "other-owner"}))
                    else:
                        fixture.access.write_text("external edit\n")
                    return TEXT_QR
                with fixture.active(), mock.patch.object(core, "render_vless_qr", side_effect=concurrent_edit):
                    with self.assertRaisesRegex(core.NodeError, "changed"):
                        core.main(["credentials", "--refresh-file"])
                    self.assertEqual(fixture.access.read_bytes(), old_access if changed == "state" else b"external edit\n")
                    self.assertEqual(fixture.calls, [])

    def test_panel_switch_saves_qr_or_explicit_fallback_without_rotating_identity(self):
        saved_formatter = core.make_saved_access_text
        for qr_fails in (False, True):
            with self.subTest(qr_fails=qr_fails), tempfile.TemporaryDirectory() as temporary:
                fixture = PanelTransactionFixture(Path(temporary))
                with fixture.active(), \
                        mock.patch.object(core, "make_saved_access_text", side_effect=saved_formatter), \
                        mock.patch.object(core, "render_vless_qr", side_effect=core.NodeError("fixture failure") if qr_fails else None,
                                          return_value=TEXT_QR):
                    fixture.change("https", ["198.51.100.4"])
                    fixture.assert_identity_and_files(self)
                    text = fixture.access.read_text()
                    self.assertIn("Public panel:", text)
                    self.assertIn(core.client_link(fixture.state), text)
                    self.assertIn("VLESS QR code: unavailable" if qr_fails else TEXT_QR, text)
                    self.assertEqual(len(fixture.reloaded), 1)


if __name__ == "__main__":
    unittest.main()
