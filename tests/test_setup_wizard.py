#!/usr/bin/env python3
"""Bounded PTY wizard and synthetic DNS checks; never run a real installer."""

from __future__ import annotations

import contextlib
import errno
import fcntl
import io
import json
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import struct
import subprocess
import tempfile
import termios
import time
import types
import unittest
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT / "setup.sh"
DOMAIN = "node.example.test"
ADDRESS = "93.184.216.34"  # Synthetic interface/DNS fixture; never contacted.
SOURCE = SCRIPT.read_text(encoding="utf-8")
PYTHON_SOURCE = SOURCE.split("<<'SITEKIT_SETUP_PYTHON'\n", 1)[1].split("\nSITEKIT_SETUP_PYTHON\n", 1)[0]
DNS = types.ModuleType("sitekit_setup_dns_fixture")
exec(compile(PYTHON_SOURCE, str(SCRIPT) + ":embedded-python", "exec"), DNS.__dict__)


HARNESS = r'''
source "$1"
shift
ip() { return 99; }
setup_require_root() { :; }
setup_find_apt_backports() { printf '%s' "$TEST_APT_BACKPORTS"; }
setup_check_dns() {
    printf 'dns:%s\n' "$1" >> "$TEST_TRACE"
    if [[ "$1" == bad.example.test ]]; then printf 'fixture DNS mismatch\n' >&2; return 1; fi
    if [[ "${TEST_DNS_WARNING:-0}" == 1 ]]; then printf '%s\n' 'Warning: only Google provided a complete DNS answer.' >&2; fi
    printf '%s\n' '93.184.216.34'
}
setup_download() {
    printf 'download\n' >> "$TEST_TRACE"
    printf '%s' 'untrusted synthetic bootstrap' > "$2"
    printf '%s' "$2" > "$TEST_TEMPFILE"
}
setup_run_bootstrap() {
    printf 'execute\n' >> "$TEST_TRACE"
    printf '%s\0' "$@" > "$TEST_ARGS"
    return "${TEST_CHILD_EXIT:-0}"
}
mktemp() { printf 'mktemp\n' >> "$TEST_TRACE"; command mktemp "$@"; }
if [[ "${TEST_VERIFY:-real}" == pass ]]; then setup_verify_bootstrap() { return 0; }; fi
setup_main "$@"
'''


FAKE_WHIPTAIL = r"""#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys
args = sys.argv[1:]
widget = next((value[2:] for value in args if value in ('--menu', '--inputbox', '--yesno', '--msgbox', '--infobox')), '')
with Path(os.environ['TEST_DIALOG_CALLS']).open('a') as stream:
    stream.write(json.dumps({'widget': widget, 'argv': args}, ensure_ascii=False) + '\n')
if widget == 'infobox':
    raise SystemExit(0)
state = Path(os.environ['TEST_DIALOG_RESPONSES'])
responses = json.loads(state.read_text())
if not responses or responses[0][0] != widget:
    print('unexpected fake dialog call: ' + widget, file=sys.stderr)
    raise SystemExit(2)
expected, response, status = responses.pop(0)
state.write_text(json.dumps(responses))
print('[dialog:' + widget + ']', flush=True)
if response:
    print(response, end='', file=sys.stderr)
raise SystemExit(status)
"""


class WizardPTY(unittest.TestCase):
    def run_wizard(self, lines, *, arguments=("--dry-run",), verify="real", child_exit=0,
                   eof=False, interrupt=False, choose_language=False, dialog=None, terminal="xterm-256color", dns_warning=False,
                   apt_backports=""):
        with tempfile.TemporaryDirectory(prefix="sitekit-wizard-test-") as temporary:
            root = Path(temporary)
            trace, args, tempfile_record = root / "trace", root / "args", root / "tempfile"
            env = {**os.environ, "TEST_TRACE": str(trace), "TEST_ARGS": str(args),
                   "TEST_TEMPFILE": str(tempfile_record), "TEST_VERIFY": verify,
                   "TEST_CHILD_EXIT": str(child_exit), "PYTHONDONTWRITEBYTECODE": "1", "TERM": terminal,
                   "TEST_APT_BACKPORTS": apt_backports, "TEST_DNS_WARNING": "1" if dns_warning else "0"}
            invocation = list(arguments)
            if "--lang" not in invocation and not choose_language:
                invocation[:0] = ["--lang", "en"]
            if "--ui" not in invocation:
                invocation[:0] = ["--ui", "dialog" if dialog is not None else "text"]
            calls_path = root / "dialog-calls"
            responses_path = root / "dialog-responses"
            if dialog is not None:
                binary = root / "bin"
                binary.mkdir()
                fake = binary / "whiptail"
                fake.write_text(FAKE_WHIPTAIL)
                fake.chmod(0o755)
                responses_path.write_text(json.dumps(dialog))
                env.update({"PATH": str(binary) + os.pathsep + env["PATH"],
                            "TEST_DIALOG_CALLS": str(calls_path),
                            "TEST_DIALOG_RESPONSES": str(responses_path)})
            master, slave = pty.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
            settings = termios.tcgetattr(slave)
            settings[3] &= ~termios.ECHO
            termios.tcsetattr(slave, termios.TCSANOW, settings)
            def attach_terminal():
                signal.signal(signal.SIGINT, signal.SIG_DFL)
                signal.signal(signal.SIGTERM, signal.SIG_DFL)
                os.setsid()
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
            process = subprocess.Popen(["bash", "-c", HARNESS, "wizard-fixture", str(SCRIPT), *invocation],
                                       stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=attach_terminal)
            os.close(slave)
            output = bytearray()
            try:
                if lines:
                    os.write(master, ("\n".join(lines) + "\n").encode())
                if eof:
                    os.write(master, b"\x04")
                deadline = time.monotonic() + 8
                sent_interrupt = False
                while time.monotonic() < deadline:
                    ready, _, _ = select.select([master], [], [], 0.05)
                    if ready:
                        try:
                            chunk = os.read(master, 65536)
                        except OSError as exc:
                            if exc.errno == errno.EIO:
                                break
                            raise
                        if not chunk:
                            break
                        output.extend(chunk)
                    if interrupt and not sent_interrupt and b"Domain" in output:
                        os.write(master, b"\x03")  # Real foreground-terminal Ctrl-C.
                        sent_interrupt = True
                    if process.poll() is not None and not ready:
                        break
                if process.poll() is None:
                    try:
                        process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        self.fail("Wizard did not finish before the fixture deadline:\n" + output.decode(errors="replace"))
                result = process.returncode
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
                os.close(master)
            actions = trace.read_text().splitlines() if trace.exists() else []
            argv = [item.decode() for item in args.read_bytes().split(b"\0")[:-1]] if args.exists() else []
            downloaded = Path(tempfile_record.read_text()) if tempfile_record.exists() else None
            if downloaded is not None:
                self.assertFalse(downloaded.parent.exists(), "Private temporary download directory was not removed")
            self.dialog_calls = [json.loads(line) for line in calls_path.read_text().splitlines()] if calls_path.exists() else []
            self.dialog_remaining = json.loads(responses_path.read_text()) if responses_path.exists() else []
            return result, output.decode(errors="replace"), actions, argv

    def test_defaults_preview_is_read_only_and_command_is_safely_quoted(self):
        status, output, actions, _ = self.run_wizard([DOMAIN, "owner@example.com", "", "", "", "y", "y"])
        self.assertEqual(status, 0, output)
        self.assertEqual(actions, ["dns:" + DOMAIN])
        command = next(line.strip() for line in output.splitlines() if line.startswith("  bash "))
        arguments = shlex.split(command)
        self.assertEqual(arguments[:2], ["bash", "./install.sh"])
        for option, value in (("--panel-access", "ssh"), ("--site-theme", "auto"), ("--transport", "xhttp"),
                              ("--bind-ip", ADDRESS), ("--repository", "mountdevhands/3x-ui-sitekit")):
            self.assertEqual(arguments[arguments.index(option) + 1], value)
        self.assertIn("No files downloaded", output)
        self.assertIn("Release:", output)

    def test_backports_requires_consent_is_in_review_and_reaches_only_confirmed_install(self):
        location = "/etc/apt/sources.list.d/ubuntu.sources (stanza at line 1)"
        status, output, actions, args = self.run_wizard([""], arguments=(), apt_backports=location)
        self.assertEqual((status, actions, args), (0, [], []))
        self.assertIn("outside the verified SiteKit package set", output)
        self.assertIn(location, output)
        answers = ["y", DOMAIN, "owner@example.com", "", "", "", "y"]
        for arguments, confirmation in ((('--dry-run',), 'y'), ((), '')):
            status, output, actions, args = self.run_wizard([*answers, confirmation], arguments=arguments,
                                                            apt_backports=location)
            self.assertEqual((status, actions, args), (0, ["dns:" + DOMAIN], []))
            self.assertIn("APT during installation: back up original files and disable only resolute-backports", output)
            if arguments:
                self.assertIn("--disable-apt-backports", output)
        status, output, actions, args = self.run_wizard([*answers, "y"], arguments=(), verify="pass",
                                                        apt_backports=location)
        self.assertEqual(status, 0, output)
        self.assertEqual(args.count("--disable-apt-backports"), 1)
        self.assertEqual(actions[-3:], ["mktemp", "download", "execute"])

    def test_https_allowlist_normalizes_deduplicates_and_keeps_actual_arguments(self):
        status, output, actions, argv = self.run_wizard(
            [DOMAIN, "owner@example.com", "https", "198.51.100.9/24,198.51.100.0/24 203.0.113.8", "palettes", "ws", "yes", "yes"],
            arguments=("--lang", "ru"), verify="pass")
        self.assertEqual(status, 0, output)
        self.assertEqual(actions, ["dns:" + DOMAIN, "mktemp", "download", "execute"])
        self.assertEqual([argv[index + 1] for index, item in enumerate(argv) if item == "--panel-allow"],
                         ["198.51.100.0/24", "203.0.113.8"])
        self.assertEqual(argv[argv.index("--transport") + 1], "ws")
        self.assertIn("без SSH-туннеля", output)

    def test_invalid_input_is_correctable_and_metacharacters_are_never_executed(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "must-not-exist"
            payload = "$(touch " + str(target) + ")"
            status, output, actions, _ = self.run_wizard([
                payload, DOMAIN, "owner@example.com;" + payload, "owner@example.com", "https",
                "198.51.100.7;" + payload, "198.51.100.7", "wrong-theme", "", "wrong-transport", "", "y", "y",
            ])
            self.assertEqual(status, 0, output)
            self.assertFalse(target.exists())
            self.assertEqual(actions, ["dns:" + DOMAIN])
            self.assertIn("valid DNS name", output)
            self.assertIn("valid unquoted email", output)

    def test_blank_email_needs_explicit_consent(self):
        for consent, next_lines, expected in (("", ["owner@example.com"], "--email owner@example.com"),
                                               ("yes", [], "--acme-no-email")):
            with self.subTest(consent=consent):
                status, output, actions, _ = self.run_wizard([DOMAIN, "", consent, *next_lines, "", "", "", "y", "y"])
                self.assertEqual(status, 0, output)
                self.assertIn("WITHOUT an email address", output)
                self.assertIn(expected, output)
                self.assertNotIn(r"\x27", output)
                self.assertEqual(actions, ["dns:" + DOMAIN])

    def test_terms_summary_eof_and_interrupt_cancel_without_downloads(self):
        cases = ([DOMAIN, "owner@example.com", "", "", "", ""],
                 [DOMAIN, "owner@example.com", "", "", "", "y", ""])
        for lines in cases:
            with self.subTest(lines=lines):
                status, output, actions, _ = self.run_wizard(lines, arguments=())
                self.assertEqual(status, 0, output)
                self.assertEqual(actions, ["dns:" + DOMAIN])
        for kind in ("eof", "interrupt"):
            with self.subTest(kind=kind):
                status, output, actions, _ = self.run_wizard([], arguments=(), eof=kind == "eof", interrupt=kind == "interrupt")
                self.assertEqual(status, 130, output)
                self.assertEqual(actions, [])

    def test_hash_mismatch_never_executes_and_child_status_is_propagated(self):
        lines = [DOMAIN, "owner@example.com", "", "", "", "y", "y"]
        status, output, actions, argv = self.run_wizard(lines, arguments=())
        self.assertEqual(status, 1, output)
        self.assertNotIn("execute", actions)
        self.assertEqual(argv, [])
        self.assertIn("SHA-256 mismatch", output)
        status, output, actions, argv = self.run_wizard(lines, arguments=(), verify="pass", child_exit=37)
        self.assertEqual(status, 37, output)
        self.assertEqual(actions[-1], "execute")
        self.assertNotIn("Installed.", output)

    def test_dns_failure_allows_change_or_cancel_before_other_questions(self):
        status, output, actions, _ = self.run_wizard(["bad.example.test", "c", DOMAIN, "owner@example.com", "", "", "", "y", "y"])
        self.assertEqual(status, 0, output)
        self.assertEqual(actions, ["dns:bad.example.test", "dns:" + DOMAIN])
        status, output, actions, _ = self.run_wizard(["bad.example.test", "q"], arguments=())
        self.assertEqual(status, 0, output)
        self.assertNotIn("Certificate email", output)
        self.assertEqual(actions, ["dns:bad.example.test"])


    def test_language_selection_defaults_to_english_and_numeric_menus_work(self):
        status, output, actions, _ = self.run_wizard(
            ['', DOMAIN, 'owner@example.com', '2', '', '4', '2', 'yes', 'yes'], choose_language=True)
        self.assertEqual(status, 0, output)
        self.assertIn('English  [default]', output)
        self.assertIn('[1 / 6  Domain and DNS]', output)
        self.assertIn('[6 / 6  Review and install]', output)
        self.assertIn('--panel-access https', output)
        self.assertIn('--site-theme palettes', output)
        self.assertIn('--transport ws', output)
        self.assertEqual(actions, ['dns:' + DOMAIN])
        status, output, actions, _ = self.run_wizard(
            ['2', DOMAIN, 'owner@example.com', '', '', '', 'да', 'да'], choose_language=True)
        self.assertEqual(status, 0, output)
        self.assertIn('Настройте свой сервер', output)
        self.assertIn('[1 / 6  Домен и DNS]', output)

    def test_real_run_summary_does_not_show_shell_command(self):
        status, output, actions, argv = self.run_wizard(
            [DOMAIN, 'owner@example.com', '', '', '', 'y', 'y'], arguments=(), verify='pass')
        self.assertEqual(status, 0, output)
        self.assertNotIn('  bash ', output)
        self.assertNotIn('--agree-tos', output)
        self.assertEqual(actions[-1], 'execute')
        self.assertIn('--agree-tos', argv)

    def test_dialog_flow_uses_widgets_and_default_no_confirmations(self):
        dialogs = [
            ('menu', 'en', 0), ('msgbox', '', 0),
            ('inputbox', DOMAIN, 0), ('inputbox', 'owner@example.com', 0),
            ('menu', 'https', 0), ('inputbox', '', 0),
            ('menu', 'auto', 0), ('menu', 'xhttp', 0),
            ('yesno', '', 0), ('yesno', '', 0), ('msgbox', '', 0),
        ]
        status, output, actions, argv = self.run_wizard([], arguments=(), verify='pass',
                                                       choose_language=True, dialog=dialogs)
        self.assertEqual(status, 0, output)
        self.assertEqual(self.dialog_remaining, [])
        self.assertEqual(actions, ['dns:' + DOMAIN, 'mktemp', 'download', 'execute'])
        self.assertEqual(argv[argv.index('--panel-access') + 1], 'https')
        self.assertNotIn('--panel-allow', argv)
        calls = self.dialog_calls
        self.assertEqual(calls[0]['widget'], 'menu')
        self.assertEqual(calls[0]['argv'][calls[0]['argv'].index('--default-item') + 1], 'en')
        self.assertTrue(any(call['widget'] == 'infobox' for call in calls))
        confirms = [call for call in calls if call['widget'] == 'yesno']
        self.assertEqual(len(confirms), 2)
        self.assertTrue(all('--defaultno' in call['argv'] for call in confirms))
        summary = confirms[-1]['argv'][confirms[-1]['argv'].index('--yesno') + 1]
        self.assertIn('HTTPS link in your browser', summary)
        self.assertIn('Any IP, with login and password', summary)
        self.assertNotIn('bash ', summary)
        self.assertTrue(all('--default-item' not in call['argv'] or '--menu' in call['argv'] for call in calls))

    def test_dialog_explicit_russian_skips_language_and_cancel_or_escape_is_clean(self):
        for status_code, expected in ((1, 0), (255, 130), (130, 130)):
            with self.subTest(status=status_code):
                status, output, actions, argv = self.run_wizard([], arguments=('--lang', 'ru'),
                    dialog=[('msgbox', '', 0), ('inputbox', '', status_code)])
                self.assertEqual(status, expected, output)
                self.assertEqual(actions, [])
                self.assertEqual(argv, [])
                self.assertEqual(self.dialog_calls[0]['widget'], 'msgbox')
                self.assertIn('Добро пожаловать', ' '.join(self.dialog_calls[0]['argv']))
        status, output, actions, _ = self.run_wizard([], arguments=(), choose_language=True,
                                                   dialog=[('menu', '', 255)])
        self.assertEqual(status, 130, output)
        self.assertEqual(actions, [])

    def test_dialog_declined_terms_never_downloads_and_error_never_silently_accepts(self):
        dialogs = [
            ('msgbox', '', 0), ('inputbox', DOMAIN, 0), ('inputbox', 'owner@example.com', 0),
            ('menu', 'ssh', 0), ('menu', 'auto', 0), ('menu', 'xhttp', 0), ('yesno', '', 1),
        ]
        status, output, actions, _ = self.run_wizard([], arguments=(), dialog=dialogs)
        self.assertEqual(status, 0, output)
        self.assertEqual(actions, ['dns:' + DOMAIN])
        status, output, actions, _ = self.run_wizard([], arguments=(), dialog=[('msgbox', '', 2)])
        self.assertEqual(status, 2, output)
        self.assertEqual(actions, [])
        self.assertIn('--ui text', output)

    def test_dialog_success_screen_escape_keeps_install_success_and_instructions(self):
        dialogs = [
            ('msgbox', '', 0), ('inputbox', DOMAIN, 0), ('inputbox', 'owner@example.com', 0),
            ('menu', 'ssh', 0), ('menu', 'auto', 0), ('menu', 'xhttp', 0),
            ('yesno', '', 0), ('yesno', '', 0), ('msgbox', '', 255),
        ]
        status, output, actions, _ = self.run_wizard([], arguments=(), verify='pass', dialog=dialogs)
        self.assertEqual(status, 0, output)
        self.assertEqual(actions[-1], 'execute')
        self.assertIn('cat /root/https-node-access.txt', output)
        self.assertNotIn('No installation was started', output)

    def test_dns_warning_is_shown_and_does_not_corrupt_bind_ip(self):
        status, output, actions, argv = self.run_wizard(
            [DOMAIN, 'owner@example.com', '', '', '', 'y', 'y'],
            arguments=(), verify='pass', dns_warning=True)
        self.assertEqual(status, 0, output)
        self.assertIn('only Google', output)
        self.assertEqual(argv[argv.index('--bind-ip') + 1], ADDRESS)


    def test_dialog_unavailable_terminal_and_auto_fallback(self):
        status, output, actions, _ = self.run_wizard([], arguments=('--ui', 'dialog'),
                                                   terminal='dumb', dialog=[])
        self.assertEqual(status, 2, output)
        self.assertEqual(actions, [])
        self.assertIn('72 columns by 22 rows', output)
        status, output, actions, _ = self.run_wizard(
            [DOMAIN, 'owner@example.com', '', '', '', 'y', 'y'],
            arguments=('--ui', 'auto', '--dry-run'), terminal='dumb', dialog=[])
        self.assertEqual(status, 0, output)
        self.assertEqual(self.dialog_calls, [])
        self.assertIn('[1 / 6  Domain and DNS]', output)
        self.assertEqual(actions, ['dns:' + DOMAIN])


class SyntheticDNS(unittest.TestCase):
    def response(self, kind, records=(), *, status=0, owner=DOMAIN):
        number = 1 if kind == "A" else 28
        return {"Status": status, "TC": False, "Question": [{"name": DOMAIN + ".", "type": number}],
                "Answer": [{"name": owner + ".", "type": number, "data": address} for address in records]}

    def run_dns(self, replies, *, local=(ADDRESS, "172.17.0.1")):
        calls = []
        def open_response(request, timeout):
            self.assertEqual(timeout, 5)
            url = DNS.urllib.parse.urlsplit(request.full_url)
            self.assertEqual(url.scheme, "https")
            query = DNS.urllib.parse.parse_qs(url.query)
            self.assertEqual(query["name"], [DOMAIN + "."])
            provider = "Cloudflare" if url.hostname == "cloudflare-dns.com" else "Google"
            key = (provider, query["type"][0])
            calls.append(key)
            result = replies[key]
            if isinstance(result, BaseException):
                raise result
            return io.BytesIO(json.dumps(result).encode())
        opener = mock.Mock(open=mock.Mock(side_effect=open_response))
        interface_json = json.dumps([{"addr_info": [{"family": "inet", "local": value}]} for value in local])
        warning = io.StringIO()
        with mock.patch.object(DNS.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, interface_json, "")) as inspect, \
                mock.patch.object(DNS.urllib.request, "build_opener", return_value=opener), contextlib.redirect_stderr(warning):
            result = DNS.check_dns(DOMAIN, "en")
        inspect.assert_called_once_with(["ip", "-j", "-4", "addr", "show", "scope", "global"],
                                        capture_output=True, text=True, check=True, timeout=5)
        return result, warning.getvalue(), calls

    def positive(self):
        return {(provider, kind): self.response(kind, [ADDRESS] if kind == "A" else [])
                for provider in ("Cloudflare", "Google") for kind in ("A", "AAAA")}

    def test_public_interface_matches_and_private_docker_address_is_ignored(self):
        result, warning, calls = self.run_dns(self.positive())
        self.assertEqual(result, ADDRESS)
        self.assertEqual(warning, "")
        self.assertEqual(len(calls), 4)

    def test_unavailable_resolver_requires_one_complete_pair_and_warns(self):
        replies = self.positive()
        replies.update({("Cloudflare", kind): TimeoutError() for kind in ("A", "AAAA")})
        result, warning, _ = self.run_dns(replies)
        self.assertEqual(result, ADDRESS)
        self.assertIn("only Google", warning)
        replies.update({("Google", kind): TimeoutError() for kind in ("A", "AAAA")})
        with self.assertRaisesRegex(DNS.DNSRejected, "Neither resolver"):
            self.run_dns(replies)

    def test_mismatch_aaaa_and_nxdomain_are_not_hidden_by_other_success_or_timeout(self):
        for bad, phrase in ((self.response("A", ["8.8.8.8"]), "server IPv4"),
                            (self.response("A", status=3), "NXDOMAIN")):
            replies = self.positive()
            replies[("Google", "A")] = bad
            replies[("Google", "AAAA")] = TimeoutError()
            with self.subTest(phrase=phrase), self.assertRaisesRegex(DNS.DNSRejected, phrase):
                self.run_dns(replies)
        replies = self.positive()
        replies[("Google", "A")] = TimeoutError()
        replies[("Google", "AAAA")] = self.response("AAAA", ["2001:db8::1"])
        with self.assertRaisesRegex(DNS.DNSRejected, "remove AAAA"):
            self.run_dns(replies)

    def test_question_truncation_unrelated_answers_and_cname_are_checked(self):
        for change in ({"TC": True}, {"TC": 0}, {"TC": None}, {"Question": [{"name": "other.test.", "type": 1}]}):
            replies = self.positive()
            replies[("Cloudflare", "A")] = {**self.response("A", [ADDRESS]), **change}
            replies[("Google", "A")] = TimeoutError()
            with self.subTest(change=change), self.assertRaisesRegex(DNS.DNSRejected, "Neither resolver"):
                self.run_dns(replies)
        replies = self.positive()
        replies[("Google", "A")] = self.response("A", [ADDRESS], owner="unrelated.example.test")
        with self.assertRaisesRegex(DNS.DNSRejected, "exactly one"):
            self.run_dns(replies)
        replies = self.positive()
        for provider in ("Cloudflare", "Google"):
            reply = self.response("A", [ADDRESS], owner="alias.example.test")
            reply["Answer"].append({"name": DOMAIN + ".", "type": 5, "data": "alias.example.test."})
            replies[(provider, "A")] = reply
        self.assertEqual(self.run_dns(replies)[0], ADDRESS)

    def test_deadline_is_not_mislabeled_as_resolver_failure_or_nxdomain(self):
        with mock.patch.object(DNS, "check_dns_queries", side_effect=DNS.DNSDeadline()):
            with self.assertRaisesRegex(DNS.DNSRejected, "exceeded 30 seconds"):
                DNS.check_dns(DOMAIN, "en")


if __name__ == "__main__":
    unittest.main()
