"""The pinned downloader never starts system services during these tests."""

import hashlib
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


BOOTSTRAP = Path(__file__).resolve().parents[1] / "install.sh"


def release_constant(name):
    match = re.search(r"^" + re.escape(name) + r"=(['\"]?)([A-Za-z0-9._-]+)\1$",
                      BOOTSTRAP.read_text(), re.MULTILINE)
    if match is None:
        raise ValueError("Missing release constant: " + name)
    return match.group(2)


TAG = release_constant("TAG")
INSTALLER = release_constant("INSTALLER")
RUNTIME = release_constant("RUNTIME")
FIXTURE = r'''
source "$BOOTSTRAP"
INSTALLER_SHA256=$EXPECTED_INSTALLER
RUNTIME_SHA256=$EXPECTED_RUNTIME
mktemp() { command mktemp -d "$TMPDIR/sitekit.XXXXXXXX"; }
check_host() {
    if [[ "$SCENARIO" = unsupported ]]; then
        id() { echo 0; }
        uname() { echo Darwin; }
        # The real gate is exercised in a fresh subprocess below.
        BASH_ENV="$HOST_FIXTURE" bash "$BOOTSTRAP" --repository example/3x-ui-sitekit \
            --domain example.com --acme-no-email --agree-tos
    fi
}
download() {
    printf '%s\n' "$1" >> "$RECORD"
    case "$SCENARIO:${1##*/}" in
        http:*.tar.gz) return 22 ;;
        partial:*.tar.gz) printf x > "$2"; return 18 ;;
        mismatch:*.tar.gz) printf x > "$2"; return 0 ;;
    esac
    cp "$INPUT/${1##*/}" "$2"
}
run_installer() {
    [[ -s "$1" && -s "$6" && "$2" = install && "$3" = --domain && "$4" = example.com && "$5" = --release-archive ]] || return 99
    [[ "$(ls -ld "$(dirname "$1")" | cut -c 1-10)" = drwx------ ]] || return 99
    printf 'ran\n' >> "$RECORD"
    return 7
}
main --repository example/3x-ui-sitekit --domain example.com --acme-no-email --agree-tos
'''


class BootstrapTests(unittest.TestCase):
    def run_fixture(self, scenario):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            (root / INSTALLER).write_bytes(b"python fixture")
            (root / RUNTIME).write_bytes(b"runtime fixture")
            record = root / "log"
            record.touch()
            host_fixture = root / "host"
            host_fixture.write_text("id() { echo 0; }; uname() { echo Darwin; }\n")
            env = {**os.environ, "BOOTSTRAP": str(BOOTSTRAP), "SCENARIO": scenario,
                   "HOST_FIXTURE": str(host_fixture), "INPUT": str(root), "TMPDIR": str(root),
                   "RECORD": str(record),
                   "EXPECTED_INSTALLER": hashlib.sha256(b"python fixture").hexdigest(),
                   "EXPECTED_RUNTIME": hashlib.sha256(b"runtime fixture").hexdigest()}
            result = subprocess.run(["bash", "-c", FIXTURE], env=env, capture_output=True, text=True, timeout=15)
            self.assertEqual(list(root.glob("sitekit.*")), [])
            return result, record.read_text().splitlines()

    def test_exact_release_and_exit_status(self):
        result, lines = self.run_fixture("ok")
        self.assertEqual(result.returncode, 7, result.stderr)
        prefix = "https://github.com/example/3x-ui-sitekit/releases/download/" + TAG + "/"
        self.assertEqual(lines, [prefix + INSTALLER, prefix + RUNTIME, "ran"])

    def test_failed_transfers_or_tampering_do_not_run_installer(self):
        for scenario in ("http", "partial", "mismatch"):
            with self.subTest(scenario=scenario):
                result, lines = self.run_fixture(scenario)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(len(lines), 2)
                self.assertNotIn("ran", lines)

    def test_unsupported_host_is_rejected_before_download(self):
        result, lines = self.run_fixture("unsupported")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Linux amd64", result.stderr)
        self.assertEqual(lines, [])
