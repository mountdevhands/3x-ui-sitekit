#!/usr/bin/env python3
"""Focused package-policy and nginx-maintenance runtime regressions.

Package/service commands and network probes are strict mocks. All file writes
stay in temporary directories. No real apt, systemd, dpkg, nginx, or VDS runs.
"""

from __future__ import annotations

import argparse
import contextlib
import copy
import importlib
import io
import itertools
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
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
core = importlib.import_module("installer_core")
policy = importlib.import_module("security_policy")
TODAY = "2026-11-23"
INFO = {"ID": "ubuntu", "VERSION_ID": "26.04", "VERSION_CODENAME": "resolute"}
OLD = "1.28.3-2ubuntu1.9"
FIXED = "1.28.3-2ubuntu1.14"
NEWER = "1.28.3-2ubuntu1.15"
OFFICIAL_FILE = "http://security.ubuntu.com/ubuntu resolute-security/main amd64 Packages"
PPA_FILE = "https://ppa.example.invalid/nginx resolute/main amd64 Packages"


def completed(argv, stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


def candidate_policy(package, version=FIXED, *, files=(OFFICIAL_FILE,)):
    sources = "\n".join("        500 " + source for source in files)
    return (f"{package}:\n  Installed: {OLD}\n  Candidate: {version}\n"
            f"  Version table:\n     {version} 500\n{sources}\n"
            f" *** {OLD} 100\n        100 /var/lib/dpkg/status\n")


APT_RELEASES = f"""Package files:
 100 /var/lib/dpkg/status
     release a=now
 500 {OFFICIAL_FILE}
     release v=26.04,o=Ubuntu,a=resolute-security,n=resolute,l=Ubuntu,c=main,b=amd64
     origin security.ubuntu.com
 500 {PPA_FILE}
     release o=LP-PPA-example-nginx,a=resolute,n=resolute,l=example nginx,c=main,b=amd64
     origin ppa.example.invalid
Pinned packages:
"""


class InventoryAndOriginGuards(unittest.TestCase):
    def test_inventory_preserves_full_source_versions_and_surfaces_wrong_source_identity(self):
        stdout = (
            "nginx:amd64\tnginx\t0:1.28.3-2ubuntu1.14\t0:1.28.3-2ubuntu1.14+b1\tii \n"
            "nginx-common\tnginx\t1.28.3-2ubuntu1.14\t1.28.3-2ubuntu1.14\tii \n"
            "certbot\tpython-certbot\t4.0.0-4\t4.0.0-4\tii \n"
            "python3-certbot\tpython-certbot\t4.0.0-4\t4.0.0-4\tiU \n"
            "nginx-core\tvendor-nginx\t1.28.3-2ubuntu1.14\t1.28.3-2ubuntu1.14\tii \n"
            "nginx-light\tnginx\t1.28.3-2ubuntu1.14\t1.28.3-2ubuntu1.14\thi \n"
            "irrelevant\tunrelated\t1.0-1\t1.0-1\tii \n"
        )
        with mock.patch.object(core, "command", return_value=completed([], stdout)) as command:
            rows = core.package_inventory()
        argv = command.call_args.args[0]
        self.assertEqual(argv[:2], ["dpkg-query", "-W"])
        self.assertIn("${source:Version}", argv[2])
        by_name = {row["package"]: row for row in rows}
        self.assertEqual(by_name["nginx:amd64"]["source_version"], "0:1.28.3-2ubuntu1.14")
        self.assertEqual(by_name["nginx:amd64"]["version"], "0:1.28.3-2ubuntu1.14+b1")
        self.assertEqual(by_name["certbot"]["source_package"], "python-certbot")
        self.assertEqual(by_name["nginx-core"]["source_package"], "vendor-nginx",
                         "A tracked binary with a foreign source must reach the policy evaluator")
        self.assertNotIn("irrelevant", by_name)
        self.assertEqual(by_name["python3-certbot"]["status"], "broken")
        self.assertEqual(by_name["nginx-light"]["status"], "installed", "A configured held package remains installed")
        result = policy.evaluate_packages(INFO, rows, lambda *args: True, required_sources=("nginx",), today=TODAY)
        self.assertEqual(result["status"], "UNKNOWN", "Foreign source identity must survive collection and block evaluation")

    def test_reinst_required_is_not_reported_as_fully_installed(self):
        stdout = ("nginx\tnginx\t1.28.3-2ubuntu1.14\t1.28.3-2ubuntu1.14\tiiR\n"
                  "nginx-common\tnginx\t1.28.3-2ubuntu1.14\t1.28.3-2ubuntu1.14\tii \n")
        with mock.patch.object(core, "command", return_value=completed([], stdout)):
            rows = core.package_inventory()
        self.assertEqual(next(row for row in rows if row["package"] == "nginx")["status"], "broken",
                         "dpkg's R error flag requires repair and must not disappear behind nginx-common")
        result = policy.evaluate_packages(INFO, rows, lambda *args: True, required_sources=("nginx",), today=TODAY)
        self.assertEqual(result["status"], "UNKNOWN")

    def test_release_parser_accepts_current_distro_and_rejects_cross_suite_or_ppa(self):
        releases = core.read_apt_releases(APT_RELEASES)
        self.assertEqual(releases[OFFICIAL_FILE]["n"], "resolute")
        self.assertEqual(releases[PPA_FILE]["o"], "LP-PPA-example-nginx")
        self.assertTrue(core.apt_candidate_origin(candidate_policy("nginx"), FIXED, releases, INFO))
        self.assertFalse(core.apt_candidate_origin(candidate_policy("nginx", files=(PPA_FILE,)), FIXED, releases, INFO))
        self.assertFalse(core.apt_candidate_origin(candidate_policy("nginx"), FIXED, releases,
                                                   {"ID": "ubuntu", "VERSION_ID": "24.04"}))
        for pocket in ("bookworm", "bookworm-security", "bookworm-updates"):
            archive = "debian-security" if pocket.endswith("security") else "debian"
            source = f"https://deb.debian.org/{archive} {pocket}/main amd64 Packages"
            release = {source: {"o": "Debian", "l": "Debian-Security" if pocket.endswith("security") else "Debian",
                                "n": pocket, "a": "oldstable-security"}}
            with self.subTest(pocket=pocket):
                self.assertTrue(core.apt_candidate_origin(candidate_policy("nginx", files=(source,)), FIXED, release,
                                                         {"ID": "debian", "VERSION_ID": "12"}))
                self.assertFalse(core.apt_candidate_origin(candidate_policy("nginx", files=(source,)), FIXED, release,
                                                          {"ID": "debian", "VERSION_ID": "13"}))
        cross_suite = copy.deepcopy(releases)
        cross_suite[OFFICIAL_FILE]["n"] = "noble"
        self.assertFalse(core.apt_candidate_origin(candidate_policy("nginx"), FIXED, cross_suite, INFO))

    def test_same_candidate_in_official_and_ppa_origins_is_not_unambiguously_official(self):
        releases = core.read_apt_releases(APT_RELEASES)
        for files in ((OFFICIAL_FILE, PPA_FILE), (PPA_FILE, OFFICIAL_FILE)):
            with self.subTest(files=files):
                self.assertFalse(core.apt_candidate_origin(candidate_policy("nginx", files=files), FIXED, releases, INFO),
                                 "A matching official version must not authorize a different-origin archive with the same version")

    def test_candidate_inventory_reads_exact_source_version_and_stops_at_bad_origin(self):
        calls = []
        source_version = "0:" + FIXED
        binary_version = source_version + "+b2"

        def command(argv, **kwargs):
            calls.append(argv)
            if argv == ["apt-cache", "policy"]:
                return completed(argv, APT_RELEASES)
            if argv == ["apt-cache", "policy", "nginx"]:
                return completed(argv, candidate_policy("nginx", version=binary_version))
            if argv == ["apt-cache", "show", "nginx=" + binary_version]:
                return completed(argv, f"Package: nginx\nVersion: {binary_version}\nArchitecture: amd64\nSource: nginx ({source_version})\n\n")
            raise AssertionError("Unexpected command: " + repr(argv))

        with mock.patch.object(core, "command", side_effect=command):
            rows = core.apt_candidates(["nginx"], INFO)
        self.assertEqual(rows, [{"package": "nginx", "version": binary_version, "source_package": "nginx",
                                "source_version": source_version, "status": "candidate"}])
        bad_policy = candidate_policy("nginx", files=(PPA_FILE,))
        with mock.patch.object(core, "command", side_effect=[completed([], APT_RELEASES), completed([], bad_policy)]) as mocked:
            with self.assertRaisesRegex(core.NodeError, "reviewed distro pocket"):
                core.apt_candidates(["nginx"], INFO)
        self.assertEqual(mocked.call_count, 2, "Bad origin must fail before reading/installing its metadata")

    def test_known_blocked_release_stops_install_before_any_io(self):
        def evaluated(version, digest):
            return policy.evaluate_pinned_release(version, digest, today=TODAY)

        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(core, "evaluate_pinned_release", side_effect=evaluated))
            forbidden = []
            stack.enter_context(mock.patch.object(core, "RELEASE_VERSION", policy.SECURITY_BLOCKED_BUNDLE_VERSION))
            stack.enter_context(mock.patch.object(core, "RELEASE_SHA256", policy.SECURITY_BLOCKED_BUNDLE_SHA256))
            for name in ("command", "preflight", "extract_release", "save_state", "new_state"):
                forbidden.append(stack.enter_context(mock.patch.object(core, name, side_effect=AssertionError("Unexpected I/O path: " + name))))
            forbidden.append(stack.enter_context(mock.patch.object(core.subprocess, "run", side_effect=AssertionError("Unexpected process"))))
            forbidden.append(stack.enter_context(mock.patch.object(core.urllib.request, "urlopen", side_effect=AssertionError("Unexpected network"))))
            forbidden.append(stack.enter_context(mock.patch.object(core.tempfile, "TemporaryDirectory", side_effect=AssertionError("Unexpected filesystem work"))))
            # No option fields: touching args before the release gate would also fail.
            with self.assertRaisesRegex(core.NodeError, "Release security policy"):
                core.install(object())
            for operation in forbidden:
                operation.assert_not_called()


class AptSourceTrustGuards(unittest.TestCase):
    def ubuntu_record(self, **overrides):
        return {
            "uris": "https://archive.ubuntu.com/ubuntu",
            "suites": "resolute resolute-updates resolute-security",
            "signed-by": "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
            **overrides,
        }

    def test_official_archive_uris_with_explicit_distribution_keyrings_pass(self):
        for uri in ("http://archive.ubuntu.com/ubuntu", "https://security.ubuntu.com/ubuntu/",
                    "https://us.archive.ubuntu.com/ubuntu"):
            with self.subTest(uri=uri):
                self.assertTrue(core.approved_archive_uri(uri, INFO))
                self.assertIsNone(core.validate_apt_source_record(self.ubuntu_record(uris=uri), INFO))
        info = {"ID": "debian", "VERSION_ID": "12"}
        for uri in ("https://deb.debian.org/debian", "https://deb.debian.org/debian-security",
                    "http://security.debian.org/debian-security/"):
            with self.subTest(uri=uri):
                self.assertTrue(core.approved_archive_uri(uri, info))
                self.assertIsNone(core.validate_apt_source_record({
                    "uris": uri, "suites": "bookworm bookworm-updates bookworm-security",
                    "signed-by": "/usr/share/keyrings/debian-archive-keyring.gpg",
                }, info))

    def test_foreign_uri_cannot_pass_by_spoofing_official_origin_and_release(self):
        foreign_file = "https://mirror.example.invalid/ubuntu resolute-security/main amd64 Packages"
        releases = {foreign_file: {"o": "Ubuntu", "l": "Ubuntu", "n": "resolute", "a": "resolute-security"}}
        self.assertFalse(core.apt_candidate_origin(candidate_policy("nginx", files=(foreign_file,)), FIXED, releases, INFO))
        for uri in ("https://mirror.example.invalid/ubuntu", "https://ppa.launchpadcontent.net/team/nginx/ubuntu",
                    "https://archive.ubuntu.com.example.invalid/ubuntu"):
            with self.subTest(uri=uri):
                self.assertFalse(core.approved_archive_uri(uri, INFO))
                with self.assertRaisesRegex(core.NodeError, "distro-operated archive"):
                    core.validate_apt_source_record(self.ubuntu_record(uris=uri, origin="Ubuntu", label="Ubuntu"), INFO)

    def test_official_uri_with_different_signing_keyring_is_rejected(self):
        for keyring in ("/etc/apt/trusted.gpg", "/usr/share/keyrings/vendor-archive.gpg",
                        "/usr/share/keyrings/debian-archive-keyring.gpg"):
            with self.subTest(keyring=keyring), self.assertRaisesRegex(core.NodeError, "Signed-By"):
                core.validate_apt_source_record(self.ubuntu_record(**{"signed-by": keyring}), INFO)

    def test_insecure_source_flags_are_rejected_even_with_official_uri_and_key(self):
        for name, value in (("trusted", "yes"), ("allow-insecure", "true"), ("allow-weak", "1"),
                            ("allow-downgrade-to-insecure", "yes"), ("check-valid-until", "no")):
            with self.subTest(option=name), self.assertRaises(core.NodeError):
                core.validate_apt_source_record(self.ubuntu_record(**{name: value}), INFO)

    def test_cross_suite_and_unsigned_legacy_source_records_are_rejected(self):
        for suites in ("noble", "resolute noble-security", "resolute-backports", "testing"):
            with self.subTest(suites=suites), self.assertRaisesRegex(core.NodeError, "outside the reviewed"):
                core.validate_apt_source_record(self.ubuntu_record(suites=suites), INFO)
        unsigned = self.ubuntu_record()
        unsigned.pop("signed-by")
        with self.assertRaisesRegex(core.NodeError, "Signed-By"):
            core.validate_apt_source_record(unsigned, INFO)

    def test_trust_rejection_stops_refresh_before_apt_update_without_io(self):
        with mock.patch.object(core, "os_info", return_value=INFO), \
                mock.patch.object(core, "verify_apt_trust", side_effect=core.NodeError("fixture untrusted source")) as trust, \
                mock.patch.object(core, "command", side_effect=AssertionError("No command may run after rejected trust")) as command:
            with self.assertRaisesRegex(core.NodeError, "fixture untrusted source"):
                core.refresh_apt()
        trust.assert_called_once_with(INFO)
        command.assert_not_called()


class AptSourceFilePreflightGuards(unittest.TestCase):
    """Exercise real source parsing with files rooted in a temporary VPS model."""

    @contextlib.contextmanager
    def sources(self, text, suffix=".sources"):
        with tempfile.TemporaryDirectory(prefix="sitekit-apt-preflight-") as temporary:
            root = Path(temporary).resolve()
            source = root / ("etc/apt/sources.list.d/ubuntu" + suffix)
            source.parent.mkdir(parents=True)
            source.write_text(text, encoding="utf-8")
            source.chmod(0o644)
            keyring = root / "usr/share/keyrings/ubuntu-archive-keyring.gpg"
            keyring.parent.mkdir(parents=True)
            keyring.write_bytes(b"fixture archive keyring")
            keyring.chmod(0o644)
            (root / "run/systemd/system").mkdir(parents=True)
            (root / "root").mkdir()
            original_stat = Path.stat
            calls = []

            def owned_stat(path, *args, **kwargs):
                values = list(original_stat(path, *args, **kwargs))
                values[4] = 0  # Model root ownership on unprivileged CI runners.
                return os.stat_result(values)

            def rooted(path):
                path = Path(path)
                return path if path.is_relative_to(root) else root / path.relative_to("/")

            def command(argv, **kwargs):
                calls.append(argv)
                if argv == ["apt-config", "dump"]:
                    return completed(argv)
                if argv == ["dpkg-query", "-S", str(keyring)]:
                    return completed(argv, "ubuntu-keyring: " + str(keyring))
                if argv == ["dpkg", "--verify", "ubuntu-keyring"]:
                    return completed(argv)
                if argv in (["getent", "passwd", core.USER], ["getent", "group", core.USER]):
                    return completed(argv, returncode=2)
                raise AssertionError("Unexpected external command: " + repr(argv))

            with mock.patch.object(core, "Path", side_effect=rooted), \
                    mock.patch.object(Path, "stat", new=owned_stat), \
                    mock.patch.object(core, "command", side_effect=command), \
                    mock.patch.dict(os.environ, {}, clear=True):
                yield root, source, calls

    def deb822(self, suites="resolute resolute-updates resolute-security"):
        return ("Types: deb\nURIs: http://nl.archive.ubuntu.com/ubuntu\n"
                + "Suites: " + suites + "\nComponents: main universe\n"
                + "Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n")

    def test_backports_in_multiline_suites_reports_file_without_rewriting_it(self):
        content = self.deb822("resolute resolute-updates\n resolute-backports")
        with self.sources(content) as (_, source, calls):
            with self.assertRaises(core.NodeError) as rejected:
                core.verify_apt_trust(INFO)
            self.assertIn(str(source), str(rejected.exception))
            self.assertIn("resolute-backports", str(rejected.exception))
            self.assertIn("--disable-apt-backports", str(rejected.exception))
            self.assertEqual(source.read_text(encoding="utf-8"), content)
            self.assertEqual(calls, [["apt-config", "dump"]])

    def test_backports_legacy_source_reports_exact_line(self):
        content = ("# fixture\n\n"
                   "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] "
                   "http://nl.archive.ubuntu.com/ubuntu resolute-backports main\n")
        with self.sources(content, ".list") as (_, source, calls):
            with self.assertRaises(core.NodeError) as rejected:
                core.verify_apt_trust(INFO)
            self.assertIn(str(source) + ":3", str(rejected.exception))
            self.assertIn("resolute-backports", str(rejected.exception))
            self.assertEqual(source.read_text(encoding="utf-8"), content)
            self.assertEqual(calls, [["apt-config", "dump"]])

    def test_disabled_backports_and_commented_legacy_sources_are_ignored(self):
        content = self.deb822() + "\n" + self.deb822("resolute-backports") + "Enabled: no\n"
        with self.sources(content) as (_, source, calls):
            legacy = source.with_name("disabled.list")
            legacy.write_text("# deb http://example.invalid/ubuntu resolute-backports main\n", encoding="utf-8")
            self.assertIsNone(core.verify_apt_trust(INFO))
            self.assertEqual(source.read_text(encoding="utf-8"), content)
            self.assertEqual([argv[0] for argv in calls], ["apt-config", "dpkg-query", "dpkg"])

    def test_changes_only_the_pocket_in_mixed_standalone_and_disabled_stanzas(self):
        mixed = self.deb822("resolute\n resolute-backports\n resolute-updates")
        standalone = self.deb822("resolute-backports")
        disabled = standalone + "Enabled: no\n"
        already_disabled = [standalone + f"Enabled: {value}\n" for value in ("no", "off", "0x0")]
        security = self.deb822("resolute-security")
        original = "\n".join((mixed, standalone, *already_disabled, security))
        with self.sources(original) as (root, source, _), mock.patch.object(core.os, "fchown"):
            legacy = source.with_name("ubuntu-legacy.list")
            line = "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu "
            old_list = line + "resolute-backports main # retain this comment\n" + line + "resolute main\n"
            legacy.write_text(old_list)
            changes = core.apt_backports_plan(INFO)
            self.assertEqual(set(changes), {source, legacy})
            self.assertEqual(source.read_text(), original)
            self.assertEqual(legacy.read_text(), old_list)
            core.apply_apt_backports(INFO)
            self.assertEqual(source.read_text(), "\n".join((mixed.replace(" resolute-backports\n", ""),
                                                           disabled, *already_disabled, security)))
            self.assertEqual(legacy.read_text(), "# Disabled by SiteKit: " + old_list)
            backup, = (root / "root").glob("sitekit-apt-backports.*")
            self.assertEqual((backup / "sources.list.d" / source.name).read_text(), original)
            self.assertEqual((backup / "sources.list.d" / legacy.name).read_text(), old_list)
            self.assertEqual(stat.S_IMODE(backup.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(source.stat().st_mode), 0o644)
            self.assertEqual(core.apt_backports_plan(INFO), {})

    def test_restores_original_files_if_post_edit_trust_verification_fails(self):
        original = self.deb822("resolute resolute-backports")
        actual_verify = core.verify_apt_trust
        with self.sources(original) as (root, source, _), mock.patch.object(core.os, "fchown"):
            legacy = source.with_name("ubuntu-legacy.list")
            line = "deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] http://archive.ubuntu.com/ubuntu resolute-backports main\n"
            legacy.write_text(line)

            def reject_after_writes(info, *, planned=None):
                actual_verify(info, planned=planned)
                if planned is None:
                    self.assertNotEqual(source.read_text(), original)
                    self.assertNotEqual(legacy.read_text(), line)
                    raise core.NodeError("fixture rejected updated sources")

            with mock.patch.object(core, "verify_apt_trust", side_effect=reject_after_writes):
                with self.assertRaisesRegex(core.NodeError, "fixture rejected"):
                    core.apply_apt_backports(INFO)
            self.assertEqual(source.read_text(), original)
            self.assertEqual(legacy.read_text(), line)
            self.assertEqual(len(list((root / "root").glob("sitekit-apt-backports.*"))), 1)

    def test_opt_in_refuses_other_suites_and_external_backports_before_editing(self):
        for content, message in (
            (self.deb822("resolute resolute-backports resolute-proposed"), "resolute-proposed"),
            (self.deb822("resolute-backports").replace("nl.archive.ubuntu.com", "vendor.example"), "archive URI"),
            (self.deb822("resolute resolute-backports") + " # part of Signed-By\n", "Signed-By"),
            (self.deb822("resolute resolute-backports"), "linked APT source"),
        ):
            with self.subTest(message=message), self.sources(content) as (root, source, _):
                if message == "linked APT source":
                    source.with_name("other-copy").hardlink_to(source)
                with self.assertRaisesRegex(core.NodeError, message):
                    core.apply_apt_backports(INFO)
                self.assertEqual(source.read_text(), content)
                self.assertEqual(list((root / "root").iterdir()), [])

    def test_backports_stops_real_install_preflight_before_any_managed_write(self):
        args = argparse.Namespace(domain="example.com", bind_ip=None, reuse_stock_nginx=False,
                                  release_archive="unused.tar.gz", agree_tos=True,
                                  email="owner@example.com", acme_no_email=False)
        with self.sources(self.deb822("resolute resolute-backports")) as (root, _, calls), \
                contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(core, "ETC", root / "etc/https-node"))
            stack.enter_context(mock.patch.object(core, "OWNED_PATHS", (root / "etc/https-node",)))
            stack.enter_context(mock.patch.object(core, "UNIT_DIR", root / "etc/systemd/system"))
            stack.enter_context(mock.patch.object(core, "require_release_policy"))
            stack.enter_context(mock.patch.object(core.os, "geteuid", return_value=0))
            stack.enter_context(mock.patch.object(core, "os_info", return_value=INFO))
            stack.enter_context(mock.patch.object(core.platform, "machine", return_value="x86_64"))
            stack.enter_context(mock.patch.object(core.shutil, "which", side_effect=lambda name: name if name != "nginx" else None))
            forbidden = []
            for name in ("new_state", "save_state", "extract_release", "verify_public_dns"):
                forbidden.append(stack.enter_context(mock.patch.object(core, name, side_effect=AssertionError(name))))
            forbidden.append(stack.enter_context(mock.patch.object(core.tempfile, "TemporaryDirectory", side_effect=AssertionError("release workspace"))))
            with self.assertRaisesRegex(core.NodeError, "resolute-backports"):
                core.install(args)
            self.assertFalse((root / "etc/https-node").exists())
            self.assertEqual(calls, [["getent", "passwd", core.USER], ["getent", "group", core.USER],
                                     ["apt-config", "dump"]])
            for operation in forbidden:
                operation.assert_not_called()


class MaintenanceFixture:
    """A running node model; every external command has an explicit handler."""

    def __init__(self, root, *, current=OLD, after=FIXED, planned=True, extra_plan=False,
                 extra_config=False, running_current=True, same_pid=False, cleanup_fail=False):
        self.root = root
        self.current, self.after = current, after
        self.planned, self.extra_plan = planned, extra_plan
        self.extra_config, self.cleanup_fail = extra_config, cleanup_fail
        self.running_current, self.same_pid = running_current, same_pid
        self.installed, self.restarted = False, False
        self.calls = []
        self.etc = root / "etc"
        self.units = root / "units"
        self.site = root / "site"
        for directory in (self.etc, self.units, self.site / "assets"):
            directory.mkdir(parents=True)
        self.state = {"format": "https-node-v1", "domain": "node.example.org", "status": "ready", "stage": "complete",
                      "release_version": core.RELEASE_VERSION, "release_sha256": core.RELEASE_SHA256,
                      "uuid": "fixture-identity", "panel_password": "fixture-private-password", "site_profile": {"seed": "a" * 64}}
        self.state_file = self.etc / "state.json"
        self.state_file.write_text(json.dumps(self.state, indent=2) + "\n")
        self.state_file.chmod(0o600)
        self.access = root / "access.txt"
        self.access.write_text("fixture credentials and VLESS identity\n")
        self.access.chmod(0o600)
        (self.etc / "nginx.conf").write_text("# managed fixture config\n")
        (self.units / core.NGINX_SERVICE).write_text("[Service]\nLimitNOFILE=65536\n")
        (self.site / "index.html").write_text("<!doctype html><title>Persisted site</title><p>Existing content</p>")
        (self.site / "assets/style.css").write_text("body { color: #123; }\n")
        self.protected = {path: path.read_bytes() for path in (
            self.state_file, self.access, self.etc / "nginx.conf", self.units / core.NGINX_SERVICE,
            self.site / "index.html", self.site / "assets/style.css")}

    def path(self, *args):
        if len(args) == 1 and str(args[0]) == "/run/systemd/system/nginx.service":
            return self.root / "stock-runtime-service"
        return Path(*args)

    def samefile(self, left, right):
        expected_pid = 202 if self.restarted and not self.same_pid else 101
        if str(left) != f"/proc/{expected_pid}/exe" or str(right) != "/usr/sbin/nginx":
            raise AssertionError("Unexpected executable comparison")
        return True if self.restarted else self.running_current

    def readlink(self, path, *args, **kwargs):
        if str(path) not in {"/proc/101/exe", "/proc/202/exe"}:
            raise AssertionError("Unexpected readlink: " + str(path))
        return "/usr/sbin/nginx"

    def command(self, argv, **kwargs):
        argv = [str(item) for item in argv]
        self.calls.append(argv)
        if argv[:2] == ["dpkg-query", "-W"]:
            version = self.after if self.installed else self.current
            output = "".join(f"{package}\tnginx\t{version}\t{version}\tii \n" for package in ("nginx", "nginx-common"))
            # An independent Certbot blocker must not prevent targeted nginx repair.
            output += "certbot\tpython-certbot\t4.0.0-4\t4.0.0-4\tii \n"
            return completed(argv, output)
        if argv == ["dpkg-query", "-S", "/usr/sbin/nginx"]:
            return completed(argv, "nginx: /usr/sbin/nginx\n")
        if argv == ["dpkg", "--audit"]:
            return completed(argv)
        if argv[:2] == ["dpkg", "--compare-versions"]:
            if len(argv) != 5 or argv[3:] != ["ge", FIXED] or argv[2] not in {OLD, FIXED, NEWER}:
                raise AssertionError("Unexpected comparison: " + repr(argv))
            return completed(argv, returncode=1 if argv[2] == OLD else 0)
        if argv == ["dpkg", "--verify", "nginx"]:
            return completed(argv)
        if argv == ["apt-cache", "policy"]:
            return completed(argv, APT_RELEASES)
        if argv[:2] == ["apt-cache", "policy"] and len(argv) == 3 and argv[2] in {"nginx", "nginx-common"}:
            return completed(argv, candidate_policy(argv[2]))
        if argv[:2] == ["apt-cache", "show"] and len(argv) == 3:
            package, version = argv[2].split("=")
            if package not in {"nginx", "nginx-common"} or version != FIXED:
                raise AssertionError("Unexpected candidate metadata request")
            return completed(argv, f"Package: {package}\nVersion: {FIXED}\nArchitecture: amd64\nSource: nginx ({FIXED})\n\n")
        if argv[0] == "apt-get":
            if "update" in argv:
                if "APT::Update::Error-Mode=any" not in argv:
                    raise AssertionError("Partial apt index failures must fail closed")
                return completed(argv)
            if "--simulate" in argv:
                if "--no-remove" not in argv or "--only-upgrade" not in argv:
                    raise AssertionError("Unsafe apt simulation flags")
                output = ""
                if self.planned:
                    output = "".join(f"Inst {name} [{self.current}] ({FIXED} Ubuntu:26.04/resolute-security [amd64])\n"
                                     for name in ("nginx", "nginx-common"))
                if self.extra_plan:
                    output += "Inst unrelated-package [1.0-1] (2.0-1 foreign [amd64])\n"
                if self.extra_config:
                    output += "Conf unrelated-package (2.0-1 foreign [amd64])\n"
                return completed(argv, output)
            if "install" in argv:
                if ("--no-remove" not in argv or "--only-upgrade" not in argv
                        or argv[-2:] != ["nginx=" + FIXED, "nginx-common=" + FIXED]):
                    raise AssertionError("Unexpected unbounded apt install")
                self.installed = True
                return completed(argv)
        if argv == ["systemctl", "is-enabled", "nginx.service"]:
            if self.cleanup_fail and self.installed:
                return completed(argv, "masked\n", 1)
            return completed(argv, "disabled\n", 1)
        if argv == ["systemctl", "is-active", "nginx.service"]:
            return completed(argv, "inactive\n", 3)
        if argv == ["systemctl", "show", core.NGINX_SERVICE, "--property=MainPID", "--value"]:
            return completed(argv, "202\n" if self.restarted and not self.same_pid else "101\n")
        if argv == ["systemctl", "restart", core.NGINX_SERVICE]:
            self.restarted = True
            return completed(argv)
        if argv == ["systemctl", "unmask", "--runtime", "nginx.service"] and self.cleanup_fail:
            return completed(argv, returncode=1, stderr="Fixture unmask failure\n")
        if argv in (["systemctl", "mask", "--runtime", "nginx.service"],
                    ["systemctl", "unmask", "--runtime", "nginx.service"],
                    ["systemctl", "disable", "--now", "nginx.service"]):
            return completed(argv)
        if argv == ["/usr/sbin/nginx", "-t", "-c", str(self.etc / "nginx.conf")]:
            return completed(argv)
        raise AssertionError("Unexpected external command: " + repr(argv))

    @contextlib.contextmanager
    def active(self):
        with contextlib.ExitStack() as stack:
            for name, value in {"ETC": self.etc, "STATE_FILE": self.state_file, "ACCESS": self.access,
                                "SITE": self.site, "UNIT_DIR": self.units,
                                "CHECKPOINT_ROOT": self.root / "checkpoints", "MAINTENANCE_LOCK": self.root / "maintenance.lock"}.items():
                stack.enter_context(mock.patch.object(core, name, value))
            stack.enter_context(mock.patch.object(core, "Path", side_effect=self.path))
            stack.enter_context(mock.patch.object(core, "command", side_effect=self.command))
            stack.enter_context(mock.patch.object(core.subprocess, "run", side_effect=AssertionError("Real subprocess prohibited")))
            stack.enter_context(mock.patch.object(core.urllib.request, "urlopen", side_effect=AssertionError("Real network prohibited")))
            stack.enter_context(mock.patch.object(core.os, "geteuid", return_value=0))
            stack.enter_context(mock.patch.object(core.os, "readlink", side_effect=self.readlink))
            stack.enter_context(mock.patch.object(core.os.path, "samefile", side_effect=self.samefile))
            clock = itertools.count(0, 5)
            stack.enter_context(mock.patch.object(core.time, "monotonic", side_effect=lambda: next(clock)))
            stack.enter_context(mock.patch.object(core.time, "sleep"))
            stack.enter_context(mock.patch.object(core, "os_info", return_value=INFO))
            self.trust_probe = stack.enter_context(mock.patch.object(core, "verify_apt_trust"))
            stack.enter_context(mock.patch.object(core, "load_state", side_effect=lambda: json.loads(self.state_file.read_text())))
            stack.enter_context(mock.patch.object(core, "verify_policy_freshness", side_effect=lambda: policy.verify_policy_freshness(TODAY)))
            stack.enter_context(mock.patch.object(core, "evaluate_packages",
                                                 side_effect=lambda *args, **kwargs: policy.evaluate_packages(*args, **kwargs, today=TODAY)))
            self.tls_probe = stack.enter_context(mock.patch.object(core, "final_tls_probe"))
            self.private_probe = stack.enter_context(mock.patch.object(core, "ensure_private_listeners"))
            for name in ("new_state", "save_state", "populate_site", "bootstrap_panel", "install_units", "extract_release"):
                stack.enter_context(mock.patch.object(core, name, side_effect=AssertionError("Reinstall path prohibited: " + name)))
            self.output = io.StringIO()
            stack.enter_context(contextlib.redirect_stdout(self.output))
            yield self

    def update(self):
        core.update_nginx(argparse.Namespace(confirm_domain=self.state["domain"]))

    def assert_protected_unchanged(self, testcase):
        for path, before in self.protected.items():
            testcase.assertEqual(path.read_bytes(), before, str(path))


class NginxMaintenanceGuards(unittest.TestCase):
    def test_restart_wait_handles_transient_pid_and_proc_races_without_real_sleep(self):
        clock = itertools.count(0, 1)
        with mock.patch.object(core, "managed_nginx_pid", side_effect=[core.NodeError("not ready"), OSError("proc changed"), 101, 202]), \
                mock.patch.object(core.os.path, "samefile", return_value=True) as samefile, \
                mock.patch.object(core.time, "monotonic", side_effect=lambda: next(clock)), \
                mock.patch.object(core.time, "sleep") as sleep:
            self.assertEqual(core.wait_managed_nginx(101), 202)
        samefile.assert_called_once_with(Path("/proc/202/exe"), "/usr/sbin/nginx")
        self.assertEqual(sleep.call_count, 3)

    def test_success_restarts_new_master_and_preserves_identity_site_and_unit(self):
        with tempfile.TemporaryDirectory(prefix="https-node-update-test-") as temporary:
            fixture = MaintenanceFixture(Path(temporary))
            with fixture.active():
                fixture.update()
            self.assertTrue(fixture.installed)
            self.assertTrue(fixture.restarted)
            fixture.assert_protected_unchanged(self)
            self.assertEqual(fixture.tls_probe.call_count, 2)
            self.assertEqual(fixture.private_probe.call_count, 2)
            fixture.trust_probe.assert_called_once_with(INFO)
            self.assertEqual(fixture.calls.count(["systemctl", "restart", core.NGINX_SERVICE]), 1)
            self.assertFalse(any("reload" in argv or core.PANEL_SERVICE in argv for argv in fixture.calls))
            checkpoints = list((fixture.root / "checkpoints").iterdir())
            self.assertEqual(len(checkpoints), 1)
            before = json.loads((checkpoints[0] / "before.json").read_text())
            after = json.loads((checkpoints[0] / "after.json").read_text())
            self.assertEqual((before["master_pid"], after["master_pid"]), (101, 202))
            self.assertEqual(after["site_and_identity"], "unchanged")
            self.assertIn(["systemctl", "unmask", "--runtime", "nginx.service"], fixture.calls)
            self.assertIn(["systemctl", "disable", "--now", "nginx.service"], fixture.calls)

    def test_vulnerable_post_apt_inventory_prevents_restart_and_preserves_node(self):
        with tempfile.TemporaryDirectory(prefix="https-node-update-test-") as temporary:
            fixture = MaintenanceFixture(Path(temporary), after=OLD)
            with fixture.active():
                with self.assertRaisesRegex(core.NodeError, "Installed nginx packages"):
                    fixture.update()
            self.assertTrue(fixture.installed)
            self.assertFalse(fixture.restarted)
            fixture.assert_protected_unchanged(self)
            self.assertNotIn(["dpkg", "--verify", "nginx"], fixture.calls)
            self.assertIn(["systemctl", "unmask", "--runtime", "nginx.service"], fixture.calls)
            self.assertFalse(list((fixture.root / "checkpoints").glob("*/after.json")))

    def test_plan_with_non_nginx_package_prevents_apt_install_and_service_actions(self):
        with tempfile.TemporaryDirectory(prefix="https-node-update-test-") as temporary:
            fixture = MaintenanceFixture(Path(temporary), extra_plan=True)
            with fixture.active():
                with self.assertRaisesRegex(core.NodeError, "outside the nginx source"):
                    fixture.update()
            self.assertFalse(fixture.installed)
            self.assertFalse(fixture.restarted)
            self.assertNotIn(["systemctl", "mask", "--runtime", "nginx.service"], fixture.calls)
            fixture.assert_protected_unchanged(self)
            self.assertTrue(list((fixture.root / "checkpoints").glob("*/apt-plan.txt")))

    def test_conf_only_third_party_plan_is_rejected_before_noop_or_install(self):
        with tempfile.TemporaryDirectory(prefix="https-node-update-test-") as temporary:
            fixture = MaintenanceFixture(Path(temporary), current=FIXED, planned=False, extra_config=True)
            with fixture.active():
                with self.assertRaisesRegex(core.NodeError, "outside the nginx source"):
                    fixture.update()
            self.assertFalse(fixture.installed)
            self.assertFalse(fixture.restarted)
            self.assertNotIn(["systemctl", "mask", "--runtime", "nginx.service"], fixture.calls)
            fixture.assert_protected_unchanged(self)

    def test_post_apt_version_above_floor_but_not_exact_reviewed_target_is_rejected(self):
        with tempfile.TemporaryDirectory(prefix="https-node-update-test-") as temporary:
            fixture = MaintenanceFixture(Path(temporary), after=NEWER)
            with fixture.active():
                with self.assertRaisesRegex(core.NodeError, "reviewed exact apt targets"):
                    fixture.update()
            self.assertTrue(fixture.installed)
            self.assertFalse(fixture.restarted)
            self.assertNotIn(["dpkg", "--verify", "nginx"], fixture.calls)
            self.assertFalse(list((fixture.root / "checkpoints").glob("*/after.json")))
            fixture.assert_protected_unchanged(self)

    def test_cleanup_failure_preserves_original_error_and_checkpoint_without_success(self):
        with tempfile.TemporaryDirectory(prefix="https-node-update-test-") as temporary:
            fixture = MaintenanceFixture(Path(temporary), after=OLD, cleanup_fail=True)
            with fixture.active():
                with self.assertRaisesRegex(core.NodeError, "Installed nginx packages"):
                    fixture.update()
            self.assertTrue(fixture.installed)
            self.assertFalse(fixture.restarted)
            self.assertIn(["systemctl", "disable", "--now", "nginx.service"], fixture.calls,
                          "The second cleanup action must still run after unmask fails")
            self.assertNotIn("nginx package policy, new master executable, HTTPS and unchanged site/identity: PASS",
                             fixture.output.getvalue())
            checkpoints = list((fixture.root / "checkpoints").iterdir())
            self.assertEqual(len(checkpoints), 1)
            self.assertTrue((checkpoints[0] / "before.json").is_file())
            errors = json.loads((checkpoints[0] / "cleanup-errors.json").read_text())
            self.assertIn("systemctl unmask failed", errors)
            self.assertFalse((checkpoints[0] / "after.json").exists())
            fixture.assert_protected_unchanged(self)

    def test_current_fixed_binary_and_empty_plan_is_noop_without_restart(self):
        with tempfile.TemporaryDirectory(prefix="https-node-update-test-") as temporary:
            fixture = MaintenanceFixture(Path(temporary), current=FIXED, planned=False)
            with fixture.active():
                fixture.update()
            self.assertFalse(fixture.installed)
            self.assertFalse(fixture.restarted)
            self.assertIn("no restart needed", fixture.output.getvalue())
            fixture.assert_protected_unchanged(self)
            self.assertNotIn(["systemctl", "mask", "--runtime", "nginx.service"], fixture.calls)
            self.assertEqual(fixture.tls_probe.call_count, 1)

    def test_old_running_inode_is_restarted_even_if_package_plan_is_empty(self):
        with tempfile.TemporaryDirectory(prefix="https-node-update-test-") as temporary:
            fixture = MaintenanceFixture(Path(temporary), current=FIXED, planned=False, running_current=False)
            with fixture.active():
                fixture.update()
            self.assertTrue(fixture.restarted)
            fixture.assert_protected_unchanged(self)

    def test_unchanged_master_pid_after_restart_is_not_reported_as_success(self):
        with tempfile.TemporaryDirectory(prefix="https-node-update-test-") as temporary:
            fixture = MaintenanceFixture(Path(temporary), same_pid=True)
            with fixture.active():
                with self.assertRaisesRegex(core.NodeError, "new master process"):
                    fixture.update()
            self.assertTrue(fixture.restarted)
            self.assertFalse(list((fixture.root / "checkpoints").glob("*/after.json")))
            fixture.assert_protected_unchanged(self)


if __name__ == "__main__":
    unittest.main(verbosity=2)
