#!/usr/bin/env python3
"""Focused local checks for the dated security policy.

Only dpkg's read-only version comparator is invoked. No apt update/install,
network request, service operation, remote host, or persistent write is used.
"""

from __future__ import annotations

import copy
import datetime
import importlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import unittest
from unittest import mock


sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
policy = importlib.import_module("security_policy")
TODAY = "2026-11-23"


def dpkg_compare(left, operation, right):
    result = subprocess.run(
        ["dpkg", "--compare-versions", left, operation, right],
        capture_output=True, text=True, timeout=5, check=False,
    )
    if result.returncode not in (0, 1):
        raise RuntimeError("dpkg comparison failed")
    return result.returncode == 0


def inventory_row(source, version, *, package=None, binary_version=None, status="installed"):
    return {
        "package": package or ("certbot" if source == "python-certbot" else source),
        "version": binary_version or version,
        "source_package": source,
        "source_version": version,
        "status": status,
    }


def evaluate(info, rows, compare=dpkg_compare, *, required=("nginx",), today=TODAY):
    return policy.evaluate_packages(info, rows, compare, required_sources=required, today=today)


class PolicyFreshnessAndIdentity(unittest.TestCase):
    def test_review_window_has_explicit_utc_boundary_and_rejects_clock_errors(self):
        cases = (
            ("2026-11-23", "PASS"),
            (datetime.date(2026, 12, 22), "PASS"),
            ("2026-12-23", "STALE"),
            ("2027-01-01", "STALE"),
            ("2026-11-22", "UNKNOWN"),
            ("2026-02-31", "UNKNOWN"),
            ("20261201", "UNKNOWN"),
            (datetime.datetime(2026, 12, 1), "UNKNOWN"),
            (False, "UNKNOWN"),
            # This local Dec 22 instant is already Dec 23 in UTC.
            (datetime.datetime(2026, 12, 22, 20, tzinfo=datetime.timezone(datetime.timedelta(hours=-5))), "STALE"),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                check = policy.verify_policy_freshness(value)
                self.assertEqual(check["status"], expected)
                self.assertEqual(check["blocking"], expected != "PASS")

    def test_reviewed_archive_is_blocked_and_unknown_identity_is_never_approved(self):
        report = policy.evaluate_pinned_release(
            policy.SECURITY_BLOCKED_BUNDLE_VERSION, policy.SECURITY_BLOCKED_BUNDLE_SHA256, today=TODAY,
        )
        self.assertEqual(report["status"], "BLOCKED")
        self.assertTrue(report["blocking"])
        advisories = [check for check in report["checks"] if check["status"] == "BLOCKED"]
        self.assertEqual({check["code"] for check in advisories},
                         {"bundle_go_stdlib", "bundle_brotli", "bundle_compress"})
        self.assertTrue(all(check["refs"] for check in advisories))
        for version, digest in (
            ("v3.11.0", "0" * 64),
            ("v3.11.1", policy.SECURITY_BLOCKED_BUNDLE_SHA256),
            ("latest", policy.SECURITY_BLOCKED_BUNDLE_SHA256),
            ("v3.11.0", None),
        ):
            with self.subTest(version=version, digest=digest):
                result = policy.evaluate_pinned_release(version, digest, today=TODAY)
                self.assertEqual(result["status"], "UNKNOWN")
                self.assertTrue(result["blocking"])
        # Reports must be JSON data detached from the static review record.
        json.dumps(report)
        advisories[0]["observed"]["panel_go"] = "changed"
        fresh = policy.evaluate_pinned_release("v3.11.0", policy.SECURITY_BLOCKED_BUNDLE_SHA256, today=TODAY)
        self.assertEqual(next(check for check in fresh["checks"] if check["code"] == "bundle_go_stdlib")["observed"]["panel_go"], "1.27.3")


@unittest.skipUnless(shutil.which("dpkg"), "Requires the read-only Debian version comparator")
class PackagePolicyGuards(unittest.TestCase):
    def test_nginx_full_distribution_versions_enforce_security_floors(self):
        cases = (
            ({"ID": "ubuntu", "VERSION_ID": "24.04"}, "1.24.0-2ubuntu7.20", "1.24.0-2ubuntu7.21", "1.24.0-2ubuntu7.22"),
            ({"ID": "ubuntu", "VERSION_ID": "26.04"}, "1.28.3-2ubuntu1.13", "1.28.3-2ubuntu1.14", "1.28.3-2ubuntu1.15"),
            ({"ID": "debian", "VERSION_ID": "12"}, "1.22.1-9+deb12u9", "1.22.1-9+deb12u11", "1.22.1-9+deb12u12"),
            ({"ID": "debian", "VERSION_ID": "13"}, "1.26.3-3+deb13u10", "1.26.3-3+deb13u11", "1.26.3-3+deb13u12"),
        )
        for info, vulnerable, minimum, later in cases:
            for version, status in ((vulnerable, "BLOCKED"), (minimum, "PASS"), (later, "PASS")):
                with self.subTest(info=info, version=version):
                    result = evaluate(info, [inventory_row("nginx", version)])
                    self.assertEqual(result["status"], status)
                    self.assertEqual(result["blocking"], status != "PASS")
                    self.assertTrue(next(check for check in result["checks"] if check["code"] == "package:nginx")["refs"])

    def test_zero_epoch_and_binary_rebuild_work_but_foreign_versions_cannot_bypass_floor(self):
        info = {"ID": "debian", "VERSION_ID": "12", "VERSION_CODENAME": "bookworm"}
        for source, binary in (
            ("0:1.22.1-9+deb12u11", "1.22.1-9+deb12u11"),
            ("1.22.1-9+deb12u11", "1.22.1-9+deb12u11+b2"),
        ):
            with self.subTest(source=source, binary=binary):
                result = evaluate(info, [inventory_row("nginx", source, binary_version=binary)])
                self.assertEqual(result["status"], "PASS")
        unknown_versions = (
            "1:1.22.1-9+deb12u1",  # An inflated epoch must not make a low branch pass.
            "999:1.22.1-9+deb12u11",
            "1.26.3-3+deb13u11",  # Another Debian release.
            "1.22.1-9+deb13u99",  # Correct upstream, wrong distribution suffix.
            "1.24.0-2ubuntu7.99", # Ubuntu package on Debian.
            "1.30.0-1",          # Unreviewed upstream branch.
            "1.22.1-9+deb12u11local1",
            "1.22.1-9+deb12u11~bpo12+1",
            "1.22.1",           # nginx -v is not a full distribution version.
            "1.22.1-9+deb12u11\n",
        )
        comparator = mock.Mock(return_value=True)
        for version in unknown_versions:
            with self.subTest(version=version):
                result = evaluate(info, [inventory_row("nginx", version)], comparator)
                self.assertEqual(result["status"], "UNKNOWN")
                self.assertTrue(result["blocking"])
        comparator.assert_not_called()
        inconsistent = inventory_row("nginx", "1.22.1-9+deb12u11", binary_version="1.22.1-9+deb12u1")
        self.assertEqual(evaluate(info, [inconsistent])["status"], "UNKNOWN")

    def test_certbot_requires_reviewed_backport_and_does_not_block_nginx_only_repair(self):
        cases = (
            ({"ID": "ubuntu", "VERSION_ID": "24.04"}, "2.9.0-1"),
            ({"ID": "ubuntu", "VERSION_ID": "26.04"}, "4.0.0-4"),
            ({"ID": "debian", "VERSION_ID": "12"}, "2.1.0-4"),
            ({"ID": "debian", "VERSION_ID": "13"}, "4.0.0-2+deb13u1"),
        )
        for info, certbot in cases:
            with self.subTest(info=info):
                rule = policy.SECURITY_PACKAGE_RULES[(info["ID"], info["VERSION_ID"])]["nginx"]
                rows = [inventory_row("nginx", rule["minimum"]), inventory_row("python-certbot", certbot)]
                result = evaluate(info, rows, required=("nginx", "certbot"))
                self.assertEqual(result["status"], "BLOCKED")
                self.assertEqual(evaluate(info, rows, required=("nginx",))["status"], "PASS")
                self.assertEqual(evaluate(info, rows, required=("python-certbot",))["status"], "BLOCKED")
                self.assertEqual(evaluate(info, [inventory_row("python-certbot", "5.10.0-1")], required=("certbot",))["status"], "UNKNOWN")
        wrong_source = inventory_row("certbot", "4.0.0-4")
        self.assertEqual(evaluate(cases[1][0], [wrong_source], required=("certbot",))["status"], "UNKNOWN")

    def test_missing_or_inconsistent_inventory_cannot_report_pass(self):
        info = {"ID": "debian", "VERSION_ID": "12"}
        valid = inventory_row("nginx", "1.22.1-9+deb12u11")
        missing_source = copy.deepcopy(valid)
        missing_source.pop("source_version")
        unconfigured = dict(valid, status="unpacked")
        wrong_source = dict(valid, source_package="custom-nginx")
        mixed = [valid, inventory_row("nginx", "1.22.1-9+deb12u11", package="nginx-common", status="candidate")]
        cases = (None, [], [None], [missing_source], [unconfigured], [wrong_source], [valid, valid], mixed)
        for rows in cases:
            with self.subTest(rows=rows):
                report = evaluate(info, rows)
                self.assertEqual(report["status"], "UNKNOWN")
                self.assertTrue(report["blocking"])
        # At the default install gate, omitting Certbot remains a failure.
        self.assertEqual(policy.evaluate_packages(info, [valid], dpkg_compare, today=TODAY)["status"], "UNKNOWN")
        # Multiple binary packages from a source must all meet the floor.
        old_common = inventory_row("nginx", "1.22.1-9+deb12u10", package="nginx-common")
        self.assertEqual(evaluate(info, [valid, old_common])["status"], "BLOCKED")
        self.assertEqual(evaluate(info, [dict(valid, status="candidate")])["status"], "PASS")

    def test_unsupported_os_or_requirement_is_unknown_and_expiry_blocks_valid_inventory(self):
        row = inventory_row("nginx", "1.22.1-9+deb12u11")
        for info in (
            None,
            {"ID": "debian"},
            {"ID": "debian", "VERSION_ID": "14"},
            {"ID": "linuxmint", "VERSION_ID": "12"},
            {"ID": "debian", "VERSION_ID": "12", "VERSION_CODENAME": "trixie"},
        ):
            with self.subTest(info=info):
                self.assertEqual(evaluate(info, [row])["status"], "UNKNOWN")
        info = {"ID": "debian", "VERSION_ID": "12"}
        for required in ((), ("openssl",), ("certbot", "python-certbot"), "nginx"):
            with self.subTest(required=required):
                self.assertEqual(evaluate(info, [row], required=required)["status"], "UNKNOWN")
        stale = evaluate(info, [row], today="2026-12-23")
        self.assertEqual(stale["status"], "STALE")
        self.assertTrue(stale["blocking"])
        json.dumps(stale)

    def test_comparator_errors_are_unknown_and_never_treated_as_success_or_false(self):
        info = {"ID": "debian", "VERSION_ID": "12"}
        row = inventory_row("nginx", "1.22.1-9+deb12u11")
        for comparator in (
            mock.Mock(side_effect=RuntimeError("private diagnostic must not be echoed")),
            mock.Mock(return_value=0),
            mock.Mock(return_value=1),
            mock.Mock(return_value=None),
        ):
            with self.subTest(comparator=comparator):
                result = evaluate(info, [row], comparator)
                self.assertEqual(result["status"], "UNKNOWN")
                self.assertNotIn("private diagnostic", json.dumps(result))
                comparator.assert_called_once_with("1.22.1-9+deb12u11", "ge", "1.22.1-9+deb12u11")


if __name__ == "__main__":
    unittest.main(verbosity=2)
