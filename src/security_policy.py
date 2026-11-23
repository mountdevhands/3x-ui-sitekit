"""Dated, conservative package/release checks for HTTPS Node.

This module performs no network, filesystem, package-manager or service actions.
Inventory collection and package authenticity checks belong to the caller.  A
PASS means only that the supplied inventory meets this curated policy; it is not
a claim that the host, dependencies, or configured service have no vulnerabilities.

Inventory is a list of dictionaries with these string fields::

    package, version, source_package, source_version, status

``version`` is the full binary Debian version; ``source_version`` is the full
source Debian version (including any epoch).  ``status`` is ``installed`` or
``candidate``.  Submit a single phase per call, including the executable-owning
package and other relevant installed/candidate binaries from each required
source.  The caller must not substitute an upstream program's ``--version``.

The comparator is injected: ``compare(left, "ge", right) -> bool``.  A caller
using dpkg must distinguish comparison false (exit 1) from errors (exit >= 2).
All non-PASS results block a new install/update, but evaluating or reporting
them must never itself stop an existing service.
"""

from __future__ import annotations

import datetime as _security_datetime
import re as _security_re


SECURITY_POLICY_ID = "https-node-curated-2026-11-23"
SECURITY_POLICY_REVIEWED_AT = "2026-11-23"
# Expiration is at 00:00 UTC on this date: exactly 30 days after review.
SECURITY_POLICY_VALID_UNTIL = "2026-12-23"
SECURITY_POLICY_SCOPE = (
    "Dated checks for selected Debian source-package versions and explicitly "
    "reviewed release digests. This is not a whole-system vulnerability scan, "
    "an authenticity attestation, or an exploitability assessment."
)

SECURITY_NGINX_UBUNTU_REFS = (
    "https://ubuntu.com/security/notices/USN-9182-1",
)
SECURITY_NGINX_DEBIAN_REFS = (
    "https://security-tracker.debian.org/tracker/source-package/nginx",
)
SECURITY_CERTBOT_REFS = (
    "https://github.com/certbot/certbot/security/advisories/GHSA-9qv6-9g6h-3x7x",
    "https://api.github.com/repos/certbot/certbot/security-advisories/GHSA-9qv6-9g6h-3x7x",
    "https://security-tracker.debian.org/tracker/source-package/python-certbot",
)

# These are reviewed *source* package branches, not upstream version ranges.
# A higher version from another branch, release or nonzero epoch is UNKNOWN;
# it cannot obtain PASS merely by sorting above a distro's security floor.
SECURITY_PACKAGE_RULES = {
    ("ubuntu", "24.04"): {
        "codename": "noble",
        "nginx": {
            "source_package": "nginx",
            "minimum": "1.24.0-2ubuntu7.21",
            "version_pattern": r"1\.24\.0-2ubuntu7(?:\.[0-9]+)*",
            "refs": SECURITY_NGINX_UBUNTU_REFS,
        },
        "certbot": {
            "source_package": "python-certbot",
            "upstream_minimum": "5.10.0",
            "version_pattern": r"2\.9\.0-1(?:ubuntu[0-9]+(?:\.[0-9]+)*)?",
            "fixed_backports": (),
            "refs": SECURITY_CERTBOT_REFS,
        },
    },
    ("ubuntu", "26.04"): {
        "codename": "resolute",
        "nginx": {
            "source_package": "nginx",
            "minimum": "1.28.3-2ubuntu1.14",
            "version_pattern": r"1\.28\.3-2ubuntu1(?:\.[0-9]+)*",
            "refs": SECURITY_NGINX_UBUNTU_REFS,
        },
        "certbot": {
            "source_package": "python-certbot",
            "upstream_minimum": "5.10.0",
            "version_pattern": r"4\.0\.0-4(?:ubuntu[0-9]+(?:\.[0-9]+)*)?",
            "fixed_backports": (),
            "refs": SECURITY_CERTBOT_REFS,
        },
    },
    ("debian", "12"): {
        "codename": "bookworm",
        "nginx": {
            "source_package": "nginx",
            "minimum": "1.22.1-9+deb12u11",
            "version_pattern": r"1\.22\.1-9(?:\+deb12u[0-9]+)?",
            "refs": SECURITY_NGINX_DEBIAN_REFS,
        },
        "certbot": {
            "source_package": "python-certbot",
            "upstream_minimum": "5.10.0",
            "version_pattern": r"2\.1\.0-4(?:\+deb12u[0-9]+)?",
            "fixed_backports": (),
            "refs": SECURITY_CERTBOT_REFS,
        },
    },
    ("debian", "13"): {
        "codename": "trixie",
        "nginx": {
            "source_package": "nginx",
            "minimum": "1.26.3-3+deb13u11",
            "version_pattern": r"1\.26\.3-3(?:\+deb13u[0-9]+)?",
            "refs": SECURITY_NGINX_DEBIAN_REFS,
        },
        "certbot": {
            "source_package": "python-certbot",
            "upstream_minimum": "5.10.0",
            "version_pattern": r"4\.0\.0-2(?:\+deb13u[0-9]+)?",
            "fixed_backports": (),
            "refs": SECURITY_CERTBOT_REFS,
        },
    },
}

SECURITY_SOURCE_ALIASES = {
    "nginx": "nginx", "certbot": "certbot", "python-certbot": "certbot",
}
SECURITY_REAL_SOURCE_NAMES = {"nginx": "nginx", "certbot": "python-certbot"}
SECURITY_BINARY_SOURCES = {
    "nginx": "nginx", "nginx-common": "nginx", "nginx-core": "nginx",
    "nginx-full": "nginx", "nginx-light": "nginx", "nginx-extras": "nginx",
    "certbot": "certbot", "python3-certbot": "certbot",
}

SECURITY_BLOCKED_BUNDLE_VERSION = "v3.11.0"
SECURITY_BLOCKED_BUNDLE_SHA256 = (
    "0ddfa4702f595442e2962acd81addc768fdacaa4ff2672c971a0463dae744916"
)
# A replacement is admitted by a reviewed, exact archive identity only.
SECURITY_LEGACY_BUNDLE = (
    "https-node-0.3.0-rc2-linux-amd64",
    "832452bfe1e36e91e89a478f866d93e972a80a9d9306aa40f8b509f0eb8b8a9b",
)
SECURITY_APPROVED_BUNDLE = (
    "3x-ui-sitekit-0.3.0-rc4-linux-amd64",
    "cb2abb5a45b8eee5d30ad0d4e8de6003b088a943ae8f0c2d32af6fec799e787f",
)
SECURITY_CERTBOT_MANIFEST_SHA256 = "d2a90e1562452a185485161081e91a204367dcd5045291ec348922ec2d5d7689"
SECURITY_APPROVED_BUNDLE_REFS = (
    "https://go.dev/doc/devel/release#go1.27.minor",
    "https://pkg.go.dev/vuln/GO-2026-6859",
    "https://pkg.go.dev/vuln/GO-2026-6888",
    "https://pkg.go.dev/vuln/GO-2026-6865",
    "https://pkg.go.dev/vuln/GO-2026-5932",
    *SECURITY_CERTBOT_REFS,
    "https://openssl-library.org/news/secadv/20261110.txt",
    "https://openssl-library.org/news/secadv/20261117.txt",
)
SECURITY_BLOCKED_BUNDLE_ADVISORIES = (
    {
        "code": "bundle_go_stdlib",
        "observed": {"panel_go": "1.27.3", "xray_go": "1.27.3"},
        "expected": {"minimum_go": "1.27.4"},
        "refs": ("https://pkg.go.dev/vuln/GO-2026-6859",),
    },
    {
        "code": "bundle_brotli",
        "observed": {"panel_brotli": "1.2.6", "xray_brotli": "1.2.3"},
        "expected": {"minimum_brotli": "1.2.7"},
        "refs": ("https://pkg.go.dev/vuln/GO-2026-6888",),
    },
    {
        "code": "bundle_compress",
        "observed": {"xray_compress": "1.20.0"},
        "expected": {"minimum_compress": "1.20.2"},
        "refs": ("https://pkg.go.dev/vuln/GO-2026-6865",),
    },
)


def _security_check(code, status, reason, *, observed=None, expected=None, refs=()):
    return {
        "code": code,
        "status": status,
        "blocking": status != "PASS",
        "reason": reason,
        "observed": observed,
        "expected": expected,
        "refs": list(refs),
    }


def _security_report(checks):
    # Keep a known published blocker visible even when some inventory is missing.
    statuses = {check["status"] for check in checks}
    status = next((value for value in ("BLOCKED", "UNKNOWN", "STALE")
                   if value in statuses), "PASS")
    return {
        "policy_id": SECURITY_POLICY_ID,
        "reviewed_at": SECURITY_POLICY_REVIEWED_AT,
        "valid_until": SECURITY_POLICY_VALID_UNTIL,
        "status": status,
        "blocking": status != "PASS",
        "scope": SECURITY_POLICY_SCOPE,
        "checks": checks,
    }


def verify_policy_freshness(today=None):
    """Return a check; expiration starts at 00:00 UTC on valid_until.

    ``today`` may be a date, timezone-aware datetime, or YYYY-MM-DD string.
    None uses today's UTC date. A clock before the review date is UNKNOWN.
    """
    try:
        if today is None:
            current = _security_datetime.datetime.now(_security_datetime.timezone.utc).date()
        elif isinstance(today, _security_datetime.datetime):
            if today.tzinfo is None:
                raise ValueError("Datetime must include a timezone")
            current = today.astimezone(_security_datetime.timezone.utc).date()
        elif isinstance(today, _security_datetime.date):
            current = today
        elif isinstance(today, str) and _security_re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", today):
            current = _security_datetime.date.fromisoformat(today)
        else:
            raise ValueError("Invalid date")
        reviewed = _security_datetime.date.fromisoformat(SECURITY_POLICY_REVIEWED_AT)
        expires = _security_datetime.date.fromisoformat(SECURITY_POLICY_VALID_UNTIL)
    except (TypeError, ValueError, OverflowError):
        return _security_check("policy_freshness", "UNKNOWN", "Cannot establish the policy evaluation date.")
    expected = {"reviewed_at": reviewed.isoformat(), "expires_at_utc": expires.isoformat() + "T00:00:00Z"}
    if current < reviewed:
        return _security_check("policy_freshness", "UNKNOWN", "The evaluation clock precedes the policy review.",
                               observed=current.isoformat(), expected=expected)
    if current >= expires:
        return _security_check("policy_freshness", "STALE", "The curated policy has expired; obtain a newly reviewed policy.",
                               observed=current.isoformat(), expected=expected)
    return _security_check("policy_freshness", "PASS", "The dated policy is within its review window.",
                           observed=current.isoformat(), expected=expected)


def _security_version_without_zero_epoch(value):
    """A deliberately narrow Debian-version parser; never order versions here."""
    if not isinstance(value, str) or len(value) > 160:
        return None
    if not _security_re.fullmatch(r"(?:[0-9]+:)?[0-9][A-Za-z0-9.+~:-]*-[A-Za-z0-9.+~]+", value):
        return None
    if ":" in value:
        epoch, value = value.split(":", 1)
        # Only the reviewed epoch is accepted. A new nonzero epoch needs review.
        if not epoch.isascii() or not epoch.isdigit() or int(epoch) != 0 or ":" in value:
            return None
    return value


def _security_compare(compare, actual, minimum):
    try:
        result = compare(actual, "ge", minimum)
    except Exception:
        return None
    return result if type(result) is bool else None


def _security_package_check(logical, row, rule):
    name = row["package"]
    observed = {key: row[key] for key in ("package", "version", "source_package", "source_version", "status")}
    expected = {"source_package": rule["source_package"], "reviewed_epoch": 0}
    if logical == "nginx":
        expected["minimum_source_version"] = rule["minimum"]
    else:
        expected["upstream_minimum"] = rule["upstream_minimum"]
        expected["reviewed_fixed_backports"] = list(rule["fixed_backports"])
    source = _security_version_without_zero_epoch(row["source_version"])
    binary = _security_version_without_zero_epoch(row["version"])
    if source is None or binary is None:
        return _security_check("package:" + name, "UNKNOWN", "Malformed version or an unreviewed Debian epoch.",
                               observed=observed, expected=expected, refs=rule["refs"])
    if binary != source and not _security_re.fullmatch(_security_re.escape(source) + r"\+b[0-9]+", binary):
        return _security_check("package:" + name, "UNKNOWN", "Binary and source version metadata are inconsistent.",
                               observed=observed, expected=expected, refs=rule["refs"])
    if not _security_re.fullmatch(rule["version_pattern"], source):
        return _security_check("package:" + name, "UNKNOWN", "The version is outside the reviewed distribution package branch.",
                               observed=observed, expected=expected, refs=rule["refs"])
    # Returning an unevaluated record avoids putting comparator capabilities in
    # policy data and lets evaluate_packages distinguish schema from comparison.
    return observed, expected


def evaluate_packages(info, inventory, compare, *, required_sources=("nginx", "certbot"), today=None):
    """Evaluate one installed or candidate inventory without performing I/O.

    ``info`` uses os-release keys ID, VERSION_ID, and optional VERSION_CODENAME.
    Logical source ``certbot`` and canonical source ``python-certbot`` are aliases.
    ``required_sources=("nginx",)`` permits a targeted nginx repair even when
    Certbot or a pinned bundle is blocked by independent policy checks.
    """
    checks = [verify_policy_freshness(today)]
    if not isinstance(required_sources, (tuple, list)) or not required_sources:
        checks.append(_security_check("required_sources", "UNKNOWN", "At least one reviewed source must be requested."))
        return _security_report(checks)
    required = []
    for source in required_sources:
        if not isinstance(source, str) or source not in SECURITY_SOURCE_ALIASES:
            checks.append(_security_check("required_sources", "UNKNOWN", "An unreviewed source was requested."))
            return _security_report(checks)
        logical = SECURITY_SOURCE_ALIASES[source]
        if logical in required:
            checks.append(_security_check("required_sources", "UNKNOWN", "A source was requested more than once."))
            return _security_report(checks)
        required.append(logical)
    if not isinstance(info, dict) or not isinstance(info.get("ID"), str) or not isinstance(info.get("VERSION_ID"), str):
        checks.append(_security_check("platform", "UNKNOWN", "Missing distribution identity or release metadata."))
        return _security_report(checks)
    key = (info["ID"], info["VERSION_ID"])
    platform = SECURITY_PACKAGE_RULES.get(key)
    if platform is None:
        checks.append(_security_check("platform", "UNKNOWN", "No curated package policy exists for this distribution release.",
                                      observed={"ID": key[0], "VERSION_ID": key[1]}))
        return _security_report(checks)
    if "VERSION_CODENAME" in info and info["VERSION_CODENAME"] != platform["codename"]:
        checks.append(_security_check("platform", "UNKNOWN", "Distribution release and codename metadata disagree.",
                                      expected=platform["codename"]))
        return _security_report(checks)
    checks.append(_security_check("platform", "PASS", "Distribution release has a curated package policy.",
                                  observed={"ID": key[0], "VERSION_ID": key[1], "codename": platform["codename"]}))
    if not isinstance(inventory, (list, tuple)):
        checks.append(_security_check("inventory", "UNKNOWN", "Package inventory is missing or malformed."))
        return _security_report(checks)
    seen_sources, seen_packages, phases = set(), set(), set()
    for index, row in enumerate(inventory):
        if not isinstance(row, dict):
            checks.append(_security_check("inventory:" + str(index), "UNKNOWN", "Malformed package inventory row."))
            continue
        package = row.get("package")
        source = row.get("source_package")
        if not isinstance(package, str) or not _security_re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?", package):
            checks.append(_security_check("inventory:" + str(index), "UNKNOWN", "Missing or malformed binary package name."))
            continue
        if not isinstance(source, str) or not _security_re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", source):
            checks.append(_security_check("package:" + package, "UNKNOWN", "Missing or malformed source package identity."))
            continue
        known_binary = SECURITY_BINARY_SOURCES.get(package.split(":", 1)[0])
        logical = {value: name for name, value in SECURITY_REAL_SOURCE_NAMES.items()}.get(source)
        if known_binary in required and logical != known_binary:
            checks.append(_security_check("package:" + package, "UNKNOWN", "The binary belongs to an unexpected source package.",
                                          observed=source, expected=SECURITY_REAL_SOURCE_NAMES[known_binary]))
            continue
        if logical not in required:
            continue
        if known_binary is not None and known_binary != logical:
            checks.append(_security_check("package:" + package, "UNKNOWN", "Binary and source package identities disagree."))
            continue
        seen_sources.add(logical)
        if package in seen_packages:
            checks.append(_security_check("package:" + package, "UNKNOWN", "Duplicate binary package inventory row."))
            continue
        seen_packages.add(package)
        if row.get("status") not in ("installed", "candidate"):
            checks.append(_security_check("package:" + package, "UNKNOWN", "The package is neither fully installed nor a selected candidate."))
            continue
        phases.add(row["status"])
        if any(not isinstance(row.get(field), str) or not row[field] for field in ("version", "source_version")):
            checks.append(_security_check("package:" + package, "UNKNOWN", "Full binary and source versions are both required."))
            continue
        rule = platform[logical]
        preliminary = _security_package_check(logical, row, rule)
        if isinstance(preliminary, dict):
            checks.append(preliminary)
            continue
        observed, expected = preliminary
        if logical == "certbot" and _security_version_without_zero_epoch(row["source_version"]) in rule["fixed_backports"]:
            checks.append(_security_check("package:" + package, "PASS", "Version matches an explicitly reviewed fixed distribution backport.",
                                          observed=observed, expected=expected, refs=rule["refs"]))
            continue
        minimum = rule["minimum"] if logical == "nginx" else rule["upstream_minimum"]
        meets_floor = _security_compare(compare, row["source_version"], minimum)
        if meets_floor is None:
            status, reason = "UNKNOWN", "The Debian version comparison could not be completed reliably."
        elif not meets_floor:
            status = "BLOCKED"
            reason = ("Source version is below the reviewed distribution security floor." if logical == "nginx" else
                      "Certbot is below the advisory's corrected upstream version, and no fixed distribution backport is reviewed in this policy.")
        elif logical == "certbot":
            status, reason = "UNKNOWN", "No reviewed fixed distribution branch covers this Certbot version."
        else:
            status, reason = "PASS", "Source version meets the reviewed nginx floor within this distribution branch."
        checks.append(_security_check("package:" + package, status, reason, observed=observed, expected=expected, refs=rule["refs"]))
    if len(phases) > 1:
        checks.append(_security_check("inventory_phase", "UNKNOWN", "Installed and candidate versions must be evaluated in separate inventories."))
    for logical in required:
        if logical not in seen_sources:
            checks.append(_security_check("source:" + logical, "UNKNOWN", "Required source-package inventory is missing.",
                                          expected=SECURITY_REAL_SOURCE_NAMES[logical]))
    return _security_report(checks)


def evaluate_pinned_release(version, sha256, *, today=None):
    """Evaluate the upstream archive identity, not the installer script's hash.

    The reviewed v3.11.0 archive is blocked by embedded dependency advisories.
    Unknown digests or release versions require a new review; there is no implicit
    approval of "latest".
    """
    checks = [verify_policy_freshness(today)]
    if (not isinstance(version, str) or not isinstance(sha256, str)
            or not _security_re.fullmatch(r"[0-9a-f]{64}", sha256)):
        checks.append(_security_check("bundle_identity", "UNKNOWN", "Release version or archive SHA256 is missing or malformed."))
        return _security_report(checks)
    observed = {"version": version, "archive_sha256": sha256}
    if (version, sha256) in (SECURITY_APPROVED_BUNDLE, SECURITY_LEGACY_BUNDLE):
        checks.append(_security_check("bundle_identity", "PASS", "Matches the reviewed local replacement archive.",
                                      observed=observed, refs=SECURITY_APPROVED_BUNDLE_REFS))
        return _security_report(checks)
    if version != SECURITY_BLOCKED_BUNDLE_VERSION or sha256 != SECURITY_BLOCKED_BUNDLE_SHA256:
        checks.append(_security_check("bundle_identity", "UNKNOWN", "This release and archive digest have not been reviewed by this policy.",
                                      observed=observed))
        return _security_report(checks)
    checks.append(_security_check("bundle_identity", "PASS", "Archive identity matches the reviewed release record.", observed=observed,
                                  refs=("https://github.com/MHSanaei/3x-ui/releases/tag/v3.11.0",)))
    for advisory in SECURITY_BLOCKED_BUNDLE_ADVISORIES:
        checks.append(_security_check(
            advisory["code"], "BLOCKED",
            "The reviewed archive embeds a dependency version covered by a published advisory; reachability in the deployed configuration was not established.",
            observed=dict(advisory["observed"]), expected=dict(advisory["expected"]), refs=advisory["refs"],
        ))
    return _security_report(checks)
