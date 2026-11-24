#!/usr/bin/env python3
# 3x-ui SiteKit 0.3.0-rc7 — single-file distribution
# Source: bundled security_policy.py, certbot_runtime.py, site_content.py, site_art.py, artifact_sites.py, rendering.py, apt_sources.py, installer_core.py
# License: MIT (upstream components retain their own licenses)
from __future__ import annotations

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


"""Install the verified offline Certbot runtime from an approved release archive."""


import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil


CERTBOT_RUNTIME_VERSION = "5.10.0"
CERTBOT_OPENSSL_PREFIX = "OpenSSL 3.5.10"
CERTBOT_PIP_WHEEL = "pip-26.3-py3-none-any.whl"
CERTBOT_LIBRARIES = ("libcrypto.so.3", "libssl.so.3")
CERTBOT_PIP_BOOTSTRAP = (
    "import runpy,sys; wheel=sys.argv.pop(1); sys.path.insert(0,wheel); "
    "runpy.run_module('pip',run_name='__main__')"
)
CERTBOT_ENTRYPOINT = '''import os
import ssl
import sys
from importlib.metadata import version

# The private payload does not ship the optional legacy provider.
os.environ["CRYPTOGRAPHY_OPENSSL_NO_LEGACY"] = "1"
from cryptography.hazmat.backends.openssl.backend import backend

versions = (ssl.OPENSSL_VERSION, backend.openssl_version_text())
allowed = tuple(item.split() for item in ({openssl!r}, {openssl!r} + "-dev"))
if not all(item.split()[:2] in allowed for item in versions):
    raise SystemExit("The private OpenSSL runtime was not loaded")
if version("certbot") != {version!r} or version("acme") != {version!r}:
    raise SystemExit("Unexpected Certbot or ACME version")
# Hooks and their children use the distribution's normal dynamic library paths.
os.environ.pop("LD_LIBRARY_PATH", None)
os.environ.pop("CRYPTOGRAPHY_OPENSSL_NO_LEGACY", None)
if sys.argv[1:] == ["--https-node-runtime-info"]:
    print("Certbot", version("certbot"), "ACME", version("acme"))
    print("Python ssl:", versions[0])
    print("cryptography:", versions[1])
else:
    from certbot.main import main
    raise SystemExit(main())
'''


def verify_certbot_payload(source):
    """Prove the exact file set and hashes inside the digest-pinned archive."""
    manifest = source / "SHA256SUMS"
    if source.is_symlink() or manifest.is_symlink() or not manifest.is_file():
        raise ValueError("Missing regular Certbot payload manifest")
    entries = {}
    for line in manifest.read_text(encoding="ascii").splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if not match or match[2] in entries or match[2] in {".", "..", "SHA256SUMS"}:
            raise ValueError("Invalid Certbot payload manifest")
        digest, name = match.groups()
        entries[name] = digest
    required = {"requirements.lock", CERTBOT_PIP_WHEEL, *CERTBOT_LIBRARIES}
    if not required.issubset(entries) or set(entries) | {"SHA256SUMS"} != {p.name for p in source.iterdir()}:
        raise ValueError("Certbot payload is incomplete or contains unlisted files")
    for name, digest in entries.items():
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Unexpected file type in the Certbot payload")
        with path.open("rb") as stream:
            if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                raise ValueError("Certbot payload checksum mismatch: " + name)


def install_certbot_runtime(source, runtime, run):
    """Install only hash-verified wheels into a root-only, separately managed venv."""
    source, runtime = Path(source).absolute(), Path(runtime).absolute()
    verify_certbot_payload(source)
    runtime.mkdir(mode=0o700)
    try:
        lib = runtime / "lib"
        lib.mkdir(mode=0o700)
        for name in CERTBOT_LIBRARIES:
            shutil.copyfile(source / name, lib / name)
            (lib / name).chmod(0o600)
        shutil.copyfile(source / "SHA256SUMS", runtime / "payload.sha256")
        (runtime / "payload.sha256").chmod(0o600)
        venv = runtime / "venv"
        run(["/usr/bin/python3", "-I", "-m", "venv", "--without-pip", venv])
        python = venv / "bin/python"
        pip = [python, "-I", "-c", CERTBOT_PIP_BOOTSTRAP, source / CERTBOT_PIP_WHEEL, "--isolated"]
        env = {key: value for key, value in os.environ.items() if not key.startswith("PIP_")}
        env["PIP_CONFIG_FILE"] = os.devnull
        run([*pip, "install", "--disable-pip-version-check", "--no-index", "--only-binary=:all:",
             "--find-links", source, "--require-hashes", "-r", source / "requirements.lock"], env=env)
        run([*pip, "check"], env=env)
        entry = runtime / "entry.py"
        entry.write_text(CERTBOT_ENTRYPOINT.format(openssl=CERTBOT_OPENSSL_PREFIX,
                                                   version=CERTBOT_RUNTIME_VERSION), encoding="utf-8")
        entry.chmod(0o600)
        wrapper = runtime / "certbot"
        wrapper.write_text("#!/bin/sh\nset -eu\nunset LD_PRELOAD\nexport LD_LIBRARY_PATH="
                           + shlex.quote(str(lib)) + "\nexec " + shlex.quote(str(python))
                           + " -I " + shlex.quote(str(entry)) + ' "$@"\n', encoding="utf-8")
        wrapper.chmod(0o700)
        run([wrapper, "--https-node-runtime-info"])
        return wrapper
    except BaseException:
        shutil.rmtree(runtime)
        raise


"""Original editorial material for additional generated-site themes.

No real person, company, client, contact address, or professional credential is
claimed. The entries are short reading notes and observation exercises.
"""


def _article(slug, category, titles, summary, paragraphs):
    return {"slug": slug, "category": category, "titles": titles,
            "summary": summary, "paragraphs": paragraphs}


EXTRA_SITE_CONTENT = {
    "typography": {
        "names": ("Letterform Notes", "Quiet Type", "Between the Letters", "The Reading Measure"),
        "descriptions": (
            "Observations on letterforms, spacing, and the structure of readable pages.",
            "A small collection of type specimens and notes about the rhythm of text.",
            "Looking closely at the details that give a page its voice and pace.",
        ),
        "eyebrow": "Letters & reading",
        "about": (
            "This notebook considers typography through ordinary reading: a heading, a paragraph, a caption, and the spaces that connect them. Each note focuses on a detail that can be compared on a single page.",
            "The exercises use short passages and simple specimens. Keep the text consistent while changing one decision, and describe the difference in terms of what becomes easier to notice or follow.",
        ),
        "caption": "A study in strokes, counters, and the intervals between repeated forms.",
        "palettes": {
            "type-ivory": ("#F5F0E7", "#252321", "#6F6861", "#A34332", "#EAE1D3", "#D6CABC"),
            "type-slate": ("#EEF1F1", "#202C35", "#626F76", "#365F78", "#DCE5E8", "#C8D5DB"),
            "type-plum": ("#F3EDF0", "#372A35", "#786A74", "#7B4366", "#E8DBE3", "#D7C6D1"),
        },
        "articles": (
            _article("reading-measure", "Reading", ("Finding a comfortable measure", "A paragraph at three widths"),
                     "Compare the same paragraph in narrow, medium, and wide columns.", (
                         "Choose a paragraph that can be read without needing its surrounding article. Set it in three column widths while keeping the type size and line spacing unchanged.",
                         "Read each version at an ordinary pace. Notice where your eye returns to the beginning of a line, and whether a short final line interrupts the paragraph's shape.",
                         "Keep the version that suits the page's purpose. A caption, a long essay, and a narrow sidebar can each benefit from a different measure.",
                     )),
            _article("letter-pairs", "Spacing", ("Look at the space between pairs", "An exercise in optical spacing"),
                     "Repeated words make small differences between letter pairs easier to see.", (
                         "Write a short heading with several round, straight, and diagonal letters. Compare the spaces around those shapes before adjusting the word as a whole.",
                         "A useful specimen contains the same word on several lines. Change one pair at a time, then step back and read the heading without concentrating on the individual letters.",
                         "Save the earlier version beside the adjusted one. The comparison is more informative than trying to remember how the original spacing felt.",
                     )),
            _article("small-hierarchy", "Structure", ("A hierarchy with three levels", "Give each level a clear role"),
                     "A title, a subheading, and body text can carry a complete short page.", (
                         "Begin with the content outline. Decide which words introduce the whole page, which divide it into sections, and which belong to the continuous reading text.",
                         "Give each level a consistent treatment. Size, weight, spacing, and position offer several ways to make the structure visible without adding an extra style to every paragraph.",
                         "Review the page as a silhouette before reading it closely. The largest elements should help a reader predict the sequence and find a useful place to begin.",
                     )),
            _article("numeral-specimens", "Specimens", ("Keep a small numeral specimen", "Numbers deserve their own proof"),
                     "Dates, prices, and measurements reveal details that an alphabet specimen can miss.", (
                         "Make a specimen with a date, a short table, a decimal measurement, and a numbered list. Use the same examples whenever you compare a new typeface.",
                         "Look at the width and alignment of the digits. In a table, the relationship between columns matters alongside the shape of each individual numeral.",
                         "Include punctuation and symbols that the actual document needs. A short practical specimen is easier to judge than a page filled with unrelated characters.",
                     )),
            _article("quiet-captions", "Details", ("Writing a useful caption", "Small text with a clear purpose"),
                     "A caption should connect an image to the surrounding page.", (
                         "Start by identifying the detail that the reader should notice. Write a sentence that adds context to the image instead of repeating the nearest heading.",
                         "Set the caption beside the image and examine their spacing together. The distance should make their relationship clear even when several illustrations appear on one page.",
                         "Read the smallest text at its intended display size. Adjust the words as well as the typography when a caption becomes crowded or difficult to scan.",
                     )),
            _article("specimen-notebook", "Practice", ("Build a repeatable type specimen", "Keep the test text familiar"),
                     "A consistent set of sample text helps separate preference from habit.", (
                         "Choose a heading, a paragraph, a list, and a short quotation. Keep their wording fixed so that successive specimens can be compared directly.",
                         "Record the typeface, size, line spacing, and width beside each version. Add a brief observation about the reading experience while the comparison is still fresh.",
                         "Return to the specimen after working on other pages. The choices that continue to feel useful are good candidates for a small, dependable type system.",
                     )),
        ),
    },
    "cartography": {
        "names": ("Contour Notebook", "Ways on Paper", "Small Map Studies", "Lines of Place"),
        "descriptions": (
            "Notes about maps, landmarks, and the choices that make a place legible.",
            "A collection of small mapping exercises, route sketches, and visual keys.",
            "Exploring how lines, labels, and symbols describe a familiar landscape.",
        ),
        "eyebrow": "Maps & places",
        "about": (
            "A map begins with a question about a place. These notes examine the choices behind a route sketch, a legend, a group of labels, or a page of contour lines.",
            "The exercises are intended for observation and design. Keep sources and dates beside a working map, and use an appropriate current map when a real journey requires dependable navigation.",
        ),
        "caption": "An imagined terrain drawn as layered contours and a small network of paths.",
        "palettes": {
            "map-parchment": ("#F2EEDF", "#303C32", "#6B7565", "#617649", "#E1E5D0", "#CBD3BC"),
            "map-blueprint": ("#EAF0F5", "#25374A", "#657A8C", "#426F95", "#D7E3EC", "#BDCFE0"),
            "map-clay": ("#F4EDE6", "#43342C", "#857263", "#A46B45", "#EBDCCE", "#D9C4B2"),
        },
        "articles": (
            _article("map-question", "Purpose", ("Begin with one mapping question", "What should this map explain?"),
                     "A clear question makes the selection of features much easier.", (
                         "Choose a small area and write one question about it. You might want to compare entrances, show a walking route, or explain the relationship between several public spaces.",
                         "List the features that help answer that question. Draw a first version using only those features, then add context where the sketch becomes difficult to understand.",
                         "Ask someone to describe what they think the map shows. Their first reading can reveal whether the most prominent marks support the intended purpose.",
                     )),
            _article("working-legend", "Symbols", ("Make the legend while drawing", "A key that matches the marks"),
                     "Keep a small key beside a map as its visual language develops.", (
                         "Create one sample of every line, fill, and point symbol used in the drawing. Give each a short label while its meaning is still clear.",
                         "Compare similar symbols at the final page size. A difference that is obvious while zoomed in may become difficult to see in a compact legend.",
                         "Remove unused entries before sharing the map. The legend should describe the marks that appear on that particular sheet.",
                     )),
            _article("landmark-route", "Routes", ("Sketch a route through landmarks", "A familiar walk from memory"),
                     "Landmarks provide useful reference points for a first route sketch.", (
                         "Draw a familiar short route from memory and mark the places where you usually make a decision. Add the landmarks that help distinguish those points.",
                         "Compare the sketch with a dependable map or a later observation. Note where memory compressed a distance, omitted a turn, or exaggerated a memorable feature.",
                         "Keep both drawings. Their differences show which details carried the route in memory and which details needed a more careful record.",
                     )),
            _article("label-placement", "Labels", ("Give labels a place to breathe", "Read the map through its names"),
                     "Labels should help a reader connect a name with the correct feature.", (
                         "Place the most important names first. Leave enough room around each one to distinguish it from neighbouring lines, symbols, and other labels.",
                         "Read the sheet in small sections. Check that a label cannot easily be mistaken for the name of an adjacent street, boundary, or point.",
                         "Use consistent treatments for similar features. A modest hierarchy of size or weight can make the map's naming system easier to follow.",
                     )),
            _article("contour-reading", "Terrain", ("Follow a contour across the page", "Study the pattern before the detail"),
                     "A contour sketch is an exercise in following a continuous visual pattern.", (
                         "Begin with a simple contour drawing and trace one line through the whole image. Observe its turns and how the neighbouring lines relate to it.",
                         "Compare several small portions of the drawing. Describe their patterns in plain terms such as broad, narrow, closely grouped, or widely spaced.",
                         "Keep the line work clear when adding labels or shading. The additional information should preserve the continuity that makes the pattern readable.",
                     )),
            _article("source-margin", "Records", ("Leave room for the map's sources", "The useful margin of a working map"),
                     "A small source note makes a map easier to revisit and revise.", (
                         "Record the source, date, and purpose beside a working map. Add a note when a feature comes from observation, memory, or another published source.",
                         "Mark unresolved details clearly while drawing. A question in the margin is more useful than a precise-looking symbol whose meaning is uncertain.",
                         "When revising the map, keep a dated copy of the earlier version. The record helps explain why a line, name, or selected area changed.",
                     )),
        ),
    },
    "ceramics": {
        "names": ("Clay Surface", "Form in the Hand", "Kilnside Notes", "Small Vessel Studies"),
        "descriptions": (
            "Observations on ceramic form, surface, and the details of everyday vessels.",
            "A notebook of proportions, material samples, and small design decisions in clay.",
            "Looking at the relationship between a vessel's outline and the way it is handled.",
        ),
        "eyebrow": "Clay & form",
        "about": (
            "This collection looks at ceramics through shape, balance, and surface. The focus is on describing what a piece communicates before turning an observation into another design decision.",
            "Sketches, sample labels, and photographs provide a practical record. The notes concern observation and documentation; material and firing decisions belong to the established procedures of the studio using them.",
        ),
        "caption": "A group of imagined vessel silhouettes, with quiet changes in rim and body.",
        "palettes": {
            "clay-terracotta": ("#F4EAE2", "#44332B", "#856E60", "#B06E4F", "#E8D5C6", "#D5BBA7"),
            "clay-celadon": ("#EDF1E9", "#334239", "#6C7D70", "#638470", "#DAE4D8", "#C0D0BE"),
            "clay-cobalt": ("#F0F0F2", "#29374A", "#6A7483", "#456697", "#DEE3EC", "#C4CEDD"),
        },
        "articles": (
            _article("vessel-outline", "Form", ("Draw the outline first", "A vessel seen as a silhouette"),
                     "An outline makes the relationship between rim, body, and foot easier to compare.", (
                         "Draw several versions of a vessel as simple silhouettes. Keep the height similar while changing the width or the point at which the profile begins to curve.",
                         "Place the drawings beside each other and describe their character. Words such as upright, rounded, narrow, or settled can be more useful than an immediate judgement of preference.",
                         "Choose one outline for a closer study of the rim and base. Those details can change the impression of the whole form.",
                     )),
            _article("handle-relationship", "Use", ("Consider the handle with the body", "Where a handle begins and ends"),
                     "A handle is part of the vessel's overall proportion and movement.", (
                         "Sketch the body and handle together instead of adding the handle as a final detail. Compare its height, opening, and points of attachment with the surrounding shape.",
                         "Use photographs or drawings from more than one angle. A profile that looks balanced from the side can describe a different relationship from above.",
                         "Record the observations that matter during ordinary handling. Let those notes guide the next comparison between two possible forms.",
                     )),
            _article("surface-library", "Samples", ("Keep a small surface library", "Label the sample while it is familiar"),
                     "A well-labelled sample connects a visual result with its working record.", (
                         "Give each sample a short identifier and record the information needed to find its process notes. Keep the identifier visible in photographs as well as on the physical sample.",
                         "Photograph comparable samples under the same light and against a plain background. Include one overall view and one closer view of a useful detail.",
                         "Group samples by the question they help answer. A compact set of relevant comparisons can be more practical than a large collection without labels.",
                     )),
            _article("rim-details", "Details", ("A closer look at the rim", "The small line at the top"),
                     "The rim gives the eye and hand a clear place to meet a vessel.", (
                         "Look at several rim profiles in section drawings. Compare the transition from the outside wall to the edge and then to the inside surface.",
                         "Keep the drawing large enough to describe the change clearly. Add brief notes about the visual weight of the edge and its relationship to the rest of the piece.",
                         "Return to the full silhouette before deciding. A rim detail is most useful when it belongs to the proportions of the vessel around it.",
                     )),
            _article("photographing-form", "Records", ("Photograph a form consistently", "A useful sequence of vessel views"),
                     "A repeatable set of views helps compare pieces made at different times.", (
                         "Choose a small sequence of views: side, top, and one angled photograph. Keep the background and camera position as consistent as the available space allows.",
                         "Include a plain reference for scale in a separate record image. Keep the main photographs uncluttered so that the outline and surface remain easy to examine.",
                         "Store the images with the piece's identifier and a short observation. Consistent records make it easier to recognise a recurring design decision.",
                     )),
            _article("small-series", "Practice", ("Make a series around one question", "Comparing a family of forms"),
                     "A small series can explore one proportion through several related pieces.", (
                         "Write down the single feature that the series will compare. It might be the height of a foot, the width of an opening, or the position of a shoulder.",
                         "Keep a simple drawing of each version beside the working notes. Mark the difference clearly so that it remains visible when the pieces are viewed together.",
                         "Finish the comparison with a short description of what each version suggests. The notes become a starting point for the next, more focused series.",
                     )),
        ),
    },
    "coffee": {
        "names": ("Brew Margin", "The Cup Notebook", "Morning Filter", "Notes Beside a Cup"),
        "descriptions": (
            "A quiet notebook about coffee preparation, tasting language, and repeatable routines.",
            "Small observations from the preparation of an everyday cup of coffee.",
            "Keeping useful records of beans, brewing choices, and the way a cup changes as it cools.",
        ),
        "eyebrow": "Coffee & routine",
        "about": (
            "These pages treat coffee preparation as a small repeatable practice. The notes focus on describing a cup clearly and keeping enough context to make the next comparison useful.",
            "A simple record can include the coffee, equipment, measured inputs, and a few observations. The aim is a routine that remains easy to follow on an ordinary morning.",
        ),
        "caption": "An imagined arrangement of a cup, filter, and the repeating shapes of coffee beans.",
        "palettes": {
            "coffee-oat": ("#F4EFE5", "#3D3027", "#806F5F", "#96704B", "#E8DCC9", "#D6C3AB"),
            "coffee-olive": ("#EFF0E6", "#393E2F", "#747B64", "#747B45", "#E0E3CE", "#CDD2B4"),
            "coffee-copper": ("#F5EBE6", "#45332D", "#8A7064", "#A5664B", "#ECD8CD", "#DDBDAA"),
        },
        "articles": (
            _article("short-brew-record", "Records", ("Keep the brew record short", "Five lines beside the cup"),
                     "A record is useful when it is simple enough to complete regularly.", (
                         "Write down the coffee, brewing method, measured coffee and water, and the time or sequence you followed. Leave a final line for the most noticeable result.",
                         "Use the same order for each entry. A consistent format makes two cups easier to compare without turning a short routine into a long report.",
                         "When a cup is especially pleasing, note the circumstances while they are easy to remember. The next attempt then has a clear starting point.",
                     )),
            _article("change-one-choice", "Practice", ("Change one brewing choice", "A comparison with a clear question"),
                     "One deliberate adjustment gives a comparison a more useful focus.", (
                         "Begin with a familiar preparation and choose one detail to adjust. Keep the remaining steps as close to the earlier routine as practical.",
                         "Write the question before tasting. You might be comparing the finish, the balance of the cup, or how clearly a particular impression stands out.",
                         "Describe the difference before choosing a favourite. The description will be more useful later than a score with no explanation.",
                     )),
            _article("tasting-language", "Tasting", ("Use words that describe your cup", "A small personal tasting vocabulary"),
                     "Plain, familiar descriptions can make a tasting note easier to revisit.", (
                         "Start with broad observations such as light, rounded, dry, bright, or lingering. Add a more specific comparison only when it helps communicate what you noticed.",
                         "Keep the note connected to the actual cup and moment. A description can change as the drink cools or as you return to it after a short pause.",
                         "Review older notes for words you use consistently. A small reliable vocabulary gives your records a useful continuity.",
                     )),
            _article("cooling-cup", "Observation", ("Return to the cup as it cools", "Three moments in one tasting"),
                     "A few spaced observations can describe a cup more fully than one quick impression.", (
                         "Take an initial note, then return to the cup at two later moments. Keep the descriptions brief enough that the exercise remains part of an ordinary tasting.",
                         "Look for what stays familiar and what becomes easier to notice. Record your impressions without assuming that every difference requires a change to the recipe.",
                         "Read the three notes together. The sequence can suggest which part of the experience matters most to your preference.",
                     )),
            _article("repeatable-station", "Routine", ("Arrange a repeatable brewing space", "Give each tool a clear place"),
                     "A simple arrangement helps the preparation proceed in a familiar order.", (
                         "Lay out the equipment in the order it will be used. Keep the scale, coffee, water, and receiving vessel easy to reach without crowding the working area.",
                         "Remove objects that are unrelated to the current preparation. A clear space makes it easier to notice which step has been completed and which comes next.",
                         "After brewing, return the equipment to its usual place. A routine is easier to repeat when the next session begins from the same arrangement.",
                     )),
            _article("bean-label", "Reference", ("Keep the information from the bag", "A useful reference for the next cup"),
                     "The original label provides context that a tasting note alone can miss.", (
                         "Copy the coffee's name and the information supplied on its label into your notebook. Keep a photograph when that is quicker than transcribing the details.",
                         "Add the date on which you opened the bag and began using it. This gives later observations a place within the same sequence of preparations.",
                         "Store the label record beside the brew notes. The combination is more useful than trying to reconstruct the coffee's identity from a remembered flavour.",
                     )),
        ),
    },
    "acoustics": {
        "names": ("Listening Room Notes", "Sound in Place", "The Quiet Interval", "Rooms and Resonance"),
        "descriptions": (
            "Observations about listening spaces, familiar sounds, and the character of a room.",
            "A collection of listening exercises and notes about sound in everyday interiors.",
            "Looking at a room through the sounds that begin, move, and fade within it.",
        ),
        "eyebrow": "Sound & space",
        "about": (
            "These notes approach a listening space through careful description. A familiar recording, a short spoken passage, or an ordinary room sound provides a repeatable point of comparison.",
            "The exercises are informal observations rather than acoustic measurements. Record the position, surroundings, and listening level so that a later comparison has the same context.",
        ),
        "caption": "An imagined field of wave lines and repeated intervals across a quiet surface.",
        "palettes": {
            "sound-indigo": ("#EEF0F7", "#30364D", "#737B96", "#596EAA", "#DEE4F2", "#C6D1E6"),
            "sound-sand": ("#F4F0E6", "#3C3930", "#827B68", "#8D8051", "#E9E1CC", "#D8CCAA"),
            "sound-teal": ("#EAF2F1", "#283F41", "#668384", "#407E82", "#D5E6E3", "#BCD5D2"),
        },
        "articles": (
            _article("listening-position", "Position", ("Record the listening position", "A small map of where you listened"),
                     "A position note gives a listening comparison a useful physical context.", (
                         "Sketch the room and mark the place where you listened. Include the sound source and the nearby surfaces or furniture that define that position.",
                         "Choose a short familiar passage and keep the playback level comfortable. Describe what you notice before moving to another position.",
                         "Place the notes beside the sketch. The record can help separate an impression of the room from a memory of the passage itself.",
                     )),
            _article("sound-ending", "Listening", ("Listen to the end of a sound", "The interval after a phrase"),
                     "The moment after a sound can be as useful to describe as its beginning.", (
                         "Choose a familiar short sound or spoken phrase. After it ends, pay attention to the way the room returns to its ordinary background.",
                         "Use simple descriptions such as brief, extended, distinct, or blended. Keep the observation tied to the same position and surrounding conditions.",
                         "Repeat the exercise on another day before drawing a strong conclusion. A small collection of notes is more informative than one isolated impression.",
                     )),
            _article("background-inventory", "Environment", ("Make a background sound inventory", "The sounds already in the room"),
                     "A quiet minute can reveal the ordinary sounds that form a room's background.", (
                         "Sit in one place and list the sounds you can distinguish without searching for them. Note which remain steady and which appear only briefly.",
                         "Group the notes by what you can reasonably identify. Use a question mark when the source is uncertain instead of assigning it a confident label.",
                         "Return to the inventory at another time. The comparison describes how the space is used as well as how it sounds.",
                     )),
            _article("spoken-passage", "Reference", ("Keep a familiar spoken passage", "A repeatable listening reference"),
                     "A short piece of speech provides a consistent starting point for room notes.", (
                         "Select a passage whose words and pace are easy to recognise. Keep the same recording and playback arrangement when comparing positions or small room changes.",
                         "Write about how easily the words can be followed and how the pauses feel. Avoid changing several parts of the setup during the same comparison.",
                         "Keep the passage's details beside the notes. A reference is useful because it can be returned to under familiar conditions.",
                     )),
            _article("room-sketch", "Structure", ("Draw the room before adjusting it", "A visual record of the listening space"),
                     "A simple room drawing can clarify the arrangement behind a listening observation.", (
                         "Mark the main boundaries, openings, large furnishings, and listening positions. The drawing only needs enough detail to identify the arrangement being described.",
                         "When you make a small change, draw it on a second copy. Keep a short note about the purpose of the change and the reference used to compare it.",
                         "Save both versions with the listening notes. The record helps explain an earlier decision without relying on memory alone.",
                     )),
            _article("comparison-notes", "Practice", ("Separate observation from preference", "Two useful lines in a listening note"),
                     "A description and a preference answer different parts of a comparison.", (
                         "Write one line about what seemed different, then another about which version you preferred. Give each line enough context to remain meaningful later.",
                         "Use the same reference and a comfortable, consistent level. Pause when the comparison stops producing a clear observation.",
                         "Review the notes after some time has passed. A preference that remains useful across several ordinary listening sessions deserves closer attention.",
                     )),
        ),
    },
    "printmaking": {
        "names": ("Paper and Pressure", "The Proof Notebook", "Ink Margin", "Small Edition Studies"),
        "descriptions": (
            "Notes about print surfaces, proof sheets, and the rhythm of repeated marks.",
            "A collection of observations on ink, paper, and the making of a clear image.",
            "Keeping a useful record of proofs, compositions, and small changes between impressions.",
        ),
        "eyebrow": "Ink & paper",
        "about": (
            "This notebook considers prints through the decisions visible on a proof sheet. A border, a repeated mark, or a change in the relationship between light and dark can give a comparison its focus.",
            "The notes concern composition and documentation. A short identifier and a clear description help connect each impression to the working process that produced it.",
        ),
        "caption": "A procedural study of overlapping shapes, interrupted lines, and a restrained ink palette.",
        "palettes": {
            "print-carbon": ("#F4F1E9", "#292B2A", "#737770", "#505D55", "#E2E4D9", "#CBCFC0"),
            "print-rust": ("#F6EDE4", "#49342C", "#8A7364", "#B36C48", "#ECD8C5", "#DEBFA1"),
            "print-blue": ("#EEF1F5", "#2A3648", "#6D7C91", "#4A6B98", "#DEE5EE", "#C5D1E0"),
        },
        "articles": (
            _article("proof-identifier", "Records", ("Label every useful proof", "A proof sheet with enough context"),
                     "A short identifier connects an impression with the notes that explain it.", (
                         "Choose a simple naming sequence and use it consistently. Record the image, date, and version beside the observations that distinguish one proof from the next.",
                         "Photograph the identifier together with the sheet. A separate clean image can document the composition, while the record image preserves its working context.",
                         "Keep the most informative proofs even when they are unfinished. A visible intermediate decision can be useful during a later project.",
                     )),
            _article("negative-space", "Composition", ("Look at the unprinted shapes", "Reading the spaces between marks"),
                     "The empty portions of an image contribute to its structure and pace.", (
                         "Study the composition as a group of light and dark shapes. Trace the spaces between the main marks and compare their size and direction.",
                         "Make a small paper sketch before changing the working surface. This gives the proposed adjustment a clear form that can be considered beside the existing proof.",
                         "Return to the whole image after studying the details. A useful change should support the composition at the size where it will be viewed.",
                     )),
            _article("border-study", "Edges", ("Give the border a separate study", "The image and its surrounding paper"),
                     "A border influences the way an image sits on the sheet.", (
                         "Place the same image within several paper outlines. Compare narrow, broad, even, and deliberately uneven margins before choosing a final arrangement.",
                         "Look at the relationship between the image's strongest direction and the surrounding space. Include any caption or identifier that belongs in the finished layout.",
                         "Keep the preferred arrangement as a simple reference drawing. It can save repeated decisions when preparing a related group of prints.",
                     )),
            _article("repeated-marks", "Rhythm", ("Vary one mark within a sequence", "A rhythm made from simple shapes"),
                     "A repeated element creates a clear setting for a small deliberate variation.", (
                         "Begin with a short row of similar marks. Change one feature, such as width, spacing, or orientation, while keeping the rest of the sequence familiar.",
                         "Compare the row at close range and from farther away. Notice whether the variation reads as a focal point, an interruption, or part of a gradual change.",
                         "Use the observation to make a second sequence. A few focused studies can suggest several directions for a larger composition.",
                     )),
            _article("paper-observations", "Material", ("Describe the paper beside the proof", "A small paper reference library"),
                     "A paper sample is more useful when its identity and observations remain together.", (
                         "Keep a small labelled sample with the information supplied by its maker. Record the details needed to identify the same paper again.",
                         "Add an observation about the particular impression you made on it. Describe the visible result without assuming that another process would produce the same effect.",
                         "Group samples around a current question. A compact selection makes it easier to compare the papers that are relevant to the next piece.",
                     )),
            _article("proof-comparison", "Practice", ("Compare proofs in a fixed order", "A sequence of visible decisions"),
                     "An ordered set of proofs can make the development of an image easier to understand.", (
                         "Lay out a small group of proofs in the order they were made. Place a short note beside each one describing the intended change.",
                         "Look for the point where a decision became clearer, and the point where another detail became less useful. Keep both observations in the record.",
                         "Finish with a concise description of the next question. The comparison then becomes a practical guide for continuing the work.",
                     )),
        ),
    },
    "coastal": {
        "names": ("Shoreline Notebook", "Along the Waterline", "Coastal Observations", "The Distant Shore"),
        "descriptions": (
            "Small observations of coastal light, distant lines, and the textures of a shoreline.",
            "A visual notebook of the meeting between land, water, and open sky.",
            "Looking closely at repeated forms, changing colours, and the scale of a coastal view.",
        ),
        "eyebrow": "Shore & horizon",
        "about": (
            "These notes describe a coast through visible details: an edge in the distance, a group of textures, or a change in the colour of the water. Short sketches and clear labels keep the observations connected.",
            "The exercises can be made from a photograph or a familiar public viewpoint. They focus on looking and recording, without claiming to describe the conditions of a particular place.",
        ),
        "caption": "An imagined shoreline assembled from layered water, low land, and a broad sky.",
        "palettes": {
            "shore-seaglass": ("#EDF3EF", "#2D4540", "#6C8880", "#478B7E", "#D5E7DD", "#BBD7C9"),
            "shore-sand": ("#F5F0E5", "#454137", "#89806B", "#9B8653", "#EAE0C8", "#DACEAA"),
            "shore-harbour": ("#EAF0F5", "#293F51", "#6A8396", "#487A9F", "#D5E2ED", "#BAD0E0"),
        },
        "articles": (
            _article("horizon-placement", "Composition", ("Place the horizon deliberately", "Three versions of one coastal view"),
                     "Moving the horizon within a sketch changes the balance of land, water, and sky.", (
                         "Draw the same simple view with the horizon low, central, and high on the page. Keep the main shapes consistent while changing their relative amount of space.",
                         "Describe where your attention goes in each version. The comparison can suggest whether the view is primarily about the sky, the water, or the near edge of land.",
                         "Choose one arrangement for a more detailed study. Keep the other sketches as a reminder of the alternatives that were considered.",
                     )),
            _article("shore-textures", "Texture", ("Make a small texture inventory", "Patterns near the waterline"),
                     "A few clearly described textures can give a visual note its sense of place.", (
                         "Choose a photograph or a familiar view and identify several distinct textures. Sketch a small sample of each without trying to describe the entire scene at once.",
                         "Use plain labels such as ridged, smooth, scattered, or layered. Add a short note about the size of the pattern within the larger view.",
                         "Compare the samples on one page. Their differences can help decide which details deserve emphasis in a later drawing.",
                     )),
            _article("colour-strips", "Colour", ("Keep a strip of observed colours", "A coastal palette in a few samples"),
                     "A short sequence of colour samples can preserve an impression of changing light.", (
                         "Select a few colours from the same view and place them in a narrow strip. Note which belong to the sky, water, distant land, or nearby surfaces.",
                         "Keep the source and observation time beside the strip when they are known. If the study comes from an image, record that context as well.",
                         "Return to the strip while making a larger composition. It can provide a useful starting palette without requiring every part of the scene to match exactly.",
                     )),
            _article("distant-landmarks", "Distance", ("Use a landmark to describe scale", "A small shape across open water"),
                     "One recognisable shape can provide a reference within a broad coastal view.", (
                         "Choose a distant feature that can be identified clearly in the source image or view. Sketch its outline beside a larger drawing of the surrounding space.",
                         "Compare the feature's height with the horizon and nearby shapes. The aim is a useful visual relationship, so record uncertainty instead of adding unsupported precision.",
                         "Keep the landmark simple in the final composition. A few well-placed lines may carry the reference more clearly than a crowded description.",
                     )),
            _article("repeated-view", "Observation", ("Return to the same view", "A sequence from one viewpoint"),
                     "A consistent viewpoint makes changes between observations easier to describe.", (
                         "Choose a view that can be recorded from the same ordinary position. Keep the framing similar and write down the available context for each observation.",
                         "Compare the sequence for changes in light, visible shapes, and the distribution of colour. Describe what the images show without assuming a cause for every difference.",
                         "Select a few frames that explain the sequence clearly. A small, well-labelled group is easier to revisit than a large set of nearly identical images.",
                     )),
            _article("edge-drawing", "Lines", ("Follow one edge across the page", "A shoreline drawn as a continuous line"),
                     "Tracing a single boundary can reveal the rhythm of a complicated scene.", (
                         "Choose one visible edge and follow it through a sketch. Let the line record its broad turns before adding smaller interruptions and details.",
                         "Notice where the line changes pace through repeated bends, long stretches, or short angular sections. Describe those changes in the margin.",
                         "Use the study as a framework for a second drawing with a few additional shapes. Keep the original line legible as the composition becomes more detailed.",
                     )),
        ),
    },
}


"""Local deterministic SVG artwork for the version-one site generator.

These are decorative studies, not photographs, astronomical charts or maps.
No user text, external image/font references, scripts or installation secrets
are interpolated into the SVG. Geometry and colours are bounded and validated.
"""

import hashlib as _art_hashlib
import re as _art_re


_ART_THEMES = (
    "journal", "botanical", "photography", "architecture", "astronomy",
    "typography", "cartography", "ceramics", "coffee", "acoustics", "printmaking", "coastal",
)


def _art_inputs(seed, theme, colors):
    if not isinstance(seed, str) or not _art_re.fullmatch(r"[0-9a-f]{64}", seed):
        raise ValueError("Artwork seed must be 64 lowercase hexadecimal characters")
    if not isinstance(theme, str) or theme not in _ART_THEMES:
        raise ValueError("Unsupported artwork theme")
    if not isinstance(colors, (tuple, list)) or len(colors) != 6:
        raise ValueError("Artwork palette must have six colours")
    if any(not isinstance(c, str) or not _art_re.fullmatch(r"#[0-9A-Fa-f]{6}", c) for c in colors):
        raise ValueError("Artwork colours must be six-digit hexadecimal values")


def _art_n(seed, key, low, high):
    digest = _art_hashlib.sha256(("art-v1\0" + seed + "\0" + key).encode()).hexdigest()
    return low + int(digest[:16], 16) % (high - low + 1)


def render_site_illustration(seed: str, theme: str, colors) -> str:
    """Return a decorative 960x600 study, varied by the installation seed."""
    _art_inputs(seed, theme, colors)
    bg, ink, muted, accent, panel, border = colors
    n = lambda key, low, high: _art_n(seed, key, low, high)
    elements = [
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 960 600" role="img" aria-labelledby="art-title">',
        '<title id="art-title">An abstract ' + theme + ' study</title>',
        f'<rect width="960" height="600" fill="{panel}"/>',
    ]
    add = elements.append
    if theme == "journal":
        for i in range(3):
            x, y = 145 + i * 194 + n(f"x{i}", -22, 22), 80 + n(f"y{i}", 0, 55)
            w, h = n(f"w{i}", 220, 260), n(f"h{i}", 320, 390)
            angle = n(f"angle{i}", -8, 8)
            add(f'<g transform="rotate({angle} {x+w//2} {y+h//2})">')
            add(f'<rect x="{x+8}" y="{y+12}" width="{w}" height="{h}" fill="{border}"/>')
            add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{bg}"/>')
            add(f'<rect x="{x+27}" y="{y+35}" width="{n(f"head{i}",65,115)}" height="8" fill="{accent}"/>')
            for j in range(7):
                width = n(f"line{i}:{j}", 75, w - 55)
                add(f'<path d="M{x+27} {y+82+j*30}h{width}" stroke="{muted}" stroke-width="2" opacity=".5"/>')
            add('</g>')
    elif theme == "botanical":
        for i in range(5):
            x, top = 185 + i * 148 + n(f"stem{i}", -20, 20), n(f"top{i}", 90, 210)
            bend = n(f"bend{i}", -65, 65)
            add(f'<path d="M{x} 535 Q{x+bend} 320 {x+bend//2} {top}" fill="none" stroke="{accent}" stroke-width="5"/>')
            for j in range(5):
                y, side = 460 - j * 62, 1 if j % 2 else -1
                dx, dy = n(f"leafx{i}:{j}", 45, 85) * side, n(f"leafy{i}:{j}", 22, 48)
                add(f'<path d="M{x} {y} Q{x+dx} {y-dy-45} {x+dx} {y-dy} Q{x+dx//2} {y+12} {x} {y}Z" fill="{accent if j%2 else muted}" opacity=".75"/>')
        add(f'<path d="M100 537h760" stroke="{border}" stroke-width="2"/>')
    elif theme == "photography":
        x, y = n("lightx", 220, 720), n("lighty", 130, 270)
        add(f'<rect x="110" y="60" width="740" height="480" rx="2" fill="{bg}"/>')
        add(f'<circle cx="{x}" cy="{y}" r="{n("radius",55,105)}" fill="{accent}" opacity=".65"/>')
        add(f'<path d="M110 420 Q310 {n("hill1",170,310)} 520 400 T850 390V540H110Z" fill="{border}"/>')
        add(f'<path d="M110 480 Q400 {n("hill2",320,420)} 850 450V540H110Z" fill="{muted}" opacity=".7"/>')
        add(f'<rect x="145" y="95" width="670" height="410" fill="none" stroke="{bg}" stroke-width="2" opacity=".8"/>')
        add(f'<path d="M480 120v360M170 300h620" stroke="{bg}" stroke-width="1" opacity=".45"/>')
    elif theme == "architecture":
        ground = 515
        for i in range(5):
            x, width, height = 110 + i * 151, n(f"width{i}", 100, 137), n(f"height{i}", 175, 385)
            y = ground - height
            add(f'<rect x="{x+13}" y="{y+16}" width="{width}" height="{height-16}" fill="{border}"/>')
            add(f'<rect x="{x}" y="{y}" width="{width}" height="{height}" fill="{bg if i%2 else accent}"/>')
            for row in range((height - 30) // 47):
                for col in range(2):
                    add(f'<rect x="{x+22+col*49}" y="{y+25+row*47}" width="21" height="25" fill="{ink}" opacity=".18"/>')
        add(f'<path d="M70 {ground}h820" stroke="{muted}" stroke-width="3"/>')
    elif theme == "astronomy":
        add(f'<rect width="960" height="600" fill="{ink}"/>')
        points = []
        for i in range(46):
            x, y = n(f"sx{i}", 65, 895), n(f"sy{i}", 55, 545)
            radius = n(f"sr{i}", 12, 34) / 10
            add(f'<circle cx="{x}" cy="{y}" r="{radius:.1f}" fill="{bg}" opacity=".{n(f"so{i}",40,95)}"/>')
            if i < 6:
                points.append(f"{x},{y}")
        add(f'<polyline points="{" ".join(points)}" fill="none" stroke="{border}" stroke-width="1" opacity=".3"/>')
        x, y, r = n("moonx", 230, 740), n("moony", 160, 380), n("moonr", 55, 85)
        add(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{panel}"/>')
        add(f'<circle cx="{x+r//2}" cy="{y-r//5}" r="{r-4}" fill="{ink}"/>')
    elif theme == "typography":
        add(f'<rect x="100" y="65" width="760" height="470" fill="{bg}"/>')
        for y in (165, 300, 450):
            add(f'<path d="M145 {y}h670" stroke="{border}" stroke-width="2"/>')
        pairs = ("Aa", "Gg", "Rr", "Mm", "Ee", "Bb")
        pair = pairs[n("glyphs", 0, len(pairs)-1)]
        add(f'<text x="{n("textx",160,220)}" y="445" font-family="Georgia,serif" font-size="{n("size",300,350)}" fill="{ink}">{pair}</text>')
        add(f'<circle cx="{n("dotx",700,790)}" cy="{n("doty",135,220)}" r="{n("dotr",22,38)}" fill="{accent}"/>')
    elif theme == "cartography":
        for i in range(10):
            y = 50 + i * 55
            offset = n(f"contour{i}", -45, 45)
            add(f'<path d="M-20 {y} C220 {y-150+offset} 275 {y+130} 510 {y+offset} S780 {y-115} 980 {y+55}" fill="none" stroke="{accent if i%3==0 else muted}" stroke-width="{2 if i%3==0 else 1}" opacity=".7"/>')
        x = n("route", 370, 580)
        add(f'<path d="M120 590 Q{x-140} 380 {x} 290 T820 10" fill="none" stroke="{bg}" stroke-width="13"/>')
        add(f'<path d="M120 590 Q{x-140} 380 {x} 290 T820 10" fill="none" stroke="{border}" stroke-width="3"/>')
        for i in range(4):
            add(f'<circle cx="{n(f"px{i}",160,800)}" cy="{n(f"py{i}",90,510)}" r="5" fill="{ink}"/>')
    elif theme == "ceramics":
        for i in range(3):
            x, top, half = 235 + i * 245, n(f"top{i}", 125, 250), n(f"half{i}", 48, 72)
            belly = n(f"belly{i}", 88, 112)
            fill = (accent, muted, bg)[i]
            add(f'<ellipse cx="{x+7}" cy="500" rx="{belly}" ry="17" fill="{border}"/>')
            add(f'<path d="M{x-half} {top} Q{x-half+13} {top+70} {x-belly} 350 Q{x-belly-12} 470 {x-55} 489 H{x+55} Q{x+belly+12} 470 {x+belly} 350 Q{x+half-13} {top+70} {x+half} {top}Z" fill="{fill}"/>')
            add(f'<ellipse cx="{x}" cy="{top}" rx="{half}" ry="14" fill="{ink}" opacity=".3"/>')
            add(f'<path d="M{x-belly+15} 380h{2*belly-30}M{x-belly+18} 400h{2*belly-36}" stroke="{panel}" stroke-width="2" opacity=".5"/>')
    elif theme == "coffee":
        for i in range(3):
            x, y, r = 230 + i * 250, n(f"cy{i}", 235, 365), n(f"cr{i}", 58, 76)
            add(f'<ellipse cx="{x+5}" cy="{y+16}" rx="{r+35}" ry="{r+24}" fill="{border}"/>')
            add(f'<circle cx="{x}" cy="{y}" r="{r+25}" fill="{bg}"/>')
            add(f'<ellipse cx="{x+r}" cy="{y}" rx="25" ry="21" fill="none" stroke="{muted}" stroke-width="10"/>')
            add(f'<circle cx="{x}" cy="{y}" r="{r}" fill="{muted}"/>')
            add(f'<circle cx="{x}" cy="{y}" r="{r-12}" fill="{ink}"/>')
            add(f'<path d="M{x-r//3} {y} Q{x} {y-r//2} {x+r//3} {y} T{x-r//3} {y+r//3}" fill="none" stroke="{panel}" stroke-width="5" opacity=".7"/>')
        for i in range(8):
            x, y = n(f"beanx{i}", 110, 850), n(f"beany{i}", 440, 520)
            add(f'<ellipse cx="{x}" cy="{y}" rx="11" ry="7" fill="{accent}" transform="rotate({n(f"beana{i}",0,160)} {x} {y})"/>')
    elif theme == "acoustics":
        add(f'<path d="M75 300h810" stroke="{border}" stroke-width="2"/>')
        for i in range(47):
            x = 85 + i * 17
            height = n(f"amplitude{i}", 15, 205)
            add(f'<path d="M{x} {300-height}v{height*2}" stroke="{accent if i%3 else muted}" stroke-width="{n(f"stroke{i}",4,9)}" stroke-linecap="round" opacity=".8"/>')
        add(f'<path d="M80 530h800" stroke="{muted}" stroke-width="2"/>')
        for i in range(9):
            add(f'<path d="M{80+i*100} 522v16" stroke="{muted}" stroke-width="2"/>')
    elif theme == "printmaking":
        for i in range(8):
            x, y = 100 + (i % 4) * 195, 100 + (i // 4) * 225
            width, height = n(f"pw{i}", 120, 165), n(f"ph{i}", 140, 185)
            fill = (accent, muted, ink)[i % 3]
            add(f'<rect x="{x}" y="{y}" width="{width}" height="{height}" fill="{fill}" opacity=".8" transform="rotate({n(f"pa{i}",-4,4)} {x+width//2} {y+height//2})"/>')
            for j in range(4):
                add(f'<path d="M{x+15} {y+30+j*32}q{width//3} {n(f"curve{i}:{j}",-20,20)} {width-30} 0" fill="none" stroke="{panel}" stroke-width="3" opacity=".75"/>')
    elif theme == "coastal":
        add(f'<rect width="960" height="600" fill="{bg}"/>')
        for i in range(7):
            y, drift = 110 + i * 70, n(f"wave{i}", -40, 40)
            add(f'<path d="M-20 {y} Q220 {y-65+drift} 470 {y+10} T980 {y-5} V620H-20Z" fill="{accent if i%2 else muted}" opacity=".23"/>')
            add(f'<path d="M-20 {y} Q220 {y-65+drift} 470 {y+10} T980 {y-5}" fill="none" stroke="{bg}" stroke-width="{n(f"foam{i}",2,5)}" opacity=".7"/>')
        for i in range(8):
            add(f'<ellipse cx="{n(f"pebblex{i}",70,890)}" cy="{n(f"pebbley{i}",490,555)}" rx="{n(f"pr{i}",8,21)}" ry="{n(f"ph{i}",4,11)}" fill="{ink}" opacity=".25"/>')
    add('</svg>\n')
    return '\n'.join(elements)


def render_site_icon(seed: str, theme: str, colors) -> str:
    """A compact thematic favicon drawn entirely from validated primitives."""
    _art_inputs(seed, theme, colors)
    bg, ink, muted, accent, panel, border = colors
    radius = _art_n(seed, "icon-corner", 10, 23)
    motifs = {
        "journal": '<path d="M20 18h24v30H20zM25 26h14M25 32h11M25 38h14"/>',
        "botanical": '<path d="M31 48V20M31 35Q12 32 18 20Q32 20 31 35M31 42Q49 39 47 27Q32 27 31 42"/>',
        "photography": '<rect x="16" y="19" width="32" height="27" rx="3"/><circle cx="32" cy="33" r="8"/>',
        "architecture": '<path d="M17 47V28h10v19M28 47V16h10v31M39 47V24h9v23"/>',
        "astronomy": '<path d="M38 15A18 18 0 1 0 48 42A20 20 0 0 1 38 15Z"/>',
        "typography": '<path d="M17 47L30 16h4l13 31M23 34h18"/>',
        "cartography": '<path d="M12 22q15-18 28 0t16 4M10 34q15-18 28 0t18 4M10 46q15-18 28 0t16 4"/>',
        "ceramics": '<path d="M24 17h16q-2 11 4 20q4 12-12 12T20 37q6-9 4-20Z"/>',
        "coffee": '<path d="M18 25h25v14q0 10-12 10T18 39ZM43 27q15-2 10 10q-3 5-10 2M25 12v6M34 12v6"/>',
        "acoustics": '<path d="M16 25v14M24 16v32M32 22v20M40 12v40M48 25v14"/>',
        "printmaking": '<path d="M16 17h14v14H16ZM35 17h13v14H35ZM16 36h14v13H16ZM35 36h13v13H35Z"/>',
        "coastal": '<path d="M10 22q11-10 22 0t22 0M10 33q11-10 22 0t22 0M10 44q11-10 22 0t22 0"/>',
    }
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
            f'<rect width="64" height="64" rx="{radius}" fill="{accent}"/>'
            f'<g fill="none" stroke="{bg}" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">'
            + motifs[theme] + '</g></svg>\n')


"""Version-two static collections whose content is an actual generated artifact.

Everything is local and deterministic: SVG, usable CSS, parameter JSON and
descriptions are derived from the same bounded data.  No network, model API,
invented people, clients, publication dates or commercial claims are used.
Version-one content lives in rendering.py and is deliberately unchanged.
"""

import colorsys as _as_colorsys
import hashlib as _as_hashlib
import html as _as_html
import json as _as_json
import re as _as_re
from pathlib import PurePosixPath as _ASPath


ARTIFACT_THEMES = ("generative", "patterns", "palettes", "curves")
_AS_LAYOUTS = ("editorial", "gallery", "index", "notebook", "bulletin", "folio")
_AS_KEYS = {"version", "seed", "theme", "title", "description", "layout", "palette"}
_AS_PALETTES = {
    "chalk-blue": ("#F3F1EA", "#26333C", "#63747E", "#3E6C83", "#E0E7E8", "#CAD3D4"),
    "warm-clay": ("#F5EEE5", "#3A302C", "#7B685E", "#9F5D41", "#EBDBCF", "#D7C3B4"),
    "sage-paper": ("#EFF1E6", "#2B382E", "#65735D", "#54734F", "#DFE5D3", "#C8D2BC"),
    "rose-ink": ("#F4EDF0", "#3E303B", "#7F6878", "#86536E", "#E8DCE3", "#D7C5D0"),
    "night-blue": ("#142332", "#EEEAE0", "#AEC0CE", "#CDAE73", "#243C50", "#3A5266"),
}
_AS_CONTENT = {
    "generative": {
        "names": ("Form Sequences", "Geometric Studies", "A Small Shape Archive", "Ordered Variations", "Fields of Form"),
        "descriptions": ("Original geometric compositions with their coordinates, colours, and downloadable SVG files.",
                         "A collection of circle fields, bar rhythms, and nested frames built from explicit parameters.",
                         "Small studies in repetition and proportion, with the source data beside each image."),
        "eyebrow": "Geometry / repetition / proportion",
        "methods": ("circle-grid", "bar-field", "nested-frames"),
        "about": "This collection treats a geometric composition as both an image and a set of decisions. Every study includes the actual coordinates, dimensions and colours used to draw it.",
        "method_text": "Circles are placed on a regular grid, bars share a baseline, and nested frames use progressively inset rectangles. The parameter JSON records every primitive so changes can be compared coordinate by coordinate.",
        "editing": "Open the SVG in a vector editor to move, resize, or recolour its circles, bars, or frames. The JSON lists each primitive's coordinates and colours, providing a reference when making a related variation.",
    },
    "patterns": {
        "names": ("Repeat Studies", "The Pattern Shelf", "Tiles in Sequence", "Small Repeats", "A Repeating Field"),
        "descriptions": ("Original repeating SVG tiles, full-field previews, and CSS ready for a local project.",
                         "Dot grids, diagonal stripes, and Truchet tiles with their dimensions and repeat rules.",
                         "A small library of geometric surface patterns with real downloadable source files."),
        "eyebrow": "Tile / repeat / surface",
        "methods": ("dot-grid", "diagonal-stripes", "truchet"),
        "about": "Each item is a real repeating tile. Its large preview is drawn by repeating the same SVG geometry that is available for download, so the preview and the usable material stay connected.",
        "method_text": "Dot tiles repeat a centred circle. The vertical offset between consecutive stripes divides the tile size exactly. Truchet arcs meet the midpoint of each cell edge, including the outer boundary. The SVG viewport clips each tile; the supplied CSS repeats it at its recorded dimensions.",
        "editing": "Keep the SVG and CSS in the same directory and apply the study-pattern class to an element with a defined size. Edit fill and stroke values in the SVG to change its colours. When changing tile geometry, preserve the connections at opposite edges to keep the repeat continuous.",
    },
    "palettes": {
        "names": ("Colour Sets", "The Palette Notebook", "Measured Colours", "Small Colour Collections", "Colour Relationships"),
        "descriptions": ("Generated colour sets with exact hex values, CSS variables, and measured contrast pairs.",
                         "Analogous, split-complementary, and monochrome colour studies with reusable downloads.",
                         "A collection of colour relationships whose numbers match the swatches on the page."),
        "eyebrow": "Hue / lightness / contrast",
        "methods": ("analogous", "split-complementary", "monochrome"),
        "about": "These studies begin with explicit hue, saturation and lightness steps. The displayed sRGB hex colours, exported CSS variables and measured contrast matrix all come from the same final values.",
        "method_text": "HSL values are converted to eight-bit sRGB colours. Relative luminance and contrast are calculated from those final hex values using the WCAG sRGB formula. A ratio describes a colour pair; it does not certify the accessibility of a whole design.",
        "editing": "Copy the supplied --study-color-1 through --study-color-5 CSS variables into a stylesheet and assign them to text, backgrounds, or borders. If you change a hex value, calculate its contrast again before choosing a text and background pair.",
    },
    "curves": {
        "names": ("Curve Studies", "The Control Point Archive", "Lines in Motion", "A Bezier Collection", "Paths and Handles"),
        "descriptions": ("Original cubic Bezier studies with explicit control points and editable SVG paths.",
                         "Single curves, mirrored pairs, and curve bundles with the data needed to inspect their construction.",
                         "A small collection of parameter-based line studies, from control polygons to finished curves."),
        "eyebrow": "Endpoint / handle / curve",
        "methods": ("single-cubic", "mirrored-pair", "curve-bundle"),
        "about": "A curve is presented together with the four points that define it. The collection uses cubic Bezier paths so that each drawing can be inspected, edited, and reproduced from its parameter file.",
        "method_text": "Each path begins at P0 and ends at P3; P1 and P2 are its control points. Mirrored pairs reflect those points across the vertical centreline. Bundles vary the control points while retaining a shared start and end. Moving an inner control point reshapes the curve while its endpoints keep their positions.",
        "editing": "Edit the two inner coordinate pairs after the SVG path's C command to move its control points. The JSON records all four points in order, so you can compare the curve before and after an edit. Use the matching CSS to place the resulting SVG as a background.",
    },
}


def _as_digest(seed, label):
    return _as_hashlib.sha256(("artifact-site-v2\0" + seed + "\0" + label).encode()).hexdigest()


def _as_n(seed, label, low, high):
    return low + int(_as_digest(seed, label)[:16], 16) % (high - low + 1)


def _as_pick(seed, label, values):
    return values[_as_n(seed, label, 0, len(values) - 1)]


def _as_seed(seed):
    if not isinstance(seed, str) or not _as_re.fullmatch(r"[0-9a-f]{64}", seed):
        raise ValueError("Artifact-site seed must contain exactly 64 lowercase hexadecimal characters")
    return seed


def _as_text(value, name, limit, normalize=False):
    if not isinstance(value, str) or any((ord(c) < 32 and c not in "\t\r\n") or ord(c) == 127 for c in value):
        raise ValueError("Invalid artifact-site " + name)
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError("Artifact-site text must be valid UTF-8") from exc
    if normalize:
        value = " ".join(value.split())
    if not value or len(value) > limit or value != " ".join(value.split()):
        raise ValueError(f"Artifact-site {name} must contain 1–{limit} normalized characters")
    return value


def _as_domain(value):
    if not isinstance(value, str) or not value.isascii() or value != value.strip() or len(value) > 253:
        raise ValueError("Invalid artifact-site domain")
    value = value.lower()
    labels = value.split(".")
    if len(labels) < 2 or not any("a" <= c <= "z" for c in labels[-1]):
        raise ValueError("A DNS domain is required")
    for label in labels:
        if not _as_re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label):
            raise ValueError("Invalid DNS label")
        if label.startswith("xn--"):
            try:
                if label.encode().decode("idna").encode("idna").decode() != label:
                    raise UnicodeError()
            except UnicodeError as exc:
                raise ValueError("Invalid Punycode label") from exc
    return value


def generate_artifact_profile(seed, theme="auto", title=None, description=None):
    """Create a v2 profile; auto selects only the four artifact-based families."""
    seed = _as_seed(seed)
    if theme not in ("auto", *ARTIFACT_THEMES):
        raise ValueError("Unknown artifact-site theme")
    theme = _as_pick(seed, "theme", ARTIFACT_THEMES) if theme == "auto" else theme
    data = _AS_CONTENT[theme]
    return {
        "version": 2, "seed": seed, "theme": theme,
        "title": _as_text(title if title is not None else _as_pick(seed, theme + ":title", data["names"]), "title", 160, True),
        "description": _as_text(description if description is not None else _as_pick(seed, theme + ":description", data["descriptions"]), "description", 1000, True),
        "layout": _as_pick(seed, theme + ":layout", _AS_LAYOUTS),
        "palette": _as_pick(seed, theme + ":palette", tuple(_AS_PALETTES)),
    }


def _as_profile(profile):
    if not isinstance(profile, dict) or set(profile) != _AS_KEYS:
        raise ValueError("Invalid artifact-site profile fields")
    if type(profile["version"]) is not int or profile["version"] != 2:
        raise ValueError("Unsupported artifact-site profile version")
    if profile["theme"] not in ARTIFACT_THEMES:
        raise ValueError("Artifact-site profile needs a concrete theme")
    _as_text(profile["title"], "title", 160)
    _as_text(profile["description"], "description", 1000)
    if profile != generate_artifact_profile(profile["seed"], profile["theme"], profile["title"], profile["description"]):
        raise ValueError("Artifact-site layout or palette disagrees with its seed")
    return dict(profile)


def _as_hex(hue, saturation, lightness):
    red, green, blue = _as_colorsys.hls_to_rgb((hue % 360) / 360, lightness / 100, saturation / 100)
    return "#" + "".join(f"{int(channel * 255 + 0.5):02X}" for channel in (red, green, blue))


def artifact_relative_luminance(color):
    """WCAG 2.2 sRGB luminance, from the exact exported eight-bit hex colour.

    Primary definition: https://www.w3.org/TR/WCAG22/#dfn-relative-luminance
    """
    if not isinstance(color, str) or not _as_re.fullmatch(r"#[0-9A-Fa-f]{6}", color):
        raise ValueError("Expected a six-digit RGB hex colour")
    values = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
    linear = [value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4 for value in values]
    return sum(value * weight for value, weight in zip(linear, (0.2126, 0.7152, 0.0722)))


def artifact_contrast(first, second):
    high, low = sorted((artifact_relative_luminance(first), artifact_relative_luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def _as_svg(width, height, body, title):
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="study-title">\n'
            f'<title id="study-title">{_as_html.escape(title)}</title>\n' + "\n".join(body) + '\n</svg>\n')


def _as_spec(seed, kind, method):
    """Return source data and facts. Every public description uses these facts."""
    n = lambda label, low, high: _as_n(seed, label, low, high)
    hue = n("hue", 0, 359)
    colors = [_as_hex(hue, n("saturation", 35, 65), level) for level in (16, 38, 62, 88)]
    spec = {"kind": kind, "method": method, "canvas": {"width": 960, "height": 600}, "colors": colors, "parameters": {}, "primitives": []}
    params, primitives = spec["parameters"], spec["primitives"]
    if kind == "generative":
        if method == "circle-grid":
            columns, rows = n("columns", 5, 9), n("rows", 3, 5)
            params.update(columns=columns, rows=rows, margin=70, radius_min=10, radius_max=38)
            for row in range(rows):
                for column in range(columns):
                    primitives.append({"shape": "circle", "cx": 70 + column * 820 // (columns - 1), "cy": 70 + row * 460 // (rows - 1),
                                       "radius": n(f"radius:{row}:{column}", 10, 38), "color": colors[n(f"color:{row}:{column}", 0, 2)]})
            title = f"Circle field · {columns} × {rows}"
            summary = f"{len(primitives)} circles on a {columns}-column, {rows}-row grid. Radius and colour vary within the recorded bounds."
        elif method == "bar-field":
            count = n("bars", 9, 18)
            params.update(baseline=520, bars=count, gap=8)
            width = (820 - 8 * (count - 1)) // count
            for index in range(count):
                height = n(f"height:{index}", 100, 420)
                primitives.append({"shape": "rect", "x": 70 + index * (width + 8), "y": 520 - height,
                                   "width": width, "height": height, "color": colors[n(f"color:{index}", 0, 2)]})
            title = f"Bar rhythm · {count} elements"
            summary = f"{count} rectangles share a baseline at y=520. Their widths are {width} units; their individual heights are preserved in the JSON."
        else:
            count, step = n("frames", 7, 14), n("inset", 11, 16)
            params.update(frames=count, inset_step=step, stroke_width=n("stroke", 2, 5))
            for index in range(count):
                inset = 45 + index * step
                primitives.append({"shape": "frame", "x": inset, "y": inset, "width": 960 - 2 * inset,
                                   "height": 600 - 2 * inset, "color": colors[index % 3], "stroke_width": params["stroke_width"]})
            title = f"Nested frames · {count} steps"
            summary = f"{count} rectangular outlines are inset by {step} units per step, using a {params['stroke_width']}-unit stroke."
    elif kind == "patterns":
        tile = _as_pick(seed, "tile", (96, 128, 160))
        spec["canvas"] = {"width": tile, "height": tile}
        params.update(tile_width=tile, tile_height=tile)
        if method == "dot-grid":
            radius = n("radius", tile // 12, tile // 4)
            params.update(radius=radius)
            primitives.append({"shape": "circle", "cx": tile // 2, "cy": tile // 2, "radius": radius, "color": colors[1]})
            title = f"Dot repeat · {tile}-unit tile"
            summary = f"A centred circle with radius {radius} repeats on a {tile} × {tile} tile. The large preview repeats this exact tile."
        elif method == "diagonal-stripes":
            divisions = _as_pick(seed, "divisions", (4, 8))
            spacing = tile // divisions
            stroke = n("stroke", 2, max(2, spacing // 3))
            params.update(vertical_offset_interval=spacing, stroke_width=stroke, slope=1)
            for offset in range(-tile, tile + 1, spacing):
                primitives.append({"shape": "line", "x1": 0, "y1": offset, "x2": tile, "y2": offset + tile,
                                   "color": colors[1], "stroke_width": stroke})
            title = f"Diagonal repeat · {spacing}-unit interval"
            summary = f"Parallel 45-degree lines use vertical offsets of {spacing} units. That interval divides the {tile}-unit tile exactly, preserving the repeat across its edges."
        else:
            cells = 4
            step = tile // cells
            stroke = n("stroke", 2, max(2, step // 6))
            orientations = [[n(f"turn:{row}:{column}", 0, 1) for column in range(cells)] for row in range(cells)]
            params.update(columns=cells, rows=cells, cell_size=step, stroke_width=stroke, orientations=orientations)
            radius = step // 2
            for row in range(cells):
                for column in range(cells):
                    x, y = column * step, row * step
                    # Opposite corners need opposite sweep flags. This makes
                    # each arc cross its cell edge normally, so adjacent cells
                    # and copies of the complete tile join with equal tangents.
                    if orientations[row][column] == 0:
                        paths = (f"M{x+radius} {y}A{radius} {radius} 0 0 1 {x} {y+radius}", f"M{x+step} {y+radius}A{radius} {radius} 0 0 0 {x+radius} {y+step}")
                    else:
                        paths = (f"M{x} {y+radius}A{radius} {radius} 0 0 1 {x+radius} {y+step}", f"M{x+radius} {y}A{radius} {radius} 0 0 0 {x+step} {y+radius}")
                    for path in paths:
                        primitives.append({"shape": "path", "d": path, "color": colors[1], "stroke_width": stroke})
            title = f"Truchet repeat · {cells} × {cells} cells"
            summary = f"{cells*cells} cells contain {len(primitives)} quarter-circle arcs. Every arc meets a cell-edge midpoint; the JSON records all {cells*cells} orientations."
    elif kind == "palettes":
        base_hue, saturation = hue, n("palette-saturation", 35, 72)
        lightness = (15, 32, 50, 70, 90)
        if method == "analogous":
            step = n("hue-step", 9, 24)
            hues = [(base_hue + (index - 2) * step) % 360 for index in range(5)]
        elif method == "split-complementary":
            offset = n("split-offset", 22, 42)
            hues = [base_hue, (base_hue + 180 - offset) % 360, (base_hue + 180 + offset) % 360, base_hue, (base_hue + 180 - offset) % 360]
        else:
            hues = [base_hue] * 5
        hsl = [{"h": hue_value, "s": saturation, "l": level} for hue_value, level in zip(hues, lightness)]
        colors = [_as_hex(item["h"], item["s"], item["l"]) for item in hsl]
        spec["colors"] = colors
        params.update(hsl=hsl, hex=colors, contrast_matrix=[[round(artifact_contrast(first, second), 3) for second in colors] for first in colors])
        for index, color in enumerate(colors):
            primitives.append({"shape": "rect", "x": index * 192, "y": 0, "width": 192, "height": 600, "color": color})
        pairs = [(artifact_contrast(colors[i], colors[j]), i, j) for i in range(5) for j in range(i + 1, 5)]
        ratio, first, second = max(pairs)
        params["strongest_pair"] = {"first": colors[first], "second": colors[second], "ratio": round(ratio, 3)}
        title = method.replace("-", " ").title() + f" · hue {base_hue}°"
        summary = f"Five sRGB colours from explicit HSL steps. The strongest measured pair is {colors[first]} / {colors[second]} at {ratio:.2f}:1."
    else:
        p0, p3 = [75, 450], [885, 150]
        p1, p2 = [n("p1x", 130, 390), n("p1y", 60, 510)], [n("p2x", 550, 830), n("p2y", 60, 510)]
        paths = [[p0, p1, p2, p3]]
        if method == "mirrored-pair":
            paths.append([[960 - x, y] for x, y in paths[0]])
        elif method == "curve-bundle":
            paths = [[p0, [n(f"p1x:{index}", 130, 420), n(f"p1y:{index}", 60, 520)],
                      [n(f"p2x:{index}", 540, 830), n(f"p2y:{index}", 60, 520)], p3] for index in range(n("curves", 5, 9))]
        stroke = n("curve-stroke", 3, 6)
        params.update(control_points=paths, stroke_width=stroke, curve_count=len(paths))
        for index, points in enumerate(paths):
            a, b, c, d = points
            primitives.append({"shape": "path", "d": f"M{a[0]} {a[1]}C{b[0]} {b[1]} {c[0]} {c[1]} {d[0]} {d[1]}",
                               "color": colors[index % 3], "stroke_width": stroke})
        title = method.replace("-", " ").title() + f" · {len(paths)} path" + ("s" if len(paths) != 1 else "")
        summary = f"{len(paths)} cubic Bezier path" + ("s" if len(paths) != 1 else "") + f" with a {stroke}-unit stroke. All four control points for every path are included in the downloadable data."
    return spec, title, summary


def _as_draw(spec):
    width, height = spec["canvas"]["width"], spec["canvas"]["height"]
    body = [f'<rect width="{width}" height="{height}" fill="{spec["colors"][-1]}"/>']
    for item in spec["primitives"]:
        shape = item["shape"]
        if shape == "circle":
            body.append(f'<circle cx="{item["cx"]}" cy="{item["cy"]}" r="{item["radius"]}" fill="{item["color"]}"/>')
        elif shape in ("rect", "frame"):
            style = f'fill="{item["color"]}"' if shape == "rect" else f'fill="none" stroke="{item["color"]}" stroke-width="{item["stroke_width"]}"'
            body.append(f'<rect x="{item["x"]}" y="{item["y"]}" width="{item["width"]}" height="{item["height"]}" {style}/>')
        elif shape == "line":
            body.append(f'<line x1="{item["x1"]}" y1="{item["y1"]}" x2="{item["x2"]}" y2="{item["y2"]}" stroke="{item["color"]}" stroke-width="{item["stroke_width"]}"/>')
        else:
            body.append(f'<path d="{item["d"]}" fill="none" stroke="{item["color"]}" stroke-width="{item["stroke_width"]}"/>')
    if spec["kind"] == "palettes":
        for index, color in enumerate(spec["colors"]):
            label_color = "#FFFFFF" if artifact_contrast(color, "#FFFFFF") >= artifact_contrast(color, "#000000") else "#000000"
            body.append(f'<text x="{index*192+96}" y="540" text-anchor="middle" font-family="monospace" font-size="22" fill="{label_color}">{color}</text>')
    return body


def build_artifact_collection(profile):
    """Return the actual public artifacts, with text/data/assets kept together."""
    profile = _as_profile(profile)
    seed, theme = profile["seed"], profile["theme"]
    methods = sorted(_AS_CONTENT[theme]["methods"], key=lambda method: _as_digest(seed, "method-order:" + method))
    count = _as_n(seed, "collection-size", 3, 5)
    collection = []
    for index in range(count):
        spec, title, summary = _as_spec(_as_digest(seed, f"object:{index}"), theme, methods[index % len(methods)])
        identity = _as_hashlib.sha256(_as_json.dumps(spec, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:12]
        stem = f"study-{index+1:02d}-{identity}"
        svg_name, css_name, json_name = ("downloads/" + stem + extension for extension in (".svg", ".css", ".json"))
        body = _as_draw(spec)
        width, height = spec["canvas"]["width"], spec["canvas"]["height"]
        svg = _as_svg(width, height, body, title)
        css = ":root {\n" + "".join(f"  --study-color-{number}: {color};\n" for number, color in enumerate(spec["colors"], 1)) + "}\n"
        if theme == "patterns":
            css += (f".study-pattern {{\n  background-image: url('./{stem}.svg');\n  background-repeat: repeat;\n"
                    f"  background-size: {width}px {height}px;\n}}\n")
            preview_body = [f'<defs><pattern id="tile" width="{width}" height="{height}" patternUnits="userSpaceOnUse">', *body, '</pattern></defs>',
                            '<rect width="960" height="600" fill="url(#tile)"/>']
            preview = _as_svg(960, 600, preview_body, title + " — repeated field")
        else:
            css += (f".study-artwork {{\n  background-image: url('./{stem}.svg');\n  background-repeat: no-repeat;\n"
                    f"  background-size: contain;\n  aspect-ratio: {width} / {height};\n}}\n")
            preview = svg
        data = {**spec, "title": title, "description": summary,
                "files": {"svg": svg_name.rsplit("/", 1)[-1], "css": css_name.rsplit("/", 1)[-1]},
                "svg_sha256": _as_hashlib.sha256(svg.encode()).hexdigest()}
        collection.append({"id": stem, "title": title, "summary": summary, "spec": spec,
                           "page": "studies/" + stem + ".html", "preview": "assets/" + stem + ".svg",
                           "svg_name": svg_name, "css_name": css_name, "json_name": json_name,
                           "svg": svg, "css": css, "json": _as_json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                           "preview_svg": preview})
    return collection


_AS_CSS = r'''
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.75 Georgia,'Times New Roman',serif}a{color:inherit;text-underline-offset:4px}a:hover{color:var(--accent)}a:focus-visible{outline:2px solid var(--accent);outline-offset:5px}img{display:block;width:100%;height:auto}.shell{max-width:1220px;margin:auto;padding:0 40px}header{display:flex;justify-content:space-between;align-items:center;gap:25px;border-bottom:1px solid var(--border);padding:28px 0}.brand{display:flex;align-items:center;gap:12px;text-decoration:none;font-size:18px;font-weight:bold}.brand img{width:30px;height:30px}.brand span{overflow-wrap:anywhere}nav{display:flex;gap:22px;font:12px/1.5 Arial,sans-serif;flex-shrink:0}nav a{text-decoration:none}nav a[aria-current=page]{text-decoration:underline}.eyebrow,.number,.method-label{font:11px/1.5 'Courier New',monospace;text-transform:uppercase;letter-spacing:.1em;color:var(--muted)}h1,h2,h3{font-weight:400;line-height:1.15;letter-spacing:-.025em;overflow-wrap:anywhere}h1{font-size:clamp(38px,6vw,72px);margin:18px 0 25px}h2{font-size:26px;margin:16px 0}h3{font-size:22px}.lead{color:var(--muted);font-size:20px;max-width:760px}.summary{color:var(--muted);font-size:15px}.intro{padding:55px 0 40px}.artwork{display:block;overflow:hidden;background:var(--panel);border:1px solid var(--border)}.artwork img{aspect-ratio:8/5;object-fit:cover}.object-title{text-decoration:none}.download-links{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0;font:12px/1.5 Arial,sans-serif}.download-links a{padding:8px 12px;border:1px solid var(--border);text-decoration:none;background:var(--panel)}.study-page,.text-page{max-width:850px;margin:60px auto 75px}.study-page h1,.text-page h1{font-size:clamp(34px,5vw,56px)}.study-page figure{margin:32px 0}.study-page figure img{border:1px solid var(--border)}figcaption{font:12px/1.6 Arial,sans-serif;color:var(--muted);margin-top:12px}table{width:100%;border-collapse:collapse;margin:25px 0;font:13px/1.6 Arial,sans-serif}th,td{text-align:left;border-bottom:1px solid var(--border);padding:10px 12px;vertical-align:top;overflow-wrap:anywhere}th{font-weight:600}code,pre{font-family:'Courier New',monospace;font-size:12px}pre{padding:20px;overflow:auto;background:var(--panel);line-height:1.6;border:1px solid var(--border)}.table-scroll{overflow:auto}.downloads-index li,.related li{margin:14px 0}.related{margin-top:40px;padding-top:20px;border-top:1px solid var(--border)}footer{display:flex;justify-content:space-between;gap:25px;flex-wrap:wrap;border-top:1px solid var(--border);margin-top:55px;padding:24px 0 35px;color:var(--muted);font:11px/1.6 Arial,sans-serif}.swatch{display:inline-block;width:18px;height:18px;border:1px solid var(--border);vertical-align:middle;margin-right:10px}.hero-split{display:grid;grid-template-columns:1fr 1fr;gap:50px;align-items:center;padding:60px 0}.cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:40px 30px}.cards article{padding-bottom:20px}.cards .number{display:block;margin:15px 0}.catalog{list-style:none;padding:0;border-top:2px solid var(--fg)}.catalog li{display:grid;grid-template-columns:40px minmax(0,1fr) 200px;gap:25px;align-items:start;border-bottom:1px solid var(--border);padding:28px 0}.catalog h2{margin-top:5px}.catalog .number{padding-top:10px}.folio-row{display:grid;grid-template-columns:1.25fr 1fr;gap:60px;align-items:center;padding:48px 0;border-top:1px solid var(--border)}.folio-row:nth-child(even){direction:rtl}.folio-row>*{direction:ltr}.folio-row h2{font-size:32px}.notebook{display:grid;grid-template-columns:210px minmax(0,1fr);gap:45px}.notebook-toc{position:sticky;top:25px;align-self:start}.notebook-toc ol{padding-left:20px}.notebook-toc li{margin:14px 0;font-size:14px}.notebook-entry{background:var(--panel);padding:28px;border-left:3px solid var(--accent);margin-bottom:30px}.notebook-entry .artwork{max-width:440px;margin:22px 0}.bulletin-heading{text-align:center;border-bottom:3px double var(--fg);padding:48px 25px 35px}.bulletin-heading h1{font-weight:bold;font-size:clamp(45px,7vw,90px)}.bulletin-heading .lead{margin:20px auto}.bulletin-grid{display:grid;grid-template-columns:1.5fr 1fr;gap:40px;margin-top:35px}.bulletin-main{border-right:1px solid var(--border);padding-right:38px}.bulletin-column article{border-bottom:1px solid var(--border);padding:10px 0 25px}.bulletin-main h2{font-size:36px}.editorial-feature{display:grid;grid-template-columns:1.2fr 1fr;gap:40px;align-items:center;padding:35px 0;border-top:1px solid var(--border);border-bottom:1px solid var(--border);margin-bottom:35px}.editorial-rest{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:35px}.editorial-rest article{padding:20px 0;border-bottom:1px solid var(--border)}.layout-gallery .shell{display:grid;grid-template-columns:185px minmax(0,1fr);gap:0 45px;max-width:1400px}.layout-gallery header{display:block;grid-column:1;grid-row:1/3;border-bottom:0;border-right:1px solid var(--border);padding:32px 22px 0 0;align-self:start;position:sticky;top:0}.layout-gallery .brand{display:block;font-size:23px}.layout-gallery .brand img{margin-bottom:20px;width:40px;height:40px}.layout-gallery nav{display:flex;flex-direction:column;margin-top:35px;gap:18px}.layout-gallery main,.layout-gallery footer{grid-column:2}.layout-gallery h1{font-family:Arial,sans-serif;font-size:clamp(40px,6vw,75px)}.layout-index{font-family:Arial,sans-serif}.layout-index h1{font-size:clamp(36px,5vw,60px)}.layout-notebook h1{font-family:'Courier New',monospace;font-size:clamp(34px,4vw,52px)}.layout-folio .hero-split{grid-template-columns:1.15fr 1fr}.layout-folio .hero-split .artwork{aspect-ratio:4/5}.layout-folio .hero-split .artwork img{height:100%;object-fit:cover}
@media(max-width:800px){.shell{padding:0 24px}.hero-split{gap:30px}.catalog li{grid-template-columns:28px minmax(0,1fr) 140px;gap:18px}.folio-row{gap:30px}.notebook{grid-template-columns:160px minmax(0,1fr);gap:25px}.layout-gallery .shell{grid-template-columns:140px minmax(0,1fr);gap:0 25px}.layout-gallery .brand{font-size:19px}}
@media(max-width:600px){header{padding:22px 0;gap:15px}.brand{font-size:15px}nav{gap:14px;font-size:11px}.hero-split,.editorial-feature,.bulletin-grid,.folio-row{display:block}.hero-split .artwork{margin-top:25px}.cards,.editorial-rest{grid-template-columns:1fr}.catalog li{grid-template-columns:25px minmax(0,1fr)}.catalog .row-preview{display:none}.folio-row .artwork{margin-bottom:25px}.notebook{display:block}.notebook-toc{position:static}.notebook-toc ol{columns:2}.notebook-entry{padding:22px}.bulletin-main{border-right:0;border-bottom:1px solid var(--border);padding:0 0 28px}.bulletin-column{margin-top:25px}.layout-gallery .shell{display:block}.layout-gallery header{display:flex;position:static;border-right:0;border-bottom:1px solid var(--border);padding:22px 0}.layout-gallery .brand{display:flex;font-size:16px}.layout-gallery .brand img{width:26px;height:26px;margin:0}.layout-gallery nav{flex-direction:row;margin:0;gap:12px}.layout-folio .hero-split .artwork{aspect-ratio:8/5}.study-page,.text-page{margin:42px auto 50px}.lead{font-size:18px}th,td{padding:8px}.intro{padding-top:40px}}
'''


def render_artifact_site(domain, profile):
    """Return a complete site of real, downloadable SVG/CSS/JSON studies."""
    domain, profile = _as_domain(domain), _as_profile(profile)
    e = _as_html.escape
    seed, theme, layout = profile["seed"], profile["theme"], profile["layout"]
    content, colors = _AS_CONTENT[theme], _AS_PALETTES[profile["palette"]]
    formula_link = ('<p>The calculations follow the <a href="https://www.w3.org/TR/WCAG22/#dfn-relative-luminance">W3C definition of sRGB relative luminance</a>; the contrast ratio is (lighter luminance + 0.05) / (darker luminance + 0.05).</p>'
                    if theme == "palettes" else "")
    studies = build_artifact_collection(profile)
    css_name = "assets/site-" + _as_digest(seed, "stylesheet")[:16] + ".css"
    icon_name = "assets/icon-" + _as_digest(seed, "favicon")[:16] + ".svg"
    properties = "".join(f"--{name}:{color};" for name, color in zip(("bg", "fg", "muted", "accent", "panel", "border"), colors))
    files = {css_name: ":root{" + properties + "}\n" + _AS_CSS,
             icon_name: _as_svg(64, 64, [f'<rect width="64" height="64" rx="14" fill="{colors[3]}"/>',
                                       f'<circle cx="24" cy="25" r="10" fill="{colors[0]}"/><path d="M22 45L45 22V45Z" fill="{colors[0]}"/>'], content["eyebrow"])}

    def page(title, body, filename, active="", description=None):
        navigation = "".join(f'<a href="{url}"' + (' aria-current="page"' if active == key else '') + f'>{label}</a>'
                             for key, url, label in (("collection", "/", "Collection"), ("methods", "/methods.html", "Methods"), ("about", "/about.html", "About")))
        canonical = "https://" + domain + "/" + ("" if filename == "index.html" else filename)
        return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="{e(description if description is not None else profile['description'], quote=True)}">
<title>{e(title, quote=True)} · {e(profile['title'], quote=True)}</title><link rel="canonical" href="{canonical}">
<link rel="icon" type="image/svg+xml" href="/{icon_name}"><link rel="stylesheet" href="/{css_name}"></head>
<body class="layout-{layout} theme-{theme}"><div class="shell"><header><a class="brand" href="/"><img src="/{icon_name}" alt="" width="30" height="30"><span>{e(profile['title'], quote=True)}</span></a><nav aria-label="Main navigation">{navigation}</nav></header>
<main>{body}</main><footer><span>{domain}</span><span><a href="/downloads.html">Download the studies</a> · SVG / CSS / JSON</span></footer></div></body></html>
'''

    def preview(item, cls="artwork"):
        return f'<a class="{cls}" href="/{item["page"]}"><img src="/{item["preview"]}" alt="{e(item["title"], quote=True)}" width="960" height="600" loading="lazy"></a>'

    def text(item):
        return (f'<p class="method-label">{e(item["spec"]["method"].replace("-", " "))}</p><h2><a class="object-title" href="/{item["page"]}">{e(item["title"])}</a></h2>'
                f'<p class="summary">{e(item["summary"])}</p><a href="/{item["page"]}">Inspect the study</a>')

    intro = f'<p class="eyebrow">{e(content["eyebrow"])}</p><h1>{e(profile["title"])}</h1><p class="lead">{e(profile["description"])}</p>'
    if layout == "gallery":
        cards = "".join(f'<article><span class="number">Study {index:02d}</span>{preview(item)}{text(item)}</article>' for index, item in enumerate(studies, 1))
        home = f'<section class="intro">{intro}</section><section class="cards" aria-label="The collection">{cards}</section>'
    elif layout == "index":
        rows = "".join(f'<li><span class="number">{index:02d}</span><div>{text(item)}</div>{preview(item,"row-preview")}</li>' for index, item in enumerate(studies, 1))
        home = f'<section class="intro">{intro}</section><ol class="catalog">{rows}</ol>'
    elif layout == "folio":
        rows = "".join(f'<article class="folio-row">{preview(item)}<div><p class="number">{index:02d} / {len(studies):02d}</p>{text(item)}</div></article>' for index, item in enumerate(studies, 1))
        home = f'<section class="hero-split">{preview(studies[0])}<div>{intro}</div></section><section aria-label="The collection">{rows}</section>'
    elif layout == "notebook":
        toc = "".join(f'<li><a href="#study-{index}">{e(item["title"])}</a></li>' for index, item in enumerate(studies, 1))
        entries = "".join(f'<article class="notebook-entry" id="study-{index}"><p class="number">Study {index:02d}</p>{text(item)}{preview(item)}<p class="summary">Source files: editable SVG, matching CSS, and the actual parameter JSON.</p></article>' for index, item in enumerate(studies, 1))
        home = f'<section class="intro">{intro}</section><div class="notebook"><aside class="notebook-toc"><p class="eyebrow">In this collection</p><ol>{toc}</ol></aside><section>{entries}</section></div>'
    elif layout == "bulletin":
        column = "".join(f'<article>{text(item)}</article>' for item in studies[1:])
        home = f'<section class="bulletin-heading">{intro}</section><section class="bulletin-grid"><article class="bulletin-main">{preview(studies[0])}{text(studies[0])}</article><div class="bulletin-column">{column}</div></section>'
    else:
        rest = "".join(f'<article>{text(item)}</article>' for item in studies[1:])
        home = f'<section class="intro">{intro}</section><article class="editorial-feature">{preview(studies[0])}<div>{text(studies[0])}</div></article><section class="editorial-rest" aria-label="More studies">{rest}</section>'
    files["index.html"] = page("Collection", home, "index.html", "collection")

    def downloads(item):
        return '<div class="download-links">' + "".join(f'<a download href="/{item[key]}">Download {label}</a>' for key, label in (("svg_name", "SVG"), ("css_name", "CSS"), ("json_name", "JSON"))) + '</div>'

    for item in studies:
        files.update({item["svg_name"]: item["svg"], item["css_name"]: item["css"], item["json_name"]: item["json"], item["preview"]: item["preview_svg"]})
        spec = item["spec"]
        rows = [("Construction", spec["method"].replace("-", " ")), ("SVG dimensions", f'{spec["canvas"]["width"]} × {spec["canvas"]["height"]}'),
                ("Geometric primitives", str(len(spec["primitives"]))), ("Colours", ", ".join(spec["colors"]))]
        table = '<table><tbody>' + "".join(f'<tr><th>{e(label)}</th><td>{e(value)}</td></tr>' for label, value in rows) + '</tbody></table>'
        detail = ""
        if theme == "palettes":
            matrix = spec["parameters"]["contrast_matrix"]
            table_head = '<tr><th>Pair</th>' + "".join(f'<th>{e(color)}</th>' for color in spec["colors"]) + '</tr>'
            table_rows = "".join('<tr><th>' + e(color) + '</th>' + "".join(f'<td>{ratio:.2f}:1</td>' for ratio in matrix[index]) + '</tr>' for index, color in enumerate(spec["colors"]))
            detail = '<h2>Measured contrast pairs</h2><div class="table-scroll"><table>' + table_head + table_rows + '</table></div><p>Ratios use the exact exported sRGB hex values. They describe these pairs, not the accessibility of an entire interface.</p>'
        params = _as_json.dumps(spec["parameters"], ensure_ascii=False, indent=2)
        related = "".join(f'<li><a href="/{other["page"]}">{e(other["title"])}</a></li>' for other in studies if other is not item)
        caption = "The repeated field uses the exact downloadable tile." if theme == "patterns" else "This preview uses the exact downloadable SVG."
        body = (f'<article class="study-page"><p class="eyebrow">{e(spec["method"].replace("-", " "))}</p><h1>{e(item["title"])}</h1><p class="lead">{e(item["summary"])}</p>'
                f'<figure><img src="/{item["preview"]}" alt="{e(item["title"], quote=True)}" width="960" height="600"><figcaption>{caption}</figcaption></figure>'
                f'{downloads(item)}<h2>What is in this study</h2>{table}<p>{e(content["method_text"])}</p>{detail}{formula_link}'
                f'<h2>The actual parameters</h2><pre>{e(params)}</pre><p>The JSON download also records every geometric primitive and the SHA-256 of the SVG file.</p>'
                f'<h2>Make a variation</h2><p>{e(content["editing"])}</p>'
                '<p>Keep the SVG and CSS in the same directory when using the background-image rule. The CSS also exports the colours as custom properties.</p>'
                f'<section class="related"><h2>Other studies</h2><ul>{related}</ul></section></article>')
        files[item["page"]] = page(item["title"], body, item["page"], description=item["summary"])
    files["methods.html"] = page("Methods", f'<article class="text-page"><p class="eyebrow">How the materials are made</p><h1>From parameters to a usable file</h1><p class="lead">{e(content["method_text"])}</p>{formula_link}<h2>One source for image and description</h2><p>Each study begins with a bounded set of parameters. Those values produce its SVG, its downloadable JSON, and the measurements stated on its page. Compare the image with its numbers to see how individual choices affect the composition.</p><h2>Three useful formats</h2><p>SVG contains editable vector geometry. CSS provides colour variables and a local background-image rule. JSON preserves the parameters, primitives and SVG checksum. Download the SVG and CSS into the same directory, then include the stylesheet in your project.</p><h2>Make a variation</h2><p>{e(content["editing"])}</p><p><a href="/downloads.html">Browse the available downloads</a></p></article>', "methods.html", "methods")
    files["about.html"] = page("About", f'<article class="text-page"><p class="eyebrow">About the collection</p><h1>{e(profile["title"])}</h1><p class="lead">{e(content["about"])}</p><h2>Explore, compare, and adapt</h2><p>The collection contains {len(studies)} original parameter-based studies. Each page pairs the finished image with its dimensions, construction data, and source files. Open two studies to compare their proportions or colour choices, then download a starting point for your own variation.</p><h2>Take a study into your project</h2><p>{e(content["editing"])}</p><p><a href="/methods.html">Read about the construction methods</a> or <a href="/downloads.html">browse the available files</a>.</p></article>', "about.html", "about")
    download_entries = "".join(f'<li><h2><a href="/{item["page"]}">{e(item["title"])}</a></h2><p class="summary">{e(item["summary"])}</p>{downloads(item)}</li>' for item in studies)
    files["downloads.html"] = page("Downloads", f'<section class="text-page"><p class="eyebrow">Usable source files</p><h1>Download the studies</h1><p class="lead">Every link below points to a real local file. Keep matching SVG and CSS files together to use the supplied background rule.</p><ul class="downloads-index">{download_entries}</ul></section>', "downloads.html")
    files["404.html"] = page("Page not found", '<section class="text-page"><p class="eyebrow">404</p><h1>Page not found</h1><p>The address may have changed.</p><p><a href="/">Return to the collection</a></p></section>', "404.html")
    pages = ["", "about.html", "methods.html", "downloads.html"] + [item["page"] for item in studies]
    files["sitemap.xml"] = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + "".join(f'  <url><loc>https://{domain}/{name}</loc></url>\n' for name in pages) + '</urlset>\n'
    files["robots.txt"] = f"User-agent: *\nAllow: /\nSitemap: https://{domain}/sitemap.xml\n"
    for name, value in files.items():
        path = _ASPath(name)
        if path.is_absolute() or str(path) != name or ".." in path.parts or not _as_re.fullmatch(r"[a-z0-9][a-z0-9_./-]*", name) or not isinstance(value, str):
            raise ValueError("Invalid generated artifact file")
    return files


"""Pure renderers for HTTPS Node; no filesystem or network side effects.

The XHTTP upstream uses HTTP/2 cleartext via nginx's grpc module, following
https://github.com/XTLS/Xray-examples/tree/main/VLESS-XHTTP3-Nginx .  The client
transport remains XHTTP.  This avoids the HTTP/1.1 streaming-upload failure
described in https://github.com/XTLS/Xray-core/issues/7180 .

ssl_reject_handshake needs nginx >= 1.19.4; the target distribution packages
are Ubuntu 24.04/26.04 and Debian 12/13.  The older ``listen ... http2`` syntax is
intentional: it also works with nginx 1.22 and 1.24.
"""


import html
import ipaddress
import re
from pathlib import PurePosixPath
from typing import Dict, Optional


def validate_domain(value: str) -> str:
    """Return a canonical ASCII FQDN, rejecting addresses and config syntax.

    Unicode domain names must be supplied as their ASCII/Punycode form.  A
    trailing dot is rejected so certificate, HTTP Host and SNI comparisons
    use one spelling.  This is syntax validation, not DNS/control validation.
    """
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("Domain must be a nonempty DNS name without whitespace")
    if not value.isascii() or len(value) > 253 or value.endswith("."):
        raise ValueError("Use an ASCII/Punycode domain without a trailing dot")
    value = value.lower()
    labels = value.split(".")
    if len(labels) < 2:
        raise ValueError("A fully qualified domain such as example.com is required")
    label_pattern = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
    for label in labels:
        if not label_pattern.fullmatch(label):
            raise ValueError("Domain contains an invalid DNS label")
        if label.startswith("xn--"):
            try:
                decoded = label.encode("ascii").decode("idna")
                if decoded.encode("idna").decode("ascii") != label:
                    raise UnicodeError("Punycode label is not canonical")
            except UnicodeError as exc:
                raise ValueError("Domain contains an invalid Punycode label") from exc
    if not any("a" <= char <= "z" for char in labels[-1]):
        raise ValueError("Domain must be a DNS name, not an IP address")
    return value


def validate_ipv4(value: str) -> str:
    """Return one concrete unicast IPv4 address (loopback is valid for tests)."""
    if not isinstance(value, str):
        raise ValueError("A literal IPv4 bind address is required")
    try:
        address = ipaddress.IPv4Address(value)
    except (ipaddress.AddressValueError, TypeError, ValueError) as exc:
        raise ValueError("A literal IPv4 bind address is required") from exc
    if address.is_unspecified or address.is_multicast or int(address) == 0xFFFFFFFF:
        raise ValueError("Use a concrete unicast IPv4 address, not a wildcard")
    return str(address)


def _render_port(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 65535:
        raise ValueError("TCP ports must be integers between 1 and 65535")
    return value


def _nginx_path(value: str) -> str:
    """Quote a literal absolute nginx path; variables and controls are rejected.

    Nginx variable interpolation differs between directives.  Rejecting '$'
    avoids relying on a directive-specific escape to make a path literal.
    Spaces, Unicode and embedded quotes are otherwise supported.
    """
    value = str(value)
    if not value.startswith("/") or str(PurePosixPath(value)) in {"/", "//"}:
        raise ValueError("NGINX file paths must be absolute and must not be /")
    if any(ord(char) < 32 or ord(char) == 127 for char in value) or "$" in value:
        raise ValueError("NGINX file paths must not contain control characters or $")
    if ".." in PurePosixPath(value).parts:
        raise ValueError("NGINX file paths must not contain parent traversal")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _child_path(parent: str, name: str) -> str:
    return str(PurePosixPath(str(parent)) / name)


def _tunnel_path(value: str) -> str:
    if not isinstance(value, str) or len(value) > 240:
        raise ValueError("Tunnel path must be a short literal URL path")
    if not re.fullmatch(r"/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]{16,128}/", value):
        raise ValueError("Tunnel path needs a trailing slash and a token of 16+ characters")
    return value


def normalize_panel_access(mode="ssh", allow=None):
    """Validate panel exposure and return literal, canonical nginx ACL entries."""
    if not isinstance(mode, str) or mode not in {"ssh", "https"}:
        raise ValueError("Panel access must be ssh or https")
    if allow is None:
        allow = []
    if not isinstance(allow, (list, tuple)) or len(allow) > 128:
        raise ValueError("Panel allowlist must be a list of at most 128 IP addresses or CIDRs")
    normalized = []
    for entry in allow:
        if (not isinstance(entry, str) or not entry or len(entry) > 128
                or entry != entry.strip() or "%" in entry):
            raise ValueError("Panel allowlist entries must be literal IP addresses or CIDRs")
        try:
            address = ipaddress.ip_network(entry, strict=False) if "/" in entry else ipaddress.ip_address(entry)
        except ValueError as exc:
            raise ValueError("Panel allowlist entries must be literal IP addresses or CIDRs") from exc
        value = str(address)
        if value not in normalized:
            normalized.append(value)
    if mode == "ssh" and normalized:
        raise ValueError("A panel allowlist requires --panel-access https or --mode https")
    return mode, normalized


def render_site(domain: str, title: str, description: str) -> Dict[str, str]:
    """Render editable static pages without login forms or external requests."""
    domain = validate_domain(domain)
    if not isinstance(title, str) or not title.strip() or len(title) > 160:
        raise ValueError("Site title must contain 1–160 characters")
    if not isinstance(description, str) or not description.strip() or len(description) > 1000:
        raise ValueError("Site description must contain 1–1000 characters")
    for value in (title, description):
        if any(ord(char) < 32 and char not in "\n\t" for char in value):
            raise ValueError("Site text must not contain control characters")
    heading = html.escape(title.strip(), quote=True)
    description_text = html.escape(description.strip(), quote=True)
    domain_text = html.escape(domain, quote=True)

    def page(page_title: str, body: str, selected: str = "") -> str:
        home_current = ' aria-current="page"' if selected == "home" else ""
        about_current = ' aria-current="page"' if selected == "about" else ""
        return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="{description_text}">
  <title>{page_title} · {heading}</title>
  <link rel="stylesheet" href="/style.css">
</head>
<body>
  <div class="page">
    <header class="site-header">
      <a class="brand" href="/">{heading}</a>
      <nav aria-label="Main navigation">
        <a href="/"{home_current}>Notes</a>
        <a href="/about.html"{about_current}>About</a>
      </nav>
    </header>
    <main>{body}</main>
    <footer><span>{domain_text}</span><span>Notes, ideas, and useful references.</span></footer>
  </div>
</body>
</html>
'''

    index_body = f'''
      <section class="intro">
        <p class="eyebrow">A small collection</p>
        <h1>{heading}</h1>
        <p class="lead">{description_text}</p>
      </section>
      <section class="notes" aria-label="Notes">
        <article>
          <p class="category">Practice</p>
          <h2>Keep a useful notebook</h2>
          <p>A note is most useful when it explains one idea clearly. Give it a
          descriptive title, include the context, and leave a next step when
          there is more to explore.</p>
          <p>Small observations are worth keeping. Revisiting them occasionally
          makes it easier to find connections without turning every thought
          into a finished article.</p>
        </article>
        <article>
          <p class="category">Reading</p>
          <h2>Make room for slow reading</h2>
          <p>Choose one question before opening a long article. Write a few
          sentences about what changed your understanding, and keep a reference
          to the original so the context is easy to recover.</p>
          <p>A short list of worthwhile references is easier to revisit than
          an overflowing collection of unexplained bookmarks.</p>
        </article>
      </section>
'''
    about_body = f'''
      <section class="intro narrow">
        <p class="eyebrow">About this site</p>
        <h1>A place for useful ideas</h1>
        <p class="lead">{description_text}</p>
        <p>The pages here are a small collection of notes and references.
        The focus is clear writing, practical observations, and ideas that are
        worth returning to.</p>
        <p>This site works without an account, tracking scripts, or external
        fonts. Its pages can be read directly in any modern browser.</p>
        <p><a class="text-link" href="/">Return to the notes</a></p>
      </section>
'''
    missing_body = '''
      <section class="intro narrow">
        <p class="eyebrow">404</p>
        <h1>Page not found</h1>
        <p class="lead">The address may have changed, or the page may no longer be here.</p>
        <p><a class="text-link" href="/">Return to the notes</a></p>
      </section>
'''
    css = '''*{box-sizing:border-box}html{color-scheme:light}body{margin:0;background:#f6f4ef;color:#25312d;font-family:Georgia,"Times New Roman",serif;line-height:1.7}.page{max-width:1040px;margin:0 auto;padding:0 44px}.site-header{display:flex;justify-content:space-between;align-items:center;gap:24px;padding:30px 0;border-bottom:1px solid #d8ddd4}.brand{font-size:18px;font-weight:bold;letter-spacing:-.02em;text-decoration:none;color:inherit}nav{display:flex;gap:24px;font-family:system-ui,sans-serif;font-size:13px}nav a{color:#55635a;text-decoration:none}nav a[aria-current=page]{color:#172a21;text-decoration:underline;text-underline-offset:6px}.intro{padding:74px 0 54px;max-width:750px}.eyebrow,.category{font-family:system-ui,sans-serif;font-size:11px;font-weight:650;letter-spacing:.15em;text-transform:uppercase;color:#60715b}.eyebrow{margin:0 0 20px}h1{font-size:clamp(36px,6vw,60px);font-weight:400;line-height:1.12;letter-spacing:-.04em;margin:0 0 24px;overflow-wrap:anywhere}.lead{font-size:21px;color:#5a655c;line-height:1.6}.notes{display:grid;grid-template-columns:1fr 1fr;gap:54px;border-top:1px solid #d8ddd4;padding:40px 0 70px}.category{margin:0 0 10px}h2{font-size:25px;font-weight:400;line-height:1.3;letter-spacing:-.02em;margin:0 0 20px}article p{color:#526057;font-size:16px}.narrow{max-width:690px;padding-bottom:80px}.text-link{color:#34583d;text-underline-offset:4px}footer{display:flex;flex-wrap:wrap;justify-content:space-between;gap:8px;border-top:1px solid #d8ddd4;padding:24px 0 36px;color:#778078;font-family:system-ui,sans-serif;font-size:11px}@media(max-width:640px){.page{padding:0 22px}.site-header{padding:23px 0}.brand{font-size:16px}nav{gap:16px}.intro{padding:48px 0 34px}.lead{font-size:19px}.notes{grid-template-columns:1fr;gap:30px;padding-bottom:44px}footer{display:block}footer span{display:block}}
'''
    return {
        "index.html": page("Notes", index_body, "home"),
        "about.html": page("About", about_body, "about"),
        "style.css": css,
        "404.html": page("Page not found", missing_body),
        "robots.txt": "User-agent: *\nAllow: /\n",
    }


def render_nginx(
    domain: str,
    bind_ip: str,
    transport: str,
    inbound_port: int,
    path: str,
    site_root: str,
    cert_path: Optional[str] = None,
    key_path: Optional[str] = None,
    http_port: int = 80,
    https_port: int = 443,
    runtime_root: str = "/run/https-node-nginx",
    log_root: str = "/var/log/https-node/nginx",
    cache_root: str = "/var/cache/https-node-nginx",
    worker_user: Optional[str] = "www-data",
    *,
    panel_access: str = "ssh",
    panel_path: Optional[str] = None,
    panel_port: Optional[int] = None,
    panel_allow=None,
) -> str:
    """Render a complete isolated nginx configuration, including ACME mode.

    With both certificate paths omitted, only an HTTP ACME listener is
    rendered.  Supply ``worker_user=None`` for an unprivileged local test.
    The caller creates directories and sets their permissions before starting
    nginx.  No upstream configuration or shared nginx files are included.
    Optional HTTPS panel routing retains the upstream base path and applies
    source-IP access rules only to that path. SSH remains the default.
    """
    domain = validate_domain(domain)
    bind_ip = validate_ipv4(bind_ip)
    inbound_port, http_port, https_port = map(_render_port, (inbound_port, http_port, https_port))
    if len({inbound_port, http_port, https_port}) != 3:
        raise ValueError("HTTP, HTTPS, and loopback inbound ports must be distinct")
    if transport not in {"xhttp", "ws"}:
        raise ValueError("Transport must be xhttp or ws")
    path = _tunnel_path(path)
    panel_access, panel_allow = normalize_panel_access(panel_access, panel_allow)
    if panel_path is not None:
        panel_path = _tunnel_path(panel_path)
        if panel_path.startswith(path) or path.startswith(panel_path):
            raise ValueError("Panel and transport URL paths must not overlap")
    if panel_port is not None:
        panel_port = _render_port(panel_port)
        if panel_port in {inbound_port, http_port, https_port}:
            raise ValueError("Panel, inbound, HTTP and HTTPS ports must be distinct")
    if panel_access == "https" and (panel_path is None or panel_port is None):
        raise ValueError("HTTPS panel access requires its existing secret path and loopback port")
    if (cert_path is None) != (key_path is None):
        raise ValueError("Certificate and key paths must be supplied together")
    tls = cert_path is not None
    site = _nginx_path(site_root)
    runtime_pid = _nginx_path(_child_path(runtime_root, "nginx.pid"))
    error_log = _nginx_path(_child_path(log_root, "error.log"))
    access_log = _nginx_path(_child_path(log_root, "access.log"))
    # Validate even parent paths: joining must not conceal a malformed input.
    for parent in (runtime_root, log_root, cache_root):
        _nginx_path(parent)
    if worker_user is not None and not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", worker_user):
        raise ValueError("Invalid nginx worker user")
    user_line = f"user {worker_user};\n" if worker_user else ""
    temp_lines = "\n".join(
        f"    {directive} {_nginx_path(_child_path(cache_root, name))};"
        for directive, name in (
            ("client_body_temp_path", "client_body"),
            ("proxy_temp_path", "proxy"),
            ("fastcgi_temp_path", "fastcgi"),
            ("uwsgi_temp_path", "uwsgi"),
            ("scgi_temp_path", "scgi"),
        )
    )
    authority = domain + (f":{https_port}" if https_port != 443 else "")
    http_action = f"return 301 https://{authority}$request_uri;" if tls else "return 404;"
    http_servers = f'''
    server {{
        listen {bind_ip}:{http_port} default_server;
        server_name _;
        return 404;
    }}
    server {{
        listen {bind_ip}:{http_port};
        server_name {domain};
        if ($host != {domain}) {{ return 404; }}
        if ($http_host = "") {{ return 404; }}
        location ^~ /.well-known/acme-challenge/ {{
            root {site};
            default_type text/plain;
            try_files $uri =404;
        }}
        location / {{ {http_action} }}
    }}
'''
    tls_servers = ""
    if tls:
        cert = _nginx_path(cert_path)
        key = _nginx_path(key_path)
        if transport == "xhttp":
            tunnel = f'''
        location = {path[:-1]} {{ return 404; }}
        location ^~ {path} {{
            access_log off;
            client_max_body_size 0;
            client_body_timeout 300s;
            grpc_connect_timeout 5s;
            grpc_read_timeout 3600s;
            grpc_send_timeout 3600s;
            grpc_socket_keepalive on;
            grpc_set_header Host $host;
            grpc_set_header X-Real-IP $remote_addr;
            grpc_set_header X-Forwarded-For $remote_addr;
            grpc_set_header X-Https-Node 1;
            grpc_pass grpc://127.0.0.1:{inbound_port};
        }}
'''
        else:
            tunnel = f'''
        location = {path} {{
            if ($request_method != GET) {{ return 404; }}
            if ($http_upgrade !~* ^websocket$) {{ return 404; }}
            access_log off;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Https-Node 1;
            proxy_connect_timeout 5s;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            proxy_buffering off;
            proxy_request_buffering off;
            proxy_pass http://127.0.0.1:{inbound_port};
        }}
'''
        panel_map = ""
        if panel_access == "https":
            panel_map = '''
    map $http_upgrade $https_node_panel_connection {
        default upgrade;
        "" close;
    }
'''
            acl = "".join(f"            allow {entry};\n" for entry in panel_allow)
            if panel_allow:
                acl += "            deny all;\n"
            # Proxy the bare URL as well: a local `return 301` would run before
            # nginx's access phase and would bypass its source-IP restrictions.
            for selector in ("= " + panel_path[:-1], "^~ " + panel_path):
                tunnel += f'''
        location {selector} {{
{acl}            access_log off;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $https_node_panel_connection;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $remote_addr;
            proxy_set_header X-Forwarded-Proto https;
            proxy_set_header X-Forwarded-Host $host;
            proxy_set_header X-Forwarded-Port $server_port;
            proxy_connect_timeout 5s;
            proxy_read_timeout 3600s;
            proxy_send_timeout 3600s;
            proxy_buffering off;
            proxy_redirect http://127.0.0.1:{panel_port}/ https://{authority}/;
            proxy_pass http://127.0.0.1:{panel_port};
        }}
'''
        tls_servers = panel_map + f'''
    # Host-name map comparisons are case-insensitive, as DNS names require.
    map $ssl_server_name $https_node_sni_ok {{
        hostnames;
        default 0;
        {domain} 1;
    }}
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:HTTPSNodeTLS:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    server {{
        listen {bind_ip}:{https_port} ssl http2 default_server;
        server_name _;
        ssl_reject_handshake on;
        return 404;
    }}
    server {{
        listen {bind_ip}:{https_port} ssl http2;
        server_name {domain};
        ssl_certificate {cert};
        ssl_certificate_key {key};
        if ($https_node_sni_ok = 0) {{ return 404; }}
        if ($host != {domain}) {{ return 404; }}
        if ($http_host = "") {{ return 404; }}
        add_header Strict-Transport-Security "max-age=15552000" always;
        add_header X-Content-Type-Options nosniff always;
        add_header Referrer-Policy strict-origin-when-cross-origin always;
        root {site};
        index index.html;
        error_page 404 /404.html;
        location = /404.html {{ internal; }}
{tunnel}
        location ~ /\\. {{ return 404; }}
        location / {{ try_files $uri $uri/ =404; }}
    }}
'''
    return f'''# HTTPS Node: dedicated configuration. No shared nginx includes.
# XHTTP uses HTTP/2 cleartext to loopback, not an HTTP/1.1 proxy upstream.
{user_line}worker_processes auto;
pid {runtime_pid};
error_log {error_log} warn;

events {{ worker_connections 4096; }}
http {{
    types {{
        text/html html htm;
        text/css css;
        text/plain txt;
        application/javascript js;
        application/json json;
        application/xml xml;
        application/pdf pdf;
        image/svg+xml svg;
        image/png png;
        image/jpeg jpg jpeg;
        image/gif gif;
        image/webp webp;
        image/x-icon ico;
        font/woff woff;
        font/woff2 woff2;
        video/mp4 mp4;
    }}
    default_type application/octet-stream;
    access_log {access_log} combined;
    server_tokens off;
    sendfile on;
    tcp_nopush on;
    keepalive_timeout 65s;
    client_header_timeout 15s;
    client_body_timeout 300s;
    reset_timedout_connection on;
{temp_lines}
{http_servers}
{tls_servers}
}}
'''


# Site generator v1.  Keep these banks and selection namespaces stable for v1:
# an existing private profile must reproduce the same public files after restart.
# New content banks or generation rules require a new profile version.
import hashlib as _site_hashlib

SITE_THEMES = ("journal", "botanical", "photography", "architecture", "astronomy")
_SITE_LAYOUTS = ("editorial", "gallery", "index", "notebook", "bulletin", "folio")
_SITE_PROFILE_KEYS = {"version", "seed", "theme", "title", "description", "layout", "palette"}

_SITE_THEME_DATA = {
    "journal": {
        "names": ("Collected Notes", "Useful Margins", "Quiet Pages", "Small Observations", "A Working Notebook", "Notes in Passing"),
        "descriptions": (
            "Short notes on attention, reading, and making room for useful ideas.",
            "A collection of small observations, practical questions, and things worth revisiting.",
            "Ideas about everyday routines, clear thinking, and the value of keeping a notebook.",
            "An open notebook about noticing more and collecting less.",
        ),
        "eyebrow": "Ideas for everyday life",
        "about": (
            "These pages explore the small habits that make ideas easier to notice and revisit. The subjects are ordinary: a question in a notebook, a passage in a book, or a pause between tasks.",
            "Each note follows one idea far enough to make it useful. There is no need to read the collection in order; start with a question that matches the day.",
        ),
        "caption": "A study of paper, lines, and the space between them.",
        "palettes": {
            "oat": ("#F4F0E7", "#26322E", "#627167", "#537258", "#E5E8DA", "#D6D9CC"),
            "terracotta": ("#F6EFE7", "#3E302A", "#806D61", "#A55F43", "#ECDED1", "#DCC9BA"),
            "slate": ("#EEF0F0", "#25333B", "#62747F", "#426C83", "#DCE5E9", "#C8D3DA"),
            "plum": ("#F3EDF1", "#3F303E", "#7B6477", "#81556F", "#E8DCE5", "#D7C7D2"),
        },
    },
    "botanical": {
        "names": ("Notes on Leaves", "The Green Margin", "A Window Garden", "Plant Observations", "Among the Stems", "An Everyday Herbarium"),
        "descriptions": (
            "A small collection of observations about leaves, light, growth, and garden edges.",
            "Botanical notes for looking closely at the plants in everyday surroundings.",
            "Shape, texture, and seasonal change, gathered into a quiet plant notebook.",
            "Simple studies of plants and the spaces in which they grow.",
        ),
        "eyebrow": "Botanical observations",
        "about": (
            "This collection begins with the visible details of plants: the outline of a leaf, a branching stem, or the way light changes across a windowsill.",
            "The notes encourage close observation rather than a checklist of things to own. A familiar plant can offer a new detail when it is seen at a different time or from a different angle.",
        ),
        "caption": "An abstract study of branching stems and leaf shapes.",
        "palettes": {
            "fern": ("#F0F2E7", "#263A2B", "#66755E", "#507B50", "#DDE7CF", "#C7D4BB"),
            "clay": ("#F6EFE2", "#3C392A", "#7D775E", "#9B6B43", "#ECE0C8", "#D9CCAE"),
            "sage": ("#EAF0EA", "#283C35", "#627C6B", "#487D67", "#D5E5D9", "#BDCFBF"),
            "berry": ("#F5EFEA", "#44313A", "#806472", "#92586C", "#EAD9DF", "#D6C3CB"),
        },
    },
    "photography": {
        "names": ("Everyday Frames", "Light Studies", "A Passing Frame", "Looking at Light", "The Quiet Image", "Notes on Seeing"),
        "descriptions": (
            "Notes on light, framing, colour, and the quiet details of everyday images.",
            "A visual notebook about finding a clear frame in ordinary surroundings.",
            "Small studies in composition, contrast, and the space around a subject.",
            "Observations about photographs before the shutter is pressed.",
        ),
        "eyebrow": "Studies in seeing",
        "about": (
            "These notes look at the choices that shape an image: where to stand, what to leave outside the frame, and how light divides a surface.",
            "The illustrations are abstract composition studies. They keep attention on relationships between shapes and tones, without depending on a particular camera or location.",
        ),
        "caption": "A geometric composition study in light and shadow.",
        "palettes": {
            "silver": ("#F0F0ED", "#272C30", "#70777A", "#527985", "#DDE5E5", "#CDD1D0"),
            "amber": ("#F8F1E5", "#38332B", "#84765F", "#AC7840", "#EEDFBE", "#D8C9AD"),
            "rose": ("#F3EDEC", "#3C3033", "#846970", "#A56A77", "#E9D8D9", "#D7C2C7"),
            "blue": ("#EAF0F4", "#283542", "#687E90", "#487996", "#D6E4EE", "#BCD0DE"),
        },
    },
    "architecture": {
        "names": ("Notes on Space", "Room and Measure", "Built Observations", "Between Rooms", "Everyday Structures", "A Measure of Space"),
        "descriptions": (
            "Observations about rooms, thresholds, materials, and the spaces between buildings.",
            "A notebook on the proportions and textures of everyday architecture.",
            "Looking closely at how light, scale, and movement give a place its character.",
            "Short studies of built spaces and the details that connect them.",
        ),
        "eyebrow": "Space and proportion",
        "about": (
            "This notebook considers architecture through everyday experience: crossing a doorway, finding a place to sit, or watching daylight move along a wall.",
            "Its diagrams are abstract studies rather than representations of named buildings. The aim is to make spatial relationships easier to notice in the places already around us.",
        ),
        "caption": "An abstract elevation exploring proportion and repetition.",
        "palettes": {
            "concrete": ("#F0EFEA", "#343631", "#777B70", "#737F5B", "#E0E2D7", "#CBCEC2"),
            "brick": ("#F3ECE5", "#3D312C", "#846D5F", "#A1664A", "#E8D9CA", "#D2BEAC"),
            "chalk": ("#F5F2E9", "#343A3D", "#7B8282", "#477B87", "#DDE8E5", "#C7D4CE"),
            "ink": ("#EDEFF2", "#2B3342", "#6B758A", "#5B6E91", "#DCE2EC", "#C8D0DE"),
        },
    },
    "astronomy": {
        "names": ("Sky Notebook", "Notes after Twilight", "A Quiet Sky", "Night Observations", "The Evening Index", "Patterns above Us"),
        "descriptions": (
            "A notebook about twilight, the Moon, and finding familiar patterns in the night sky.",
            "Short observations for looking up with patience and curiosity.",
            "Notes on the changing sky and the simple practice of keeping an observing record.",
            "A collection of sky studies, from the colours of dusk to the shapes between stars.",
        ),
        "eyebrow": "An observing notebook",
        "about": (
            "This collection approaches the sky through familiar starting points: the changing Moon, a clear horizon, and a few recognisable star patterns.",
            "The illustrations are abstract sky studies, not navigation charts. The notes focus on observation and on keeping enough context to compare one evening with another.",
        ),
        "caption": "An abstract sky study; star positions are decorative, not a chart.",
        "palettes": {
            "midnight": ("#101D2D", "#EEE9DE", "#AFBDCA", "#CBAA68", "#20374C", "#3B5065"),
            "violet": ("#201B35", "#F0E8E2", "#BDB0C9", "#D4A6BB", "#382D51", "#514361"),
            "deep-sea": ("#102B31", "#E7EFE5", "#A5C2BE", "#89C5B2", "#20454C", "#3A6266"),
            "dusk": ("#30232F", "#F1E6DD", "#C8B0B9", "#DCAD86", "#4D3542", "#6A4D5C"),
        },
    },
}


def _site_article(slug, category, titles, summary, paragraphs):
    return {"slug": slug, "category": category, "titles": titles,
            "summary": summary, "paragraphs": paragraphs}


# Original, curated short-form text.  This is a deterministic template/content
# bank, not an LLM invocation or a claim of newly researched reporting.
_SITE_ARTICLES = {
    "journal": (
        _site_article("collecting-ideas", "Notebooks", ("Give an idea somewhere to land", "A notebook with room to return"),
            "A useful note keeps enough context to make sense when the moment has passed.", (
            "Start with the observation itself. A title such as a question or a small claim is usually easier to find again than a general topic.",
            "Add the detail that made the idea interesting: a contrast, an example, or something that did not fit an expectation. This detail gives the note a reason to exist.",
            "Leave room for a second visit. A short line about what remains uncertain can be more useful than forcing a tidy conclusion while the thought is still forming.",
            "When a notebook grows, connect related entries with a few plain words. The connection matters more than an elaborate system of folders and labels.",
        )),
        _site_article("useful-questions", "Thinking", ("Ask a question that opens a door", "The shape of a useful question"),
            "A small change in wording can turn a vague problem into something observable.", (
            "Broad questions can hide several different problems. Before looking for an answer, write down which part can be described with a concrete example.",
            "Questions beginning with when, where, or under what conditions often reveal differences that a simple yes or no would miss.",
            "Keep the question separate from a favourite explanation. Doing so leaves space for an observation that challenges the first impression.",
            "A useful question does not have to be impressive. It only needs to make the next step clearer than it was before.",
        )),
        _site_article("working-rhythm", "Practice", ("Leave a clear place to begin again", "A quieter rhythm of work"),
            "The end of one session can make the beginning of the next much easier.", (
            "Before closing a task, leave a short account of where it stands. Separate what is finished from what needs another decision.",
            "Write the next action in terms that can be carried out. Compare two examples is clearer than continue thinking, even when the larger question is still open.",
            "A pause can be part of the process. Keeping the context nearby makes it possible to step away without spending the next session reconstructing every detail.",
            "Review the note when returning. If the next action no longer makes sense, update it before adding more work to an outdated plan.",
        )),
        _site_article("reading-again", "Reading", ("Return to a passage with a new question", "What a second reading reveals"),
            "Rereading is a way to compare an earlier impression with a more specific question.", (
            "On a first reading, follow the main line of the argument. A second visit can focus on the examples, the assumptions, or the parts that once seemed unimportant.",
            "Keep a brief note of why a passage was saved. Without that context, a quotation can become a polished fragment with no clear connection to its original purpose.",
            "Paraphrase one idea before looking back at the text. The difference between the paraphrase and the original often shows where understanding is still incomplete.",
            "It is reasonable to change an earlier interpretation. A reading note is a record of a conversation with a text, not a promise to keep the same opinion.",
        )),
        _site_article("ordinary-details", "Observation", ("Notice the detail that usually disappears", "An exercise in ordinary attention"),
            "Familiar surroundings still contain differences worth describing.", (
            "Choose one small part of a familiar place: the sound near a doorway, the light on a table, or the order of objects on a shelf.",
            "Describe it without immediately deciding what it means. Shape, position, colour, and change are useful starting points because they can be compared later.",
            "Return at another time and record what is different. Even a short comparison can reveal the influence of weather, activity, or the angle of daylight.",
            "The point is not to make an ordinary detail dramatic. It is to give an accurate account of something that would otherwise pass unnoticed.",
        )),
        _site_article("small-routines", "Everyday", ("Make a routine easy to recognise", "Small routines, clearly defined"),
            "A modest routine works best when its beginning and end are visible.", (
            "Describe a routine as a small sequence rather than a general ambition. Open the notebook and write one observation is easier to recognise than be more reflective.",
            "Use an existing moment as its starting point. A familiar transition can provide context without adding another complicated reminder.",
            "Keep the first version short enough to fit an ordinary day. It can grow later if the extra steps continue to serve a clear purpose.",
            "Occasionally ask what the routine is helping with. A habit that no longer fits can be adjusted without treating its earlier form as a failure.",
        )),
    ),
    "botanical": (
        _site_article("leaf-outlines", "Form", ("Read the outline of a leaf", "A closer look at leaf shapes"),
            "An outline offers a simple way to compare plants without losing the smaller details.", (
            "Begin with the whole shape before looking at veins or texture. Notice where the leaf is widest and how the edge changes near the tip.",
            "Compare several leaves from the same plant. Size and orientation may vary even when the basic pattern remains easy to recognise.",
            "A quick contour drawing can be more useful than a perfect illustration. Its purpose is to record which features caught the eye.",
            "Keep the stem attachment in the drawing. The relationship between a leaf and its branch often adds context that an isolated outline cannot show.",
        )),
        _site_article("window-light", "Light", ("Follow light across a windowsill", "The changing light around a plant"),
            "A position that looks bright at one moment can feel quite different later in the day.", (
            "Observe a windowsill at several times rather than judging it from one glance. Direct patches, reflections, and soft daylight move across the same surface.",
            "Nearby buildings, curtains, and the depth of the window opening all influence the pattern. Their shadows are part of the plant's immediate setting.",
            "Record the direction and duration of the clearest light. These notes describe the location more precisely than a simple bright or dark label.",
            "Repeat the observation as the season changes. The same window can offer a different arrangement of light without anything inside the room being moved.",
        )),
        _site_article("surface-textures", "Texture", ("Look at the surface between stems", "Texture in a small planted space"),
            "The ground around a plant has its own changing pattern of colour and structure.", (
            "A planted space includes more than leaves. Soil, bark, stones, and fallen fragments create a background that changes the appearance of each stem.",
            "Notice the difference between a smooth area and a loose collection of small pieces. Side light can make these surface variations especially clear.",
            "Use the same viewpoint when making comparisons. Changes in distance or angle can disguise the very texture being observed.",
            "A few written details are often enough: rough or fine, pale or dark, open or densely covered. The aim is a useful description, not a fixed classification.",
        )),
        _site_article("branching-patterns", "Structure", ("Trace a stem from one junction to the next", "The rhythm of a branching plant"),
            "Branches show how repeated parts can form an irregular whole.", (
            "Start at a visible stem and follow it outward. Mark the points where a leaf, branch, or flower stalk changes the direction of the line.",
            "Look for repetition without expecting perfect symmetry. Similar intervals can coexist with bends and gaps caused by the plant's surroundings.",
            "A diagram made from a few lines helps separate structure from the distraction of colour. It need not copy every leaf to describe the main arrangement.",
            "Compare the diagram with the plant again. The differences show which features were essential to recognising its particular shape.",
        )),
        _site_article("growth-notebook", "Practice", ("Keep a small record of growth", "A repeatable way to observe a plant"),
            "Consistent notes make gradual changes easier to recognise.", (
            "Choose a few visible features to follow, such as the number of open leaves or the position of a new shoot. Keep the description simple enough to repeat.",
            "Use a fixed reference in a photograph or sketch. A pot rim or a nearby marker can help make changes in scale easier to compare.",
            "Record the date and the setting alongside the observation. A change in location or light is useful context when looking back through the notebook.",
            "Leave space for uncertainty. A detail that is unclear today may become easier to interpret after several observations from the same viewpoint.",
        )),
        _site_article("garden-edges", "Place", ("Where a garden meets its surroundings", "The interest in a planted edge"),
            "Edges bring different textures and growing forms into the same small view.", (
            "The boundary between planting and a path often offers more variety than either area viewed alone. Look for places where one surface gives way to another.",
            "Notice whether the edge is crisp, broken, or gradually mixed. Its character can change with the height and direction of the surrounding plants.",
            "A low viewpoint can reveal overlaps that disappear when looking straight down. The same boundary may read as a line, a band, or a layered space.",
            "Sketch only the main transitions at first. Adding every small detail can obscure the larger relationship that makes the edge interesting.",
        )),
    ),
    "photography": (
        _site_article("side-light", "Light", ("Let side light describe a surface", "Finding shape in a band of light"),
            "The direction of light changes which parts of a subject become legible.", (
            "Light from the side can separate a raised edge from the surface beside it. Move slightly and notice how the shadow changes before choosing a frame.",
            "A bright area is not automatically the most useful one. The transition from light to shade may describe the subject more clearly than either extreme.",
            "Keep an eye on the background as well as the subject. A small change in position can give the lit edge enough contrast to stand out.",
            "Try a second frame with less of the scene included. Simplifying the surroundings makes it easier to see what the light is contributing.",
        )),
        _site_article("negative-space", "Composition", ("Give the subject some breathing room", "The work done by an empty area"),
            "The space around a subject can be an active part of the composition.", (
            "Look at the shape of the background as carefully as the subject. An apparently empty area still has edges, tone, and a relationship to the frame.",
            "Shift the subject away from the centre and compare the balance. The useful position depends on the direction of surrounding lines and the amount of visual weight elsewhere.",
            "A quiet background can make a small gesture or detail easier to notice. It can also give the image a slower pace without changing the subject itself.",
            "Check the corners before taking the photograph. A bright fragment near an edge may compete with the space that was meant to feel calm.",
        )),
        _site_article("frame-edges", "Framing", ("Check what the edge is doing", "A photograph begins at its borders"),
            "Small decisions near the border often affect the whole image.", (
            "Trace the four sides of a proposed frame before concentrating on the centre. Notice where a line enters, where a shape is cut, and where an object almost touches the border.",
            "A deliberate crop usually reads more clearly than an accidental-looking sliver. Move closer or farther away until the relationship feels intentional.",
            "Compare a horizontal and a vertical frame when the scene allows it. The choice changes the surrounding space as well as the amount of the subject included.",
            "Keep a little context when it helps explain scale or position. Tight framing is useful only when the removed information was not doing important work.",
        )),
        _site_article("colour-pairs", "Colour", ("Build a frame around two colours", "A simple colour relationship"),
            "Reducing the number of competing colours can make a scene easier to organise.", (
            "Choose two colours already present in the scene and look for a viewpoint that brings them into a clear relationship. One can occupy a large area while the other remains small.",
            "Notice differences in brightness as well as hue. Two distinct colours may merge visually if their tones are too similar in the available light.",
            "Look for repeated hints of the smaller colour elsewhere in the frame. A subtle repetition can connect areas without making the composition feel rigid.",
            "Avoid changing everything at once while comparing frames. Keeping the subject or viewpoint steady makes the effect of colour easier to judge.",
        )),
        _site_article("repeated-forms", "Pattern", ("Find the break in a repeated form", "When a pattern becomes a picture"),
            "Repetition provides structure; a small difference can provide a point of interest.", (
            "Begin by identifying the repeated element, such as windows, chairs, or shadows. Choose a viewpoint that makes the relationship easy to see.",
            "Then look for a variation in spacing, colour, or direction. A single difference can become a focal point because the surrounding pattern gives it context.",
            "The pattern does not have to fill the entire image. Leaving a quieter area nearby can make its rhythm feel more deliberate.",
            "Pay attention to perspective. A slight change in position may strengthen the repetition or replace it with a different arrangement of lines.",
        )),
        _site_article("quiet-backgrounds", "Observation", ("Choose the background before the moment", "A quieter setting for a clear subject"),
            "A useful background often comes from a small change in viewpoint.", (
            "Before adjusting the subject, inspect what appears behind it. Bright edges, strong lines, and small high-contrast objects can attract attention unexpectedly.",
            "Move a short distance to either side and compare the overlaps. A background line that seems to grow from the subject may disappear with a modest change of position.",
            "A simple background need not be blank. A few related textures can add context while keeping the main shape easy to follow.",
            "Wait for the arrangement to settle when the scene is changing. Choosing the setting first leaves more attention available for the moment itself.",
        )),
    ),
    "architecture": (
        _site_article("thresholds", "Movement", ("Notice the space of a doorway", "The small transition between places"),
            "A threshold can change pace, light, and expectation within a few steps.", (
            "Approach a doorway slowly enough to notice what changes before crossing it. The floor surface, ceiling height, or amount of light may already signal a transition.",
            "Look at the depth of the opening. A thin boundary and a deep passage offer different experiences even when they lead into rooms of similar size.",
            "Consider where the first view is directed. A threshold may reveal a whole space at once or allow it to unfold through a sequence of smaller views.",
            "A simple plan sketch can help record the relationship. Mark the approach, the opening, and the place where movement naturally pauses.",
        )),
        _site_article("material-surfaces", "Materials", ("Read a material at two distances", "The character of a familiar surface"),
            "A wall can appear uniform from afar and varied at arm's length.", (
            "Begin with the overall field of a surface. Colour, joint spacing, and the direction of light establish an impression before individual details become visible.",
            "Move closer and notice the marks of making or use. Texture can reveal layers that a distant view compresses into a single tone.",
            "Pay attention to how two materials meet. A narrow seam or a change in plane can explain the construction more clearly than either surface on its own.",
            "Compare the same material in light and shade. Its apparent weight and texture may change without any difference in the material itself.",
        )),
        _site_article("room-light", "Daylight", ("Follow daylight around a room", "How a room changes without moving"),
            "The arrangement of light can describe a room differently throughout the day.", (
            "Notice which surfaces receive direct light and which are lit by reflection. A bright wall can influence the feeling of a room even when the window is outside the immediate view.",
            "Look at the depth of shadows near openings and corners. They help reveal the thickness of a wall and the distance between surfaces.",
            "Keep the same viewpoint for two observations at different times. The comparison shows how light changes the emphasis within an unchanged arrangement.",
            "A sketch can record only the largest areas of light and shade. These broad shapes often explain more than an attempt to copy every object in the room.",
        )),
        _site_article("human-scale", "Scale", ("Measure a place through familiar objects", "Finding scale in everyday space"),
            "A step, seat, or doorway gives the eye a reference for a larger space.", (
            "When a place feels unusually large or small, identify the reference that creates that impression. A handrail or a chair may provide a more immediate scale than a distant wall.",
            "Compare the dimensions of adjacent elements rather than treating each one separately. The relation between a window and a room can be more revealing than either measurement alone.",
            "Notice where a person can pause without blocking movement. These small opportunities often describe how a space accommodates ordinary use.",
            "Use approximate observations carefully. Their value lies in making relationships visible, not in replacing measured drawings or technical information.",
        )),
        _site_article("street-rhythm", "Streets", ("Read the rhythm of a street edge", "Repetition along a familiar route"),
            "Doors, windows, and gaps divide a long frontage into smaller experiences.", (
            "Follow a short stretch of street and notice the intervals between openings. Similar widths can create a rhythm even when the buildings differ in age or material.",
            "Look for the interruptions: an entrance set back, a narrow passage, or a change in height. Each one can become a marker along the route.",
            "Observe how the ground floor relates to the spaces above it. The part of a building met at walking pace may have a different rhythm from its upper levels.",
            "A strip sketch made from rectangles and gaps can record the pattern. Details can be added later if they help explain a particular change.",
        )),
        _site_article("room-sequence", "Sequence", ("Let a place unfold in stages", "The order in which rooms are seen"),
            "A building is experienced through a sequence rather than from one fixed viewpoint.", (
            "Trace an ordinary route through a place and note which spaces appear first. The order can influence how large, bright, or quiet the later rooms feel.",
            "Notice where a view continues through more than one opening. These alignments can connect spaces that remain physically separate.",
            "A change in direction can provide a pause or reveal a new focus. It may also hide a destination until the last part of the route.",
            "Draw the sequence as a few connected shapes rather than a complete plan. This keeps attention on movement and on the moments when the experience changes.",
        )),
    ),
    "astronomy": (
        _site_article("twilight-colours", "Twilight", ("Watch the sky change after sunset", "The slow transition into night"),
            "Twilight makes the changing relationship between sky and horizon especially visible.", (
            "Choose a place with a clear view of part of the horizon and compare it with the sky higher overhead. The colours and brightness need not change at the same pace.",
            "Use a nearby silhouette as a reference. A tree line or roof edge makes a gradual change in the background easier to recognise.",
            "Record the time and general sky conditions with a short description. Thin clouds can change the pattern enough to make two evenings look very different.",
            "A few observations spaced apart can be more informative than one elaborate description. Together they preserve the order in which the scene changed.",
        )),
        _site_article("moon-shapes", "The Moon", ("Keep track of the Moon's changing shape", "A familiar object, a different outline"),
            "The illuminated part of the Moon offers a clear subject for repeated observations.", (
            "Sketch the visible outline before adding detail. Record which side appears illuminated and how the Moon is oriented relative to the horizon.",
            "Include the date and approximate time. The Moon's position and appearance become easier to compare when the observation has a clear context.",
            "Look at the boundary between light and dark as a shape of its own. A simple drawing of that boundary can preserve the main character of the view.",
            "Compare several entries together instead of relying on memory. The sequence makes gradual changes more apparent than an isolated sketch.",
        )),
        _site_article("star-patterns", "Patterns", ("Begin with a few recognisable stars", "Learning the spaces between points"),
            "A small, familiar pattern can be a useful starting point for exploring a larger sky.", (
            "Choose a few clearly visible points and compare the shapes between them. A triangle or a short curve is often easier to remember than a list of separate positions.",
            "Notice relative brightness as well as spacing. These differences help distinguish one arrangement from another when more stars become visible.",
            "Use a reliable chart when identifying an unfamiliar pattern. A decorative illustration is not a substitute for a chart matched to the location and time.",
            "Return to the same area on another evening. Recognition becomes easier when the pattern is seen in several slightly different conditions.",
        )),
        _site_article("quiet-observing", "Practice", ("Give an observing session a little time", "A slower way to look at the sky"),
            "A short pause can reveal differences that a quick glance misses.", (
            "Let the first part of an observing session be a simple survey. Notice the clearest direction, the brightest nearby lights, and the parts of the sky interrupted by buildings or trees.",
            "Avoid jumping between too many targets. Staying with one area makes subtle differences in brightness and arrangement easier to compare.",
            "Keep notes brief enough that they do not replace the observation itself. A few keywords can be expanded later while the scene is still familiar.",
            "Record interruptions such as passing clouds or nearby lighting. They explain why a detail visible at one moment may be difficult to find again.",
        )),
        _site_article("sky-records", "Notebooks", ("Make an observing record easy to revisit", "What belongs in a sky notebook"),
            "Useful context helps separate a change in the sky from a change in the observing conditions.", (
            "Begin an entry with the date, time, and general location. Add the direction of the view so that a later comparison starts from the same part of the sky.",
            "Describe the conditions in plain language. Cloud cover, haze, and nearby light can matter more to an observation than the length of the written account.",
            "Keep a sketch simple and label what is uncertain. It is better to preserve an honest question than to turn a doubtful impression into a confident identification.",
            "Revisit related entries together. Repeated notes can show which details remain consistent and which depended on a particular evening.",
        )),
        _site_article("seasonal-sky", "Change", ("Return to the same view in another season", "A familiar horizon under a changing sky"),
            "A fixed viewpoint provides a useful reference for longer-term observations.", (
            "Choose a recognisable foreground and note the direction it faces. A stable reference makes it easier to compare the arrangement above it over time.",
            "Keep the observing time in the record. A change in time as well as a change in date can alter the view, so both pieces of context are useful.",
            "Compare broad patterns before searching for small differences. The most noticeable change may be which part of the sky is available between nearby obstructions.",
            "An observing notebook can preserve these comparisons without requiring a complete account of every visible object. A clear question gives each visit a purpose.",
        )),
    ),
}



for _extra_theme, _extra_data in EXTRA_SITE_CONTENT.items():
    if _extra_theme in _SITE_THEME_DATA:
        raise ValueError("Duplicate generated-site theme in the content bank")
    _SITE_THEME_DATA[_extra_theme] = {key: value for key, value in _extra_data.items() if key != "articles"}
    _SITE_ARTICLES[_extra_theme] = _extra_data["articles"]
SITE_THEMES += tuple(EXTRA_SITE_CONTENT)


def _site_digest(seed: str, namespace: str) -> str:
    return _site_hashlib.sha256(("site-v1\0" + seed + "\0" + namespace).encode("utf-8")).hexdigest()


def _site_number(seed: str, namespace: str, lower: int, upper: int) -> int:
    return lower + int(_site_digest(seed, namespace)[:16], 16) % (upper - lower + 1)


def _site_pick(seed: str, namespace: str, values):
    return values[_site_number(seed, namespace, 0, len(values) - 1)]


def _site_seed(seed: str) -> str:
    if not isinstance(seed, str) or not re.fullmatch(r"[0-9a-f]{64}", seed):
        raise ValueError("Site seed must be exactly 64 lowercase hexadecimal characters")
    return seed


def _site_text(value: str, name: str, limit: int, *, normalize: bool) -> str:
    if not isinstance(value, str):
        raise ValueError(f"Site {name} must be text")
    if any((ord(char) < 32 and char not in "\t\r\n") or ord(char) == 127 for char in value):
        raise ValueError(f"Site {name} contains a control character")
    try:
        value.encode("utf-8")
    except UnicodeError as exc:
        raise ValueError(f"Site {name} must be valid UTF-8 text") from exc
    if normalize:
        value = " ".join(value.split())
    if not value or len(value) > limit or value != " ".join(value.split()):
        raise ValueError(f"Site {name} must contain 1–{limit} characters of normalized text")
    return value


def generate_site_profile(seed: str, theme: str = "auto", title: Optional[str] = None,
                          description: Optional[str] = None) -> dict:
    """Create a private, serializable v1 site profile from an installation seed.

    Selection uses SHA-256 namespaces, not Python's random/hash machinery.
    The returned profile is deterministic across processes/Python versions.
    ``auto`` is resolved to a concrete theme before the profile is returned.
    A seed is generated by the installer once per clean installation, never
    here, so an existing profile remains stable through restarts.
    """
    seed = _site_seed(seed)
    if theme not in ("auto", *SITE_THEMES):
        raise ValueError("Unknown generated-site theme")
    selected = _site_pick(seed, "theme", SITE_THEMES) if theme == "auto" else theme
    data = _SITE_THEME_DATA[selected]
    palette_ids = tuple(data["palettes"])
    return {
        "version": 1, "seed": seed, "theme": selected,
        "title": _site_text(title if title is not None else _site_pick(seed, selected + ":title", data["names"]),
                            "title", 160, normalize=True),
        "description": _site_text(description if description is not None else _site_pick(seed, selected + ":description", data["descriptions"]),
                                  "description", 1000, normalize=True),
        "layout": _site_pick(seed, selected + ":layout", _SITE_LAYOUTS),
        "palette": _site_pick(seed, selected + ":palette", palette_ids),
    }


def _validated_site_profile(profile: dict) -> dict:
    if not isinstance(profile, dict) or set(profile) != _SITE_PROFILE_KEYS:
        raise ValueError("Site profile has missing or unexpected fields")
    if type(profile["version"]) is not int or profile["version"] != 1:
        raise ValueError("Unsupported site profile version")
    seed = _site_seed(profile["seed"])
    theme = profile["theme"]
    if not isinstance(theme, str) or theme not in SITE_THEMES:
        raise ValueError("Site profile needs a concrete supported theme")
    _site_text(profile["title"], "title", 160, normalize=False)
    _site_text(profile["description"], "description", 1000, normalize=False)
    expected = generate_site_profile(seed, theme, profile["title"], profile["description"])
    if profile != expected:
        raise ValueError("Site layout/palette does not match its seed and theme")
    return dict(profile)


_SITE_BASE_CSS = r'''
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{margin:0;background:var(--paper);color:var(--ink);font-family:var(--body-font);font-size:16px;line-height:1.75}
a{color:inherit;text-decoration-thickness:1px;text-underline-offset:4px}
a:hover{color:var(--accent)}
a:focus-visible{outline:2px solid var(--accent);outline-offset:5px}
img{display:block;width:100%;height:auto}
.shell{max-width:var(--page-width);margin:auto;padding:0 40px}
.site-header{display:flex;justify-content:space-between;align-items:center;gap:28px;padding:28px 0;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:12px;text-decoration:none;min-width:0;font:600 17px/1.3 var(--heading-font)}
.brand img{width:31px;height:31px;flex:0 0 31px}
.brand span{overflow-wrap:anywhere}
.site-nav{display:flex;gap:24px;flex-shrink:0;font:12px/1.5 var(--label-font)}
.site-nav a{text-decoration:none;color:var(--muted)}
.site-nav a[aria-current=page]{color:var(--ink);text-decoration:underline}
.eyebrow,.category,.number,.breadcrumbs,.small-label{font-family:var(--label-font);font-size:10px;line-height:1.5;letter-spacing:.13em;text-transform:uppercase;color:var(--muted)}
.eyebrow{margin:0 0 19px}
h1,h2,h3{font-family:var(--heading-font);overflow-wrap:anywhere}
h1{font-size:clamp(37px,6vw,68px);font-weight:400;line-height:1.08;letter-spacing:-.035em;margin:0 0 24px}
h2{font-size:26px;font-weight:400;line-height:1.25;letter-spacing:-.02em;margin:12px 0 15px}
h3{font-size:20px;font-weight:400;line-height:1.3}
.lead{color:var(--muted);font-size:20px;line-height:1.6;margin:0 0 25px}
.summary{color:var(--muted);font-size:15px;line-height:1.7}
.read-link{font:11px/1.5 var(--label-font);letter-spacing:.05em;display:inline-block;margin-top:12px}
.article-title-link{text-decoration:none}
.cover,.article-art{border-radius:var(--image-radius);overflow:hidden;background:var(--soft)}
.cover img{aspect-ratio:8/5;object-fit:cover}
.category{margin:0}
.site-footer{display:flex;justify-content:space-between;gap:24px;flex-wrap:wrap;border-top:1px solid var(--line);padding:25px 0 34px;margin-top:55px;font:11px/1.6 var(--label-font);color:var(--muted)}
.site-footer p{margin:0}
.content-page{max-width:760px;margin:66px auto 80px}
.content-page h1{font-size:clamp(34px,5vw,56px)}
.content-page h2{margin-top:34px}
.content-page p{margin:20px 0}
.breadcrumbs{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 27px}
.article-figure{margin:33px 0 34px}
.article-figure img{border-radius:var(--image-radius);background:var(--soft)}
figcaption{font:11px/1.6 var(--label-font);color:var(--muted);margin-top:11px}
.related{border-top:1px solid var(--line);margin-top:48px;padding-top:23px}
.related ul,.about-links{padding-left:20px}
.related li,.about-links li{margin:12px 0}
.not-found{min-height:45vh}
@media(max-width:700px){.shell{padding:0 22px}.site-header{padding:22px 0;gap:16px}.brand{font-size:15px}.brand img{width:25px;height:25px;flex-basis:25px}.site-nav{gap:16px;font-size:11px}.lead{font-size:18px}.content-page{margin:44px auto 55px}.site-footer{margin-top:36px;padding-bottom:25px}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
'''

_SITE_LAYOUT_CSS = {
    "editorial": r'''
.editorial-hero{display:grid;grid-template-columns:1.1fr 1fr;gap:60px;align-items:center;padding:70px 0}
.editorial-hero .cover{transform:rotate(-2deg)}
.editorial-feature{display:grid;grid-template-columns:1fr 1.2fr;gap:45px;align-items:center;border-top:1px solid var(--line);border-bottom:1px solid var(--line);padding:35px 0}
.editorial-feature img{aspect-ratio:8/5;object-fit:cover;border-radius:var(--image-radius)}
.editorial-feature h2{font-size:32px}
.editorial-lower{display:grid;grid-template-columns:2fr 1fr;gap:70px;padding:12px 0 10px}
.editorial-rows article{padding:30px 0;border-bottom:1px solid var(--line)}
.editorial-aside{border-left:1px solid var(--line);padding-left:30px;margin-top:35px;color:var(--muted);font-size:14px}
@media(max-width:850px){.editorial-hero{gap:30px;padding:45px 0}.editorial-lower{gap:35px}.editorial-feature{gap:30px}}
@media(max-width:600px){.editorial-hero,.editorial-feature,.editorial-lower{grid-template-columns:1fr}.editorial-hero .cover{transform:none}.editorial-feature h2{font-size:28px}.editorial-aside{margin-top:0;padding-top:15px}.editorial-lower{gap:20px}}
''',
    "gallery": r'''
.layout-gallery .shell{display:grid;grid-template-columns:185px minmax(0,1fr);gap:0 50px;max-width:1400px;padding-top:30px}
.layout-gallery .site-header{grid-column:1;grid-row:1/3;display:block;border:0;border-right:1px solid var(--line);padding:9px 28px 0 0;align-self:start;position:sticky;top:28px}
.layout-gallery .brand{display:block;font-size:22px;line-height:1.2}
.layout-gallery .brand img{width:42px;height:42px;margin-bottom:22px}
.layout-gallery .site-nav{display:flex;flex-direction:column;gap:18px;margin-top:40px}
.layout-gallery main,.layout-gallery .site-footer{grid-column:2}
.gallery-intro{display:grid;grid-template-columns:1.4fr 1fr;align-items:end;gap:40px;padding:25px 0 42px}
.gallery-intro h1{font-size:clamp(40px,6vw,78px)}
.gallery-banner img{aspect-ratio:2.8/1;object-fit:cover}
.gallery-cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:42px 28px;padding-top:38px}
.gallery-card .article-art{margin-bottom:23px}.gallery-card img{aspect-ratio:5/4;object-fit:cover}
.gallery-card h2{font-size:25px}.gallery-card .number{display:block;margin-bottom:12px}
.layout-gallery .content-page{margin-top:22px}
@media(max-width:1000px){.layout-gallery .shell{grid-template-columns:145px minmax(0,1fr);gap:0 30px}.layout-gallery .site-header{padding-right:20px}.gallery-intro{grid-template-columns:1fr;gap:0}}
@media(max-width:700px){.layout-gallery .shell{display:block;padding-top:0}.layout-gallery .site-header{position:static;display:flex;align-items:center;border-right:0;border-bottom:1px solid var(--line);padding:22px 0}.layout-gallery .brand{display:flex;font-size:16px}.layout-gallery .brand img{width:28px;height:28px;margin:0}.layout-gallery .site-nav{flex-direction:row;margin:0;gap:14px}.gallery-intro{padding-top:38px}.gallery-cards{gap:30px 20px}.gallery-card h2{font-size:22px}.layout-gallery .content-page{margin-top:42px}}
@media(max-width:450px){.gallery-cards{grid-template-columns:1fr}}
''',
    "index": r'''
.layout-index .shell{max-width:1120px}.layout-index .site-header{padding:22px 0}
.index-intro{display:grid;grid-template-columns:1fr 190px;align-items:center;gap:65px;padding:65px 0 52px}
.index-intro .cover{border-radius:50%;aspect-ratio:1}.index-intro .cover img{width:100%;height:100%;object-fit:cover}
.index-intro h1{font-size:clamp(38px,5vw,62px)}
.index-heading{display:flex;justify-content:space-between;gap:20px;border-top:2px solid var(--ink);padding:14px 0;font:10px/1.5 var(--label-font);letter-spacing:.13em;text-transform:uppercase;color:var(--muted)}
.index-list{list-style:none;padding:0;margin:0}
.index-row{display:grid;grid-template-columns:42px minmax(0,1fr) 150px;gap:27px;border-top:1px solid var(--line);padding:28px 0;align-items:start}
.index-row .number{padding-top:5px}.index-row h2{margin-top:6px;font-size:26px}.index-row .summary{max-width:620px;margin-bottom:0}
.index-row img{aspect-ratio:4/3;object-fit:cover;border-radius:var(--image-radius)}
@media(max-width:650px){.index-intro{grid-template-columns:1fr 110px;gap:25px;padding:45px 0 35px}.index-row{grid-template-columns:28px minmax(0,1fr);gap:18px}.index-row .row-art{display:none}.index-row h2{font-size:23px}}
@media(max-width:410px){.index-intro{grid-template-columns:1fr}.index-intro .cover{display:none}}
''',
    "notebook": r'''
.layout-notebook .shell{max-width:1170px}.layout-notebook h1{font-size:clamp(34px,4.8vw,54px)}
.notebook-heading{display:grid;grid-template-columns:1.4fr 1fr;gap:50px;align-items:center;padding:55px 0 45px}
.notebook-heading .cover{padding:12px;background:var(--soft);transform:rotate(2deg)}
.notebook-body{display:grid;grid-template-columns:220px minmax(0,1fr);gap:45px;align-items:start;border-top:1px solid var(--line);padding-top:32px}
.notebook-toc{position:sticky;top:25px;padding-right:20px;border-right:1px solid var(--line)}
.notebook-toc ol{padding-left:20px;margin:18px 0}.notebook-toc li{margin:14px 0;color:var(--muted);font-size:13px;line-height:1.5}
.notebook-entry{margin-bottom:38px;padding:24px 28px 28px;border-left:3px solid var(--accent);background:linear-gradient(var(--soft),var(--soft)) 0 0/100% 100% no-repeat}
.notebook-entry h2{font-size:25px}.notebook-entry .entry-open{font-size:15px;color:var(--muted)}
.notebook-entry .entry-foot{display:flex;align-items:end;justify-content:space-between;gap:25px;margin-top:20px}
.notebook-entry .entry-foot img{width:105px;height:70px;object-fit:cover;border-radius:var(--image-radius)}
.layout-notebook .content-page{border-left:1px solid var(--line);padding-left:32px}
@media(max-width:750px){.notebook-heading{gap:25px}.notebook-body{grid-template-columns:165px minmax(0,1fr);gap:25px}.notebook-entry{padding:20px}}
@media(max-width:580px){.notebook-heading{grid-template-columns:1fr;padding-top:40px}.notebook-heading .cover{max-width:340px}.notebook-body{display:block}.notebook-toc{position:static;border-right:0;border-bottom:1px solid var(--line);padding:0 0 18px;margin-bottom:28px}.notebook-toc ol{columns:2;column-gap:30px}.notebook-toc li{break-inside:avoid}.layout-notebook .content-page{padding-left:20px}}
''',
    "bulletin": r'''
.layout-bulletin .site-header{border-bottom:3px double var(--ink)}
.bulletin-masthead{text-align:center;padding:48px 50px 35px;border-bottom:3px double var(--ink)}
.bulletin-masthead h1{font-size:clamp(46px,7vw,94px);font-weight:700;letter-spacing:-.06em}.bulletin-masthead .lead{max-width:680px;margin:0 auto 15px;font-size:18px}
.bulletin-strip{display:flex;justify-content:space-between;gap:20px;padding:13px 0;border-bottom:1px solid var(--line);font:10px/1.4 var(--label-font);letter-spacing:.13em;text-transform:uppercase;color:var(--muted)}
.bulletin-grid{display:grid;grid-template-columns:1.6fr 1fr;gap:38px;margin-top:30px}
.bulletin-lead{border-right:1px solid var(--line);padding-right:37px}.bulletin-lead h2{font-size:36px}.bulletin-lead .article-art{margin:22px 0}.bulletin-lead .opening{font-size:16px}
.bulletin-column article{padding:24px 0;border-bottom:1px solid var(--line)}.bulletin-column article:first-child{padding-top:0}.bulletin-column h2{font-size:24px}
.bulletin-note{margin-top:32px;padding:22px;background:var(--soft);font-size:14px;color:var(--muted)}
.layout-bulletin .content-page h1{font-weight:700;letter-spacing:-.04em}
@media(max-width:650px){.bulletin-masthead{padding:36px 0 28px}.bulletin-grid{display:block}.bulletin-lead{padding-right:0;border-right:0;border-bottom:1px solid var(--line);padding-bottom:30px;margin-bottom:28px}.bulletin-column{display:grid;grid-template-columns:1fr 1fr;gap:20px}.bulletin-column article,.bulletin-column article:first-child{padding-top:0}.bulletin-note{grid-column:1/-1}}
@media(max-width:440px){.bulletin-column{display:block}}
''',
    "folio": r'''
.layout-folio .shell{max-width:1380px}.layout-folio .site-header{border-bottom:0;padding-top:34px}
.folio-opening{display:grid;grid-template-columns:1.15fr 1fr;gap:60px;align-items:center;padding:45px 0 75px}
.folio-opening .cover{grid-column:1;grid-row:1;aspect-ratio:4/5}.folio-opening .cover img{width:100%;height:100%;object-fit:cover}
.folio-opening .folio-title{grid-column:2;grid-row:1}.folio-opening h1{font-size:clamp(46px,6.5vw,86px);line-height:1.04}.folio-opening .lead{font-size:19px}
.folio-label{display:block;margin-top:35px;font:11px/1.5 var(--label-font);color:var(--muted)}
.folio-sheet{display:grid;grid-template-columns:1.2fr 1fr;gap:65px;align-items:center;padding:58px 0;border-top:1px solid var(--line)}
.folio-sheet:nth-child(even){grid-template-columns:1fr 1.2fr}.folio-sheet:nth-child(even) .folio-image{grid-column:2;grid-row:1}.folio-sheet:nth-child(even) .folio-text{grid-column:1;grid-row:1}
.folio-sheet .folio-image{aspect-ratio:8/5;overflow:hidden;border-radius:var(--image-radius)}.folio-sheet .folio-image img{width:100%;height:100%;object-fit:cover}
.folio-sheet h2{font-size:33px}.folio-sheet .number{display:block;margin-bottom:20px}
@media(max-width:850px){.folio-opening{gap:35px}.folio-sheet{gap:35px}.folio-sheet h2{font-size:28px}}
@media(max-width:600px){.folio-opening{display:flex;flex-direction:column-reverse;gap:28px;padding:30px 0 45px;align-items:stretch}.folio-opening .cover{aspect-ratio:8/5}.folio-sheet,.folio-sheet:nth-child(even){display:flex;flex-direction:column;align-items:stretch;gap:25px;padding:35px 0}.folio-sheet .number{margin-bottom:10px}}
''',
}


def _generated_css(profile: dict, colors) -> str:
    seed, layout = profile["seed"], profile["layout"]
    heading_fonts = {
        "editorial": ("Georgia,'Times New Roman',serif", "'Palatino Linotype','Book Antiqua',Palatino,serif"),
        "gallery": ("'Trebuchet MS',Arial,sans-serif", "Arial,Helvetica,sans-serif", "Verdana,Geneva,sans-serif"),
        "index": ("Arial,Helvetica,sans-serif", "'Trebuchet MS',Arial,sans-serif"),
        "notebook": ("'Courier New',Courier,monospace", "Georgia,'Times New Roman',serif"),
        "bulletin": ("Georgia,'Times New Roman',serif", "'Times New Roman',Times,serif"),
        "folio": ("'Palatino Linotype','Book Antiqua',Palatino,serif", "Georgia,'Times New Roman',serif", "'Trebuchet MS',Arial,sans-serif"),
    }
    body_fonts = ("Georgia,'Times New Roman',serif", "'Trebuchet MS',Arial,sans-serif", "Arial,Helvetica,sans-serif")
    heading = _site_pick(seed, "font:" + layout, heading_fonts[layout])
    body = _site_pick(seed, "body-font:" + profile["theme"], body_fonts)
    radius = _site_pick(seed, "image-radius:" + layout, (0, 4, 9)) if layout in {"gallery", "folio"} else 0
    width = _site_pick(seed, "page-width", (1120, 1180, 1240))
    names = ("paper", "ink", "muted", "accent", "soft", "line")
    declarations = "".join(f"--{name}:{value};" for name, value in zip(names, colors))
    declarations += (f"--heading-font:{heading};--body-font:{body};"
                     f"--label-font:'Courier New',Courier,monospace;--page-width:{width}px;--image-radius:{radius}px;")
    return ":root{" + declarations + "}\n" + _SITE_BASE_CSS + _SITE_LAYOUT_CSS[layout]


def _generated_article_selection(profile: dict) -> list:
    seed, theme = profile["seed"], profile["theme"]
    bank = _SITE_ARTICLES[theme]
    if len(bank) < 3:
        raise ValueError("A site theme needs at least three curated articles")
    count = _site_number(seed, theme + ":article-count", 3, min(5, len(bank)))
    selected = sorted(bank, key=lambda item: _site_digest(seed, theme + ":select:" + item["slug"]))[:count]
    selected.sort(key=lambda item: _site_digest(seed, theme + ":order:" + item["slug"]))
    result = []
    for original in selected:
        slug = original["slug"]
        if not re.fullmatch(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*", slug):
            raise ValueError("Curated article slug is not a safe URL component")
        paragraphs = original["paragraphs"]
        if len(paragraphs) < 3:
            raise ValueError("A curated article needs at least three paragraphs")
        amount = _site_number(seed, theme + ":paragraph-count:" + slug, 3, min(4, len(paragraphs)))
        indices = sorted(sorted(range(len(paragraphs)),
            key=lambda index: _site_digest(seed, theme + ":paragraph:" + slug + ":" + str(index)))[:amount])
        filename = "notes/" + slug + "-" + _site_digest(seed, theme + ":slug:" + slug)[:6] + ".html"
        figure = "assets/figure-" + slug + "-" + _site_digest(seed, theme + ":figure-file:" + slug)[:16] + ".svg"
        result.append({
            "slug": slug, "category": original["category"],
            "title": _site_pick(seed, theme + ":article-title:" + slug, original["titles"]),
            "summary": original["summary"], "paragraphs": tuple(paragraphs[index] for index in indices),
            "filename": filename, "figure": figure,
        })
    return result


def _generated_home(profile, data, articles, cover):
    e = html.escape
    title, description, layout = e(profile["title"], quote=True), e(profile["description"], quote=True), profile["layout"]
    eyebrow = f'<p class="eyebrow">{e(data["eyebrow"], quote=True)}</p>'
    intro = eyebrow + f'<h1>{title}</h1><p class="lead">{description}</p>'
    cover_html = f'<div class="cover"><img src="/{cover}" alt="{e(data["caption"], quote=True)}" width="960" height="600"></div>'

    def text(item, opening=False):
        value = (f'<p class="category">{e(item["category"], quote=True)}</p>'
                 f'<h2><a class="article-title-link" href="/{item["filename"]}">{e(item["title"], quote=True)}</a></h2>'
                 f'<p class="summary">{e(item["summary"], quote=True)}</p>')
        if opening:
            value += f'<p class="entry-open">{e(item["paragraphs"][0], quote=True)}</p>'
        return value + f'<a class="read-link" href="/{item["filename"]}">Read the note</a>'

    def figure(item, cls="article-art"):
        return (f'<a class="{cls}" href="/{item["filename"]}" aria-label="Read {e(item["title"], quote=True)}">'
                f'<img src="/{item["figure"]}" alt="{e(data["caption"], quote=True)}" width="960" height="600" loading="lazy"></a>')

    if layout == "editorial":
        first = articles[0]
        rows = "".join(f'<article>{text(item)}</article>' for item in articles[1:])
        return (f'<section class="editorial-hero"><div>{intro}</div>{cover_html}</section>'
                f'<section class="editorial-feature">{figure(first)}<div>{text(first)}</div></section>'
                f'<div class="editorial-lower"><section class="editorial-rows" aria-label="More notes">{rows}</section>'
                f'<aside class="editorial-aside"><p class="small-label">About this collection</p><p>{e(data["about"][0], quote=True)}</p>'
                '<a class="read-link" href="/about.html">A little more context</a></aside></div>')
    if layout == "gallery":
        cards = "".join(f'<article class="gallery-card"><span class="number">Study {index:02d}</span>{figure(item)}{text(item)}</article>'
                        for index, item in enumerate(articles, 1))
        return (f'<section class="gallery-intro"><div>{eyebrow}<h1>{title}</h1></div><p class="lead">{description}</p></section>'
                f'<div class="gallery-banner">{cover_html}</div><section class="gallery-cards" aria-label="Visual notes">{cards}</section>')
    if layout == "index":
        rows = "".join(f'<li class="index-row"><span class="number">{index:02d}</span><div>{text(item)}</div>{figure(item,"row-art")}</li>'
                       for index, item in enumerate(articles, 1))
        return (f'<section class="index-intro"><div>{intro}</div>{cover_html}</section>'
                f'<div class="index-heading"><span>A short index</span><span>{len(articles)} notes to explore</span></div>'
                f'<ol class="index-list">{rows}</ol>')
    if layout == "notebook":
        contents = "".join(f'<li><a href="#entry-{index}">{e(item["title"], quote=True)}</a></li>' for index, item in enumerate(articles, 1))
        entries = "".join(
            f'<article class="notebook-entry" id="entry-{index}"><span class="number">Entry {index:02d}</span>'
            f'<p class="category">{e(item["category"], quote=True)}</p><h2>{e(item["title"], quote=True)}</h2>'
            f'<p class="summary">{e(item["summary"], quote=True)}</p><p class="entry-open">{e(item["paragraphs"][0], quote=True)}</p>'
            f'<div class="entry-foot"><a class="read-link" href="/{item["filename"]}">Continue this note</a>{figure(item)}</div></article>'
            for index, item in enumerate(articles, 1))
        return (f'<section class="notebook-heading"><div>{intro}</div>{cover_html}</section>'
                f'<div class="notebook-body"><nav class="notebook-toc" aria-label="Notebook contents"><p class="small-label">In this notebook</p><ol>{contents}</ol></nav>'
                f'<section class="notebook-entries" aria-label="Notebook entries">{entries}</section></div>')
    if layout == "bulletin":
        first = articles[0]
        column = "".join(f'<article>{text(item)}</article>' for item in articles[1:])
        return (f'<section class="bulletin-masthead">{intro}</section><div class="bulletin-strip"><span>{e(data["eyebrow"], quote=True)}</span><span>A collection of short notes</span></div>'
                f'<section class="bulletin-grid" aria-label="Selected notes"><article class="bulletin-lead">{text(first)}{figure(first)}'
                f'<p class="opening">{e(first["paragraphs"][0], quote=True)}</p></article><div class="bulletin-column">{column}'
                f'<aside class="bulletin-note"><p class="small-label">From the collection</p><p>{e(data["about"][1], quote=True)}</p></aside></div></section>')
    if layout == "folio":
        sheets = "".join(f'<article class="folio-sheet">{figure(item,"folio-image")}<div class="folio-text"><span class="number">{index:02d} / {len(articles):02d}</span>{text(item)}</div></article>'
                         for index, item in enumerate(articles, 1))
        return (f'<section class="folio-opening">{cover_html}<div class="folio-title">{intro}<span class="folio-label">A small visual collection · {len(articles)} notes</span></div></section>'
                f'<section class="folio-stack" aria-label="The collection">{sheets}</section>')
    raise ValueError("Unsupported generated-site layout")


def render_generated_site(domain: str, profile: dict) -> Dict[str, str]:
    """Render an entire deterministic static site from a validated v1 profile.

    Returned keys are safe relative POSIX paths, including nested assets and
    articles.  All assets are local.  The private seed/profile/version are
    deliberately absent from public files; asset names use derived digests.
    The illustrations are procedural SVG studies, and prose is selected from
    the original curated bank above.  There is no model/API/network call.
    """
    domain = validate_domain(domain)
    profile = _validated_site_profile(profile)
    seed, theme, layout = profile["seed"], profile["theme"], profile["layout"]
    data = _SITE_THEME_DATA[theme]
    colors = data["palettes"][profile["palette"]]
    articles = _generated_article_selection(profile)
    style = "assets/style-" + _site_digest(seed, theme + ":style-file")[:16] + ".css"
    cover = "assets/cover-" + _site_digest(seed, theme + ":cover-file")[:16] + ".svg"
    icon = "assets/icon-" + _site_digest(seed, theme + ":icon-file")[:16] + ".svg"
    e = html.escape

    def page(page_title, body, filename, selected="", description=None):
        home_current = ' aria-current="page"' if selected == "home" else ""
        about_current = ' aria-current="page"' if selected == "about" else ""
        canonical = "https://" + domain + "/" + ("" if filename == "index.html" else filename)
        return f'''<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="{e(description if description is not None else profile['description'], quote=True)}">
  <title>{e(page_title, quote=True)} · {e(profile['title'], quote=True)}</title>
  <link rel="canonical" href="{canonical}">
  <link rel="icon" type="image/svg+xml" href="/{icon}">
  <link rel="stylesheet" href="/{style}">
</head>
<body class="layout-{layout} theme-{theme}">
  <div class="shell">
    <header class="site-header">
      <a class="brand" href="/"><img src="/{icon}" alt="" width="31" height="31"><span>{e(profile['title'], quote=True)}</span></a>
      <nav class="site-nav" aria-label="Main navigation"><a href="/"{home_current}>Notes</a><a href="/about.html"{about_current}>About</a></nav>
    </header>
    <main>{body}</main>
    <footer class="site-footer"><p>{domain}</p><p><a href="/">Browse the notes</a> · <a href="/about.html">About this collection</a></p></footer>
  </div>
</body>
</html>
'''

    files = {
        style: _generated_css(profile, colors),
        cover: render_site_illustration(seed, theme, colors),
        icon: render_site_icon(seed, theme, colors),
        "index.html": page("Notes", _generated_home(profile, data, articles, cover), "index.html", "home"),
    }
    about_paragraphs = "".join(f"<p>{e(paragraph, quote=True)}</p>" for paragraph in data["about"])
    about_links = "".join(f'<li><a href="/{item["filename"]}">{e(item["title"], quote=True)}</a></li>' for item in articles)
    about_body = (f'<article class="content-page"><p class="eyebrow">About the collection</p><h1>{e(profile["title"], quote=True)}</h1>'
                  f'<p class="lead">{e(profile["description"], quote=True)}</p>{about_paragraphs}'
                  '<h2>Read at your own pace</h2><p>Each note follows one subject. The pages can be read in any order, with related ideas linked at the end of each article.</p>'
                  f'<h2>Explore the notes</h2><ul class="about-links">{about_links}</ul></article>')
    files["about.html"] = page("About", about_body, "about.html", "about")
    for item in articles:
        figure_seed = _site_digest(seed, "figure:" + theme + ":" + item["slug"])
        files[item["figure"]] = render_site_illustration(figure_seed, theme, colors)
        related = [other for other in articles if other["slug"] != item["slug"]][:2]
        links = "".join(f'<li><a href="/{other["filename"]}">{e(other["title"], quote=True)}</a></li>' for other in related)
        paragraphs = "".join(f"<p>{e(paragraph, quote=True)}</p>" for paragraph in item["paragraphs"])
        body = (f'<article class="content-page"><nav class="breadcrumbs" aria-label="Breadcrumb"><a href="/">Notes</a><span>/</span><span>{e(item["category"], quote=True)}</span></nav>'
                f'<p class="eyebrow">{e(item["category"], quote=True)}</p><h1>{e(item["title"], quote=True)}</h1><p class="lead">{e(item["summary"], quote=True)}</p>'
                f'<figure class="article-figure"><img src="/{item["figure"]}" alt="{e(data["caption"], quote=True)}" width="960" height="600">'
                f'<figcaption>{e(data["caption"], quote=True)}</figcaption></figure>{paragraphs}'
                f'<section class="related"><p class="small-label">Continue exploring</p><ul>{links}</ul></section></article>')
        files[item["filename"]] = page(item["title"], body, item["filename"], description=item["summary"])
    missing = ('<section class="content-page not-found"><p class="eyebrow">404</p><h1>Page not found</h1>'
               '<p class="lead">The address may have changed, or the page may no longer be here.</p>'
               '<p><a href="/">Return to the notes</a></p></section>')
    files["404.html"] = page("Page not found", missing, "404.html")
    urls = ["https://" + domain + "/", "https://" + domain + "/about.html"]
    urls.extend("https://" + domain + "/" + item["filename"] for item in articles)
    files["sitemap.xml"] = ('<?xml version="1.0" encoding="UTF-8"?>\n'
                            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
                            + "".join(f"  <url><loc>{e(url, quote=True)}</loc></url>\n" for url in urls)
                            + '</urlset>\n')
    files["robots.txt"] = "User-agent: *\nAllow: /\nSitemap: https://" + domain + "/sitemap.xml\n"
    for filename, content in files.items():
        path = PurePosixPath(filename)
        if (path.is_absolute() or ".." in path.parts or str(path) != filename
                or not re.fullmatch(r"[a-z0-9][a-z0-9_./-]*", filename) or "\\" in filename):
            raise ValueError("Generated site has an unsafe relative filename")
        if not isinstance(content, str):
            raise ValueError("Generated site content must be UTF-8 text")
    return files


# Version two is a separate renderer. The version-one implementation and
# content above remain frozen so existing saved profiles keep identical files.

LEGACY_SITE_THEMES = SITE_THEMES
_generate_site_profile_v1 = generate_site_profile
_render_generated_site_v1 = render_generated_site
SITE_THEMES = LEGACY_SITE_THEMES + ARTIFACT_THEMES


def generate_site_profile(seed: str, theme: str = "auto", title: Optional[str] = None,
                          description: Optional[str] = None) -> dict:
    """Create a private profile; auto now chooses an artifact-based v2 theme.

    Explicit legacy themes still produce their original v1 profiles. Stored
    profiles always have a concrete theme, so rendering does not re-run auto
    selection when an installation is restarted or upgraded.
    """
    if theme == "auto" or theme in ARTIFACT_THEMES:
        return generate_artifact_profile(seed, theme, title, description)
    if theme not in LEGACY_SITE_THEMES:
        raise ValueError("Unknown generated-site theme")
    return _generate_site_profile_v1(seed, theme, title, description)


def render_generated_site(domain: str, profile: dict) -> Dict[str, str]:
    """Dispatch by the saved profile version without migrating existing sites."""
    if isinstance(profile, dict) and type(profile.get("version")) is int and profile["version"] == 2:
        return render_artifact_site(domain, profile)
    if isinstance(profile, dict) and profile.get("theme") not in LEGACY_SITE_THEMES:
        raise ValueError("Version-one site profile needs a legacy theme")
    return _render_generated_site_v1(domain, profile)


"""Read conventional APT sources and plan the single supported pocket change."""

import re
from pathlib import Path
from typing import NamedTuple

APT_BACKPORTS = "resolute-backports"
APT_LIST_LINE = re.compile(r"deb(?:-src)?\s+(?:\[([^]]*)\]\s+)?(\S+)\s+(\S+)(?:\s+.*)?")


class AptSource(NamedTuple):
    fields: dict
    location: str
    start: int
    end: int
    positions: dict


def apt_source_paths(root: Path):
    parts = root / "sources.list.d"
    return [root / "sources.list", *sorted(parts.glob("*.list")), *sorted(parts.glob("*.sources"))]


def apt_source_records(path, text):
    lines = text.splitlines(keepends=True)
    if path.suffix != ".sources":
        for index, raw in enumerate(lines):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            location = f"{path}:{index + 1}"
            match = APT_LIST_LINE.fullmatch(line)
            if not match:
                raise ValueError(f"Unrecognized APT source line in {location}.")
            options = {}
            for item in (match[1] or "").split():
                if "=" not in item:
                    continue
                key, value = item.split("=", 1)
                if key.lower() == "enabled":
                    raise ValueError(f"Enabled is a deb822 field and is unsupported in {location}.")
                if key in options:
                    raise ValueError(f"Duplicate APT option {key} in {location}.")
                options[key] = value
            yield AptSource({**options, "uris": match[2], "suites": match[3]}, location, index, index + 1, {})
        return

    start = 0
    fields, positions, last_key = {}, {}, None
    for index, raw in enumerate([*lines, ""]):
        location = f"{path} (stanza at line {start + 1})"
        if not raw.strip():
            if fields:
                yield AptSource(fields, location, start, index, positions)
            start = index + 1
            fields, positions, last_key = {}, {}, None
        elif raw.startswith("#"):
            continue
        elif raw[:1].isspace() and last_key:
            fields[last_key] += " " + raw.strip()
            positions[last_key].append(index)
        elif re.match(r"^[A-Za-z][A-Za-z0-9-]*:", raw):
            key, value = raw.split(":", 1)
            last_key = key.lower()
            if last_key in fields:
                raise ValueError(f"Duplicate deb822 APT field {key} in {location}.")
            fields[last_key] = value.strip()
            positions[last_key] = [index]
        else:
            raise ValueError(f"Malformed deb822 APT source at {path}:{index + 1}.")


def apt_source_enabled(fields):
    value = fields.get("enabled", "yes").strip().lower()
    # APT's deb822 parser accepts these aliases as well as numeric zero.
    return value not in {"no", "false", "without", "off", "disable"} and not re.fullmatch(r"[+-]?(?:0+|0x0+)", value)


def apt_backports_records(path, text):
    return [record for record in apt_source_records(path, text)
            if apt_source_enabled(record.fields) and APT_BACKPORTS in record.fields.get("suites", "").split()]


def without_apt_backports(path, text, records):
    lines = text.splitlines(keepends=True)
    for record in reversed(records):
        if path.suffix != ".sources":
            lines[record.start] = "# Disabled by SiteKit: " + lines[record.start]
            continue
        suites = record.fields["suites"].split()
        if any(suite != APT_BACKPORTS for suite in suites):
            for position in record.positions["suites"]:
                first = position == record.positions["suites"][0]
                prefix, value = lines[position].split(":", 1) if first else ("", lines[position])
                value = re.sub(r"(?<!\S)" + APT_BACKPORTS + r"(?!\S)", "", value)
                lines[position] = prefix + ":" + value if first else value if value.strip() else ""
        elif "enabled" in record.positions:
            first, *continuations = record.positions["enabled"]
            newline = "\r\n" if lines[first].endswith("\r\n") else "\n" if lines[first].endswith("\n") else ""
            lines[first] = lines[first].split(":", 1)[0] + ": no" + newline
            for position in continuations:
                lines[position] = ""
        else:
            newline = "\r\n" if lines[record.end - 1].endswith("\r\n") else "\n"
            if not lines[record.end - 1].endswith("\n"):
                lines[record.end - 1] += newline
            lines.insert(record.end, "Enabled: no" + newline)
    return "".join(lines)


# ---------------- Installer and command line ----------------
"""HTTPS Node: an isolated, pinned 3x-ui/Xray + nginx installer.

Copyright (c) 2026. MIT licensed. The upstream programs retain their licenses.
The offline release targets fresh Ubuntu 26.04 amd64 with one IPv4 address
and one DNS name pointing directly at it.
"""


import argparse
import contextlib
import fcntl
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import platform
import pwd
import re
import secrets
import shutil
import signal
import socket
import sqlite3
import ssl
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


APP_VERSION = "0.3.0-rc7"
RELEASE_VERSION = SECURITY_APPROVED_BUNDLE[0] if SECURITY_APPROVED_BUNDLE else "v3.11.0"
RELEASE_SHA256 = (SECURITY_APPROVED_BUNDLE[1] if SECURITY_APPROVED_BUNDLE else
                  "0ddfa4702f595442e2962acd81addc768fdacaa4ff2672c971a0463dae744916")
MAX_ARCHIVE_BYTES = 256 * 1024 * 1024
USER = "https-node"
PANEL_SERVICE = "https-node-panel.service"
NGINX_SERVICE = "https-node-nginx.service"
CERTBOT_SERVICE = "https-node-certbot.service"
CERTBOT_TIMER = "https-node-certbot.timer"
NGINX_OPENSSL_SHA256 = {
    "libssl.so.3": "8712ef346d30f30e4dcde34baa940a204f01fb1aa7f344e4a13201e9f91a2151",
    "libcrypto.so.3": "6097d4e32bccd08541bca97868687e5edb7c71f46b73cedbcffc4c30dadbc159",
}
NGINX_OPENSSL_COMMIT = "20d13b0afd31c8ce269dd16465fb2d9c7fb07db7"
ETC = Path("/etc/https-node")
STATE_FILE = ETC / "state.json"
OPT = Path("/opt/https-node")
DATA = Path("/var/lib/https-node")
LOG = Path("/var/log/https-node")
SITE = Path("/var/www/https-node")
CACHE = Path("/var/cache/https-node-nginx")
ACCESS = Path("/root/https-node-access.txt")
HOOK = Path("/etc/letsencrypt/renewal-hooks/deploy/https-node-reload")
UNIT_DIR = Path("/etc/systemd/system")
CHECKPOINT_ROOT = Path("/root/https-node-checkpoints")
MAINTENANCE_LOCK = Path("/run/https-node-maintenance.lock")
OWNED_PATHS = (ETC, OPT, DATA, LOG, SITE, CACHE, ACCESS, HOOK,
               UNIT_DIR / PANEL_SERVICE, UNIT_DIR / NGINX_SERVICE,
               UNIT_DIR / CERTBOT_SERVICE, UNIT_DIR / CERTBOT_TIMER)


class NodeError(RuntimeError):
    """An actionable failure, with no secret command arguments in its text."""


def log(message):
    print(message, flush=True)


def command(argv, *, env=None, timeout=180, check=True, secret=False, input_text=None):
    """Never invoke a shell; never include a secret argv or stdout in errors."""
    try:
        result = subprocess.run(
            [str(x) for x in argv], input=input_text, capture_output=True,
            text=True, env=env, timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NodeError(f"Cannot complete {Path(str(argv[0])).name}: {type(exc).__name__}") from exc
    if check and result.returncode:
        detail = " (private output suppressed)" if secret else "\n" + result.stderr[-3000:]
        raise NodeError(f"{Path(str(argv[0])).name} failed with exit {result.returncode}{detail}")
    return result


def write_file(path, content, mode=0o600):
    """Atomic replacement with restrictive permissions from creation time."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise NodeError(f"Refusing a symbolic link: {path}")
    fd, tmp = tempfile.mkstemp(prefix=".https-node-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def save_state(state):
    write_file(STATE_FILE, json.dumps(state, indent=2, ensure_ascii=False) + "\n")


def panel_settings(state):
    """Read optional exposure settings without rewriting legacy installation state."""
    if not isinstance(state, dict):
        raise NodeError("Unrecognized installation state.")
    allow = state.get("panel_allow", [])
    if not isinstance(allow, list):
        raise NodeError("Installation panel_allow must be a list of IP addresses or CIDRs.")
    try:
        return normalize_panel_access(state.get("panel_access", "ssh"), allow)
    except ValueError as exc:
        raise NodeError("Invalid installation panel access settings: " + str(exc)) from exc


def load_state():
    if STATE_FILE.is_symlink() or not STATE_FILE.is_file():
        raise NodeError("No managed installation state was found.")
    info = STATE_FILE.stat()
    if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
        raise NodeError("Installation state must be root-owned and mode 0600.")
    state = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    if not isinstance(state, dict) or state.get("format") != "https-node-v1":
        raise NodeError("Unrecognized installation state.")
    validate_domain(state.get("domain"))
    panel_settings(state)
    return state


def verify_digest(path, expected):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    if not hmac.compare_digest(digest.hexdigest(), expected):
        raise NodeError("Release SHA-256 mismatch; the archive will not be extracted or executed.")
    return digest.hexdigest()


def verify_nginx_openssl(directory):
    """Authenticate the private nginx libraries independently of Certbot."""
    if directory.is_symlink() or not directory.is_dir():
        raise NodeError("The nginx OpenSSL component is missing.")
    expected = "".join(f"{value}  {name}\n" for name, value in sorted(NGINX_OPENSSL_SHA256.items()))
    if {path.name for path in directory.iterdir()} != {*NGINX_OPENSSL_SHA256, "SHA256SUMS"}:
        raise NodeError("Unexpected nginx OpenSSL payload contents.")
    manifest = directory / "SHA256SUMS"
    if manifest.is_symlink() or not manifest.is_file() or manifest.read_text(encoding="ascii") != expected:
        raise NodeError("The nginx OpenSSL manifest does not match the reviewed component.")
    for name, expected_hash in NGINX_OPENSSL_SHA256.items():
        library = directory / name
        if library.is_symlink() or not library.is_file():
            raise NodeError("Expected a regular nginx OpenSSL library.")
        verify_digest(library, expected_hash)


def nginx_command(state):
    if state.get("nginx_openssl") == "managed":
        return str(OPT / "nginx-openssl/nginx")
    return "/usr/sbin/nginx"


def install_nginx_openssl(source, state):
    verify_nginx_openssl(source)
    target = OPT / "nginx-openssl"
    target.mkdir(mode=0o700)
    libraries = target / "lib"
    shutil.copytree(source, libraries)
    checks = "\n".join(f"{digest}  {libraries / name}" for name, digest in sorted(NGINX_OPENSSL_SHA256.items()))
    write_file(Path(nginx_command(state)), f'''#!/bin/sh
set -eu
unset LD_PRELOAD LD_AUDIT LD_LIBRARY_PATH
fail_openssl() {{
    printf '%s\\n' 'SiteKit: the private nginx OpenSSL component failed verification.' >&2
    exit 1
}}
for path in {target} {libraries}; do
    [ ! -L "$path" ] && [ -d "$path" ] || fail_openssl
done
for path in {libraries}/libcrypto.so.3 {libraries}/libssl.so.3; do
    [ ! -L "$path" ] && [ -f "$path" ] || fail_openssl
done
/usr/bin/sha256sum --check --strict --status <<'SITEKIT_OPENSSL' || fail_openssl
{checks}
SITEKIT_OPENSSL
export LD_LIBRARY_PATH={libraries}
export OPENSSL_MODULES={libraries}/ossl-modules OPENSSL_ENGINES={libraries}/engines-3
exec /usr/sbin/nginx "$@"
''', 0o700)


def verify_nginx_openssl_maps(maps, libraries):
    """Require both reviewed objects by path, device, and inode."""
    required = {libraries / name for name in NGINX_OPENSSL_SHA256}
    found = set()
    for row in maps.splitlines():
        columns = row.split(maxsplit=5)
        if len(columns) != 6:
            continue
        mapped = columns[5]
        path = Path(mapped.removesuffix(" (deleted)"))
        if path.name not in NGINX_OPENSSL_SHA256:
            continue
        if path not in required or mapped.endswith(" (deleted)"):
            raise NodeError("nginx maps an unreviewed OpenSSL object.")
        details = path.stat()
        major, minor = (int(part, 16) for part in columns[3].split(":"))
        if (major, minor, int(columns[4])) != (os.major(details.st_dev), os.minor(details.st_dev), details.st_ino):
            raise NodeError("The mapped nginx OpenSSL object differs from the file on disk.")
        found.add(path)
    if found != required:
        raise NodeError("Could not verify both OpenSSL objects in nginx.")


def verify_running_nginx_openssl(state):
    if state.get("nginx_openssl") != "managed":
        raise NodeError("No reviewed nginx OpenSSL runtime is recorded.")
    libraries = OPT / "nginx-openssl/lib"
    verify_nginx_openssl(libraries)
    pid = managed_nginx_pid()
    verify_nginx_openssl_maps((Path("/proc") / str(pid) / "maps").read_text(), libraries)
    if managed_nginx_pid() != pid:
        raise NodeError("nginx master changed during OpenSSL verification.")
    return {"commit": NGINX_OPENSSL_COMMIT, "sha256": NGINX_OPENSSL_SHA256}


def extract_release(archive, destination):
    """Reject links, special files, path traversal and unexpected archive roots."""
    root = Path(destination)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise NodeError("Archive destination is not empty.")
    with tarfile.open(archive, "r:gz") as tf:
        members = tf.getmembers()
        if len(members) > 5000 or sum(m.size for m in members) > 1024 ** 3:
            raise NodeError("Release archive exceeds extraction limits.")
        seen = set()
        file_paths = set()
        for member in members:
            p = Path(member.name)
            parts = p.parts
            if (p.is_absolute() or not parts or parts[0] != "x-ui"
                    or ".." in parts or "\\" in member.name
                    or not (member.isfile() or member.isdir())
                    or p.as_posix() in seen or member.size > MAX_ARCHIVE_BYTES):
                raise NodeError("Unsafe or unexpected release archive member.")
            seen.add(p.as_posix())
            if member.isfile():
                file_paths.add(p)
        for member in members:
            if any(parent in file_paths for parent in Path(member.name).parents):
                raise NodeError("An archive file is also used as a parent directory.")
        for member in members:
            target = root / member.name
            if member.isdir():
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
                continue
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            source = tf.extractfile(member)
            if source is None:
                raise NodeError("Cannot read a release member.")
            with source, open(target, "xb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(0o755 if member.mode & 0o111 else 0o644)
    for required in ("x-ui/x-ui", "x-ui/bin/xray-linux-amd64", "x-ui/bin/geoip.dat", "x-ui/bin/geosite.dat"):
        if not (root / required).is_file():
            raise NodeError(f"Release lacks required file: {required}")


def free_port(used=()):
    for _ in range(50):
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        if port not in used:
            return port
    raise NodeError("Cannot select a free loopback port.")


def require_free_port(address, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((address, port))
    except OSError as exc:
        raise NodeError(f"TCP {address}:{port} is unavailable.") from exc


def os_info():
    values = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip('"')
    return values


def package_inventory():
    """Read installed binary/source versions without refreshing apt or starting services."""
    fmt = "${binary:Package}\t${source:Package}\t${source:Version}\t${Version}\t${db:Status-Abbrev}\n"
    result = command(["dpkg-query", "-W", "-f=" + fmt])
    rows = []
    for line in result.stdout.splitlines():
        values = line.split("\t")
        if len(values) != 5:
            continue
        package, source, source_version, version, package_state = values
        tracked_names = {"nginx", "nginx-common", "nginx-core", "nginx-full", "nginx-light",
                         "nginx-extras", "certbot", "python3-certbot"}
        if source not in {"nginx", "python-certbot", "certbot"} and package.split(":")[0] not in tracked_names:
            continue
        if len(package_state) == 3 and package_state[1] in {"n", "c"}:
            continue
        complete = len(package_state) == 3 and package_state[1] == "i" and package_state[2] == " "
        rows.append({"package": package, "source_package": source,
                     "source_version": source_version, "version": version,
                     "status": "installed" if complete else "broken"})
    return rows


def deb_version_compare(left, operation, right):
    result = command(["dpkg", "--compare-versions", left, operation, right], check=False)
    if result.returncode not in (0, 1):
        raise NodeError("dpkg could not compare the complete package versions.")
    return result.returncode == 0


def require_security_report(report, label):
    if report.get("blocking", True):
        reasons = [item["reason"] for item in report.get("checks", []) if item.get("blocking")]
        raise NodeError(label + ": " + "; ".join(reasons or [report.get("status", "UNKNOWN")]))


def require_release_policy():
    """A denied or unreviewed bundle must never reach download/apt/systemd/ACME."""
    require_security_report(evaluate_pinned_release(RELEASE_VERSION, RELEASE_SHA256), "Release security policy")


def read_apt_releases(text):
    """Map apt policy package-file identities to their signed Release metadata."""
    releases = {}
    current = None
    for line in text.splitlines():
        row = re.match(r"^\s*-?\d+\s+(.+\sPackages)\s*$", line)
        if row:
            current = row.group(1)
        elif current and line.strip().startswith("release "):
            fields = line.strip()[len("release "):].split(",")
            releases[current] = dict(field.split("=", 1) for field in fields if "=" in field)
            current = None
    return releases


def approved_archive_uri(uri, info):
    """Restrict the small release to distro-operated archives, not arbitrary mirrors."""
    parsed = urllib.parse.urlsplit(uri)
    if (parsed.scheme not in {"http", "https"} or parsed.username or parsed.password
            or parsed.port is not None or parsed.query or parsed.fragment):
        return False
    host, path = parsed.hostname or "", parsed.path.rstrip("/")
    if info.get("ID") == "ubuntu":
        return (host in {"archive.ubuntu.com", "security.ubuntu.com"}
                or re.fullmatch(r"[a-z]{2}\.archive\.ubuntu\.com", host) is not None) and path == "/ubuntu"
    if info.get("ID") == "debian":
        return ((host == "deb.debian.org" and path in {"/debian", "/debian-security"})
                or (host == "security.debian.org" and path in {"/debian-security", "/debian-security/"}))
    return False


def validate_apt_source_record(fields, info, *, source=None):
    """Require explicit official signing-key binding for each enabled source."""
    if not apt_source_enabled(fields):
        return
    location = " in " + source if source else ""
    distro = info.get("ID")
    expected_keyring = {"ubuntu": "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
                        "debian": "/usr/share/keyrings/debian-archive-keyring.gpg"}.get(distro)
    codename = {("ubuntu", "24.04"): "noble", ("ubuntu", "26.04"): "resolute",
                ("debian", "12"): "bookworm", ("debian", "13"): "trixie"}.get(
                    (distro, info.get("VERSION_ID")))
    if not codename or fields.get("signed-by") != expected_keyring:
        raise NodeError("APT source needs an explicit Signed-By binding to the distro archive keyring" + location + ".")
    if not fields.get("uris") or any(not approved_archive_uri(uri, info) for uri in fields["uris"].split()):
        raise NodeError("APT source uses an unapproved archive URI" + location + ". Use a distro-operated archive.")
    allowed_suites = {codename, codename + "-security", codename + "-updates"}
    suites = fields.get("suites", "").split()
    unsupported = sorted(set(suites) - allowed_suites)
    if not suites or unsupported:
        detail = ", ".join(unsupported) if unsupported else "missing Suites"
        advice = " Review or disable the unsupported source before retrying."
        if unsupported == [APT_BACKPORTS] and codename == "resolute":
            advice = (" Use --disable-apt-backports during a fresh install to back up the source file "
                      "and disable only resolute-backports, or back up the source file and edit it yourself.")
        raise NodeError("APT source suite is outside the reviewed release/security/updates pockets"
                        + location + ": " + detail + ". Allowed: " + ", ".join(sorted(allowed_suites))
                        + "." + advice)
    for name in ("trusted", "allow-insecure", "allow-weak", "allow-downgrade-to-insecure"):
        if fields.get(name, "no").lower() not in {"no", "false", "0"}:
            raise NodeError("APT source weakens archive verification" + location + ": " + name + ".")
    if fields.get("check-valid-until", "yes").lower() not in {"yes", "true", "1"}:
        raise NodeError("APT source disables index expiry checks" + location + ".")


def verify_apt_trust(info, *, planned=None):
    """Validate conventional distro apt source files; do not rewrite the user's repos."""
    if os.environ.get("APT_CONFIG"):
        raise NodeError("A custom APT_CONFIG needs separate review before this limited update.")
    config = command(["apt-config", "dump"]).stdout
    if re.search(r'^Binary::[^:\s"]+::(?:RootDir|Dir)(?:::|\s)', config, re.M | re.I):
        raise NodeError("Binary-specific apt directory overrides need separate review.")
    root_dirs = re.findall(r'^RootDir\s+"([^"\n]*)";', config, re.M | re.I)
    if any(value not in {"", "/"} for value in root_dirs):
        raise NodeError("A custom APT RootDir needs separate review before this limited update.")
    for name, expected in {"Dir": "/", "Dir::Etc": "etc/apt", "Dir::Etc::sourcelist": "sources.list",
                           "Dir::Etc::sourceparts": "sources.list.d"}.items():
        found = re.findall(r"^" + re.escape(name) + r'\s+"([^"\n]*)";', config, re.M | re.I)
        if found and (found[-1] != expected if name == "Dir" else found[-1].rstrip("/") != expected.rstrip("/")):
            raise NodeError("Custom apt source-directory configuration needs separate review.")
    count = 0
    for path in apt_source_paths(Path("/etc/apt")):
        if path.is_symlink() or path.exists():
            data, _ = read_apt_source(path)
            if planned and path in planned:
                data = planned[path]
            for record in read_apt_records(path, data):
                validate_apt_source_record(record.fields, info, source=record.location)
                count += 1
    if not count:
        raise NodeError("No explicitly verified distro APT sources found.")
    keyring_package = "ubuntu-keyring" if info["ID"] == "ubuntu" else "debian-archive-keyring"
    keyring = Path("/usr/share/keyrings") / ("ubuntu-archive-keyring.gpg" if info["ID"] == "ubuntu" else "debian-archive-keyring.gpg")
    if keyring.is_symlink() or not keyring.is_file() or keyring.stat().st_uid != 0 or keyring.stat().st_mode & 0o022:
        raise NodeError("The distro archive keyring is missing or has unsafe ownership/mode.")
    owner = command(["dpkg-query", "-S", str(keyring)]).stdout.strip()
    if owner != keyring_package + ": " + str(keyring):
        raise NodeError("Archive keyring does not belong to the expected distro package.")
    result = command(["dpkg", "--verify", keyring_package], check=False)
    if result.returncode not in (0, 1) or any(line.rstrip().endswith(str(keyring)) for line in result.stdout.splitlines()):
        raise NodeError("Archive keyring differs from the installed distro package.")



def read_apt_source(path):
    metadata = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
        raise NodeError(f"APT source must be a root-owned regular file without group/world write access: {path}.")
    try:
        return path.read_bytes().decode("utf-8"), metadata
    except UnicodeError as exc:
        raise NodeError(f"APT source is not UTF-8: {path}.") from exc


def read_apt_records(path, data):
    try:
        for record in apt_source_records(path, data):
            if not apt_source_enabled(record.fields):
                continue
            if path.suffix == ".sources" and (not record.fields.get("types") or any(
                    kind not in {"deb", "deb-src"} for kind in record.fields["types"].split())):
                raise NodeError(f"Unrecognized APT Types field in {record.location}.")
            yield record
    except ValueError as exc:
        raise NodeError(str(exc)) from exc


def apt_backports_plan(info):
    """Validate proposed source files without changing the host."""
    if (info.get("ID"), info.get("VERSION_ID")) != ("ubuntu", "26.04"):
        raise NodeError("--disable-apt-backports is supported on Ubuntu 26.04 only.")
    changes = {}
    for path in apt_source_paths(Path("/etc/apt")):
        if not path.is_symlink() and not path.exists():
            continue
        before, metadata = read_apt_source(path)
        records = [record for record in read_apt_records(path, before)
                   if APT_BACKPORTS in record.fields.get("suites", "").split()]
        if not records:
            continue
        if metadata.st_nlink != 1 or any(parent.is_symlink() for parent in path.parents):
            raise NodeError(f"Refusing to modify a linked APT source: {path}.")
        for parent in (path.parent, path.parent.parent):
            parent_info = parent.stat()
            if parent_info.st_uid != 0 or parent_info.st_mode & 0o022:
                raise NodeError(f"Refusing to modify APT sources in an unsafe directory: {parent}.")
        for record in records:
            suites = [value for value in record.fields["suites"].split() if value != APT_BACKPORTS]
            fields = {**record.fields, "suites": " ".join(suites) or "resolute"}
            validate_apt_source_record(fields, info, source=record.location)
        changes[path] = (before, without_apt_backports(path, before, records), metadata)
    verify_apt_trust(info, planned={path: after for path, (_, after, _) in changes.items()})
    return changes


def write_apt_source(path, data, metadata):
    fd, temporary = tempfile.mkstemp(prefix=".sitekit-apt-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
            os.fchmod(stream.fileno(), stat.S_IMODE(metadata.st_mode))
            stream.write(data.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def apply_apt_backports(info):
    changes = apt_backports_plan(info)
    if not changes:
        return
    backup = Path(tempfile.mkdtemp(prefix="sitekit-apt-backports.", dir=Path("/root")))
    originals = {}
    for path, (before, _, metadata) in changes.items():
        destination = backup / path.relative_to(Path("/etc/apt"))
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        write_apt_source(destination, before, metadata)
        originals[path] = destination
    log("APT source backup: " + str(backup))
    applied = []
    try:
        for path, (before, after, metadata) in changes.items():
            current, current_metadata = read_apt_source(path)
            identity = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid")
            if current != before or any(getattr(current_metadata, key) != getattr(metadata, key) for key in identity):
                raise NodeError(f"APT source changed after preflight: {path}.")
            write_apt_source(path, after, metadata)
            applied.append(path)
        verify_apt_trust(info)
    except BaseException:
        failures = []
        for path in reversed(applied):
            try:
                if read_apt_source(path)[0] != changes[path][1]:
                    raise NodeError("APT source changed during rollback.")
                write_apt_source(path, originals[path].read_bytes().decode("utf-8"), changes[path][2])
            except (OSError, ValueError, NodeError):
                failures.append(str(path))
        if failures:
            raise NodeError(f"Unable to restore {', '.join(failures)}. Original sources: {backup}.")
        log("Restored original APT source files after validation failed.")
        raise
    log("Disabled only resolute-backports. APT source trust checks passed.")

def apt_candidate_origin(policy_text, candidate, releases, info):
    """Require a candidate from the supported distro's release/security/updates pockets."""
    codename = {("ubuntu", "24.04"): "noble", ("ubuntu", "26.04"): "resolute",
                ("debian", "12"): "bookworm", ("debian", "13"): "trixie"}.get(
                    (info.get("ID"), info.get("VERSION_ID")))
    if not codename:
        return False
    current = None
    found = False
    for line in policy_text.splitlines():
        version_row = re.match(r"^\s*(?:\*\*\*\s+)?(\S+)\s+-?\d+\s*$", line)
        if version_row:
            current = version_row.group(1)
            continue
        source_row = re.match(r"^\s*-?\d+\s+(.+\sPackages)\s*$", line)
        if current != candidate or not source_row:
            continue
        if not approved_archive_uri(source_row.group(1).split()[0], info):
            return False
        release = releases.get(source_row.group(1), {})
        allowed = False
        if info["ID"] == "ubuntu":
            if (release.get("o") == "Ubuntu" and release.get("l") == "Ubuntu"
                    and release.get("n") == codename
                    and release.get("a") in {codename, codename + "-security", codename + "-updates"}):
                allowed = True
        elif (release.get("o") == "Debian" and release.get("l") in {"Debian", "Debian-Security"}
              and release.get("n") in {codename, codename + "-security", codename + "-updates"}):
            allowed = True
        if not allowed:
            return False
        found = True
    return found


def apt_candidates(packages, info):
    env = {**os.environ, "LC_ALL": "C"}
    releases = read_apt_releases(command(["apt-cache", "policy"], env=env).stdout)
    rows = []
    for package in packages:
        if not re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::(?:amd64|all))?", package):
            raise NodeError("Unexpected package name in the nginx inventory.")
        policy = command(["apt-cache", "policy", package], env=env).stdout
        match = re.search(r"^\s*Candidate:\s*(\S+)\s*$", policy, re.M)
        if not match or match.group(1) == "(none)":
            raise NodeError("No apt candidate for " + package)
        version = match.group(1)
        if not re.fullmatch(r"[0-9][A-Za-z0-9.+:~_-]*", version):
            raise NodeError("Unexpected apt candidate version.")
        if not apt_candidate_origin(policy, version, releases, info):
            raise NodeError("Candidate is not from a reviewed distro pocket: " + package)
        metadata = command(["apt-cache", "show", package + "=" + version], env=env).stdout
        record = None
        for paragraph in metadata.split("\n\n"):
            fields = dict(line.split(": ", 1) for line in paragraph.splitlines()
                          if line and not line[0].isspace() and ": " in line)
            if (fields.get("Version") == version and fields.get("Architecture") in {"amd64", "all"}
                    and fields.get("Package") == package.split(":")[0]):
                record = fields
                break
        if record is None:
            raise NodeError("Cannot read exact apt candidate metadata for " + package)
        source = record.get("Source", record["Package"])
        source_match = re.fullmatch(r"([a-z0-9][a-z0-9+.-]*)(?: \(([^()\s]+)\))?", source)
        if not source_match:
            raise NodeError("Unrecognized source package metadata.")
        rows.append({"package": package, "version": version,
                     "source_package": source_match.group(1),
                     "source_version": source_match.group(2) or version, "status": "candidate"})
    return rows


def refresh_apt():
    verify_apt_trust(os_info())
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive", "LC_ALL": "C"}
    command(["apt-get", "-o", "DPkg::Lock::Timeout=300", "-o", "APT::Update::Error-Mode=any",
             "-o", "Acquire::AllowInsecureRepositories=false", "-o", "Acquire::Check-Valid-Until=true",
             "-o", "Acquire::AllowWeakRepositories=false", "-o", "Acquire::AllowDowngradeToInsecureRepositories=false",
             "update", "-qq"], env=env, timeout=900)
    return env


def runtime_state(state):
    """Read the independently recorded runtime identity without rewriting the node state."""
    marker = ETC / "runtime-release.json"
    if marker.is_symlink():
        raise NodeError("The runtime record must not be a symlink.")
    if not marker.exists():
        return state
    info = marker.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600:
        raise NodeError("The runtime record must be a root-owned, private file.")
    record = json.loads(marker.read_text(encoding="utf-8"))
    if record["domain"] != state["domain"] or record["cert_name"] != state["cert_name"]:
        raise NodeError("The runtime record does not belong to this installation.")
    return {**state, **{key: record[key] for key in ("release_version", "release_sha256", "certbot_backend",
                                                     "restore_stock_certbot_timer")}}


def audit_managed_certbot(state):
    try:
        require_security_report(evaluate_pinned_release(state["release_version"], state["release_sha256"]),
                                "Runtime security policy")
        runtime = OPT / "certbot"
        manifest = runtime / "payload.sha256"
        if not SECURITY_CERTBOT_MANIFEST_SHA256:
            raise NodeError("No exact Certbot manifest has been approved.")
        verify_digest(manifest, SECURITY_CERTBOT_MANIFEST_SHA256)
        files = dict(line.split()[::-1] for line in manifest.read_text(encoding="ascii").splitlines())
        for name in CERTBOT_LIBRARIES:
            verify_digest(runtime / "lib" / name, files[name])
        if command(["systemctl", "is-active", CERTBOT_TIMER], check=False).stdout.strip() != "active":
            raise NodeError("Managed Certbot timer is not active.")
        if command(["systemctl", "is-enabled", CERTBOT_TIMER], check=False).stdout.strip() != "enabled":
            raise NodeError("Managed Certbot timer is not enabled.")
        if command(["systemctl", "is-active", "certbot.timer"], check=False).stdout.strip() == "active":
            raise NodeError("Distribution Certbot timer is also active.")
        stock = command(["systemctl", "show", "certbot.timer", "-p", "LoadState", "--value"], check=False).stdout.strip()
        if stock != "not-found" and command(["systemctl", "is-enabled", "certbot.timer"],
                                             check=False).stdout.strip() != "disabled":
            raise NodeError("Distribution Certbot timer is not disabled.")
        for unit, expected in certbot_unit_contents(state).items():
            path = UNIT_DIR / unit
            values = dict(line.split("=", 1) for line in command(
                ["systemctl", "show", "--all", unit, "-p", "FragmentPath", "-p", "DropInPaths", "-p", "NeedDaemonReload"]
            ).stdout.splitlines())
            if (path.is_symlink() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022
                    or path.read_text(encoding="utf-8") != expected
                    or values != {"FragmentPath": str(path), "DropInPaths": "", "NeedDaemonReload": "no"}):
                raise NodeError("Effective Certbot unit differs from the managed configuration.")
        details = command([certbot_command(state), "--https-node-runtime-info"]).stdout.strip().splitlines()
    except (NodeError, OSError, ValueError, KeyError):
        return {"status": "UNKNOWN", "blocking": True, "reason": "Managed Certbot runtime or timer could not be validated."}
    return {"status": "PASS", "blocking": False, "evidence": details}


def security_check():
    """Read-only, scoped evidence; never labels the entire machine CVE-free."""
    info = os_info()
    inventory = package_inventory()
    release_version, release_sha = RELEASE_VERSION, RELEASE_SHA256
    release_origin = "bundled installer candidate"
    managed_certbot = None
    nginx_openssl = {"status": "UNKNOWN", "reason": "No reviewed running nginx OpenSSL runtime was verified."}
    try:
        state_exists = STATE_FILE.exists()
    except PermissionError:
        state_exists = True
    if state_exists:
        if os.geteuid() == 0:
            try:
                state = runtime_state(load_state())
                release_version, release_sha = state.get("release_version"), state.get("release_sha256")
                release_origin = "managed state; installed binary integrity is a separate check"
                if state.get("certbot_backend") == "managed-venv":
                    managed_certbot = audit_managed_certbot(state)
                try:
                    nginx_openssl = {"status": "PASS", **verify_running_nginx_openssl(state)}
                except (NodeError, OSError, ValueError) as error:
                    nginx_openssl["reason"] = str(error)
            except (NodeError, OSError, ValueError, KeyError, TypeError):
                release_version, release_sha = None, None
                release_origin = "managed state could not be validated"
        else:
            release_version, release_sha = None, None
            release_origin = "managed state unreadable without root"
    sources = ("nginx",) if managed_certbot is not None else ("nginx", "certbot")
    packages = evaluate_packages(info, inventory, deb_version_compare, required_sources=sources)
    release = evaluate_pinned_release(release_version, release_sha)
    report = {"app_version": APP_VERSION, "os": {key: info.get(key) for key in ("ID", "VERSION_ID")},
              "package_policy": packages, "release_policy": release, "release_origin": release_origin,
              "managed_certbot": managed_certbot, "nginx_openssl": nginx_openssl, "inventory": inventory,
              "blocking": (packages["blocking"] or release["blocking"]
                           or bool(managed_certbot and managed_certbot["blocking"]) or nginx_openssl["status"] != "PASS"),
              "coverage": "Dated nginx/Certbot package and release policy and the mapped nginx OpenSSL objects. "
                          "No live advisory feed, full-OS scan or exploitability claim."}
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 2 if report["blocking"] else 0


def site_file_hashes():
    result = {}
    if SITE.is_symlink() or not SITE.is_dir():
        raise NodeError("Expected a real managed website directory.")
    for current, directories, files in os.walk(SITE, followlinks=False):
        for name in directories + files:
            path = Path(current) / name
            relative = path.relative_to(SITE).as_posix()
            if path.is_symlink():
                raise NodeError("Unexpected symlink in the managed website.")
            if path.is_file() and not relative.startswith(".well-known/acme-challenge/"):
                result[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def managed_nginx_pid():
    value = command(["systemctl", "show", NGINX_SERVICE, "--property=MainPID", "--value"]).stdout.strip()
    if not value.isdigit() or int(value) < 2:
        raise NodeError("The managed nginx service has no running master PID.")
    executable = Path("/proc") / value / "exe"
    target = os.readlink(executable)
    if target.removesuffix(" (deleted)") != "/usr/sbin/nginx":
        raise NodeError("The managed service is not running the expected nginx executable.")
    return int(value)


def wait_managed_nginx(previous_pid, seconds=15):
    deadline = time.monotonic() + seconds
    while True:
        try:
            pid = managed_nginx_pid()
            if pid != previous_pid and os.path.samefile(Path("/proc") / str(pid) / "exe", "/usr/sbin/nginx"):
                return pid
        except (NodeError, OSError):
            pass
        if time.monotonic() >= deadline:
            raise NodeError("nginx did not start the installed executable in a new master process before the deadline.")
        time.sleep(0.25)


def nginx_worker_snapshot(master_pid):
    """Read the Linux identities of workers still accepting new connections."""
    proc = Path("/proc")
    master = proc / str(master_pid)
    # Linux stat fields after the final ')' start at field 3; starttime is 22.
    master_fields = (master / "stat").read_bytes().rsplit(b")", 1)[1].split()
    master_start = int(master_fields[19])
    try:
        children = (master / "task" / str(master_pid) / "children").read_text(encoding="ascii").split()
    except FileNotFoundError:
        # Some Linux/container kernels omit the optional per-task children file.
        # Inspect PPid first, so unrelated processes' command lines are not read.
        children = [entry.name for entry in proc.iterdir() if entry.name.isdecimal()]
    workers = set()
    for child in children:
        try:
            process = proc / child
            fields = (process / "stat").read_bytes().rsplit(b")", 1)[1].split()
            if int(fields[1]) != master_pid:
                continue
            title = (process / "cmdline").read_bytes().split(b"\0", 1)[0].strip()
            # Draining workers can retain a WebSocket for a long time. They no
            # longer accept new connections and must not delay this operation.
            if title != b"nginx: worker process":
                continue
            workers.add((int(child), int(fields[19])))
        except (FileNotFoundError, ProcessLookupError):
            # A worker may exit between the child-list and process reads.
            continue
    return master_start, frozenset(workers)


def reload_managed_nginx(seconds=15):
    """Reload and await a new accepting worker generation under the same master."""
    master_pid = managed_nginx_pid()
    master_start, previous_workers = nginx_worker_snapshot(master_pid)
    if not previous_workers:
        raise NodeError("Cannot confirm accepting nginx workers before reload.")
    command(["systemctl", "reload", NGINX_SERVICE], timeout=60)
    deadline = time.monotonic() + seconds
    while True:
        current_start, current_workers = nginx_worker_snapshot(master_pid)
        if current_start != master_start:
            raise NodeError("The nginx master changed during a reload-only operation.")
        if current_workers and not previous_workers.intersection(current_workers):
            if managed_nginx_pid() != master_pid:
                raise NodeError("The managed nginx master changed during reload.")
            return
        if time.monotonic() >= deadline:
            raise NodeError("nginx did not acknowledge the new worker generation before the reload deadline.")
        time.sleep(min(0.1, max(0, deadline - time.monotonic())))


def update_nginx(args):
    """A bounded distro nginx update on an already accepted node; no reinstall."""
    if os.geteuid() != 0:
        raise NodeError("update-nginx requires root.")
    freshness = verify_policy_freshness()
    require_security_report({"blocking": freshness["blocking"], "checks": [freshness]}, "Security policy freshness")
    state = load_state()
    if args.confirm_domain != state["domain"] or state.get("status") != "ready" or state.get("stage") != "complete":
        raise NodeError("update-nginx requires a ready/complete node and its exact --confirm-domain.")
    audit = command(["dpkg", "--audit"], check=False)
    if audit.returncode or audit.stdout.strip() or audit.stderr.strip():
        raise NodeError("dpkg reports pending/broken package state; resolve it before this limited nginx update.")
    if command(["systemctl", "is-enabled", "nginx.service"], check=False).stdout.strip() != "disabled":
        raise NodeError("The stock nginx service must already be disabled.")
    if command(["systemctl", "is-active", "nginx.service"], check=False).stdout.strip() not in {"inactive", "failed"}:
        raise NodeError("The stock nginx service must already be stopped.")
    for path in (Path("/run/systemd/system/nginx.service"), UNIT_DIR / "nginx.service"):
        if path.exists() or path.is_symlink():
            raise NodeError("An existing nginx override/mask requires manual review.")
    owner = command(["dpkg-query", "-S", "/usr/sbin/nginx"]).stdout.strip()
    if "\n" in owner or not owner.endswith(": /usr/sbin/nginx"):
        raise NodeError("Cannot establish the package owning /usr/sbin/nginx.")
    owner = owner.removesuffix(": /usr/sbin/nginx")
    current = package_inventory()
    nginx_rows = [row for row in current if row["source_package"] == "nginx"]
    if owner not in {row["package"] for row in nginx_rows} and owner + ":amd64" not in {row["package"] for row in nginx_rows}:
        raise NodeError("The nginx executable does not belong to the expected distro source package.")
    pid = managed_nginx_pid()
    if state.get("nginx_openssl") == "managed":
        verify_running_nginx_openssl(state)
    command([nginx_command(state), "-t", "-c", str(ETC / "nginx.conf")])
    final_tls_probe(state)
    ensure_private_listeners()
    if MAINTENANCE_LOCK.is_symlink():
        raise NodeError("Maintenance lock must not be a symlink.")
    with open(MAINTENANCE_LOCK, "a", encoding="ascii") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise NodeError("Another HTTPS Node maintenance operation is running.") from exc
        immutable = {path: path.read_bytes() for path in (STATE_FILE, ACCESS, ETC / "nginx.conf")}
        before_site = site_file_hashes()
        checkpoint_root = CHECKPOINT_ROOT
        if checkpoint_root.is_symlink():
            raise NodeError("Checkpoint root must not be a symlink.")
        checkpoint_root.mkdir(mode=0o700, exist_ok=True)
        checkpoint = Path(tempfile.mkdtemp(prefix="nginx-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-", dir=checkpoint_root))
        for path, content in immutable.items():
            target = checkpoint / path.name
            target.write_bytes(content)
            target.chmod(0o600)
        write_file(checkpoint / "before.json", json.dumps({"packages": current, "site_files": before_site, "master_pid": pid}, indent=2))
        env = refresh_apt()
        candidates = apt_candidates([row["package"] for row in nginx_rows], os_info())
        require_security_report(evaluate_packages(os_info(), candidates, deb_version_compare,
                                                  required_sources=("nginx",)), "nginx apt candidates")
        targets = [row["package"] + "=" + row["version"] for row in candidates]
        simulation = command(["apt-get", "--simulate", "--no-remove", "--only-upgrade", "install", *targets], env=env)
        write_file(checkpoint / "apt-plan.txt", simulation.stdout + simulation.stderr)
        planned = re.findall(r"^Inst\s+(\S+)", simulation.stdout, re.M)
        configured = re.findall(r"^Conf\s+(\S+)", simulation.stdout, re.M)
        allowed = {row["package"].split(":")[0] for row in nginx_rows}
        if any(package.split(":")[0] not in allowed for package in planned + configured) or re.search(r"^Remv\s", simulation.stdout, re.M):
            raise NodeError("The nginx plan changes packages outside the nginx source; inspect the saved plan.")
        if not planned and os.path.samefile(Path("/proc") / str(pid) / "exe", "/usr/sbin/nginx"):
            require_security_report(evaluate_packages(os_info(), current, deb_version_compare,
                                                      required_sources=("nginx",)), "Installed nginx packages")
            log("nginx already meets this policy and runs the installed executable; no restart needed.")
            log("Checkpoint: " + str(checkpoint))
            return
        masked = False
        cleanup_errors = []
        try:
            command(["systemctl", "mask", "--runtime", "nginx.service"])
            masked = True
            command(["apt-get", "-o", "DPkg::Lock::Timeout=300", "-o", "APT::Get::AllowUnauthenticated=false",
                     "--no-remove", "--only-upgrade", "install", "-y", *targets], env=env, timeout=900)
            after = package_inventory()
            require_security_report(evaluate_packages(os_info(), after, deb_version_compare,
                                                      required_sources=("nginx",)), "Installed nginx packages")
            for expected in candidates:
                actual = [row for row in after if row["package"].split(":")[0] == expected["package"].split(":")[0]]
                if len(actual) != 1 or any(actual[0].get(key) != expected.get(key)
                                           for key in ("version", "source_package", "source_version")):
                    raise NodeError("Installed nginx versions differ from the reviewed exact apt targets.")
            verified = command(["dpkg", "--verify", owner], check=False)
            if verified.returncode not in (0, 1) or any(line.rstrip().endswith("/usr/sbin/nginx") for line in verified.stdout.splitlines()):
                raise NodeError("The installed nginx executable failed package integrity verification.")
            command([nginx_command(state), "-t", "-c", str(ETC / "nginx.conf")])
            # Reload retains the old master executable. Restart is intentional.
            command(["systemctl", "restart", NGINX_SERVICE], timeout=60)
            new_pid = wait_managed_nginx(pid)
            if state.get("nginx_openssl") == "managed":
                verify_running_nginx_openssl(state)
            for attempt in range(6):
                try:
                    final_tls_probe(state)
                    break
                except (OSError, NodeError):
                    if attempt == 5:
                        raise
                    time.sleep(0.5)
            ensure_private_listeners()
            if any(path.read_bytes() != content for path, content in immutable.items()) or site_file_hashes() != before_site:
                raise NodeError("Managed identity/configuration/site changed during maintenance; inspect checkpoint.")
            write_file(checkpoint / "after.json", json.dumps({"packages": after, "master_pid": new_pid,
                       "nginx_policy": "PASS", "site_and_identity": "unchanged"}, indent=2))
        except BaseException:
            log("nginx maintenance did not finish. Checkpoint: " + str(checkpoint))
            log("Package transactions are not automatically rolled back. Panel, credentials and website were not intentionally replaced.")
            raise
        finally:
            if masked:
                for action in (["systemctl", "unmask", "--runtime", "nginx.service"],
                               ["systemctl", "disable", "--now", "nginx.service"]):
                    try:
                        if command(action, check=False, timeout=30).returncode:
                            cleanup_errors.append("systemctl " + action[1] + " failed")
                    except Exception as exc:
                        cleanup_errors.append("systemctl " + action[1] + ": " + type(exc).__name__)
                try:
                    enabled = command(["systemctl", "is-enabled", "nginx.service"], check=False).stdout.strip()
                    active = command(["systemctl", "is-active", "nginx.service"], check=False).stdout.strip()
                    if enabled != "disabled" or active not in {"inactive", "failed"}:
                        cleanup_errors.append("stock nginx is not disabled/stopped")
                except Exception as exc:
                    cleanup_errors.append("stock nginx status: " + type(exc).__name__)
                if cleanup_errors:
                    log("Stock-service cleanup needs attention: " + "; ".join(cleanup_errors))
                    try:
                        write_file(checkpoint / "cleanup-errors.json", json.dumps(cleanup_errors, indent=2))
                    except Exception:
                        log("Could not save cleanup errors in checkpoint.")
        if cleanup_errors:
            raise NodeError("nginx was updated, but stock-service cleanup needs attention; inspect the checkpoint.")
        log("nginx package policy, new master executable, HTTPS and unchanged site/identity: PASS")
        log("Checkpoint: " + str(checkpoint))
        log("This updated nginx only. Run security-check for the separate Certbot/release findings.")


def preflight(domain, bind_ip=None, *, installing=False, reuse_stock_nginx=False, disable_apt_backports=False):
    domain = validate_domain(domain)
    if installing and os.geteuid() != 0:
        raise NodeError("Install requires root. Run with sudo python3.")
    if platform.machine().lower() not in ("x86_64", "amd64"):
        raise NodeError("This tested release supports x86-64 only.")
    info = os_info()
    if (info.get("ID"), info.get("VERSION_ID")) not in {
        ("ubuntu", "24.04"), ("ubuntu", "26.04"), ("debian", "12"), ("debian", "13")
    }:
        raise NodeError("Use a fresh Ubuntu 24.04/26.04, Debian 12 or Debian 13 VPS. Ubuntu 22.04 nginx is too old.")
    for program in ("systemctl", "ip", "ss", "apt-get", "getent", "pgrep"):
        if not shutil.which(program):
            raise NodeError(f"Required base-system command is missing: {program}")
    if not Path("/run/systemd/system").is_dir():
        raise NodeError("A running systemd VPS is required; a plain container is not supported.")
    for path in (*OWNED_PATHS, Path("/usr/local/x-ui"), Path("/etc/x-ui")):
        if path.exists() or path.is_symlink():
            raise NodeError(f"Existing installation or managed-path conflict: {path}")
    if shutil.which("nginx") or Path("/etc/nginx/nginx.conf").exists():
        if not reuse_stock_nginx:
            raise NodeError("nginx is already installed. For packages left by this installer, use --reuse-stock-nginx after uninstall.")
        if command(["pgrep", "-x", "nginx"], check=False).returncode == 0:
            raise NodeError("A running nginx process was found; existing services will not be changed.")
        enabled = command(["systemctl", "is-enabled", "nginx.service"], check=False).stdout.strip()
        if enabled != "disabled":
            raise NodeError("--reuse-stock-nginx requires an already disabled, stopped stock nginx service.")
    if Path("/etc/letsencrypt/renewal").exists() and any(Path("/etc/letsencrypt/renewal").iterdir()):
        raise NodeError("Existing Certbot certificates found; use a separate fresh VPS.")
    for database in ("passwd", "group"):
        if command(["getent", database, USER], check=False).returncode == 0:
            raise NodeError("The https-node system account/group already exists.")
    for path in (UNIT_DIR / "nginx.service", Path("/run/systemd/system/nginx.service")):
        if path.exists() or path.is_symlink():
            raise NodeError("Existing nginx service override/mask; no change was made.")
    # Reject source-policy conflicts before creating private state or masking nginx.
    # refresh_apt() checks again immediately before using the package manager.
    if disable_apt_backports:
        apt_backports_plan(info)
    else:
        verify_apt_trust(info)
    addresses = command(["ip", "-j", "-4", "addr", "show", "scope", "global"]).stdout
    local = {a["local"] for item in json.loads(addresses) for a in item.get("addr_info", []) if a.get("family") == "inet"}
    if bind_ip is not None:
        bind_ip = validate_ipv4(bind_ip)
    bind_ip = verify_public_dns(domain, bind_ip)
    if bind_ip not in local:
        raise NodeError("The domain A record must match the selected local IPv4. CDN proxy/NAT are outside this release.")
    if not ipaddress.ip_address(bind_ip).is_global:
        raise NodeError("Installation requires a public IPv4 address.")
    for port in (80, 443):
        require_free_port(bind_ip, port)
    require_free_port("127.0.0.1", 2053)
    return {"domain": domain, "bind_ip": bind_ip, "os": info["ID"] + " " + info["VERSION_ID"]}


def dig_records(resolver, domain, kind):
    result = command(["dig", "@" + resolver, domain + ".", kind, "+time=3", "+tries=1",
                      "+noall", "+comments", "+answer"], check=False, timeout=10)
    if result.returncode or "status: NOERROR" not in result.stdout:
        raise NodeError("Public DNS lookup failed.")
    rows = [line.split() for line in result.stdout.splitlines() if line and not line.startswith(";")]
    return {row[4] for row in rows if len(row) >= 5 and row[3] == kind}


def doh_records(resolver, domain, kind):
    # JSON DNS-over-HTTPS allows a read-only preflight before dnsutils is installed.
    query = urllib.parse.urlencode({"name": domain + ".", "type": kind})
    request = urllib.request.Request(resolver + "?" + query, headers={"Accept": "application/dns-json"})
    with urllib.request.urlopen(request, timeout=5) as response:
        reply = json.loads(response.read(65536))
    number = {"A": 1, "AAAA": 28}[kind]
    question = [(str(row["name"]).rstrip(".").lower(), row["type"]) for row in reply["Question"]]
    if reply["Status"] != 0 or reply.get("TC") or question != [(domain, number)]:
        raise NodeError("Public DNS lookup failed.")
    return {row["data"] for row in reply.get("Answer", []) if row["type"] == number}


def verify_public_dns(domain, address=None):
    """Require matching public A records and no AAAA, independent of NSS."""
    if shutil.which("dig"):
        resolvers = ("1.1.1.1", "8.8.8.8")
        query_records = dig_records
    else:
        resolvers = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")
        query_records = doh_records
    verified = None
    for resolver in resolvers:
        try:
            records = {kind: query_records(resolver, domain, kind) for kind in ("A", "AAAA")}
        except (NodeError, OSError, http.client.HTTPException, ValueError, KeyError, TypeError):
            continue
        if address is None:
            if len(records["A"]) != 1:
                raise NodeError("The domain must have exactly one A record pointing directly at this VPS.")
            address = validate_ipv4(next(iter(records["A"])))
        if records["A"] != {address}:
            raise NodeError("Public DNS A records disagree with the selected VPS IPv4.")
        if records["AAAA"]:
            raise NodeError("Remove the domain AAAA record for this IPv4-only release, then retry after DNS propagation.")
        verified = address
    if verified is None:
        raise NodeError("Cannot verify A/AAAA through public DNS. Check outbound DNS and the domain.")
    return verified


def new_state(facts, args):
    panel_mode, panel_allow = normalize_panel_access(getattr(args, "panel_access", "ssh"),
                                                    getattr(args, "panel_allow", None))
    # Generate once for this installation, then persist with the private state.
    # Serving pages, restarting services and reading status never regenerate it.
    custom_site = bool(getattr(args, "site_dir", None))
    profile = None if custom_site else generate_site_profile(
        secrets.token_hex(32), getattr(args, "site_theme", "auto"),
        args.site_title, args.site_description,
    )
    ports = [2053]
    for _ in range(3):
        ports.append(free_port(ports))
    return {
        "format": "https-node-v1", "app_version": APP_VERSION,
        "release_version": RELEASE_VERSION, "release_sha256": RELEASE_SHA256,
        "created_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "status": "installing", "stage": "preflight", **facts,
        "transport": args.transport, "email": args.email,
        "panel_access": panel_mode, "panel_allow": panel_allow,
        "site_mode": "custom" if custom_site else "generated",
        "site_profile": profile,
        "site_title": profile["title"] if profile else args.site_title,
        "site_description": profile["description"] if profile else args.site_description,
        "panel_port": ports[0], "inbound_port": ports[1],
        "api_port": ports[2], "metrics_port": ports[3],
        "panel_path": "/" + secrets.token_hex(16) + "/",
        "transport_path": "/api/" + secrets.token_hex(16) + "/",
        "username": "owner-" + secrets.token_hex(4), "password": secrets.token_urlsafe(24),
        "uuid": str(uuid.uuid4()), "sub_id": secrets.token_hex(16),
        "client_name": "HTTPS Node", "nginx_mask_created": False,
        "system_user_created": False, "certificate_issued": False,
    }


def build_inbound(state):
    transport = state["transport"]
    if transport not in ("xhttp", "ws"):
        raise NodeError("Unknown transport.")
    stream = {
        "network": transport, "security": "none",
        "sockopt": {"trustedXForwardedFor": ["X-Https-Node"]},
    }
    stream[transport + "Settings"] = {
        "path": state["transport_path"], "host": state["domain"],
        **({"mode": "auto"} if transport == "xhttp" else {}),
    }
    client = {"id": state["uuid"], "email": state["client_name"], "subId": state["sub_id"], "enable": True, "flow": ""}
    return {
        "up": 0, "down": 0, "total": 0, "remark": "HTTPS Node",
        "enable": True, "expiryTime": 0, "listen": "127.0.0.1",
        "port": state["inbound_port"], "protocol": "vless",
        "settings": json.dumps({"clients": [client], "decryption": "none"}),
        "streamSettings": json.dumps(stream),
        "sniffing": json.dumps({"enabled": False, "destOverride": []}),
    }


def xray_template(state):
    return {
        "log": {"access": "none", "error": "", "loglevel": "warning"},
        "api": {"tag": "api", "services": ["HandlerService", "LoggerService", "StatsService", "RoutingService"]},
        "inbounds": [{"tag": "api", "listen": "127.0.0.1", "port": state["api_port"], "protocol": "tunnel", "settings": {"rewriteAddress": "127.0.0.1"}}],
        "outbounds": [
            {"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [{"action": "block", "ip": ["geoip:private"]}, {"action": "allow"}]}},
            {"tag": "blocked", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {"domainStrategy": "AsIs", "rules": [
            {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
            {"type": "field", "ip": ["geoip:private"], "outboundTag": "blocked"},
        ]},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
                   "system": {"statsInboundUplink": True, "statsInboundDownlink": True}},
        "metrics": {"tag": "metrics_out", "listen": "127.0.0.1:" + str(state["metrics_port"])},
        "stats": {},
    }


def client_link(state):
    options = {"encryption": "none", "security": "tls", "sni": state["domain"],
               "fp": "chrome", "type": state["transport"], "host": state["domain"],
               "path": state["transport_path"], "alpn": "h2" if state["transport"] == "xhttp" else "http/1.1"}
    if state["transport"] == "xhttp":
        options["mode"] = "auto"
    return "vless://" + state["uuid"] + "@" + state["domain"] + ":443?" + urllib.parse.urlencode(options, quote_via=urllib.parse.quote) + "#" + urllib.parse.quote(state["client_name"])


def panel_env():
    return {"XUI_DB_TYPE": "sqlite", "XUI_DB_FOLDER": str(DATA / "panel"),
            "XUI_LOG_FOLDER": str(LOG / "panel"), "XUI_BIN_FOLDER": str(DATA / "xray"),
            "XUI_ENABLE_FAIL2BAN": "false", "XUI_SKIP_HSTS": "true", "XUI_LOG_LEVEL": "warning"}


def set_database_settings(db_path, values):
    with sqlite3.connect(db_path, timeout=30) as connection:
        for key, value in values.items():
            connection.execute("DELETE FROM settings WHERE key = ?", (key,))
            connection.execute("INSERT INTO settings(key, value) VALUES (?, ?)", (key, str(value)))
        for key, expected in values.items():
            rows = connection.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchall()
            if rows != [(str(expected),)]:
                raise NodeError(f"Cannot verify offline panel setting: {key}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise NodeError("Unexpected redirect from the loopback API.")


class PanelAPI:
    def __init__(self, port, path, token):
        if not 1024 <= int(port) <= 65535 or not re.fullmatch(r"/[A-Za-z0-9_-]+/", path):
            raise NodeError("Invalid loopback API endpoint.")
        self.base = f"http://127.0.0.1:{port}{path}panel/api/"
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def call(self, endpoint, payload=None):
        if not re.fullmatch(r"[A-Za-z0-9/]+", endpoint):
            raise NodeError("Invalid API operation.")
        headers = {"Authorization": "Bearer " + self.token, "Content-Type": "application/json"}
        data = None if payload is None else json.dumps(payload).encode()
        req = urllib.request.Request(self.base + endpoint, data=data, headers=headers)
        try:
            with self.opener.open(req, timeout=15) as response:
                body = response.read(4 * 1024 * 1024 + 1)
            if len(body) > 4 * 1024 * 1024:
                raise NodeError("Oversized API response.")
            parsed = json.loads(body)
            if parsed.get("success") is not True:
                raise NodeError("Panel API rejected operation " + endpoint + ".")
            return parsed.get("obj")
        except (urllib.error.URLError, ValueError, TimeoutError) as exc:
            raise NodeError("Loopback API failed for " + endpoint + ": " + type(exc).__name__) from exc


def wait_api(api, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            return api.call("inbounds/list")
        except NodeError:
            time.sleep(1)
    raise NodeError("Panel API did not become ready; inspect journalctl -u https-node-panel.")


def verify_panel_database(state):
    required = {"webListen": "127.0.0.1", "webPort": str(state["panel_port"]),
                "webBasePath": state["panel_path"], "subEnable": "false", "subJsonEnable": "false"}
    db_uri = (DATA / "panel/x-ui.db").as_uri() + "?mode=ro"
    with sqlite3.connect(db_uri, uri=True) as connection:
        for key, expected in required.items():
            if connection.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchall() != [(expected,)]:
                raise NodeError("Panel configuration verification failed for " + key)
        count = connection.execute("SELECT COUNT(*) FROM users WHERE username=?", (state["username"],)).fetchone()[0]
        if count != 1:
            raise NodeError("Panel account creation could not be verified.")


def ensure_private_listeners():
    result = command(["ss", "-H", "-ltnp"]).stdout
    matched = 0
    for line in result.splitlines():
        if '"x-ui"' not in line and '"xray-linux-' not in line:
            continue
        matched += 1
        columns = line.split()
        if len(columns) < 4 or not columns[3].startswith(("127.0.0.1:", "[::1]:")):
            raise NodeError("A panel/Xray TCP listener is not private; services have to stop.")
    if matched < 2:
        raise NodeError("Cannot confirm panel and Xray private listeners.")


def install_units(state):
    panel = """[Unit]
Description=HTTPS Node private 3x-ui and Xray
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=https-node
Group=https-node
WorkingDirectory=/var/lib/https-node
EnvironmentFile=/etc/https-node/panel.env
ExecStart=/opt/https-node/x-ui
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/https-node /var/log/https-node/panel
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""
    executable = nginx_command(state)
    nginx = f"""[Unit]
Description=HTTPS Node public nginx
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
RuntimeDirectory=https-node-nginx
RuntimeDirectoryMode=0755
ExecStartPre={executable} -t -c /etc/https-node/nginx.conf
ExecStart={executable} -c /etc/https-node/nginx.conf -g "daemon off;"
ExecReload={executable} -c /etc/https-node/nginx.conf -s reload
KillSignal=SIGQUIT
TimeoutStopSec=20
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/run/https-node-nginx /var/log/https-node/nginx /var/cache/https-node-nginx
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
"""
    write_file(UNIT_DIR / PANEL_SERVICE, panel, 0o644)
    write_file(UNIT_DIR / NGINX_SERVICE, nginx, 0o644)
    write_file(ETC / "panel.env", "".join(k + "=" + v + "\n" for k, v in panel_env().items()))
    command(["systemctl", "daemon-reload"])


def validate_site_source(directory):
    root = Path(directory)
    if root.is_symlink() or not root.is_dir() or not (root / "index.html").is_file():
        raise NodeError("--site-dir must be a static site directory with index.html and no symbolic links.")
    total = 0
    count = 0
    for current, dirs, files in os.walk(root, followlinks=False):
        for name in dirs + files:
            path = Path(current) / name
            if path.is_symlink() or name.startswith(".") or (not path.is_dir() and not path.is_file()):
                raise NodeError("Custom sites may not contain hidden files, symbolic links or special files.")
            if path.is_file():
                count += 1
                total += path.stat().st_size
    if count > 2000 or total > 100 * 1024 * 1024:
        raise NodeError("Custom site exceeds 2000 files / 100 MiB.")
    return root


def validate_generated_files(files):
    """Reject an invalid renderer result before creating any output files."""
    if not isinstance(files, dict) or not files or len(files) > 256 or "index.html" not in files:
        raise NodeError("Generated site must contain index.html and at most 256 files.")
    total = 0
    for name, content in files.items():
        if (not isinstance(name, str) or len(name) > 240
                or not re.fullmatch(r"[A-Za-z0-9_/-]+(?:\.[A-Za-z0-9]+)?", name)
                or name.startswith("/") or "//" in name
                or any(part.startswith(".") or not part for part in name.split("/"))
                or not isinstance(content, str)):
            raise NodeError("Generated site contains an unsafe file path or non-text content.")
        parts = name.split("/")
        if any("/".join(parts[:n]) in files for n in range(1, len(parts))):
            raise NodeError("A generated file cannot also be a directory.")
        total += len(content.encode("utf-8"))
    if total > 16 * 1024 * 1024:
        raise NodeError("Generated site exceeds 16 MiB.")


def write_generated_files(root, files):
    """Write trusted rendered text inside a newly created site directory."""
    validate_generated_files(files)
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        raise NodeError("Generated site destination must be a real directory.")
    for name, content in files.items():
        parent = root
        for part in name.split("/")[:-1]:
            parent = parent / part
            if parent.is_symlink():
                raise NodeError("Refusing a symbolic link inside the generated site.")
            parent.mkdir(mode=0o755, exist_ok=True)
            parent.chmod(0o755)
        write_file(root / name, content, 0o644)


def preview_site(args):
    """Create an offline preview; no root, DNS, package or service operations."""
    domain = validate_domain(args.domain)
    profile = generate_site_profile(
        args.site_seed if args.site_seed is not None else secrets.token_hex(32),
        args.site_theme, args.site_title, args.site_description,
    )
    files = render_generated_site(domain, profile)
    validate_generated_files(files)
    output = Path(args.output).expanduser().absolute()
    if ".." in output.parts or any(path.is_symlink() for path in (output, *output.parents)):
        raise NodeError("Preview output may not contain parent traversal or symbolic links.")
    if output.exists() or not output.parent.is_dir():
        raise NodeError("Choose a new preview directory inside an existing directory; existing output is never overwritten.")
    output.mkdir(mode=0o700)
    output.chmod(0o700)
    webroot = output / "site"
    webroot.mkdir(mode=0o755)
    webroot.chmod(0o755)
    write_generated_files(webroot, files)
    manifest = {
        "format": "https-node-site-preview-v1", "app_version": APP_VERSION,
        "domain": domain, "site_profile": profile,
        "files_sha256": {name: hashlib.sha256(text.encode("utf-8")).hexdigest() for name, text in files.items()},
    }
    manifest_path = output / "site-profile.json"
    write_file(manifest_path, json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps({
        "site_root": str(webroot), "profile_file": str(manifest_path),
        "theme": profile["theme"], "title": profile["title"], "files": len(files),
    }, indent=2, ensure_ascii=False))
    log("Preview saved. Serve only the site/ directory to keep its profile outside the webroot.")


def populate_site(state, custom_directory=None):
    generated = None
    if not custom_directory:
        if state.get("site_mode") == "custom":
            raise NodeError("Custom site directory is missing; refusing to generate a replacement.")
        if state.get("site_profile") is not None:
            generated = render_generated_site(state["domain"], state["site_profile"])
        elif state.get("site_mode") == "generated":
            raise NodeError("Generated site profile is missing; refusing to silently replace it.")
        else:
            # Compatibility with a 0.1.0 state. It must not acquire a new identity.
            generated = render_site(state["domain"], state["site_title"], state["site_description"])
        validate_generated_files(generated)
    SITE.mkdir(mode=0o755, parents=True)
    SITE.chmod(0o755)
    if custom_directory:
        source = validate_site_source(custom_directory)
        for current, dirs, files in os.walk(source, followlinks=False):
            relative = Path(current).relative_to(source)
            dest = SITE / relative
            dest.mkdir(mode=0o755, parents=True, exist_ok=True)
            dest.chmod(0o755)
            for name in files:
                item = Path(current) / name
                # Recheck immediately before opening; never follow source links.
                fd = os.open(item, os.O_RDONLY | os.O_NOFOLLOW)
                try:
                    if not stat.S_ISREG(os.fstat(fd).st_mode):
                        raise NodeError("A custom-site file changed during copying.")
                    with os.fdopen(fd, "rb") as src, open(dest / name, "xb") as out:
                        fd = -1
                        shutil.copyfileobj(src, out)
                    (dest / name).chmod(0o644)
                finally:
                    if fd >= 0:
                        os.close(fd)
    else:
        write_generated_files(SITE, generated)
    if not (SITE / "404.html").exists():
        write_file(SITE / "404.html", "<!doctype html><title>Not found</title><h1>Not found</h1>\n", 0o644)
    (SITE / ".well-known/acme-challenge").mkdir(mode=0o755, parents=True)
    (SITE / ".well-known").chmod(0o755)
    (SITE / ".well-known/acme-challenge").chmod(0o755)


def make_directories(state, extracted):
    command(["useradd", "--system", "--user-group", "--home-dir", str(DATA), "--no-create-home", "--shell", "/usr/sbin/nologin", USER])
    state["system_user_created"] = True
    account = pwd.getpwnam(USER)
    state["service_uid"] = account.pw_uid
    state["service_gid"] = account.pw_gid
    save_state(state)
    OPT.mkdir(mode=0o755)
    OPT.chmod(0o755)
    shutil.copy2(Path(extracted) / "x-ui/x-ui", OPT / "x-ui")
    (OPT / "x-ui").chmod(0o755)
    # Keep the parent of root nginx logs outside the panel user's control.
    LOG.mkdir(mode=0o755)
    LOG.chmod(0o755)
    for directory in (DATA, DATA / "panel", DATA / "xray", LOG / "panel"):
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chown(directory, account.pw_uid, account.pw_gid)
    for item in (Path(extracted) / "x-ui/bin").iterdir():
        target = DATA / "xray" / item.name
        shutil.copy2(item, target)
        os.chown(target, account.pw_uid, account.pw_gid)
        target.chmod(0o700 if item.stat().st_mode & 0o111 else 0o600)
    (LOG / "nginx").mkdir(mode=0o750)
    (LOG / "nginx").chmod(0o750)
    CACHE.mkdir(mode=0o700)
    web = pwd.getpwnam("www-data")
    os.chown(CACHE, web.pw_uid, web.pw_gid)


def bootstrap_panel(state):
    environment = {**os.environ, **panel_env()}
    result = command([
        OPT / "x-ui", "setting", "-listenIP", "127.0.0.1",
        "-port", str(state["panel_port"]), "-webBasePath", state["panel_path"],
        "-username", state["username"], "-password", state["password"],
        "-getApiToken", "-tokenName", "https-node-bootstrap",
    ], env=environment, secret=True, timeout=60)
    tokens = re.findall(r"^apiToken:\s*(\S+)\s*$", result.stdout, re.MULTILINE)
    if len(tokens) != 1:
        raise NodeError("The pinned panel did not produce the expected private bootstrap token.")
    state["api_token"] = tokens[0]
    save_state(state)
    settings = {
        "webListen": "127.0.0.1", "webPort": str(state["panel_port"]),
        "webBasePath": state["panel_path"], "webDomain": "",
        "subEnable": "false", "subJsonEnable": "false", "subListen": "127.0.0.1",
        "tgBotEnable": "false", "discordBotEnable": "false",
        "xrayTemplateConfig": json.dumps(xray_template(state)),
    }
    set_database_settings(DATA / "panel/x-ui.db", settings)
    verify_panel_database(state)
    account = pwd.getpwnam(USER)
    # CLI bootstrap runs as root; transfer any DB/log/config files it created.
    # No service has started yet, and these are exclusively new owned trees.
    for base in (DATA, LOG / "panel"):
        for directory, dirs, files in os.walk(base):
            os.chown(directory, account.pw_uid, account.pw_gid)
            os.chmod(directory, 0o700)
            for name in files:
                path = Path(directory) / name
                if path.is_symlink():
                    raise NodeError("Unexpected link in the new private data tree.")
                mode = 0o700 if path.stat().st_mode & 0o111 else 0o600
                os.chown(path, account.pw_uid, account.pw_gid)
                path.chmod(mode)
    # No process has listened before this point. Both subscriptions are already off.
    command(["systemctl", "start", PANEL_SERVICE])
    api = PanelAPI(state["panel_port"], state["panel_path"], state["api_token"])
    existing = wait_api(api)
    if existing:
        raise NodeError("Unexpected inbound in a new database.")
    added = api.call("inbounds/add", build_inbound(state))
    if not isinstance(added, dict) or not isinstance(added.get("id"), int):
        raise NodeError("The panel returned an unexpected inbound id.")
    state["inbound_id"] = added["id"]
    save_state(state)
    api.call("hosts/add", {"remark": state["client_name"], "inboundIds": [added["id"]],
        "hosts": [state["domain"] + ":443"], "security": "tls", "sni": state["domain"], "fingerprint": "chrome"})
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", state["inbound_port"]), timeout=1):
                break
        except OSError:
            time.sleep(0.5)
    else:
        raise NodeError("Xray inbound did not become ready.")
    ensure_private_listeners()
    xenv = {**os.environ, "XRAY_LOCATION_ASSET": str(DATA / "xray")}
    command([DATA / "xray/xray-linux-amd64", "run", "-test", "-config", DATA / "xray/config.json"], env=xenv, timeout=30)
    links = api.call("inbounds/allLinks")
    if not isinstance(links, list) or not any(isinstance(link, str) and ("@" + state["domain"] + ":443?") in link and "security=tls" in link for link in links):
        raise NodeError("The panel did not generate the expected TLS client link.")


def nginx_config(state, tls):
    panel_mode, panel_allow = panel_settings(state)
    cert_name = state.get("cert_name")
    if not isinstance(cert_name, str) or not re.fullmatch(r"https-node-[0-9a-f]{16}", cert_name):
        raise NodeError("Unexpected managed certificate name.")
    lineage = Path("/etc/letsencrypt/live") / cert_name
    return render_nginx(
        state["domain"], state["bind_ip"], state["transport"], state["inbound_port"],
        state["transport_path"], str(SITE),
        str(lineage / "fullchain.pem") if tls else None,
        str(lineage / "privkey.pem") if tls else None,
        panel_access=panel_mode, panel_path=state["panel_path"],
        panel_port=state["panel_port"], panel_allow=panel_allow,
    )


def local_http_probe(state):
    token = secrets.token_hex(24)
    name = "https-node-" + secrets.token_hex(8)
    probe = SITE / ".well-known/acme-challenge" / name
    write_file(probe, token, 0o644)
    try:
        with contextlib.closing(http.client.HTTPConnection(state["bind_ip"], 80, timeout=10)) as connection:
            # systemd's Type=simple reports a started process before nginx binds.
            deadline = time.monotonic() + 10
            while True:
                try:
                    connection.connect()
                    break
                except ConnectionRefusedError as exc:
                    if time.monotonic() >= deadline:
                        raise NodeError("nginx did not listen on port 80 for the local ACME probe.") from exc
                    time.sleep(0.25)
            connection.request("GET", "/.well-known/acme-challenge/" + name, headers={"Host": state["domain"]})
            response = connection.getresponse()
            if response.status != 200 or response.read(1024).decode() != token:
                raise NodeError("The local ACME webroot probe failed.")
    finally:
        probe.unlink(missing_ok=True)


def final_tls_probe(state):
    context = ssl.create_default_context()
    with socket.create_connection((state["bind_ip"], 443), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=state["domain"]) as connection:
            connection.sendall(("GET / HTTP/1.1\r\nHost: " + state["domain"] + "\r\nConnection: close\r\n\r\n").encode())
            head = connection.recv(4096)
            if not head.startswith(b"HTTP/1.1 200 "):
                raise NodeError("The public TLS website did not return HTTP 200.")
    # TLS must fail before any HTTP request for an unrelated SNI.
    try:
        with socket.create_connection((state["bind_ip"], 443), timeout=10) as raw:
            with ssl._create_unverified_context().wrap_socket(raw, server_hostname="invalid.example"):
                pass
    except ssl.SSLError:
        pass
    else:
        raise NodeError("Unexpected SNI was accepted by the default TLS server.")


def render_vless_qr(state):
    """Render a plain-text QR without placing the connection secret in argv."""
    try:
        result = command(["qrencode", "-t", "UTF8", "-m", "4"],
                         input_text=client_link(state), timeout=10, secret=True)
    except UnicodeError:
        raise NodeError("qrencode returned text that could not be decoded.") from None
    qr = result.stdout
    # UTF8 output needs only half/full blocks, spaces and newlines. In
    # particular, no terminal escape sequences belong in a saved text file.
    lines = qr.splitlines()
    if (not qr.endswith("\n") or len(qr) > 65536
            or any(char not in " ▀▄█\n" for char in qr)
            or not 15 <= len(lines) <= 93
            or not 29 <= len(lines[0]) <= 185
            or any(len(line) != len(lines[0]) for line in lines)
            or not any(char in qr for char in "▀▄")):
        raise NodeError("qrencode did not return a valid plain UTF-8 QR code.")
    return qr


def make_access_text(state, *, qr_text=None, qr_unavailable=False):
    """Format saved access details; QR rendering is an explicit caller action."""
    panel_mode, panel_allow = panel_settings(state)
    panel_summary = (
        "Panel access: SSH tunnel only; its public HTTPS URL is disabled.\n"
        "To enable browser access without a tunnel, run on the server once:\n"
        f"python3 /root/https-node.py panel-access --mode https --confirm-domain {state['domain']}\n"
        "Use your verified standalone installer at /root/https-node.py, or substitute its saved path.\n"
        "Optionally append --allow YOUR_PUBLIC_IP/32 to restrict only the HTTPS panel.\n"
        "Then read the Public panel URL in this file and open it in your browser.\n"
    )
    if panel_mode == "https":
        panel_summary = (f"Panel access: HTTPS and SSH tunnel.\n"
                         f"Public panel: https://{state['domain']}{state['panel_path']}\n"
                         "Open the Public panel URL directly in your browser; no SSH tunnel is needed.\n"
                         "Sign in with the Username and Password below.\n"
                         "HTTPS panel allowed source IPs: " + (", ".join(panel_allow) if panel_allow else
                         "any IP (normal panel authentication is required)") + "\n")
    routing_summary = ("Panel is not routed through public nginx. Subscription service is disabled.\n"
                       if panel_mode == "ssh" else
                       "Only the secret panel URL is proxied to loopback. Subscription service is disabled.\n"
                       "Source-IP restrictions apply only to that HTTPS panel URL; website and VLESS remain public.\n")
    qr_section = ""
    if qr_text is not None:
        qr_section = (
            "VLESS QR code (import this connection in your VLESS client):\n"
            "Display with a fixed-width font, light text on a dark background, and no line wrapping.\n"
            + qr_text + "\n"
        )
    elif qr_unavailable:
        qr_section = (
            "VLESS QR code: unavailable. The VLESS link above is still usable.\n"
            "To regenerate this file with QR, run your verified installer on the server:\n"
            "python3 /root/https-node.py credentials --refresh-file\n\n"
        )
    return (
        f"HTTPS Node {APP_VERSION}\nDomain: {state['domain']}\nTransport: VLESS + {state['transport']} + TLS\n"
        f"Website: https://{state['domain']}/\n" + panel_summary + "\n"
        f"SSH tunnel instructions (run on YOUR computer; replace root/SSH port if needed):\n"
        f"ssh -N -L 127.0.0.1:2053:127.0.0.1:{state['panel_port']} root@{state['bind_ip']}\n"
        f"Panel in YOUR local browser: http://127.0.0.1:2053{state['panel_path']}\n"
        f"Username: {state['username']}\nPassword: {state['password']}\n\n"
        f"VLESS link:\n{client_link(state)}\n\n"
        + qr_section + routing_summary +
        "Proxy connections to private/local IP ranges are blocked; system firewall is unchanged.\n"
        "Panel/transport versions are pinned at installation; inspect future updates explicitly.\n"
    )


def make_saved_access_text(state):
    """Keep usable credentials if the optional QR renderer is unavailable."""
    try:
        return make_access_text(state, qr_text=render_vless_qr(state))
    except NodeError:
        log("WARNING: VLESS QR generation failed; access details retain the connection link. "
            "Use credentials --refresh-file to retry after fixing qrencode.")
        return make_access_text(state, qr_unavailable=True)


def _panel_safe_parent(path):
    """Protect the fixed managed paths before a root-owned atomic replacement."""
    path = Path(path)
    if not path.is_absolute() or any(parent.is_symlink() for parent in path.parents):
        raise NodeError("Panel access maintenance requires literal managed paths without symlink parents.")
    info = path.parent.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
        raise NodeError("Panel access maintenance requires root-owned, non-writable managed parent directories.")


def _panel_private_file(path):
    _panel_safe_parent(path)
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size > 8 * 1024 * 1024):
        raise NodeError("Panel access maintenance requires root-owned, regular mode 0600 managed files.")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (opened.st_dev, opened.st_ino, opened.st_mode, opened.st_uid, opened.st_nlink) != (
                info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink):
            raise NodeError("A managed panel access file changed during validation.")
        return stream.read(8 * 1024 * 1024 + 1)


@contextlib.contextmanager
def _panel_maintenance_lock():
    _panel_safe_parent(MAINTENANCE_LOCK)
    fd = os.open(MAINTENANCE_LOCK, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) & 0o022):
            raise NodeError("Maintenance lock must be a root-owned regular file.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise NodeError("Another HTTPS Node maintenance operation is running.") from exc
        yield
    finally:
        os.close(fd)


def credentials(args):
    """Show access details, or explicitly refresh only the private access file."""
    if os.geteuid() != 0:
        raise NodeError("Use sudo to read credentials.")
    if not args.refresh_file:
        state = load_state()
        if state.get("status") != "ready":
            raise NodeError("Installation is not ready; inspect status.")
        qr = render_vless_qr(state) if args.qr else None
        print(make_access_text(state, qr_text=qr), end="")
        return
    with _panel_maintenance_lock():
        before_state = _panel_private_file(STATE_FILE)
        _panel_safe_parent(ACCESS)
        try:
            before_access = _panel_private_file(ACCESS)
        except FileNotFoundError:
            before_access = None
        state = load_state()
        if state.get("status") != "ready" or state.get("stage") != "complete":
            raise NodeError("Refreshing access details requires a ready/complete installation.")
        # A refresh is deliberately strict: QR failure never replaces the
        # previous access file. No service or installation state is changed.
        content = make_access_text(state, qr_text=render_vless_qr(state))
        if _panel_private_file(STATE_FILE) != before_state:
            raise NodeError("Installation state changed; access details were not overwritten.")
        if before_access is None:
            if ACCESS.exists() or ACCESS.is_symlink():
                raise NodeError("The access file appeared during refresh; nothing was overwritten.")
            _panel_safe_parent(ACCESS)
        elif _panel_private_file(ACCESS) != before_access:
            raise NodeError("The access file changed during refresh; nothing was overwritten.")
        write_file(ACCESS, content)
        log("Updated root-only access file: " + str(ACCESS))
        if args.qr:
            print(content, end="")


def panel_access(args):
    """Change only nginx panel exposure; retain the existing installation identity."""
    if os.geteuid() != 0:
        raise NodeError("panel-access requires root.")
    mode, allow = normalize_panel_access(args.mode, args.allow)
    with _panel_maintenance_lock():
        # Acquire the shared maintenance lock before observing the previous mode.
        paths = (STATE_FILE, ACCESS, ETC / "nginx.conf")
        before = {path: _panel_private_file(path) for path in paths}
        state = load_state()
        if args.confirm_domain != state["domain"] or state.get("status") != "ready" or state.get("stage") != "complete":
            raise NodeError("panel-access requires a ready/complete node and its exact --confirm-domain.")
        previous_mode, previous_allow = panel_settings(state)
        if before[ETC / "nginx.conf"] != nginx_config(state, True).encode("utf-8"):
            raise NodeError("Managed nginx configuration differs from the recorded settings; review manual changes first.")
        if mode == previous_mode and allow == previous_allow:
            log("Panel access already matches the requested mode and allowlist; no changes or reload needed.")
            return
        updated = {**state, "panel_access": mode, "panel_allow": allow}
        after = {
            STATE_FILE: (json.dumps(updated, indent=2, ensure_ascii=False) + "\n").encode("utf-8"),
            ACCESS: make_saved_access_text(updated).encode("utf-8"),
            ETC / "nginx.conf": nginx_config(updated, True).encode("utf-8"),
        }
        # Validate all snapshots before any replacement, including their text encoding.
        previous_text = {path: content.decode("utf-8") for path, content in before.items()}
        if command(["systemctl", "is-active", NGINX_SERVICE], check=False).stdout.strip() != "active":
            raise NodeError("The managed nginx service must already be active.")
        command([nginx_command(state), "-t", "-c", str(ETC / "nginx.conf")])
        verify_panel_database(state)
        ensure_private_listeners()
        final_tls_probe(state)
        _panel_safe_parent(CHECKPOINT_ROOT)
        if CHECKPOINT_ROOT.is_symlink():
            raise NodeError("Checkpoint root must not be a symlink.")
        CHECKPOINT_ROOT.mkdir(mode=0o700, exist_ok=True)
        info = CHECKPOINT_ROOT.lstat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise NodeError("Checkpoint root must be a root-owned mode 0700 directory.")
        checkpoint = Path(tempfile.mkdtemp(prefix="panel-access-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + "-",
                                          dir=CHECKPOINT_ROOT))
        for path, content in previous_text.items():
            write_file(checkpoint / path.name, content)
        write_file(checkpoint / "change.json", json.dumps({
            "domain": state["domain"], "from": {"mode": previous_mode, "allow": previous_allow},
            "to": {"mode": mode, "allow": allow}, "status": "prepared",
        }, indent=2) + "\n")
        # SIGTERM should receive the same rollback as Ctrl-C. Uncatchable kills
        # still leave the private checkpoint available for explicit recovery.
        old_term = signal.getsignal(signal.SIGTERM)
        old_int = signal.getsignal(signal.SIGINT)
        def interrupted(signum, frame):
            raise KeyboardInterrupt("Panel access maintenance interrupted")
        signal.signal(signal.SIGTERM, interrupted)
        changed = False
        try:
            if any(_panel_private_file(path) != content for path, content in before.items()):
                raise NodeError("Managed files changed before panel access maintenance; nothing was overwritten.")
            changed = True
            write_file(ETC / "nginx.conf", after[ETC / "nginx.conf"].decode("utf-8"))
            command([nginx_command(state), "-t", "-c", str(ETC / "nginx.conf")])
            write_file(STATE_FILE, after[STATE_FILE].decode("utf-8"))
            write_file(ACCESS, after[ACCESS].decode("utf-8"))
            reload_managed_nginx()
            if command(["systemctl", "is-active", NGINX_SERVICE], check=False).stdout.strip() != "active":
                raise NodeError("Managed nginx did not remain active after reload.")
            final_tls_probe(updated)
            ensure_private_listeners()
            verify_panel_database(updated)
            if any(_panel_private_file(path) != content for path, content in after.items()):
                raise NodeError("Managed files changed during panel access maintenance.")
            write_file(checkpoint / "result.json", json.dumps({"status": "complete", "panel_access": mode,
                       "panel_allow": allow}, indent=2) + "\n")
        except BaseException:
            # Repeated termination requests must not interrupt the bounded rollback.
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            errors = []
            if changed:
                for path, content in previous_text.items():
                    try:
                        _panel_safe_parent(path)
                        if path.is_symlink():
                            raise NodeError("Managed file became a symlink during rollback.")
                        write_file(path, content)
                    except Exception as exc:
                        errors.append(path.name + ": " + type(exc).__name__)
                if not errors:
                    try:
                        command([nginx_command(state), "-t", "-c", str(ETC / "nginx.conf")])
                        reload_managed_nginx()
                        if command(["systemctl", "is-active", NGINX_SERVICE], check=False).stdout.strip() != "active":
                            raise NodeError("Managed nginx is not active after rollback.")
                    except Exception as exc:
                        errors.append("nginx rollback: " + type(exc).__name__)
            try:
                write_file(checkpoint / "result.json", json.dumps({"status": "rollback-incomplete" if errors else
                           "rolled-back" if changed else "unchanged", "errors": errors}, indent=2) + "\n")
            except Exception:
                log("Could not save panel access rollback diagnostics.")
            log("Panel access maintenance did not finish. Checkpoint: " + str(checkpoint))
            if errors:
                raise NodeError("Panel access rollback needs attention: " + "; ".join(errors))
            raise
        finally:
            signal.signal(signal.SIGTERM, old_term)
            signal.signal(signal.SIGINT, old_int)
        log("Panel access updated to " + mode + "; website, panel account and VLESS settings retained.")
        log("Checkpoint: " + str(checkpoint))
        log("Updated access details: " + str(ACCESS))


def finish_mask(state):
    if state.get("nginx_mask_created"):
        command(["systemctl", "unmask", "--runtime", "nginx.service"])
        # disable while masked can exit 0 without removing enablement links.
        command(["systemctl", "disable", "--now", "nginx.service"], check=False)
        enabled = command(["systemctl", "is-enabled", "nginx.service"], check=False).stdout.strip()
        active = command(["systemctl", "is-active", "nginx.service"], check=False).stdout.strip()
        if enabled not in ("disabled", "not-found") or active not in ("inactive", "failed", "unknown"):
            raise NodeError("The stock nginx service could not be disabled and stopped.")
        state["nginx_mask_created"] = False
        save_state(state)


def certbot_command(state):
    if state.get("certbot_backend") == "managed-venv":
        return OPT / "certbot/certbot"
    return "certbot"


def certbot_unit_contents(state):
    cert_name = state["cert_name"]
    if not re.fullmatch(r"https-node-[0-9a-f]{16}", cert_name):
        raise NodeError("Unexpected managed certificate name.")
    service = f"""[Unit]
Description=Renew the HTTPS Node certificate
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
UMask=0077
ExecStart={certbot_command(state)} renew --cert-name {cert_name} --quiet --no-random-sleep-on-renew
"""
    timer = f"""[Unit]
Description=Check the HTTPS Node certificate for renewal

[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=3600
Persistent=true
Unit={CERTBOT_SERVICE}

[Install]
WantedBy=timers.target
"""
    return {CERTBOT_SERVICE: service, CERTBOT_TIMER: timer}


def stage_certbot_timer(state, *, persist=None, start=True):
    units = certbot_unit_contents(state)
    cert_name = state["cert_name"]
    if any(path.name != cert_name + ".conf" for path in Path("/etc/letsencrypt/renewal").glob("*.conf")):
        raise NodeError("Another Certbot lineage needs the distribution renewal timer.")
    legacy_unit = command(["systemctl", "is-enabled", "certbot.timer"], check=False).stdout.strip()
    legacy_active = command(["systemctl", "is-active", "certbot.timer"], check=False).stdout.strip()
    if legacy_unit == "enabled" or legacy_active == "active":
        if (legacy_unit, legacy_active) != ("enabled", "active"):
            raise NodeError("Unexpected distribution Certbot timer state.")
        state["restore_stock_certbot_timer"] = True
        (persist or save_state)(state)
        command(["systemctl", "disable", "--now", "certbot.timer"])
    if command(["systemctl", "is-active", "certbot.service"], check=False).stdout.strip() not in {"inactive", "unknown"}:
        raise NodeError("A distribution Certbot job is still running or failed.")
    for unit, content in units.items():
        write_file(UNIT_DIR / unit, content, 0o644)
    command(["systemctl", "daemon-reload"])
    if start:
        command(["systemctl", "enable", "--now", CERTBOT_TIMER])


def stop_certbot_timer(state):
    if state.get("certbot_backend") != "managed-venv":
        return
    if (UNIT_DIR / CERTBOT_TIMER).is_file():
        command(["systemctl", "disable", "--now", CERTBOT_TIMER])
    if (UNIT_DIR / CERTBOT_SERVICE).is_file():
        command(["systemctl", "stop", CERTBOT_SERVICE])


def restore_stock_certbot_timer(state):
    if state.get("restore_stock_certbot_timer"):
        command(["systemctl", "enable", "--now", "certbot.timer"])


def install(args):
    normalize_panel_access(getattr(args, "panel_access", "ssh"), getattr(args, "panel_allow", None))
    require_release_policy()
    if not args.release_archive:
        raise NodeError("Provide the digest-pinned local bundle with --release-archive.")
    if not args.agree_tos:
        raise NodeError("Pass --agree-tos to accept Let's Encrypt's subscriber agreement.")
    if args.email:
        if not re.fullmatch(r"[^\s@]{1,64}@[^\s@]{1,190}", args.email) or any(ord(c) < 32 for c in args.email):
            raise NodeError("Provide a valid --email for certificate notifications.")
    elif not args.acme_no_email:
        raise NodeError("Provide --email or explicitly select --acme-no-email.")
    disable_backports = getattr(args, "disable_apt_backports", False)
    facts = preflight(args.domain, args.bind_ip, installing=True, reuse_stock_nginx=args.reuse_stock_nginx,
                      disable_apt_backports=disable_backports)
    if facts["os"] != "ubuntu 26.04" or sys.version_info[:2] != (3, 14):
        raise NodeError("The reviewed offline Certbot wheels require Ubuntu 26.04 amd64 with Python 3.14.")
    if args.site_dir:
        validate_site_source(args.site_dir)
    state = new_state(facts, args)
    # Validate the complete generated result before any system mutation.
    if state["site_profile"] is not None:
        validate_generated_files(render_generated_site(facts["domain"], state["site_profile"]))
    state["cert_name"] = "https-node-" + secrets.token_hex(8)
    state["certbot_backend"] = "managed-venv"
    state["nginx_openssl"] = "managed"
    log("Preflight passed. Verifying the pinned local release.")
    with tempfile.TemporaryDirectory(prefix="https-node-", dir="/tmp") as work:
        archive = Path(work) / "release.tar.gz"
        shutil.copyfile(args.release_archive, archive)
        verify_digest(archive, RELEASE_SHA256)
        extracted = Path(work) / "release"
        extract_release(archive, extracted)
        certbot_payload = extracted / "x-ui/certbot"
        if not SECURITY_CERTBOT_MANIFEST_SHA256:
            raise NodeError("The Certbot payload does not have an approved manifest.")
        verify_digest(certbot_payload / "SHA256SUMS", SECURITY_CERTBOT_MANIFEST_SHA256)
        verify_certbot_payload(certbot_payload)
        nginx_payload = extracted / "x-ui/nginx-openssl"
        verify_nginx_openssl(nginx_payload)
        if disable_backports:
            apply_apt_backports(os_info())
        else:
            verify_apt_trust(os_info())
        ETC.mkdir(mode=0o700)
        save_state(state)
        try:
            state["stage"] = "packages"
            save_state(state)
            log("Installing Ubuntu nginx and utilities; service auto-start is held until configuration is ready.")
            # Only a fresh host reaches here. Never replace another policy-rc.d.
            command(["systemctl", "mask", "--runtime", "nginx.service"])
            state["nginx_mask_created"] = True
            save_state(state)
            apt_env = refresh_apt()
            candidates = apt_candidates(["nginx", "nginx-common"], os_info())
            require_security_report(evaluate_packages(os_info(), candidates, deb_version_compare,
                                                      required_sources=("nginx",)), "APT candidate policy")
            targets = [row["package"] + "=" + row["version"] for row in candidates]
            command(["apt-get", "-o", "DPkg::Lock::Timeout=300", "-o", "APT::Get::AllowUnauthenticated=false",
                     "install", "-y", "--no-remove", "--no-install-recommends", *targets,
                     "ca-certificates", "dnsutils", "qrencode"], env=apt_env, timeout=900)
            require_security_report(evaluate_packages(os_info(), package_inventory(), deb_version_compare,
                                                      required_sources=("nginx",)), "Installed package policy")
            finish_mask(state)
            verify_public_dns(state["domain"], state["bind_ip"])
            state["stage"] = "private-panel"
            save_state(state)
            log("Creating the service account and offline panel settings.")
            make_directories(state, extracted)
            install_nginx_openssl(nginx_payload, state)
            version = command([nginx_command(state), "-v"]).stderr
            match = re.search(r"nginx/(\d+)\.(\d+)\.(\d+)", version)
            if not match or tuple(map(int, match.groups())) < (1, 19, 4):
                raise NodeError("nginx >= 1.19.4 is required for SNI rejection.")
            install_certbot_runtime(certbot_payload, OPT / "certbot", command)
            populate_site(state, args.site_dir)
            if state["site_profile"] is not None:
                log("Generated website: " + state["site_title"] + " (" + state["site_profile"]["theme"] + ")")
            install_units(state)
            bootstrap_panel(state)
            state["stage"] = "certificate"
            save_state(state)
            log("Starting the ACME webroot and requesting the domain certificate.")
            write_file(ETC / "nginx.conf", nginx_config(state, False))
            command(["systemctl", "start", NGINX_SERVICE])
            local_http_probe(state)
            verify_running_nginx_openssl(state)
            registration = ["--email", args.email] if args.email else ["--register-unsafely-without-email"]
            command([certbot_command(state), "certonly", "--non-interactive", "--agree-tos", *registration,
                     "--webroot", "-w", str(SITE), "-d", state["domain"], "--cert-name", state["cert_name"],
                     "--key-type", "ecdsa", "--keep-until-expiring"], timeout=300)
            state["certificate_issued"] = True
            state["stage"] = "public-tls"
            save_state(state)
            write_file(ETC / "nginx.conf", nginx_config(state, True))
            command([nginx_command(state), "-t", "-c", str(ETC / "nginx.conf")])
            command(["systemctl", "reload", NGINX_SERVICE])
            lineage = "/etc/letsencrypt/live/" + state["cert_name"]
            hook = ('#!/bin/sh\nset -eu\n[ "${RENEWED_LINEAGE:-}" = "' + lineage + '" ] || exit 0\n'
                    + nginx_command(state) + ' -t -c /etc/https-node/nginx.conf\n'
                    '/bin/systemctl reload https-node-nginx.service\n')
            write_file(HOOK, hook, 0o700)
            stage_certbot_timer(state)
            command(["systemctl", "enable", PANEL_SERVICE, NGINX_SERVICE])
            # Allow nginx's reload to finish before the first TLS connect.
            for attempt in range(20):
                try:
                    final_tls_probe(state)
                    break
                except (OSError, NodeError):
                    if attempt == 19:
                        raise
                    time.sleep(0.5)
            ensure_private_listeners()
            verify_running_nginx_openssl(state)
            write_file(ACCESS, make_saved_access_text(state))
            state["status"] = "ready"
            state["stage"] = "complete"
            save_state(state)
            log(f"Ready. Panel credentials, VLESS link and QR status: {ACCESS}")
            log(f"Website: https://{state['domain']}/")
            if panel_settings(state)[0] == "https":
                log("HTTPS panel enabled. Open the Public panel URL in the access file; no SSH tunnel is needed.")
            else:
                log("Panel access is SSH-only. The access file includes the command to enable HTTPS browser access.")
                log(f"Open a local SSH tunnel: ssh -N -L 127.0.0.1:2053:127.0.0.1:{state['panel_port']} root@{state['bind_ip']}")
        except BaseException as exc:
            state["status"] = "failed"
            state["last_error_type"] = type(exc).__name__
            # Stop only our services. Preserve diagnostics/DB/certificates.
            cleanup_errors = []
            for unit in (NGINX_SERVICE, PANEL_SERVICE):
                try:
                    command(["systemctl", "disable", "--now", unit], check=False)
                    activity = command(["systemctl", "is-active", unit], check=False).stdout.strip()
                    if activity not in ("inactive", "failed", "unknown"):
                        cleanup_errors.append(unit + " stop could not be verified (" + (activity or "empty status") + ")")
                except Exception as cleanup_error:
                    cleanup_errors.append(unit + ": " + type(cleanup_error).__name__)
            try:
                finish_mask(state)
            except Exception as cleanup_error:
                cleanup_errors.append("stock nginx: " + type(cleanup_error).__name__)
            try:
                stop_certbot_timer(state)
            except Exception as cleanup_error:
                cleanup_errors.append("Certbot timer: " + type(cleanup_error).__name__)
            try:
                restore_stock_certbot_timer(state)
            except Exception as cleanup_error:
                cleanup_errors.append("Stock Certbot timer: " + type(cleanup_error).__name__)
            state["cleanup_errors"] = cleanup_errors
            try:
                save_state(state)
            except Exception as cleanup_error:
                log("Could not persist failure state: " + type(cleanup_error).__name__)
            if cleanup_errors:
                log("Cleanup needs attention: " + "; ".join(cleanup_errors))
            log(f"Installation stopped at {state['stage']}. Private diagnostics were preserved in {ETC}.")
            log("Use status for details. To reset: uninstall --confirm-domain " + state["domain"])
            if shutil.which("nginx"):
                log("nginx files remain. After correcting the cause and uninstalling this attempt, retry with --reuse-stock-nginx.")
            else:
                log("After correcting the cause, uninstall this failed attempt, then retry installation.")
            raise


def status():
    if os.geteuid() != 0:
        raise NodeError("Use sudo to read private installation status.")
    state = runtime_state(load_state())
    public = {key: state[key] for key in ("domain", "bind_ip", "transport", "status", "stage", "release_version")}
    panel_mode, panel_allow = panel_settings(state)
    public["panel_access"] = panel_mode
    public["panel_allow"] = panel_allow
    if state.get("site_profile") is not None:
        public["website"] = {key: state["site_profile"][key] for key in ("title", "theme", "version")}
    print(json.dumps(public, indent=2, ensure_ascii=False))
    timer = CERTBOT_TIMER if state.get("certbot_backend") == "managed-venv" else "certbot.timer"
    for unit in (PANEL_SERVICE, NGINX_SERVICE, timer):
        active = command(["systemctl", "is-active", unit], check=False).stdout.strip()
        log(unit + ": " + active)
    if state["status"] == "ready":
        ensure_private_listeners()
        verify_panel_database(state)
        final_tls_probe(state)
        if state.get("nginx_openssl") == "managed":
            verify_running_nginx_openssl(state)
        log("Private listeners, panel settings and HTTPS: PASS")


def uninstall(args):
    if os.geteuid() != 0:
        raise NodeError("Uninstall requires root.")
    state = runtime_state(load_state())
    if args.confirm_domain != state["domain"]:
        raise NodeError("Uninstall deletes the managed DB/site/credentials. Pass --confirm-domain with the exact installed domain.")
    # No path from state is used for deletion. All targets are fixed above.
    certbot_units = {UNIT_DIR / CERTBOT_TIMER, UNIT_DIR / CERTBOT_SERVICE}
    owned = [path for path in OWNED_PATHS if path not in certbot_units or state.get("certbot_backend") == "managed-venv"]
    for path in owned:
        if path.is_symlink():
            raise NodeError(f"A managed path was replaced by a symlink; inspect it manually: {path}")
    record = command(["getent", "passwd", USER], check=False)
    if state.get("system_user_created") and record.returncode == 0:
        fields = record.stdout.strip().split(":")
        if (len(fields) != 7 or fields[5] != str(DATA) or fields[6] != "/usr/sbin/nologin"
                or int(fields[2]) != state.get("service_uid") or int(fields[3]) != state.get("service_gid")):
            raise NodeError("The service account was changed; uninstall stopped before deleting files.")
    for unit in (NGINX_SERVICE, PANEL_SERVICE):
        command(["systemctl", "disable", "--now", unit], check=False)
        if command(["systemctl", "is-active", unit], check=False).stdout.strip() not in ("inactive", "failed", "unknown"):
            raise NodeError("A managed service stop could not be verified; no data was deleted.")
    finish_mask(state)
    stop_certbot_timer(state)
    if not args.keep_certificate and state.get("certificate_issued"):
        name = state.get("cert_name", "")
        if not re.fullmatch(r"https-node-[0-9a-f]{16}", name):
            raise NodeError("Unexpected managed certificate name.")
        cfg = Path("/etc/letsencrypt/renewal") / (name + ".conf")
        if cfg.exists():
            command([certbot_command(state), "delete", "--non-interactive", "--cert-name", name])
        elif any((Path("/etc/letsencrypt") / path / name).exists() for path in ("live", "archive")):
            raise NodeError("Unmanaged certificate files remain without a renewal record.")
    # Keep the state until the other deletions and account cleanup succeed.
    for path in (p for p in owned if p != ETC):
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()
    if state.get("system_user_created"):
        if record.returncode == 0:
            command(["userdel", USER])
        group = command(["getent", "group", USER], check=False)
        if group.returncode == 0:
            fields = group.stdout.strip().split(":")
            if len(fields) != 4 or int(fields[2]) != state.get("service_gid") or fields[3]:
                raise NodeError("The service group was changed; it was not removed.")
            command(["groupdel", USER])
    command(["systemctl", "daemon-reload"])
    restore_stock_certbot_timer(state)
    shutil.rmtree(ETC)
    log("Managed services, site, database and credentials removed. Installed apt packages remain.")
    if state.get("certificate_issued") and args.keep_certificate:
        log("The certificate was kept: " + state["cert_name"] + ". Its renewal needs a working webroot; fresh install preflight will reject it.")
    if shutil.which("nginx"):
        log("nginx files remain. To install again, add --reuse-stock-nginx; its stock service must be stopped and disabled.")
    elif Path("/etc/nginx/nginx.conf").exists():
        log("Review the residual nginx configuration before retrying installation.")
    else:
        log("No nginx files remain; the normal fresh-install command can be used again.")


def main(argv=None):
    parser = argparse.ArgumentParser(description="HTTPS Node: pinned private 3x-ui + VLESS + nginx TLS, for a fresh VPS.")
    parser.add_argument("--version", action="version", version=APP_VERSION)
    sub = parser.add_subparsers(dest="operation", required=True)
    check_parser = sub.add_parser("check", help="Read-only fresh-VPS preflight; run with sudo.")
    check_parser.add_argument("--domain", required=True)
    check_parser.add_argument("--bind-ip")
    check_parser.add_argument("--reuse-stock-nginx", action="store_true")
    install_parser = sub.add_parser("install", help="Strict fresh installation with the approved local dependency archive.")
    install_parser.add_argument("--domain", required=True)
    install_parser.add_argument("--bind-ip")
    registration = install_parser.add_mutually_exclusive_group(required=True)
    registration.add_argument("--email", help="Email associated with the ACME account.")
    registration.add_argument("--acme-no-email", action="store_true", help="Explicitly register the ACME account without email (useful for a test VPS).")
    install_parser.add_argument("--agree-tos", action="store_true")
    install_parser.add_argument("--disable-apt-backports", action="store_true",
                                help="Back up APT sources and disable only resolute-backports on Ubuntu 26.04.")
    install_parser.add_argument("--transport", choices=("xhttp", "ws"), default="xhttp")
    install_parser.add_argument("--panel-access", choices=("ssh", "https"), default="ssh",
                                help="Panel access: SSH tunnel only (default), or HTTPS at its secret path plus SSH.")
    install_parser.add_argument("--panel-allow", action="append", metavar="IP/CIDR",
                                help="Allowed source IP/CIDR for the HTTPS panel only; repeatable. Without this option, HTTPS mode allows any IP with normal panel authentication. Invalid with SSH mode.")
    install_parser.add_argument("--site-title", help="Optional generated-site title override; a fresh title is chosen by default.")
    install_parser.add_argument("--site-description", help="Optional generated-site description override.")
    install_parser.add_argument("--site-theme", choices=("auto", *SITE_THEMES), default="auto", help="Generated site subject; default: choose for this installation.")
    install_parser.add_argument("--site-dir", help="Use your static site instead of generating one; index.html required, no symlinks or hidden files.")
    install_parser.add_argument("--release-archive", help="Use a pre-downloaded release tar.gz; the same embedded SHA-256 is required.")
    install_parser.add_argument("--reuse-stock-nginx", action="store_true", help="Reuse an installed, stopped, disabled nginx package after removing our prior attempt.")
    preview_parser = sub.add_parser("preview-site", help="Generate a local site preview without root, network or installing services.")
    preview_parser.add_argument("--domain", required=True, help="Domain used in canonical URLs; no DNS lookup.")
    preview_parser.add_argument("--output", required=True, help="New directory for site/ and a private site-profile.json; must not exist.")
    preview_parser.add_argument("--site-theme", choices=("auto", *SITE_THEMES), default="auto")
    preview_parser.add_argument("--site-title")
    preview_parser.add_argument("--site-description")
    preview_parser.add_argument("--site-seed", help="Optional 64-character lowercase hexadecimal seed for a reproducible preview.")
    sub.add_parser("status", help="Inspect only the managed installation.")
    sub.add_parser("security-check", help="Read-only JSON report against the bundled dated policy; exit 2 for findings or unknown coverage.")
    update_parser = sub.add_parser("update-nginx", help="Update only distro nginx on a ready node, preserving the site and credentials.")
    update_parser.add_argument("--confirm-domain", required=True, help="Exact domain of the existing ready/complete installation.")
    panel_parser = sub.add_parser("panel-access", help="Change HTTPS panel access on a ready node without reinstalling or changing its account/site.")
    panel_parser.add_argument("--mode", choices=("ssh", "https"), required=True,
                              help="SSH tunnel only, or HTTPS at the existing secret panel path plus SSH.")
    panel_parser.add_argument("--allow", action="append", metavar="IP/CIDR",
                              help="Replace the HTTPS panel allowlist; repeatable. Omit to allow any IP with normal panel authentication. Invalid with SSH mode.")
    panel_parser.add_argument("--confirm-domain", required=True, help="Exact domain of the existing ready/complete installation.")
    credentials_parser = sub.add_parser("credentials", help="Print the root-only saved panel credentials and VLESS link.")
    credentials_parser.add_argument("--qr", action="store_true", help="Also display one plain-text VLESS QR code; read-only unless --refresh-file is used.")
    credentials_parser.add_argument("--refresh-file", action="store_true", help="Regenerate the private access file with QR, preserving all accounts/settings; print only its path unless --qr is also used.")
    remove_parser = sub.add_parser("uninstall", help="Delete only this installation's services, DB, website and credentials.")
    remove_parser.add_argument("--confirm-domain", required=True)
    remove_parser.add_argument("--keep-certificate", action="store_true", help="Keep the issued certificate; this intentionally prevents a fresh install until it is removed.")
    args = parser.parse_args(argv)
    if args.operation == "check":
        facts = preflight(args.domain, args.bind_ip, reuse_stock_nginx=args.reuse_stock_nginx)
        print(json.dumps(facts, indent=2))
        log("Preflight PASS. Public DNS verified. External ACME reachability is verified during installation.")
    elif args.operation == "install":
        install(args)
    elif args.operation == "preview-site":
        preview_site(args)
    elif args.operation == "status":
        status()
    elif args.operation == "security-check":
        code = security_check()
        if code:
            raise SystemExit(code)
    elif args.operation == "update-nginx":
        update_nginx(args)
    elif args.operation == "panel-access":
        panel_access(args)
    elif args.operation == "credentials":
        credentials(args)
    elif args.operation == "uninstall":
        uninstall(args)


if __name__ == "__main__":
    try:
        main()
    except (NodeError, ValueError, OSError) as error:
        print("ERROR: " + str(error), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("Interrupted.", file=sys.stderr)
        sys.exit(130)

