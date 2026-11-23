#!/usr/bin/env python3
"""HTTPS Node: an isolated, pinned 3x-ui/Xray + nginx installer.

Copyright (c) 2026. MIT licensed. The upstream programs retain their licenses.
The offline release targets fresh Ubuntu 26.04 amd64 with one IPv4 address
and one DNS name pointing directly at it.
"""

from __future__ import annotations

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

from rendering import SITE_THEMES, generate_site_profile, normalize_panel_access, render_generated_site, render_nginx, render_site, validate_domain, validate_ipv4
from security_policy import SECURITY_APPROVED_BUNDLE, SECURITY_CERTBOT_MANIFEST_SHA256, evaluate_packages, evaluate_pinned_release, verify_policy_freshness
from certbot_runtime import CERTBOT_LIBRARIES, install_certbot_runtime, verify_certbot_payload

APP_VERSION = "0.3.0-rc4"
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


def validate_apt_source_record(fields, info):
    """Require explicit official signing-key binding for each enabled source."""
    if fields.get("enabled", "yes").lower() == "no":
        return
    distro = info.get("ID")
    expected_keyring = {"ubuntu": "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
                        "debian": "/usr/share/keyrings/debian-archive-keyring.gpg"}.get(distro)
    codename = {("ubuntu", "24.04"): "noble", ("ubuntu", "26.04"): "resolute",
                ("debian", "12"): "bookworm", ("debian", "13"): "trixie"}.get(
                    (distro, info.get("VERSION_ID")))
    if not codename or fields.get("signed-by") != expected_keyring:
        raise NodeError("APT sources need an explicit Signed-By binding to the distro archive keyring.")
    if not fields.get("uris") or any(not approved_archive_uri(uri, info) for uri in fields["uris"].split()):
        raise NodeError("This limited update accepts only distro-operated archive URIs; custom mirrors/PPA need separate review.")
    if not fields.get("suites") or any(suite not in {codename, codename + "-security", codename + "-updates"}
                                       for suite in fields["suites"].split()):
        raise NodeError("APT source suite is outside the reviewed release/security/updates pockets.")
    for name in ("trusted", "allow-insecure", "allow-weak", "allow-downgrade-to-insecure"):
        if fields.get(name, "no").lower() not in {"no", "false", "0"}:
            raise NodeError("APT source weakens archive verification: " + name)
    if fields.get("check-valid-until", "yes").lower() not in {"yes", "true", "1"}:
        raise NodeError("APT source disables index expiry checks.")


def verify_apt_trust(info):
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
    paths = [Path("/etc/apt/sources.list"), *sorted(Path("/etc/apt/sources.list.d").glob("*.list")),
             *sorted(Path("/etc/apt/sources.list.d").glob("*.sources"))]
    count = 0
    for path in paths:
        if not path.exists():
            continue
        if path.is_symlink() or not path.is_file() or path.stat().st_uid != 0 or path.stat().st_mode & 0o022:
            raise NodeError("APT source files must be root-owned regular files without group/world write access.")
        data = path.read_text(encoding="utf-8")
        if path.suffix == ".sources":
            for paragraph in re.split(r"\n\s*\n", data):
                fields, last_key = {}, None
                for line in paragraph.splitlines():
                    if not line.strip() or line.lstrip().startswith("#"):
                        continue
                    if line[:1].isspace() and last_key:
                        fields[last_key] += " " + line.strip()
                    elif ":" in line:
                        key, value = line.split(":", 1)
                        last_key = key.lower()
                        fields[last_key] = value.strip()
                    else:
                        raise NodeError("Malformed deb822 APT source file.")
                if not fields or fields.get("enabled", "yes").lower() == "no":
                    continue
                if not fields.get("types") or any(kind not in {"deb", "deb-src"} for kind in fields["types"].split()):
                    raise NodeError("Unrecognized APT source Types field.")
                validate_apt_source_record(fields, info)
                count += 1
        else:
            for line in data.splitlines():
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                match = re.fullmatch(r"deb(?:-src)?\s+(?:\[([^]]*)\]\s+)?(\S+)\s+(\S+)(?:\s+.*)?", line)
                if not match:
                    raise NodeError("Unrecognized APT source line.")
                options = dict(item.split("=", 1) for item in (match.group(1) or "").split() if "=" in item)
                validate_apt_source_record({**options, "uris": match.group(2), "suites": match.group(3)}, info)
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


def preflight(domain, bind_ip=None, *, installing=False, reuse_stock_nginx=False):
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


def make_access_text(state):
    panel_mode, panel_allow = panel_settings(state)
    panel_summary = "Panel access: SSH tunnel only.\n"
    if panel_mode == "https":
        panel_summary = (f"Panel access: HTTPS and SSH tunnel.\n"
                         f"Public panel: https://{state['domain']}{state['panel_path']}\n"
                         "HTTPS panel allowed source IPs: " + (", ".join(panel_allow) if panel_allow else
                         "any IP (normal panel authentication is required)") + "\n")
    routing_summary = ("Panel is not routed through public nginx. Subscription service is disabled.\n"
                       if panel_mode == "ssh" else
                       "Only the secret panel URL is proxied to loopback. Subscription service is disabled.\n"
                       "Source-IP restrictions apply only to that HTTPS panel URL; website and VLESS remain public.\n")
    return (
        f"HTTPS Node {APP_VERSION}\nDomain: {state['domain']}\nTransport: VLESS + {state['transport']} + TLS\n"
        f"Website: https://{state['domain']}/\n" + panel_summary + "\n"
        f"SSH tunnel (replace root/SSH port if needed):\n"
        f"ssh -N -L 127.0.0.1:2053:127.0.0.1:{state['panel_port']} root@{state['bind_ip']}\n"
        f"Panel in YOUR local browser: http://127.0.0.1:2053{state['panel_path']}\n"
        f"Username: {state['username']}\nPassword: {state['password']}\n\n"
        f"VLESS link:\n{client_link(state)}\n\n"
        + routing_summary +
        "Proxy connections to private/local IP ranges are blocked; system firewall is unchanged.\n"
        "Panel/transport versions are pinned at installation; inspect future updates explicitly.\n"
    )


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
            ACCESS: make_access_text(updated).encode("utf-8"),
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
    facts = preflight(args.domain, args.bind_ip, installing=True, reuse_stock_nginx=args.reuse_stock_nginx)
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
            write_file(ACCESS, make_access_text(state))
            state["status"] = "ready"
            state["stage"] = "complete"
            save_state(state)
            log(f"Ready. Credentials and the VLESS link: {ACCESS}")
            log(f"Website: https://{state['domain']}/")
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
            log("After correcting the cause, install again with --reuse-stock-nginx (the inactive apt package remains).")
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
    log("To install again, add --reuse-stock-nginx. Existing active nginx services are always refused.")


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
    credentials_parser.add_argument("--qr", action="store_true", help="Also display the VLESS QR code.")
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
        if os.geteuid() != 0:
            raise NodeError("Use sudo to read credentials.")
        state = load_state()
        if state["status"] != "ready":
            raise NodeError("Installation is not ready; inspect status.")
        print(make_access_text(state))
        if args.qr:
            subprocess.run(["qrencode", "-t", "ANSIUTF8", "-m", "2", client_link(state)], check=True)
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

