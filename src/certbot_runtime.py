"""Install the verified offline Certbot runtime from an approved release archive."""

from __future__ import annotations

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
