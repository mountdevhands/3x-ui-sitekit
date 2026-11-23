"""Ensure reviewed files and the running service's ELF mappings agree."""

import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import installer_core as core


class NginxOpenSSLTests(unittest.TestCase):
    def test_manifest_and_files_are_both_checked(self):
        with tempfile.TemporaryDirectory() as scratch:
            libraries = Path(scratch)
            digests = {}
            for name in core.NGINX_OPENSSL_SHA256:
                raw = name.encode()
                (libraries / name).write_bytes(raw)
                digests[name] = hashlib.sha256(raw).hexdigest()
            manifest = libraries / "SHA256SUMS"
            manifest.write_text("".join(f"{value}  {name}\n" for name, value in sorted(digests.items())))
            with mock.patch.object(core, "NGINX_OPENSSL_SHA256", digests):
                core.verify_nginx_openssl(libraries)
                (libraries / "libssl.so.3").write_text("wrong")
                with self.assertRaises(core.NodeError):
                    core.verify_nginx_openssl(libraries)

    @unittest.skipUnless(sys.platform == "linux", "Requires GNU sha256sum as on the deployment host")
    def test_launcher_stops_when_a_verified_library_disappears_or_changes(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch)
            payload = root / "payload"
            payload.mkdir()
            digests = {}
            for name in core.NGINX_OPENSSL_SHA256:
                body = name.encode()
                (payload / name).write_bytes(body)
                digests[name] = hashlib.sha256(body).hexdigest()
            (payload / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in sorted(digests.items())))
            state = {"nginx_openssl": "managed"}
            with mock.patch.object(core, "OPT", root), mock.patch.object(core, "NGINX_OPENSSL_SHA256", digests):
                core.install_nginx_openssl(payload, state)
                launcher = Path(core.nginx_command(state))
            launcher.write_text(launcher.read_text().replace("exec /usr/sbin/nginx", "exec /bin/true"))
            command = [str(launcher)]
            self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
            library = root / "nginx-openssl/lib/libssl.so.3"
            library.write_bytes(b"unreviewed")
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
            library.unlink()
            self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)

    def test_loader_fallback_and_stale_inode_are_rejected(self):
        with tempfile.TemporaryDirectory() as scratch:
            libs = Path(scratch)
            rows = []
            for name in core.NGINX_OPENSSL_SHA256:
                path = libs / name
                path.touch()
                data = path.stat()
                device = f"{os.major(data.st_dev):x}:{os.minor(data.st_dev):x}"
                rows.append(f"1000-2000 r-xp 00000000 {device} {data.st_ino} {path}")
            core.verify_nginx_openssl_maps("\n".join(rows), libs)
            with self.assertRaises(core.NodeError):
                core.verify_nginx_openssl_maps(rows[0], libs)
            with self.assertRaises(core.NodeError):
                core.verify_nginx_openssl_maps(rows[0] + "\n" + rows[1] + " (deleted)", libs)
            with self.assertRaises(core.NodeError):
                core.verify_nginx_openssl_maps("\n".join(rows).replace(str(libs), "/usr/lib"), libs)
            wrong = rows[1].rsplit(" ", 2)
            with self.assertRaises(core.NodeError):
                core.verify_nginx_openssl_maps(rows[0] + "\n" + f"{wrong[0]} 1 {wrong[2]}", libs)
