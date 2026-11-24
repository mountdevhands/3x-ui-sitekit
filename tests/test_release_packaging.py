"""Bounded release packaging checks using tiny local fixtures; no network or VPS."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock
import zipfile


PROJECT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sitekit_package_release", PROJECT / "tools/package_release.py")
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)


class ReleasePackagingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="sitekit-package-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = self.base / "repository"
        self.source.mkdir()
        self.runtime = self.base / "runtime.tar.gz"
        self.runtime.write_bytes(b"approved synthetic runtime, never extracted or executed")
        self.runtime_sha = PACKAGE.digest(self.runtime)
        self.archive_root = self.base / "dependency-sources"
        archive = self.archive_root / "dependencies/example.source.tar.gz"
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b"synthetic source archive")
        self.files = {
            ".gitignore": "__pycache__/\n",
            "src/installer_core.py": 'APP_VERSION = "0.3.0-rc5"\n',
            "src/security_policy.py": f'SECURITY_APPROVED_BUNDLE = ("approved-runtime-rc4", "{self.runtime_sha}")\n',
            "dependencies/SOURCE-ARCHIVES.sha256": f"{PACKAGE.digest(archive)}  dependencies/example.source.tar.gz\n",
            "build.py": (
                "from pathlib import Path\n"
                "Path('dist/https-node.py').write_text('#!/usr/bin/env python3\\nprint(42)\\n')\n"
                "Path('dist/https-node.py').chmod(0o755)\n"
            ),
            "dist/https-node.py": "old standalone\n",
            "install.sh": (
                "#!/usr/bin/env bash\nset -euo pipefail\nTAG=v0.3.0-rc4\n"
                "INSTALLER=3x-ui-sitekit-0.3.0-rc4.py\n"
                "RUNTIME=3x-ui-sitekit-0.3.0-rc4-linux-amd64.tar.gz\n"
                f"INSTALLER_SHA256={'0' * 64}\nRUNTIME_SHA256={'0' * 64}\n"
            ),
            "setup.sh": (
                "#!/usr/bin/env bash\nreadonly SITEKIT_SETUP_TAG='v0.3.0-rc4'\n"
                f"readonly SITEKIT_SETUP_BOOTSTRAP_SHA256='{'0' * 64}'\n"
            ),
            "README.md": (
                "# SiteKit\n"
                "<!-- sitekit-release-sha256: installer -->\n"
                "Installer: SITEKIT_RC5_INSTALLER_SHA256_FINAL\n"
                "<!-- /sitekit-release-sha256 -->\n"
                "<!-- sitekit-release-sha256: bootstrap -->\n"
                "Bootstrap: SITEKIT_RC5_BOOTSTRAP_SHA256_FINAL\n"
                "<!-- /sitekit-release-sha256 -->\n"
                "<!-- sitekit-release-sha256: setup -->\n"
                "Wizard: SITEKIT_RC5_SETUP_SHA256_FINAL\n"
                "<!-- /sitekit-release-sha256 -->\n"
            ),
            "SHA256SUMS.txt": "previous manifest\n",
        }
        for name, text in self.files.items():
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            if name.endswith(".sh"):
                path.chmod(0o755)
        subprocess.run(["git", "init", "-q", str(self.source)], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.source), "add", "."], check=True, capture_output=True)
        subprocess.run(["git", "-C", str(self.source), "-c", "user.name=Packaging fixture",
                        "-c", "user.email=fixture@example.invalid", "commit", "-qm", "fixture"],
                       check=True, capture_output=True)

    def package(self, name="release", **kwargs):
        output = self.base / name
        PACKAGE.package_release(self.source, self.runtime, output,
                                source_archives_dir=self.archive_root, **kwargs)
        return output

    def assert_source_unchanged(self):
        for name, text in self.files.items():
            self.assertEqual((self.source / name).read_text(), text, name)

    def test_release_chain_complete_sources_and_repeatability(self):
        one, two = self.package("one"), self.package("two")
        first = {p.name: PACKAGE.digest(p) for p in one.iterdir()}
        second = {p.name: PACKAGE.digest(p) for p in two.iterdir()}
        self.assertEqual(first, second)
        self.assertEqual(len(first), 7)
        self.assertEqual((one / "3x-ui-sitekit-0.3.0-rc5-linux-amd64.tar.gz").read_bytes(), self.runtime.read_bytes())
        self.assertIn("TAG='v0.3.0-rc5'", (one / "install.sh").read_text())
        self.assertIn(PACKAGE.digest(one / "3x-ui-sitekit-0.3.0-rc5.py"), (one / "install.sh").read_text())
        self.assertIn(self.runtime_sha, (one / "install.sh").read_text())
        self.assertIn(PACKAGE.digest(one / "install.sh"), (one / "setup.sh").read_text())
        for line in (one / "SHA256SUMS").read_text().splitlines():
            expected, name = line.split("  ", 1)
            self.assertEqual(PACKAGE.digest(one / name), expected, name)
        with zipfile.ZipFile(one / "3x-ui-sitekit-0.3.0-rc5-source.zip") as archive:
            prefix = "3x-ui-sitekit-0.3.0-rc5/"
            self.assertIn(prefix + "dependencies/example.source.tar.gz", archive.namelist())
            self.assertNotIn(".git", archive.namelist())
            readme = archive.read(prefix + "README.md").decode()
            self.assertNotIn("_FINAL", readme)
            self.assertIn(PACKAGE.digest(one / "setup.sh"), readme)
            for line in archive.read(prefix + "SHA256SUMS.txt").decode().splitlines():
                expected, name = line.split("  ", 1)
                self.assertEqual(hashlib.sha256(archive.read(prefix + name)).hexdigest(), expected, name)
        self.assert_source_unchanged()

    def test_sync_source_updates_only_generated_files_and_rendered_docs(self):
        output = self.package(sync_source=True)
        self.assertEqual((self.source / "setup.sh").read_bytes(), (output / "setup.sh").read_bytes())
        self.assertEqual((self.source / "install.sh").read_bytes(), (output / "install.sh").read_bytes())
        self.assertNotIn("_FINAL", (self.source / "README.md").read_text())
        self.assertEqual((self.source / "src/security_policy.py").read_text(), self.files["src/security_policy.py"])
        self.assertEqual((self.source / "src/installer_core.py").read_text(), self.files["src/installer_core.py"])
        for line in (self.source / "SHA256SUMS.txt").read_text().splitlines():
            expected, name = line.split("  ", 1)
            self.assertEqual(PACKAGE.digest(self.source / name), expected, name)

    def test_resync_after_code_changes_refreshes_published_documentation_hashes(self):
        original = self.package("original", sync_source=True)
        first_hashes = {name: PACKAGE.digest(original / name)
                        for name in ("setup.sh", "install.sh", "3x-ui-sitekit-0.3.0-rc5.py")}
        setup = self.source / "setup.sh"
        setup.write_text(setup.read_text() + "# Additional reviewed wizard change.\n")
        build = self.source / "build.py"
        build.write_text(build.read_text().replace("print(42)", "print(43)"))
        updated = self.package("updated", sync_source=True)
        readme = (self.source / "README.md").read_text()
        for name, previous in first_hashes.items():
            actual = PACKAGE.digest(updated / name)
            self.assertNotEqual(actual, previous, name)
            self.assertIn(actual, readme, name)
            self.assertNotIn(previous, readme, name)
        self.assertEqual(readme.count("<!-- sitekit-release-sha256:"), 3)
        repeat = self.package("repeat")
        self.assertEqual({p.name: PACKAGE.digest(p) for p in updated.iterdir()},
                         {p.name: PACKAGE.digest(p) for p in repeat.iterdir()})

    def test_unmanaged_or_ambiguous_documentation_pins_fail_closed(self):
        hashes = {"setup": "1" * 64, "installer": "2" * 64, "bootstrap": "3" * 64}
        cases = (
            "SITEKIT_RC5_SETUP_SHA256_FINAL\n",
            "<!-- sitekit-release-sha256: setup -->\n" + "0" * 64 + "\n",
            "<!-- sitekit-release-sha256: setup -->\n" + "0" * 64 + " " + "a" * 64
            + "\n<!-- /sitekit-release-sha256 -->\n",
            "<!-- sitekit-release-sha256: setup -->\nSITEKIT_RC5_INSTALLER_SHA256_FINAL\n"
            "<!-- /sitekit-release-sha256 -->\n",
        )
        for text in cases:
            with self.subTest(text=text), self.assertRaises(PACKAGE.PackageError):
                PACKAGE.render_placeholders(text, hashes)

    def test_missing_or_tampered_inputs_leave_no_output(self):
        self.runtime.write_bytes(b"wrong runtime")
        with self.assertRaisesRegex(PACKAGE.PackageError, "Runtime"):
            self.package(sync_source=True)
        self.assertFalse((self.base / "release").exists())
        self.assert_source_unchanged()
        self.runtime.write_bytes(b"approved synthetic runtime, never extracted or executed")
        archive = self.archive_root / "dependencies/example.source.tar.gz"
        archive.write_bytes(b"wrong source")
        with self.assertRaisesRegex(PACKAGE.PackageError, "source SHA-256"):
            self.package(sync_source=True)
        archive.unlink()
        with self.assertRaisesRegex(PACKAGE.PackageError, "missing"):
            self.package(sync_source=True)
        self.assertFalse((self.base / "release").exists())
        self.assert_source_unchanged()

    def test_existing_output_is_never_replaced(self):
        output = self.base / "release"
        output.mkdir()
        (output / "keep").write_text("existing artifact")
        with self.assertRaisesRegex(PACKAGE.PackageError, "already exists"):
            self.package(sync_source=True)
        self.assertEqual((output / "keep").read_text(), "existing artifact")
        self.assert_source_unchanged()

    def test_development_version_or_unsafe_input_is_rejected(self):
        core = self.source / "src/installer_core.py"
        core.write_text('APP_VERSION = "0.3.0-rc5-dev"\n')
        with self.assertRaisesRegex(PACKAGE.PackageError, "without -dev"):
            self.package()
        core.write_text(self.files["src/installer_core.py"])
        archive = self.archive_root / "dependencies/example.source.tar.gz"
        archive.unlink()
        archive.symlink_to(self.runtime)
        with self.assertRaisesRegex(PACKAGE.PackageError, "Symlink"):
            self.package()
        self.assertFalse((self.base / "release").exists())

    def test_repository_only_mode_is_explicitly_disclosed(self):
        output = self.base / "repository-only"
        PACKAGE.package_release(self.source, self.runtime, output, repository_source_only=True)
        self.assertIn("NOT included", (output / "RELEASE-NOTES.md").read_text())
        with zipfile.ZipFile(output / "3x-ui-sitekit-0.3.0-rc5-source.zip") as archive:
            self.assertFalse(any(name.endswith("example.source.tar.gz") for name in archive.namelist()))

    def test_normal_sync_error_rolls_back_prior_replacements(self):
        real_write = PACKAGE.atomic_write
        calls = 0
        def fail_once(path, content, mode):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError("synthetic source sync failure")
            return real_write(path, content, mode)
        with mock.patch.object(PACKAGE, "atomic_write", side_effect=fail_once):
            with self.assertRaisesRegex(OSError, "synthetic"):
                self.package(sync_source=True)
        self.assertFalse((self.base / "release").exists())
        self.assert_source_unchanged()


if __name__ == "__main__":
    unittest.main()
