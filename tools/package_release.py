#!/usr/bin/env python3
"""Prepare a deterministic, hash-pinned SiteKit release without network access.

The working checkout is read-only unless --sync-source is supplied. The complete
release is assembled in a private staging directory and published locally only
after all inputs and generated files pass verification. An existing output
directory is never replaced. This command does not create Git tags or releases.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile


class PackageError(ValueError):
    """A release input or generated artifact failed verification."""


GENERATED_FILES = ("dist/https-node.py", "install.sh", "setup.sh", "SHA256SUMS.txt")
PLACEHOLDERS = {
    "SITEKIT_RC5_INSTALLER_SHA256_FINAL": "installer",
    "SITEKIT_RC5_BOOTSTRAP_SHA256_FINAL": "bootstrap",
    "SITEKIT_RC5_SETUP_SHA256_FINAL": "setup",
}


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def relative_path(value: str) -> str:
    path = PurePosixPath(value)
    if (not value or path.is_absolute() or ".." in path.parts or "." in path.parts
            or "\\" in value or any(ord(char) < 32 for char in value)
            or path.as_posix() != value or path.parts[0] == ".git"):
        raise PackageError(f"Unsafe source path: {value!r}")
    return value


def source_file(root: Path, relative: str) -> Path:
    relative_path(relative)
    path = root / relative
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        if current.is_symlink():
            raise PackageError(f"Symlink inputs are not supported: {relative}")
    if not path.is_file():
        raise PackageError(f"Required source file is missing: {path}")
    return path


def assignment(path: Path, name: str):
    matches = [node.value for node in ast.parse(path.read_text(encoding="utf-8")).body
               if isinstance(node, ast.Assign) and len(node.targets) == 1
               and isinstance(node.targets[0], ast.Name) and node.targets[0].id == name]
    if len(matches) != 1:
        raise PackageError(f"Expected exactly one literal {name} in {path.name}")
    try:
        return ast.literal_eval(matches[0])
    except (ValueError, TypeError) as exc:
        raise PackageError(f"{name} must be a literal") from exc


def repository_files(root: Path) -> list[str]:
    result = subprocess.run(
        ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
        check=True, capture_output=True, timeout=15,
    )
    names = sorted({relative_path(name.decode("utf-8"))
                    for name in result.stdout.split(b"\0") if name})
    for name in names:
        source_file(root, name)
    return names


def read_archive_manifest(path: Path) -> dict[str, str]:
    entries = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if not match:
            raise PackageError("Malformed dependencies/SOURCE-ARCHIVES.sha256")
        expected, name = match.groups()
        relative_path(name)
        if not name.startswith("dependencies/") or not name.endswith(".tar.gz") or name in entries:
            raise PackageError(f"Unexpected or duplicate dependency archive: {name}")
        entries[name] = expected
    if not entries:
        raise PackageError("The dependency source archive manifest is empty")
    return entries


def replace_assignment(text: str, name: str, value: str, *, readonly: bool = False) -> str:
    prefix = "readonly " if readonly else ""
    pattern = re.compile(r"^" + re.escape(prefix + name) + r"=[^\n]*$", re.MULTILINE)
    if len(pattern.findall(text)) != 1:
        raise PackageError(f"Expected exactly one shell assignment for {name}")
    if not re.fullmatch(r"[A-Za-z0-9._/-]+", value):
        raise PackageError(f"Unsafe generated shell value for {name}")
    return pattern.sub(lambda _: f"{prefix}{name}='{value}'", text)


def render_placeholders(text: str, hashes: dict[str, str]) -> str:
    """Refresh marked Markdown pins, including documents already synchronized.

    Keep both marker comments outside a code fence so copied commands contain
    only shell code. A block owns exactly one digest and survives rendering:
      <!-- sitekit-release-sha256: setup -->
      ... one setup placeholder or previously rendered SHA-256 ...
      <!-- /sitekit-release-sha256 -->
    Historical, unmarked hashes are deliberately left unchanged.
    """
    start = re.compile(r"<!-- sitekit-release-sha256: (installer|bootstrap|setup) -->")
    end = "<!-- /sitekit-release-sha256 -->"
    token = re.compile(r"SITEKIT_RC5_(?:INSTALLER|BOOTSTRAP|SETUP)_SHA256_FINAL"
                       r"|(?<![A-Za-z0-9])[0-9a-f]{64}(?![A-Za-z0-9])")
    result, body = [], []
    active = None
    for line in text.splitlines(keepends=True):
        stripped = line.strip()
        opening = start.fullmatch(stripped)
        if opening:
            if active is not None:
                raise PackageError("Nested release SHA-256 markers are not allowed")
            active = opening.group(1)
            result.append(line)
            body = []
        elif stripped == end:
            if active is None:
                raise PackageError("Release SHA-256 closing marker has no opening marker")
            block = "".join(body)
            matches = list(token.finditer(block))
            if len(matches) != 1:
                raise PackageError(f"The {active} release SHA-256 block must contain exactly one digest")
            previous = matches[0].group()
            if previous in PLACEHOLDERS and PLACEHOLDERS[previous] != active:
                raise PackageError(f"The {active} release SHA-256 block contains a different placeholder")
            result.append(token.sub(lambda _: hashes[active], block))
            result.append(line)
            active = None
        elif "sitekit-release-sha256" in line:
            raise PackageError("Malformed or unknown release SHA-256 marker")
        elif active is not None:
            body.append(line)
        else:
            result.append(line)
    if active is not None:
        raise PackageError("Unclosed release SHA-256 marker")
    rendered = "".join(result)
    if re.search(r"SITEKIT_RC5_[A-Z0-9_]+_FINAL", rendered):
        raise PackageError("A release hash placeholder is outside its managed Markdown block")
    return rendered


def write_source_manifest(root: Path, names: list[str]) -> None:
    lines = [f"{digest(root / name)}  {name}\n"
             for name in sorted(set(names)) if name != "SHA256SUMS.txt"]
    (root / "SHA256SUMS.txt").write_text("".join(lines), encoding="utf-8")


def deterministic_zip(root: Path, names: list[str], output: Path, prefix: str) -> None:
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for name in sorted(set(names)):
            path = source_file(root, name)
            info = zipfile.ZipInfo(prefix + "/" + name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            mode = 0o755 if path.stat().st_mode & 0o111 else 0o644
            info.external_attr = (stat.S_IFREG | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            with archive.open(info, "w", force_zip64=True) as target, path.open("rb") as incoming:
                shutil.copyfileobj(incoming, target)


def atomic_write(path: Path, content: bytes, mode: int) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".sitekit-sync-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


class SourceTransaction:
    """Roll back ordinary filesystem errors while synchronizing generated files."""

    def __init__(self, root: Path, staged: Path, originals: dict[str, tuple[bytes, int]], names: list[str]):
        self.root, self.staged, self.originals, self.names = root, staged, originals, names
        self.applied: list[str] = []
        self.committed = False

    def __enter__(self):
        for name in self.names:
            current = source_file(self.root, name)
            if current.read_bytes() != self.originals[name][0]:
                raise PackageError(f"Source changed during packaging; retry after reviewing it: {name}")
        return self

    def apply(self) -> None:
        for name in self.names:
            staged = self.staged / name
            atomic_write(self.root / name, staged.read_bytes(), stat.S_IMODE(staged.stat().st_mode))
            self.applied.append(name)

    def __exit__(self, error_type, error, traceback):
        if not self.committed:
            failures = []
            for name in reversed(self.applied):
                content, mode = self.originals[name]
                try:
                    atomic_write(self.root / name, content, mode)
                except OSError as exc:
                    failures.append(f"{name}: {exc}")
            if failures:
                raise PackageError("Source rollback needs attention: " + "; ".join(failures)) from error
        return False


def package_release(source: Path, runtime: Path, output: Path, *,
                    source_archives_dir: Path | None = None,
                    repository_source_only: bool = False,
                    sync_source: bool = False, notes: Path | None = None) -> dict[str, str]:
    source = source.resolve(strict=True)
    runtime = runtime.absolute()
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise PackageError("Output already exists; choose a new release directory")
    if output.resolve().is_relative_to(source):
        raise PackageError("Keep release output outside the source checkout")
    if bool(source_archives_dir) == repository_source_only:
        raise PackageError("Choose --source-archives-dir or explicitly use --repository-source-only")
    names = repository_files(source)
    for required in (*GENERATED_FILES, "build.py", "src/installer_core.py", "src/security_policy.py",
                     "dependencies/SOURCE-ARCHIVES.sha256"):
        if required not in names:
            raise PackageError(f"Required repository file is not included: {required}")
    version = assignment(source / "src/installer_core.py", "APP_VERSION")
    if not isinstance(version, str) or not re.fullmatch(r"\d+\.\d+\.\d+(?:-rc[1-9]\d*)?", version):
        raise PackageError("APP_VERSION must be a release version without -dev")
    approved = assignment(source / "src/security_policy.py", "SECURITY_APPROVED_BUNDLE")
    if (not isinstance(approved, tuple) or len(approved) != 2 or not all(isinstance(v, str) for v in approved)
            or not re.fullmatch(r"[0-9a-f]{64}", approved[1])):
        raise PackageError("SECURITY_APPROVED_BUNDLE is malformed")
    if runtime.is_symlink() or not runtime.is_file() or digest(runtime) != approved[1]:
        raise PackageError("Runtime is missing or its SHA-256 does not match SECURITY_APPROVED_BUNDLE")
    archives = read_archive_manifest(source / "dependencies/SOURCE-ARCHIVES.sha256")
    archive_inputs = {}
    if source_archives_dir is not None:
        archive_root = source_archives_dir.resolve(strict=True)
        for name, expected in archives.items():
            path = source_file(archive_root, name)
            if digest(path) != expected:
                raise PackageError(f"Dependency source SHA-256 mismatch: {name}")
            archive_inputs[name] = path
    if notes is None:
        candidate = source / "docs" / f"RELEASE-NOTES-{version}.md"
        notes = candidate if candidate.is_file() else None
    elif not notes.is_absolute():
        notes = source / notes
    if notes is not None and (notes.is_symlink() or not notes.is_file()):
        raise PackageError("Release notes file is missing or is a symlink")
    commit = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], check=True,
                            capture_output=True, text=True, timeout=15).stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", commit):
        raise PackageError("Unable to identify source checkout base commit")
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".sitekit-release-", dir=output.parent) as temporary:
        temporary = Path(temporary)
        staged = temporary / "source"
        assets = temporary / "assets"
        staged.mkdir()
        assets.mkdir()
        originals = {}
        for name in names:
            incoming = source_file(source, name)
            contents = incoming.read_bytes()
            mode = 0o755 if incoming.stat().st_mode & 0o111 else 0o644
            originals[name] = (contents, stat.S_IMODE(incoming.stat().st_mode))
            target = staged / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(contents)
            target.chmod(mode)
        for name, incoming in archive_inputs.items():
            target = staged / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(incoming, target)
            target.chmod(0o644)
            if digest(target) != archives[name]:
                raise PackageError(f"Dependency source changed during packaging: {name}")
        built = subprocess.run([sys.executable, "-B", "build.py"], cwd=staged, capture_output=True,
                               text=True, timeout=60)
        if built.returncode:
            raise PackageError("Standalone build failed: " + built.stderr[-2000:])
        installer_name = f"3x-ui-sitekit-{version}.py"
        runtime_name = f"3x-ui-sitekit-{version}-linux-amd64.tar.gz"
        hashes = {"installer": digest(staged / "dist/https-node.py")}
        bootstrap = (staged / "install.sh").read_text(encoding="utf-8")
        for key, value in {"TAG": "v" + version, "INSTALLER": installer_name, "RUNTIME": runtime_name,
                           "INSTALLER_SHA256": hashes["installer"], "RUNTIME_SHA256": approved[1]}.items():
            bootstrap = replace_assignment(bootstrap, key, value)
        (staged / "install.sh").write_text(bootstrap, encoding="utf-8")
        hashes["bootstrap"] = digest(staged / "install.sh")
        setup = (staged / "setup.sh").read_text(encoding="utf-8")
        setup = replace_assignment(setup, "SITEKIT_SETUP_TAG", "v" + version, readonly=True)
        setup = replace_assignment(setup, "SITEKIT_SETUP_BOOTSTRAP_SHA256", hashes["bootstrap"], readonly=True)
        (staged / "setup.sh").write_text(setup, encoding="utf-8")
        hashes["setup"] = digest(staged / "setup.sh")
        for name in ("install.sh", "setup.sh"):
            result = subprocess.run(["bash", "-n", str(staged / name)], capture_output=True,
                                    text=True, timeout=15)
            if result.returncode:
                raise PackageError(f"Generated {name} has invalid shell syntax: " + result.stderr[-1000:])
        changed_docs = []
        for name in names:
            if not name.endswith(".md"):
                continue
            path = staged / name
            before = path.read_text(encoding="utf-8")
            after = render_placeholders(before, hashes)
            if after != before:
                path.write_text(after, encoding="utf-8")
                changed_docs.append(name)
        write_source_manifest(staged, names)
        shutil.copy2(staged / "dist/https-node.py", assets / installer_name)
        shutil.copyfile(runtime, assets / runtime_name)
        if digest(assets / runtime_name) != approved[1]:
            raise PackageError("Runtime changed during packaging")
        for name in ("install.sh", "setup.sh"):
            shutil.copy2(staged / name, assets / name)
        prefix = f"3x-ui-sitekit-{version}"
        source_name = prefix + "-source.zip"
        deterministic_zip(staged, names + list(archive_inputs), assets / source_name, prefix)
        source_description = (
            "Complete repository sources plus every verified archive in dependencies/SOURCE-ARCHIVES.sha256."
            if source_archives_dir is not None else
            "Repository sources only. Dependency source archives are NOT included; this is not a complete dependency source bundle."
        )
        note_text = notes.read_text(encoding="utf-8") if notes else f"# 3x-ui SiteKit {version}\n"
        note_text = render_placeholders(note_text, hashes).rstrip() + (
            "\n\n## Artifact provenance\n\n"
            f"- Source checkout base: `{commit}`. Assets include the supplied working-tree changes.\n"
            f"- Source ZIP: {source_description}\n"
            f"- Runtime identity: `{approved[0]}`; copied byte for byte under the {version} asset name.\n"
            f"- Runtime SHA-256: `{approved[1]}`.\n"
            "- Packaging is offline and does not establish VPS installation, TLS, renewal or reboot acceptance.\n"
        )
        (assets / "RELEASE-NOTES.md").write_text(note_text, encoding="utf-8")
        checksums = {p.name: digest(p) for p in sorted(assets.iterdir())}
        (assets / "SHA256SUMS").write_text(
            "".join(f"{expected}  {name}\n" for name, expected in checksums.items()), encoding="utf-8")
        sync_names = list(GENERATED_FILES) + changed_docs if sync_source else []
        with SourceTransaction(source, staged, originals, sync_names) as transaction:
            transaction.apply()
            if output.exists() or output.is_symlink():
                raise PackageError("Output appeared during packaging; no release was overwritten")
            assets.rename(output)
            transaction.committed = True
    return checksums


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parents[1],
                        help="Git checkout to package (defaults to this project)")
    parser.add_argument("--runtime", type=Path, required=True, help="Existing digest-approved runtime tar.gz")
    sources = parser.add_mutually_exclusive_group(required=True)
    sources.add_argument("--source-archives-dir", type=Path,
                         help="Root containing dependencies/... files from SOURCE-ARCHIVES.sha256")
    sources.add_argument("--repository-source-only", action="store_true",
                         help="Explicitly omit dependency source archives; disclose this in release notes")
    parser.add_argument("--output", type=Path, required=True, help="New release directory outside the checkout")
    parser.add_argument("--notes", type=Path, help="Notes file (defaults to docs/RELEASE-NOTES-VERSION.md if present)")
    parser.add_argument("--sync-source", action="store_true",
                        help="After successful preparation, atomically replace generated files and rendered Markdown")
    args = parser.parse_args(argv)
    try:
        checksums = package_release(args.source, args.runtime, args.output,
                                    source_archives_dir=args.source_archives_dir,
                                    repository_source_only=args.repository_source_only,
                                    sync_source=args.sync_source, notes=args.notes)
    except (PackageError, OSError, subprocess.SubprocessError) as exc:
        print(f"Release packaging failed: {exc}", file=sys.stderr)
        return 2
    print(f"Prepared release directory: {args.output.absolute()}")
    for name, expected in checksums.items():
        print(f"{expected}  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
