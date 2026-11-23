#!/usr/bin/env python3
"""Bounded offline behavioral tests for generated static sites and preview flow.

No installer, package manager, service, browser or public network is used.
Generated files are parsed as HTML/XML/CSS and all references are resolved
against the actual returned file map, including fragments.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import html
from html.parser import HTMLParser
import importlib.util
import inspect
import io
import itertools
import json
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock
import urllib.parse
import xml.etree.ElementTree as ET


PROJECT = Path(__file__).resolve().parents[1]
DOMAIN = "notes.example.test"
THEMES = set()  # Version 1 catalog. Version 2 is covered in test_artifact_sites.py.
LAYOUTS = {"editorial", "gallery", "index", "notebook", "bulletin", "folio"}
core = None
OBSERVED = {"themes": set(), "layouts": set(), "sample_count": 0,
            "files_checked": 0, "references_checked": 0, "sitemap_urls_checked": 0}


def seed(number: int) -> str:
    return hashlib.sha256(f"HTTPS Node generated-site behavioral fixture {number}".encode()).hexdigest()


def fingerprint(files: dict[str, str]) -> str:
    return hashlib.sha256(json.dumps(files, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


CSS_URL = re.compile(r"url\(\s*(?:'([^']*)'|\"([^\"]*)\"|([^\s)]*))\s*\)", re.I)


def css_references(text: str) -> list[str]:
    return [next(group for group in match.groups() if group is not None) for match in CSS_URL.finditer(text)]


class HTMLDocument(HTMLParser):
    def __init__(self, text: str):
        super().__init__(convert_charrefs=True)
        self.references = []
        self.identifiers = []
        self.tags = []
        self.unsafe = []
        self.body_class = ""
        self.feed(text)
        self.close()

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        self.tags.append(tag)
        if tag in {"script", "iframe", "object", "embed", "form"}:
            self.unsafe.append("unexpected active/form element " + tag)
        if tag == "input" and attrs.get("type", "").lower() == "password":
            self.unsafe.append("password field")
        for key in attrs:
            if key.startswith("on"):
                self.unsafe.append("event handler " + key)
        if tag == "meta" and attrs.get("http-equiv", "").lower() == "refresh":
            self.unsafe.append("meta refresh")
        if attrs.get("id") is not None:
            self.identifiers.append(attrs["id"])
        if tag == "body":
            self.body_class = attrs.get("class", "")
        for key in ("href", "src", "poster"):
            if attrs.get(key) is not None:
                self.references.append(attrs[key])
        if attrs.get("srcset"):
            self.references.extend(part.strip().split()[0] for part in attrs["srcset"].split(",") if part.strip())
        self.references.extend(css_references(attrs.get("style", "")))

    handle_startendtag = handle_starttag


def check_site(test: unittest.TestCase, files: dict[str, str], profile: dict) -> None:
    test.assertIsInstance(files, dict)
    test.assertTrue({"index.html", "about.html", "404.html", "robots.txt", "sitemap.xml"}.issubset(files))
    test.assertLessEqual(sum(len(value.encode()) for value in files.values()), 16 * 1024 * 1024)
    identifiers = {}
    references = []
    for name, text in files.items():
        test.assertIsInstance(name, str)
        test.assertIsInstance(text, str)
        path = PurePosixPath(name)
        test.assertFalse(path.is_absolute() or ".." in path.parts or "\\" in name or "\x00" in name, name)
        test.assertEqual(path.as_posix(), name)
        test.assertFalse(any(part.startswith(".") for part in path.parts), name)
        test.assertNotIn(profile["seed"], text, "The private full seed appeared in a public file")
        test.assertNotIn("vless://", text)
        test.assertNotIn("/panel/api/", text)
        if name.endswith(".html"):
            document = HTMLDocument(text)
            test.assertEqual(document.unsafe, [], (name, document.unsafe))
            test.assertEqual(len(document.identifiers), len(set(document.identifiers)), "Duplicate HTML id in " + name)
            identifiers[name] = set(document.identifiers)
            references.extend((name, value) for value in document.references)
            if name == "index.html":
                test.assertIn("layout-" + profile["layout"], document.body_class.split())
        elif name.endswith(".svg"):
            root = ET.fromstring(text)
            test.assertEqual(root.tag.split("}")[-1], "svg")
            ids = []
            for element in root.iter():
                tag = element.tag.split("}")[-1]
                test.assertNotIn(tag, {"script", "foreignObject", "iframe"})
                for attr, value in element.attrib.items():
                    plain = attr.split("}")[-1]
                    test.assertFalse(plain.lower().startswith("on"), (name, plain))
                    if plain == "id":
                        ids.append(value)
                    elif plain in {"href", "src"}:
                        references.append((name, value))
                    references.extend((name, ref) for ref in css_references(value))
            test.assertEqual(len(ids), len(set(ids)), "Duplicate SVG id in " + name)
            identifiers[name] = set(ids)
        elif name.endswith(".css"):
            test.assertNotRegex(text, r"(?i)@import\b")
            references.extend((name, value) for value in css_references(text))
    html_pages = {name for name in files if name.endswith(".html")}
    notes = {name for name in html_pages if name.startswith("notes/")}
    test.assertGreaterEqual(len(notes), 3)
    test.assertLessEqual(len(notes), 5)
    test.assertTrue(any(name.endswith(".svg") for name in files))
    test.assertTrue(any(name.endswith(".css") for name in files))

    def resolve(source: str, value: str) -> str:
        test.assertFalse(any(ord(char) < 32 for char in value), (source, value))
        parsed = urllib.parse.urlsplit(value)
        test.assertIn(parsed.scheme.lower(), {"", "https"}, (source, value))
        if parsed.netloc:
            test.assertEqual(parsed.hostname, DOMAIN, (source, value))
            test.assertIsNone(parsed.username)
            test.assertIn(parsed.port, {None, 443})
        elif parsed.scheme:
            test.fail("A URL with scheme but no allowed origin appeared: " + value)
        decoded = urllib.parse.unquote(parsed.path)
        test.assertNotIn("\\", decoded)
        test.assertNotIn("\x00", decoded)
        if not decoded:
            target = source
        elif decoded.startswith("/"):
            target = posixpath.normpath(decoded.lstrip("/"))
        else:
            target = posixpath.normpath(posixpath.join(posixpath.dirname(source), decoded))
        test.assertFalse(target == ".." or target.startswith("../"), (source, value))
        if target == ".":
            target = "index.html"
        elif decoded.endswith("/"):
            target = target.rstrip("/") + "/index.html"
        test.assertIn(target, files, f"Broken local reference {source}: {value} -> {target}")
        if parsed.fragment:
            test.assertIn(urllib.parse.unquote(parsed.fragment), identifiers.get(target, set()),
                          f"Broken fragment {source}: {value}")
        OBSERVED["references_checked"] += 1
        return target

    for source, value in references:
        resolve(source, value)
    sitemap = ET.fromstring(files["sitemap.xml"])
    locations = [element.text for element in sitemap.iter() if element.tag.split("}")[-1] == "loc"]
    test.assertEqual(len(locations), len(set(locations)))
    sitemap_targets = set()
    for location in locations:
        parsed = urllib.parse.urlsplit(location)
        test.assertEqual((parsed.scheme, parsed.netloc), ("https", DOMAIN))
        test.assertFalse(parsed.query or parsed.fragment)
        target = resolve("sitemap.xml", location)
        test.assertIn(target, html_pages)
        test.assertNotEqual(target, "404.html")
        sitemap_targets.add(target)
        OBSERVED["sitemap_urls_checked"] += 1
    test.assertEqual(sitemap_targets, html_pages - {"404.html"})
    for line in files["robots.txt"].splitlines():
        if line.lower().startswith("sitemap:"):
            test.assertEqual(resolve("robots.txt", line.split(":", 1)[1].strip()), "sitemap.xml")
    OBSERVED["files_checked"] += len(files)


class GeneratedSiteBehavior(unittest.TestCase):
    def test_saved_profile_roundtrip_is_byte_deterministic_and_unmodified(self):
        profile = core.generate_site_profile(seed(1), "journal")
        original = copy.deepcopy(profile)
        first = core.render_generated_site(DOMAIN, profile)
        reconstructed = json.loads(json.dumps(profile))
        second = core.render_generated_site(DOMAIN, reconstructed)
        self.assertEqual(profile, original)
        self.assertEqual(first, second)
        self.assertEqual(core.generate_site_profile(seed(1), "journal"), profile)

    def test_independent_seeds_change_site_bytes_visible_titles_and_artwork(self):
        profiles = [core.generate_site_profile(seed(number)) for number in range(24)]
        sites = [core.render_generated_site(DOMAIN, profile) for profile in profiles]
        self.assertEqual(len({fingerprint(files) for files in sites}), len(sites))
        self.assertGreater(len({profile["title"] for profile in profiles}), 3)
        self.assertGreater(len({files["index.html"] for files in sites}), 3)
        artwork = [hashlib.sha256("".join(text for name, text in sorted(files.items()) if name.endswith(".svg")).encode()).hexdigest()
                   for files in sites]
        self.assertEqual(len(set(artwork)), len(artwork))

    def test_all_themes_layouts_and_local_references_in_bounded_sample(self):
        self.assertGreaterEqual(len(THEMES), 12)
        for theme in sorted(THEMES):
            for number in range(12):
                with self.subTest(theme=theme, sample=number):
                    profile = core.generate_site_profile(seed(number + 100), theme)
                    self.assertEqual(profile["theme"], theme)
                    self.assertIn(profile["layout"], LAYOUTS)
                    self.assertEqual(profile["version"], 1)
                    self.assertRegex(profile["seed"], r"\A[0-9a-f]{64}\Z")
                    OBSERVED["themes"].add(theme)
                    OBSERVED["layouts"].add(profile["layout"])
                    OBSERVED["sample_count"] += 1
                    check_site(self, core.render_generated_site(DOMAIN, profile), profile)
        self.assertEqual(OBSERVED["themes"], THEMES)
        self.assertEqual(OBSERVED["layouts"], LAYOUTS)

    def test_title_and_description_overrides_remain_inert_visible_text(self):
        title = '<img id="injected-title" src="https://bad.example/x" onerror="alert(1)"> & "quoted"'
        description = '</style><script id="injected-script">alert(2)</script> and a normal description'
        profile = core.generate_site_profile(seed(2), "astronomy", title, description)
        files = core.render_generated_site(DOMAIN, profile)
        self.assertEqual(profile["title"], title)
        self.assertEqual(profile["description"], description)
        self.assertIn(title, html.unescape(files["index.html"]))
        self.assertIn(description, html.unescape(files["index.html"]))
        for name, text in files.items():
            if name.endswith(".html"):
                doc = HTMLDocument(text)
                self.assertEqual(doc.unsafe, [], (name, doc.unsafe))
                self.assertNotIn("injected-title", doc.identifiers)
                self.assertNotIn("injected-script", doc.identifiers)
                self.assertNotIn('<img id="injected-title"', text)
                self.assertNotIn('<script id="injected-script"', text)
            elif name.endswith(".svg"):
                ET.fromstring(text)
        check_site(self, files, profile)

    def test_invalid_seed_theme_and_profile_are_rejected(self):
        for bad_seed in ("", "a" * 63, "a" * 65, "g" * 64, "../" + "a" * 61, "a" * 63 + "\n", None, 123):
            with self.subTest(seed=repr(bad_seed)), self.assertRaises((ValueError, TypeError)):
                core.generate_site_profile(bad_seed)
        for bad_theme in ("../../escape", "not-a-theme", "<script>"):
            with self.subTest(theme=bad_theme), self.assertRaises(ValueError):
                core.generate_site_profile(seed(3), bad_theme)
        for field, value in (("version", 2), ("layout", "../../escape"), ("palette", 'x";display:none'),
                             ("theme", "unknown"), ("title", "bad\x00text")):
            profile = core.generate_site_profile(seed(3), "journal")
            profile[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                core.render_generated_site(DOMAIN, profile)

    def test_invalid_site_domain_cannot_be_injected_into_xml_or_html(self):
        profile = core.generate_site_profile(seed(4))
        for domain in ("example.com\n", "example.com/<script>", "example.com\" onclick=\"x", "../example.com"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                core.render_generated_site(domain, profile)


class GeneratedSiteIntegration(unittest.TestCase):
    def fixture_args(self, **updates):
        values = dict(transport="xhttp", email="fixture@example.test", site_theme="auto",
                      site_title=None, site_description=None, site_dir=None)
        values.update(updates)
        return argparse.Namespace(**values)

    def fixture_state(self, **updates):
        with mock.patch.object(core, "free_port", side_effect=itertools.count(30000)):
            return core.new_state({"domain": DOMAIN, "bind_ip": "127.0.0.1"}, self.fixture_args(**updates))

    def test_new_installations_have_independent_profiles_and_saved_identity(self):
        first = self.fixture_state()
        second = self.fixture_state()
        self.assertEqual(first["site_mode"], "generated")
        self.assertNotEqual(first["site_profile"]["seed"], second["site_profile"]["seed"])
        self.assertEqual(first["site_title"], first["site_profile"]["title"])
        self.assertEqual(first["site_description"], first["site_profile"]["description"])
        serialized = json.loads(json.dumps(first))
        self.assertEqual(core.render_generated_site(DOMAIN, first["site_profile"]),
                         core.render_generated_site(DOMAIN, serialized["site_profile"]))

    def test_populate_uses_saved_profile_without_leaking_private_state(self):
        state = self.fixture_state(site_theme="photography")
        profile = copy.deepcopy(state["site_profile"])
        markers = [state["password"], state["username"], state["uuid"], state["sub_id"],
                   state["panel_path"], state["transport_path"], profile["seed"]]
        expected = {name: content.encode() for name, content in core.render_generated_site(DOMAIN, profile).items()}
        with tempfile.TemporaryDirectory(prefix="https-node-generated-") as temporary:
            root = Path(temporary)
            for suffix in ("first", "restored"):
                destination = root / suffix
                with mock.patch.object(core, "SITE", destination), \
                        mock.patch.object(core, "command", side_effect=AssertionError("Unexpected external command")):
                    core.populate_site(json.loads(json.dumps(state)))
                actual = {str(item.relative_to(destination)): item.read_bytes()
                          for item in destination.rglob("*") if item.is_file()}
                self.assertEqual(actual, expected)
                for content in actual.values():
                    for marker in markers:
                        self.assertNotIn(marker.encode(), content)
        self.assertEqual(state["site_profile"], profile)

    def test_generated_profile_cannot_silently_disappear(self):
        state = self.fixture_state()
        state["site_profile"] = None
        with tempfile.TemporaryDirectory(prefix="https-node-missing-profile-") as temporary:
            destination = Path(temporary) / "site"
            with mock.patch.object(core, "SITE", destination), self.assertRaises(core.NodeError):
                core.populate_site(state)
            self.assertFalse(destination.exists())

    def test_custom_site_is_preserved_and_does_not_get_generated_identity(self):
        state = self.fixture_state(site_dir="operator-provided")
        self.assertEqual(state["site_mode"], "custom")
        self.assertIsNone(state["site_profile"])
        with tempfile.TemporaryDirectory(prefix="https-node-custom-preserved-") as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            original = b"<!doctype html><title>My real site</title><h1>Original content</h1>"
            (source / "index.html").write_bytes(original)
            destination = root / "installed"
            with mock.patch.object(core, "SITE", destination):
                core.populate_site(state, source)
            self.assertEqual((destination / "index.html").read_bytes(), original)
            self.assertFalse((destination / "site-profile.json").exists())
            self.assertFalse((destination / "sitemap.xml").exists())

    def test_preview_cli_is_offline_and_keeps_private_manifest_outside_webroot(self):
        with tempfile.TemporaryDirectory(prefix="https-node-preview-") as temporary:
            output = Path(temporary).resolve() / "preview"
            with mock.patch.object(core, "command", side_effect=AssertionError("Unexpected external command")), \
                    mock.patch.object(core, "preflight", side_effect=AssertionError("Unexpected VPS preflight")), \
                    mock.patch.object(core, "extract_release", side_effect=AssertionError("Unexpected release extraction")), \
                    mock.patch.object(core, "install", side_effect=AssertionError("Unexpected installation")), \
                    mock.patch("sys.stdout", new=io.StringIO()):
                core.main(["preview-site", "--domain", DOMAIN, "--output", str(output),
                           "--site-theme", "botanical", "--site-seed", seed(5)])
            site = output / "site"
            manifest_path = output / "site-profile.json"
            manifest = json.loads(manifest_path.read_text())
            self.assertEqual(manifest["domain"], DOMAIN)
            self.assertEqual(manifest["site_profile"]["seed"], seed(5))
            self.assertEqual(manifest["site_profile"]["theme"], "botanical")
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(manifest_path.stat().st_mode), 0o600)
            self.assertFalse(manifest_path.is_relative_to(site))
            actual = {str(item.relative_to(site)): hashlib.sha256(item.read_bytes()).hexdigest()
                      for item in site.rglob("*") if item.is_file()}
            self.assertEqual(actual, manifest["files_sha256"])
            self.assertFalse((site / "site-profile.json").exists())

    def test_preview_refuses_existing_destination_symlink_and_parent_traversal(self):
        def preview(path):
            args = argparse.Namespace(domain=DOMAIN, output=str(path), site_seed=seed(6), site_theme="auto",
                                      site_title=None, site_description=None)
            with mock.patch("sys.stdout", new=io.StringIO()):
                core.preview_site(args)

        with tempfile.TemporaryDirectory(prefix="https-node-preview-paths-") as temporary:
            root = Path(temporary)
            existing = root / "existing"
            existing.mkdir()
            with self.assertRaises(core.NodeError):
                preview(existing)
            self.assertEqual(list(existing.iterdir()), [])
            link = root / "linked-parent"
            link.symlink_to(existing, target_is_directory=True)
            with self.assertRaises(core.NodeError):
                preview(link / "unexpected")
            self.assertFalse((existing / "unexpected").exists())
            with self.assertRaises(core.NodeError):
                preview(existing / ".." / "unexpected")
            self.assertFalse((root / "unexpected").exists())

    def test_generated_output_paths_are_validated_before_preview_writes(self):
        for bad_path in ("../escape.html", "/absolute.html", "assets/../../escape", "assets\\escape.html"):
            with self.subTest(path=bad_path), tempfile.TemporaryDirectory(prefix="https-node-output-map-") as temporary:
                output = Path(temporary) / "preview"
                args = argparse.Namespace(domain=DOMAIN, output=str(output), site_seed=seed(7), site_theme="auto",
                                          site_title=None, site_description=None)
                malicious = {"index.html": "valid placeholder", bad_path: "must not be written"}
                with mock.patch.object(core, "render_generated_site", return_value=malicious), self.assertRaises(core.NodeError):
                    core.preview_site(args)
                self.assertFalse(output.exists())


def main() -> int:
    global core, THEMES
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=Path, default=PROJECT / "src/installer_core.py")
    parser.add_argument("--report", type=Path, default=PROJECT / "tests/GENERATED-SITE.txt")
    args = parser.parse_args()
    args.module = args.module.resolve()
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(args.module.parent))
    spec = importlib.util.spec_from_file_location("https_node_generated_site_subject", args.module)
    assert spec is not None and spec.loader is not None
    core = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = core
    spec.loader.exec_module(core)
    THEMES = set(core.LEGACY_SITE_THEMES)
    renderer_file = Path(inspect.getsourcefile(core.generate_site_profile)).resolve()
    subject_files = {args.module, renderer_file}
    provenance_files = {PROJECT / "src" / name for name in
                        ("site_content.py", "site_art.py", "rendering.py", "installer_core.py")}
    before = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(subject_files)}
    provenance = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(provenance_files)
                  if path.is_file()}
    started = time.monotonic()
    output = io.StringIO()
    suite = unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromTestCase(GeneratedSiteBehavior),
                               unittest.defaultTestLoader.loadTestsFromTestCase(GeneratedSiteIntegration)])
    result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    after = {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(subject_files)}
    stable = before == after
    metrics = {key: sorted(value) if isinstance(value, set) else value for key, value in OBSERVED.items()}
    header = {"outcome": "PASS" if result.wasSuccessful() and stable else "FAIL", "tests_run": result.testsRun,
              "elapsed_seconds": round(time.monotonic() - started, 3), "uid": os.getuid(),
              "subject_files_sha256": before, "subject_files_unchanged_during_run": stable,
              "source_provenance_sha256": provenance,
              "coverage": metrics, "scope": "Offline rendering, local-link parsing, temporary new_state/populate_site/preview CLI; no VPS install or network"}
    text = "HTTPS Node generated-site behavioral verification\n\n" + json.dumps(header, indent=2) + "\n\n" + output.getvalue()
    args.report.write_text(text)
    print(text)
    return 0 if result.wasSuccessful() and stable else 1


if __name__ == "__main__":
    raise SystemExit(main())
