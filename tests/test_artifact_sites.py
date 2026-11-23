#!/usr/bin/env python3
"""Focused offline release checks for version-two artifact collections.

No browser, network, service or installer is started. Frozen v1 digests were
captured from the accepted 0.2.0 source before this change. The other checks
compare actual public downloads, construction data, references and geometry.
"""
from __future__ import annotations

import argparse
import hashlib
import html
from html.parser import HTMLParser
import importlib.util
import json
import math
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import subprocess
import sys
import unittest
from urllib.parse import unquote, urlsplit
import xml.etree.ElementTree as ET


PROJECT = Path(__file__).resolve().parents[1]
DOMAIN = "example.org"
FIXTURE_SEED = "0123456789abcdef" * 4
NEW_THEMES = ("generative", "patterns", "palettes", "curves")
FORMULA_URL = "https://www.w3.org/TR/WCAG22/#dfn-relative-luminance"
LAYOUTS = {"editorial", "gallery", "index", "notebook", "bulletin", "folio"}
FROZEN_V1 = {
    "journal": ("4ac04e60a4d86404808170b7a535e515b22da9397ad924fd9fbdf4f19d36b732", "cdb346450d5581dac085b1de3f33103372ec5655fe93d2bc6bc5e10b3b2faadb"),
    "botanical": ("f7bfabf84101dd8aee1cfb8f04fee286745702d1dc3fdd30419a5dd69f303399", "985d0da768c1737a5947713172ca2e8f3febd0f37c32455d6c96b69cc6f480e9"),
    "photography": ("0bad83b51a6d5cdb199e97cb33bfb306dc62ec3e238737a2566f52c6f50186cb", "66e03b205f792fd5749b63eb2b6e503968ebfe83059b52adfded34702d6b6eec"),
    "architecture": ("77f84d9a6fd9fddd202781b9ebbe7ccd99743341dfb0c64adf53cce4e11bb271", "f1ede3063f9af0c7ceecbaa54c726075f5d3576678b5530bc1ef93d6a58783ac"),
    "astronomy": ("205fef0610ca2eec2a7a8604ad471107998e625e58f48d4640a8ea99e70f09d2", "e586b9ac3ba682e8f0a3acbac9e2fb6825e544045256be9a832a9effe4516c20"),
    "typography": ("2917ff9b875f42efc57c66aec0c243f65346e6d59e23ec5fb776fe4a813773f4", "69a5fda0a3aee689545faa9421c6761ae7d93dff5e8e247ba2269d8ff4445db5"),
    "cartography": ("891aec0f4dc6f56134a4003c28941f8a7bcf0d1f9c43ae09d8e86d1353864083", "a28d27a6095327e734ba49db27f958dbf59d055f826ffef7ff5df94731c12089"),
    "ceramics": ("84d0068ea28477badf1dedbe7e08e25d3a0cf8065d64c3965c44373b506b25b2", "71c68d386ce154b83f5f1a33e742bb98a5060f4416136802e5a7e765a2a3e2b4"),
    "coffee": ("96e218324c5195d481fa42aaa58edc645e40d4a26724ff7edb3b77bb3108c048", "6ed217d0d07690591b60602e7c13539b2029b815849982f3efbb215180b1db9d"),
    "acoustics": ("df62417797c4abe7f627d50a2fba4a915c1304ee85ce4336885ad8bdac7b8ac1", "a1111941eeb3f530463c5aa6316ac7ee1b0bad90d457456b6365c9fa273797f4"),
    "printmaking": ("ad9572a0b62c4db0a6edcb2a614638ff7f2b47a079d3fc6686298935e71c7dfc", "f8f8faa76e5edbc662e3bf8cb055d571a75acd87381302e851e2d1a2363a4530"),
    "coastal": ("b0cd185cf7921651bc4d0ab8ca4cd91182e87655f6171f8f9970bf0b201ca4fd", "df5d1868e91c4a0410747e0bae7c69134546d0910ab1c1a4e333d1e8bc262379"),
}
core = None
artifacts = None
MODULE_PATH = PROJECT / "src" / "rendering.py"


def digest_files(files):
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode() + b"\0" + files[name].encode() + b"\0")
    return digest.hexdigest()


def fixture_seed(number):
    return hashlib.sha256(f"artifact-site fixture {number}".encode()).hexdigest()


CSS_URL = re.compile(r"url\(\s*['\"]?([^'\")\s]+)['\"]?\s*\)", re.I)


class Document(HTMLParser):
    def __init__(self, content):
        super().__init__(convert_charrefs=True)
        self.refs, self.ids, self.downloads, self.unsafe = [], set(), [], []
        self.remote_resources = []
        self.feed(content)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag in {"script", "iframe", "object", "embed", "form"} or any(key.startswith("on") for key in attrs):
            self.unsafe.append(tag)
        if "id" in attrs:
            self.ids.add(attrs["id"])
        for key in ("href", "src"):
            if key in attrs:
                self.refs.append(attrs[key])
                if urlsplit(attrs[key]).netloc and not (tag == "a" and key == "href") and not (tag == "link" and attrs.get("rel") == "canonical"):
                    self.remote_resources.append(attrs[key])
        if "download" in attrs:
            self.downloads.append(attrs.get("href"))

    handle_startendtag = handle_starttag


class ArtifactSites(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profiles = {theme: core.generate_site_profile(FIXTURE_SEED, theme) for theme in NEW_THEMES}
        cls.sites = {theme: core.render_generated_site(DOMAIN, profile) for theme, profile in cls.profiles.items()}

    def test_v1_profiles_and_files_are_byte_compatible(self):
        for theme, (profile_hash, files_hash) in FROZEN_V1.items():
            with self.subTest(theme=theme):
                profile = core.generate_site_profile(FIXTURE_SEED, theme)
                encoded = json.dumps(profile, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
                self.assertEqual(profile["version"], 1)
                self.assertEqual(hashlib.sha256(encoded).hexdigest(), profile_hash)
                self.assertEqual(digest_files(core.render_generated_site(DOMAIN, json.loads(json.dumps(profile)))), files_hash)

    def test_auto_chooses_new_themes_and_saved_profiles_remain_stable(self):
        seen = set()
        for number in range(48):
            profile = core.generate_site_profile(fixture_seed(number))
            self.assertEqual(profile["version"], 2)
            self.assertIn(profile["theme"], NEW_THEMES)
            seen.add(profile["theme"])
        self.assertEqual(seen, set(NEW_THEMES))
        self.assertEqual(set(core.SITE_THEMES), set(FROZEN_V1) | set(NEW_THEMES))
        for theme, profile in self.profiles.items():
            with self.subTest(theme=theme):
                self.assertEqual(profile, core.generate_site_profile(FIXTURE_SEED, theme))
                self.assertEqual(self.sites[theme], core.render_generated_site(DOMAIN, json.loads(json.dumps(profile))))
                other = core.render_generated_site(DOMAIN, core.generate_site_profile(fixture_seed(101), theme))
                first_downloads = {name: value for name, value in self.sites[theme].items() if name.startswith("downloads/")}
                other_downloads = {name: value for name, value in other.items() if name.startswith("downloads/")}
                self.assertNotEqual(first_downloads, other_downloads)

    def test_determinism_across_process_hash_seeds(self):
        script = """
import hashlib, importlib.util, json, pathlib, sys
path = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(path.parent))
spec = importlib.util.spec_from_file_location('artifact_process_test', path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
result = {}
for theme in ('generative','patterns','palettes','curves'):
    profile = module.generate_site_profile(sys.argv[2], theme)
    result[theme] = [profile, module.render_generated_site('example.org', profile)]
print(hashlib.sha256(json.dumps(result, sort_keys=True, ensure_ascii=False).encode()).hexdigest())
"""
        outputs = []
        for hash_seed in ("1", "91823"):
            env = {**os.environ, "PYTHONHASHSEED": hash_seed}
            outputs.append(subprocess.run([sys.executable, "-c", script, str(MODULE_PATH), FIXTURE_SEED],
                                          env=env, capture_output=True, check=True, text=True, timeout=15).stdout)
        self.assertEqual(outputs[0], outputs[1])

    def test_six_layouts_remain_structural_options(self):
        examples = {}
        for number in range(96):
            profile = core.generate_site_profile(fixture_seed(number), "generative")
            examples.setdefault(profile["layout"], profile)
            if set(examples) == LAYOUTS:
                break
        self.assertEqual(set(examples), LAYOUTS)
        signatures = {"editorial": 'class="editorial-feature"', "gallery": 'class="cards"',
                      "index": 'class="catalog"', "notebook": 'class="notebook-toc"',
                      "bulletin": 'class="bulletin-grid"', "folio": 'class="folio-row"'}
        for layout, profile in examples.items():
            self.assertIn(signatures[layout], core.render_generated_site(DOMAIN, profile)["index.html"])

    def test_public_files_are_safe_local_and_connected(self):
        for theme, files in self.sites.items():
            with self.subTest(theme=theme):
                documents, identifiers, references = {}, {}, []
                self.assertLess(sum(len(text.encode()) for text in files.values()), 1024 * 1024)
                self.assertTrue({"index.html", "about.html", "methods.html", "downloads.html", "404.html", "robots.txt", "sitemap.xml"} <= set(files))
                for name, content in files.items():
                    path = PurePosixPath(name)
                    self.assertFalse(path.is_absolute() or ".." in path.parts)
                    self.assertEqual(str(path), name)
                    self.assertRegex(name, r"^[a-z0-9][a-z0-9_./-]*$")
                    self.assertNotIn(FIXTURE_SEED, content)
                    self.assertNotIn('"seed"', content)
                    self.assertNotIn("site_profile", content)
                    self.assertNotIn("vless://", content)
                    if name.endswith(".html"):
                        doc = Document(content)
                        self.assertFalse(doc.unsafe)
                        self.assertFalse(doc.remote_resources)
                        documents[name], identifiers[name] = doc, doc.ids
                        references.extend((name, ref) for ref in doc.refs)
                    elif name.endswith(".svg"):
                        svg = ET.fromstring(content)
                        identifiers[name] = {node.attrib["id"] for node in svg.iter() if "id" in node.attrib}
                        for node in svg.iter():
                            self.assertNotIn(node.tag.rsplit("}", 1)[-1], {"script", "foreignObject", "image"})
                            self.assertFalse(any(key.lower().startswith("on") for key in node.attrib))
                            for key, value in node.attrib.items():
                                if key.rsplit("}", 1)[-1] in {"href", "src"}:
                                    references.append((name, value))
                                references.extend((name, match) for match in CSS_URL.findall(value))
                    elif name.endswith(".css"):
                        self.assertNotRegex(content, r"(?i)@import\b")
                        references.extend((name, ref) for ref in CSS_URL.findall(content))
                for source, reference in references:
                    parsed = urlsplit(reference)
                    self.assertIn(parsed.scheme, {"", "https"})
                    if parsed.netloc not in {"", DOMAIN}:
                        self.assertEqual(reference, FORMULA_URL)
                        self.assertEqual(theme, "palettes")
                        continue
                    self.assertIn(parsed.netloc, {"", DOMAIN})
                    decoded = unquote(parsed.path)
                    target = (source if not decoded else posixpath.normpath(decoded.lstrip("/"))
                              if decoded.startswith("/") else posixpath.normpath(posixpath.join(posixpath.dirname(source), decoded)))
                    target = "index.html" if target == "." else target
                    self.assertIn(target, files, (source, reference))
                    if parsed.fragment:
                        self.assertIn(unquote(parsed.fragment), identifiers.get(target, set()))
                pages = {name for name in files if name.startswith("studies/")}
                self.assertTrue(3 <= len(pages) <= 5)
                sitemap = ET.fromstring(files["sitemap.xml"])
                locations = {node.text for node in sitemap.iter() if node.tag.endswith("}loc")}
                expected = {f"https://{DOMAIN}/" + name for name in pages | {"about.html", "methods.html", "downloads.html", ""}}
                self.assertEqual(locations, expected)
                download_paths = {path for doc in documents.values() for path in doc.downloads}
                self.assertEqual(download_paths, {"/" + name for name in files if name.startswith("downloads/")})

    def test_downloads_describe_the_exact_rendered_artifacts(self):
        expected_methods = {"generative": {"circle-grid", "bar-field", "nested-frames"},
                            "patterns": {"dot-grid", "diagonal-stripes", "truchet"},
                            "palettes": {"analogous", "split-complementary", "monochrome"},
                            "curves": {"single-cubic", "mirrored-pair", "curve-bundle"}}
        for theme, files in self.sites.items():
            methods = set()
            for json_name, json_text in files.items():
                if not json_name.endswith(".json"):
                    continue
                data = json.loads(json_text)
                methods.add(data["method"])
                svg_name = "downloads/" + data["files"]["svg"]
                css_name = "downloads/" + data["files"]["css"]
                svg, css = files[svg_name], files[css_name]
                self.assertEqual(hashlib.sha256(svg.encode()).hexdigest(), data["svg_sha256"])
                root = ET.fromstring(svg)
                self.assertEqual(root.attrib["viewBox"], f'0 0 {data["canvas"]["width"]} {data["canvas"]["height"]}')
                geometry = [node for node in root if node.tag.rsplit("}", 1)[-1] in {"circle", "rect", "line", "path"}]
                self.assertEqual(len(geometry) - 1, len(data["primitives"]))
                self.assertTrue(0 < len(data["primitives"]) <= 64)
                for color in data["colors"]:
                    self.assertIn(color, css)
                    self.assertRegex(color, r"^#[A-F0-9]{6}$")
                self.assertIn("./" + data["files"]["svg"], CSS_URL.findall(css))
                page = files["studies/" + Path(json_name).stem + ".html"]
                self.assertIn(html.escape(data["title"]), page)
                self.assertIn(html.escape(data["description"]), page)
                for node, primitive in zip(geometry[1:], data["primitives"]):
                    expected_tag = "rect" if primitive["shape"] == "frame" else primitive["shape"]
                    self.assertEqual(node.tag.rsplit("}", 1)[-1], expected_tag)
                    color = node.attrib.get("stroke") if primitive["shape"] in {"frame", "line", "path"} else node.attrib.get("fill")
                    self.assertEqual(color, primitive["color"])
                    if primitive["shape"] == "path":
                        self.assertEqual(node.attrib["d"], primitive["d"])
                if theme == "patterns":
                    preview = ET.fromstring(files["assets/" + Path(svg_name).name])
                    pattern = preview.find("{http://www.w3.org/2000/svg}defs/{http://www.w3.org/2000/svg}pattern")
                    self.assertIsNotNone(pattern)
                    self.assertEqual([(node.tag, node.attrib, node.text) for node in pattern],
                                     [(node.tag, node.attrib, node.text) for node in list(root)[1:]])
            self.assertEqual(methods, expected_methods[theme])

    def test_contrast_values_are_computed_from_downloaded_hex(self):
        self.assertAlmostEqual(artifacts.artifact_contrast("#000000", "#FFFFFF"), 21.0)
        self.assertEqual(artifacts.artifact_contrast("#336699", "#336699"), 1.0)
        for name, text in self.sites["palettes"].items():
            if not name.endswith(".json"):
                continue
            data = json.loads(text)
            colors, params = data["colors"], data["parameters"]
            self.assertEqual(params["hex"], colors)
            for row, first in enumerate(colors):
                for column, second in enumerate(colors):
                    expected = artifacts.artifact_contrast(first, second)
                    self.assertAlmostEqual(params["contrast_matrix"][row][column], expected, delta=0.00051)
                    self.assertEqual(params["contrast_matrix"][row][column], params["contrast_matrix"][column][row])
            pair = params["strongest_pair"]
            self.assertAlmostEqual(pair["ratio"], max(max(row) for row in params["contrast_matrix"]), delta=0.00051)

    def test_truchet_edges_join_with_matching_tangents(self):
        # SVG arc endpoint-to-centre conversion, specialized to equal radii
        # and zero rotation. This checks the finished public path geometry,
        # including sweep flags, rather than reproducing generator strings.
        data = next(json.loads(text) for name, text in self.sites["patterns"].items()
                    if name.endswith(".json") and json.loads(text)["method"] == "truchet")
        endpoints = {}
        width, height = data["canvas"]["width"], data["canvas"]["height"]
        for primitive in data["primitives"]:
            values = re.findall(r"-?\d+", primitive["d"])
            x1, y1, radius, ry, rotation, large, sweep, x2, y2 = map(int, values)
            self.assertEqual(radius, ry)
            self.assertEqual((rotation, large), (0, 0))
            dx, dy = (x1 - x2) / 2, (y1 - y2) / 2
            factor = math.sqrt(max(0, (radius**2 - dx**2 - dy**2) / (dx**2 + dy**2)))
            if large == sweep:
                factor = -factor
            cx, cy = factor * dy + (x1 + x2) / 2, -factor * dx + (y1 + y2) / 2
            for x, y in ((x1, y1), (x2, y2)):
                key = (x % width, y % height)
                tangent = (round(abs(y - cy), 6), round(abs(x - cx), 6))
                endpoints.setdefault(key, []).append(tangent)
        for coordinate, tangents in endpoints.items():
            self.assertEqual(len(tangents), 2, coordinate)
            self.assertEqual(tangents[0], tangents[1], coordinate)

    def test_overrides_are_escaped_and_profiles_are_strict(self):
        title = '<img src=x onerror="alert(1)"> & title'
        description = "<script>alert('x')</script> & description"
        profile = core.generate_site_profile(FIXTURE_SEED, "generative", title, description)
        site = core.render_generated_site(DOMAIN, profile)
        self.assertIn(html.escape(title), site["index.html"])
        self.assertIn(html.escape(description), site["index.html"])
        self.assertFalse(Document(site["index.html"]).unsafe)
        for seed in ("", "f" * 63, "F" * 64, "g" * 64, None):
            with self.subTest(seed=seed), self.assertRaises(ValueError):
                core.generate_site_profile(seed, "curves")
        for domain in ("example.org/path", "user@example.org", "example.org;", "exаmple.org", "127.0.0.1", "*.example.org"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                core.render_generated_site(domain, profile)
        for change in ({"version": True}, {"version": 3}, {"theme": "auto"}, {"theme": "journal"},
                       {"layout": "../evil"}, {"palette": "red;"}, {"title": "bad\x00text"},
                       {"description": " leading"}, {"seed": "a" * 63}):
            changed = {**profile, **change}
            with self.subTest(change=change), self.assertRaises(ValueError):
                core.render_generated_site(DOMAIN, changed)
        for changed in (None, [], {}, {**profile, "unrecognized": 1}):
            with self.assertRaises(ValueError):
                core.render_generated_site(DOMAIN, changed)
        # A v1 profile cannot smuggle a new theme into the old renderer.
        changed = {**profile, "version": 1}
        with self.assertRaises(ValueError):
            core.render_generated_site(DOMAIN, changed)


def main():
    global core, artifacts, MODULE_PATH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=Path, default=MODULE_PATH, help="source rendering.py or bundled installer")
    args, remaining = parser.parse_known_args()
    MODULE_PATH = args.module.resolve()
    sys.path.insert(0, str(MODULE_PATH.parent))
    spec = importlib.util.spec_from_file_location("artifact_sites_release_test", MODULE_PATH)
    core = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = core
    spec.loader.exec_module(core)
    if hasattr(core, "artifact_contrast"):
        artifacts = core
    else:
        import artifact_sites
        artifacts = artifact_sites
    print("Artifact-site guard tests; offline, no browser or installer started.", flush=True)
    print("Module:", MODULE_PATH, flush=True)
    unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)


if __name__ == "__main__":
    main()
