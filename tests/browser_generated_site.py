#!/usr/bin/env python3
"""Bounded local rendering QA. Optional test dependency: Playwright + Chromium.

Requests are fulfilled from the generated in-memory files. No remote website,
credentials, VDS or installed services are used. Screenshots stay in scratch.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from urllib.parse import urlsplit, unquote

from playwright.sync_api import sync_playwright


PROJECT = Path(__file__).resolve().parents[1]
DOMAIN = "preview.example.test"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--module", type=Path, default=PROJECT / "dist/https-node.py")
    parser.add_argument("--chromium", default="/usr/bin/chromium")
    parser.add_argument("--report", type=Path, default=PROJECT / "tests/BROWSER.txt")
    args = parser.parse_args()
    spec = importlib.util.spec_from_file_location("browser_subject", args.module)
    subject = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(subject)
    screenshots = Path(tempfile.mkdtemp(prefix="generated-site-qa-", dir=PROJECT))
    # Pick one case per theme, favoring a layout not yet covered.
    cases, layouts = [], set()
    for theme in subject.SITE_THEMES:
        for number in range(128):
            seed = hashlib.sha256(f"browser:{theme}:{number}".encode()).hexdigest()
            profile = subject.generate_site_profile(seed, theme)
            if profile["layout"] not in layouts or len(layouts) == 6 or number == 127:
                break
        layouts.add(profile["layout"])
        cases.append((profile, subject.render_generated_site(DOMAIN, profile)))
    results, violations = [], []
    mime = {".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8",
            ".svg": "image/svg+xml", ".xml": "application/xml", ".txt": "text/plain"}

    def handler(files):
        def fulfill(route):
            url = urlsplit(route.request.url)
            key = unquote(url.path.lstrip("/")) or "index.html"
            if url.hostname != DOMAIN or key not in files:
                violations.append({"url": route.request.url, "problem": "unexpected request"})
                route.abort()
                return
            route.fulfill(status=200, body=files[key].encode("utf-8"),
                          content_type=mime.get(Path(key).suffix, "application/octet-stream"))
        return fulfill

    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=args.chromium, headless=True,
                                    args=["--no-sandbox"])
        version = browser.version
        try:
            for profile, files in cases:
                context = browser.new_context()
                context.route("**/*", handler(files))
                page = context.new_page()
                page.on("pageerror", lambda error: violations.append({"problem": str(error)}))
                for label, width, height in (("desktop", 1366, 960), ("mobile", 390, 844)):
                    page.set_viewport_size({"width": width, "height": height})
                    page.goto(f"https://{DOMAIN}/", wait_until="load")
                    # Load lazy illustrations for bounded full-page QA without
                    # changing geometry or relying on timed scrolling.
                    page.evaluate("document.querySelectorAll('img').forEach(i => i.loading = 'eager')")
                    page.wait_for_function("[...document.images].every(i => i.complete && i.naturalWidth > 0)")
                    metrics = page.evaluate("""() => ({
                      width: innerWidth, scrollWidth: document.documentElement.scrollWidth,
                      headingCount: document.querySelectorAll('h1').length,
                      images: [...document.images].map(i => ({ok: i.complete && i.naturalWidth > 0, src: i.getAttribute('src')})),
                      links: document.querySelectorAll('a[href]').length,
                      bodyText: document.body.innerText.length
                    })""")
                    assert metrics["scrollWidth"] <= width + 1, (profile, label, metrics)
                    assert metrics["headingCount"] == 1 and metrics["bodyText"] > 250, (profile, metrics)
                    assert all(item["ok"] for item in metrics["images"]), (profile, metrics)
                    assert metrics["links"] >= 4, (profile, metrics)
                    name = f"{profile['theme']}-{profile['layout']}-{label}.png"
                    page.screenshot(path=str(screenshots / name), full_page=True)
                    results.append({"theme": profile["theme"], "layout": profile["layout"],
                                    "viewport": label, "result": "PASS", **metrics})
                context.close()
        finally:
            browser.close()
    assert not violations, violations
    report = {"result": "PASS", "module_sha256": hashlib.sha256(args.module.read_bytes()).hexdigest(),
              "chromium": version, "themes": len(cases), "layouts": sorted(layouts),
              "pages_checked": len(results), "network": "all requests served from in-memory generated files",
              "fixture_change": "lazy illustrations loaded eagerly for full-page capture; layout and CSS unchanged",
              "screenshots_for_internal_inspection": str(screenshots), "results": results}
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k != "results"}, indent=2))


if __name__ == "__main__":
    main()
