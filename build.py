#!/usr/bin/env python3
"""Build the standalone and sync the wizard's APT parser offline."""
import ast
import hashlib
import re
from pathlib import Path

base = Path(__file__).resolve().parent
security = (base / "src/security_policy.py").read_text(encoding="utf-8")
certbot = (base / "src/certbot_runtime.py").read_text(encoding="utf-8")
content = (base / "src/site_content.py").read_text(encoding="utf-8")
art = (base / "src/site_art.py").read_text(encoding="utf-8")
artifacts = (base / "src/artifact_sites.py").read_text(encoding="utf-8")
render = (base / "src/rendering.py").read_text(encoding="utf-8")
apt_sources = (base / "src/apt_sources.py").read_text(encoding="utf-8")
core = (base / "src/installer_core.py").read_text(encoding="utf-8")
content = content.replace("from __future__ import annotations\n", "")
security = security.replace("from __future__ import annotations\n", "")
certbot = certbot.replace("from __future__ import annotations\n", "")
artifacts = artifacts.replace("from __future__ import annotations\n", "")
art = art.replace("from __future__ import annotations\n", "")
render = render.replace("from __future__ import annotations\n", "")
render = render.replace("from site_content import EXTRA_SITE_CONTENT\n", "")
render = render.replace("from site_art import render_site_illustration, render_site_icon\n", "")
render = render.replace("from artifact_sites import ARTIFACT_THEMES, generate_artifact_profile, render_artifact_site\n", "")
core = core.replace("from __future__ import annotations\n", "")
core = core.replace("from rendering import SITE_THEMES, generate_site_profile, normalize_panel_access, render_generated_site, render_nginx, render_site, validate_domain, validate_ipv4\n", "")
core = core.replace("from security_policy import SECURITY_APPROVED_BUNDLE, SECURITY_CERTBOT_MANIFEST_SHA256, evaluate_packages, evaluate_pinned_release, verify_policy_freshness\n", "")
core = core.replace("from certbot_runtime import CERTBOT_LIBRARIES, install_certbot_runtime, verify_certbot_payload\n", "")
core = core.replace("from apt_sources import APT_BACKPORTS, apt_source_enabled, apt_source_paths, apt_source_records, without_apt_backports\n", "")
version = re.search(r'^APP_VERSION = "([^"\n]+)"$', core, re.M).group(1)
header = f"""#!/usr/bin/env python3
# 3x-ui SiteKit {version} — single-file distribution
# Source: bundled security_policy.py, certbot_runtime.py, site_content.py, site_art.py, artifact_sites.py, rendering.py, apt_sources.py, installer_core.py
# License: MIT (upstream components retain their own licenses)
from __future__ import annotations

"""
body = (header + security + "\n\n" + certbot + "\n\n" + content + "\n\n" + art + "\n\n" + artifacts + "\n\n" + render + "\n\n" + apt_sources
        + "\n\n# ---------------- Installer and command line ----------------\n"
        + core.replace("#!/usr/bin/env python3\n", ""))
ast.parse(body)
target = base / "dist/https-node.py"
target.parent.mkdir(exist_ok=True)
target.write_text(body, encoding="utf-8")
target.chmod(0o755)
print(f"{hashlib.sha256(target.read_bytes()).hexdigest()}  {target.name}")

wizard = base / "setup.sh"
original = wizard.read_text(encoding="utf-8")
start = "# BEGIN GENERATED APT SOURCE PARSER\n"
end = "# END GENERATED APT SOURCE PARSER"
before, separator, rest = original.partition(start)
_, closing, after = rest.partition(end)
if not separator or not closing or start in after:
    raise ValueError("The generated APT parser markers in setup.sh are missing or ambiguous")
updated = before + start + apt_sources + end + after
if updated != original:
    wizard.write_text(updated, encoding="utf-8")
