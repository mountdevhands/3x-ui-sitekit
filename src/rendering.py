"""Pure renderers for HTTPS Node; no filesystem or network side effects.

The XHTTP upstream uses HTTP/2 cleartext via nginx's grpc module, following
https://github.com/XTLS/Xray-examples/tree/main/VLESS-XHTTP3-Nginx .  The client
transport remains XHTTP.  This avoids the HTTP/1.1 streaming-upload failure
described in https://github.com/XTLS/Xray-core/issues/7180 .

ssl_reject_handshake needs nginx >= 1.19.4; the target distribution packages
are Ubuntu 24.04/26.04 and Debian 12/13.  The older ``listen ... http2`` syntax is
intentional: it also works with nginx 1.22 and 1.24.
"""

from __future__ import annotations

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


from site_content import EXTRA_SITE_CONTENT
from site_art import render_site_illustration, render_site_icon

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
from artifact_sites import ARTIFACT_THEMES, generate_artifact_profile, render_artifact_site

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
