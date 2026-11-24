# 3x-ui SiteKit

English · [Русский](README.ru.md)

SiteKit installs 3x-ui and Xray on a dedicated VPS, configures nginx, TLS and
VLESS over XHTTP or WebSocket, and creates a static website with procedurally
generated content.

**Release candidate: 0.3.0-rc7.** This version combines the interactive setup
wizard, saved VLESS QR codes and `credentials --refresh-file` in one release.
The download commands target the `v0.3.0-rc7` assets; check
[GitHub Releases](https://github.com/mountdevhands/3x-ui-sitekit/releases)
for publication. Updating `main` alone does not publish those assets.

## Requirements

- A clean Ubuntu 26.04 amd64 VPS with systemd and system CPython 3.14.
- Root access for installation and maintenance.
- A public IPv4 directly assigned to the VPS interface, with the domain's DNS A record pointing to it.
- No AAAA record for the domain: this installation supports IPv4 only.
- Available TCP ports 80 and 443, reachable from outside; outbound access to DNS, APT and ACME.
- Official signed Ubuntu repositories for the same release: release, updates and security.

A CDN proxy or NAT in front of the VPS is outside this release's supported
configuration. Use a separate host without a running nginx, another panel
or existing Certbot lineages. `check` does not replace the additional Python,
dependency and APT checks performed by `install`.


## Install from GitHub Releases

Log in to the **new server as root**, using SSH or your provider's interactive
console. Paste the entire block as one command. It uses the system `curl`,
`sha256sum`, `python3` and `ip` to open the verified RC6 wizard. Enter your
domain and email in the wizard.

<!-- sitekit-release-sha256: setup -->
```bash
(
  set -eu
  sitekit_download=$(mktemp -d)
  trap 'rm -rf -- "$sitekit_download"' EXIT
  curl -q --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' \
    --connect-timeout 10 --max-time 60 --retry 2 --retry-max-time 90 \
    --output "$sitekit_download/setup.sh" \
    'https://github.com/mountdevhands/3x-ui-sitekit/releases/download/v0.3.0-rc7/setup.sh'
  printf '%s  %s\n' \
    '068aebeca75b76f67cdba5fa5fcde23f6c49349d0243efd3f47450aaf0b88bc6' "$sitekit_download/setup.sh" |
    sha256sum --check --strict
  bash "$sitekit_download/setup.sh"
)
```
<!-- /sitekit-release-sha256 -->

The first screen selects **English by default**. Choose Russian there, or
append `--lang ru` to the final `bash` line to skip the language selection.
If `whiptail` is installed, the wizard uses terminal windows and keyboard menus.
Text menus are available on minimal images.
Type directly in fields, use the arrow keys to choose an item, and press
Enter to continue. Next, Yes and Install are the default actions in their
respective windows. Esc or Cancel closes the wizard before installation.

The pinned wizard installs **rc7**, including the saved QR feature. It
verifies the rc7 bootstrap, which verifies the installer and runtime before
executing them. The reviewed runtime is byte-for-byte the same dependency
bundle used by rc4. If Ubuntu enables `resolute-backports`, the wizard asks
whether to back up the source files and disable only that pocket. The final
confirmation includes the affected entries. [Installation details](docs/INSTALL.md).

## Guided setup

The wizard shows a welcome screen and walks through these choices:

| Setting | What to enter or choose |
| --- | --- |
| Domain | Your domain without `https://`, a path or a port. DNS is checked immediately. |
| Certificate email | Your email, or explicitly confirm registration without one. |
| Panel access | **SSH tunnel** by default; choose **HTTPS browser access** for an ordinary login URL. |
| Allowed panel IPs | Optional in HTTPS mode. Enter your computer's public IP/CIDR, or leave blank for any IP with normal panel authentication. |
| Website | **Automatic** selects a generated theme; individual themes are also available. |
| Transport | **XHTTP** by default, or WebSocket. |

The domain must have exactly one A record matching a public IPv4 assigned
to this server and no AAAA record. If DNS does not match, choose Retry,
Change domain or Cancel. Review your settings and the Let’s Encrypt
Subscriber Agreement in the final summary. Choose **Install** to accept
the agreement and start downloading the release files. The summary shows
any planned backports change. In text mode, Enter accepts `[Y/n]` after a
successful read, and `n` declines.

A verified local copy of `setup.sh` also supports:

```bash
sudo bash setup.sh --lang en --ui dialog
sudo bash setup.sh --lang ru --ui text
bash setup.sh --lang en --dry-run
```

`--ui auto` is the default: it uses `whiptail` when the terminal supports
it, or numbered text menus otherwise. `--ui dialog` requires `whiptail` and
a suitable terminal; `--ui text` explicitly selects text menus. `--lang en`
or `--lang ru` skips language selection. EOF, Ctrl-C or Cancel ends setup.

`--dry-run` performs DNS checks and shows the resulting command without
downloading release files or changing the system. It does not require root.
All interactive modes require a terminal; use the
[explicit bootstrap arguments](docs/INSTALL.md#install-with-explicit-arguments)
for automation.

After installation, read the access details on the server:

```bash
cat /root/https-node-access.txt
```

For HTTPS, open the exact **`Public panel:`** URL and sign in with the saved
`Username:` and `Password:`. The domain's root URL opens the generated site.
For SSH mode, follow the tunnel command and local URL in the access file.
The installer generates the password, VLESS UUID and random panel path.

## Open the admin panel in a browser

With the default installation, **the public panel URL returns 404**.
To enable browser access without an SSH tunnel, run this **once on the
server**, through SSH or your provider's server console:

```bash
sudo python3 /root/https-node.py panel-access \
  --mode https \
  --confirm-domain node.example.com

sudo cat /root/https-node-access.txt
```

Replace `node.example.com` with your existing installation's domain. The
examples assume a verified installer saved as `/root/https-node.py`; use
its actual path if different. If it is missing, first follow
[Get a maintenance installer](docs/PANEL-ACCESS.md#get-a-maintenance-installer):
it downloads the pinned rc7 file, verifies SHA-256 and saves it at that path.
Use maintenance commands on an existing node.

Open the **exact `Public panel:` URL** from the access file in your normal
browser, then sign in with its `Username:` and `Password:`. The URL includes
your installation's random path. Opening just the domain shows the generated
website. You can close the SSH session after enabling HTTPS; subsequent
browser visits do not require a tunnel.

To restrict the HTTPS panel to your own external IP:

```bash
sudo python3 /root/https-node.py panel-access \
  --mode https \
  --allow 198.51.100.24/32 \
  --confirm-domain node.example.com
```

Replace the documentation address `198.51.100.24` with your own public IP.
Repeat `--allow` for additional addresses or networks. Omitting `--allow`
permits any source IP, with normal panel authentication. Each call replaces
the entire allowlist. These rules affect only the panel; the website and
VLESS on port 443 remain available. SSH access remains available too.

To return to SSH-only access:

```bash
sudo python3 /root/https-node.py panel-access \
  --mode ssh \
  --confirm-domain node.example.com
```

For SSH-only access, run this on **your computer**, replacing `SERVER_IP`:

```bash
ssh -N -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:2053:127.0.0.1:2053 root@SERVER_IP
```

Keep the tunnel open and open the exact local `http://127.0.0.1:2053/.../`
URL from the access file in the browser on that same computer. VLESS
clients do not need an SSH tunnel.

Every clean installation creates a path containing 32 random hexadecimal
characters, such as `/9b62d4e1a7304c8fbe09521d6a84f703/`. It has no fixed
text prefix and is independent of the domain and password. Reboots,
certificate renewal and access-mode changes preserve the path.
[Full panel access guide](docs/PANEL-ACCESS.md).


## VLESS link and QR code

The root-only `/root/https-node-access.txt` contains panel credentials and
the VLESS connection link. **In rc7**, installation and access-mode changes
also save a plain UTF-8 QR code in that file. Scan
it in your VLESS client's import screen; it represents the VLESS link,
not the admin panel login. Use light text on a dark background and a monospaced font. Widen the
terminal window until the QR lines do not wrap before scanning.

Use the [rc7 maintenance installer](docs/PANEL-ACCESS.md#get-a-maintenance-installer)
or build the matching source with `python3 -B build.py`. The rc7 installer
SHA-256 is:

<!-- sitekit-release-sha256: installer -->
```text
b6e086aea99af79122210cd79057d3304a31dd1fd02e4976751b852d9cbd55e1
```
<!-- /sitekit-release-sha256 -->

Verify the downloaded or built file before using it as the updated
`/root/https-node.py`. With that installer on an existing node:

```bash
sudo python3 /root/https-node.py credentials --refresh-file
sudo cat /root/https-node-access.txt
```

`--refresh-file` rewrites only the access file from existing state, keeping
root ownership and mode `0600`. It does not change the panel path, password,
UUID, site, database, certificate or services. If QR generation fails, the
previous file remains unchanged. Its output reports only the saved path.

For a read-only display of credentials and a QR code:

```bash
sudo python3 /root/https-node.py credentials --qr
```

`--refresh-file` is included in rc7. Existing rc4 nodes can use the verified
rc7 standalone for this command. QR generation uses plain UTF-8 without
ANSI color escapes and does not send the link to a remote QR service. If
automatic QR generation during installation or panel-mode changes fails,
the access file retains usable credentials and the link, with an explicit
QR-unavailable message. The file and its QR contain connection secrets.


## What SiteKit installs

| Component | Purpose |
| --- | --- |
| 3x-ui | Manages users and Xray configuration; listens on loopback |
| Xray | VLESS with XHTTP `auto` or WebSocket behind nginx |
| nginx | Public website, TLS and transport routes; optional HTTPS panel |
| Certbot | Certificate issuance and renewal in a separate environment with its own systemd timer |
| Website generator | Local SVG, CSS, JSON and pages describing the generated materials |

`install` verifies the runtime SHA-256 and nested manifests before installing.
Managed paths and services use the system name `https-node`.


## Install from downloaded files

Download `3x-ui-sitekit-0.3.0-rc7.py` and the separate
`3x-ui-sitekit-0.3.0-rc7-linux-amd64.tar.gz`. The runtime SHA-256 is:

```text
cb2abb5a45b8eee5d30ad0d4e8de6003b088a943ae8f0c2d32af6fec799e787f
```

Verify the files against a trusted copy of `SHA256SUMS`, save the installer
locally as `https-node.py`, and substitute your own domain:

```bash
sudo python3 https-node.py check --domain node.example.com

sudo python3 https-node.py install \
  --domain node.example.com \
  --release-archive ./3x-ui-sitekit-0.3.0-rc7-linux-amd64.tar.gz \
  --transport xhttp \
  --panel-access ssh \
  --site-theme auto \
  --email admin@example.com \
  --agree-tos
```

`--agree-tos` accepts the ACME provider's terms. If you intentionally register
without email, use `--acme-no-email` instead of `--email`. If certificate
issuance fails, preserve the diagnostics and fix the cause before retrying.
Keep a verified standalone copy for later maintenance commands.


## Generated website

The default `auto` option selects one of four themes during installation:

| Theme | Generated materials |
| --- | --- |
| `generative` | Geometric compositions |
| `patterns` | Seamless SVG tiles |
| `palettes` | Palettes, CSS variables and color parameters |
| `curves` | Bézier curves and control points |

Pages describe the actual generated SVG parameters. CSS and JSON downloads
are included; JSON records the SVG SHA-256. Generation runs locally without
an external LLM or API keys. A random profile is created once and retained.
General method explanations may repeat across sites. Older explicitly
selected themes remain available; `preview-site --help` lists them. Use
`--site-dir` to supply your own static website.

A local preview needs no root access, DNS lookup or certificate:

```bash
python3 https-node.py preview-site --domain example.test \
  --site-theme palettes --output ./palette-preview

python3 -m http.server 8080 --bind 127.0.0.1 \
  --directory ./palette-preview/site
```

Open `http://127.0.0.1:8080/`. Serve only the `site` subdirectory; the private
`site-profile.json` is stored beside it.


## Maintenance

```bash
sudo python3 https-node.py status
sudo python3 https-node.py security-check
sudo python3 https-node.py update-nginx --confirm-domain node.example.com
```

`security-check` compares selected packages and pinned dependencies against
a dated policy. `update-nginx` maintains nginx packages. New 3x-ui, Xray or
Certbot versions require a separately reviewed release.

[Security policy](SECURITY.md) · [Updates](docs/UPDATE.md) ·
[Diagnostics](docs/DIAGNOSTICS.md) · [Backups](docs/BACKUP.md) ·
[Uninstall](docs/UNINSTALL.md)

State is stored in `/etc/https-node/state.json`, the panel database in
`/var/lib/https-node/panel/x-ui.db`, and the website in `/var/www/https-node`.
Before migration or removal, keep a private consistent backup of state,
database, website and Certbot data. Diagnostic checkpoints do not replace
a complete backup and must not be published with the source code.


## Build and local checks

```bash
python3 -B build.py
sha256sum -c SHA256SUMS.txt
python3 -B -m unittest discover -s tests -p 'test_release_bootstrap.py'
python3 -B tests/test_artifact_sites.py --module dist/https-node.py
```

The [CI workflow](.github/workflows/ci.yml) lists the full set of commands.
To test routing and access rules using an existing local nginx binary:

```bash
python3 -B tests/integration_panel_access.py \
  --nginx /absolute/path/to/nginx --module dist/https-node.py
```

This fixture uses loopback, a temporary certificate explicitly trusted by
the test client, and HTTP/WebSocket mock backends. It installs no packages
and does not replace real 3x-ui, VLESS or renewal acceptance on a VPS.


The [rc4 acceptance report](docs/ACCEPTANCE-0.3.0-rc4.en.md) documents that
historical release. Local checks of rc7 do not constitute a new VPS, ACME or
reboot acceptance. Release preparation and publication are described in
[RELEASING.md](docs/RELEASING.md).

## Licenses

The installer is distributed under [MIT](LICENSE). Third-party components
retain their licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
and the archives in the full source release. Pinned versions and build
instructions are in [dependencies/REBUILD.txt](dependencies/REBUILD.txt).
