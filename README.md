# 3x-ui SiteKit

English · [Русский](README.ru.md)

SiteKit installs 3x-ui and Xray on a dedicated VPS, configures nginx, TLS and
VLESS over XHTTP or WebSocket, and creates a static website with procedurally
generated content.

**Published prerelease: 0.3.0-rc4.** The installation commands below use that
exact release. Panel access defaults to an SSH tunnel; HTTPS browser access
can be enabled without reinstalling. nginx and Certbot each use a separate
copy of the pinned OpenSSL libraries. See the [security scope](SECURITY.md)
and [rc4 acceptance report](docs/ACCEPTANCE-0.3.0-rc4.en.md).

**Current source: 0.3.0-rc5-dev.** Guided `setup.sh`, saved VLESS QR codes
and `credentials --refresh-file` are development additions described below.
The guided setup installs verified rc4; it does not enable the QR additions
that are absent from the published rc4 assets.

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
it downloads the pinned rc4 file, verifies SHA-256 and saves it at that path. Do not run `install` again
on an existing node.

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
the VLESS connection link. **In the current development source**, installation
and access-mode changes also save a plain UTF-8 QR code in that file. Scan
it in your VLESS client's import screen; it represents the VLESS link,
not the admin panel login. Use light text on a dark background and a monospaced font. Widen the
terminal window until the QR lines do not wrap before scanning.

Use the [development standalone](dist/https-node.py) from this source
revision, or build it with `python3 -B build.py`. Its SHA-256 is:

```text
1e19523c9185918be41a9338b4d608343a98dabc5e7979a5bfcda13f5ee1796b
```

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

`--qr` also exists in released rc4, where it displays the QR in the terminal.
`--refresh-file` requires the updated source; downloading rc4 again will not
add that option. The new implementation uses plain UTF-8 without ANSI color
escapes and does not send the connection link to a remote QR service. If
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

## Guided setup

For an interactive server terminal, use the question-and-answer setup.
Save a reviewed local copy of [setup.sh](setup.sh) from these sources, then run:

```bash
sudo bash setup.sh
```

English is the default; use `sudo bash setup.sh --lang ru` for Russian.
The wizard asks for the domain and immediately checks public DNS, before
any download or installation. A single A record must match a public IPv4
assigned to this VPS; the domain must have no AAAA record. It checks two
public resolvers and does not mistake a private `docker0` address for your
public IP. On a mismatch, correct DNS and retry, enter another domain, or
cancel. The installer repeats its own preflight later.

The remaining questions cover email registration, panel access, an optional
HTTPS IP/CIDR list, the generated-site theme and transport. Defaults are
**SSH**, **auto** and **XHTTP**. Leaving email blank requires a separate
confirmation to register without email. HTTPS allowlist entries may be
separated by spaces or commas. The wizard asks you to accept the Let's Encrypt
terms and displays a settings summary before final confirmation; both consent
prompts default to **no**. EOF or Ctrl-C at a prompt cancels the wizard.

To review the selected command without installing:

```bash
bash setup.sh --lang en --dry-run
```

`--dry-run` still performs the read-only DNS checks. It does not download
release files, install packages or change the system. It does not require
root. The question flow requires an interactive terminal; `--help` lists
the available options.

You do not need to choose a panel password, VLESS UUID or random panel
path: the installer generates and saves them. Open the resulting
`/root/https-node-access.txt` for your actual access details.

`setup.sh` is a development-source addition. It downloads and verifies the
unchanged **rc4 bootstrap**, which in turn verifies the rc4 installer and
runtime. Thus this guided flow installs published rc4; the saved-QR and
`--refresh-file` additions still require the separate development installer.
There is no published `setup.sh` release download linked here yet.

For automation or a noninteractive environment, use the pinned command
below with explicit arguments. [Guided setup details](docs/INSTALL.md#guided-setup).

## Install from GitHub Releases

The source is [mountdevhands/3x-ui-sitekit](https://github.com/mountdevhands/3x-ui-sitekit).
This command uses the published, publicly accessible `v0.3.0-rc4`. Replace
the domain and email before running it. Verify the bootstrap SHA-256 against
a trusted copy of the accepted release manifest. A manifest from the same
location verifies transfer integrity only if you trust that release source.

```bash
(
  set -eu
  repo='mountdevhands/3x-ui-sitekit'
  scratch=$(mktemp -d)
  trap 'rm -rf -- "$scratch"' EXIT
  curl -q --fail --silent --show-error --location --proto '=https' \
    --proto-redir '=https' --connect-timeout 10 --max-time 60 --retry 2 \
    --retry-max-time 90 --output "$scratch/install.sh" \
    "https://github.com/$repo/releases/download/v0.3.0-rc4/install.sh"
  (cd "$scratch" && printf '%s  %s\n' \
    06df2e8cdbf4ee8e75979e8c4a141aa4f2eb0a87264f2e91ffbf81632cb76328 install.sh | sha256sum --check --strict)
  sudo bash "$scratch/install.sh" --repository "$repo" \
    --domain node.example.com --email admin@example.com --agree-tos
)
```

To enable HTTPS panel access during installation, append `--panel-access https`
to the final `sudo bash` command. Optionally add `--panel-allow YOUR_PUBLIC_IP/32`.
Omitting these options keeps the default SSH-only panel.
[Bootstrap options and installation requirements](docs/INSTALL.md).

## Install from downloaded files

Download `3x-ui-sitekit-0.3.0-rc4.py` and the separate
`3x-ui-sitekit-0.3.0-rc4-linux-amd64.tar.gz`. The runtime SHA-256 is:

```text
cb2abb5a45b8eee5d30ad0d4e8de6003b088a943ae8f0c2d32af6fec799e787f
```

Verify the files against a trusted copy of `SHA256SUMS`, save the installer
locally as `https-node.py`, and substitute your own domain:

```bash
sudo python3 https-node.py check --domain node.example.com

sudo python3 https-node.py install \
  --domain node.example.com \
  --release-archive ./3x-ui-sitekit-0.3.0-rc4-linux-amd64.tar.gz \
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

## Licenses

The installer is distributed under [MIT](LICENSE). Third-party components
retain their licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
and the archives in the full source release. Pinned versions and build
instructions are in [dependencies/REBUILD.txt](dependencies/REBUILD.txt).
