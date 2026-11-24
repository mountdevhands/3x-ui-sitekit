# Fresh installation

English · [Русский](INSTALL.ru.md)

The installation commands in this source version target **v0.3.0-rc7**.
Use its published assets from [GitHub Releases](https://github.com/mountdevhands/3x-ui-sitekit/releases);
a source commit and a published release are separate steps.

Use Ubuntu 26.04 amd64, system CPython 3.14, systemd, available TCP ports
80/443, and a public IPv4 directly assigned to the VPS interface. Point one
DNS A record for the domain at that IPv4 and remove any AAAA record. This
release does not configure an IPv6 listener. A CDN proxy or NAT in front
of the VPS is outside this release's supported configuration.

Use the official signed Ubuntu pockets `resolute`, `resolute-updates` and
`resolute-security`, with the distribution's `Signed-By` keyring. The wizard
detects `resolute-backports` before installation and shows the proposed change
in the final confirmation. For an explicit installation use
`--disable-apt-backports` if you want to approve that change.

The installer checks APT trust before saving installation state or masking
nginx. After confirmation it saves original files in a private
`/root/sitekit-apt-backports.*` directory and disables only the backports
pocket. It repeats the full trust check and restores the originals if the
edit or recheck fails. `check` and `--dry-run` only read the sources. See
[APT source recovery](DIAGNOSTICS.md#apt-source-policy-stopped-installation)
for an earlier RC5 failure.

A fresh installation requires a dedicated host with available ports and no
previous SiteKit state or Certbot lineage. Start with the
[one-command wizard](../README.md#install-from-github-releases) in an
interactive root shell with `curl`, `sha256sum`, `python3` and `ip`. The wizard
uses `whiptail` in terminals of at least 72×22 when available. Type in
fields, choose with the arrow keys, and press Enter to continue. Smaller
terminals and `--ui text` use numbered menus.

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
[explicit bootstrap arguments](#install-with-explicit-arguments)
for automation.

After installation, read the access details on the server:

```bash
cat /root/https-node-access.txt
```

For HTTPS, open the exact **`Public panel:`** URL and sign in with the saved
`Username:` and `Password:`. The domain's root URL opens the generated site.
For SSH mode, follow the tunnel command and local URL in the access file.
The installer generates the password, VLESS UUID and random panel path.


## Install with explicit arguments

For automation, download the pinned rc7 bootstrap, verify its SHA-256, and
supply the settings explicitly. This example requires `curl`, `sha256sum`
and `sudo`; when running as root, omit `sudo`. Replace the domain and email.
Pass `--agree-tos` only after accepting the ACME provider's terms.
Append `--disable-apt-backports` to approve the documented APT change on an
image where that pocket is enabled.

<!-- sitekit-release-sha256: bootstrap -->
```bash
(
  set -eu
  sitekit_download=$(mktemp -d)
  trap 'rm -rf -- "$sitekit_download"' EXIT
  curl -q --fail --silent --show-error --location \
    --proto '=https' --proto-redir '=https' \
    --connect-timeout 10 --max-time 60 --retry 2 --retry-max-time 90 \
    --output "$sitekit_download/install.sh" \
    'https://github.com/mountdevhands/3x-ui-sitekit/releases/download/v0.3.0-rc7/install.sh'
  printf '%s  %s\n' \
    'f91c150ca973ea11f0f7f29da23300bda8d94a4b73d32f19f6a9cac3f104545b' "$sitekit_download/install.sh" |
    sha256sum --check --strict
  sudo bash "$sitekit_download/install.sh" \
    --repository mountdevhands/3x-ui-sitekit \
    --domain node.example.com --email admin@example.com --agree-tos \
    --panel-access ssh --site-theme auto --transport xhttp
)
```
<!-- /sitekit-release-sha256 -->

Instead of `--email`, explicitly select `--acme-no-email` for registration
without email. `--transport` accepts `xhttp` or `ws`. The bootstrap supplies
the verified local runtime through `--release-archive`. For files already
on the server, see [Install from downloaded files](../README.md#install-from-downloaded-files).

## Choose the panel access mode

The wizard presents **SSH tunnel** and **HTTPS browser access** as menu
options. SSH is selected by default. For the noninteractive bootstrap,
choose HTTPS with `--panel-access https` and optionally repeat
`--panel-allow YOUR_PUBLIC_IP/32` for each allowed client IP or CIDR.

The IP must be your computer's public address, not the server's IP. A blank
list accepts any source IP with the panel's normal username/password login.
These rules apply only to the panel; the website and VLESS remain reachable.
You can change the mode later using [`panel-access`](PANEL-ACCESS.md), with
the existing certificate and panel path.

## Completion and maintenance

After success, read `/root/https-node-access.txt` locally as root. It contains
the panel URL, username, password, VLESS link and, in rc7, its plain UTF-8 QR.
Follow the [panel access guide](PANEL-ACCESS.md) to open the correct URL.
Keep a verified standalone as `/root/https-node.py` for maintenance; the
bootstrap removes its temporary downloaded installer. Use the
[maintenance download](PANEL-ACCESS.md#get-a-maintenance-installer) if needed.

If installation fails, retain the output and inspect the recorded stage
before making another ACME request. Use maintenance commands to change an
existing ready node. `--dry-run` is a settings preview, not a real installation
or certificate acceptance test.
