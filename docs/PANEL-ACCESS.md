# Panel access

English · [Русский](PANEL-ACCESS.ru.md)

## Get a maintenance installer

The bootstrap removes its temporary installer after installation. It does
not automatically install a `/root/https-node.py` management command. If you
do not already have a verified rc5 standalone there, download the rc5
installer and verify its exact SHA-256 before saving it. The URL targets
the rc5 release assets; check [Releases](https://github.com/mountdevhands/3x-ui-sitekit/releases)
for their publication:

<!-- sitekit-release-sha256: installer -->
```bash
(
  set -eu
  sitekit_download=$(mktemp -d)
  trap 'rm -rf -- "$sitekit_download"' EXIT
  curl -q --fail --silent --show-error --location --proto '=https' \
    --proto-redir '=https' --connect-timeout 10 --max-time 60 --retry 2 \
    --retry-max-time 90 --output "$sitekit_download/https-node.py" \
    'https://github.com/mountdevhands/3x-ui-sitekit/releases/download/v0.3.0-rc5/3x-ui-sitekit-0.3.0-rc5.py'
  printf '%s  %s\n' \
    419874b25257c3bda3df7dd004bf500c1813b18762cdad7bdf4a908779730663 \
    "$sitekit_download/https-node.py" | sha256sum --check --strict
  sudo install -m 0700 "$sitekit_download/https-node.py" /root/https-node.py
)
```
<!-- /sitekit-release-sha256 -->

The rc5 standalone supports both `panel-access` and
`credentials --refresh-file`. Downloading it only saves the management file;
maintenance begins when you run a command. Keep the existing verified file
if it belongs to a newer release.

## Enable browser access without a tunnel

For a fresh installation, choose **HTTPS browser access** in the wizard.
The steps below change the mode on an already installed node.

The default `ssh` mode deliberately has no public panel route. Receiving
HTTP 404 at the panel's HTTPS URL is expected until you enable HTTPS access.

Run the following once **in a server shell**, through SSH or the provider's
console. These examples assume your verified standalone is stored as
`/root/https-node.py`; substitute its actual path if different.

```bash
sudo python3 /root/https-node.py panel-access \
  --mode https \
  --confirm-domain node.example.com

sudo cat /root/https-node-access.txt
```

Use the exact domain of the installed node. Open the URL labelled
**`Public panel:`** in your normal browser, then enter `Username:` and
`Password:` from the same private file. The public root URL serves the
website; the admin login is at the saved random path. After this one-time
change, you can close SSH and use the HTTPS URL directly.

The file is root-only (`0600`); it is never served by the public website.
If the standalone is missing, get the matching release's installer and
verify its hash before running maintenance commands. Do not repeat `install`.

## Restrict access to your IP

To enable HTTPS with an IP restriction, use:

```bash
sudo python3 /root/https-node.py panel-access \
  --mode https \
  --allow 198.51.100.24/32 \
  --confirm-domain node.example.com
```

The IP above is a documentation example. Replace it with your public IP,
not a local address such as `192.168.0.10`. Repeat `--allow` for more addresses
or CIDRs. **Each invocation supplies the complete new allowlist.** Omitting
`--allow` in HTTPS mode removes IP restrictions, while retaining the panel's
normal username/password authentication.

At installation time, the equivalent arguments are `--panel-access https`
and repeatable `--panel-allow IP/CIDR`. IP and CIDR literals are accepted;
hostnames are not. CIDRs are normalized to their network address. Although
IPv6 syntax is accepted in an allowlist, it does not enable an IPv6 listener
in this IPv4-only installation.

With a nonempty list, other sources receive 403, including for the URL
without a trailing slash. The restriction covers UI, API, panel assets
and new WebSocket connections. nginx uses the actual TCP peer address;
client-supplied `X-Forwarded-For` and `X-Real-IP` cannot grant access. A CDN
or another reverse proxy in front of the node requires a separate address
trust design and is outside the current configuration.

The website and VLESS use the same public port 443 but do not receive the
panel's rules. Restricting the entire port 443 in a network firewall would
restrict those services too. If your external IP changes, update the panel
allowlist through SSH. The backend panel, Xray API and metrics keep listening
on loopback. The subscription service on port 2096 remains disabled.

## SSH-only access

Switch back to SSH-only mode on the server:

```bash
sudo python3 /root/https-node.py panel-access \
  --mode ssh \
  --confirm-domain node.example.com
```

On **your computer**, open a tunnel, replacing `SERVER_IP`:

```bash
ssh -N -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:2053:127.0.0.1:2053 root@SERVER_IP
```

Keep that process running and open the saved local
`http://127.0.0.1:2053/<your-random-path>/` URL in a browser on the same
computer. Use the panel credentials from the access file. SSH access remains
available when HTTPS is enabled. VLESS clients import their VLESS link or
QR code and connect directly; they do not need this admin tunnel.

## The panel address stays stable

Each clean installation creates `/<32 random hexadecimal characters>/`
using `secrets.token_hex(16)`. The domain is chosen by the owner. The path
has no fixed text prefix, is not derived from the domain or password, and
is saved in the private state. A new clean installation creates a new path;
maintenance, reboot, renewal and mode changes preserve the existing path,
including paths created by older versions. The random path does not replace
authentication.

## Access file and VLESS QR code

Display the credentials and QR in the terminal without changing the file:

```bash
sudo python3 /root/https-node.py credentials --qr
```

**Version 0.3.0-rc5 also saves a plain UTF-8 QR code**
inside `/root/https-node-access.txt` during installation and panel-mode
changes. It is the VLESS import QR, not a link that logs in to the panel.
Use light text on a dark background and a monospaced font. Widen the
terminal window until the QR lines do not wrap, then scan it.

With the verified rc5 installer, refresh an existing access file:

```bash
sudo python3 /root/https-node.py credentials --refresh-file
```

This writes only the access file from existing state, preserving root
ownership and mode `0600`. It does not change node identity or reload services.
The command reports the saved path without printing secrets. If QR generation
fails, it leaves the old file unchanged. Add `--qr` if you also want to print
the refreshed access details and QR once. Without `--refresh-file`, `credentials`
and `credentials --qr` remain read-only. Existing rc4 installations need
the verified rc5 standalone for `--refresh-file`.

QR generation runs locally, using plain UTF-8 without ANSI color escapes.
During automatic installation or mode changes, a QR-tool failure leaves
usable credentials and the connection link in the file with an explicit
QR-unavailable message. The QR encodes the same connection secret as the
VLESS link; keep the entire access file private.

## What switching changes

`panel-access` requires root, the exact domain and `ready/complete` state.
It checks the existing configuration, creates a private checkpoint, and
updates nginx configuration, state and the access file. It preserves the
panel path, credentials, UUID, database, site and certificate. A caught
failure triggers a bounded rollback; incomplete recovery returns an error
with the checkpoint location.

If the managed nginx configuration has manual changes, the command stops
before overwriting them. Review the difference first. Matching mode and
allowlist are a no-op: no extra file writes or reload occur.

The three file replacements and reload are not one crash-atomic operation.
Normal exceptions, SIGINT and SIGTERM trigger rollback. SIGKILL, OS failure
or power loss require manual inspection of the checkpoint and the loaded
configuration. A no-op after such an interruption does not prove what
configuration the running nginx has loaded.

nginx uses graceful reload. Existing long-lived connections, including
WebSocket sessions, may continue after the change. New connections use the
new configuration. Immediate revocation of existing sessions requires a
separate decision to terminate connections or change credentials.

## Check the result

Test login from an allowed address and rejection from another source.
In SSH mode the public panel URL should return 404 and the tunnel should
continue to work. Check that the public website and one small VLESS request
remain available. Do not put real panel URLs, passwords, UUIDs, VLESS links
or the access file in a public report.
