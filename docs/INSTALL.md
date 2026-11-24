# Fresh installation

English · [Русский](INSTALL.ru.md)

Use Ubuntu 26.04 amd64, system CPython 3.14, systemd, available TCP ports
80/443, and a public IPv4 directly assigned to the VPS interface. Point one
DNS A record for the domain at that IPv4 and remove any AAAA record. This
release does not configure an IPv6 listener.

Use the official signed Ubuntu pockets `resolute`, `resolute-updates` and
`resolute-security`, with the distribution's `Signed-By` keyring. If the
image enables `resolute-backports`, preserve the original sources file and
remove only that pocket before installation.

Keep earlier backups separately. A fresh installation requires a dedicated
host with available ports and no previous Certbot lineage. For downloaded
files, follow [Install from downloaded files](../README.md#install-from-downloaded-files).
For GitHub Releases, use the [verified command in the README](../README.md#install-from-github-releases).
Both examples install the published `v0.3.0-rc4`; they do not install development
changes from `main`.

## Guided setup

For an interactive server terminal, use the question-and-answer setup.
Save a reviewed local copy of [setup.sh](../setup.sh) from these sources, then run:

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

For automation or a noninteractive environment, use the
[pinned rc4 command](../README.md#install-from-github-releases) with explicit
arguments. The question-and-answer frontend requires an interactive terminal.

## Choose the panel access mode

By default, the panel uses `--panel-access ssh`: access it through an SSH
tunnel. To enable an HTTPS login URL during installation, add:

```text
--panel-access https
```

To allow only your external IP, also add the optional, repeatable argument:

```text
--panel-allow 198.51.100.24/32
```

Replace this documentation address with your own public IP. Without a list,
HTTPS accepts requests from any source IP and requires normal panel login.
The website and VLESS are not restricted by the panel's IP rules. You can
change the mode later using [`panel-access`](PANEL-ACCESS.md), without a new
installation, new certificate or new panel path.

## Other options and completion

In an interactive terminal, the bootstrap can ask for the domain if
`--domain` is omitted. Instead of `--email`, explicitly select
`--acme-no-email` if you want registration without email. `--transport`
accepts `xhttp` or `ws`. `https-node.py preview-site --help` lists the available
`--site-theme` values. The bootstrap supplies the verified local runtime
through `--release-archive`.

After success, read `/root/https-node-access.txt` locally as root. It contains
the panel URL, username, password and VLESS link. Follow the
[panel access guide](PANEL-ACCESS.md) to open the correct URL. Keep a verified
standalone copy as `/root/https-node.py` for maintenance; the bootstrap cleans
up its temporary downloaded installer.

If installation fails, retain the output and inspect the recorded stage
before making another ACME request. Do not run `install` to change the
configuration of an existing ready node.
