# Updates

English · [Русский](UPDATE.ru.md)

On a running node, check `status`, save a [backup](BACKUP.md), and obtain
the matching standalone with a trusted SHA-256. If the bootstrap's temporary
installer is gone, follow [Get a maintenance installer](PANEL-ACCESS.md#get-a-maintenance-installer)
to download, verify and save the published rc4 standalone before running
maintenance commands. Use the updated development standalone for the new QR
refresh option below.

```bash
sudo python3 https-node.py security-check
sudo python3 https-node.py update-nginx --confirm-domain node.example.com
sudo python3 https-node.py status
```

`update-nginx` checks candidates from signed Ubuntu pockets and builds a
plan containing only binaries from the `nginx` source package. It then
checks the running process and TLS. If the executable already satisfies
the policy, it may finish without restarting. The private checkpoint
contains the package plan and diagnostic information. On failure, inspect
that checkpoint and dpkg state first; an APT transaction may need separate
recovery.

The panel, Xray, Certbot and pinned OpenSSL are updated by a separate
candidate with a verified migration procedure. `install` is for a clean
host. Use [`panel-access`](PANEL-ACCESS.md) to change panel access on an
existing node.

## Refresh the access file with a QR code

This is a **0.3.0-rc5-dev source feature**; published rc4 does not include
the option. Download the [development standalone](../dist/https-node.py)
from this source revision or run `python3 -B build.py` from the source root.
The SHA-256 of `dist/https-node.py` is:

```text
1e19523c9185918be41a9338b4d608343a98dabc5e7979a5bfcda13f5ee1796b
```

Verify the file against that digest before using it as `/root/https-node.py`.
Then run:

```bash
sudo python3 /root/https-node.py credentials --refresh-file
```

Use the file's actual path if different. This regenerates only
`/root/https-node-access.txt` from saved state, adding its plain UTF-8 VLESS
QR code. It does not reinstall anything, reload a service, or change the
panel URL, username, password, UUID, database, site or certificate. It
prints only the saved path. A QR generation failure leaves the previous
access file unchanged. Use `credentials --qr` for a read-only display.

The published rc4 tag, release assets and installation command remain
unchanged. A development source update is not a new accepted runtime release.
