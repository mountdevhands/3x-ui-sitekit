# Updates

English · [Русский](UPDATE.ru.md)

On a running node, check `status`, save a [backup](BACKUP.md), and obtain
the matching standalone with a trusted SHA-256. If the bootstrap's temporary
installer is gone, follow [Get a maintenance installer](PANEL-ACCESS.md#get-a-maintenance-installer)
to download, verify and save the rc6 standalone before running maintenance
commands. It includes the QR refresh option below.

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

This option is included in **0.3.0-rc6**. Obtain the
[verified maintenance installer](PANEL-ACCESS.md#get-a-maintenance-installer),
or run `python3 -B build.py` from the matching source root. The rc6
standalone SHA-256 is:

<!-- sitekit-release-sha256: installer -->
```text
ad10280e655dad12441f097c97402de73f59fc9ea75eca0b9ccdf35d40dbd8a3
```
<!-- /sitekit-release-sha256 -->

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

The rc6 installer reuses the exact approved rc4 dependency runtime. Refreshing
the access file does not upgrade those dependencies. Their versions and
security coverage remain governed by the [dated policy](../SECURITY.md).
