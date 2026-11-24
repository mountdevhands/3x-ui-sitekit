# Diagnostics

English · [Русский](DIAGNOSTICS.ru.md)

```bash
sudo python3 https-node.py status
sudo python3 https-node.py security-check
sudo systemctl status https-node-panel.service https-node-nginx.service https-node-certbot.timer
sudo journalctl --since today -u https-node-nginx.service -u https-node-panel.service -u https-node-certbot.service
```

On rc4, check the managed nginx configuration with the same OpenSSL
libraries used by its service:

```bash
sudo /opt/https-node/nginx-openssl/nginx -t -c /etc/https-node/nginx.conf
```

## The panel does not open

| Symptom | What to check |
| --- | --- |
| The domain shows a website | Open the exact random panel path from the root-only access file |
| The public panel URL returns 404 | Default mode is `ssh`; enable `https` using the [panel guide](PANEL-ACCESS.md) |
| The panel returns 403 | Your current public IP must match the configured panel allowlist |
| A local `127.0.0.1:2053` link fails | Open the SSH tunnel on the same computer as the browser and keep it running |
| `credentials --refresh-file` is unrecognized | This option is in the development source after rc4; rc4 supports terminal `credentials --qr` |
| A text QR will not scan | Use light text on a dark background, a monospaced font, preserved whitespace and no wrapping; the VLESS text link remains usable |

For DNS/ACME, first check that the A record matches the VPS IPv4, that
there is no AAAA record, and that TCP 80 is reachable from outside. A
`failed` status includes the last recorded stage. Private Certbot logs
are in `/var/log/letsencrypt`.

For a policy error, check its expiry, full package versions and any
`UNKNOWN`/`BLOCKED` findings. Before sharing output, remove credentials,
connection URIs, private paths and production-host details.

## APT source policy stopped installation

Published rc5 can stop at `packages` with `APT source suite is outside the
reviewed release/security/updates pockets` when an image enables
`resolute-backports`. Only `resolute`, `resolute-updates` and
`resolute-security` are allowed. This error identifies an unsupported source;
it does not establish that an installed package has a vulnerability.

In that exact rc5 failure, the source check happens before the installer's
APT update and package installation. SiteKit has saved failed state, but has
not deployed nginx, the panel or Certbot, and has not requested a certificate.
The generic suggestion that an nginx package remains is incorrect for this
case. RC6 checks APT during read-only preflight and reports the source file
and offending suite. The wizard offers the scoped edit with a backup.

For an already failed rc5 attempt:

1. Inspect `status` with the verified rc5 standalone. Confirm the domain and
   `failed/packages` state, and preserve `/etc/https-node` in a root-only backup
   outside that directory. Do not publish `state.json`; it contains credentials.
2. Confirm that the earlier cleanup succeeded and there is no deployed runtime,
   managed service or certificate lineage. Then use
   the ordinary [uninstall command](UNINSTALL.md) with the exact failed domain.
3. Run the RC6 wizard after the reset. Authorize the backports edit in the wizard
   or pass `--disable-apt-backports` to the explicit installation command.

If the failure happened later and nginx files are present, the stock service
must be stopped and disabled, and the manual installer needs
`--reuse-stock-nginx`. Do not apply that recovery to a working node.
