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
