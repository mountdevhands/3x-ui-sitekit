# Acceptance of 0.3.0-rc4

English translation · [Русский: original report](ACCEPTANCE-0.3.0-rc4.md)

23 November 2026 UTC. One clean installation on a dedicated Ubuntu 26.04.1
LTS amd64 VPS with system CPython 3.14.4. Panel mode: `ssh`; transport:
VLESS XHTTP `auto`; newly generated website theme: `palettes`.

| Check | Result |
| --- | --- |
| Fresh installation | PASS. Signed `resolute`, `resolute-updates` and `resolute-security` repositories. Managed services and timer `active/enabled`; distribution nginx `inactive/disabled`. |
| Runtime | PASS. `nginx` and `nginx-common` source/binary version `1.28.3-2ubuntu1.14`. Running 3x-ui and Xray executables verified through `/proc` against accepted SHA-256 values. |
| OpenSSL | PASS. nginx `libssl` and `libcrypto` checked by path, device/inode and SHA-256. The separate OpenSSL built from commit `20d13b0afd31c8ce269dd16465fb2d9c7fb07db7` was loaded. Certbot/ACME 5.10.0 and Python `ssl`/`cryptography` passed a separate check. |
| TLS | PASS. One production Let's Encrypt issuance. An external client with its normal CA store trusted the chain; SAN matched. Wrong or missing SNI was rejected. Wrong Host and the panel route returned HTTP 404. |
| Website | PASS. Private v2 profile. Verified 24 files and three SVG/CSS/JSON sets, including colors, dimensions and SVG SHA-256. |
| VLESS | PASS. One XHTTP `auto` GET before reboot and one afterward. Both 78-byte responses matched the webroot `robots.txt` SHA-256. |
| Panel | PASS. UI returned HTTP 200 through the SSH tunnel; authenticated API returned the configured inbound. Panel, Xray API and metrics listeners were loopback-only. Port 2096 was absent. |
| Renewal | PASS. One staging dry-run with `--run-deploy-hooks`. Configuration validation and reload were confirmed. Production fullchain bytes stayed identical. The stock `certbot.timer` was absent. |
| Reboot | PASS. One reboot; boot ID changed, SSH and services returned. Profile, state and access-file bytes, certificate and all 24 public-file hashes matched. |
| Visual browser check | SKIPPED. Chromium/Playwright were unavailable in the permitted local environment. |

Certbot's deploy-hook stderr contained nginx warnings about `listen ... http2`
and the configuration-check process's file-descriptor limit. `nginx -t`
succeeded, the journal confirmed reload, and the running nginx had
`RLIMIT_NOFILE` of 65536.

| Artifact | SHA-256 |
| --- | --- |
| 3x-ui 3.11.0, Go 1.27.4 | `752c24d37e9fa196eb53d1cf06774108e659282be45a46ff70bbdacee9f1dcf1` |
| Xray 26.10.21, Go 1.27.4 | `c088ddac2e8bda6bd629bdef94be96b3bfb4d7c16e9a5c65e4003246e3824f90` |
| nginx `libssl.so.3` | `8712ef346d30f30e4dcde34baa940a204f01fb1aa7f344e4a13201e9f91a2151` |
| nginx `libcrypto.so.3` | `6097d4e32bccd08541bca97868687e5edb7c71f46b73cedbcffc4c30dadbc159` |
| Certbot nested `SHA256SUMS` | `d2a90e1562452a185485161081e91a204367dcd5045291ec348922ec2d5d7689` |

The security-check scope is described in [SECURITY.md](../SECURITY.md).

Bootstrap was tested locally with a mock source, an exact tag and two
SHA-256 values. Coverage included successful download, interruption,
HTTP error, wrong hash, unsupported OS and preserving the installer's
exit status. GitHub Release asset availability is checked separately
after publication.

This translation retains the original rc4 acceptance scope. It does not
claim that subsequent development changes or HTTPS panel mode were tested
on that VPS.
