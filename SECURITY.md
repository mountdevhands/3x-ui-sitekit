# Security checks

English · [Русский](SECURITY.ru.md)

## Scope

`security-check` reads selected package information and node state. It does
not update APT, install software or stop services. Its result applies to
the rules in `src/security_policy.py`, full distribution package versions
and the exact pinned runtime SHA-256.

Policy identifier: `https-node-curated-2026-11-23`. It expires at
**2026-12-23 00:00 UTC**. After expiry, new `install` and `update-nginx`
operations require a policy update; the running service is not shut down.
Unknown branches or unconfirmed backports do not become accepted merely
because their version number is higher.

`security-check` exit codes:

| Code | Meaning |
| --- | --- |
| `0` | The checked data satisfies this policy |
| `2` | BLOCKED, UNKNOWN or STALE |
| `1` | An execution error |

PASS does not mean that the entire OS or every execution path has been
checked for every known CVE.

## OpenSSL used by nginx and Certbot

RC4 includes the eight CVE fixes from the OpenSSL advisories of 10 and
17 November 2026 at pinned commit `20d13b0` on the `openssl-3.5` branch.
Exact fix commits and source hashes are recorded in `dependencies/`.
The Ubuntu 26.04 `openssl`/`libssl3t64` candidate reviewed at that time had
source/binary version `3.5.5-1ubuntu3.7`; Ubuntu was still evaluating the
listed November CVEs for that series on the review date.

Managed nginx loads its own two libraries from
`/opt/https-node/nginx-openssl/lib`. The installer verifies a separate
manifest before writing state. The launcher verifies both libraries before
invoking nginx, and `security-check` compares the path, device, inode and
SHA-256 of the objects mapped into the master process. Certbot and its
Python modules use their own library copy in a separate directory.
Ubuntu continues to maintain the OpenSSL packages used by the rest of
the operating system.

## Updates

Dependency changes receive a new version with pinned sources, lockfiles,
manifests, build information and focused checks of affected behavior.
Do not replace the approved archive hash with an arbitrary value to bypass
installation checks. A hash downloaded from the same unverified source
does not independently establish authorship.

`update-nginx` updates only the approved nginx package set. APT does not
provide atomic rollback; retained diagnostics help investigate failures.
3x-ui, Xray and Certbot fixes are released separately.

## Private data and reports

Do not publish `state.json`, `https-node-access.txt`, the panel database,
private keys, ACME accounts, real VLESS links or diagnostic checkpoints.
A saved QR code contains the same connection secret as its VLESS link.
Use documentation domains, example IPs and synthetic credentials when
reproducing an issue.

Keep secrets out of public issues. Reports should include the version,
a sanitized reproduction, the observed result and the relevant log excerpts.
If a private reporting channel is needed, confirm its availability before
sending sensitive details.

## Primary references

- [Ubuntu nginx notice](https://ubuntu.com/security/notices/USN-9182-1)
- [Ubuntu OpenSSL notice](https://ubuntu.com/security/notices/USN-8861-1)
- [Certbot advisory](https://github.com/certbot/certbot/security/advisories/GHSA-9qv6-9g6h-3x7x)
- [OpenSSL advisory, 10 November](https://openssl-library.org/news/secadv/20261110.txt)
- [OpenSSL advisory, 17 November](https://openssl-library.org/news/secadv/20261117.txt)
- [Pinned OpenSSL commit](https://github.com/openssl/openssl/commit/20d13b0afd31c8ce269dd16465fb2d9c7fb07db7)
- [nginx access module](https://nginx.org/en/docs/http/ngx_http_access_module.html)
- Exact dependency sources and hashes: [dependencies/REBUILD.txt](dependencies/REBUILD.txt).
