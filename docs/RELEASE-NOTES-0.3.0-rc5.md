# 3x-ui SiteKit 0.3.0-rc5

This release candidate brings the interactive installer and saved VLESS QR
into the same pinned installation path.

## Installation experience

- The terminal wizard opens with a language choice. English is selected by
  default; Russian is available. `--lang en` or `--lang ru` skips that choice.
- With `whiptail` and a suitable terminal, settings appear in dialog windows
  with keyboard navigation. `--ui text` provides numbered menus for minimal
  terminals; `--ui auto` selects the available interface.
- A welcome screen explains the requirements, followed by the domain, email,
  panel access, generated-site theme, and transport settings.
- DNS is checked immediately after the domain is entered. The domain must have
  one public A record matching this VPS and no AAAA record.
- The wizard asks for ACME terms consent and a final confirmation before
  downloading the release or starting the installer. Cancelling or running
  `--dry-run` does not start an installation.
- The release wizard, bootstrap, standalone installer, and runtime hashes are
  produced together. The rc5 wizard installs rc5.

## Credentials and panel access

The installer saves the VLESS URI and a plain UTF-8 QR in
`/root/https-node-access.txt`, with root ownership and mode `0600`.
`credentials --refresh-file` refreshes that private file from saved state.
It preserves the panel path, password, UUID, database, site, and services.

Choose HTTPS panel access to open the exact generated panel URL in an ordinary
browser. An optional client IP/CIDR allowlist restricts the panel. The default
panel mode remains an SSH tunnel. The generated site and VLESS connection are
separate from the panel allowlist.

## Runtime and scope

The Linux amd64 runtime is the exact previously approved rc4 runtime, copied
under the rc5 asset name without rebuilding its binaries:

```text
cb2abb5a45b8eee5d30ad0d4e8de6003b088a943ae8f0c2d32af6fec799e787f
```

Its internal security-policy identity remains
`3x-ui-sitekit-0.3.0-rc4-linux-amd64`. The application version is `0.3.0-rc5`.
The dated dependency policy and its expiry remain unchanged. This release
does not claim a new vulnerability audit of those dependencies.

## Validation boundary

Local tests cover the wizard, DNS validation, cancellation, pinned downloads,
credentials, and release packaging. The source includes the commands needed
to reproduce those checks. Packaging verifies the runtime and source-archive
hashes before publishing any output directory.

The earlier rc4 server acceptance remains a historical result. A fresh rc5
installation, production ACME, renew, reboot, and a real VLESS connection must
be recorded separately for rc5; local tests do not establish those results.

See the English and Russian README files for installation and
`docs/RELEASING.md` for the release procedure.
