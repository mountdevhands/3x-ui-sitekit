# Changelog

English · [Русский](CHANGELOG.ru.md)

## 0.3.0-rc5-dev — unreleased

- Add a guided Bash `setup.sh` frontend that collects installation choices,
  checks public DNS immediately after the domain input, confirms ACME terms
  and a settings summary, then verifies and launches the immutable rc4
  bootstrap. Defaults remain SSH, XHTTP and generated-site auto. English and
  Russian prompts and a read-only `--dry-run` are available. It installs rc4;
  development QR features remain a separate update.

- Save a plain UTF-8 VLESS QR code in the private access file on installation
  and panel access-mode changes. Automatic QR failures retain usable access
  details with an explicit unavailable message.
- Add `credentials --refresh-file` to update an existing access file without
  changing node identity or services. A QR failure leaves the old file intact.
- Keep `credentials --qr` read-only and pass the VLESS link to the local QR
  renderer through standard input, without ANSI color escapes in its output.
- Add English and Russian documentation, with explicit instructions for
  enabling HTTPS panel access and obtaining a maintenance installer.

Published rc4 assets, bootstrap command and runtime remain unchanged.
Development-source checks do not replace a new release's VPS acceptance.

## 0.3.0-rc4 — 23 November 2026

- Add a separate pinned OpenSSL library bundle for managed nginx.
- Verify its nested manifest before changing the host. Check both libraries
  when starting nginx and compare loaded objects with the process memory map
  during diagnostics.
- Add `install.sh` with an exact tag and SHA-256 values for the two release files.
- Show the access-file location during installation and in `status`, without
  disclosing the private panel path.
- Add maintenance guides, CI and a separate GitHub Releases distribution.

## 0.3.0-rc3 — 23 November 2026

- Generate a new panel path from 32 random hexadecimal characters without a
  text prefix on every clean installation. Preserve it for that installation.
- Add `install --panel-access ssh|https`, defaulting to SSH.
- Add optional repeatable `--panel-allow IP/CIDR` for HTTPS mode.
- Add `panel-access` to switch a ready node while retaining its account,
  path, site, database and certificate.
- Apply panel IP restrictions to the bare URL and nested panel routes,
  preserving the availability of the website and VLESS.
- Add local validation, mode-switching and failure-recovery checks, plus
  routing checks using real nginx with a mock backend.
- Prepare documentation under the 3x-ui SiteKit name.

At rc3, the rc2 dependency bundle was unchanged, full installation on a fresh
VPS had not been accepted, and the GitHub bootstrap was not yet included.
