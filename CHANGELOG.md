# Changelog

English · [Русский](CHANGELOG.ru.md)

## 0.3.0-rc7 — release candidate

- Continue through the wizard with typing, arrows and Enter.
- Show the Let’s Encrypt agreement and any planned APT change in the final
  Install summary. Text confirmations use `[Y/n]`.
- Cover the minimum 72×22 terminal and cancellation with a whiptail PTY fixture.

## 0.3.0-rc6 — release candidate

- Check APT trust before writing installation state or masking nginx.
- Detect Ubuntu 26.04 backports in the wizard. With explicit consent or
  `--disable-apt-backports`, back up the originals and disable only that pocket.
  Restore the originals if the edit or trust recheck fails.
- Report the offending APT file, line or stanza and suite. Suggest reusing
  stock nginx after cleanup only if nginx files are present.

## 0.3.0-rc5 — release candidate

- Add a terminal setup wizard with a welcome screen, language selection,
  numbered steps and keyboard menus using `whiptail`. English is the default;
  `--lang en|ru` skips the language screen. `--ui auto|dialog|text` supports
  windowed and numbered-text modes.
- Check public DNS immediately after entering the domain. Collect email,
  panel access, optional HTTPS client IP/CIDR restrictions, generated-site
  theme and transport. Defaults remain SSH, auto and XHTTP. Ask for ACME
  terms acceptance and a readable final confirmation before installation.
- Package the wizard with the rc5 bootstrap and installer, with matching
  pinned hashes. The release uses the byte-identical approved rc4 runtime.
- Save a plain UTF-8 VLESS QR code in the private access file during install
  and panel-mode changes. Automatic QR failures retain usable credentials
  and the connection link with an explicit unavailable message.
- Add `credentials --refresh-file` to update an existing access file while
  preserving node identity and services. A QR failure leaves the old file intact.
  `credentials --qr` remains a read-only display.
- Provide English and Russian installation, panel and maintenance instructions,
  including one-command startup and SHA-256 verification.
- Add deterministic release packaging that verifies runtime and dependency
  source archives, synchronizes release pins and emits the complete asset set.

Publication is a separate step from merging source. The historical rc4
acceptance report does not constitute fresh rc5 VPS, ACME or reboot acceptance.
See [release preparation](docs/RELEASING.md) for the remaining publication gates.

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
