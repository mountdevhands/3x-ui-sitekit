# Preparing a release

This guide is for maintainers. Users should start with the
[installation wizard](../README.md#install-from-github-releases).

A merge to `main` publishes source code. A tagged GitHub Release publishes
installable assets. The wizard, bootstrap, standalone and documentation must
refer to the same version and exact hashes before those assets are published.

## Inputs for 0.3.0

- A reviewed source checkout with `APP_VERSION = "0.3.0"` in
  `src/installer_core.py`.
- The exact rc4 runtime archive, SHA-256
  `cb2abb5a45b8eee5d30ad0d4e8de6003b088a943ae8f0c2d32af6fec799e787f`.
- The dependency source archives from the full rc4 source release, under their
  original `dependencies/...` paths. Their six hashes are listed in
  `dependencies/SOURCE-ARCHIVES.sha256`.
- Release notes describing changes and the checks actually performed.

The 0.3.0 runtime asset reuses the verified rc4 bytes. The internal approved
runtime identity and dated security policy therefore remain unchanged.
This is an installer and wizard update, not a claim that every dependency
has been rebuilt or reviewed against newer advisories.

## Build the complete release

Run from the source root, using real absolute paths for the input artifacts
and a new output directory:

```bash
python3 -B tools/package_release.py \
  --runtime /path/to/3x-ui-sitekit-0.3.0-rc4-linux-amd64.tar.gz \
  --source-archives-dir /path/to/extracted-rc4-source-root \
  --output /path/to/3x-ui-sitekit-0.3.0-release \
  --notes docs/RELEASE-NOTES-0.3.0.md \
  --sync-source
```

`--source-archives-dir` is the directory containing `dependencies/`, not the
`dependencies/` directory itself. The output directory must not already
exist. The tool uses a staging copy, validates the runtime and source inputs,
builds the standalone, updates the bootstrap and wizard pins, and creates
the source and release manifests. `--sync-source` also brings those generated
pins and manifests back into the source checkout for review and commit.
Without that option the checkout is not changed.

The release contains these seven assets:

| Asset | Content |
| --- | --- |
| `3x-ui-sitekit-0.3.0.py` | Complete standalone installer and maintenance CLI |
| `3x-ui-sitekit-0.3.0-linux-amd64.tar.gz` | Exact approved dependency runtime |
| `setup.sh` | Interactive English/Russian wizard |
| `install.sh` | Version-pinned bootstrap with explicit CLI arguments |
| `3x-ui-sitekit-0.3.0-source.zip` | Project sources and the verified dependency source archives |
| `RELEASE-NOTES.md` | Changes, validation and remaining limitations |
| `SHA256SUMS` | Hashes of the six other release files |

`--repository-source-only` replaces `--source-archives-dir` for an explicitly
incomplete repository-source package, such as a packaging fixture. It is not
the complete source archive described in the table above. Use the complete
source inputs for the normal public release.

## Review the exact candidate

Review the resulting source diff and run the bounded local commands in
[CI](../.github/workflows/ci.yml) once against that candidate. Check shell
scripts separately, so a second file is not interpreted as an argument:

```bash
for script in install.sh setup.sh; do
  bash -n "$script"
done
python3 -B build.py
sha256sum --check --strict SHA256SUMS.txt
```

Verify the release `SHA256SUMS` from inside its output directory. Confirm that
`setup.sh` names `v0.3.0` and hashes the packaged `install.sh`; the latter
must name and hash the packaged standalone and runtime. The README's setup
hash and maintenance-installer hash must match those same files.

For wizard changes, run the real whiptail PTY tests in CI on Ubuntu. The
fixture checks a 72×22 terminal, the English flow with Enter and arrows,
the final review, and cancellation. It uses test DNS and a test installer.

For a stable release, record a controlled clean VPS installation and the
actual checks performed. Capture the candidate hashes, DNS result, certificate
validation, selected panel route, a small VLESS request and local QR decoding.
Report renewal and reboot only if exercised. Use a separate clean test host
or a host explicitly prepared for a fresh installation.

## Publish and verify

Commit the reviewed generated source changes and check the exact commit's CI
result. Create the new `v0.3.0` tag and a stable release on that commit, then
upload all seven generated assets. Keep prior tags and release assets intact.
A release with missing assets is not a working installation source.

Download the published assets without authentication and verify all six
manifest entries. Confirm that the documented startup command points to the
published 0.3.0 wizard and that its SHA-256 is correct. Record the tag, commit,
asset hashes, CI result and actual VPS acceptance result in the release notes.
If a check was not performed, state that explicitly. Avoid publishing access
files, real panel paths, passwords, UUIDs or private server checkpoints.
