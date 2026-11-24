# 3x-ui SiteKit 0.3.0-rc6

RC6 checks APT trust before creating installation state or changing services.
The terminal wizard detects Ubuntu 26.04 `resolute-backports`, explains the
package policy, and includes the proposed edit in the final confirmation.
The explicit installer flag is `--disable-apt-backports`.

The installer backs up the original `.list` and deb822 `.sources` files in a
private directory, disables only backports, and repeats the full trust check.
It restores the originals if editing or revalidation fails. `check` and
`--dry-run` read configuration only. Unsupported sources report their location
and suite when applicable.

The RC6 runtime contains the exact previously approved nginx OpenSSL, 3x-ui,
Xray, and Certbot payload bytes supplied with RC4 and RC5. The dated package
policy still applies.

See the release description for the actual RC6 server acceptance results.
