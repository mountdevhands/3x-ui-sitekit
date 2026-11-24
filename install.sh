#!/usr/bin/env bash
set -euo pipefail

TAG='v0.3.0-rc5'
INSTALLER='3x-ui-sitekit-0.3.0-rc5.py'
RUNTIME='3x-ui-sitekit-0.3.0-rc5-linux-amd64.tar.gz'
INSTALLER_SHA256='419874b25257c3bda3df7dd004bf500c1813b18762cdad7bdf4a908779730663'
RUNTIME_SHA256='cb2abb5a45b8eee5d30ad0d4e8de6003b088a943ae8f0c2d32af6fec799e787f'

fail() { printf '%s\n' "$*" >&2; exit 1; }

check_host() {
    [[ "$(id -u)" = 0 ]] || fail "Run SiteKit as root."
    [[ "$(uname -s)" = Linux && "$(uname -m)" = x86_64 ]] || fail "Linux amd64 is required."
    [[ -r /etc/os-release ]] || fail "Unable to identify this Linux distribution."
    # shellcheck disable=SC1091
    . /etc/os-release
    [[ "${ID:-}" = ubuntu && "${VERSION_ID:-}" = 26.04 ]] || fail "Ubuntu 26.04 is required."
    [[ -d /run/systemd/system ]] || fail "A running systemd host is required."
    /usr/bin/python3 -c 'import platform,sys; sys.exit(not (platform.python_implementation() == "CPython" and sys.version_info[:2] == (3, 14)))' \
        || fail "System CPython 3.14 is required."
    [[ ! -e /etc/https-node && ! -L /etc/https-node ]] || fail "This host already has SiteKit state. Use its maintenance commands."
}

download() {
    curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 10 --max-time 180 --retry 2 --retry-max-time 240 --max-filesize 268435456 \
        --output "$2" "$1"
}

verify_sha() {
    local output
    output=$(sha256sum < "$2") || fail "Unable to hash release file."
    [[ "${output%% *}" = "$1" ]] || fail "Release file integrity check failed."
}

run_installer() { /usr/bin/python3 "$@"; }

main() (
    local repo="" domain="" registration=0 tos=0 base option
    local -a arguments=()
    while (($#)); do
        option=$1
        shift
        case "$option" in
            --repository)
                (($#)) && [[ -z "$repo" ]] || fail 'Provide one --repository OWNER/3x-ui-sitekit.'
                repo=$1; shift ;;
            --domain)
                (($#)) && [[ -z "$domain" ]] || fail 'Provide one --domain example.com.'
                domain=$1; shift ;;
            --email)
                (($#)) && [[ "$1" != --* ]] || fail '--email requires a value.'
                ((registration+=1)); arguments+=("$option" "$1"); shift ;;
            --acme-no-email)
                ((registration+=1)); arguments+=("$option") ;;
            --agree-tos)
                tos=1; arguments+=("$option") ;;
            --bind-ip|--transport|--site-theme|--site-title|--site-description|--site-dir|--panel-access|--panel-allow)
                (($#)) && [[ "$1" != --* ]] || fail "$option requires a value."
                arguments+=("$option" "$1"); shift ;;
            --reuse-stock-nginx) arguments+=("$option") ;;
            *) fail "Unsupported bootstrap option: $option" ;;
        esac
    done
    check_host
    [[ "$repo" =~ ^[A-Za-z0-9][A-Za-z0-9-]{0,38}/3x-ui-sitekit$ ]] || fail 'Use --repository with the verified GitHub owner.'
    if [[ -z "$domain" && -t 0 ]]; then
        read -r -p "Public DNS name: " domain || fail "Unable to read a domain."
    fi
    [[ "$domain" =~ ^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$ ]] || fail 'A public DNS name is required with --domain.'
    ((registration == 1 && tos == 1)) || fail 'Use one of --email/--acme-no-email and explicitly pass --agree-tos.'
    [[ "$INSTALLER_SHA256" =~ ^[0-9a-f]{64}$ && "$RUNTIME_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail 'Release hashes are missing.'
    command -v curl >/dev/null && command -v sha256sum >/dev/null || fail "curl and sha256sum are required."

    umask 077
    DOWNLOAD_DIR="$(mktemp -d /tmp/sitekit.XXXXXXXX)"
    trap 'rm -rf -- "$DOWNLOAD_DIR"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    base="https://github.com/$repo/releases/download/$TAG"
    download "$base/$INSTALLER" "$DOWNLOAD_DIR/$INSTALLER" || fail 'Installer download failed.'
    verify_sha "$INSTALLER_SHA256" "$DOWNLOAD_DIR/$INSTALLER"
    download "$base/$RUNTIME" "$DOWNLOAD_DIR/$RUNTIME" || fail 'Runtime download failed.'
    verify_sha "$RUNTIME_SHA256" "$DOWNLOAD_DIR/$RUNTIME"
    # The outer shell stays alive until its EXIT trap removes both downloads.
    local status=0
    run_installer "$DOWNLOAD_DIR/$INSTALLER" install --domain "$domain" --release-archive "$DOWNLOAD_DIR/$RUNTIME" "${arguments[@]}" || status=$?
    return "$status"
)

if [[ "${BASH_SOURCE[0]}" = "$0" ]]; then
    main "$@"
fi
