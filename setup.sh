#!/usr/bin/env bash
# Interactive terminal wizard for the pinned SiteKit release.

readonly SITEKIT_SETUP_REPOSITORY='mountdevhands/3x-ui-sitekit'
readonly SITEKIT_SETUP_TAG='v0.3.0-rc6'
readonly SITEKIT_SETUP_BOOTSTRAP_SHA256='9b08fbc3655573fc9a124d31f844bc8c307dbf71177e0b7f8042d0b359e4e209'

setup_text() {
    if [[ "${setup_lang:-en}" == ru ]]; then printf '%s' "$2"; else printf '%s' "$1"; fi
}

setup_line() { setup_text "$1" "$2"; printf '\n'; }

setup_cancel() {
    setup_line 'Cancelled. No installation was started.' 'Отменено. Установка не запускалась.'
    exit "${1:-0}"
}

# The presentation layer never evaluates user input or installs optional packages.
# whiptail is optional; small/minimal terminals keep the same numbered workflow.
setup_read() {
    local prompt
    prompt=$(setup_text "$1" "$2")
    if ! IFS= read -r -p "$prompt" REPLY; then setup_cancel 130; fi
}

setup_yes() {
    case "$REPLY" in y|Y|yes|YES|Yes|д|Д|да|ДА|Да) return 0 ;; *) return 1 ;; esac
}

setup_dialog() {
    local result=0
    REPLY=$(whiptail --title "$setup_title" \
        --backtitle "3x-ui SiteKit  $SITEKIT_SETUP_TAG  |  $(setup_text 'Setup' 'Установка')" \
        --ok-button "$(setup_text 'Next' 'Далее')" \
        --cancel-button "$(setup_text 'Cancel' 'Отмена')" \
        "$@" 3>&1 1>&2 2>&3) || result=$?
    # Closing the completion screen must not change a successful install status.
    if [[ "${setup_complete:-0}" == 1 ]]; then return 0; fi
    case "$result" in
        0) return 0 ;;
        1) return 1 ;;
        130|143|255) setup_cancel 130 ;;
        *) setup_line 'The terminal dialog could not be displayed. Retry with --ui text.' \
                      'Не удалось открыть окно. Повторите с --ui text.' >&2; exit 2 ;;
    esac
}

setup_ui_init() {
    local dimensions='' rows=0 columns=0
    setup_ui=text
    if [[ "$ui_requested" == text ]]; then return; fi
    if [[ -t 0 && -t 1 && -t 2 && -n "${TERM:-}" && "${TERM:-}" != dumb ]] && command -v whiptail >/dev/null; then
        dimensions=$(stty size 2>/dev/null) || dimensions=''
        if [[ "$dimensions" =~ ^([0-9]+)[[:space:]]+([0-9]+)$ ]]; then
            rows=${BASH_REMATCH[1]}; columns=${BASH_REMATCH[2]}
            if (( rows >= 22 && columns >= 72 )); then
                setup_ui=dialog
                setup_width=$((columns - 4)); (( setup_width <= 96 )) || setup_width=96
                setup_height=$((rows - 4)); (( setup_height <= 24 )) || setup_height=24
                return
            fi
        fi
    fi
    if [[ "$ui_requested" == dialog ]]; then
        setup_line 'Dialog mode needs whiptail and an interactive terminal of at least 72 columns by 22 rows. Use --ui text for this console.' \
                   'Для окон нужны whiptail и интерактивный терминал минимум 72 столбца на 22 строки. Для этой консоли используйте --ui text.' >&2
        exit 2
    fi
}

setup_step() {
    setup_title="$1 / 6  $(setup_text "$2" "$3")"
    if [[ "$setup_ui" == text ]]; then printf '\n[%s]\n' "$setup_title"; fi
}

setup_notice() {
    local message
    message=$(setup_text "$1" "$2")
    if [[ "$setup_ui" == dialog ]]; then
        setup_dialog --scrolltext --msgbox "$message" "$setup_height" "$setup_width" || setup_cancel
        if [[ "${setup_complete:-0}" == 1 ]]; then printf '%s\n' "$message"; fi
    else
        printf '%s\n' "$message"
    fi
}

setup_input() {
    local message initial=${3:-}
    message=$(setup_text "$1" "$2")
    if [[ "$setup_ui" == dialog ]]; then
        setup_dialog --inputbox "$message" "$setup_height" "$setup_width" "$initial" || setup_cancel
    else
        printf '%s\n' "$message"
        setup_read '> ' '> '
        # Empty input is meaningful for email and the HTTPS allowlist.
    fi
}

# Arguments: EN prompt, RU prompt, default value, followed by value/EN/RU triples.
setup_choice() {
    local message default=$3 number=0 item='' index=0 found=0
    local -a values=() descriptions=() dialog_items=()
    message=$(setup_text "$1" "$2"); shift 3
    while (($#)); do
        values+=("$1"); descriptions+=("$(setup_text "$2" "$3")"); shift 3
    done
    while :; do
        if [[ "$setup_ui" == dialog ]]; then
            dialog_items=()
            for ((index=0; index<${#values[@]}; index++)); do
                dialog_items+=("${values[$index]}" "${descriptions[$index]}")
            done
            setup_dialog --default-item "$default" --menu "$message" "$setup_height" "$setup_width" \
                "${#values[@]}" "${dialog_items[@]}" || setup_cancel
        else
            printf '%s\n' "$message"
            for ((index=0; index<${#values[@]}; index++)); do
                printf '  %s) %s' "$((index+1))" "${descriptions[$index]}"
                if [[ "${values[$index]}" == "$default" ]]; then printf '  [%s]' "$(setup_text 'default' 'по умолчанию')"; fi
                printf '\n'
            done
            setup_read 'Choose a number, or press Enter for the default: ' 'Введите номер или нажмите Enter для варианта по умолчанию: '
            if [[ -z "$REPLY" ]]; then REPLY=$default; fi
            case "$REPLY" in SSH) REPLY=ssh ;; HTTPS) REPLY=https ;; EN) REPLY=en ;; RU) REPLY=ru ;; esac
            # Compare literal numbers instead of evaluating user text as arithmetic.
            for ((index=0; index<${#values[@]}; index++)); do
                if [[ "$REPLY" == "$((index+1))" ]]; then REPLY=${values[$index]}; break; fi
            done
        fi
        found=0
        for item in "${values[@]}"; do if [[ "$REPLY" == "$item" ]]; then found=1; break; fi; done
        if (( found )); then return; fi
        setup_notice 'Choose one of the listed options.' 'Выберите один из предложенных вариантов.'
    done
}

setup_confirm() {
    local message
    message=$(setup_text "$1" "$2")
    if [[ "$setup_ui" == dialog ]]; then
        setup_dialog --defaultno --yes-button "$(setup_text 'Yes' 'Да')" \
            --no-button "$(setup_text 'No' 'Нет')" --scrolltext --yesno "$message" "$setup_height" "$setup_width"
    else
        printf '%s\n' "$message"
        setup_read 'Confirm? [y/N]: ' 'Подтвердить? [y/N]: '
        setup_yes
    fi
}

setup_dns_progress() {
    local message
    message=$(setup_text 'Checking that your domain points to this server...' 'Проверяю, что домен указывает на этот сервер...')
    if [[ "$setup_ui" == dialog ]]; then
        setup_dialog --infobox "$message" 8 "$setup_width" || setup_cancel
    else
        printf '%s\n' "$message"
    fi
}

setup_python() {
    python3 -B - "$@" <<'SITEKIT_SETUP_PYTHON'
import http.client
import ipaddress
import json
import re
import signal
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

# BEGIN GENERATED APT SOURCE PARSER
"""Read conventional APT sources and plan the single supported pocket change."""

import re
from pathlib import Path
from typing import NamedTuple

APT_BACKPORTS = "resolute-backports"
APT_LIST_LINE = re.compile(r"deb(?:-src)?\s+(?:\[([^]]*)\]\s+)?(\S+)\s+(\S+)(?:\s+.*)?")


class AptSource(NamedTuple):
    fields: dict
    location: str
    start: int
    end: int
    positions: dict


def apt_source_paths(root: Path):
    parts = root / "sources.list.d"
    return [root / "sources.list", *sorted(parts.glob("*.list")), *sorted(parts.glob("*.sources"))]


def apt_source_records(path, text):
    lines = text.splitlines(keepends=True)
    if path.suffix != ".sources":
        for index, raw in enumerate(lines):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            location = f"{path}:{index + 1}"
            match = APT_LIST_LINE.fullmatch(line)
            if not match:
                raise ValueError(f"Unrecognized APT source line in {location}.")
            options = {}
            for item in (match[1] or "").split():
                if "=" not in item:
                    continue
                key, value = item.split("=", 1)
                if key.lower() == "enabled":
                    raise ValueError(f"Enabled is a deb822 field and is unsupported in {location}.")
                if key in options:
                    raise ValueError(f"Duplicate APT option {key} in {location}.")
                options[key] = value
            yield AptSource({**options, "uris": match[2], "suites": match[3]}, location, index, index + 1, {})
        return

    start = 0
    fields, positions, last_key = {}, {}, None
    for index, raw in enumerate([*lines, ""]):
        location = f"{path} (stanza at line {start + 1})"
        if not raw.strip():
            if fields:
                yield AptSource(fields, location, start, index, positions)
            start = index + 1
            fields, positions, last_key = {}, {}, None
        elif raw.startswith("#"):
            continue
        elif raw[:1].isspace() and last_key:
            fields[last_key] += " " + raw.strip()
            positions[last_key].append(index)
        elif re.match(r"^[A-Za-z][A-Za-z0-9-]*:", raw):
            key, value = raw.split(":", 1)
            last_key = key.lower()
            if last_key in fields:
                raise ValueError(f"Duplicate deb822 APT field {key} in {location}.")
            fields[last_key] = value.strip()
            positions[last_key] = [index]
        else:
            raise ValueError(f"Malformed deb822 APT source at {path}:{index + 1}.")


def apt_source_enabled(fields):
    value = fields.get("enabled", "yes").strip().lower()
    # APT's deb822 parser accepts these aliases as well as numeric zero.
    return value not in {"no", "false", "without", "off", "disable"} and not re.fullmatch(r"[+-]?(?:0+|0x0+)", value)


def apt_backports_records(path, text):
    return [record for record in apt_source_records(path, text)
            if apt_source_enabled(record.fields) and APT_BACKPORTS in record.fields.get("suites", "").split()]


def without_apt_backports(path, text, records):
    lines = text.splitlines(keepends=True)
    for record in reversed(records):
        if path.suffix != ".sources":
            lines[record.start] = "# Disabled by SiteKit: " + lines[record.start]
            continue
        suites = record.fields["suites"].split()
        if any(suite != APT_BACKPORTS for suite in suites):
            for position in record.positions["suites"]:
                first = position == record.positions["suites"][0]
                prefix, value = lines[position].split(":", 1) if first else ("", lines[position])
                value = re.sub(r"(?<!\S)" + APT_BACKPORTS + r"(?!\S)", "", value)
                lines[position] = prefix + ":" + value if first else value if value.strip() else ""
        elif "enabled" in record.positions:
            first, *continuations = record.positions["enabled"]
            newline = "\r\n" if lines[first].endswith("\r\n") else "\n" if lines[first].endswith("\n") else ""
            lines[first] = lines[first].split(":", 1)[0] + ": no" + newline
            for position in continuations:
                lines[position] = ""
        else:
            newline = "\r\n" if lines[record.end - 1].endswith("\r\n") else "\n"
            if not lines[record.end - 1].endswith("\n"):
                lines[record.end - 1] += newline
            lines.insert(record.end, "Enabled: no" + newline)
    return "".join(lines)
# END GENERATED APT SOURCE PARSER


class DNSRejected(ValueError):
    pass


class DNSDeadline(Exception):
    pass


def plain(value, limit):
    if not isinstance(value, str) or len(value) > limit or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError('Invalid input')
    return value


def domain_name(value):
    plain(value, 253)
    if not value or value != value.strip() or not value.isascii() or value.endswith('.'):
        raise ValueError('Use an ASCII/Punycode domain, without a URL, port or trailing dot')
    value = value.lower()
    labels = value.split('.')
    if len(labels) < 2 or not any(c.isalpha() for c in labels[-1]):
        raise ValueError('Use a fully qualified DNS name')
    for label in labels:
        if not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label):
            raise ValueError('Invalid DNS label')
        if label.startswith('xn--'):
            if label.encode().decode('idna').encode('idna').decode() != label:
                raise ValueError('Invalid Punycode label')
    return value


def email_address(value):
    plain(value, 254)
    if value.count('@') != 1 or value != value.strip():
        raise ValueError('Use one email address')
    mailbox, domain = value.rsplit('@', 1)
    if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}', mailbox)
            or '..' in mailbox or mailbox.endswith('.')):
        raise ValueError('Use an unquoted email address')
    return mailbox + '@' + domain_name(domain)


def allowlist(value):
    plain(value, 8192)
    entries = [item for item in re.split(r'[ ,]+', value.strip()) if item]
    if value.strip() and not entries:
        raise ValueError('Use IP addresses/CIDRs or leave the input blank')
    if len(entries) > 128:
        raise ValueError('At most 128 IP addresses/CIDRs are supported')
    normalized = []
    for item in entries:
        if '%' in item:
            raise ValueError('Scoped addresses are not supported')
        parsed = ipaddress.ip_network(item, strict=False) if '/' in item else ipaddress.ip_address(item)
        canonical = str(parsed)
        if canonical not in normalized:
            normalized.append(canonical)
    return '\n'.join(normalized)


def message(lang, english, russian):
    return russian if lang == 'ru' else english


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, 'DNS redirect refused', headers, fp)


def dns_name(value):
    if not isinstance(value, str) or not value.isascii() or len(value) > 254:
        raise ValueError('Invalid DNS response name')
    value = (value[:-1] if value.endswith('.') else value).lower()
    if not value or any(not re.fullmatch(r'[a-z0-9_-]{1,63}', part) for part in value.split('.')):
        raise ValueError('Invalid DNS response name')
    return value


def query_dns(opener, resolver, name, kind):
    number = {'A': 1, 'AAAA': 28}[kind]
    query = urllib.parse.urlencode({'name': name + '.', 'type': kind})
    request = urllib.request.Request(resolver + '?' + query, headers={'Accept': 'application/dns-json'})
    with opener.open(request, timeout=5) as response:
        payload = response.read(65537)
    if len(payload) > 65536:
        raise ValueError('DNS response too large')
    reply = json.loads(payload)
    if not isinstance(reply, dict):
        raise ValueError('Invalid DNS response')
    questions = reply.get('Question')
    if (not isinstance(questions, list) or len(questions) != 1
            or not isinstance(questions[0], dict)
            or dns_name(questions[0]['name']) != name or questions[0]['type'] != number
            or type(questions[0]['type']) is not int or reply.get('TC') is not False
            or type(reply.get('Status')) is not int):
        raise ValueError('Invalid DNS response')
    if reply['Status'] == 3:
        raise DNSRejected('NXDOMAIN')
    if reply['Status'] != 0:
        raise ValueError('DNS resolver failure')
    answers = reply.get('Answer', [])
    if not isinstance(answers, list) or len(answers) > 256:
        raise ValueError('Invalid DNS answers')
    aliases = {}
    for row in answers:
        if not isinstance(row, dict) or type(row.get('type')) is not int:
            raise ValueError('Invalid DNS answer')
        if row['type'] == 5:
            owner, target = dns_name(row['name']), dns_name(row['data'])
            if owner in aliases and aliases[owner] != target:
                raise ValueError('Conflicting CNAME')
            aliases[owner] = target
    terminal, visited = name, set()
    while terminal in aliases:
        if terminal in visited or len(visited) >= 16:
            raise ValueError('Invalid CNAME chain')
        visited.add(terminal)
        terminal = aliases[terminal]
    records = set()
    for row in answers:
        if row['type'] == number and dns_name(row['name']) == terminal:
            if '%' in row['data']:
                raise ValueError('Invalid address in DNS')
            address = ipaddress.ip_address(row['data'])
            if address.version != (4 if kind == 'A' else 6):
                raise ValueError('Wrong DNS address family')
            records.add(str(address))
    return records


def public_local_ipv4():
    result = subprocess.run(['ip', '-j', '-4', 'addr', 'show', 'scope', 'global'],
                            capture_output=True, text=True, check=True, timeout=5)
    interfaces = json.loads(result.stdout)
    addresses = set()
    for interface in interfaces:
        for row in interface.get('addr_info', []):
            if row.get('family') == 'inet':
                address = ipaddress.IPv4Address(row['local'])
                if address.is_global and not address.is_multicast and not address.is_unspecified:
                    addresses.add(str(address))
    return addresses


def check_dns_queries(name, lang):
    try:
        local = public_local_ipv4()
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, AttributeError):
        raise DNSRejected(message(lang, 'Cannot inspect local IPv4 interfaces with ip -j.',
                                  'Не удалось прочитать IPv4 интерфейсов через ip -j.')) from None
    if not local:
        raise DNSRejected(message(lang, 'No global IPv4 is configured on this server. NAT/CDN is unsupported.',
                                  'На сервере нет публичного IPv4 интерфейса. NAT/CDN не поддерживаются.'))
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    resolvers = (('Cloudflare', 'https://cloudflare-dns.com/dns-query'),
                 ('Google', 'https://dns.google/resolve'))
    expected, complete = None, []
    for label, endpoint in resolvers:
        observations = {}
        for kind in ('A', 'AAAA'):
            try:
                records = query_dns(opener, endpoint, name, kind)
            except DNSRejected:
                raise DNSRejected(message(lang, f'{label}: domain does not exist in public DNS (NXDOMAIN).',
                                          f'{label}: публичный DNS сообщает, что домена нет (NXDOMAIN).')) from None
            except (OSError, http.client.HTTPException, ValueError, KeyError, TypeError, AttributeError):
                continue
            observations[kind] = records
            if kind == 'AAAA' and records:
                raise DNSRejected(message(lang, f'{label}: remove AAAA records for this IPv4-only release: ',
                                          f'{label}: удалите AAAA для этой IPv4-only версии: ') + ', '.join(sorted(records)))
            if kind == 'A':
                if len(records) != 1:
                    raise DNSRejected(message(lang, f'{label}: exactly one public A record is required.',
                                              f'{label}: требуется ровно одна публичная A-запись.'))
                address = next(iter(records))
                if address not in local:
                    raise DNSRejected(message(lang, f'{label}: A={address}; server IPv4: ',
                                              f'{label}: A={address}; IPv4 сервера: ') + ', '.join(sorted(local)))
                if expected is not None and expected != address:
                    raise DNSRejected(message(lang, 'Public resolvers disagree on the A record; wait for DNS propagation.',
                                              'Публичные резолверы видят разные A-записи; дождитесь обновления DNS.'))
                expected = address
        if set(observations) == {'A', 'AAAA'}:
            complete.append(label)
    if not complete:
        raise DNSRejected(message(lang, 'Neither resolver provided a complete valid A/AAAA answer; check DNS and outbound HTTPS.',
                                  'Ни один резолвер не дал полного ответа A/AAAA; проверьте DNS и исходящий HTTPS.'))
    if len(complete) == 1:
        print(message(lang, f'Warning: only {complete[0]} provided a complete DNS answer.',
                      f'Внимание: полный DNS-ответ получен только от {complete[0]}.'), file=sys.stderr)
    return expected


def check_dns(name, lang):
    def expired(_signum, _frame):
        raise DNSDeadline()
    previous = signal.signal(signal.SIGALRM, expired)
    signal.alarm(30)
    try:
        return check_dns_queries(name, lang)
    except DNSDeadline:
        raise DNSRejected(message(lang, 'Public DNS check exceeded 30 seconds. Retry or change the domain.',
                                  'Проверка публичного DNS превысила 30 секунд. Повторите или измените домен.')) from None
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


def main(argv):
    action = argv[0]
    if action == 'domain':
        result = domain_name(argv[1])
    elif action == 'email':
        result = email_address(argv[1])
    elif action == 'allowlist':
        result = allowlist(argv[1])
    elif action == 'dns':
        result = check_dns(domain_name(argv[1]), argv[2])
    elif action == 'apt-backports':
        locations = []
        try:
            for path in apt_source_paths(Path('/etc/apt')):
                if path.exists() or path.is_symlink():
                    records = apt_backports_records(path, path.read_text(encoding='utf-8'))
                    locations.extend(record.location for record in records)
        except (OSError, ValueError) as error:
            print(str(error), file=sys.stderr)
            raise SystemExit(1)
        result = '\n'.join(locations)
    else:
        raise ValueError('Unknown validation action')
    print(result)


if __name__ == '__main__':
    try:
        main(sys.argv[1:])
    except DNSRejected as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1)
    except (ValueError, UnicodeError, IndexError):
        raise SystemExit(1)
SITEKIT_SETUP_PYTHON
}

setup_check_dns() { setup_python dns "$1" "$setup_lang"; }

setup_find_apt_backports() { setup_python apt-backports; }

setup_require_root() {
    if [[ "$EUID" != 0 ]]; then
        setup_line 'Run with sudo for installation, or use --dry-run for a preview.' \
                   'Для установки запустите через sudo; для предпросмотра используйте --dry-run.' >&2
        return 2
    fi
}

setup_download() {
    curl -q --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --connect-timeout 10 --max-time 60 --retry 2 --retry-max-time 90 --max-filesize 1048576 \
        --output "$2" "$1"
}

setup_verify_bootstrap() {
    local actual
    actual=$(sha256sum < "$1") || return 1
    [[ "${actual%% *}" == "$SITEKIT_SETUP_BOOTSTRAP_SHA256" ]]
}

setup_run_bootstrap() { bash "$@"; }

setup_help() {
    setup_line 'Usage: bash setup.sh [--lang en|ru] [--ui auto|dialog|text] [--dry-run] [--help]' \
               'Запуск: bash setup.sh [--lang en|ru] [--ui auto|dialog|text] [--dry-run] [--help]'
    setup_line 'English is selected by default. Choose Russian on the first screen, or pass --lang ru.' \
               'По умолчанию выбран английский. Выберите русский на первом экране или передайте --lang ru.'
    setup_line 'The wizard uses whiptail windows when available; otherwise it shows numbered text menus.' \
               'Мастер открывает окна whiptail, если они доступны; иначе использует нумерованные текстовые меню.'
    setup_line '--ui dialog requires whiptail and a terminal of at least 72x22. --ui text works in minimal consoles.' \
               '--ui dialog требует whiptail и терминал минимум 72x22. --ui text подходит для минимальных консолей.'
    printf '%s %s\n' "$(setup_text 'Release:' 'Версия:')" "$SITEKIT_SETUP_TAG"
    setup_line 'Use a fresh Ubuntu 26.04 amd64 VPS. Installation requires root.' \
               'Нужен чистый VPS Ubuntu 26.04 amd64. Для установки требуется root.'
    setup_line '--dry-run checks DNS and previews your choices without downloading or installing SiteKit.' \
               '--dry-run проверяет DNS и показывает настройки без скачивания и установки SiteKit.'
}

setup_main() (
    set -euo pipefail
    local setup_lang=en lang_selected=0 ui_requested=auto setup_ui=text setup_complete=0 setup_title='Language / Язык'
    local setup_width=76 setup_height=20 dry_run=0 REPLY='' domain='' bind_ip='' email='' panel=ssh theme=auto transport=xhttp
    local value allow_text='' status=0 dns_result='' dns_warning='' summary='' panel_label='' allowed_label='' apt_changes=''
    local -a allowed=() registration=() arguments=()
    SITEKIT_SETUP_DOWNLOAD_DIR=''
    while (($#)); do
        case "$1" in
            --lang)
                [[ $# -ge 2 && ( "$2" == en || "$2" == ru ) ]] || { printf '%s\n' 'Use --lang en or --lang ru.' >&2; exit 2; }
                setup_lang=$2; lang_selected=1; shift 2 ;;
            --ui)
                [[ $# -ge 2 && ( "$2" == auto || "$2" == dialog || "$2" == text ) ]] || { printf '%s\n' 'Use --ui auto, --ui dialog or --ui text.' >&2; exit 2; }
                ui_requested=$2; shift 2 ;;
            --dry-run) dry_run=1; shift ;;
            --help|-h) setup_help; exit 0 ;;
            *) printf '%s\n' 'Unknown option. Use --help.' >&2; exit 2 ;;
        esac
    done
    [[ -t 0 ]] || { setup_line 'Open an interactive SSH session or server console to run the wizard.' 'Запустите мастер в интерактивном SSH-сеансе или консоли сервера.' >&2; exit 2; }
    command -v python3 >/dev/null || { setup_line 'python3 is required.' 'Требуется python3.' >&2; exit 2; }
    command -v ip >/dev/null || { setup_line 'The ip command (iproute2) is required to inspect this VPS.' 'Для проверки интерфейсов VPS нужна команда ip (iproute2).' >&2; exit 2; }
    if (( ! dry_run )); then setup_require_root || exit $?; fi
    trap '[[ -z "$SITEKIT_SETUP_DOWNLOAD_DIR" ]] || rm -rf -- "$SITEKIT_SETUP_DOWNLOAD_DIR"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    setup_ui_init
    if (( ! lang_selected )); then
        setup_choice 'Choose your language / Выберите язык' 'Choose your language / Выберите язык' en \
            en 'English' 'English' ru 'Русский' 'Русский'
        setup_lang=$REPLY
    fi
    setup_title=$(setup_text 'Welcome to SiteKit' 'Добро пожаловать в SiteKit')
    setup_notice \
        $'Set up your own 3x-ui server in six steps.\n\nWe will configure the panel, a generated website, HTTPS and VLESS. Your login details and QR code will be saved on the server.\n\nBefore you begin:\n- A fresh Ubuntu 26.04 amd64 VPS\n- A domain with one A record pointing to this VPS, and no AAAA record\n- Public TCP ports 80 and 443 available\n\nUse the arrow keys and Tab in windows, then Enter. Esc cancels the wizard.' \
        $'Настройте свой сервер 3x-ui за шесть шагов.\n\nМастер подготовит панель, сгенерированный сайт, HTTPS и VLESS. Доступы и QR-код будут сохранены на сервере.\n\nПеред началом нужны:\n- Чистый VPS Ubuntu 26.04 amd64\n- Домен с одной A-записью на этот VPS, без AAAA\n- Доступные извне TCP-порты 80 и 443\n\nВ окнах используйте стрелки, Tab и Enter. Esc отменяет мастер.'
    if (( dry_run )); then
        setup_notice 'PREVIEW MODE: DNS will be checked, but SiteKit will not be downloaded or installed.' \
                     'ПРЕДПРОСМОТР: мастер проверит DNS, но не будет скачивать и устанавливать SiteKit.'
    fi
    if ! apt_changes=$(setup_find_apt_backports 2>&1); then
        setup_notice "Could not read APT sources: $apt_changes" "Не удалось прочитать источники APT: $apt_changes"
        setup_cancel 1
    fi
    if [[ -n "$apt_changes" ]]; then
        setup_confirm \
            $'resolute-backports is enabled and is outside the verified SiteKit package set.\n\nAffected entries:\n'"$apt_changes"$'\n\nBack up the original files and disable only resolute-backports when installation starts?' \
            $'Активен resolute-backports. Он не входит в проверенный набор пакетов SiteKit.\n\nЗатронутые записи:\n'"$apt_changes"$'\n\nСохранить оригиналы и отключить только resolute-backports при установке?' || setup_cancel
    fi

    setup_step 1 'Domain and DNS' 'Домен и DNS'
    while :; do
        setup_input $'Domain\n\nEnter the name visitors will use, for example node.example.com. Use the name only, without https:// or a path.' \
                    $'Домен\n\nУкажите имя для подключения, например node.example.com. Только имя: без https:// и пути.' "$domain"
        if ! domain=$(setup_python domain "$REPLY"); then
            setup_notice 'Enter a valid DNS name, without https://, a path or port.' 'Введите корректное DNS-имя без https://, пути и порта.'
            continue
        fi
        while :; do
            setup_dns_progress
            if dns_result=$(setup_check_dns "$domain" 2>&1); then
                bind_ip=${dns_result##*$'\n'}
                if [[ "$dns_result" != "$bind_ip" ]]; then
                    dns_warning=${dns_result%$'\n'*}
                    setup_notice "$dns_warning" "$dns_warning"
                fi
                printf 'DNS OK: %s -> %s\n' "$domain" "$bind_ip"
                break 2
            fi
            setup_notice "$dns_result" "$dns_result"
            setup_choice 'The domain is not ready yet. What would you like to do?' \
                         'Домен пока не готов. Что сделать?' c \
                         r 'Check again after updating DNS' 'Проверить снова после изменения DNS' \
                         c 'Enter another domain' 'Указать другой домен' \
                         q 'Cancel setup' 'Отменить установку'
            case "$REPLY" in r) ;; c) continue 2 ;; q) setup_cancel ;; esac
        done
    done

    setup_step 2 'HTTPS certificate' 'Сертификат HTTPS'
    while :; do
        setup_input $'Certificate email\n\nEnter an email address for your Let\'s Encrypt account. You may leave this blank and explicitly choose registration without email.' \
                    $'Email для сертификата\n\nУкажите email для учётной записи Let\'s Encrypt. Можно оставить поле пустым и отдельно подтвердить регистрацию без email.' "$email"
        if [[ -z "$REPLY" ]]; then
            if setup_confirm "Register with Let's Encrypt WITHOUT an email address?" "Зарегистрироваться в Let's Encrypt БЕЗ email?"; then
                registration=(--acme-no-email); email=''; break
            fi
        elif email=$(setup_python email "$REPLY"); then
            registration=(--email "$email"); break
        else
            setup_notice 'Enter a valid unquoted email address.' 'Введите корректный email без кавычек.'
        fi
    done

    setup_step 3 'Panel access' 'Вход в панель'
    setup_choice 'How would you like to open the admin panel?' 'Как вы хотите открывать панель управления?' ssh \
        ssh 'Private: open through an SSH tunnel' 'Приватно: через SSH-туннель' \
        https 'Browser: open a unique HTTPS link' 'В браузере: по уникальной HTTPS-ссылке'
    panel=$REPLY
    if [[ "$panel" == https ]]; then
        while :; do
            setup_input $'Allowed client IPs (optional)\n\nTo restrict panel access, enter the PUBLIC IP of your computer or a CIDR such as 198.51.100.24/32. Separate multiple entries with spaces or commas.\n\nLeave blank to allow any IP; a login and password will still be required.' \
                        $'Разрешённые IP клиентов (необязательно)\n\nДля ограничения доступа укажите ПУБЛИЧНЫЙ IP своего компьютера или CIDR, например 198.51.100.24/32. Несколько адресов разделяйте пробелом или запятой.\n\nПустое поле разрешает любой IP; логин и пароль остаются обязательными.'
            if allow_text=$(setup_python allowlist "$REPLY"); then break; fi
            setup_notice 'Use literal IP addresses or CIDRs, up to 128 entries.' 'Введите IP-адреса или CIDR, не более 128 записей.'
        done
        if [[ -n "$allow_text" ]]; then
            while IFS= read -r value; do allowed+=("$value"); done <<< "$allow_text"
        fi
    fi

    setup_step 4 'Website style' 'Стиль сайта'
    setup_choice 'Choose the theme for your automatically generated website.' 'Выберите тему автоматически создаваемого сайта.' auto \
        auto 'Surprise me: choose a theme automatically' 'Выбрать тему автоматически' \
        generative 'Generative: geometric compositions' 'Генеративная графика: геометрические композиции' \
        patterns 'Patterns: repeating SVG tiles' 'Паттерны: повторяющиеся SVG-узоры' \
        palettes 'Palettes: colours and downloadable CSS' 'Палитры: цвета и CSS для скачивания' \
        curves 'Curves: Bezier drawings and control points' 'Кривые: рисунки Безье и контрольные точки'
    theme=$REPLY

    setup_step 5 'Connection type' 'Тип подключения'
    setup_choice 'Choose the VLESS transport. Keep XHTTP unless you specifically need WebSocket.' \
                 'Выберите транспорт VLESS. Оставьте XHTTP, если вам не нужен именно WebSocket.' xhttp \
                 xhttp 'XHTTP (recommended)' 'XHTTP (рекомендуется)' \
                 ws 'WebSocket' 'WebSocket'
    transport=$REPLY

    setup_step 6 'Review and install' 'Проверка и установка'
    if ! setup_confirm \
        $'Let\'s Encrypt provides the HTTPS certificate.\n\nRead the terms: https://letsencrypt.org/repository/\n\nDo you agree to these terms?' \
        $'Let\'s Encrypt выпускает сертификат HTTPS.\n\nУсловия: https://letsencrypt.org/repository/\n\nВы согласны с этими условиями?'; then setup_cancel; fi
    arguments=(--repository "$SITEKIT_SETUP_REPOSITORY" --domain "$domain" --bind-ip "$bind_ip"
               "${registration[@]}" --agree-tos --panel-access "$panel" --site-theme "$theme" --transport "$transport")
    if [[ -n "$apt_changes" ]]; then arguments+=(--disable-apt-backports); fi
    if [[ -n "$allow_text" ]]; then
        for value in "${allowed[@]}"; do arguments+=(--panel-allow "$value"); done
    fi
    if [[ "$panel" == https ]]; then
        panel_label=$(setup_text 'HTTPS link in your browser' 'HTTPS-ссылка в браузере')
        allowed_label=${allow_text:-$(setup_text 'Any IP, with login and password' 'Любой IP, с логином и паролем')}
    else
        panel_label=$(setup_text 'Private, through an SSH tunnel' 'Приватно, через SSH-туннель')
        allowed_label=$(setup_text 'SSH access only' 'Только SSH-доступ')
    fi
    summary=$(printf '%s: %s\n%s: %s\nIPv4: %s\nEmail: %s\n%s: %s\n%s: %s\n%s: %s\n%s: %s\n\n%s' \
        "$(setup_text 'Release' 'Версия')" "$SITEKIT_SETUP_TAG" \
        "$(setup_text 'Domain' 'Домен')" "$domain" "$bind_ip" "${email:-$(setup_text '(without email)' '(без email)')}" \
        "$(setup_text 'Panel' 'Панель')" "$panel_label" "$(setup_text 'Allowed clients' 'Доступ клиентов')" "$allowed_label" \
        "$(setup_text 'Website' 'Сайт')" "$theme" "$(setup_text 'Transport' 'Транспорт')" "$transport" \
        "$(setup_text 'Your panel login, random panel address and VLESS link/QR will be generated automatically.' 'Логин, пароль, случайный адрес панели и VLESS-ссылка/QR будут созданы автоматически.')")
    if [[ -n "$apt_changes" ]]; then
        summary="$summary"$'\n\n'"$(setup_text 'APT during installation: back up original files and disable only resolute-backports.' 'APT при установке: сохранить оригиналы и отключить только resolute-backports.')"$'\n'"$apt_changes"
    fi
    if (( dry_run )); then
        summary="$summary"$'\n\n'"$(setup_text 'Complete this preview?' 'Завершить предпросмотр?')"
    else
        summary="$summary"$'\n\n'"$(setup_text 'Install SiteKit with these settings?' 'Установить SiteKit с этими настройками?')"
    fi
    setup_confirm "$summary" "$summary" || setup_cancel
    if (( dry_run )); then
        setup_line 'Command after downloading and verifying install.sh:' 'Команда после загрузки и проверки install.sh:'
        printf '  bash %q' './install.sh'
        printf ' %q' "${arguments[@]}"
        printf '\n'
        setup_line 'Preview complete. No files downloaded and no system changes made.' 'Предпросмотр завершён. Файлы не скачивались, система не изменялась.'
        exit 0
    fi
    command -v curl >/dev/null && command -v sha256sum >/dev/null || {
        setup_line 'curl and sha256sum are required.' 'Требуются curl и sha256sum.' >&2; exit 2;
    }
    setup_title=$(setup_text 'Installing SiteKit' 'Установка SiteKit')
    setup_line 'Downloading the verified installer. Progress will appear below.' 'Скачиваю проверенный установщик. Ход установки появится ниже.'
    umask 077
    SITEKIT_SETUP_DOWNLOAD_DIR=$(mktemp -d /tmp/sitekit-setup.XXXXXXXX)
    setup_download "https://github.com/$SITEKIT_SETUP_REPOSITORY/releases/download/$SITEKIT_SETUP_TAG/install.sh" \
                   "$SITEKIT_SETUP_DOWNLOAD_DIR/install.sh" || { setup_line 'Bootstrap download failed.' 'Не удалось скачать загрузчик.' >&2; exit 1; }
    setup_verify_bootstrap "$SITEKIT_SETUP_DOWNLOAD_DIR/install.sh" || {
        setup_line 'Bootstrap SHA-256 mismatch. Nothing was executed.' 'SHA-256 загрузчика не совпал. Ничего не запускалось.' >&2; exit 1;
    }
    setup_run_bootstrap "$SITEKIT_SETUP_DOWNLOAD_DIR/install.sh" "${arguments[@]}" || status=$?
    if (( status == 0 )); then
        setup_complete=1
        setup_title=$(setup_text 'SiteKit is ready' 'SiteKit готов')
        if [[ "$panel" == https ]]; then
            setup_notice $'Installed.\n\nRun: cat /root/https-node-access.txt\n\nOpen the exact Public panel URL in your browser and use the Username and Password from that file. You can log in without an SSH tunnel.\n\nThe same file contains your VLESS link and QR code for importing into a client.' \
                         $'Установлено.\n\nВыполните: cat /root/https-node-access.txt\n\nОткройте точный URL Public panel в браузере и введите Username и Password из этого файла. Вход работает без SSH-туннеля.\n\nВ том же файле находятся VLESS-ссылка и QR-код для импорта в клиент.'
        else
            setup_notice $'Installed.\n\nRun: cat /root/https-node-access.txt\n\nFollow the SSH tunnel command and local browser URL in that file to open the panel.\n\nVLESS clients connect directly using the link or QR code in the same file.' \
                         $'Установлено.\n\nВыполните: cat /root/https-node-access.txt\n\nИспользуйте команду SSH-туннеля и локальный URL из этого файла для входа в панель.\n\nVLESS-клиенты подключаются напрямую по ссылке или QR-коду из того же файла.'
        fi
    fi
    exit "$status"
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    setup_main "$@"
fi
