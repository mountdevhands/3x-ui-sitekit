#!/usr/bin/env bash
# Interactive front end for the unchanged, verified SiteKit rc4 release.

readonly SITEKIT_SETUP_REPOSITORY='mountdevhands/3x-ui-sitekit'
readonly SITEKIT_SETUP_TAG='v0.3.0-rc4'
readonly SITEKIT_SETUP_BOOTSTRAP_SHA256='06df2e8cdbf4ee8e75979e8c4a141aa4f2eb0a87264f2e91ffbf81632cb76328'

setup_text() {
    if [[ "${setup_lang:-en}" == ru ]]; then printf '%s' "$2"; else printf '%s' "$1"; fi
}

setup_line() { setup_text "$1" "$2"; printf '\n'; }

setup_cancel() {
    setup_line 'Cancelled. No installation was started.' 'Отменено. Установка не запускалась.'
    exit "${1:-0}"
}

setup_read() {
    local prompt
    prompt=$(setup_text "$1" "$2")
    if ! IFS= read -r -p "$prompt" REPLY; then setup_cancel 130; fi
}

setup_yes() {
    case "$REPLY" in y|Y|yes|YES|Yes|д|Д|да|ДА|Да) return 0 ;; *) return 1 ;; esac
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
    setup_line 'Usage: bash setup.sh [--lang en|ru] [--dry-run] [--help]' \
               'Запуск: bash setup.sh [--lang en|ru] [--dry-run] [--help]'
    setup_line 'An interactive TTY is required. English is the default language.' \
               'Нужен интерактивный терминал. Язык по умолчанию — английский.'
    setup_line 'Installs the verified v0.3.0-rc4 release on a fresh Ubuntu 26.04 amd64 VPS.' \
               'Устанавливает проверенную v0.3.0-rc4 на чистый VPS Ubuntu 26.04 amd64.'
    setup_line 'The saved-QR feature in the development version is not included in rc4.' \
               'QR в файле доступов из версии разработки в rc4 не включён.'
    setup_line '--dry-run permits non-root preview. It checks public DNS but downloads nothing and changes no system files.' \
               '--dry-run допускает запуск без root: проверяет публичный DNS, но ничего не скачивает и не меняет.'
    setup_line 'Root is required for installation. No download or installation occurs before both terms and summary consent.' \
               'Для установки нужен root. Загрузка и установка начнутся только после согласия с условиями и итогом.'
}

setup_main() (
    set -euo pipefail
    local setup_lang=en dry_run=0 REPLY='' domain='' bind_ip='' email='' panel=ssh theme=auto transport=xhttp
    local value allow_text='' status=0
    local -a allowed=() registration=() arguments=()
    SITEKIT_SETUP_DOWNLOAD_DIR=''
    while (($#)); do
        case "$1" in
            --lang)
                [[ $# -ge 2 && ( "$2" == en || "$2" == ru ) ]] || { printf '%s\n' 'Use --lang en or --lang ru.' >&2; exit 2; }
                setup_lang=$2; shift 2 ;;
            --dry-run) dry_run=1; shift ;;
            --help|-h) setup_help; exit 0 ;;
            *) printf '%s\n' 'Unknown option. Use --help.' >&2; exit 2 ;;
        esac
    done
    [[ -t 0 ]] || { setup_line 'Use an interactive terminal for setup.sh.' 'Запустите setup.sh в интерактивном терминале.' >&2; exit 2; }
    command -v python3 >/dev/null || { setup_line 'python3 is required.' 'Требуется python3.' >&2; exit 2; }
    command -v ip >/dev/null || { setup_line 'The ip command (iproute2) is required to inspect this VPS.' 'Для проверки интерфейсов VPS нужна команда ip (iproute2).' >&2; exit 2; }
    if (( ! dry_run )); then setup_require_root || exit $?; fi
    trap '[[ -z "$SITEKIT_SETUP_DOWNLOAD_DIR" ]] || rm -rf -- "$SITEKIT_SETUP_DOWNLOAD_DIR"' EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    setup_line '3x-ui SiteKit — interactive installation of v0.3.0-rc4' \
               '3x-ui SiteKit — интерактивная установка v0.3.0-rc4'
    setup_line 'Use this on the new VPS. Domain validation performs read-only public DNS requests.' \
               'Запускайте на новом VPS. Проверка домена выполняет только чтение публичного DNS.'
    if (( dry_run )); then setup_line 'DRY RUN: no downloads or installation.' 'ПРЕДПРОСМОТР: без загрузки и установки.'; fi

    while :; do
        setup_read 'Domain (for example node.example.com): ' 'Домен (например node.example.com): '
        if ! domain=$(setup_python domain "$REPLY"); then
            setup_line 'Enter a valid DNS name, without https://, a path or port.' 'Введите корректное DNS-имя без https://, пути и порта.'
            continue
        fi
        while :; do
            setup_line 'Checking public A/AAAA against this server...' 'Проверяю публичные A/AAAA и IPv4 этого сервера...'
            if bind_ip=$(setup_check_dns "$domain"); then
                printf 'DNS OK: %s -> %s\n' "$domain" "$bind_ip"
                break 2
            fi
            setup_read 'DNS failed: [r]etry, [c]hange domain, [q]uit [c]: ' 'DNS не прошёл: [r] повторить, [c] другой домен, [q] отмена [c]: '
            case "$REPLY" in r|R) ;; c|C|'') continue 2 ;; q|Q) setup_cancel ;; *) setup_line 'Choose r, c or q.' 'Выберите r, c или q.' ;; esac
        done
    done

    while :; do
        setup_read 'Certificate email (blank to request registration without email): ' 'Email для сертификата (пусто — регистрация без email): '
        if [[ -z "$REPLY" ]]; then
            setup_read "Register with Let's Encrypt WITHOUT an email address? [y/N]: " "Зарегистрироваться в Let's Encrypt БЕЗ email? [y/N]: "
            if setup_yes; then registration=(--acme-no-email); email=''; break; fi
            setup_line 'Enter an email address, or explicitly confirm registration without email.' 'Введите email либо явно подтвердите регистрацию без email.'
        elif email=$(setup_python email "$REPLY"); then
            registration=(--email "$email"); break
        else
            setup_line 'Enter a valid unquoted email address.' 'Введите корректный email без кавычек.'
        fi
    done

    while :; do
        setup_read 'Panel access: ssh (tunnel) or https (browser) [ssh]: ' 'Доступ к панели: ssh (туннель) или https (браузер) [ssh]: '
        case "$REPLY" in ''|ssh|SSH|1) panel=ssh; break ;; https|HTTPS|2) panel=https; break ;; *) setup_line 'Choose ssh or https.' 'Выберите ssh или https.' ;; esac
    done
    if [[ "$panel" == https ]]; then
        while :; do
            setup_read 'Your computer/client PUBLIC IPs or CIDRs, separated by spaces or commas (blank = any IP): ' 'ПУБЛИЧНЫЕ IP ваших компьютеров/клиентов или CIDR через пробел/запятую (пусто = любой IP): '
            if allow_text=$(setup_python allowlist "$REPLY"); then break; fi
            setup_line 'Use literal IP addresses or CIDRs, up to 128 entries.' 'Введите IP-адреса или CIDR, не более 128 записей.'
        done
        if [[ -n "$allow_text" ]]; then
            while IFS= read -r value; do allowed+=("$value"); done <<< "$allow_text"
        fi
    fi
    while :; do
        setup_read 'Site theme: auto/generative/patterns/palettes/curves [auto]: ' 'Тема сайта: auto/generative/patterns/palettes/curves [auto]: '
        case "$REPLY" in ''|auto) theme=auto; break ;; generative|patterns|palettes|curves) theme=$REPLY; break ;; *) setup_line 'Choose one of the listed themes.' 'Выберите одну из указанных тем.' ;; esac
    done
    while :; do
        setup_read 'Transport: xhttp or ws [xhttp]: ' 'Транспорт: xhttp или ws [xhttp]: '
        case "$REPLY" in ''|xhttp) transport=xhttp; break ;; ws) transport=ws; break ;; *) setup_line 'Choose xhttp or ws.' 'Выберите xhttp или ws.' ;; esac
    done
    setup_line "Read the current Let's Encrypt terms: https://letsencrypt.org/repository/" \
               "Условия Let's Encrypt: https://letsencrypt.org/repository/"
    setup_read 'Do you agree to these terms? [y/N]: ' 'Вы согласны с этими условиями? [y/N]: '
    setup_yes || setup_cancel

    arguments=(--repository "$SITEKIT_SETUP_REPOSITORY" --domain "$domain" --bind-ip "$bind_ip"
               "${registration[@]}" --agree-tos --panel-access "$panel" --site-theme "$theme" --transport "$transport")
    if [[ -n "$allow_text" ]]; then
        for value in "${allowed[@]}"; do arguments+=(--panel-allow "$value"); done
    fi
    setup_line 'Review the installation settings:' 'Проверьте настройки установки:'
    printf '  %s: %s\n' "$(setup_text 'Release' 'Версия')" "$SITEKIT_SETUP_TAG"
    printf '  %s: %s\n' "$(setup_text 'Domain' 'Домен')" "$domain"
    printf '  IPv4: %s\n  Email: %s\n' "$bind_ip" "${email:-(none)}"
    printf '  %s: %s\n' "$(setup_text 'Panel' 'Панель')" "$panel"
    printf '  %s: %s\n' "$(setup_text 'Theme' 'Тема')" "$theme"
    printf '  %s: %s\n' "$(setup_text 'Transport' 'Транспорт')" "$transport"
    if [[ "$panel" == https ]]; then
        if [[ -n "$allow_text" ]]; then printf '  Allow: %s\n' "${allowed[@]}"; else setup_line '  Allow: any IP; panel login/password are still required.' '  Доступ: любой IP; логин и пароль панели обязательны.'; fi
    fi
    setup_line 'Credentials, UUID and the random panel path will be generated by the installer.' \
               'Учётные данные, UUID и случайный путь панели создаст установщик.'
    setup_line 'This installs rc4; the saved-QR feature in development is not included.' \
               'Устанавливается rc4; QR в файле доступов из версии разработки здесь ещё нет.'
    setup_line 'Command after downloading and verifying install.sh:' 'Команда после загрузки и проверки install.sh:'
    printf '  bash %q' './install.sh'
    printf ' %q' "${arguments[@]}"
    printf '\n'
    setup_read 'Proceed with the displayed settings? [y/N]: ' 'Продолжить с указанными настройками? [y/N]: '
    setup_yes || setup_cancel
    if (( dry_run )); then
        setup_line 'Preview complete. No files downloaded and no system changes made.' 'Предпросмотр завершён. Файлы не скачивались, система не изменялась.'
        exit 0
    fi
    command -v curl >/dev/null && command -v sha256sum >/dev/null || {
        setup_line 'curl and sha256sum are required.' 'Требуются curl и sha256sum.' >&2; exit 2;
    }
    umask 077
    SITEKIT_SETUP_DOWNLOAD_DIR=$(mktemp -d /tmp/sitekit-setup.XXXXXXXX)
    setup_download "https://github.com/$SITEKIT_SETUP_REPOSITORY/releases/download/$SITEKIT_SETUP_TAG/install.sh" \
                   "$SITEKIT_SETUP_DOWNLOAD_DIR/install.sh" || { setup_line 'Bootstrap download failed.' 'Не удалось скачать загрузчик.' >&2; exit 1; }
    setup_verify_bootstrap "$SITEKIT_SETUP_DOWNLOAD_DIR/install.sh" || {
        setup_line 'Bootstrap SHA-256 mismatch. Nothing was executed.' 'SHA-256 загрузчика не совпал. Ничего не запускалось.' >&2; exit 1;
    }
    setup_run_bootstrap "$SITEKIT_SETUP_DOWNLOAD_DIR/install.sh" "${arguments[@]}" || status=$?
    if (( status == 0 )); then
        if [[ "$panel" == https ]]; then
            setup_line 'Installed. Read Public panel, Username and Password in /root/https-node-access.txt; open that exact URL in your browser without an SSH tunnel.' \
                       'Установлено. В /root/https-node-access.txt найдите Public panel, Username и Password; откройте точный URL в обычном браузере без SSH-туннеля.'
        else
            setup_line 'Installed. Follow the SSH tunnel instructions and local browser URL in /root/https-node-access.txt.' \
                       'Установлено. Используйте команду SSH-туннеля и локальный URL из /root/https-node-access.txt.'
        fi
    fi
    exit "$status"
)

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    setup_main "$@"
fi
