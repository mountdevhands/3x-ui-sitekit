# 3x-ui SiteKit

SiteKit устанавливает 3x-ui и Xray на отдельный VPS, настраивает nginx,
TLS и VLESS через XHTTP либо WebSocket и создаёт статический сайт с
процедурно сгенерированными материалами.

**Версия 0.3.0-rc4, кандидат.** Установка по умолчанию открывает панель
через SSH-туннель. nginx и Certbot загружают собственные экземпляры
закреплённой OpenSSL. [Охват проверок и версии](SECURITY.md).

## Что устанавливается

| Компонент | Назначение |
| --- | --- |
| 3x-ui | Управление пользователями и конфигурацией Xray; слушает loopback |
| Xray | VLESS с XHTTP `auto` или WebSocket за nginx |
| nginx | Публичный сайт, TLS и маршруты транспорта; опционально HTTPS-панель |
| Certbot | Получение и продление сертификата; отдельная среда и systemd timer |
| Генератор сайта | Локальные SVG, CSS, JSON и страницы с описанием созданных материалов |

Команда `install` проверяет SHA-256 runtime и вложенные манифесты до
установки. Управляемые пути и службы используют системное имя `https-node`.

## Требования

- Чистый VPS с Ubuntu 26.04, архитектурой amd64, systemd и системным CPython 3.14.
- Root-доступ для установки и обслуживания.
- Публичный IPv4 непосредственно на интерфейсе VPS; DNS A домена указывает на него.
- Отсутствие AAAA-записи у домена: текущая установка рассчитана на IPv4.
- Свободные TCP 80 и 443, доступные извне; исходящий доступ к DNS, APT и ACME.
- Штатные подписанные репозитории Ubuntu своей серии: release, updates и security.

CDN-прокси и NAT перед VPS не поддерживаются этой сборкой. Для установки
нужен отдельный сервер без действующего nginx, другой панели или существующих
Certbot lineages. `check` не заменяет дополнительные проверки Python,
зависимостей и APT, которые выполняет `install`.

## Установка из готовых файлов

Понадобятся `3x-ui-sitekit-0.3.0-rc4.py` и
`3x-ui-sitekit-0.3.0-rc4-linux-amd64.tar.gz`. Runtime скачивается отдельным
файлом поставки. SHA-256 runtime приведён ниже.

```text
cb2abb5a45b8eee5d30ad0d4e8de6003b088a943ae8f0c2d32af6fec799e787f
```

Сверьте загруженные файлы с доверенной копией `SHA256SUMS`, сохраните
установщик локально как `https-node.py` и подставьте свой домен.

```bash
sudo python3 https-node.py check --domain node.example.com

sudo python3 https-node.py install \
  --domain node.example.com \
  --release-archive ./3x-ui-sitekit-0.3.0-rc4-linux-amd64.tar.gz \
  --transport xhttp \
  --panel-access ssh \
  --site-theme auto \
  --email admin@example.com \
  --agree-tos
```

`--agree-tos` подтверждает согласие с условиями ACME-провайдера. Если
регистрация без почты выбрана осознанно, вместо `--email` можно передать
`--acme-no-email`. Не повторяйте выпуск сертификата циклом при ошибке:
сохраните диагностику и устраните её причину.

## Одна команда из GitHub Releases

Источник поставки — [репозиторий mountdevhands/3x-ui-sitekit](https://github.com/mountdevhands/3x-ui-sitekit).
Команда рассчитана на опубликованный и общедоступный `v0.3.0-rc4`.
SHA-256 загрузчика сверьте с доверенной копией манифеста проверенной
поставки. Загрузка соседнего манифеста с того же адреса подтверждает
целостность передачи при условии доверия к самому источнику.

```bash
(
  set -eu
  repo='mountdevhands/3x-ui-sitekit'
  scratch=$(mktemp -d)
  trap 'rm -rf -- "$scratch"' EXIT
  curl -q --fail --silent --show-error --location --proto '=https' \
    --proto-redir '=https' --connect-timeout 10 --max-time 60 --retry 2 \
    --retry-max-time 90 --output "$scratch/install.sh" \
    "https://github.com/$repo/releases/download/v0.3.0-rc4/install.sh"
  (cd "$scratch" && printf '%s  %s\n' \
    06df2e8cdbf4ee8e75979e8c4a141aa4f2eb0a87264f2e91ffbf81632cb76328 install.sh | sha256sum --check --strict)
  sudo bash "$scratch/install.sh" --repository "$repo" \
    --domain node.example.com --email admin@example.com --agree-tos
)
```

[Параметры загрузчика и требования к VPS](docs/INSTALL.md).

## Доступ к панели

При каждой новой чистой установке создаётся путь вида
`/9b62d4e1a7304c8fbe09521d6a84f703/`: 16 криптографически случайных байтов,
записанных 32 шестнадцатеричными символами, без `manage-`, `panel-` или
другого постоянного префикса. Значение не выводится из пароля или домена.
Путь сохраняется в состоянии установки и не меняется от перезагрузки,
продления сертификата или переключения доступа. Уже существующие пути
прежних версий сохраняются при обслуживании.

| Режим | Как войти | Ограничение источника |
| --- | --- | --- |
| `ssh` — по умолчанию | SSH-туннель, затем локальная ссылка | Доступ к SSH |
| `https` без списка IP | HTTPS-ссылка на домене сайта | Обычная авторизация панели |
| `https` со списком IP/CIDR | Та же HTTPS-ссылка | Разрешённый IP и авторизация панели |

Файл `/root/https-node-access.txt` содержит адреса, учётные данные и VLESS-ссылку.
Он доступен только root. Посмотреть доступы можно локально на сервере:

```bash
sudo python3 https-node.py credentials
```

Для режима SSH выполните на своём компьютере команду ниже, затем откройте
локальную ссылку из файла доступов. Замените `SERVER_IP` адресом VPS:

```bash
ssh -N -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:2053:127.0.0.1:2053 root@SERVER_IP
```

Для HTTPS-доступа при установке используйте `--panel-access https` и,
при необходимости, повторяемый `--panel-allow IP/CIDR`.
Адрес в примере ниже учебный; укажите свой внешний адрес:

```text
--panel-access https --panel-allow 198.51.100.24/32
```

На уже установленном узле включить HTTPS-доступ только со своего IP:

```bash
sudo python3 https-node.py panel-access \
  --mode https \
  --allow 198.51.100.24/32 \
  --confirm-domain node.example.com
```

Включить HTTPS без ограничения IP — та же команда без `--allow`.
Вернуть доступ только через SSH:

```bash
sudo python3 https-node.py panel-access \
  --mode ssh \
  --confirm-domain node.example.com
```

Каждый вызов задаёт полный новый список разрешённых IP; это не добавление
к прежнему списку. SSH остаётся доступным при любом режиме. Список IP
применяется в nginx только к маршрутам панели: сайт и VLESS на том же порту
443 сохраняют прежнюю доступность. Для клиентов VLESS SSH-туннель не нужен.
Подробнее: [обслуживание доступа](docs/PANEL-ACCESS.md).

## Генерируемый сайт

При установке `auto` выбирает одну из четырёх тем:

| Тема | Создаваемые материалы |
| --- | --- |
| `generative` | Геометрические композиции |
| `patterns` | Бесшовные SVG-тайлы |
| `palettes` | Палитры, CSS-переменные, параметры цветов |
| `curves` | Кривые Безье и контрольные точки |

Страницы описывают параметры реально созданных SVG; CSS и JSON можно
скачать. В JSON включён SHA-256 изображения. Генерация выполняется локально,
без внешнего LLM и API-ключей. Случайный профиль создаётся один раз и
сохраняется; общие пояснения метода между сайтами могут повторяться.
Также доступны прежние явно выбираемые темы; полный список показывает
`preview-site --help`. Собственный статический сайт можно передать
через `--site-dir`.

Локальный предпросмотр не требует root, DNS или сертификата:

```bash
python3 https-node.py preview-site --domain example.test \
  --site-theme palettes --output ./palette-preview

python3 -m http.server 8080 --bind 127.0.0.1 \
  --directory ./palette-preview/site
```

Откройте `http://127.0.0.1:8080/`. Обслуживайте именно подкаталог `site`,
а не соседний приватный `site-profile.json`.

## Обслуживание

```bash
sudo python3 https-node.py status
sudo python3 https-node.py security-check
sudo python3 https-node.py update-nginx --confirm-domain node.example.com
```

`security-check` сверяет выбранные пакеты и закреплённые зависимости с
датированной политикой. `update-nginx` обслуживает пакеты nginx. Для новых
версий 3x-ui, Xray и Certbot требуется проверенная поставка.
[Политика безопасности](SECURITY.md) · [Обновление](docs/UPDATE.md) ·
[Диагностика](docs/DIAGNOSTICS.md) · [Резервные копии](docs/BACKUP.md) ·
[Удаление](docs/UNINSTALL.md).

Состояние находится в `/etc/https-node/state.json`, база панели —
в `/var/lib/https-node/panel/x-ui.db`, сайт — в `/var/www/https-node`.
Перед переносом или удалением сохраняйте приватную согласованную копию
состояния, базы, файлов сайта и данных Certbot. Диагностические checkpoints
не заменяют полную резервную копию. Не публикуйте их вместе с исходниками.

## Сборка и локальные проверки

```bash
python3 -B build.py
sha256sum -c SHA256SUMS.txt
python3 -B -m unittest discover -s tests -p 'test_release_bootstrap.py'
python3 -B tests/test_artifact_sites.py --module dist/https-node.py
```

Полный набор команд приведён в [локальной CI](.github/workflows/ci.yml).
Для проверки маршрутов и ACL на уже имеющемся локальном nginx выполните
команду ниже.

```bash
python3 -B tests/integration_panel_access.py \
  --nginx /absolute/path/to/nginx --module dist/https-node.py
```

Этот тест использует loopback, временный доверенный тестовым клиентом
сертификат и HTTP/WebSocket-заглушки. Он не устанавливает пакеты и не
заменяет приёмку реальных 3x-ui, VLESS и продления сертификата на VPS.

## Лицензии

Код установщика распространяется по [MIT](LICENSE). Сторонние компоненты
сохраняют собственные лицензии; см. [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)
и исходные архивы в `dependencies/`. Рецепт и сведения о закреплённых
зависимостях: [dependencies/REBUILD.txt](dependencies/REBUILD.txt).
