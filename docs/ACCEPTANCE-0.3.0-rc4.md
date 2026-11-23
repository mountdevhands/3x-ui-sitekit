# Приёмка 0.3.0-rc4

23 ноября 2026 UTC. Одна чистая установка на Ubuntu 26.04.1 LTS amd64
с системным CPython 3.14.4 на выделенном VPS. Режим панели `ssh`,
транспорт VLESS XHTTP `auto`, новая тема `palettes`.

| Проверка | Результат |
| --- | --- |
| Чистая установка | PASS. Подписанные `resolute`, `resolute-updates`, `resolute-security`. Собственные службы и таймер `active/enabled`. Ubuntu nginx `inactive/disabled`. |
| Runtime | PASS. `nginx` и `nginx-common` source/binary `1.28.3-2ubuntu1.14`. Исполняемые файлы 3x-ui и Xray сверены через `/proc` с проверенными SHA-256. |
| OpenSSL | PASS. `libssl` и `libcrypto` nginx сверены по путям, device/inode и SHA-256. Загружена отдельная OpenSSL из commit `20d13b0afd31c8ce269dd16465fb2d9c7fb07db7`. Certbot/ACME 5.10.0 и его Python `ssl`/`cryptography` прошли отдельную проверку. |
| TLS | PASS. Один production-выпуск Let's Encrypt. Цепочка проверена внешним клиентом с обычным хранилищем CA, SAN совпал. Неверный или отсутствующий SNI отклонён. Неверный Host и маршрут панели вернули HTTP 404. |
| Сайт | PASS. Приватный профиль v2. Сверены 24 файла и 3 комплекта SVG/CSS/JSON, включая цвета, размеры и SHA-256 SVG. |
| VLESS | PASS. Один GET через XHTTP `auto` до reboot и один после. Оба ответа по 78 байт, совпали с SHA-256 `robots.txt` из webroot. |
| Панель | PASS. UI ответил HTTP 200 через SSH-туннель, авторизованный API вернул настроенный inbound. Панель, Xray API и metrics слушают loopback. Порт 2096 отсутствует. |
| Продление | PASS. Один staging dry-run с `--run-deploy-hooks`. Проверка конфигурации и reload подтверждены. Production fullchain побайтно сохранился. Штатный `certbot.timer` отсутствовал. |
| Reboot | PASS. Одна перезагрузка, изменился boot ID, SSH и службы восстановились. Профиль, байты состояния и файла доступов, сертификат и SHA-256 всех 24 публичных файлов совпали. |
| Визуальная проверка | SKIPPED. В разрешённой локальной среде не было Chromium/Playwright. |

Certbot показал stderr deploy-hook, в котором nginx сообщил предупреждения
про `listen ... http2` и лимит дескрипторов проверочного процесса. `nginx -t`
завершился успешно, журнал зафиксировал reload, у рабочего nginx
`RLIMIT_NOFILE` составил 65536.

| Артефакт | SHA-256 |
| --- | --- |
| 3x-ui 3.11.0, Go 1.27.4 | `752c24d37e9fa196eb53d1cf06774108e659282be45a46ff70bbdacee9f1dcf1` |
| Xray 26.10.21, Go 1.27.4 | `c088ddac2e8bda6bd629bdef94be96b3bfb4d7c16e9a5c65e4003246e3824f90` |
| nginx `libssl.so.3` | `8712ef346d30f30e4dcde34baa940a204f01fb1aa7f344e4a13201e9f91a2151` |
| nginx `libcrypto.so.3` | `6097d4e32bccd08541bca97868687e5edb7c71f46b73cedbcffc4c30dadbc159` |
| Certbot, вложенный `SHA256SUMS` | `d2a90e1562452a185485161081e91a204367dcd5045291ec348922ec2d5d7689` |

Область security-проверки описана в [SECURITY.md](../SECURITY.md).

Bootstrap проверен локально на подставном источнике с точным тегом и двумя
SHA-256. Покрыты успешная загрузка, обрыв, HTTP-ошибка, неверный hash,
неподдерживаемая ОС и сохранение exit status. Доступность GitHub Release
assets проверяется отдельно после публикации.
