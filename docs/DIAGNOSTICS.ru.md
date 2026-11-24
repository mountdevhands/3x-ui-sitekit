# Диагностика

[English](DIAGNOSTICS.md) · Русский

```bash
sudo python3 https-node.py status
sudo python3 https-node.py security-check
sudo systemctl status https-node-panel.service https-node-nginx.service https-node-certbot.timer
sudo journalctl --since today -u https-node-nginx.service -u https-node-panel.service -u https-node-certbot.service
```

На узле RC4 управляемую конфигурацию nginx можно проверить с той же
OpenSSL, которую использует сервис.

```bash
sudo /opt/https-node/nginx-openssl/nginx -t -c /etc/https-node/nginx.conf
```

## Панель не открывается

| Симптом | Что проверить |
| --- | --- |
| На домене открывается сайт | Нужен точный случайный путь панели из закрытого файла доступов |
| Публичная панель возвращает 404 | По умолчанию включён `ssh`; включите `https` по [инструкции](PANEL-ACCESS.ru.md) |
| Панель возвращает 403 | Текущий публичный IP должен входить в список разрешённых адресов панели |
| Не работает локальная ссылка `127.0.0.1:2053` | Откройте SSH-туннель на том же компьютере, где браузер, и не закрывайте процесс |
| `credentials --refresh-file` не распознан | Это параметр версии разработки после rc4; rc4 поддерживает просмотр `credentials --qr` |
| QR из текста не сканируется | Используйте светлые символы на тёмном фоне, моноширинный шрифт и окно без переноса строк; текстовая VLESS-ссылка остаётся пригодной для импорта |

Для DNS и ACME сначала сравните A/AAAA с адресом VPS и доступность TCP 80
из внешней сети. В `status` состояние `failed` сопровождается последней
стадией. Приватные логи Certbot находятся в `/var/log/letsencrypt`.
Для ошибки политики проверьте её срок, версии пакетов и значения
`UNKNOWN`/`BLOCKED`. Перед отправкой вывода уберите учётные данные, URI,
приватные пути и данные production-хоста.
