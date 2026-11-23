# Диагностика

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

Для DNS и ACME сначала сравните A/AAAA с адресом VPS и доступность TCP 80
из внешней сети. В `status` состояние `failed` сопровождается последней
стадией. Приватные логи Certbot находятся в `/var/log/letsencrypt`.
Для ошибки политики проверьте её срок, версии пакетов и значения
`UNKNOWN`/`BLOCKED`. Перед отправкой вывода уберите учётные данные, URI,
приватные пути и данные production-хоста.
