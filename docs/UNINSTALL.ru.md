# Удаление

[English](UNINSTALL.md) · Русский

Сначала сохраните [резервную копию](BACKUP.ru.md) и подтвердите точный домен.

```bash
sudo python3 https-node.py uninstall --confirm-domain node.example.com
```

Команда останавливает управляемые службы и удаляет их данные, webroot,
доступы, локальный runtime и запись управляемого сертификата. Пакеты
Ubuntu остаются. `--keep-certificate` оставляет lineage. Для его продления
потребуется рабочий webroot. Чистая установка отклоняет существующий
lineage. Остановленный дистрибутивный nginx после удаления можно
переиспользовать с `install --reuse-stock-nginx`.
