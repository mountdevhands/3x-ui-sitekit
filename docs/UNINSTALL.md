# Uninstall

English · [Русский](UNINSTALL.ru.md)

First save a [backup](BACKUP.md), then confirm the exact domain:

```bash
sudo python3 https-node.py uninstall --confirm-domain node.example.com
```

This stops the managed services and removes their data, webroot, access
file, local runtime and managed certificate entry. Ubuntu packages remain
installed. `--keep-certificate` retains the lineage, which still needs a
working webroot for renewal. A fresh installation refuses an existing
lineage. After uninstalling, the stopped distribution nginx may be reused
with `install --reuse-stock-nginx`.
