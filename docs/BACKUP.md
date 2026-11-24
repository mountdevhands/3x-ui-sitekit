# Back up and restore data

English · [Русский](BACKUP.ru.md)

Keep a consistent encrypted copy of the following data, preserving owners,
permissions and symbolic links. Certbot uses links between `live` and
`archive`.

| Data | Path |
| --- | --- |
| State, configuration and private site profile | `/etc/https-node` |
| SQLite and panel data, including adjacent SQLite journals | `/var/lib/https-node` |
| Access details, including any saved VLESS QR | `/root/https-node-access.txt` |
| Published website files | `/var/www/https-node` |
| Certificate lineage, private key, ACME account, configuration and hooks | `/etc/letsencrypt` |
| Managed executables and libraries | `/opt/https-node` |
| Unit files | `/etc/systemd/system/https-node-*.service` and `.timer` |

Record the exact installer version, runtime SHA-256, Ubuntu package
versions and service UID/GID. For a consistent copy, take a volume snapshot
in a short maintenance window after stopping both SiteKit services and
the renewal timer. Wait for any active Certbot task to finish. After the
snapshot, start the services and check `status`.

Restore a consistent set on a compatible system. Prepare the same package
versions and service UID/GID, keep services stopped, then restore files,
links, permissions and unit files from the snapshot. After `systemctl
daemon-reload`, check nginx configuration through the managed launcher,
enable the managed services and timer, and check `status`, external TLS,
the panel through a tunnel, and one VLESS request. Test certificate renewal
separately in staging, using the correct `--cert-name`.

Moving to another address requires a separate DNS/IP binding plan. SiteKit
does not provide an automatic snapshot-import command. Diagnostic
checkpoints do not replace these backups.
