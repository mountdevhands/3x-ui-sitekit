# Сторонние компоненты

Лицензия MIT в корне относится к коду установщика SiteKit. Она не заменяет
лицензии программ, исходных архивов, библиотек и данных сторонних проектов.

| Компонент | Исходный проект | Основная лицензия |
| --- | --- | --- |
| 3x-ui | https://github.com/MHSanaei/3x-ui | GPL-3.0 |
| Xray-core | https://github.com/XTLS/Xray-core | MPL-2.0 |
| OpenSSL | https://github.com/openssl/openssl | Apache-2.0 |
| cryptography | https://github.com/pyca/cryptography | Apache-2.0 / BSD |
| Certbot / ACME | https://github.com/certbot/certbot | Apache-2.0 |
| nginx | https://nginx.org/ | Собственная BSD-подобная лицензия nginx |
| GeoIP / GeoSite | https://github.com/Loyalsoldier/v2ray-rules-dat/releases/tag/202610242205 | GPL-3.0 и условия источников списков |
| Генератор GeoIP | https://github.com/Loyalsoldier/geoip/releases/tag/202610230445 | CC-BY-SA-4.0 / GPL-3.0 |

Полный исходный комплект содержит точные upstream tars 3x-ui, Xray,
OpenSSL, cryptography и генератора GeoIP/GeoSite. Архивы сохранены
побайтно с upstream LICENSE, NOTICE и copyright. Проверьте их через
`dependencies/SOURCE-ARCHIVES.sha256`. Точные версии, исходные ссылки и
рецепты приведены в `dependencies/REBUILD.txt` и lockfiles.

This product includes GeoLite2 data created by MaxMind, available from
[MaxMind](https://www.maxmind.com). Ссылки и авторство источников списков
GeoSite сохранены в закреплённом workflow и README upstream-генератора.

`dependencies/notices/index.json` перечисляет скопированные уведомления
из поставляемых Python wheels, Go-модулей работающих бинарников, Rust
и frontend-зависимостей. Отдельный реестр frontend содержит URL, когда
текст лицензии получен из опубликованного исходного репозитория.
Подлинные тексты следует распространять вместе с артефактами и сохранять
при зеркалировании. Полный исходный комплект и runtime выпускаются
отдельными файлами одной версии.
