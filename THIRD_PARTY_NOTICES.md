# Third-party components

English · [Русский](THIRD_PARTY_NOTICES.ru.md)

The root MIT license applies to the SiteKit installer. It does not replace
the licenses of third-party programs, source archives, libraries or data.

| Component | Source project | Main license |
| --- | --- | --- |
| 3x-ui | https://github.com/MHSanaei/3x-ui | GPL-3.0 |
| Xray-core | https://github.com/XTLS/Xray-core | MPL-2.0 |
| OpenSSL | https://github.com/openssl/openssl | Apache-2.0 |
| cryptography | https://github.com/pyca/cryptography | Apache-2.0 / BSD |
| Certbot / ACME | https://github.com/certbot/certbot | Apache-2.0 |
| nginx | https://nginx.org/ | nginx's BSD-style license |
| GeoIP / GeoSite | https://github.com/Loyalsoldier/v2ray-rules-dat/releases/tag/202610242205 | GPL-3.0 and the source lists' terms |
| GeoIP generator | https://github.com/Loyalsoldier/geoip/releases/tag/202610230445 | CC-BY-SA-4.0 / GPL-3.0 |

The complete source distribution contains the exact upstream tar archives
for 3x-ui, Xray, OpenSSL, cryptography and the GeoIP/GeoSite generators.
They retain upstream LICENSE, NOTICE and copyright files byte-for-byte.
Verify them using `dependencies/SOURCE-ARCHIVES.sha256`. Exact versions,
source URLs and build recipes are recorded in `dependencies/REBUILD.txt`
and the lockfiles.

This product includes GeoLite2 data created by MaxMind, available from
[MaxMind](https://www.maxmind.com). Source links and attribution for GeoSite
lists are retained in the pinned upstream generator's workflow and README.

`dependencies/notices/index.json` lists copied notices from the supplied
Python wheels, the running binaries' Go modules, Rust and frontend
dependencies. A separate frontend inventory records URLs where license
text was obtained from a published source repository. Distribute the
original notices with the artifacts and preserve them when mirroring.
The complete source distribution and runtime are separate files of the
same release.
