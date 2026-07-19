# caddy-waf feeds

This repository contains a workflow to daily update and release an IP blacklist, a DNS blacklist and OWASP/Naxsi-derived rules for the [caddy-waf](https://github.com/fabriziosalmi/caddy-waf) project. This is useful to avoid the hassle of maintaining updated lists for caddy-waf features like IP, DNS and regex rules blacklisting.

## Lists

### IP blacklist

```
https://github.com/fabriziosalmi/caddy-feeds/releases/download/latest/ip_blacklist.txt
```


### DNS blacklist

```
https://github.com/fabriziosalmi/caddy-feeds/releases/download/latest/dns_blacklist.txt
```

### OWASP rules
> [!WARNING]
> You can use IP and DNS blacklists but DON'T rely on the generated DNS and OWASP rules files at the moment since it will need additional fixes and improvements. I suggest to start with the [base ruleset](https://github.com/fabriziosalmi/caddy-waf/blob/main/rules.go) provided by the caddy-waf repository.

```
https://github.com/fabriziosalmi/caddy-feeds/releases/download/latest/rules.json
```

## Sources

The published artifacts are aggregated **only** from feeds whose terms permit
redistribution. Current sources:

- **IP blacklist** (`ip_blacklist.txt`):
  - IPsum (`stamparm/ipsum`) — Unlicense
  - CI Army List (CINS Score) — community free-to-use
  - Emerging Threats compromised IPs — GPL-2.0
- **DNS blacklist** (`dns_blacklist.txt`):
  - uBlockOrigin / uAssets Badware risks — GPL-3.0
- **Rules** (`rules.json`):
  - OWASP Coreruleset (CRS) — Apache-2.0
  - Naxsi core rules — GPL-3.0
  - caddy-waf base rules — AGPL-3.0

Several feeds that were previously aggregated have been removed because their
terms do not allow redistribution of the aggregated data (or the source is
defunct): FireHOL Level 1, Spamhaus DROP, BlockList.de, GreenSnow, AlienVault
OTX, Binary Defense, Nozomi, Dragon Research Group and Phishing Army. See
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for details.

## Licensing & scope

This repository mixes first-party tooling with third-party data, so licensing is
scoped per component:

- **Tooling** — the aggregation scripts (`scripts/*.py`), `config.yaml` and the
  GitHub Actions workflow are licensed under the **MIT License**
  (`Copyright (c) 2026 Fabrizio Salmi`). See [`LICENSE`](LICENSE).
- **`rules.json`** (and `rules/*.json`) is a **derivative work** built by merging
  OWASP CRS (Apache-2.0), Naxsi (GPL-3.0) and caddy-waf base rules (AGPL-3.0).
  The combined, distributed ruleset is therefore licensed under **AGPL-3.0**.
  See [`LICENSES/AGPL-3.0.txt`](LICENSES/AGPL-3.0.txt).
- **`ip_blacklist.txt`** and **`dns_blacklist.txt`** aggregate third-party feeds
  and are redistributed under the **respective licenses of those feeds**. Each
  published file carries a `#` NOTICE header pointing to
  [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md), which maps every source to
  its license and attribution.

MIT covers the tooling only; it does not relicense the aggregated data or the
generated rules. Canonical license texts are stored under [`LICENSES/`](LICENSES/).
