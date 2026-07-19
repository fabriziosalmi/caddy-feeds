# Third-Party Notices

`caddy-feeds` aggregates and transforms data published by third parties. This
file documents every upstream source that feeds the released artifacts, the
license each source is distributed under, and the resulting license of the
artifacts this repository publishes.

The aggregation **tooling** in this repository (the Python scripts under
`scripts/`, `config.yaml`, and the GitHub Actions workflow) is licensed under
the MIT License. See [`LICENSE`](LICENSE). MIT covers the tooling **only**; it
does not relicense any third-party data listed below, nor the generated
`rules.json`.

Canonical copies of the referenced license texts are stored under
[`LICENSES/`](LICENSES/).

---

## Released artifacts and their licenses

| Artifact | Nature | License |
|----------|--------|---------|
| `ip_blacklist.txt` | Aggregate of third-party IP feeds | Distributed under the **respective licenses of its sources** (see IP sources below). Each published file carries a `#` NOTICE header pointing here. |
| `dns_blacklist.txt` | Aggregate of a third-party DNS feed | Distributed under the **respective license of its source** (see DNS sources below). Each published file carries a `#` NOTICE header pointing here. |
| `rules.json` and `rules/*.json` | **Derivative work** built from OWASP CRS, Naxsi, and caddy-waf rules | **AGPL-3.0** (see rationale below) |

### Why `rules.json` is AGPL-3.0

`rules.json` (and the per-family files under `rules/`) is a derivative work that
combines rules converted from:

- **OWASP CRS** (Apache-2.0),
- **Naxsi** core rules (GPL-3.0), and
- **caddy-waf** base rules (AGPL-3.0).

When these are merged into a single distributed work, the strongest copyleft
term governs the combination. Apache-2.0 is one-way compatible into GPLv3/AGPLv3
works, and GPL-3.0 is compatible with AGPL-3.0. The resulting combined artifact
is therefore distributed under **AGPL-3.0**. See
[`LICENSES/AGPL-3.0.txt`](LICENSES/AGPL-3.0.txt).

---

## IP blacklist sources (`ip_blacklist.txt`)

| Source | URL | SPDX / Terms | License text |
|--------|-----|--------------|--------------|
| IPsum (`stamparm/ipsum`) | https://github.com/stamparm/ipsum | `Unlicense` (public domain) | [`LICENSES/Unlicense.txt`](LICENSES/Unlicense.txt) |
| CINS Army / CI Army List | https://cinsscore.com/#list | CINS / CI Army community terms — free for community use, attribution requested | https://cinsscore.com/ (upstream terms) |
| Emerging Threats — compromised IPs | https://rules.emergingthreats.net/blockrules/compromised-ips.txt | `GPL-2.0-only` | [`LICENSES/GPL-2.0.txt`](LICENSES/GPL-2.0.txt) |

**Attribution.** IPsum data is released into the public domain by @stamparm.
The CI Army List is provided by the CINS (Collective Intelligence Network
Security) project / Sentinel IPS and is free for community use. Emerging Threats
open rules and lists are provided by Proofpoint / the Emerging Threats community
under GPL-2.0.

## DNS blacklist sources (`dns_blacklist.txt`)

| Source | URL | SPDX | License text |
|--------|-----|------|--------------|
| uBlockOrigin / uAssets — Badware risks | https://github.com/uBlockOrigin/uAssets (`filters/badware.txt`) | `GPL-3.0-only` | [`LICENSES/GPL-3.0.txt`](LICENSES/GPL-3.0.txt) |

**Attribution.** The Badware risks list is maintained by the uBlock Origin /
uAssets project and distributed under GPL-3.0.

## Rule sources (converted into `rules.json` / `rules/*.json`)

| Source | URL | SPDX | License text |
|--------|-----|------|--------------|
| OWASP Coreruleset (CRS) | https://github.com/coreruleset/coreruleset | `Apache-2.0` | [`LICENSES/Apache-2.0.txt`](LICENSES/Apache-2.0.txt) |
| Naxsi core rules (`nbs-system/naxsi`) | https://github.com/nbs-system/naxsi | `GPL-3.0-only` | [`LICENSES/GPL-3.0.txt`](LICENSES/GPL-3.0.txt) |
| caddy-waf base rules (`fabriziosalmi/caddy-waf`) | https://github.com/fabriziosalmi/caddy-waf | `AGPL-3.0-only` | [`LICENSES/AGPL-3.0.txt`](LICENSES/AGPL-3.0.txt) |

**Attribution.** OWASP CRS is a project of the OWASP Foundation, distributed
under Apache-2.0. Naxsi is distributed under GPL-3.0. The caddy-waf base ruleset
is distributed under AGPL-3.0.

---

## Sources removed for licensing/redistribution reasons

The following feeds were previously aggregated but have been **removed** because
their terms do not permit redistribution of the aggregated data (or because the
source is defunct / empty):

- FireHOL Level 1 (`iplists.firehol.org`) — removed
- Spamhaus DROP (`spamhaus.org/drop`) — removed
- BlockList.de (all + SSH, `blocklist.de`) — removed
- GreenSnow (`greensnow.co`) — no redistribution
- AlienVault / OTX IP Reputation (`reputation.alienvault.com`) — EULA, no redistribution
- Binary Defense Banlist (`binarydefense.com/banlist`) — non-commercial terms
- Nozomi Networks Bad IPs (`osint.nozominetworks.com`) — empty / discontinued
- Dragon Research Group (`drg.pt`) — defunct
- Phishing Army (`phishing.army`) — CC BY-NC (non-commercial)

If you maintain one of these feeds and want it re-added under clear
redistribution terms, please open an issue.
