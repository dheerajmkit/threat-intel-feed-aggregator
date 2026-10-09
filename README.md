# threat-intel-feed-aggregator

[![CI](https://github.com/dheerajmkit/threat-intel-feed-aggregator/actions/workflows/ci.yml/badge.svg)](https://github.com/dheerajmkit/threat-intel-feed-aggregator/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A small Python 3 CLI tool that merges threat-intelligence IOC feeds
(IPs, domains, URLs, file hashes) from multiple sources into one
deduplicated, scored feed — and exports it as JSON, a plain-text
blocklist, and a STIX 2.1 bundle. Built as a personal portfolio project
to practice security-automation scripting: feed parsing, indicator
validation, cross-source deduplication, and threat-intel exchange
formats.

This is a **personal portfolio project**. It is a learning exercise, not
a production tool, and it has never been deployed at any employer. All
sample indicators are obviously fake (TEST-NET addresses, `example.com`
domains) — never real malicious infrastructure.

## Quickstart

No dependencies to install — the standard library is all you need:

```bash
python3 aggregate.py samples/feed1.json samples/feed2.csv \
    samples/feed3-stix.json samples/vendor-feed.json \
    -o feed.json --blocklist blocklist.txt --stix bundle.json \
    --report report.md --min-score 40 --now 2026-10-07T00:00:00Z
```

Example output:

```
feeds=4 records=24 unique=16 skipped=2 expired=1 -> feed.json + blocklist blocklist.txt + stix bundle.json + report report.md
```

`blocklist.txt` — ready for firewall/proxy ingestion, highest score first:

```
# threat-intel-feed-aggregator blocklist
203.0.113.23
203.0.113.5
malware-test.example
bad-login.example.com
198.51.100.44
```

`bundle.json` — a STIX 2.1 bundle (identity + indicators):

```json
{
  "type": "bundle",
  "id": "bundle--8f3a2c1e-…",
  "objects": [
    {"type": "identity", "name": "threat-intel-feed-aggregator", …},
    {"type": "indicator",
     "pattern": "[ipv4-addr:value = '203.0.113.23']",
     "labels": ["c2"], "confidence": 94, …}
  ]
}
```

## Features

- **Multi-format parsing** — JSON record lists, CSV, and STIX-ish
  JSON bundles (`indicator` STIX patterns); feed name defaults to the
  file stem.
- **Normalization & validation** — `ipaddress` for IPs (canonical
  form, tolerated `:port`), regex for domains, `urllib` for URLs,
  hex/length checks for MD5/SHA-1/SHA-256. Bad records are reported on
  stderr, never silently dropped.
- **Cross-feed dedup** — same `(type, value)` seen in several feeds
  merges into one IOC with combined sightings, earliest `first_seen`,
  latest `last_seen`, and unioned sources/tags.
- **Scoring (0–100)** — `100 × feed_weight × 0.5^(age_days/30) +
  min(sightings×2, 20)`; weights per feed live in
  `threatintel/config.py`, overridable via `--weights`.
- **TTL expiry** — IP/domain 30d, URL 14d, hash 90d (overridable);
  stale IOCs are excluded from outputs and counted, not lost.
- **Three exports** — unified JSON feed, plain-text blocklist
  (IPs/domains/URL-hosts; hashes excluded), deterministic STIX 2.1
  bundle (UUIDv5 IDs, so re-exports diff cleanly).
- **Markdown report** — totals, breakdowns by type and feed, top-10
  IOCs by score.
- **Pytest suite** — 52 tests covering normalization, parsers, dedup,
  scoring, expiry, blocklist, STIX export, and reporting; CI runs
  `py_compile` + pytest on every push.

## How it was built

- **Day 1 — core aggregator.** Multi-format parsing, indicator
  normalization/validation, cross-feed dedup with merged sightings and
  observation windows, unified JSON output.
- **Day 2 — scoring, expiry, blocklist.** Feed-reliability weights,
  recency decay, sighting-count boosts, TTL-based expiry per IOC type,
  plain-text blocklist export, pytest suite.
- **Day 3 — exchange formats and reporting.** Deterministic STIX 2.1
  bundle export, Markdown summary report, GitHub Actions CI workflow,
  `docs/USAGE.md`.

## Docs

- [docs/USAGE.md](docs/USAGE.md) — flags, feed formats, scoring
  formula, config knobs, blocklist ingestion recipe.
- `python3 aggregate.py --help` — full CLI reference.

## Tests

```bash
pip install -r requirements.txt   # pytest
python3 -m pytest tests/ -q
```
