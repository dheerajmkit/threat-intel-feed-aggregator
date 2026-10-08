# threat-intel-feed-aggregator

A small Python 3 CLI tool that merges threat-intelligence IOC feeds
(IPs, domains, URLs, file hashes) from multiple sources into one
deduplicated, normalized feed. Built as a personal portfolio project to
practice security-automation scripting: feed parsing, indicator
validation, and cross-source deduplication.

This is a **personal portfolio project**. It is a learning exercise, not
a production tool, and it has never been deployed at any employer. All
sample indicators are obviously fake (TEST-NET addresses, `example.com`
domains) — never real malicious infrastructure.

## Quickstart

No dependencies to install — the standard library is all you need:

```bash
python3 aggregate.py samples/feed1.json samples/feed2.csv -o feed.json
```

Example output:

```
feeds=2 records=16 unique=13 skipped=2 -> feed.json
```

`feed.json` holds the unified feed:

```json
{
  "meta": {
    "generated_at": "2026-10-07T12:00:00+00:00",
    "ioc_count": 13,
    "source_feeds": ["feed1", "feed2"],
    "format": "threat-intel-feed-aggregator/v1"
  },
  "iocs": [
    {
      "type": "ip",
      "value": "203.0.113.5",
      "first_seen": "2026-09-20T00:00:00+00:00",
      "last_seen": "2026-10-06T00:00:00+00:00",
      "sightings": 2,
      "sources": ["feed1", "feed2"],
      "tags": ["c2", "phishing"],
      "score": 89.53
    }
  ]
}
```

IOCs in `feed.json` are sorted by score (highest first).

## Supported feed formats

| Format | Extension | Notes |
| ------ | --------- | ----- |
| JSON   | `.json`    | List of `{"type","value","first_seen","last_seen","tags"}` records |
| STIX-ish JSON | `.json` | `{"objects": [...]}` bundle with `indicator` STIX patterns |
| CSV    | `.csv`     | Header row: `type,value,first_seen,last_seen,tags` (`;`-separated tags) |

Timestamps are ISO-8601 (`Z` suffix accepted). The feed name defaults to
the file stem.

## How it works

- **Day 1 — core aggregator.** Multi-format parsing, indicator
  normalization/validation (`ipaddress` for IPs, regex for domains,
  `urllib` for URLs, hex/length checks for hashes), cross-feed dedup
  with merged sightings and observation windows, unified JSON output.
- **Day 2 — scoring, expiry, blocklist.** Feed-reliability weights,
  recency decay, sighting-count boosts (`threatintel/score.py`),
  TTL-based expiry per IOC type (`threatintel/expire.py`), plain-text
  blocklist export for firewall/proxy ingestion, and a pytest suite in
  `tests/`.
- **Day 3 — exchange formats and reporting** *(planned)*. STIX 2.1
  bundle export, Markdown summary report, CI workflow, usage docs.

## Scoring

Each IOC scores 0–100:

```
score = 100 × feed_weight × 0.5^(age_days / 30) + min(sightings × 2, 20)
```

`feed_weight` is the most trusted source's weight from
`threatintel/config.py` (unknown feeds default to 0.5). Override
weights with `--weights weights.json`, pin "now" for reproducible runs
with `--now 2026-10-07T00:00:00Z`.

## Expiry and blocklist

IOCs older than their type's TTL (IP/domain 30d, URL 14d, hash 90d;
override with `--ttl-days`) are excluded from outputs and counted in
`meta.expired_count`. Export a blocklist of active IOCs:

```bash
python3 aggregate.py samples/*.json samples/*.csv \
    --blocklist blocklist.txt --min-score 40 --now 2026-10-07T00:00:00Z
```

The blocklist holds IPs and domains (URLs reduce to their host);
hashes have no network-blocklist representation and are skipped.

## Tests

```bash
pip install -r requirements.txt   # pytest
python3 -m pytest tests/ -q
```

## Normalization rules

- IPs: canonical form via `ipaddress` (`203.0.113.5`, `2001:db8::1`);
  a trailing `:port` is tolerated and stripped.
- Domains: lowercased, trailing dot stripped; must have a valid TLD.
- URLs: scheme/host lowercased, default ports stripped; `http`/`https`
  only.
- Hashes: lowercased hex; MD5 (32), SHA-1 (40), SHA-256 (64) accepted.

Records that fail validation are skipped and reported on stderr —
aggregation never silently drops data without telling you.
