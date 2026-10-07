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
      "score": 0.0
    }
  ]
}
```

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
- **Day 2 — scoring and expiry** *(planned)*. Feed-reliability weights,
  recency decay, sighting-count boosts, TTL-based expiry, plain-text
  blocklist export, pytest suite.
- **Day 3 — exchange formats and reporting** *(planned)*. STIX 2.1
  bundle export, Markdown summary report, CI workflow, usage docs.

## Normalization rules

- IPs: canonical form via `ipaddress` (`203.0.113.5`, `2001:db8::1`);
  a trailing `:port` is tolerated and stripped.
- Domains: lowercased, trailing dot stripped; must have a valid TLD.
- URLs: scheme/host lowercased, default ports stripped; `http`/`https`
  only.
- Hashes: lowercased hex; MD5 (32), SHA-1 (40), SHA-256 (64) accepted.

Records that fail validation are skipped and reported on stderr —
aggregation never silently drops data without telling you.
