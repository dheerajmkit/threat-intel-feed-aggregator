# Usage

## Install

Python 3.10+ with the standard library only. For the test suite:

```bash
pip install -r requirements.txt   # pytest
```

## Basic aggregation

```bash
python3 aggregate.py samples/feed1.json samples/feed2.csv -o feed.json
```

## Full pipeline

```bash
python3 aggregate.py samples/feed1.json samples/feed2.csv \
    samples/feed3-stix.json samples/vendor-feed.json \
    -o feed.json \
    --blocklist blocklist.txt --min-score 40 \
    --stix bundle.json \
    --report report.md \
    --now 2026-10-07T00:00:00Z
```

| Flag | Purpose |
| ---- | ------- |
| `-o PATH` | Unified JSON feed (default `feed.json`) |
| `--blocklist PATH` | Plain-text blocklist, highest score first |
| `--stix PATH` | STIX 2.1 bundle (indicators + identity) |
| `--report PATH` | Markdown summary report |
| `--min-score N` | Blocklist cutoff (default 0) |
| `--weights PATH` | JSON map of feed name → reliability weight 0–1 |
| `--ttl-days N` | Override TTL for every IOC type |
| `--now ISO` | Pin "now" for scoring/expiry (reproducible runs) |

## Feed formats

**JSON** — list of records:

```json
[{"type": "ip", "value": "203.0.113.5",
  "first_seen": "2026-09-20T00:00:00Z",
  "last_seen": "2026-10-02T00:00:00Z",
  "tags": ["phishing"]}]
```

**STIX-ish JSON** — `{"objects": [...]}` with `indicator` STIX patterns;
timestamps from `created`/`modified`.

**CSV** — header `type,value,first_seen,last_seen,tags` with
semicolon-separated tags.

Feed names default to the file stem (`feed1.json` → `feed1`).

## Scoring and expiry

```
score = 100 × feed_weight × 0.5^(age_days / 30) + min(sightings × 2, 20)
```

Tune weights and TTLs in `threatintel/config.py`:

| Setting | Default | Meaning |
| ------- | ------- | ------- |
| `FEED_WEIGHTS` | per feed | Reliability 0–1 (unknown feeds: 0.5) |
| `TTL_DAYS` | ip/domain 30, url 14, hash 90 | Days after `last_seen` before expiry |
| `SCORE_HALF_LIFE_DAYS` | 30 | Score halves every 30 days |
| `SIGHTING_BOOST_CAP` | 20 | Max boost from multiple sightings |

## Ingesting the blocklist

The blocklist is one indicator per line (IPs, domains, URL hosts —
hashes excluded). Feed it to a firewall, DNS RPZ, or proxy:

```bash
# dnsmasq-style null route from the blocklist
grep -v '^#' blocklist.txt | while read -r d; do
  echo "address=/$d/0.0.0.0"
done > dns-blackhole.conf
```

## Running tests and CI

```bash
python3 -m pytest tests/ -q
```

`.github/workflows/ci.yml` runs `py_compile` plus the pytest suite on
every push and pull request.
