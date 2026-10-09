#!/usr/bin/env python3
"""aggregate.py — aggregate threat-intel IOC feeds into one deduped feed.

Reads one or more feed files (JSON or CSV), validates and normalizes
every indicator, deduplicates across feeds, scores each IOC, expires
stale ones, and writes a unified JSON feed plus an optional plain-text
blocklist for firewall/proxy ingestion.

Usage:
    python3 aggregate.py samples/feed1.json samples/feed2.csv
    python3 aggregate.py samples/*.json --blocklist blocklist.txt --min-score 40
    python3 aggregate.py samples/*.json --stix bundle.json --report report.md
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from threatintel import config
from threatintel.dedup import dedup_records
from threatintel.expire import expire
from threatintel.export import write_blocklist, write_unified_json
from threatintel.parsers import parse_feed, parse_ts
from threatintel.report import write_report
from threatintel.score import score_all
from threatintel.stix import write_stix_bundle


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Aggregate threat-intel IOC feeds into one scored, deduped feed."
    )
    ap.add_argument("feeds", nargs="+", help="feed files (.json or .csv)")
    ap.add_argument("-o", "--output", default="feed.json",
                    help="unified JSON output path (default: feed.json)")
    ap.add_argument("--blocklist", default=None, metavar="PATH",
                    help="also write a plain-text blocklist to PATH")
    ap.add_argument("--stix", default=None, metavar="PATH",
                    help="also write a STIX 2.1 bundle to PATH")
    ap.add_argument("--report", default=None, metavar="PATH",
                    help="also write a Markdown summary report to PATH")
    ap.add_argument("--min-score", type=float, default=0.0,
                    help="minimum score for blocklist entries (default: 0)")
    ap.add_argument("--weights", default=None, metavar="PATH",
                    help="JSON file mapping feed name -> reliability weight 0-1")
    ap.add_argument("--ttl-days", type=int, default=None, metavar="N",
                    help="override TTL (days) for every IOC type")
    ap.add_argument("--now", default=None, metavar="ISO",
                    help="pin 'now' (ISO-8601) for scoring/expiry; default: current UTC")
    return ap


def load_weights(path: str | None) -> dict:
    weights = dict(config.FEED_WEIGHTS)
    if path:
        overrides = json.loads(Path(path).read_text(encoding="utf-8"))
        weights.update({str(k): float(v) for k, v in overrides.items()})
    return weights


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)
    now = parse_ts(args.now) if args.now else datetime.now(timezone.utc)
    ttl_days = None
    if args.ttl_days is not None:
        ttl_days = {t: args.ttl_days for t in ("ip", "domain", "url", "hash")}

    records = []
    for feed_path in args.feeds:
        try:
            records.extend(parse_feed(feed_path))
        except (OSError, ValueError) as exc:
            print("error: %s: %s" % (feed_path, exc), file=sys.stderr)
            return 2

    iocs, skipped = dedup_records(records)
    score_all(iocs, now, load_weights(args.weights))
    active, expired = expire(iocs, now, ttl_days)
    feeds = sorted({r.feed for r in records})
    write_unified_json(active, args.output, source_feeds=feeds,
                       expired_count=len(expired))

    summary = ("feeds=%d records=%d unique=%d skipped=%d expired=%d -> %s"
               % (len(args.feeds), len(records), len(iocs),
                  len(skipped), len(expired), args.output))
    if args.blocklist:
        write_blocklist(active, args.blocklist, min_score=args.min_score)
        summary += " + blocklist %s" % args.blocklist
    if args.stix:
        write_stix_bundle(active, args.stix, now=now)
        summary += " + stix %s" % args.stix
    if args.report:
        write_report(active, args.report, expired=expired,
                     skipped=len(skipped), source_feeds=feeds, now=now)
        summary += " + report %s" % args.report
    print(summary)
    for rec, reason in skipped:
        print("  skipped [%s] %s %r: %s" % (rec.feed, rec.ioc_type, rec.value, reason),
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
