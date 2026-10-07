#!/usr/bin/env python3
"""aggregate.py — aggregate threat-intel IOC feeds into one deduped feed.

Reads one or more feed files (JSON or CSV), validates and normalizes
every indicator, deduplicates across feeds, and writes a unified JSON
feed.

Usage:
    python3 aggregate.py samples/feed1.json samples/feed2.csv
    python3 aggregate.py samples/feed1.json -o unified.json
"""
from __future__ import annotations

import argparse
import sys

from threatintel.dedup import dedup_records
from threatintel.export import write_unified_json
from threatintel.parsers import parse_feed


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="Aggregate threat-intel IOC feeds into one deduped JSON feed."
    )
    ap.add_argument("feeds", nargs="+", help="feed files (.json or .csv)")
    ap.add_argument("-o", "--output", default="feed.json",
                    help="unified JSON output path (default: feed.json)")
    return ap


def main(argv: list | None = None) -> int:
    args = build_parser().parse_args(argv)

    records = []
    for feed_path in args.feeds:
        try:
            records.extend(parse_feed(feed_path))
        except (OSError, ValueError) as exc:
            print("error: %s: %s" % (feed_path, exc), file=sys.stderr)
            return 2

    iocs, skipped = dedup_records(records)
    feeds = sorted({r.feed for r in records})
    write_unified_json(iocs, args.output, source_feeds=feeds)

    print("feeds=%d records=%d unique=%d skipped=%d -> %s"
          % (len(args.feeds), len(records), len(iocs), len(skipped), args.output))
    for rec, reason in skipped:
        print("  skipped [%s] %s %r: %s" % (rec.feed, rec.ioc_type, rec.value, reason),
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
