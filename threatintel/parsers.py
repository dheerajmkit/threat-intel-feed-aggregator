"""Feed parsers: JSON, CSV, and STIX-ish JSON bundles.

Supported input shapes:

JSON feed (list of records)::

    [
      {"type": "ip", "value": "203.0.113.5",
       "first_seen": "2026-09-20T00:00:00Z",
       "last_seen": "2026-10-02T00:00:00Z",
       "tags": ["phishing"]}
    ]

CSV feed (header row required)::

    type,value,first_seen,last_seen,tags
    ip,203.0.113.5,2026-09-20T00:00:00Z,2026-10-02T00:00:00Z,phishing

STIX-ish JSON bundle (``{"objects": [...]}``) with ``indicator`` objects
carrying STIX 2.x patterns such as ``[ipv4-addr:value = '203.0.113.5']``.
Timestamps come from ``created``/``modified`` (falling back to
``valid_from``).
"""
from __future__ import annotations

import csv
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from .ioc import IOC_TYPES

_STIX_PATTERNS = [
    # (stix observable, ioc_type, regex)
    ("ipv4-addr", "ip", re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]")),
    ("ipv6-addr", "ip", re.compile(r"\[ipv6-addr:value\s*=\s*'([^']+)'\]")),
    ("domain-name", "domain", re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]")),
    ("url", "url", re.compile(r"\[url:value\s*=\s*'([^']+)'\]")),
    (
        "file-hash",
        "hash",
        re.compile(r"\[file:hashes\.'(?:SHA-256|SHA-1|MD5)'\s*=\s*'([^']+)'\]"),
    ),
]


@dataclass
class RawRecord:
    """One unvalidated sighting from a feed file."""

    feed: str
    ioc_type: str
    value: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: list = field(default_factory=list)


def parse_ts(raw: str | None) -> datetime | None:
    """Parse an ISO-8601 timestamp (``Z`` suffix tolerated)."""
    if not raw:
        return None
    text = str(raw).strip().replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _split_tags(raw: str | list | None) -> list:
    if not raw:
        return []
    if isinstance(raw, list):
        return [str(t).strip() for t in raw if str(t).strip()]
    return [t.strip() for t in str(raw).replace(",", ";").split(";") if t.strip()]


def parse_json_feed(path: str | Path, feed: str) -> list:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and "objects" in data:
        return _parse_stix_bundle(data, feed)
    if not isinstance(data, list):
        raise ValueError("JSON feed must be a list of records or a STIX bundle")
    records = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        records.append(
            RawRecord(
                feed=feed,
                ioc_type=str(entry.get("type", "")).lower(),
                value=str(entry.get("value", "")),
                first_seen=parse_ts(entry.get("first_seen")),
                last_seen=parse_ts(entry.get("last_seen")),
                tags=_split_tags(entry.get("tags")),
            )
        )
    return records


def _parse_stix_bundle(bundle: dict, feed: str) -> list:
    records = []
    for obj in bundle.get("objects", []):
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        first_seen = parse_ts(obj.get("created") or obj.get("valid_from"))
        last_seen = parse_ts(obj.get("modified")) or first_seen
        tags = _split_tags(obj.get("labels"))
        for _observable, ioc_type, rx in _STIX_PATTERNS:
            m = rx.search(pattern)
            if m:
                records.append(
                    RawRecord(
                        feed=feed,
                        ioc_type=ioc_type,
                        value=m.group(1),
                        first_seen=first_seen,
                        last_seen=last_seen,
                        tags=tags,
                    )
                )
                break
    return records


def parse_csv_feed(path: str | Path, feed: str) -> list:
    records = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            records.append(
                RawRecord(
                    feed=feed,
                    ioc_type=str(row.get("type", "")).lower(),
                    value=str(row.get("value", "")),
                    first_seen=parse_ts(row.get("first_seen")),
                    last_seen=parse_ts(row.get("last_seen")),
                    tags=_split_tags(row.get("tags")),
                )
            )
    return records


def parse_feed(path: str | Path, feed: str | None = None) -> list:
    """Dispatch on file extension; feed name defaults to the file stem."""
    path = Path(path)
    feed = feed or path.stem
    suffix = path.suffix.lower()
    if suffix == ".json":
        return parse_json_feed(path, feed)
    if suffix == ".csv":
        return parse_csv_feed(path, feed)
    raise ValueError("unsupported feed format: %s" % path.suffix)
