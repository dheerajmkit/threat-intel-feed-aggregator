"""Cross-feed deduplication.

The same indicator often appears in several feeds (and several times in
one feed). Records are validated/normalized first; records keyed by
``(type, normalized value)`` are then merged into a single IOC with
combined sightings, the earliest ``first_seen``, the latest
``last_seen``, and the union of sources and tags.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .ioc import IOC
from .normalize import normalize_ioc
from .parsers import RawRecord


def _coalesce_ts(records: list) -> tuple:
    """Fill missing timestamps: fall back to the newest seen timestamp,
    then to ``now`` so every IOC has a defined observation window."""
    now = datetime.now(timezone.utc)
    stamps = [r.last_seen or r.first_seen for r in records]
    stamps = [s for s in stamps if s is not None]
    fallback = max(stamps) if stamps else now
    first = [r.first_seen or r.last_seen or fallback for r in records]
    last = [r.last_seen or r.first_seen or fallback for r in records]
    return min(first), max(last)


def dedup_records(records: list) -> tuple:
    """Deduplicate raw feed records into IOCs.

    Returns ``(iocs, skipped)`` where ``iocs`` is a dict keyed by
    ``(type, value)`` and ``skipped`` is a list of ``(record, reason)``
    for records that failed validation.
    """
    merged: dict = {}
    skipped: list = []
    for rec in records:
        ok, normalized, error = normalize_ioc(rec.ioc_type, rec.value)
        if not ok:
            skipped.append((rec, error))
            continue
        key = (rec.ioc_type.strip().lower(), normalized)
        first_seen, last_seen = _coalesce_ts([rec])
        candidate = IOC(
            ioc_type=key[0],
            value=normalized,
            first_seen=first_seen,
            last_seen=last_seen,
            sightings=1,
            sources=[rec.feed],
            tags=list(rec.tags),
        )
        if key in merged:
            merged[key].merge(candidate)
        else:
            merged[key] = candidate
    return merged, skipped
