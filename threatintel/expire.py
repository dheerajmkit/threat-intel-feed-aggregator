"""TTL-based expiry of stale IOCs.

An indicator whose ``last_seen`` is older than its type's TTL is
considered stale and excluded from operational outputs (blocklist,
STIX bundle). Expired IOCs are reported separately so nothing is
silently lost.
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import config
from .ioc import IOC


def age_days(ioc: IOC, now: datetime) -> float:
    return max(0.0, (now - ioc.last_seen).total_seconds() / 86400.0)


def ttl_for(ioc_type: str, ttl_days: dict | None = None) -> float:
    ttl_days = ttl_days if ttl_days is not None else config.TTL_DAYS
    return ttl_days.get(ioc_type, config.DEFAULT_TTL_DAYS)


def is_expired(ioc: IOC, now: datetime, ttl_days: dict | None = None) -> bool:
    return age_days(ioc, now) > ttl_for(ioc.ioc_type, ttl_days)


def expire(iocs: dict, now: datetime | None = None,
           ttl_days: dict | None = None) -> tuple:
    """Split IOCs into ``(active, expired)`` dicts."""
    now = now or datetime.now(timezone.utc)
    active, expired = {}, {}
    for key, ioc in iocs.items():
        (expired if is_expired(ioc, now, ttl_days) else active)[key] = ioc
    return active, expired
