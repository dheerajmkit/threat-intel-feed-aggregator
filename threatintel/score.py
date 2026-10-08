"""IOC scoring engine.

Score (0-100) = feed reliability x recency decay + sighting boost:

- **Feed reliability**: the max configured weight across the IOC's
  sources (``config.FEED_WEIGHTS``), scaled to 0-100.
- **Recency decay**: ``0.5 ** (age_days / half_life)`` — an IOC halves
  in score every ``SCORE_HALF_LIFE_DAYS`` after its ``last_seen``.
- **Sighting boost**: ``+2`` per sighting, capped at ``+20`` — an IOC
  seen independently by many feeds is more likely real.
"""
from __future__ import annotations

from datetime import datetime, timezone

from . import config
from .ioc import IOC


def feed_weight(sources: list, weights: dict | None = None) -> float:
    """Max reliability weight across an IOC's sources (0.0-1.0)."""
    weights = weights if weights is not None else config.FEED_WEIGHTS
    if not sources:
        return config.DEFAULT_FEED_WEIGHT
    return max(weights.get(src, config.DEFAULT_FEED_WEIGHT) for src in sources)


def recency_factor(last_seen: datetime, now: datetime,
                   half_life_days: float | None = None) -> float:
    """Exponential decay in (0, 1]; future timestamps clamp to 1.0."""
    half_life = half_life_days if half_life_days is not None else config.SCORE_HALF_LIFE_DAYS
    age_days = max(0.0, (now - last_seen).total_seconds() / 86400.0)
    return 0.5 ** (age_days / half_life)


def sighting_boost(sightings: int) -> float:
    return min(sightings * config.SIGHTING_BOOST_PER, config.SIGHTING_BOOST_CAP)


def score_ioc(ioc: IOC, now: datetime, weights: dict | None = None,
              half_life_days: float | None = None) -> float:
    """Score one IOC in the range 0-100."""
    base = 100.0 * feed_weight(ioc.sources, weights)
    decayed = base * recency_factor(ioc.last_seen, now, half_life_days)
    return round(min(100.0, decayed + sighting_boost(ioc.sightings)), 2)


def score_all(iocs: dict, now: datetime | None = None,
              weights: dict | None = None) -> dict:
    """Score every IOC in place; returns the same dict."""
    now = now or datetime.now(timezone.utc)
    for ioc in iocs.values():
        ioc.score = score_ioc(ioc, now, weights)
    return iocs
