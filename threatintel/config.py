"""Tunable knobs for scoring and expiry.

All weights and windows live here so operators can tune the pipeline
without touching code. Feed weights are keyed by feed name (the file
stem); unknown feeds fall back to ``DEFAULT_FEED_WEIGHT``.
"""
from __future__ import annotations

# Reliability weight per feed, 0.0 - 1.0. Higher = more trusted.
FEED_WEIGHTS = {
    "feed1": 0.9,        # internal CERT feed
    "feed2": 0.6,        # community blocklist
    "feed3-stix": 0.7,   # partner STIX bundle
    "vendor-feed": 0.8,  # commercial vendor feed
}
DEFAULT_FEED_WEIGHT = 0.5

# Days after last_seen when an IOC of a given type expires.
TTL_DAYS = {
    "ip": 30,
    "domain": 30,
    "url": 14,
    "hash": 90,
}
DEFAULT_TTL_DAYS = 30

# Scoring: score = 100 * weight * 0.5**(age_days / half_life) + sighting boost.
SCORE_HALF_LIFE_DAYS = 30.0
SIGHTING_BOOST_PER = 2.0
SIGHTING_BOOST_CAP = 20.0
