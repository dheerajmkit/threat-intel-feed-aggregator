"""IOC data model for the threat-intel feed aggregator."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime

IOC_TYPES = ("ip", "domain", "url", "hash")


@dataclass
class IOC:
    """A single normalized indicator of compromise.

    ``ioc_type`` is one of ``ip`` | ``domain`` | ``url`` | ``hash`` and
    ``value`` is the normalized indicator (lowercased domains/URLs/hashes,
    canonical IP string). ``sightings`` counts how many feed records
    contributed to this indicator; ``sources`` lists the feed names.
    """

    ioc_type: str
    value: str
    first_seen: datetime
    last_seen: datetime
    sightings: int = 1
    sources: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    score: float = 0.0

    def key(self) -> tuple:
        return (self.ioc_type, self.value)

    def merge(self, other: "IOC") -> None:
        """Fold another sighting of the same indicator into this one."""
        self.sightings += other.sightings
        self.first_seen = min(self.first_seen, other.first_seen)
        self.last_seen = max(self.last_seen, other.last_seen)
        for src in other.sources:
            if src not in self.sources:
                self.sources.append(src)
        for tag in other.tags:
            if tag not in self.tags:
                self.tags.append(tag)

    def to_dict(self) -> dict:
        return {
            "type": self.ioc_type,
            "value": self.value,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "sightings": self.sightings,
            "sources": sorted(self.sources),
            "tags": sorted(self.tags),
            "score": round(self.score, 2),
        }
