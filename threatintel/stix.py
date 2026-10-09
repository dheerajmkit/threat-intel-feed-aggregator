"""STIX 2.1 bundle export (stdlib-only, no ``stix2`` dependency).

Builds a minimal but valid STIX 2.1 bundle: one ``identity`` for the
aggregator plus one ``indicator`` per IOC with a STIX pattern, labels
from the IOC tags, and ``valid_from`` set to ``first_seen``. Object IDs
are deterministic (UUIDv5 over the pattern) so repeated exports of the
same feed produce identical bundles — handy for diffing and tests.
"""
from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime, timezone

from .normalize import hash_algorithm

SPEC_VERSION = "2.1"
_IDENTITY_ID = "identity--%s" % uuid.uuid5(uuid.NAMESPACE_URL,
                                          "threat-intel-feed-aggregator")


def stix_pattern(ioc) -> str | None:
    """Render an IOC as a STIX 2.1 observation pattern."""
    if ioc.ioc_type == "ip":
        try:
            kind = "ipv6-addr" if ipaddress.ip_address(ioc.value).version == 6 else "ipv4-addr"
        except ValueError:
            return None
        return "[%s:value = '%s']" % (kind, ioc.value)
    if ioc.ioc_type == "domain":
        return "[domain-name:value = '%s']" % ioc.value
    if ioc.ioc_type == "url":
        return "[url:value = '%s']" % ioc.value
    if ioc.ioc_type == "hash":
        algo = hash_algorithm(ioc.value)
        names = {"md5": "MD5", "sha1": "SHA-1", "sha256": "SHA-256"}
        if algo is None:
            return None
        return "[file:hashes.'%s' = '%s']" % (names[algo], ioc.value)
    return None


def indicator_object(ioc, now: datetime) -> dict | None:
    pattern = stix_pattern(ioc)
    if pattern is None:
        return None
    obj_id = "indicator--%s" % uuid.uuid5(uuid.NAMESPACE_URL, pattern)
    return {
        "type": "indicator",
        "spec_version": SPEC_VERSION,
        "id": obj_id,
        "created": ioc.first_seen.isoformat(),
        "modified": max(ioc.last_seen, ioc.first_seen).isoformat(),
        "name": "%s %s" % (ioc.ioc_type, ioc.value),
        "description": "Aggregated threat intel: %d sighting(s) from %s." % (
            ioc.sightings, ", ".join(sorted(ioc.sources))),
        "indicator_types": ["malicious-activity"],
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ioc.first_seen.isoformat(),
        "labels": sorted(ioc.tags),
        "confidence": int(round(max(0.0, min(100.0, ioc.score)))),
    }


def to_stix_bundle(iocs: dict, identity_name: str = "threat-intel-feed-aggregator",
                   now: datetime | None = None) -> dict:
    """Build a STIX 2.1 bundle dict from active IOCs."""
    now = now or datetime.now(timezone.utc)
    objects = [
        {
            "type": "identity",
            "spec_version": SPEC_VERSION,
            "id": _IDENTITY_ID,
            "created": now.isoformat(),
            "modified": now.isoformat(),
            "name": identity_name,
            "identity_class": "system",
        }
    ]
    for ioc in sorted(iocs.values(), key=lambda i: (i.ioc_type, i.value)):
        obj = indicator_object(ioc, now)
        if obj is not None:
            objects.append(obj)
    bundle_seed = "|".join(sorted(o["id"] for o in objects))
    return {
        "type": "bundle",
        "id": "bundle--%s" % uuid.uuid5(uuid.NAMESPACE_URL, bundle_seed),
        "objects": objects,
    }


def write_stix_bundle(iocs: dict, path, **kwargs) -> object:
    """Write a STIX 2.1 bundle JSON file; returns the path."""
    import json
    from pathlib import Path
    path = Path(path)
    bundle = to_stix_bundle(iocs, **kwargs)
    path.write_text(json.dumps(bundle, indent=2) + "\n", encoding="utf-8")
    return path
