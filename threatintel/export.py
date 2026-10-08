"""Output writers: unified JSON feed, plain-text blocklist."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit


def write_unified_json(iocs: dict, path: str | Path, source_feeds: list | None = None,
                       expired_count: int = 0) -> Path:
    """Write the deduplicated IOC set as one unified JSON feed."""
    path = Path(path)
    payload = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ioc_count": len(iocs),
            "expired_count": expired_count,
            "source_feeds": sorted(source_feeds or []),
            "format": "threat-intel-feed-aggregator/v1",
        },
        "iocs": [
            ioc.to_dict()
            for ioc in sorted(iocs.values(), key=lambda i: (-i.score, i.ioc_type, i.value))
        ],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path


def blocklist_value(ioc) -> str | None:
    """Render one IOC as a firewall/proxy blocklist entry.

    IPs and domains are directly blockable; URLs reduce to their host.
    Hashes have no network blocklist representation and are excluded.
    """
    if ioc.ioc_type == "ip":
        return ioc.value
    if ioc.ioc_type == "domain":
        return ioc.value
    if ioc.ioc_type == "url":
        host = urlsplit(ioc.value).hostname or ""
        return host.lower() or None
    return None  # hash: not blockable at the network layer


def write_blocklist(iocs: dict, path: str | Path, min_score: float = 0.0) -> Path:
    """Write a plain-text blocklist (one entry per line), highest score first.

    Only IOCs at or above ``min_score`` are included; hashes are
    skipped (see :func:`blocklist_value`).
    """
    path = Path(path)
    entries = []
    for ioc in iocs.values():
        if ioc.score < min_score:
            continue
        value = blocklist_value(ioc)
        if value:
            entries.append((ioc.score, value))
    # dedupe (a URL host can equal a domain IOC) keeping the best score
    best: dict = {}
    for score, value in entries:
        if value not in best or score > best[value]:
            best[value] = score
    lines = ["# threat-intel-feed-aggregator blocklist",
             "# generated %s" % datetime.now(timezone.utc).isoformat()]
    lines += [v for v, _ in sorted(best.items(), key=lambda kv: -kv[1])]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path
