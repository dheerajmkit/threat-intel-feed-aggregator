"""Output writers: unified JSON feed (day 1)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def write_unified_json(iocs: dict, path: str | Path, source_feeds: list | None = None) -> Path:
    """Write the deduplicated IOC set as one unified JSON feed."""
    path = Path(path)
    payload = {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "ioc_count": len(iocs),
            "source_feeds": sorted(source_feeds or []),
            "format": "threat-intel-feed-aggregator/v1",
        },
        "iocs": [
            ioc.to_dict()
            for ioc in sorted(iocs.values(), key=lambda i: (i.ioc_type, i.value))
        ],
    }
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return path
