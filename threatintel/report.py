"""Markdown summary report for an aggregation run."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from pathlib import Path


def build_report(iocs: dict, expired: dict | None = None, skipped: int = 0,
                 source_feeds: list | None = None,
                 now: datetime | None = None) -> str:
    """Render a Markdown summary of the aggregated feed."""
    now = now or datetime.now(timezone.utc)
    expired = expired or {}
    by_type = Counter(i.ioc_type for i in iocs.values())
    by_source = Counter(s for i in iocs.values() for s in i.sources)
    top = sorted(iocs.values(), key=lambda i: -i.score)[:10]

    lines = [
        "# Threat intel aggregation report",
        "",
        "Generated %s (UTC)." % now.strftime("%Y-%m-%d %H:%M"),
        "",
        "## Totals",
        "",
        "| Metric | Count |",
        "| ------ | ----- |",
        "| Active IOCs | %d |" % len(iocs),
        "| Expired IOCs | %d |" % len(expired),
        "| Skipped records | %d |" % skipped,
        "| Source feeds | %d |" % len(source_feeds or []),
        "",
        "## IOCs by type",
        "",
        "| Type | Count |",
        "| ---- | ----- |",
    ]
    for ioc_type in ("ip", "domain", "url", "hash"):
        lines.append("| %s | %d |" % (ioc_type, by_type.get(ioc_type, 0)))
    lines += [
        "",
        "## IOCs by source feed",
        "",
        "| Feed | IOCs |",
        "| ---- | ---- |",
    ]
    for feed, count in by_source.most_common():
        lines.append("| %s | %d |" % (feed, count))
    lines += [
        "",
        "## Top IOCs by score",
        "",
        "| Score | Type | Value | Sightings | Sources |",
        "| ----- | ---- | ----- | --------- | ------- |",
    ]
    for ioc in top:
        lines.append("| %.1f | %s | `%s` | %d | %s |" % (
            ioc.score, ioc.ioc_type, ioc.value, ioc.sightings,
            ", ".join(sorted(ioc.sources))))
    lines += [
        "",
        "_Scores: 0-100 from feed reliability x recency decay + sighting "
        "boost. See README for the formula._",
        "",
    ]
    return "\n".join(lines)


def write_report(iocs: dict, path, **kwargs) -> object:
    """Write the Markdown report; returns the path."""
    path = Path(path)
    path.write_text(build_report(iocs, **kwargs), encoding="utf-8")
    return path
