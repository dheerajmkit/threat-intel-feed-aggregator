"""Pytest suite for STIX 2.1 export and the Markdown report (day 3)."""
import json
from datetime import datetime, timedelta, timezone

from threatintel.ioc import IOC
from threatintel.report import build_report
from threatintel.stix import indicator_object, stix_pattern, to_stix_bundle

NOW = datetime(2026, 10, 7, tzinfo=timezone.utc)


def _ioc(ioc_type="ip", value="203.0.113.5", **kw):
    base = dict(ioc_type=ioc_type, value=value,
                first_seen=NOW - timedelta(days=2), last_seen=NOW - timedelta(days=1),
                sightings=2, sources=["feed1"], tags=["phishing"], score=80.0)
    base.update(kw)
    return IOC(**base)


# --- STIX patterns --------------------------------------------------------

def test_stix_pattern_ip():
    assert stix_pattern(_ioc("ip", "203.0.113.5")) == "[ipv4-addr:value = '203.0.113.5']"
    assert stix_pattern(_ioc("ip", "2001:db8::1")) == "[ipv6-addr:value = '2001:db8::1']"


def test_stix_pattern_domain_url():
    assert stix_pattern(_ioc("domain", "evil.example")) == "[domain-name:value = 'evil.example']"
    assert stix_pattern(_ioc("url", "http://evil.example/x")) == "[url:value = 'http://evil.example/x']"


def test_stix_pattern_hashes():
    assert stix_pattern(_ioc("hash", "0" * 64)) == "[file:hashes.'SHA-256' = '%s']" % ("0" * 64)
    assert stix_pattern(_ioc("hash", "1" * 40)) == "[file:hashes.'SHA-1' = '%s']" % ("1" * 40)
    assert stix_pattern(_ioc("hash", "2" * 32)) == "[file:hashes.'MD5' = '%s']" % ("2" * 32)


def test_stix_pattern_unknown_type():
    assert stix_pattern(_ioc("email", "a@example.com")) is None


def test_indicator_object_shape():
    obj = indicator_object(_ioc(), NOW)
    assert obj["type"] == "indicator"
    assert obj["spec_version"] == "2.1"
    assert obj["pattern"] == "[ipv4-addr:value = '203.0.113.5']"
    assert obj["pattern_type"] == "stix"
    assert obj["labels"] == ["phishing"]
    assert obj["confidence"] == 80
    assert obj["valid_from"] <= obj["modified"]


def test_bundle_deterministic_and_serializable():
    iocs = {
        ("ip", "203.0.113.5"): _ioc(),
        ("domain", "evil.example"): _ioc("domain", "evil.example"),
    }
    first = json.dumps(to_stix_bundle(iocs, now=NOW), sort_keys=True)
    second = json.dumps(to_stix_bundle(iocs, now=NOW), sort_keys=True)
    assert first == second  # deterministic IDs
    bundle = json.loads(first)
    assert bundle["type"] == "bundle"
    types = [o["type"] for o in bundle["objects"]]
    assert types[0] == "identity"
    assert types.count("indicator") == 2


# --- report ---------------------------------------------------------------

def test_build_report_sections():
    iocs = {
        ("ip", "203.0.113.5"): _ioc(score=90.0),
        ("domain", "evil.example"): _ioc("domain", "evil.example", score=10.0),
    }
    expired = {("ip", "192.0.2.1"): _ioc("ip", "192.0.2.1")}
    md = build_report(iocs, expired=expired, skipped=2,
                      source_feeds=["feed1"], now=NOW)
    assert "# Threat intel aggregation report" in md
    assert "| Active IOCs | 2 |" in md
    assert "| Expired IOCs | 1 |" in md
    assert "| Skipped records | 2 |" in md
    assert "| ip | 1 |" in md and "| domain | 1 |" in md
    # top IOC first
    assert md.index("203.0.113.5") < md.index("evil.example")
    assert "`203.0.113.5`" in md
