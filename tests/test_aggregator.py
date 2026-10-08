"""Pytest suite for the threat-intel feed aggregator (day 2)."""
from datetime import datetime, timedelta, timezone

import pytest

from threatintel import config
from threatintel.dedup import dedup_records
from threatintel.expire import expire, is_expired
from threatintel.export import blocklist_value, write_blocklist
from threatintel.ioc import IOC
from threatintel.normalize import normalize_ioc
from threatintel.parsers import (
    RawRecord,
    parse_csv_feed,
    parse_json_feed,
    parse_ts,
)
from threatintel.score import recency_factor, score_ioc, sighting_boost

NOW = datetime(2026, 10, 7, tzinfo=timezone.utc)
MD5 = "0" * 32
SHA1 = "1" * 40
SHA256 = "ab" * 32


def rec(ioc_type, value, feed="feed1", days_ago=1, tags=()):
    last = NOW - timedelta(days=days_ago)
    first = last - timedelta(days=2)
    return RawRecord(feed=feed, ioc_type=ioc_type, value=value,
                     first_seen=first, last_seen=last, tags=list(tags))


# --- normalization ----------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    ("203.0.113.5", "203.0.113.5"),
    ("  198.51.100.44  ", "198.51.100.44"),
    ("203.0.113.5:8080", "203.0.113.5"),          # trailing port tolerated
    ("2001:db8::1", "2001:db8::1"),
    ("2001:0DB8:0000::0001", "2001:db8::1"),      # canonicalized
])
def test_normalize_ip_valid(raw, expected):
    ok, value, _ = normalize_ioc("ip", raw)
    assert ok and value == expected


@pytest.mark.parametrize("raw", ["not-an-ip", "999.1.1.1", "", "203.0.113.5/24"])
def test_normalize_ip_invalid(raw):
    ok, _, _ = normalize_ioc("ip", raw)
    assert not ok


@pytest.mark.parametrize("raw,expected", [
    ("Bad-Login.EXAMPLE.com", "bad-login.example.com"),
    ("malware-test.example.", "malware-test.example"),
    ("a.b.example.co", "a.b.example.co"),
])
def test_normalize_domain_valid(raw, expected):
    ok, value, _ = normalize_ioc("domain", raw)
    assert ok and value == expected


@pytest.mark.parametrize("raw", ["nodot", "-bad.example", "bad-.example",
                                 "http://x.example/", ""])
def test_normalize_domain_invalid(raw):
    ok, _, _ = normalize_ioc("domain", raw)
    assert not ok


@pytest.mark.parametrize("raw,expected", [
    ("HTTP://Malware-Test.EXAMPLE/payload.bin", "http://malware-test.example/payload.bin"),
    ("https://example.com:443/a", "https://example.com/a"),   # default port stripped
    ("http://example.com:8080/a", "http://example.com:8080/a"),
])
def test_normalize_url_valid(raw, expected):
    ok, value, _ = normalize_ioc("url", raw)
    assert ok and value == expected


@pytest.mark.parametrize("raw", ["ftp://example.com/x", "notaurl", "http://"])
def test_normalize_url_invalid(raw):
    ok, _, _ = normalize_ioc("url", raw)
    assert not ok


@pytest.mark.parametrize("raw", [MD5, SHA1, SHA256, "AB" * 32])
def test_normalize_hash_valid(raw):
    ok, value, _ = normalize_ioc("hash", raw)
    assert ok and value == raw.lower()


@pytest.mark.parametrize("raw", ["zz" * 16, "abc", "0" * 33])
def test_normalize_hash_invalid(raw):
    ok, _, _ = normalize_ioc("hash", raw)
    assert not ok


def test_normalize_unknown_type():
    ok, _, err = normalize_ioc("email", "a@example.com")
    assert not ok and "unknown ioc type" in err


# --- parsers ----------------------------------------------------------

def test_parse_ts_z_suffix():
    assert parse_ts("2026-10-01T00:00:00Z") == datetime(2026, 10, 1, tzinfo=timezone.utc)


def test_parse_json_feed(tmp_path):
    p = tmp_path / "f.json"
    p.write_text('[{"type": "ip", "value": "203.0.113.9", '
                 '"first_seen": "2026-10-01T00:00:00Z", '
                 '"last_seen": "2026-10-02T00:00:00Z", "tags": ["a", "b"]}]')
    records = parse_json_feed(p, "f")
    assert len(records) == 1
    assert records[0].value == "203.0.113.9"
    assert records[0].tags == ["a", "b"]


def test_parse_csv_feed(tmp_path):
    p = tmp_path / "f.csv"
    p.write_text("type,value,first_seen,last_seen,tags\n"
                 "domain,evil.example,2026-10-01T00:00:00Z,2026-10-02T00:00:00Z,phishing\n")
    records = parse_csv_feed(p, "f")
    assert len(records) == 1
    assert (records[0].ioc_type, records[0].value) == ("domain", "evil.example")


def test_parse_stix_bundle(tmp_path):
    p = tmp_path / "b.json"
    p.write_text('{"type": "bundle", "objects": ['
                 '{"type": "indicator", "pattern": "[ipv4-addr:value = \'203.0.113.9\']", '
                 '"created": "2026-10-01T00:00:00Z", "modified": "2026-10-02T00:00:00Z", '
                 '"labels": ["c2"]}, '
                 '{"type": "identity", "name": "someone"}]}')
    records = parse_json_feed(p, "b")
    assert len(records) == 1
    assert (records[0].ioc_type, records[0].value) == ("ip", "203.0.113.9")
    assert records[0].tags == ["c2"]


# --- dedup ------------------------------------------------------------

def test_dedup_merges_sightings():
    iocs, skipped = dedup_records([
        rec("ip", "203.0.113.5", feed="a", days_ago=5, tags=["phishing"]),
        rec("ip", "203.0.113.5", feed="b", days_ago=1, tags=["c2"]),
        rec("domain", "BAD-LOGIN.example.com", feed="a", days_ago=3),
    ])
    assert not skipped
    assert len(iocs) == 2
    ioc = iocs[("ip", "203.0.113.5")]
    assert ioc.sightings == 2
    assert sorted(ioc.sources) == ["a", "b"]
    assert sorted(ioc.tags) == ["c2", "phishing"]
    assert ioc.first_seen < ioc.last_seen  # window spans both sightings
    # domain normalized before keying
    assert ("domain", "bad-login.example.com") in iocs


def test_dedup_skips_invalid():
    iocs, skipped = dedup_records([rec("ip", "not-an-ip"), rec("ip", "203.0.113.5")])
    assert len(iocs) == 1
    assert len(skipped) == 1
    assert "invalid ip" in skipped[0][1]


# --- scoring ----------------------------------------------------------

def _ioc(**kw):
    base = dict(ioc_type="ip", value="203.0.113.5",
                first_seen=NOW - timedelta(days=2), last_seen=NOW - timedelta(days=1),
                sightings=1, sources=["feed1"], tags=[])
    base.update(kw)
    return IOC(**base)


def test_score_trusted_feed_outranks_untrusted():
    hi = score_ioc(_ioc(sources=["feed1"]), NOW)          # weight 0.9
    lo = score_ioc(_ioc(sources=["feed2"]), NOW)          # weight 0.6
    assert hi > lo > 0


def test_score_recency_decay():
    fresh = score_ioc(_ioc(last_seen=NOW), NOW)
    old = score_ioc(_ioc(last_seen=NOW - timedelta(days=60)), NOW)
    assert fresh > old
    assert recency_factor(NOW, NOW) == 1.0
    assert recency_factor(NOW - timedelta(days=30), NOW) == pytest.approx(0.5)


def test_score_sighting_boost_capped():
    assert sighting_boost(1) == 2.0
    assert sighting_boost(50) == config.SIGHTING_BOOST_CAP
    assert score_ioc(_ioc(sightings=1000), NOW) <= 100.0


def test_score_unknown_feed_uses_default():
    s = score_ioc(_ioc(sources=["no-such-feed"]), NOW)
    expected = (100 * config.DEFAULT_FEED_WEIGHT
                * recency_factor(NOW - timedelta(days=1), NOW)
                + sighting_boost(1))
    assert s == pytest.approx(round(min(100.0, expected), 2))


# --- expiry -----------------------------------------------------------

def test_expire_by_ttl():
    iocs = {
        ("domain", "fresh.example"): _ioc(ioc_type="domain", value="fresh.example",
                                          last_seen=NOW - timedelta(days=5)),
        ("domain", "stale.example"): _ioc(ioc_type="domain", value="stale.example",
                                          last_seen=NOW - timedelta(days=45)),
        ("hash", "oldhash"): _ioc(ioc_type="hash", value="0" * 64,
                                  last_seen=NOW - timedelta(days=45)),
    }
    active, expired = expire(iocs, NOW)
    assert set(active) == {("domain", "fresh.example"), ("hash", "oldhash")}
    assert set(expired) == {("domain", "stale.example")}   # hash TTL is 90d


def test_is_expired_boundary():
    ioc = _ioc(ioc_type="ip", last_seen=NOW - timedelta(days=30, seconds=1))
    assert is_expired(ioc, NOW)


# --- blocklist --------------------------------------------------------

def test_blocklist_value():
    assert blocklist_value(_ioc(ioc_type="ip", value="203.0.113.5")) == "203.0.113.5"
    assert blocklist_value(_ioc(ioc_type="domain", value="evil.example")) == "evil.example"
    assert blocklist_value(_ioc(ioc_type="url",
                                value="http://evil.example:8080/x")) == "evil.example"
    assert blocklist_value(_ioc(ioc_type="hash", value="0" * 64)) is None


def test_write_blocklist_filters_and_dedupes(tmp_path):
    iocs = {
        ("ip", "203.0.113.5"): _ioc(ioc_type="ip", value="203.0.113.5", score=80.0),
        ("domain", "evil.example"): _ioc(ioc_type="domain", value="evil.example", score=90.0),
        ("url", "http://evil.example/x"): _ioc(ioc_type="url",
                                               value="http://evil.example/x", score=10.0),
        ("hash", "h"): _ioc(ioc_type="hash", value="0" * 64, score=95.0),
        ("ip", "198.51.100.1"): _ioc(ioc_type="ip", value="198.51.100.1", score=5.0),
    }
    out = tmp_path / "blocklist.txt"
    write_blocklist(iocs, out, min_score=40.0)
    lines = [l for l in out.read_text().splitlines() if not l.startswith("#")]
    # evil.example once (URL host deduped against the domain IOC), hash excluded,
    # low-score IP excluded; highest score first
    assert lines == ["evil.example", "203.0.113.5"]
