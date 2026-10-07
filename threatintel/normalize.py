"""Indicator normalization and validation.

Every indicator that enters the aggregator is validated and normalized
here so the same IOC seen in two feeds always dedups to one record:

- ``ip``     -> canonical string via the ``ipaddress`` module
               (``203.0.113.5``, ``2001:db8::1``)
- ``domain`` -> lowercase, trailing dot stripped
- ``url``    -> lowercase scheme/host, default ports stripped
- ``hash``   -> lowercase hex (md5/sha1/sha256 by length)
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, urlunsplit

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)"          # total length
    r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"          # first label
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"    # at least one more label
)
_HASH_RE = re.compile(r"^[0-9a-f]+$")
_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


def hash_algorithm(value: str) -> str | None:
    """Return md5/sha1/sha256 for a normalized hash, else None."""
    return _HASH_LENGTHS.get(len(value))


def normalize_ioc(ioc_type: str, value: str) -> tuple:
    """Validate and normalize one indicator.

    Returns ``(ok, normalized_value, error)``. ``error`` is an empty
    string on success.
    """
    ioc_type = (ioc_type or "").strip().lower()
    value = (value or "").strip()
    if not value:
        return False, "", "empty value"

    if ioc_type == "ip":
        return _normalize_ip(value)
    if ioc_type == "domain":
        return _normalize_domain(value)
    if ioc_type == "url":
        return _normalize_url(value)
    if ioc_type == "hash":
        return _normalize_hash(value)
    return False, "", "unknown ioc type %r" % ioc_type


def _normalize_ip(value: str) -> tuple:
    # tolerate a trailing port such as 203.0.113.5:8080
    host = value
    if value.count(":") == 1 and "." in value:
        host = value.rsplit(":", 1)[0]
    try:
        return True, str(ipaddress.ip_address(host)), ""
    except ValueError:
        return False, "", "invalid ip address %r" % value


def _normalize_domain(value: str) -> tuple:
    domain = value.lower().rstrip(".")
    # an embedded port or path is not a bare domain
    if "/" in domain or ":" in domain or " " in domain:
        return False, "", "invalid domain %r" % value
    if not _DOMAIN_RE.match(domain):
        return False, "", "invalid domain %r" % value
    # reject pure-numeric TLDs (those are IPs, not domains)
    if domain.rsplit(".", 1)[-1].isdigit():
        return False, "", "invalid domain %r" % value
    return True, domain, ""


def _normalize_url(value: str) -> tuple:
    try:
        parts = urlsplit(value.strip())
    except ValueError:
        return False, "", "invalid url %r" % value
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return False, "", "unsupported url scheme %r" % value
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        return False, "", "url has no host %r" % value
    ok, _, _ = _normalize_domain(host)
    if not ok:
        # host may be a literal IP
        ok, host, _ = _normalize_ip(host)
        if not ok:
            return False, "", "invalid url host %r" % value
    port = parts.port
    default = {"http": 80, "https": 443}[scheme]
    netloc = host if port in (None, default) else "%s:%d" % (host, port)
    normalized = urlunsplit((scheme, netloc, parts.path or "", parts.query, ""))
    return True, normalized, ""


def _normalize_hash(value: str) -> tuple:
    digest = value.lower().replace(" ", "")
    if not _HASH_RE.match(digest):
        return False, "", "hash is not hex %r" % value
    if hash_algorithm(digest) is None:
        return False, "", "unsupported hash length %d" % len(digest)
    return True, digest, ""
