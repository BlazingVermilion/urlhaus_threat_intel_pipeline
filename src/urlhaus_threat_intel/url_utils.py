"""URL parsing and normalization helpers.

The original internship script parsed URLs by splitting strings manually. This
module uses Python's standard URL parser and explicit fallbacks so malformed
or partially valid indicators can still be analyzed safely.
"""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from urllib.parse import urlparse


@dataclass(frozen=True)
class ParsedUrl:
    """Normalized URL fields used by the enrichment pipeline."""

    scheme: str | None
    host: str | None
    host_type: str
    registered_domain: str | None
    tld: str | None
    ip_address: str | None
    port: int | None
    path: str
    path_depth: int
    url_length: int
    has_query: bool


def _safe_int(value: str | int | None) -> int | None:
    if value in (None, "", "None"):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def infer_default_port(scheme: str | None) -> int | None:
    """Infer a default network port from a URL scheme."""

    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    return None


def classify_host(host: str | None) -> tuple[str, str | None]:
    """Return host type and IP string if the host is an IP address."""

    if not host:
        return "missing", None
    try:
        return "ip", str(ip_address(host.strip("[]")))
    except ValueError:
        return "domain", None


def extract_registered_domain(host: str | None) -> tuple[str | None, str | None]:
    """Extract a lightweight registered-domain approximation.

    This intentionally avoids external public-suffix-list downloads so the
    pipeline remains reproducible offline. For production-grade domain parsing,
    this function can be replaced with tldextract.
    """

    if not host:
        return None, None

    host = host.strip("[]").lower().rstrip(".")
    host_type, _ = classify_host(host)
    if host_type != "domain":
        return None, None

    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return host, None

    tld = labels[-1]
    registered_domain = ".".join(labels[-2:])
    return registered_domain, tld


def parse_url(value: str | None) -> ParsedUrl:
    """Parse a URLhaus URL into stable enrichment fields."""

    raw_url = (value or "").strip()
    parsed = urlparse(raw_url)

    # Some malformed URLs may not include a scheme. Prefixing with // lets
    # urlparse interpret the first component as netloc without changing output.
    if not parsed.netloc and raw_url and "://" not in raw_url:
        parsed = urlparse(f"//{raw_url}")

    scheme = parsed.scheme.lower() or None
    host = parsed.hostname.lower() if parsed.hostname else None
    host_type, ip_string = classify_host(host)
    registered_domain, tld = extract_registered_domain(host)

    port = _safe_int(parsed.port) if parsed.port is not None else infer_default_port(scheme)
    path = parsed.path or ""
    path_depth = len([segment for segment in path.split("/") if segment])

    return ParsedUrl(
        scheme=scheme,
        host=host,
        host_type=host_type,
        registered_domain=registered_domain,
        tld=tld,
        ip_address=ip_string,
        port=port,
        path=path,
        path_depth=path_depth,
        url_length=len(raw_url),
        has_query=bool(parsed.query),
    )
