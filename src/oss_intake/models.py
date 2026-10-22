"""Core data structures and small shared helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone

SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?)?\s*(Z|[+-]\d{2}:?\d{2})?$"
)


def parse_datetime(value: str | None) -> datetime | None:
    """Parse ISO 8601 timestamps as emitted by Trivy, GitHub, OSV and deps.dev.

    datetime.fromisoformat on Python 3.10 rejects 'Z' and fractional seconds that are not
    3 or 6 digits (Trivy emits e.g. '.94Z'), so this parser is deliberately lenient.
    Returns a timezone-aware UTC datetime, or None if the value is empty or unparseable.
    """
    if not value or not isinstance(value, str):
        return None
    m = _ISO_RE.match(value.strip())
    if not m:
        return None
    y, mo, d, hh, mm, ss, frac, tz = m.groups()
    micro = int((frac or "0")[:6].ljust(6, "0"))
    dt = datetime(int(y), int(mo), int(d), int(hh or 0), int(mm or 0), int(ss or 0), micro)
    if tz and tz != "Z":
        sign = 1 if tz[0] == "+" else -1
        digits = tz[1:].replace(":", "")
        offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
        dt = (dt - sign * offset).replace(tzinfo=timezone.utc)
    else:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def days_between(start: datetime | date | None, end: datetime | date | None) -> int | None:
    if start is None or end is None:
        return None
    s = start.date() if isinstance(start, datetime) else start
    e = end.date() if isinstance(end, datetime) else end
    return (e - s).days


def normalise_severity(value: str | None) -> str:
    if not value:
        return "UNKNOWN"
    v = value.strip().upper()
    if v == "MODERATE":
        v = "MEDIUM"
    if v == "NEGLIGIBLE":
        v = "LOW"
    return v if v in SEVERITY_ORDER else "UNKNOWN"


def normalise_purl(purl: str | None) -> str | None:
    """Strip qualifiers and subpath, lower-case the type, keep name@version.

    Trivy and Grype emit different qualifiers for the same package, so merging on the
    raw purl would treat identical packages as distinct.
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    base = purl.split("#", 1)[0].split("?", 1)[0]
    rest = base[4:]
    if "/" not in rest:
        return None
    ptype, remainder = rest.split("/", 1)
    return f"pkg:{ptype.lower()}/{remainder}"


def purl_without_version(purl: str | None) -> str | None:
    n = normalise_purl(purl)
    if not n:
        return None
    # The version separator is the last '@' after the final '/'.
    head, _, tail = n.rpartition("/")
    name = tail.split("@", 1)[0]
    return f"{head}/{name}"


@dataclass
class Finding:
    vuln_id: str
    package: str
    installed: str
    severity: str = "UNKNOWN"
    fixed_versions: list[str] = field(default_factory=list)
    cvss: float | None = None
    published: datetime | None = None
    purl: str | None = None
    pkg_type: str = ""
    target: str = ""
    aliases: set[str] = field(default_factory=set)
    sources: set[str] = field(default_factory=set)
    source_severity: dict[str, str] = field(default_factory=dict)
    title: str = ""
    url: str = ""
    # Enrichment
    fix_version_used: str | None = None
    fix_published: datetime | None = None
    fix_date_source: str = ""
    kev: bool = False
    likely_fixed: bool = False
    vendor_ids: list[str] = field(default_factory=list)
    note: str = ""
    # Release-lag (set by lag.compute)
    fix_available_at_release: bool | None = None
    days_fix_available: int | None = None
    published_before_release: bool | None = None

    @property
    def has_fix(self) -> bool:
        return bool(self.fixed_versions)

    def merge_key(self) -> tuple[str, str, str]:
        pkg = purl_without_version(self.purl) or f"{self.pkg_type}:{self.package}".lower()
        return (canonical_id(self.vuln_id, self.aliases), pkg, self.installed)


def canonical_id(vuln_id: str, aliases: set[str] | None = None) -> str:
    """Prefer a CVE identifier so Trivy (CVE) and Grype (often GHSA) findings merge."""
    if vuln_id.upper().startswith("CVE-"):
        return vuln_id.upper()
    for a in sorted(aliases or ()):
        if a.upper().startswith("CVE-"):
            return a.upper()
    return vuln_id
