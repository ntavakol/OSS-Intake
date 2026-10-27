"""Core data structures and small shared helpers."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from urllib.parse import unquote

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
    try:  # an impossible date (2026-02-30, hour 25) is unparseable, not a crash
        dt = datetime(int(y), int(mo), int(d), int(hh or 0), int(mm or 0), int(ss or 0), micro)
        if tz and tz != "Z":
            sign = 1 if tz[0] == "+" else -1
            digits = tz[1:].replace(":", "")
            offset = timedelta(hours=int(digits[:2]), minutes=int(digits[2:4]))
            return (dt - sign * offset).replace(tzinfo=timezone.utc)
        return dt.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        return None


def safe_date(year: int, month: int, day: int) -> datetime | None:
    """A UTC date, or None for an impossible one (31 Feb) found in upstream data."""
    try:
        return datetime(year, month, day, tzinfo=timezone.utc)
    except (ValueError, OverflowError):
        return None


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
    cvss_version: str = ""  # "3.1", "3.0" or "4.0"; v4 is used only when no source gave a v3 score
    cvss_source: str = ""  # database the score came from: nvd, ghsa, redhat, debian...
    published: datetime | None = None
    purl: str | None = None
    pkg_type: str = ""
    target: str = ""
    aliases: set[str] = field(default_factory=set)
    cwes: set[str] = field(default_factory=set)  # CWE IDs from the advisory, e.g. CWE-506 for malware
    labels: dict[str, str] = field(default_factory=dict)  # inventory label columns, e.g. owner or system
    sources: set[str] = field(default_factory=set)
    source_severity: dict[str, str] = field(default_factory=dict)
    title: str = ""
    url: str = ""
    description: str = ""  # full advisory text, for the conditions excerpt
    conditions: str = ""  # the advisory's own "affected only if" sentences, verbatim
    exploit_level: str = ""  # kev | weaponised | public | poc | none | "" (not checked)
    exploit_refs: list[str] = field(default_factory=list)
    reachability: str = ""  # govulncheck evidence for Go binaries: reachable | not reachable | ""
    reachability_note: str = ""
    malicious_package: bool = False  # another finding on this package version is malicious
    decision_status: str = ""  # assessor decision carried in with --decisions (OpenVEX status)
    decision_notes: str = ""
    decision_reachable: str = ""
    decision_justification: str = ""
    decision_version: str = ""
    # For an OS package from an SBOM: the source package's version, which distro fixes are versions of (cpp
    # 4:13.2.0 is built from gcc-defaults 1.214). 'installed' stays the package's own version, as everywhere.
    source_installed: str = ""  # the installed version the decision was made for
    triage_group: str = ""  # suggested reading order: act | review | conditions | routine | aside
    triage_reason: str = ""
    # Enrichment
    fix_version_used: str | None = None
    fix_published: datetime | None = None
    fix_date_source: str = ""
    kev: bool = False
    epss: float | None = None
    epss_percentile: float | None = None
    likely_fixed: bool = False
    excluded: str = ""  # reason the finding is kept but left out of lag and likelihood, e.g. "kernel-headers"
    vendor_ids: list[str] = field(default_factory=list)
    src_name: str = ""  # OS source package (Trivy SrcName), needed to match distro notices
    src_version: str = ""
    os_release: str = ""  # e.g. "ubuntu 24.04", for OS package findings
    note: str = ""
    # Release-lag (set by lag.compute)
    fix_available_at_release: bool | None = None
    days_fix_available: int | None = None
    published_before_release: bool | None = None

    @property
    def malicious(self) -> bool:
        """The package version itself is malware, not a version with a bug: listed in the OpenSSF malicious
        packages database (OSV IDs starting MAL-), or the advisory is classed as embedded malicious code
        (CWE-506). Many malware advisories (ua-parser-js 0.7.29, event-stream 3.3.6) have no MAL- entry but are
        tagged CWE-506."""
        return (self.malicious_package or MALWARE_CWE in self.cwes
                or any(str(i).upper().startswith("MAL-") for i in {self.vuln_id, *self.aliases}))

    @property
    def has_fix(self) -> bool:
        return bool(self.fixed_versions)

    @property
    def vs_fix(self) -> str:
        """The version to compare with fix versions."""
        return self.source_installed or self.installed

    def merge_key(self) -> tuple[str, str, str]:
        # Decode %40 and friends: OSV and Trivy may encode an npm scope (@ctrl) differently.
        pkg = unquote(purl_without_version(self.purl) or "") or f"{self.pkg_type}:{self.package}".lower()
        # An OS package from an SBOM (asked of OSV by distro): keep the release in its identity. Scanner purls
        # (Trivy, Grype) carry other qualifiers too and are merged without them, as before.
        if self.sources == {"osv"} and self.os_release and "?distro=" in (self.purl or ""):
            pkg += "?" + self.purl.split("?", 1)[1]
        return (canonical_id(self.vuln_id, self.aliases), pkg, self.installed)


MALWARE_CWE = "CWE-506"  # Embedded Malicious Code


def canonical_id(vuln_id: str, aliases: set[str] | None = None) -> str:
    """Prefer a CVE identifier so Trivy (CVE) and Grype (often GHSA) findings merge; without one, a GHSA
    identifier, so an OSV malicious-package entry (MAL-) merges with the GitHub advisory it aliases."""
    ids = [vuln_id, *sorted(aliases or ())]
    for prefix in ("CVE-", "GHSA-"):
        for a in ids:
            if a.upper().startswith(prefix):
                return a.upper() if prefix == "CVE-" else a
    return vuln_id
