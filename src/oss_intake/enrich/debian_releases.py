"""Debian fix dates from point releases, for fixes that shipped without a DSA or DLA.

Many Debian stable fixes go through proposed-updates and reach users in the next point release
(13.1, 13.2, ...), with no security advisory. Each suite's ChangeLog on the Debian mirrors lists
every upload, newest first, under a banner for the point release that shipped it:

    Sat, 11 Jul 2026 - Debian 13.6 released
    ...
    apache2 (2.4.68-1~deb13u1) trixie; urgency=medium

The fix date is the date of the point release that shipped the exact fixed version. Uploads above
the newest banner are still waiting in proposed-updates: not yet available, so left undated.
"""

from __future__ import annotations

import re
from datetime import datetime

from ..http import Http, HttpError
from ..models import Finding, safe_date
from ..versions import nearest_fix

URL = "https://deb.debian.org/debian/dists/{codename}/ChangeLog"
CODENAMES = {"10": "buster", "11": "bullseye", "12": "bookworm", "13": "trixie", "14": "forky"}
_BANNER = re.compile(r"^\s*\w{3}, (\d{1,2}) (\w{3}) (\d{4}) - Debian (\d+(?:\.\d+)?) released\s*$")
_ENTRY = re.compile(r"^([a-z0-9][a-z0-9.+-]+) \(([^)\s]+)\) [a-z0-9, -]+; urgency=", re.IGNORECASE)
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}
PENDING = "proposed-updates"


def no_epoch(v: str) -> str:
    head, sep, tail = v.partition(":")
    return tail if sep and head.isdigit() else v


def codename_for(os_release: str) -> str | None:
    m = re.match(r"^debian (\d+)", (os_release or "").strip().lower())
    return CODENAMES.get(m.group(1)) if m else None


def parse(text: str) -> dict[tuple[str, str], tuple[datetime | None, str]]:
    """Map (source package, version without epoch) to (point release date, release number)."""
    out: dict[tuple[str, str], tuple[datetime | None, str]] = {}
    current: tuple[datetime | None, str] = (None, PENDING)
    for line in text.splitlines():
        b = _BANNER.match(line)
        if b and b.group(2) in _MONTHS:
            current = (safe_date(int(b.group(3)), _MONTHS[b.group(2)], int(b.group(1))), b.group(4))
            continue
        e = _ENTRY.match(line)
        if e:
            out[(e.group(1), no_epoch(e.group(2)))] = current  # further down is older; the oldest release wins
    return out


def _is_debian(f: Finding) -> bool:
    return (f.purl or "").startswith("pkg:deb/debian/") or (f.os_release or "").startswith("debian")


def enrich(http: Http, findings: list[Finding]) -> dict:
    stats = {"candidates": 0, "found": 0, "pending": 0, "suites_loaded": [], "errors": 0}
    suites: dict[str, dict] = {}
    for f in findings:
        if f.fix_published or f.likely_fixed or f.excluded or not f.fixed_versions or not _is_debian(f):
            continue
        codename = codename_for(f.os_release)
        fix = nearest_fix(f.vs_fix, f.fixed_versions)
        if not codename or not fix:
            continue
        stats["candidates"] += 1
        if codename not in suites:
            suites[codename] = {}
            try:
                status, text = http.get_text(URL.format(codename=codename))
            except HttpError:
                stats["errors"] += 1
                continue
            if status == 200 and text:
                suites[codename] = parse(text)
                stats["suites_loaded"].append(f"{codename}:{len(suites[codename])}")
            elif status != 404:
                stats["errors"] += 1
        hit = suites[codename].get((f.src_name or f.package, no_epoch(fix)))
        if not hit:
            continue
        dt, release = hit
        if dt is None:
            stats["pending"] += 1
            note = f"fix {fix} is in Debian proposed-updates, not yet in a point release"
            f.note = f"{f.note}; {note}" if f.note else note
            continue
        f.fix_published = dt
        f.fix_version_used = fix
        f.fix_date_source = f"point release Debian {release}"
        stats["found"] += 1
    return stats
