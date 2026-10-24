"""Debian fix dates from the Debian security tracker's advisory lists.

The tracker keeps every DSA and DLA with its release date, one header line per advisory:

    [21 Oct 2026] DLA-4807-1 libpng1.6 - security update

OSV does not carry recent DLAs (Debian 12 moved to LTS in 2026, so its fixes are now DLAs),
so this is the primary source for Debian; OSV remains the fallback for anything else.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from ..http import Http, HttpError
from ..models import Finding
from ..versions import nearest_fix
from .debian_releases import codename_for, no_epoch

BASE = "https://salsa.debian.org/security-tracker-team/security-tracker/-/raw/master/data"
LISTS = {"DSA": f"{BASE}/DSA/list", "DLA": f"{BASE}/DLA/list"}
_HEADER = re.compile(r"^\[(\d{1,2}) ([A-Za-z]{3}) (\d{4})\] ((?:DSA|DLA)-\d+(?:-\d+)?)\s")
_MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], start=1)}


def parse(text: str) -> dict[str, datetime]:
    out: dict[str, datetime] = {}
    for line in text.splitlines():
        m = _HEADER.match(line)
        if m and m.group(2) in _MONTHS:
            out[m.group(4)] = datetime(int(m.group(3)), _MONTHS[m.group(2)], int(m.group(1)), tzinfo=timezone.utc)
    return out


_RELEASE_LINE = re.compile(r"^\s+\[([a-z]+)\] - (\S+) (\S+)")


def parse_versions(text: str) -> dict[tuple[str, str, str], tuple[datetime, str]]:
    """Map (codename, source package, fixed version without epoch) to the earliest advisory shipping it.

    Advisories do not always list every CVE a version fixes (a later CVE assignment, or a fix that
    rode along), so matching on the exact fixed version dates findings the advisory ID cannot.
    """
    out: dict[tuple[str, str, str], tuple[datetime, str]] = {}
    current: tuple[datetime, str] | None = None
    for line in text.splitlines():
        m = _HEADER.match(line)
        if m and m.group(2) in _MONTHS:
            current = (datetime(int(m.group(3)), _MONTHS[m.group(2)], int(m.group(1)), tzinfo=timezone.utc),
                       m.group(4))
            continue
        r = _RELEASE_LINE.match(line)
        if r and current:
            key = (r.group(1), r.group(2), no_epoch(r.group(3)))
            if key not in out or current < out[key]:
                out[key] = current
    return out


def _is_debian(f: Finding) -> bool:
    return (f.purl or "").startswith("pkg:deb/debian/") or (f.os_release or "").startswith("debian")


def enrich(http: Http, findings: list[Finding]) -> dict:
    stats = {"candidates": 0, "found": 0, "found_by_version": 0, "lists_loaded": [], "errors": 0}
    todo = [f for f in findings if not f.fix_published and not f.likely_fixed and f.fixed_versions
            and (any(v.startswith(("DSA-", "DLA-")) for v in f.vendor_ids) or (_is_debian(f) and not f.excluded))]
    if not todo:
        return stats
    needed = {v[:3] for f in todo for v in f.vendor_ids if v.startswith(("DSA-", "DLA-"))}
    if any(_is_debian(f) and codename_for(f.os_release) for f in todo):
        needed |= {"DSA", "DLA"}
    dates: dict[str, datetime] = {}
    by_version: dict[tuple[str, str, str], tuple[datetime, str]] = {}
    for kind in sorted(needed):
        try:
            status, text = http.get_text(LISTS[kind])
        except HttpError:
            stats["errors"] += 1
            continue
        if status == 200 and text:
            parsed = parse(text)
            if parsed:
                dates.update(parsed)
                for k, v in parse_versions(text).items():
                    if k not in by_version or v < by_version[k]:
                        by_version[k] = v
                stats["lists_loaded"].append(f"{kind}:{len(parsed)}")
                continue
        stats["errors"] += 1
    for f in todo:
        stats["candidates"] += 1
        hits = [(dates[v], v) for v in f.vendor_ids if v in dates]
        if hits:
            dt, vid = min(hits)
            f.fix_published = dt
            f.fix_date_source = f"advisory {vid} (Debian tracker)"
            stats["found"] += 1
            continue
        codename = codename_for(f.os_release)
        fix = nearest_fix(f.installed, f.fixed_versions) if codename else None
        hit = by_version.get((codename, f.src_name or f.package, no_epoch(fix))) if fix else None
        if hit:
            f.fix_published, vid = hit
            f.fix_version_used = fix
            f.fix_date_source = f"advisory {vid} (Debian tracker, by fixed version)"
            stats["found"] += 1
            stats["found_by_version"] += 1
    return stats
