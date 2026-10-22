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


def enrich(http: Http, findings: list[Finding]) -> dict:
    stats = {"candidates": 0, "found": 0, "lists_loaded": [], "errors": 0}
    todo = [f for f in findings if not f.fix_published and not f.likely_fixed and f.fixed_versions
            and any(v.startswith(("DSA-", "DLA-")) for v in f.vendor_ids)]
    if not todo:
        return stats
    needed = {v[:3] for f in todo for v in f.vendor_ids if v.startswith(("DSA-", "DLA-"))}
    dates: dict[str, datetime] = {}
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
    return stats
