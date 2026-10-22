"""Fix dates for OS packages from distro security advisories, fetched from OSV.

Fallback after debian_tracker, which is the primary Debian source because OSV lacks recent DLAs.
Trivy reports the advisory that shipped each Debian fix (DSA-/DLA-) in VendorIDs; USN- IDs are used
if present, but Trivy 0.76 reports none for Ubuntu. An advisory's publication date is when the
fixed package was released to that distro, which is the fix date release lag needs. Alpine has no
dated advisories and Ubuntu findings carry no advisory IDs, so both stay unknown rather than guessed.
"""

from __future__ import annotations

import re

from ..http import Http, HttpError
from ..models import Finding, parse_datetime

API = "https://api.osv.dev/v1/vulns"
_ADVISORY = re.compile(r"^(DSA|DLA|USN)-\d+(-\d+)?$")


def enrich(http: Http, findings: list[Finding]) -> dict:
    cache: dict[str, str | None] = {}
    stats = {"candidates": 0, "found": 0, "errors": 0}
    for f in findings:
        if f.fix_published or f.likely_fixed or not f.fixed_versions:
            continue
        ids = [v for v in f.vendor_ids if _ADVISORY.match(v)]
        if not ids:
            continue
        stats["candidates"] += 1
        best = None
        best_id = ""
        for vid in ids:
            if vid not in cache:
                try:
                    status, data = http.get_json(f"{API}/{vid}")
                except HttpError:
                    stats["errors"] += 1
                    cache[vid] = None
                    continue
                cache[vid] = data.get("published") if status == 200 and isinstance(data, dict) else None
            dt = parse_datetime(cache[vid])
            if dt and (best is None or dt < best):
                best, best_id = dt, vid
        if best:
            f.fix_published = best
            f.fix_date_source = f"advisory {best_id}"
            stats["found"] += 1
    return stats
