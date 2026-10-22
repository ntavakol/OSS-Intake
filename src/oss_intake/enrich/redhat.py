"""Red Hat family fix dates (RHEL, UBI, and rebuilds that reuse Red Hat advisories).

Trivy attaches the Red Hat advisory that fixed each finding (RHSA-YYYY:NNNNN, specific to the
image's RHEL release) in VendorIDs. The advisory's CSAF document from Red Hat gives its
initial release date, which is the fix date. OSV mirrors RHSAs too, but its published date can
trail Red Hat's by days, so it is used only by the generic advisory fallback.
"""

from __future__ import annotations

import re

from ..http import Http, HttpError
from ..models import Finding, parse_datetime

CSAF = "https://access.redhat.com/hydra/rest/securitydata/csaf/{id}.json"
_RH = re.compile(r"^RH[SBE]A-\d{4}:\d+$")


def enrich(http: Http, findings: list[Finding]) -> dict:
    cache: dict[str, str | None] = {}
    stats = {"candidates": 0, "advisories_fetched": 0, "found": 0, "errors": 0}
    for f in findings:
        if f.fix_published or f.likely_fixed or not f.fixed_versions:
            continue
        ids = [v for v in f.vendor_ids if _RH.match(v)]
        if not ids:
            continue
        stats["candidates"] += 1
        best, best_id = None, ""
        for vid in ids:
            if vid not in cache:
                try:
                    status, doc = http.get_json(CSAF.format(id=vid))
                except HttpError:
                    stats["errors"] += 1
                    cache[vid] = None
                    continue
                tracking = ((doc or {}).get("document") or {}).get("tracking") or {} if status == 200 else {}
                cache[vid] = tracking.get("initial_release_date") or tracking.get("current_release_date")
                stats["advisories_fetched"] += 1
            dt = parse_datetime(cache[vid])
            if dt and (best is None or dt < best):
                best, best_id = dt, vid
        if best:
            f.fix_published = best
            f.fix_date_source = f"advisory {best_id} (Red Hat)"
            stats["found"] += 1
    return stats
