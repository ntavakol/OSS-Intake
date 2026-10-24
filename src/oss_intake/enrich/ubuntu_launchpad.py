"""Ubuntu fix dates from Launchpad's publishing history, for fixes no USN match dated.

Launchpad records when each source package version was published to each Ubuntu release and pocket
(Release, Security, Updates, Proposed). The fix date is the earliest publication of the exact fixed
version in a pocket users get by default: Release, Security or Updates. Proposed is excluded, since it
is opt-in testing. In validation (mongo 7.0.14, Ubuntu 22.04) most of these fixes were in Security, so
they had notices that the OSV notice match did not find.

Requests are anonymous (api.launchpad.net), one per source package and version, cached and capped.
"""

from __future__ import annotations

import re

from ..http import Http, HttpError
from ..models import Finding, parse_datetime
from ..versions import nearest_fix

API = "https://api.launchpad.net/1.0"
POCKETS = {"Release", "Security", "Updates"}
MAX_LOOKUPS = 200
_REL = re.compile(r"^ubuntu (\d{2}\.\d{2})")


def _is_ubuntu(f: Finding) -> bool:
    return (f.purl or "").startswith("pkg:deb/ubuntu/") or (f.os_release or "").startswith("ubuntu")


def series_links(http: Http) -> dict[str, str]:
    """Map Ubuntu version ('22.04') to the Launchpad series link."""
    status, data = http.get_json(f"{API}/ubuntu/series")
    if status != 200 or not isinstance(data, dict):
        raise HttpError(f"Launchpad series list returned HTTP {status}")
    return {e["version"]: e["self_link"] for e in data.get("entries", [])
            if isinstance(e, dict) and e.get("version") and e.get("self_link")}


def earliest(entries: list[dict]) -> tuple[object, str] | None:
    best = None
    for e in entries:
        dt = parse_datetime(e.get("date_published"))
        if dt and e.get("pocket") in POCKETS and (best is None or dt < best[0]):
            best = (dt, e["pocket"])
    return best


def enrich(http: Http, findings: list[Finding]) -> dict:
    stats = {"candidates": 0, "found": 0, "lookups": 0, "skipped_limit": 0, "errors": 0}
    todo = [f for f in findings if _is_ubuntu(f) and not f.fix_published and not f.likely_fixed
            and not f.excluded and f.fixed_versions and _REL.match((f.os_release or "").lower())]
    if not todo:
        return stats
    try:
        links = series_links(http)
    except HttpError:
        stats["errors"] += 1
        return stats
    cache: dict[tuple[str, str, str], tuple | None] = {}
    for f in todo:
        stats["candidates"] += 1
        link = links.get(_REL.match(f.os_release.lower()).group(1))
        fix = nearest_fix(f.installed, f.fixed_versions)
        if not link or not fix:
            continue
        src = f.src_name or f.package
        key = (link, src, fix)
        if key not in cache:
            if stats["lookups"] >= MAX_LOOKUPS:
                stats["skipped_limit"] += 1
                continue
            stats["lookups"] += 1
            try:
                status, data = http.get_json(f"{API}/ubuntu/+archive/primary", params={
                    "ws.op": "getPublishedSources", "source_name": src, "version": fix, "exact_match": "true",
                    "distro_series": link, "ws.size": 50})
            except HttpError:
                stats["errors"] += 1
                cache[key] = None
                continue
            cache[key] = earliest(data.get("entries", [])) if status == 200 and isinstance(data, dict) else None
        hit = cache[key]
        if hit:
            f.fix_published, pocket = hit
            f.fix_version_used = fix
            f.fix_date_source = f"Launchpad publication ({pocket})"
            stats["found"] += 1
    return stats
