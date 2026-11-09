"""R (CRAN) fix dates from crandb, r-hub's database of every CRAN package and version.

deps.dev does not cover CRAN. crandb.r-pkg.org/<package>/all returns a package's whole history in one request,
with a "timeline" of when each version was published on CRAN, so each package is fetched once. crandb is run by
r-hub (the R Consortium-funded team behind pak), not by CRAN itself; a version it does not list stays undated.
"""

from __future__ import annotations

import re
from urllib.parse import quote, unquote

from ..http import Http, HttpError, prefetch
from ..models import Finding, parse_datetime
from ..versions import compare, nearest_fix

API = "https://crandb.r-pkg.org/{name}/all"
MAX_PACKAGES = 300  # packages looked up per run
_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9.]{0,99}$")  # an R package name, as CRAN allows it


def _name(purl: str | None) -> str | None:
    if not purl or not purl.lower().startswith("pkg:cran/"):
        return None
    name = unquote(purl[len("pkg:cran/"):].split("?", 1)[0].split("#", 1)[0].rsplit("@", 1)[0])
    return name if _NAME.match(name) else None


def _wanted(f: Finding) -> bool:
    return bool(not f.fix_published and not f.likely_fixed and f.fixed_versions and f.purl and _name(f.purl))


def enrich(http: Http, findings: list[Finding]) -> dict:
    """Set fix_published on CRAN findings to the nearest fix's publication time from crandb. Mutates findings in
    place; returns stats: packages, found, errors, skipped_limit."""
    names = list(dict.fromkeys(_name(f.purl) for f in findings if _wanted(f)))
    todo = [n for n in names if n][:MAX_PACKAGES]
    prefetch(http, [API.format(name=quote(n, safe="")) for n in todo])
    stats = {"packages": 0, "found": 0, "errors": 0, "skipped_limit": len(names) - len(todo)}
    cache: dict[str, dict[str, str]] = {}
    for f in findings:
        if not _wanted(f):
            continue
        name, fix = _name(f.purl), nearest_fix(f.vs_fix, f.fixed_versions)
        if not name or not fix or name not in todo:
            continue
        if name not in cache:
            stats["packages"] += 1
            cache[name] = {}
            try:
                status, data = http.get_json(API.format(name=quote(name, safe="")))
            except HttpError:
                stats["errors"] += 1
                continue
            timeline = data.get("timeline") if status == 200 and isinstance(data, dict) else None
            if isinstance(timeline, dict):
                cache[name] = {str(v): t for v, t in timeline.items() if isinstance(t, str)}
            elif status not in (200, 404):
                stats["errors"] += 1
        for version, time in cache[name].items():
            if compare(version, fix) == 0 and parse_datetime(time):
                f.fix_published = parse_datetime(time)
                f.fix_version_used = fix
                f.fix_date_source = "CRAN (crandb)"
                stats["found"] += 1
                break
    return stats
