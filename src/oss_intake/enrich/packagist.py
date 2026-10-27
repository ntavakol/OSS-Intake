"""PHP Composer fix dates from Packagist, which records a release time for every version.

deps.dev does not cover Packagist. The p2 metadata endpoint returns all versions of a package
with their release time in one request, so each package is fetched once.
"""

from __future__ import annotations

from urllib.parse import unquote

from ..http import Http, HttpError
from ..models import Finding, parse_datetime
from ..versions import compare, nearest_fix

API = "https://repo.packagist.org/p2/{name}.json"


def _name(purl: str) -> str | None:
    if not purl.startswith("pkg:composer/"):
        return None
    path = purl[len("pkg:composer/"):].split("?", 1)[0].split("#", 1)[0].rsplit("@", 1)[0]
    path = unquote(path).lower()
    return path if path.count("/") == 1 else None


def enrich(http: Http, findings: list[Finding]) -> dict:
    cache: dict[str, list[tuple[str, str]]] = {}
    stats = {"packages": 0, "found": 0, "errors": 0}
    for f in findings:
        if f.fix_published or f.likely_fixed or not f.fixed_versions or not f.purl:
            continue
        name = _name(f.purl)
        fix = nearest_fix(f.vs_fix, f.fixed_versions)
        if not name or not fix:
            continue
        if name not in cache:
            stats["packages"] += 1
            try:
                status, data = http.get_json(API.format(name=name))
            except HttpError:
                stats["errors"] += 1
                cache[name] = []
                continue
            versions = ((data or {}).get("packages") or {}).get(name) or [] if status == 200 else []
            cache[name] = [(str(v.get("version", "")), v.get("time", "")) for v in versions if v.get("version")]
        for version, time in cache[name]:
            if compare(version, fix) == 0 and parse_datetime(time):
                f.fix_published = parse_datetime(time)
                f.fix_version_used = fix
                f.fix_date_source = "Packagist"
                stats["found"] += 1
                break
    return stats
