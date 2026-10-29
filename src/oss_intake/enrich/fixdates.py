"""Find when the fixed version of a dependency was published, via the deps.dev API.

This date is the basis of the release-lag metric: a fix counts as "available at release"
only if the fixed dependency version existed before the project's release. Using the CVE
publication date instead would overstate lag when a CVE is disclosed before its fix ships.
"""

from __future__ import annotations

import re
from urllib.parse import quote, unquote

from ..http import Http, HttpError, prefetch
from ..models import Finding, parse_datetime
from ..versions import nearest_fix

API = "https://api.deps.dev/v3/systems"
_GO_MAJOR_SUFFIX = re.compile(r"/v\d+$")
_SYSTEMS = {"maven": "maven", "npm": "npm", "pypi": "pypi", "golang": "go", "cargo": "cargo", "nuget": "nuget"}


def _system_and_name(purl: str) -> tuple[str, str] | None:
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    ptype, rest = body.split("/", 1)
    system = _SYSTEMS.get(ptype.lower())
    if not system:
        return None
    path = rest.rsplit("@", 1)[0]
    path = "/".join(unquote(p) for p in path.split("/"))
    if system == "maven":
        group, _, artifact = path.rpartition("/")
        return system, f"{group}:{artifact}"
    return system, path


def _first_url(f: Finding) -> str | None:
    """The first deps.dev URL enrich() will ask for this finding, for prefetching; None if it asks none."""
    if not f.fixed_versions or f.likely_fixed or not f.purl:
        return None
    fix, sn = nearest_fix(f.vs_fix, f.fixed_versions), _system_and_name(f.purl)
    if not sn or not fix or (sn[0] == "go" and sn[1] == "stdlib"):
        return None
    if sn[0] == "go" and not fix.startswith("v"):
        fix = f"v{fix}"
    return f"{API}/{sn[0]}/packages/{quote(sn[1], safe='')}/versions/{quote(fix, safe='')}"


def enrich(http: Http, findings: list[Finding]) -> dict:
    cache: dict[tuple[str, str, str], str | None] = {}
    stats = {"looked_up": 0, "found": 0, "unsupported": 0, "errors": 0}
    prefetch(http, [u for u in map(_first_url, findings) if u])
    for f in findings:
        if not f.fixed_versions or f.likely_fixed:
            continue
        fix = nearest_fix(f.vs_fix, f.fixed_versions)
        f.fix_version_used = fix
        sn = _system_and_name(f.purl) if f.purl else None
        if not sn or not fix:
            stats["unsupported"] += 1
            continue
        if sn[0] == "go":
            if sn[1] == "stdlib":
                stats["unsupported"] += 1
                continue
            fix = fix if fix.startswith("v") else f"v{fix}"  # Trivy/Grype omit the v; deps.dev requires it
        key = (sn[0], sn[1], fix)
        if key not in cache:
            stats["looked_up"] += 1
            versions_to_try = [fix]
            if sn[0] == "go" and not _GO_MAJOR_SUFFIX.search(sn[1]) and _major(fix) >= 2:
                # Modules at v2+ without a /vN path suffix are recorded as vX.Y.Z+incompatible.
                versions_to_try.append(f"{fix}+incompatible")
            cache[key] = None
            try:
                for v in versions_to_try:
                    url = f"{API}/{sn[0]}/packages/{quote(sn[1], safe='')}/versions/{quote(v, safe='')}"
                    status, data = http.get_json(url)
                    if status == 200 and isinstance(data, dict) and data.get("publishedAt"):
                        cache[key] = data["publishedAt"]
                        break
            except HttpError:
                stats["errors"] += 1
                continue
        published = parse_datetime(cache[key])
        if published:
            f.fix_published = published
            f.fix_date_source = "deps.dev"
            stats["found"] += 1
    return stats


def _major(v: str) -> int:
    m = re.match(r"v?(\d+)", v)
    return int(m.group(1)) if m else 0
