"""Find when the fixed version of a dependency was published, via the deps.dev API.

This date is the basis of the release-lag metric: a fix counts as "available at release"
only if the fixed dependency version existed before the project's release. Using the CVE
publication date instead would overstate lag when a CVE is disclosed before its fix ships.
"""

from __future__ import annotations

from urllib.parse import quote, unquote

from ..http import Http, HttpError
from ..models import Finding, parse_datetime
from ..versions import nearest_fix

API = "https://api.deps.dev/v3/systems"
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


def enrich(http: Http, findings: list[Finding]) -> dict:
    cache: dict[tuple[str, str, str], str | None] = {}
    stats = {"looked_up": 0, "found": 0, "unsupported": 0, "errors": 0}
    for f in findings:
        if not f.fixed_versions or f.likely_fixed:
            continue
        fix = nearest_fix(f.installed, f.fixed_versions)
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
            url = f"{API}/{sn[0]}/packages/{quote(sn[1], safe='')}/versions/{quote(fix, safe='')}"
            try:
                status, data = http.get_json(url)
            except HttpError:
                stats["errors"] += 1
                cache[key] = None
                continue
            cache[key] = data.get("publishedAt") if status == 200 and isinstance(data, dict) else None
        published = parse_datetime(cache[key])
        if published:
            f.fix_published = published
            f.fix_date_source = "deps.dev"
            stats["found"] += 1
    return stats
