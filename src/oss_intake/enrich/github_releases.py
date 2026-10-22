"""Fallback fix dates for Go modules hosted on GitHub, from the module's GitHub release.

deps.dev does not index every Go module version (it has none of Grafana's v12 releases, for
example). For a module at github.com/OWNER/REPO, the release tagged vX.Y.Z on that repository
is where the fixed version was published, so its date is a sound fix date.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from ..http import Http, HttpError
from ..models import Finding, parse_datetime
from ..versions import nearest_fix

API = "https://api.github.com/repos"
MAX_LOOKUPS = 50  # protects the unauthenticated GitHub rate limit (60 requests per hour)
_GH_MODULE = re.compile(r"^pkg:golang/github\.com/([A-Za-z0-9-]+)/([A-Za-z0-9._-]+)")


def enrich(http: Http, findings: list[Finding]) -> dict:
    cache: dict[tuple[str, str, str], str | None] = {}
    stats = {"looked_up": 0, "found": 0, "skipped_limit": 0, "errors": 0}
    for f in findings:
        if f.fix_published or f.likely_fixed or not f.fixed_versions or not f.purl:
            continue
        m = _GH_MODULE.match(f.purl)
        fix = nearest_fix(f.installed, f.fixed_versions)
        if not m or not fix or f.package == "stdlib":
            continue
        tag = "v" + fix.lstrip("vV").removesuffix("+incompatible")
        key = (m.group(1), m.group(2), tag)
        if key not in cache:
            if stats["looked_up"] >= MAX_LOOKUPS:
                stats["skipped_limit"] += 1
                continue
            stats["looked_up"] += 1
            try:
                status, rel = http.get_json(f"{API}/{key[0]}/{key[1]}/releases/tags/{quote(tag, safe='')}")
            except HttpError:
                stats["errors"] += 1
                cache[key] = None
                continue
            ok = status == 200 and isinstance(rel, dict) and not rel.get("draft")
            cache[key] = rel.get("published_at") if ok else None
        dt = parse_datetime(cache[key])
        if dt:
            f.fix_published = dt
            f.fix_version_used = fix
            f.fix_date_source = f"GitHub release {key[0]}/{key[1]}@{tag}"
            stats["found"] += 1
    return stats
