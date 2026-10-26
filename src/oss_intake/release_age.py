"""How old is each package version? Flag the ones published in the last few days.

Compromised releases are usually live for hours or days before they are pulled and before any advisory exists
(chalk and debug, September 2025: about two hours). A version that is only days old has had little scrutiny, so it
is worth waiting for, or checking by hand, even when no scanner reports anything. This is a signal to look, not a
finding: most new releases are fine.

Publication dates come from deps.dev, one request per package version (Maven, npm, PyPI, Go, Cargo, NuGet).
"""

from __future__ import annotations

from datetime import datetime
from urllib.parse import quote

from .enrich.fixdates import API, _system_and_name
from .http import Http, HttpError
from .models import parse_datetime

DEFAULT_DAYS = 7
MAX_LOOKUPS = 400


def _version(purl: str) -> str:
    body = purl.split("?", 1)[0].split("#", 1)[0]
    return body.rpartition("@")[2] if "@" in body[4:] else ""


def check(http: Http, purls: list[str], as_of: datetime, days: int, limit: int = MAX_LOOKUPS) -> dict:
    info: dict = {"status": "ok", "days": days, "checked": 0, "unknown": 0, "unsupported": 0, "errors": 0,
                  "skipped_limit": 0, "recent": [], "published": {}}
    for purl in dict.fromkeys(purls):
        sn = _system_and_name(purl)
        version = _version(purl)
        if not sn or not version or sn[1] == "stdlib":
            info["unsupported"] += 1
            continue
        if info["checked"] + info["unknown"] + info["errors"] >= limit:
            info["skipped_limit"] += 1
            continue
        if sn[0] == "go" and not version.startswith("v"):
            version = f"v{version}"
        try:
            status, data = http.get_json(f"{API}/{sn[0]}/packages/{quote(sn[1], safe='')}/versions/"
                                         f"{quote(version, safe='')}")
        except HttpError:
            info["errors"] += 1
            continue
        published = parse_datetime(data.get("publishedAt")) if status == 200 and isinstance(data, dict) else None
        if not published:
            info["unknown"] += 1
            continue
        info["checked"] += 1
        info["published"][purl] = published.isoformat()[:10]
        age = (as_of - published).days
        if 0 <= age < days:  # a version published after --as-of did not exist yet, so it is not counted
            info["recent"].append({"purl": purl, "package": sn[1], "version": version,
                                   "published": published.isoformat(), "age_days": max(age, 0)})
    info["recent"].sort(key=lambda r: r["published"], reverse=True)
    if info["errors"] or info["skipped_limit"]:
        info["status"] = "partial"
    return info


def describe(r: dict) -> str:
    when = "today" if r["age_days"] == 0 else f"{r['age_days']} day{'s' if r['age_days'] != 1 else ''} ago"
    return f"{r['package']} {r['version']} (published {r['published'][:10]}, {when})"


def warning(info: dict | None) -> str | None:
    if not info or not info.get("recent"):
        return None
    shown = "; ".join(describe(r) for r in info["recent"][:8])
    more = f"; and {len(info['recent']) - 8} more" if len(info["recent"]) > 8 else ""
    return (f"{len(info['recent'])} package version(s) published in the last {info['days']} days: {shown}{more}. "
            "Compromised releases are usually caught within days; wait, or check the release before relying on it")
