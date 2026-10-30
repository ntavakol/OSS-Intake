"""How old is each package version? Flag the ones published in the last few days.

Compromised releases are usually live for hours or days before they are pulled and before any advisory exists
(chalk and debug, September 2025: about two hours). A version that is only days old has had little scrutiny, so it
is worth waiting for, or checking by hand, even when no scanner reports anything. This is a signal to look, not a
finding: most new releases are fine.

Publication dates come from deps.dev, one request per package version (Maven, npm, PyPI, Go, Cargo, NuGet).
"""

from __future__ import annotations

from datetime import datetime
from urllib.parse import quote, unquote

from .enrich.fixdates import API, _system_and_name
from .http import Http, HttpError, prefetch
from .models import parse_datetime

DEFAULT_DAYS = 7
MAX_LOOKUPS = 400
LISTED = 1000
OS_TYPES = {"deb", "dpkg", "rpm", "apk"}


def _version(purl: str) -> str:
    """The decoded version: pkg:golang/x@v2.0.0%2Bincompatible -> v2.0.0+incompatible (encoded again once, in
    the URL; left encoded here it went out as %252B and deps.dev answered 404)."""
    body = purl.split("?", 1)[0].split("#", 1)[0]
    return unquote(body.rpartition("@")[2]) if "@" in body[4:] else ""


def _url(sn: tuple[str, str], version: str) -> str:
    if sn[0] == "go" and not version.startswith("v"):
        version = f"v{version}"
    return f"{API}/{sn[0]}/packages/{quote(sn[1], safe='')}/versions/{quote(version, safe='')}"


def check(http: Http, purls: list[str], as_of: datetime, days: int, limit: int = MAX_LOOKUPS) -> dict:
    """as_of is the end of the assessment period: a version published after it did not exist yet. Ages are
    counted in calendar days (published yesterday = 1 day old)."""
    info: dict = {"status": "ok", "days": days, "checked": 0, "unknown": 0, "unsupported": 0, "errors": 0,
                  "skipped_limit": 0, "recent": [], "published": {},
                  # Language package versions with no release date, for --fail-on unknown-age (capped lists).
                  "unknown_purls": [], "unsupported_purls": [],
                  # ... and those never looked up (a failed lookup, or over the limit), named in the gate's output
                  "unchecked_purls": []}
    planned = []
    for purl in dict.fromkeys(purls):
        sn, version = _system_and_name(purl), _version(purl)
        if sn and version and sn != ("go", "stdlib") and len(planned) < limit:
            planned.append(_url(sn, version))
    prefetch(http, planned)
    for purl in dict.fromkeys(purls):
        sn = _system_and_name(purl)
        version = _version(purl)
        if not sn or not version or sn == ("go", "stdlib"):
            info["unsupported"] += 1
            # A distro package (deb, rpm, apk) or the Go standard library is not a registry release that can be
            # days old; a RubyGems or CRAN version is, but deps.dev has no dates for it.
            ptype = purl[4:].split("/", 1)[0].lower() if purl.startswith("pkg:") else ""
            if ptype not in OS_TYPES and sn != ("go", "stdlib") and len(info["unsupported_purls"]) < LISTED:
                info["unsupported_purls"].append(purl)
            continue
        if info["checked"] + info["unknown"] + info["errors"] >= limit:
            info["skipped_limit"] += 1
            if len(info["unchecked_purls"]) < LISTED:
                info["unchecked_purls"].append(purl)
            continue
        if sn[0] == "go" and not version.startswith("v"):
            version = f"v{version}"
        try:
            status, data = http.get_json(_url(sn, version))
        except HttpError:
            info["errors"] += 1
            if len(info["unchecked_purls"]) < LISTED:
                info["unchecked_purls"].append(purl)
            continue
        if status not in (200, 404):  # rate limited or a server error: not checked, never "not new"
            info["errors"] += 1
            if len(info["unchecked_purls"]) < LISTED:
                info["unchecked_purls"].append(purl)
            continue
        published = parse_datetime(data.get("publishedAt")) if status == 200 and isinstance(data, dict) else None
        if not published:
            info["unknown"] += 1
            if len(info["unknown_purls"]) < LISTED:
                info["unknown_purls"].append(purl)
            continue
        info["checked"] += 1
        info["published"][purl] = published.isoformat()[:10]
        if published > as_of:
            continue  # did not exist yet on the assessment date
        age = (as_of.date() - published.date()).days
        if age < days:
            info["recent"].append({"purl": purl, "package": sn[1], "version": version,
                                   "published": published.isoformat(), "age_days": age})
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
