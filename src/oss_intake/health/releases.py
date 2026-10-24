"""Release cadence from the GitHub REST API. GITHUB_TOKEN is optional (rate limits only)."""

from __future__ import annotations

import re
from datetime import datetime
from statistics import median
from urllib.parse import quote

from ..http import Http, HttpError
from ..models import days_between, parse_datetime

API = "https://api.github.com"


def _candidates(tag: str, repo_name: str) -> list[str]:
    """Release tags that an image tag may correspond to.

    Image tags often add a variant suffix (2.528-jdk21, 1.29.2-alpine, 12.2.0-ubuntu); those are
    tried with the suffix removed as well, most specific first.
    """
    t = tag.strip()
    bases = [t.lstrip("vV")]
    head = bases[0].split("-", 1)[0]
    if head != bases[0] and head[:1].isdigit():
        bases.append(head)
    out: list[str] = []
    for bare in bases:
        for c in (bare, f"v{bare}", f"{repo_name}-{bare}", f"{repo_name}-v{bare}", f"release-{bare}"):
            if c not in out:
                out.append(c)
    return [t] + [c for c in out if c != t]


def _version_core(tag: str) -> str:
    """'R4.5.1' -> '4.5.1', 'v2.0.0' -> '2.0.0', '2.528-jdk21' -> '2.528'; '' if no version."""
    m = re.search(r"(\d+(?:\.\d+)+)", tag)
    return m.group(1) if m else ""


def fetch(http: Http, repo: str, as_of: datetime, image_tag: str | None = None,
          release_tag: str | None = None) -> dict:
    owner, name = repo.split("/", 1)
    out: dict = {"repo": repo, "status": "ok", "warnings": []}

    status, meta = http.get_json(f"{API}/repos/{owner}/{name}")
    if status == 404:
        return {"repo": repo, "status": "not_found", "warnings": [f"GitHub repository {repo} not found"]}
    if status == 403:
        return {"repo": repo, "status": "rate_limited",
                "warnings": ["GitHub API returned 403 (rate limit?). Set GITHUB_TOKEN to raise the limit."]}
    if status != 200 or not isinstance(meta, dict):
        raise HttpError(f"GitHub repo lookup returned HTTP {status}")
    out["archived"] = bool(meta.get("archived"))
    out["pushed_at"] = meta.get("pushed_at")
    out["days_since_push"] = days_between(parse_datetime(meta.get("pushed_at")), as_of)
    out["license"] = (meta.get("license") or {}).get("spdx_id")

    status, rels = http.get_json(f"{API}/repos/{owner}/{name}/releases", params={"per_page": 100})
    if status != 200 or not isinstance(rels, list):
        out["status"] = "no_releases"
        out["warnings"].append(f"GitHub releases lookup returned HTTP {status}")
        rels = []
    releases = []
    for r in rels:
        if r.get("draft"):
            continue
        dt = parse_datetime(r.get("published_at") or r.get("created_at"))
        if dt:
            releases.append({"tag": r.get("tag_name", ""), "date": dt, "prerelease": bool(r.get("prerelease"))})
    stable = sorted((r for r in releases if not r["prerelease"]), key=lambda r: r["date"], reverse=True)
    if not stable:
        if out["status"] == "ok":
            out["status"] = "no_releases"
        out["warnings"].append("No published GitHub releases; release cadence cannot be measured")
        return out

    latest = stable[0]
    out["latest_release"] = {"tag": latest["tag"], "date": latest["date"].isoformat()}
    out["days_since_latest_release"] = days_between(latest["date"], as_of)
    out["releases_last_365d"] = sum(1 for r in stable if (days_between(r["date"], as_of) or 0) <= 365)
    recent = stable[:11]
    gaps = [days_between(recent[i + 1]["date"], recent[i]["date"]) for i in range(len(recent) - 1)]
    out["median_days_between_releases"] = median(gaps) if gaps else None
    out["release_count_sampled"] = len(stable)

    wanted = release_tag or image_tag
    scanned = None
    if wanted:
        by_tag = {r["tag"]: r for r in releases}
        candidates = [release_tag] if release_tag else _candidates(wanted, name)
        for c in candidates:
            if c in by_tag:
                scanned = by_tag[c]
                break
        if scanned is None and not release_tag:
            # Tags such as "R4.5.1" or "server-31.0.9": match on the version number alone, but only
            # when exactly one release carries it, so a guess is never made between candidates.
            want = _version_core(wanted)
            hits = [r for r in releases if want and _version_core(r["tag"]) == want]
            if len(hits) == 1:
                scanned = hits[0]
        if scanned is None:
            # The list above is the newest 100 releases only. Projects with many patch and backport
            # releases (Grafana, for example) push older tags off it, so ask for each candidate directly.
            for c in candidates:
                st, rel = http.get_json(f"{API}/repos/{owner}/{name}/releases/tags/{quote(c, safe='')}")
                dt = parse_datetime((rel or {}).get("published_at")) if st == 200 and isinstance(rel, dict) else None
                if dt and not rel.get("draft"):
                    scanned = {"tag": rel.get("tag_name", c), "date": dt, "prerelease": bool(rel.get("prerelease"))}
                    break
        if scanned is None:
            out["warnings"].append(
                f"No GitHub release matches '{wanted}', so release-lag metrics are not computed (using the "
                "latest release date instead would overstate lag). Pass --release-tag or --release-date."
            )
    if scanned is None:
        out["scanned_release"] = None
        out["scanned_is_latest"] = None
        return out
    out["scanned_release"] = {"tag": scanned["tag"], "date": scanned["date"].isoformat(), "matched": True}
    out["scanned_is_latest"] = scanned["tag"] == latest["tag"]
    out["newer_stable_releases"] = [r["tag"] for r in stable if r["date"] > scanned["date"]]
    return out
