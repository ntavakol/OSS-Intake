"""Release cadence from the project's forge: the GitHub REST API (GITHUB_TOKEN optional, rate limits only), GitLab's
(gitlab.com) or Forgejo's (codeberg.org), both public and asked without a token."""

from __future__ import annotations

import re
from datetime import datetime
from statistics import median
from urllib.parse import quote

from ..http import Http, HttpError
from ..models import days_between, parse_datetime

API = "https://api.github.com"
GITLAB_API = "https://gitlab.com/api/v4/projects"
CODEBERG_API = "https://codeberg.org/api/v1/repos"
FORGE_NAMES = {"github": "GitHub", "gitlab": "GitLab", "codeberg": "Codeberg"}
# GitLab releases carry no pre-release flag: a tag that says so is taken as one. A word (1.0.0-beta.1, 2.0-rc1),
# PEP 440's letters after a digit (1.0b1, 2.0a2, 3.1rc1) or a Maven milestone (3.0.0-M1), with anything after it
# (1.0.0-beta.1+build.5, 2.0.0-alpha.1.2).
_PRE = re.compile(r"(?i)(?:(?:^|[.\-_+\d])(?:alpha|beta|rc|pre|preview|dev|snapshot)(?:[.\-_]?\d+)?"
                  r"|\d(?:a|b|rc)\d+|[.\-_]m\d+)(?:[.\-_+][0-9a-z.\-_+]*)?$")


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


def _forge(repo: str) -> tuple[str, str]:
    """('github' | 'gitlab' | 'codeberg', the path on that forge) for a validated --repo."""
    from ..options import forge_of

    forge = forge_of(repo)
    return forge, (repo if forge == "github" else repo.partition("/")[2])


# GitLab names a licence by its licensee key (lower case, "apache-2.0"); GitHub, which uses the same keys, gives
# the SPDX ID ("Apache-2.0"). The licences licensee knows, as SPDX writes them; "other" is GitHub's NOASSERTION.
# A key not listed is kept as GitLab gives it.
_SPDX_IDS = {k.lower(): k for k in (
    "0BSD", "AFL-3.0", "AGPL-3.0", "Apache-2.0", "Artistic-2.0", "BlueOak-1.0.0", "BSD-2-Clause",
    "BSD-2-Clause-Patent", "BSD-3-Clause", "BSD-3-Clause-Clear", "BSD-4-Clause", "BSL-1.0", "CC-BY-4.0",
    "CC-BY-SA-4.0", "CC0-1.0", "CECILL-2.1", "CERN-OHL-P-2.0", "CERN-OHL-S-2.0", "CERN-OHL-W-2.0", "ECL-2.0",
    "EPL-1.0", "EPL-2.0", "EUPL-1.1", "EUPL-1.2", "GFDL-1.3", "GPL-2.0", "GPL-3.0", "ISC", "LGPL-2.1", "LGPL-3.0",
    "LPPL-1.3c", "MIT", "MIT-0", "MPL-2.0", "MS-PL", "MS-RL", "MulanPSL-2.0", "NCSA", "ODbL-1.0", "OFL-1.1",
    "OSL-3.0", "PostgreSQL", "Unlicense", "UPL-1.0", "Vim", "WTFPL", "Zlib")}
_SPDX_IDS["other"] = "NOASSERTION"


def _meta(http: Http, forge: str, path: str) -> tuple[int, dict]:
    """The repository's status code and its archived, pushed_at and license, as GitHub names them."""
    if forge == "gitlab":
        status, data = http.get_json(f"{GITLAB_API}/{quote(path, safe='')}", params={"license": "true"})
        if status != 200 or not isinstance(data, dict):
            return status, {}
        lic = data.get("license")
        key = lic.get("key") if isinstance(lic, dict) and isinstance(lic.get("key"), str) else None
        # last_activity_at moves with issues and merge requests too: the latest commit on the default branch is
        # what GitHub's pushed_at measures.
        pushed = None
        try:
            st, commits = http.get_json(f"{GITLAB_API}/{quote(path, safe='')}/repository/commits",
                                        params={"per_page": 1})
            if st == 200 and isinstance(commits, list) and commits and isinstance(commits[0], dict):
                pushed = commits[0].get("committed_date")
        except HttpError:
            pass
        return status, {"archived": data.get("archived"), "pushed_at": pushed,
                        "license": _SPDX_IDS.get(key.lower(), key) if key else None}
    if forge == "codeberg":
        status, data = http.get_json(f"{CODEBERG_API}/{path}")
        if status != 200 or not isinstance(data, dict):
            return status, {}
        # Forgejo (Codeberg) does not detect a repository's licence (a live answer, 8 Nov 2026, has no such
        # field); Gitea's "licenses" list is read if Codeberg ever gives one.
        lics = data.get("licenses")
        return status, {"archived": data.get("archived"), "pushed_at": data.get("updated_at"),
                        "license": "; ".join(x for x in lics if isinstance(x, str)) or None
                        if isinstance(lics, list) else None,
                        **({} if isinstance(lics, list) else
                           {"license_note": "Codeberg does not report a repository's licence"})}
    status, data = http.get_json(f"{API}/repos/{path}")
    if status != 200 or not isinstance(data, dict):
        return status, {}
    lic = data.get("license")
    return status, {"archived": data.get("archived"), "pushed_at": data.get("pushed_at"),
                    "license": lic.get("spdx_id") if isinstance(lic, dict) and isinstance(lic.get("spdx_id"), str)
                    else None}


def _release(forge: str, r: object) -> dict | None:
    """A release as {"tag", "date", "prerelease"}, or None for a draft, an upcoming one or one with no date."""
    if not isinstance(r, dict) or r.get("draft") or r.get("upcoming_release"):
        return None
    tag = r["tag_name"] if isinstance(r.get("tag_name"), str) else ""
    when = r.get("released_at") if forge == "gitlab" else r.get("published_at") or r.get("created_at")
    dt = parse_datetime(when)
    if not dt:
        return None
    pre = bool(_PRE.search(tag)) if forge == "gitlab" else bool(r.get("prerelease"))
    return {"tag": tag, "date": dt, "prerelease": pre}


def _releases(http: Http, forge: str, path: str) -> tuple[int, list]:
    if forge == "gitlab":
        return http.get_json(f"{GITLAB_API}/{quote(path, safe='')}/releases",
                             params={"per_page": 100, "order_by": "released_at", "sort": "desc"})
    if forge == "codeberg":
        return http.get_json(f"{CODEBERG_API}/{path}/releases", params={"limit": 50})
    return http.get_json(f"{API}/repos/{path}/releases", params={"per_page": 100})


def _release_by_tag(http: Http, forge: str, path: str, tag: str) -> tuple[int, object]:
    t = quote(tag, safe="")
    if forge == "gitlab":
        return http.get_json(f"{GITLAB_API}/{quote(path, safe='')}/releases/{t}")
    if forge == "codeberg":
        return http.get_json(f"{CODEBERG_API}/{path}/releases/tags/{t}")
    return http.get_json(f"{API}/repos/{path}/releases/tags/{t}")


def fetch(http: Http, repo: str, as_of: datetime, image_tag: str | None = None,
          release_tag: str | None = None) -> dict:
    """Repository and release data from the project's forge (GitHub, GitLab or Codeberg): archived, last push,
    licence, latest release, cadence, and the release matching release_tag or image_tag. Returns a dict with
    status (ok, not_found, rate_limited or no_releases) and warnings; raises HttpError if the repository lookup
    fails otherwise."""
    forge, path = _forge(repo)
    host = FORGE_NAMES[forge]
    name = path.rsplit("/", 1)[-1]
    out: dict = {"repo": repo, "forge": forge, "status": "ok", "warnings": []}

    status, meta = _meta(http, forge, path)
    if status == 404:
        return {"repo": repo, "forge": forge, "status": "not_found",
                "warnings": [f"{host} repository {repo} not found"]}
    if status in (403, 429):
        return {"repo": repo, "forge": forge, "status": "rate_limited",
                "warnings": [f"{host} API returned {status} (rate limit?)."
                             + (" Set GITHUB_TOKEN to raise the limit." if forge == "github" else "")]}
    if status != 200 or not meta:
        raise HttpError(f"{host} repo lookup returned HTTP {status}")
    out["archived"] = bool(meta.get("archived"))
    out["pushed_at"] = meta.get("pushed_at")
    out["days_since_push"] = days_between(parse_datetime(meta.get("pushed_at")), as_of)
    out["license"] = meta.get("license")
    if meta.get("license_note"):
        out["license_note"] = meta["license_note"]

    status, rels = _releases(http, forge, path)
    if status != 200 or not isinstance(rels, list):
        out["status"] = "no_releases"
        out["warnings"].append(f"{host} releases lookup returned HTTP {status}")
        rels = []
    releases = [r for r in (_release(forge, x) for x in rels) if r]
    stable = sorted((r for r in releases if not r["prerelease"]), key=lambda r: r["date"], reverse=True)
    if not stable:
        if out["status"] == "ok":
            out["status"] = "no_releases"
        out["warnings"].append(f"No published {host} releases; release cadence cannot be measured")
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
            # The list above is the newest 100 (Codeberg: 50) releases only. Projects with many patch and backport
            # releases (Grafana, for example) push older tags off it, so ask for each candidate directly.
            for c in candidates:
                st, rel = _release_by_tag(http, forge, path, c)
                got = _release(forge, rel) if st == 200 else None
                if got:
                    scanned = {**got, "tag": got["tag"] or c}
                    break
        if scanned is None:
            out["warnings"].append(
                f"No {host} release matches '{wanted}', so release-lag metrics are not computed (using the "
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
