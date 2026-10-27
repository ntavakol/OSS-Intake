"""Alpine fix dates from the aports commit history (GitHub mirror alpinelinux/aports).

Alpine's security database lists which package version fixed each CVE but not when. A fix ships
as a commit to the package's APKBUILD on the release branch (e.g. 3.22-stable); the commit date
is when the fix landed for that release. Matching rules, from real data:
  * a commit whose message names the CVE always counts;
  * for a new upstream version (fixed version ending -r0), a commit naming that version counts
    ("main/openssl: security upgrade to 3.5.6");
  * for a rebuild of the same version (-r1 and up), only the CVE or the exact version-rN counts,
    because "upgrade to 8.14.1" describes the original version, not the patched rebuild.
The earliest matching commit on the branch is used. Anything else stays unknown.
"""

from __future__ import annotations

import re

from ..http import Http, HttpError
from ..models import Finding, parse_datetime
from ..versions import nearest_fix

API = "https://api.github.com/repos/alpinelinux/aports/commits"
MAX_PACKAGES = 100  # each source package is one request; stays well inside a token's 5,000 per hour
_REL = re.compile(r"^alpine (\d+)\.(\d+)")


def branch_for(os_release: str) -> str | None:
    m = _REL.match((os_release or "").strip().lower())
    return f"{m.group(1)}.{m.group(2)}-stable" if m else None


def _is_alpine(f: Finding) -> bool:
    return (f.purl or "").startswith("pkg:apk/alpine/") or (f.os_release or "").startswith("alpine")


def _matches(message: str, cve_ids: set[str], ver: str, rel: str) -> bool:
    if any(re.search(rf"(?<![\w-]){re.escape(c)}(?!\d)", message) for c in cve_ids):
        return True
    if re.search(rf"(?<![\w.]){re.escape(ver)}-r{re.escape(rel)}(?![\w.])", message):
        return True
    return rel == "0" and re.search(rf"(?<![\w.]){re.escape(ver)}(?![\w.-])", message) is not None


def enrich(http: Http, findings: list[Finding]) -> dict:
    stats = {"candidates": 0, "packages": 0, "found": 0, "skipped_limit": 0, "errors": 0}
    cache: dict[tuple[str, str], list[tuple[str, str, str]]] = {}
    for f in findings:
        if f.fix_published or f.likely_fixed or f.excluded or not f.fixed_versions or not _is_alpine(f):
            continue
        branch = branch_for(f.os_release)
        fix = nearest_fix(f.vs_fix, f.fixed_versions)
        if not branch or not fix:
            continue
        stats["candidates"] += 1
        src = f.src_name or f.package
        key = (branch, src)
        if key not in cache:
            if stats["packages"] >= MAX_PACKAGES:
                stats["skipped_limit"] += 1
                continue
            stats["packages"] += 1
            cache[key] = []
            for repo in ("main", "community"):
                try:
                    status, data = http.get_json(API, params={"path": f"{repo}/{src}/APKBUILD", "sha": branch,
                                                              "per_page": 100})
                except HttpError:
                    stats["errors"] += 1
                    break
                if status == 200 and isinstance(data, list) and data:
                    cache[key] = [((c.get("commit") or {}).get("committer", {}).get("date", ""),
                                   (c.get("commit") or {}).get("message", ""), c.get("sha", "")[:10]) for c in data]
                    break
                if status not in (200, 404, 422):
                    stats["errors"] += 1
                    break
        ver, _, rel = fix.partition("-r")
        cve_ids = {i for i in {f.vuln_id, *f.aliases} if i.upper().startswith("CVE-")}
        hits = [(parse_datetime(d), sha) for d, msg, sha in cache[key]
                if parse_datetime(d) and _matches(msg, cve_ids, ver, rel or "0")]
        if hits:
            dt, sha = min(hits)
            f.fix_published = dt
            f.fix_version_used = fix
            f.fix_date_source = f"aports commit {sha}"
            stats["found"] += 1
    return stats
