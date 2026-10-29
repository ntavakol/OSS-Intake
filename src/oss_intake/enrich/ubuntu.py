"""Ubuntu fix dates from Ubuntu Security Notices (USN) in OSV.

Trivy reports no USN IDs for Ubuntu findings, so notices are found by querying OSV for each
source package in the image's Ubuntu release. A finding takes a notice's publication date only
when the notice lists the finding's CVE AND has an entry for the same release and source
package whose fixed version equals the finding's fixed version. Anything looser stays unknown.
"""

from __future__ import annotations

import re

from ..http import Http, HttpError, prefetch
from ..models import Finding, parse_datetime
from ..versions import compare

API = "https://api.osv.dev/v1"
BATCH = 1000
_REL = re.compile(r"^ubuntu (\d{2})\.(\d{2})")


def osv_ecosystem(os_release: str) -> str | None:
    """'ubuntu 24.04' -> 'Ubuntu:24.04:LTS'; 'ubuntu 24.10' -> 'Ubuntu:24.10'."""
    m = _REL.match(os_release.strip().lower())
    if not m:
        return None
    yy, mm = m.groups()
    lts = mm == "04" and int(yy) % 2 == 0
    return f"Ubuntu:{yy}.{mm}" + (":LTS" if lts else "")


def _query(http: Http, queries: list[dict]) -> list[list[str]]:
    """querybatch with per-query pagination. Returns vuln IDs per query, in order."""
    out: list[list[str]] = [[] for _ in queries]
    pending = [(i, q) for i, q in enumerate(queries)]
    while pending:
        chunk, pending = pending[:BATCH], pending[BATCH:]
        status, data = http.post_json(f"{API}/querybatch", {"queries": [q for _, q in chunk]})
        if status != 200 or not isinstance(data, dict):
            raise HttpError(f"OSV querybatch returned HTTP {status}")
        for (i, q), res in zip(chunk, data.get("results") or [], strict=False):
            res = res or {}
            out[i].extend(v["id"] for v in res.get("vulns") or [] if v.get("id"))
            if res.get("next_page_token"):
                pending.append((i, {**q, "page_token": res["next_page_token"]}))
    return out


def enrich(http: Http, findings: list[Finding]) -> dict:
    stats = {"candidates": 0, "packages_queried": 0, "notices_fetched": 0, "notices_total": 0, "found": 0,
             "errors": 0, "query_failed": False}
    todo = [f for f in findings if not f.fix_published and not f.likely_fixed and f.fixed_versions
            and f.src_name and osv_ecosystem(f.os_release)]
    if not todo:
        return stats
    stats["candidates"] = len(todo)
    keys = sorted({(osv_ecosystem(f.os_release), f.src_name, f.src_version) for f in todo})
    queries = []
    for eco, name, ver in keys:
        q: dict = {"package": {"ecosystem": eco, "name": name}}
        if "-" in ver:  # only a full version (with Ubuntu revision) narrows the query correctly
            q["version"] = ver
        queries.append(q)
    try:
        ids_per_key = _query(http, queries)
    except HttpError:
        stats["errors"] += 1
        stats["query_failed"] = True
        return stats
    stats["packages_queried"] = len(keys)

    notices: dict[str, dict] = {}
    prefetch(http, [f"{API}/vulns/{vid}" for ids in ids_per_key for vid in ids if vid.startswith("USN-")])
    for ids in ids_per_key:
        for vid in ids:
            if vid.startswith("USN-") and vid not in notices:
                stats["notices_total"] += 1
                try:
                    status, data = http.get_json(f"{API}/vulns/{vid}")
                except HttpError:
                    stats["errors"] += 1
                    notices[vid] = {}
                    continue
                notices[vid] = data if status == 200 and isinstance(data, dict) else {}
                stats["notices_fetched"] += 1

    # (ecosystem, source package, CVE) -> [(published, usn, fixed versions)]
    index: dict[tuple[str, str, str], list] = {}
    for usn, n in notices.items():
        published = parse_datetime(n.get("published"))
        refs = (n.get("upstream") or []) + (n.get("aliases") or [])
        cves = {c.upper() for c in refs if c.upper().startswith("CVE-")}
        if not published or not cves:
            continue
        for aff in n.get("affected") or []:
            pkg = aff.get("package") or {}
            fixed = [e["fixed"] for rg in aff.get("ranges") or [] for e in rg.get("events") or [] if e.get("fixed")]
            for cve in cves:
                key = (pkg.get("ecosystem", ""), pkg.get("name", ""), cve)
                index.setdefault(key, []).append((published, usn, fixed))

    for f in todo:
        cands = index.get((osv_ecosystem(f.os_release), f.src_name, f.vuln_id.upper()), [])
        exact = [(dt, usn) for dt, usn, fixed in cands
                 if any(compare(x, y) == 0 for x in fixed for y in f.fixed_versions)]
        if exact:
            dt, usn = min(exact)
            f.fix_published = dt
            f.fix_date_source = f"advisory {usn}"
            stats["found"] += 1
    return stats
