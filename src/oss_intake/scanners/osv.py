"""OSV.dev adapter. Queries the OSV API for a package list; it does not detect packages itself.

The package list (purls) comes from the Trivy report (Trivy lists all packages by default),
so OSV acts as an independent vulnerability DATABASE check, not an independent DETECTOR.
"""

from __future__ import annotations

from ..cvss import base_score, severity_from_score, version_of
from ..http import Http, HttpError
from ..models import Finding, normalise_purl, normalise_severity, parse_datetime, purl_without_version
from ..versions import split_fixed

NAME = "osv"
API = "https://api.osv.dev/v1"
BATCH = 1000
# Language ecosystems where purl queries are well supported. OS packages are left to Trivy/Grype,
# which understand distro backports.
SUPPORTED_TYPES = {"maven", "npm", "pypi", "golang", "cargo", "nuget", "gem", "composer", "hex", "pub", "cran"}


def purls_from_trivy(report: dict) -> list[str]:
    seen: dict[str, None] = {}
    for result in report.get("Results") or []:
        for p in result.get("Packages") or []:
            purl = normalise_purl((p.get("Identifier") or {}).get("PURL"))
            if purl and "@" in purl and purl[4:].split("/", 1)[0] in SUPPORTED_TYPES:
                seen[purl] = None
    return list(seen)


def purls_from_cyclonedx(sbom: dict) -> list[str]:
    seen: dict[str, None] = {}
    stack = list(sbom.get("components") or [])
    while stack:
        c = stack.pop()
        stack.extend(c.get("components") or [])
        purl = normalise_purl(c.get("purl"))
        if purl and "@" in purl and purl[4:].split("/", 1)[0] in SUPPORTED_TYPES:
            seen[purl] = None
    return list(seen)


def _query_batch(http: Http, purls: list[str]) -> dict[str, list[str]]:
    """Return {purl: [vuln ids]}, following per-query pagination tokens."""
    out: dict[str, list[str]] = {p: [] for p in purls}
    pending = [(p, None) for p in purls]
    while pending:
        chunk, pending = pending[:BATCH], pending[BATCH:]
        queries = []
        for purl, token in chunk:
            q: dict = {"package": {"purl": purl}}
            if token:
                q["page_token"] = token
            queries.append(q)
        status, data = http.post_json(f"{API}/querybatch", {"queries": queries})
        if status != 200 or not isinstance(data, dict):
            raise HttpError(f"OSV querybatch returned HTTP {status}")
        for (purl, _), res in zip(chunk, data.get("results") or [], strict=False):
            out[purl].extend(v["id"] for v in (res or {}).get("vulns") or [] if v.get("id"))
            if (res or {}).get("next_page_token"):
                pending.append((purl, res["next_page_token"]))
    return out


def _fixed_for(vuln: dict, purl: str) -> list[str]:
    target = purl_without_version(purl)
    ptype = purl[4:].split("/", 1)[0]
    pname = target.split("/", 1)[1] if target else ""
    fixed: list[str] = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        match = purl_without_version(pkg.get("purl")) == target if pkg.get("purl") else False
        if not match and ptype == "maven":
            match = pkg.get("ecosystem") == "Maven" and pkg.get("name", "").replace(":", "/") == pname
        if not match:
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    fixed.append(ev["fixed"])
    return split_fixed(fixed)


def _severity(vuln: dict) -> tuple[str, float | None, str]:
    """Severity, v3 base score and its version. OSV gives vectors only; v4 scores need the full CVSS v4
    lookup tables to compute, so OSV contributes v3 scores only."""
    score, version = None, ""
    for s in vuln.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            score = base_score(s.get("score", ""))
            if score is not None:
                version = version_of(s.get("score", ""), "3")
                break
    sev = normalise_severity((vuln.get("database_specific") or {}).get("severity"))
    if sev == "UNKNOWN":
        sev = severity_from_score(score)
    return sev, score, version


def scan(http: Http, purls: list[str]) -> list[Finding]:
    hits = _query_batch(http, purls)
    cache: dict[str, dict] = {}
    findings: list[Finding] = []
    for purl, ids in hits.items():
        name_ver = purl[4:].split("/", 1)[1]
        name, _, version = name_ver.rpartition("@")
        for vid in ids:
            if vid not in cache:
                status, data = http.get_json(f"{API}/vulns/{vid}")
                cache[vid] = data if status == 200 and isinstance(data, dict) else {"id": vid}
            v = cache[vid]
            sev, score, cvss_ver = _severity(v)
            f = Finding(
                vuln_id=vid,
                package=name.replace("/", ":") if purl.startswith("pkg:maven/") else name,
                installed=version,
                severity=sev,
                fixed_versions=_fixed_for(v, purl),
                cvss=score,
                cvss_version=cvss_ver if score is not None else "",
                cvss_source=("ghsa" if vid.startswith("GHSA-") else "osv") if score is not None else "",
                published=parse_datetime(v.get("published")),
                purl=purl,
                pkg_type=purl[4:].split("/", 1)[0],
                aliases=set(v.get("aliases") or []),
                title=(v.get("summary") or "")[:200],
                url=f"https://osv.dev/vulnerability/{vid}",
                sources={NAME},
            )
            f.source_severity[NAME] = sev
            findings.append(f)
    return findings
