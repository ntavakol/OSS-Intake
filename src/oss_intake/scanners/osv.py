"""OSV.dev adapter. Queries the OSV API for a package list; it does not detect packages itself.

The package list (purls) comes from the Trivy report (Trivy lists all packages by default),
so OSV acts as an independent vulnerability DATABASE check, not an independent DETECTOR.
"""

from __future__ import annotations

from urllib.parse import unquote

from ..cvss import base_score, severity_from_score, version_of
from ..http import Http, HttpError
from ..models import Finding, normalise_purl, normalise_severity, parse_datetime, purl_without_version
from ..os_packages import identity, is_os_purl
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


def _query_batch(http: Http, purls: list[str], os_queries: dict[str, dict] | None = None) -> dict[str, list[str]]:
    """Return {purl: [vuln ids]}, following per-query pagination tokens. A purl in os_queries is asked by distro
    ecosystem, source package name and version instead of by purl (see os_packages)."""
    out: dict[str, list[str]] = {p: [] for p in purls}
    pending = [(p, None) for p in purls]
    while pending:
        chunk, pending = pending[:BATCH], pending[BATCH:]
        queries = []
        for purl, token in chunk:
            osq = (os_queries or {}).get(purl)
            q: dict = ({"package": {"name": osq["name"], "ecosystem": osq["ecosystem"]}, "version": osq["version"]}
                       if osq else {"package": {"purl": purl}})
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


def _fixed_for_os(vuln: dict, osq: dict) -> list[str]:
    """Fix versions for a distro package: the affected entry for its ecosystem and source package."""
    fixed: list[str] = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != osq["ecosystem"] or pkg.get("name") != osq["name"]:
            continue
        for rng in aff.get("ranges") or []:
            if rng.get("type") == "GIT":
                continue
            fixed += [ev["fixed"] for ev in rng.get("events") or [] if ev.get("fixed")]
    return split_fixed(fixed)


# Distro notices group several CVEs (USN-7000-1, DSA-5700-1); the same CVEs also come as one record each
# (UBUNTU-CVE-2024-1234, DEBIAN-CVE-2024-1234). When both kinds are returned, the notices are dropped so a CVE
# is counted once.
_NOTICE = ("USN-", "DSA-", "DLA-", "DTSA-")
_PER_CVE = ("UBUNTU-CVE-", "DEBIAN-CVE-")


def _per_cve_only(ids: list[str], records: dict[str, dict] | None = None) -> list[str]:
    """Drop a notice only when every CVE it names is also returned as its own record, so nothing is lost."""
    covered = set()
    for i in ids:
        if i.startswith(_PER_CVE):
            covered |= _upstream_cve((records or {}).get(i) or {}) or {i.split("-", 1)[1]}
    out = []
    for i in ids:
        if i.startswith(_NOTICE) and covered:
            named = {u for u in ((records or {}).get(i) or {}).get("upstream") or [] if str(u).startswith("CVE-")}
            if named and named <= covered:
                continue
        out.append(i)
    return out


def _upstream_cve(vuln: dict) -> set[str]:
    """A per-CVE distro record names its CVE in 'upstream', not 'aliases'; it is added as an alias so KEV, EPSS
    and exploit lookups find it. A notice listing several CVEs is left alone: it is not any one of them."""
    up = [u for u in vuln.get("upstream") or [] if str(u).upper().startswith("CVE-")]
    return set(up) if len(up) == 1 else set()


def os_query_index(os_queries: dict[str, dict] | None) -> dict[str, dict]:
    """The same queries keyed by purl without version, to ask about another version of a package (the upgrade
    comparison asks about the minimum fix)."""
    out: dict[str, dict] = {}
    for purl, q in (os_queries or {}).items():
        out.setdefault(identity(purl), q)
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
            if rng.get("type") == "GIT":
                continue  # GIT ranges give commit hashes, not versions anyone can upgrade to
            for ev in rng.get("events") or []:
                if ev.get("fixed"):
                    fix = ev["fixed"]
                    if ptype == "golang" and fix[:1].isdigit():
                        fix = f"v{fix}"  # Go versions carry a v (v0.60.0); OSV's Go ranges omit it
                    fixed.append(fix)
    return split_fixed(fixed)


def _severity(vuln: dict) -> tuple[str, float | None, str]:
    """Severity, v3 base score and its version. OSV gives vectors only; v4 scores need the full CVSS v4
    lookup tables to compute, so OSV contributes v3 scores only."""
    score, version = None, ""
    distro_rating = ""
    for s in vuln.get("severity") or []:
        if str(s.get("type", "")).lower() in ("ubuntu", "debian"):  # a distro's own rating, as text
            distro_rating = str(s.get("score", ""))
    for s in vuln.get("severity") or []:
        if str(s.get("type", "")).startswith("CVSS_V3"):
            score = base_score(s.get("score", ""))
            if score is not None:
                version = version_of(s.get("score", ""), "3")
                break
    sev = normalise_severity((vuln.get("database_specific") or {}).get("severity") or distro_rating)
    if sev == "UNKNOWN":
        sev = severity_from_score(score)
    return sev, score, version


def scan(http: Http, purls: list[str], os_queries: dict[str, dict] | None = None) -> list[Finding]:
    """Findings for each purl. OS package purls are asked only when os_queries says how (distro ecosystem,
    source name); one without is skipped, since a purl query for it would silently find nothing."""
    by_base = os_query_index(os_queries)
    queries: dict[str, dict] = {}
    asked: list[str] = []
    for purl in purls:
        if is_os_purl(purl):
            q = (os_queries or {}).get(purl)
            if q is None and identity(purl) in by_base:  # another version of it, e.g. the minimum fix
                q = {**by_base[identity(purl)], "version": unquote(purl.split("?", 1)[0].rpartition("@")[2])}
            if q is None:
                continue
            queries[purl] = q
        asked.append(purl)
    hits = _query_batch(http, asked, queries)
    cache: dict[str, dict] = {}
    findings: list[Finding] = []
    for purl, ids in hits.items():
        name_ver = purl.split("?", 1)[0][4:].split("/", 1)[1]
        name, _, version = name_ver.rpartition("@")
        name, version = unquote(name), unquote(version)  # pkg:npm/%40ctrl/tinycolor -> @ctrl/tinycolor
        for vid in ids:
            if vid not in cache:
                status, data = http.get_json(f"{API}/vulns/{vid}")
                cache[vid] = data if status == 200 and isinstance(data, dict) else {"id": vid}
        osq = queries.get(purl)
        note = ""
        if osq:
            name = name.rsplit("/", 1)[-1]  # pkg:deb/ubuntu/libssl3t64 -> libssl3t64, as the distro names it
            ids = _per_cve_only(ids, cache)
            if osq["version"] != version:
                # Distro fixes are versions of the source package; compare like with like.
                note = f"{name} {version} is built from {osq['name']} {osq['version']}; versions are the source's"
                version = osq["version"]
        for vid in ids:
            v = cache[vid]
            sev, score, cvss_ver = _severity(v)
            f = Finding(
                vuln_id=vid,
                package=name.replace("/", ":") if purl.startswith("pkg:maven/") else name,
                installed=version,
                severity=sev,
                fixed_versions=_fixed_for_os(v, osq) if osq else _fixed_for(v, purl),
                cvss=score,
                cvss_version=cvss_ver if score is not None else "",
                cvss_source=("ghsa" if vid.startswith("GHSA-") else "osv") if score is not None else "",
                published=parse_datetime(v.get("published")),
                purl=purl,
                pkg_type=purl[4:].split("/", 1)[0],
                aliases=set(v.get("aliases") or []) | _upstream_cve(v),
                cwes={str(c).upper() for c in (v.get("database_specific") or {}).get("cwe_ids") or []},
                title=(v.get("summary") or "")[:200],
                description=v.get("details") or "",
                url=f"https://osv.dev/vulnerability/{vid}",
                sources={NAME},
            )
            f.source_severity[NAME] = sev
            if osq:
                f.os_release, f.src_name, f.src_version = osq["os_release"], osq["name"], osq["version"]
                f.note = note
            findings.append(f)
    return findings
