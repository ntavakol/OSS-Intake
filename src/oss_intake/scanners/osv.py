"""OSV.dev adapter. Queries the OSV API for a package list; it does not detect packages itself.

The package list (purls) comes from the Trivy report (Trivy lists all packages by default),
so OSV acts as an independent vulnerability DATABASE check, not an independent DETECTOR.
"""

from __future__ import annotations

import re
from urllib.parse import unquote

from ..cvss import base_score, severity_from_score, version_of
from ..http import Http, HttpError, prefetch
from ..models import Finding, normalise_purl, normalise_severity, parse_datetime, purl_without_version
from ..os_packages import identity, is_os_purl
from ..versions import split_fixed

NAME = "osv"
API = "https://api.osv.dev/v1"
BATCH = 1000
# Pages of results followed for one query. OSV pages large answers (and busy batches); a query with more than
# this many pages, or a page token that repeats, is an error rather than a partial (and so falsely clean) answer.
# High enough for the largest distro source packages (Linux kernel queries without a version): a loop is stopped
# by the repeated-token check, so this bounds only a server that keeps making new tokens.
MAX_PAGES = 200
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


def querybatch(http: Http, queries: list[dict], labels: list[str] | None = None) -> list[list[str]]:
    """POST queries to OSV's querybatch, following per-query page tokens. Returns the vulnerability IDs for each
    query, in order. labels name the queries in errors (default: their position).

    OSV answers with one result object per query, in order. An answer with a different number of results, a
    result that is not an object, a page token that repeats for a query or more than MAX_PAGES pages for one
    raise HttpError: a query left without its full result must never read as having no vulnerabilities."""
    names = labels or [f"query {n + 1}" for n in range(len(queries))]
    out: list[list[str]] = [[] for _ in queries]
    pages = [1] * len(queries)
    seen: list[set[str]] = [set() for _ in queries]
    pending: list[tuple[int, dict]] = list(enumerate(queries))
    while pending:
        chunk, pending = pending[:BATCH], pending[BATCH:]
        status, data = http.post_json(f"{API}/querybatch", {"queries": [q for _, q in chunk]})
        if status != 200 or not isinstance(data, dict):
            raise HttpError(f"OSV querybatch returned HTTP {status}")
        results = data.get("results")
        if not isinstance(results, list) or len(results) != len(chunk):
            got = len(results) if isinstance(results, list) else "no"
            raise HttpError(f"OSV querybatch answered {got} result(s) for {len(chunk)} queries; those without a "
                            "result were not checked")
        for (i, q), res in zip(chunk, results, strict=True):
            vulns, token = (res.get("vulns"), res.get("next_page_token")) if isinstance(res, dict) else (None, None)
            if not isinstance(res, dict) or not (vulns is None or isinstance(vulns, list) and all(
                    isinstance(v, dict) and isinstance(v.get("id"), str) and v["id"] for v in vulns)) \
                    or not (token is None or isinstance(token, str)):
                # An entry read as "no vulnerabilities" because of its shape would pass a gate: refused instead.
                raise HttpError(f"OSV querybatch answered for {names[i]} in a shape that is not in OSV's form (a list "
                                "of vulnerabilities, each with an id); it was not checked")
            out[i].extend(v["id"] for v in vulns or [])
            if token:
                if token in seen[i]:
                    raise HttpError(f"OSV querybatch repeated a page token for {names[i]}; its results are "
                                    "incomplete")
                pages[i] += 1
                if pages[i] > MAX_PAGES:
                    raise HttpError(f"OSV querybatch had more than {MAX_PAGES} pages for {names[i]}; its results "
                                    "are incomplete")
                seen[i].add(token)
                pending.append((i, {**q, "page_token": token}))
    return out


def _query_batch(http: Http, purls: list[str], os_queries: dict[str, dict] | None = None) -> dict[str, list[str]]:
    """Return {purl: [vuln ids]} (see querybatch). A purl in os_queries is asked by distro ecosystem, source
    package name and version instead of by purl (see os_packages). Each purl is asked once."""
    unique = list(dict.fromkeys(purls))
    queries = []
    for purl in unique:
        osq = (os_queries or {}).get(purl)
        queries.append({"package": {"name": osq["name"], "ecosystem": osq["ecosystem"]}, "version": osq["version"]}
                       if osq else {"package": {"purl": purl}})
    return dict(zip(unique, querybatch(http, queries, unique), strict=True))


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
    prefetch(http, [f"{API}/vulns/{vid}" for ids in hits.values() for vid in ids])
    for purl, ids in hits.items():
        name_ver = purl.split("?", 1)[0][4:].split("/", 1)[1]
        name, _, version = name_ver.rpartition("@")
        name, version = unquote(name), unquote(version)  # pkg:npm/%40ctrl/tinycolor -> @ctrl/tinycolor
        for vid in ids:
            if vid not in cache:
                try:
                    status, data = http.get_json(f"{API}/vulns/{vid}")
                except HttpError:  # one advisory's details: mark it, as for a bad status, not the whole lookup
                    status, data = 0, None
                # Without its details an advisory has no severity, fix or CVE alias: keep it, marked, so the run
                # says so rather than reading as complete.
                ok = status == 200 and isinstance(data, dict) and _advisory_ok(data)
                cache[vid] = data if ok else {"id": vid, "_unavailable": True}
        osq = queries.get(purl)
        note = ""
        if osq:
            name = name.rsplit("/", 1)[-1]  # pkg:deb/ubuntu/libssl3t64 -> libssl3t64, as the distro names it
            ids = _per_cve_only(ids, cache)
            src_v = osq["version"]
            if re.sub(r"^\d+:", "", src_v) != re.sub(r"^\d+:", "", version) or osq["name"] != name:
                note = f"{name} {version} is built from {osq['name']} {src_v}; fix versions are the source's"
        for vid in ids:
            try:
                f = _finding(vid, cache[vid], name, version, purl, osq)
            except (AttributeError, TypeError, KeyError, IndexError, ValueError):
                # Fields of a shape _advisory_ok did not foresee: kept, marked as without details, never dropped.
                f = _finding(vid, {"id": vid, "_unavailable": True}, name, version, purl, osq)
            if osq:
                f.note = "; ".join(x for x in (f.note, note) if x)
            findings.append(f)
    return findings


def _advisory_ok(v: dict) -> bool:
    """The OSV advisory fields read here have the types OSV documents. A forged or garbled answer (from the service
    or a cache entry) is treated as details that could not be loaded, which keeps the finding and marks it."""
    def strs(x) -> bool:
        return x is None or (isinstance(x, list) and all(isinstance(e, str) for e in x))

    def dicts(x) -> bool:
        return x is None or (isinstance(x, list) and all(isinstance(e, dict) for e in x))

    if not all(v.get(k) is None or isinstance(v[k], str) for k in ("id", "summary", "details", "published",
                                                                    "modified", "withdrawn")):
        return False
    if not (strs(v.get("aliases")) and strs(v.get("upstream")) and dicts(v.get("severity"))
            and dicts(v.get("affected")) and isinstance(v.get("database_specific") or {}, dict)):
        return False
    for a in v.get("affected") or []:
        if not (isinstance(a.get("package") or {}, dict) and dicts(a.get("ranges")) and strs(a.get("versions"))
                and isinstance(a.get("ecosystem_specific") or {}, dict)
                and isinstance(a.get("database_specific") or {}, dict)):
            return False
        for r in a.get("ranges") or []:
            if not dicts(r.get("events")) or not all(isinstance(x, str) for e in r.get("events") or []
                                                     for x in e.values()):
                return False
    return strs((v.get("database_specific") or {}).get("cwe_ids"))


def _finding(vid: str, v: dict, name: str, version: str, purl: str, osq: dict | None) -> Finding:
    """One finding from an OSV advisory (v as cached: the advisory, or {"id", "_unavailable"})."""
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
    if v.get("_unavailable"):
        f.details_unavailable = True
        f.title = "advisory details could not be loaded from OSV"
        f.note = "advisory details could not be loaded from OSV: severity, fix and CVE aliases are unknown"
    if osq:
        f.os_release, f.src_name, f.src_version = osq["os_release"], osq["name"], osq["version"]
        f.source_installed = osq["version"]
    return f
