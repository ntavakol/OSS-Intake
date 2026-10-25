"""Merge findings from several sources into one row per (vulnerability, package, version)."""

from __future__ import annotations

from .cvss import better
from .models import SEVERITY_ORDER, Finding, canonical_id

SOURCE_PRIORITY = ["trivy", "grype", "osv"]


def _norm(path: str) -> str:
    return path.lstrip("/")


def _inside(outer: str, inner: str) -> bool:
    """True when inner is a path within outer, e.g. the JAR nested in shinyproxy.jar that Trivy reports
    (opt/app.jar/BOOT-INF/lib/x.jar) versus the outer archive Grype reports (/opt/app.jar)."""
    o, i = _norm(outer), _norm(inner)
    return i.startswith(o) and len(i) > len(o) and i[len(o)] in "/:!"


def _add_target(cur: Finding, target: str) -> None:
    """Keep every location a finding was seen in (one CVE in several binaries), ';'-separated.
    Paths are compared without a leading slash (Trivy omits it, Grype keeps it), and an outer archive is
    dropped in favour of the more specific path inside it."""
    if not target:
        return
    have = [t for t in cur.target.split(";") if t] if cur.target else []
    if any(_norm(t) == _norm(target) or _inside(target, t) for t in have):
        return  # already listed, or a more specific path inside it is
    have = [t for t in have if not _inside(t, target)]
    cur.target = ";".join(have + [target])


def merge(*groups: list[Finding]) -> list[Finding]:
    merged: dict[tuple[str, str, str], Finding] = {}
    for group in groups:
        for f in group:
            key = f.merge_key()
            cur = merged.get(key)
            if cur is None:
                f.aliases = set(f.aliases)
                cid = canonical_id(f.vuln_id, f.aliases)
                if cid != f.vuln_id:
                    f.aliases.add(f.vuln_id)
                    f.vuln_id = cid
                merged[key] = f
                continue
            cur.sources |= f.sources
            cur.source_severity.update(f.source_severity)
            cur.aliases |= f.aliases | ({f.vuln_id} if f.vuln_id != cur.vuln_id else set())
            for v in f.fixed_versions:
                if v not in cur.fixed_versions:
                    cur.fixed_versions.append(v)
            # Conservative: keep the highest severity any source reported.
            if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[cur.severity]:
                cur.severity = f.severity
            if better((f.cvss, f.cvss_version, f.cvss_source), (cur.cvss, cur.cvss_version, cur.cvss_source)):
                cur.cvss, cur.cvss_version, cur.cvss_source = f.cvss, f.cvss_version, f.cvss_source
            if cur.published is None or (f.published and f.published < cur.published):
                cur.published = f.published or cur.published
            for vid in f.vendor_ids:
                if vid not in cur.vendor_ids:
                    cur.vendor_ids.append(vid)
            cur.src_name = cur.src_name or f.src_name
            cur.src_version = cur.src_version or f.src_version
            cur.os_release = cur.os_release or f.os_release
            cur.purl = cur.purl or f.purl
            _add_target(cur, f.target)
            cur.title = cur.title or f.title
            if len(f.description) > len(cur.description):
                cur.description = f.description
            cur.url = cur.url or f.url
    out = list(merged.values())
    out.sort(key=lambda x: (-SEVERITY_ORDER[x.severity], -(x.cvss or 0), x.package, x.vuln_id))
    return out


def source_agreement(findings: list[Finding], enabled: list[str]) -> dict:
    """How many findings each source saw, and how many only one source saw.

    Disagreement is expected (different databases, different package detection) and is
    reported so a reviewer can look at single-source findings rather than trust either tool blindly.
    """
    stats = {"enabled": enabled, "by_source": {}, "only": {}, "all_enabled": 0}
    for s in enabled:
        stats["by_source"][s] = sum(1 for f in findings if s in f.sources)
        stats["only"][s] = sum(1 for f in findings if f.sources == {s})
    stats["all_enabled"] = sum(1 for f in findings if set(enabled) <= f.sources)
    return stats
