"""Fix-date coverage per ecosystem, so a reader can see how far to trust the lag numbers."""

from __future__ import annotations

from collections import defaultdict

from .models import Finding

# Why each ecosystem lacks a date source, shown when coverage is low.
GAP_REASON = {
    "ubuntu": "no Ubuntu Security Notice matched the CVE, package and fixed version",
    "alpine": "no aports commit named the CVE or the fixed version (common for -rN rebuilds)",
    "redhat": "fixes without a Red Hat advisory ID, or the advisory could not be fetched",
    "amazon": "Trivy reports no ALAS advisory IDs for Amazon Linux; no dated source yet",
    "go-stdlib": "Go standard library is not on deps.dev",
    "binary": "runtime detected from a binary, no package registry to date it",
    "debian": "fixes shipped in point releases have no advisory",
}
_DISTRO = {"debian": "debian", "ubuntu": "ubuntu", "alpine": "alpine", "redhat": "redhat", "rhel": "redhat",
           "centos": "redhat", "rocky": "redhat", "almalinux": "redhat", "amazon": "amazon", "fedora": "fedora"}


def ecosystem(f: Finding) -> str:
    if f.package == "stdlib" and (f.purl or "").startswith("pkg:golang/"):
        return "go-stdlib"
    purl = f.purl or ""
    if purl.startswith("pkg:") and "/" in purl[4:]:
        ptype, rest = purl[4:].split("/", 1)
        ptype = ptype.lower()
        if ptype in ("deb", "rpm", "apk"):
            ns = rest.split("/", 1)[0].lower()
            return _DISTRO.get(ns, ns or ptype)
        return {"golang": "go", "gem": "rubygems", "generic": "binary"}.get(ptype, ptype)
    t = (f.pkg_type or "").lower()
    if t in ("jar", "pom", "gradle", "java-archive"):
        return "maven"
    if t in ("gobinary", "gomod", "go-module"):
        return "go"
    if t in ("binary", ""):
        return "binary"
    return _DISTRO.get(t, t)


def compute(findings: list[Finding]) -> list[dict]:
    rows: dict[str, dict] = defaultdict(lambda: {"with_fix": 0, "dated": 0, "sources": defaultdict(int)})
    for f in findings:
        if not f.fixed_versions or f.likely_fixed or f.excluded:
            continue
        r = rows[ecosystem(f)]
        r["with_fix"] += 1
        if f.fix_published:
            r["dated"] += 1
            r["sources"][(f.fix_date_source or "unknown").split(" ")[0]] += 1
    out = []
    for eco, r in sorted(rows.items(), key=lambda kv: -kv[1]["with_fix"]):
        pct = round(100 * r["dated"] / r["with_fix"]) if r["with_fix"] else 0
        out.append({
            "ecosystem": eco, "with_fix": r["with_fix"], "dated": r["dated"], "percent": pct,
            "sources": dict(r["sources"]),
            "gap": GAP_REASON.get(eco, "") if pct < 50 else "",
        })
    return out
