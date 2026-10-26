"""Grype adapter: an independent package detector and matcher used to cross-check Trivy."""

from __future__ import annotations

from ..cvss import better, version_of
from ..models import Finding, normalise_severity
from . import ScannerError, load_json_bytes, run

NAME = "grype"
_SOURCE_PREFIX = {"remote": "registry:", "docker": "docker:", "podman": "podman:", "containerd": "containerd:"}


def version_info(binary: str) -> dict:
    data = load_json_bytes(run([binary, "version", "-o", "json"], timeout=60), "grype version output")
    version = data.get("version")
    if not version:
        raise ScannerError("could not determine grype version")
    return {"version": str(version), "syft_version": data.get("syftVersion")}


def source_for(image: str, image_src: str | None) -> str:
    return _SOURCE_PREFIX.get(image_src or "", "") + image


def scan_path(binary: str, target: str, extra: list[str], timeout: int) -> bytes:
    """Scan a directory with Grype's dir: source."""
    return run([binary, f"dir:{target}", "-o", "json", *extra], timeout)


def scan(binary: str, image: str, image_src: str | None, extra: list[str], timeout: int,
         platform: str | None = None) -> bytes:
    # No -q: it also suppresses error messages. stderr is captured, so progress output is harmless.
    cmd = [binary, source_for(image, image_src), "-o", "json"]
    if platform:
        cmd += ["--platform", platform]
    cmd += list(extra)
    return run(cmd, timeout)


_HOSTS = {"github.com": "ghsa", "nvd.nist.gov": "nvd", "security-tracker.debian.org": "debian",
          "ubuntu.com": "ubuntu", "access.redhat.com": "redhat", "alpinelinux.org": "alpine", "osv.dev": "osv"}


def _source(v: dict) -> str:
    """Database a Grype record came from: namespace 'github:language:java' -> ghsa, 'nvd:cpe' -> nvd,
    'debian:distro:debian:12' -> debian; failing that, the dataSource host."""
    ns = str(v.get("namespace") or "")
    if ns:
        head = ns.split(":", 1)[0].lower()
        return "ghsa" if head == "github" else head
    url = str(v.get("dataSource") or "")
    for host, name in _HOSTS.items():
        if host in url:
            return name
    return ""


def _best_cvss(entries: list[dict], source: str) -> tuple[float, str, str] | None:
    best = None
    for c in entries or []:
        score = (c.get("metrics") or {}).get("baseScore")
        if score is None:
            continue
        cand = (float(score), version_of(c.get("vector"), str(c.get("version", ""))), source)
        if cand[1][:1] in ("3", "4") and better(cand, best):
            best = cand
    return best


def parse(report: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    distro = report.get("distro") or {}
    os_release = f"{distro.get('name', '')} {distro.get('version', '')}".strip().lower() if distro.get("name") else ""
    for m in report.get("matches") or []:
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        related = m.get("relatedVulnerabilities") or []
        fix = vuln.get("fix") or {}
        fixed = list(fix.get("versions") or []) if fix.get("state") == "fixed" else []
        cvss = _best_cvss(vuln.get("cvss") or [], _source(vuln))
        for r in related:
            rel = _best_cvss(r.get("cvss") or [], _source(r))
            if better(rel, cvss) and (cvss is None or not cvss[1].startswith("3")):
                cvss = rel  # related records (usually NVD) only fill a missing v3 score
        locations = art.get("locations") or []
        name = art.get("name", "")
        purl = art.get("purl") or ""
        version = art.get("version", "")
        if name == "stdlib" and purl.startswith("pkg:golang/") and version.startswith("go"):
            version = "v" + version[2:]  # Grype writes go1.22.7, Trivy v1.22.7; same binary must merge
        if purl.startswith("pkg:maven/"):
            # Report Maven packages as group:artifact, matching Trivy and OSV.
            path = purl[len("pkg:maven/"):].split("@", 1)[0].split("?", 1)[0]
            if "/" in path:
                name = path.replace("/", ":", 1) if path.count("/") == 1 else name
        f = Finding(
            vuln_id=vuln.get("id", ""),
            package=name,
            installed=version,
            severity=normalise_severity(vuln.get("severity")),
            fixed_versions=fixed,
            cvss=cvss[0] if cvss else None,
            cvss_version=cvss[1] if cvss else "",
            cvss_source=cvss[2] if cvss else "",
            purl=art.get("purl"),
            pkg_type=art.get("type", ""),
            target=(locations[0].get("path", "") if locations else ""),
            aliases={r.get("id") for r in related if r.get("id")},
            # Recent Grype databases list distro advisories (RHSA, DSA, USN...) for a match; keeping them
            # lets Grype-only OS findings be dated like Trivy's.
            vendor_ids=[a["id"] for a in vuln.get("advisories") or [] if isinstance(a, dict) and a.get("id")],
            url=vuln.get("dataSource", "") or "",
            title=(vuln.get("description") or "")[:200],
            description=vuln.get("description") or "",
            sources={NAME},
        )
        if f.pkg_type in ("apk", "deb", "rpm"):
            f.os_release = os_release
            upstreams = [u.get("name") for u in art.get("upstreams") or [] if isinstance(u, dict) and u.get("name")]
            f.src_name = upstreams[0] if upstreams else ""
        f.source_severity[NAME] = f.severity
        findings.append(f)
    desc = report.get("descriptor") or {}
    info = {"descriptor_version": desc.get("version"), "db": (desc.get("db") or {}).get("status") or desc.get("db")}
    return findings, info
