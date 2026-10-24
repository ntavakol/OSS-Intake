"""Trivy adapter: version, vulnerability scan (JSON) and CycloneDX SBOM."""

from __future__ import annotations

from ..cvss import better, version_of
from ..models import Finding, normalise_severity, parse_datetime
from ..versions import split_fixed
from . import ScannerError, load_json_bytes, run

NAME = "trivy"
_CVSS_PREF = ["nvd", "ghsa", "redhat"]


def version_info(binary: str) -> dict:
    data = load_json_bytes(run([binary, "--version", "--format", "json"], timeout=60), "trivy --version")
    version = data.get("Version")
    if not version:
        raise ScannerError("could not determine trivy version")
    db = data.get("VulnerabilityDB") or {}
    return {"version": str(version), "db_updated": db.get("UpdatedAt"), "db_next_update": db.get("NextUpdate")}


def _base_cmd(binary: str, image_src: str | None, extra: list[str], platform: str | None = None) -> list[str]:
    cmd = [binary, "image", "--quiet", "--timeout", "20m"]
    if image_src:
        cmd += ["--image-src", image_src]
    if platform:
        cmd += ["--platform", platform]
    return cmd + list(extra)


def scan(binary: str, image: str, image_src: str | None, extra: list[str], timeout: int,
         platform: str | None = None) -> bytes:
    cmd = _base_cmd(binary, image_src, extra, platform) + ["--format", "json", "--scanners", "vuln", image]
    return run(cmd, timeout)


def sbom(binary: str, image: str, image_src: str | None, extra: list[str], timeout: int,
         platform: str | None = None) -> bytes:
    cmd = _base_cmd(binary, image_src, extra, platform) + ["--format", "cyclonedx", image]
    return run(cmd, timeout)


def _cvss(v: dict) -> tuple[float | None, str, str]:
    """Highest v3 score across the sources Trivy lists (nvd, ghsa, redhat...); a v4 score only when no
    source has v3. Returns (score, version, source); ties go to the preference order."""
    table = v.get("CVSS") or {}
    order = [v.get("SeveritySource")] + _CVSS_PREF + sorted(table)
    best = None
    for src in dict.fromkeys(s for s in order if s):
        entry = table.get(src) or {}
        for score_key, vector_key, default in (("V3Score", "V3Vector", "3"), ("V40Score", "V40Vector", "4.0")):
            if entry.get(score_key) is not None:
                cand = (float(entry[score_key]), version_of(entry.get(vector_key), default), src)
                if better(cand, best):
                    best = cand
    return best if best else (None, "", "")


def _src_version(p: dict) -> str:
    v = p.get("SrcVersion") or ""
    if not v:
        return ""
    if p.get("SrcRelease"):
        v = f"{v}-{p['SrcRelease']}"
    if p.get("SrcEpoch"):
        v = f"{p['SrcEpoch']}:{v}"
    return v


def parse(report: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    meta_os = (report.get("Metadata") or {}).get("OS") or {}
    os_release = f"{meta_os.get('Family', '')} {meta_os.get('Name', '')}".strip().lower()
    for result in report.get("Results") or []:
        target = result.get("Target", "")
        rtype = result.get("Type", "")
        is_os = result.get("Class") == "os-pkgs"
        by_id = {p.get("ID"): p for p in result.get("Packages") or [] if p.get("ID")}
        by_name = {p.get("Name"): p for p in result.get("Packages") or [] if p.get("Name")}
        for v in result.get("Vulnerabilities") or []:
            ident = v.get("PkgIdentifier") or {}
            pkg = by_id.get(v.get("PkgID")) or by_name.get(v.get("PkgName")) or {}
            cvss_score, cvss_ver, cvss_src = _cvss(v)
            f = Finding(
                vuln_id=v.get("VulnerabilityID", ""),
                package=v.get("PkgName", ""),
                installed=v.get("InstalledVersion", ""),
                severity=normalise_severity(v.get("Severity")),
                fixed_versions=split_fixed(v.get("FixedVersion")),
                cvss=cvss_score,
                cvss_version=cvss_ver,
                cvss_source=cvss_src,
                published=parse_datetime(v.get("PublishedDate")),
                purl=ident.get("PURL"),
                pkg_type=rtype,
                target=v.get("PkgPath") or target,
                title=v.get("Title", "") or "",
                vendor_ids=list(v.get("VendorIDs") or []),
                src_name=pkg.get("SrcName", "") if is_os else "",
                src_version=_src_version(pkg) if is_os else "",
                os_release=os_release if is_os else "",
                url=v.get("PrimaryURL", "") or "",
                sources={NAME},
            )
            f.source_severity[NAME] = f.severity
            findings.append(f)
    meta = report.get("Metadata") or {}
    os_info = meta.get("OS") or {}
    info = {
        "artifact": report.get("ArtifactName"),
        "created_at": report.get("CreatedAt"),
        "os": f"{os_info.get('Family', '')} {os_info.get('Name', '')}".strip() or None,
        # OCI image config 'created': when the image was built. Fallback release date for lag.
        "image_created": (meta.get("ImageConfig") or {}).get("created"),
        "repo_digests": meta.get("RepoDigests") or [],
        "targets": [
            {"target": r.get("Target"), "class": r.get("Class"), "type": r.get("Type"),
             "vulnerabilities": len(r.get("Vulnerabilities") or [])}
            for r in report.get("Results") or []
        ],
    }
    return findings, info
