"""Trivy adapter: version, vulnerability scan (JSON) and CycloneDX SBOM."""

from __future__ import annotations

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


def _base_cmd(binary: str, image_src: str | None, extra: list[str]) -> list[str]:
    cmd = [binary, "image", "--quiet", "--timeout", "20m"]
    if image_src:
        cmd += ["--image-src", image_src]
    return cmd + list(extra)


def scan(binary: str, image: str, image_src: str | None, extra: list[str], timeout: int) -> bytes:
    cmd = _base_cmd(binary, image_src, extra) + ["--format", "json", "--scanners", "vuln", image]
    return run(cmd, timeout)


def sbom(binary: str, image: str, image_src: str | None, extra: list[str], timeout: int) -> bytes:
    cmd = _base_cmd(binary, image_src, extra) + ["--format", "cyclonedx", image]
    return run(cmd, timeout)


def _cvss(v: dict) -> float | None:
    table = v.get("CVSS") or {}
    order = [v.get("SeveritySource")] + _CVSS_PREF + list(table)
    for src in order:
        entry = table.get(src) if src else None
        if entry and entry.get("V3Score") is not None:
            return float(entry["V3Score"])
    return None


def parse(report: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    for result in report.get("Results") or []:
        target = result.get("Target", "")
        rtype = result.get("Type", "")
        for v in result.get("Vulnerabilities") or []:
            ident = v.get("PkgIdentifier") or {}
            f = Finding(
                vuln_id=v.get("VulnerabilityID", ""),
                package=v.get("PkgName", ""),
                installed=v.get("InstalledVersion", ""),
                severity=normalise_severity(v.get("Severity")),
                fixed_versions=split_fixed(v.get("FixedVersion")),
                cvss=_cvss(v),
                published=parse_datetime(v.get("PublishedDate")),
                purl=ident.get("PURL"),
                pkg_type=rtype,
                target=v.get("PkgPath") or target,
                title=v.get("Title", "") or "",
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
        "repo_digests": meta.get("RepoDigests") or [],
        "targets": [
            {"target": r.get("Target"), "class": r.get("Class"), "type": r.get("Type"),
             "vulnerabilities": len(r.get("Vulnerabilities") or [])}
            for r in report.get("Results") or []
        ],
    }
    return findings, info
