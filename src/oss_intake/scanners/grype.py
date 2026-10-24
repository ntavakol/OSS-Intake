"""Grype adapter: an independent package detector and matcher used to cross-check Trivy."""

from __future__ import annotations

from ..models import Finding, normalise_severity
from . import ScannerError, load_json_bytes, run

NAME = "grype"
_SOURCE_PREFIX = {"remote": "registry:", "docker": "docker:", "podman": "podman:", "containerd": "containerd:"}


def version_info(binary: str) -> dict:
    data = load_json_bytes(run([binary, "version", "-o", "json"], timeout=60), "grype version")
    version = data.get("version")
    if not version:
        raise ScannerError("could not determine grype version")
    return {"version": str(version), "syft_version": data.get("syftVersion")}


def source_for(image: str, image_src: str | None) -> str:
    return _SOURCE_PREFIX.get(image_src or "", "") + image


def scan(binary: str, image: str, image_src: str | None, extra: list[str], timeout: int,
         platform: str | None = None) -> bytes:
    # No -q: it also suppresses error messages. stderr is captured, so progress output is harmless.
    cmd = [binary, source_for(image, image_src), "-o", "json"]
    if platform:
        cmd += ["--platform", platform]
    cmd += list(extra)
    return run(cmd, timeout)


def _best_cvss(entries: list[dict]) -> float | None:
    best = None
    for c in entries or []:
        if not str(c.get("version", "")).startswith("3"):
            continue
        score = (c.get("metrics") or {}).get("baseScore")
        if score is not None and (best is None or float(score) > best):
            best = float(score)
    return best


def parse(report: dict) -> tuple[list[Finding], dict]:
    findings: list[Finding] = []
    for m in report.get("matches") or []:
        vuln = m.get("vulnerability") or {}
        art = m.get("artifact") or {}
        related = m.get("relatedVulnerabilities") or []
        fix = vuln.get("fix") or {}
        fixed = list(fix.get("versions") or []) if fix.get("state") == "fixed" else []
        cvss = _best_cvss(vuln.get("cvss") or [])
        if cvss is None:
            for r in related:
                cvss = _best_cvss(r.get("cvss") or [])
                if cvss is not None:
                    break
        locations = art.get("locations") or []
        name = art.get("name", "")
        purl = art.get("purl") or ""
        if purl.startswith("pkg:maven/"):
            # Report Maven packages as group:artifact, matching Trivy and OSV.
            path = purl[len("pkg:maven/"):].split("@", 1)[0].split("?", 1)[0]
            if "/" in path:
                name = path.replace("/", ":", 1) if path.count("/") == 1 else name
        f = Finding(
            vuln_id=vuln.get("id", ""),
            package=name,
            installed=art.get("version", ""),
            severity=normalise_severity(vuln.get("severity")),
            fixed_versions=fixed,
            cvss=cvss,
            purl=art.get("purl"),
            pkg_type=art.get("type", ""),
            target=(locations[0].get("path", "") if locations else ""),
            aliases={r.get("id") for r in related if r.get("id")},
            # Recent Grype databases list distro advisories (RHSA, DSA, USN...) for a match; keeping them
            # lets Grype-only OS findings be dated like Trivy's.
            vendor_ids=[a["id"] for a in vuln.get("advisories") or [] if isinstance(a, dict) and a.get("id")],
            url=vuln.get("dataSource", "") or "",
            title=(vuln.get("description") or "")[:200],
            sources={NAME},
        )
        f.source_severity[NAME] = f.severity
        findings.append(f)
    desc = report.get("descriptor") or {}
    info = {"descriptor_version": desc.get("version"), "db": (desc.get("db") or {}).get("status") or desc.get("db")}
    return findings, info
