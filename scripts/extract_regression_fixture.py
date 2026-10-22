"""Trim a real Trivy (and optionally Grype) report down to a small regression fixture.

Keeps only vulnerabilities and packages whose name contains one of the given substrings, plus
the first N OS-package vulnerabilities if --os-sample is set. Image metadata other than the OS
is dropped. Output goes to tests/fixtures/real/<name>-trivy.json and <name>-grype.json.

Usage:
  python scripts/extract_regression_fixture.py NAME RAW_DIR [--match SUBSTR ...] [--os-sample N]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "real"


def _hit(name: str, needles: list[str]) -> bool:
    return any(n in name for n in needles)


def trim_trivy(report: dict, needles: list[str], os_sample: int) -> dict:
    results = []
    for r in report.get("Results") or []:
        is_os = r.get("Class") == "os-pkgs"
        vulns = [v for v in r.get("Vulnerabilities") or [] if _hit(v.get("PkgName", ""), needles)]
        if is_os and os_sample:
            extra = [v for v in r.get("Vulnerabilities") or [] if v not in vulns and v.get("FixedVersion")]
            vulns += extra[:os_sample]
        if not vulns:
            continue
        names = {v.get("PkgName") for v in vulns}
        keep = ("VulnerabilityID", "PkgID", "PkgName", "PkgIdentifier", "PkgPath", "InstalledVersion", "FixedVersion",
                "Status", "Severity", "SeveritySource", "VendorIDs", "CVSS", "PublishedDate")
        results.append({
            "Target": r.get("Target"), "Class": r.get("Class"), "Type": r.get("Type"),
            "Packages": [{k: p[k] for k in ("ID", "Name", "Version", "Release", "Epoch", "SrcName", "SrcVersion",
                                            "SrcRelease", "SrcEpoch", "Identifier") if k in p}
                         for p in r.get("Packages") or [] if p.get("Name") in names],
            "Vulnerabilities": [{k: v[k] for k in keep if k in v} for v in vulns],
        })
    os_info = (report.get("Metadata") or {}).get("OS")
    return {"SchemaVersion": report.get("SchemaVersion"), "ArtifactName": report.get("ArtifactName"),
            "Metadata": {"OS": os_info} if os_info else {}, "Results": results}


def trim_grype(report: dict, needles: list[str]) -> dict:
    keep = [m for m in report.get("matches") or [] if _hit((m.get("artifact") or {}).get("name", ""), needles)
            or _hit((m.get("artifact") or {}).get("purl", "") or "", needles)]
    slim = []
    for m in keep:
        v, a = m.get("vulnerability") or {}, m.get("artifact") or {}
        slim.append({
            "vulnerability": {k: v.get(k) for k in ("id", "severity", "fix", "cvss", "dataSource")},
            "relatedVulnerabilities": [{"id": r.get("id")} for r in m.get("relatedVulnerabilities") or []],
            "artifact": {k: a.get(k) for k in ("name", "version", "type", "purl", "locations")},
        })
    return {"matches": slim}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("name")
    ap.add_argument("raw_dir", type=Path)
    ap.add_argument("--match", nargs="*", default=[])
    ap.add_argument("--os-sample", type=int, default=0)
    args = ap.parse_args()
    src = args.raw_dir / "trivy.json"
    if not src.is_file():
        raise SystemExit(f"error: {src} not found. RAW_DIR must be a report's raw/ folder, e.g. reports/app/raw")
    OUT.mkdir(parents=True, exist_ok=True)
    trivy = json.loads(src.read_text(encoding="utf-8"))
    t = trim_trivy(trivy, args.match, args.os_sample)
    (OUT / f"{args.name}-trivy.json").write_text(json.dumps(t, indent=1) + "\n", encoding="utf-8")
    n = sum(len(r["Vulnerabilities"]) for r in t["Results"])
    msg = f"{args.name}: {n} Trivy vulnerabilities"
    g = args.raw_dir / "grype.json"
    if g.exists():
        gt = trim_grype(json.loads(g.read_text(encoding="utf-8")), args.match)
        (OUT / f"{args.name}-grype.json").write_text(json.dumps(gt, indent=1) + "\n", encoding="utf-8")
        msg += f", {len(gt['matches'])} Grype matches"
    print(msg)


if __name__ == "__main__":
    main()
