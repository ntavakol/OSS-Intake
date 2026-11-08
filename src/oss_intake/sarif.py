"""SARIF 2.1.0 output (findings.sarif) for code-scanning dashboards such as GitHub code scanning.

One rule per advisory and one result per finding (advisory, package and installed version), placed at the file
the scanner found the package in (a lockfile, or a path inside the image or folder) or, when there is none, at
the target. The result's severity follows the finding's: error for critical, high, malicious or CISA KEV,
warning for medium, note otherwise; GitHub reads its own security severity from the CVSS score
(properties.security-severity). An assessor's not_affected or fixed decision, and a finding the tool set aside
on its own evidence, is carried as a suppression with the reason, not dropped.
"""
from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import quote

from .models import Finding

# A score for the severity GitHub shows, when no source gave a CVSS score: inside GitHub's bands (critical over
# 9.0, high 7.0 to 8.9, medium 4.0 to 6.9, low 0.1 to 3.9).
_SCORE = {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.0, "UNKNOWN": 0.0}


def _level(f: Finding) -> str:
    if f.malicious or f.kev or f.severity in ("CRITICAL", "HIGH"):
        return "error"
    return "warning" if f.severity == "MEDIUM" else "note"


def _score(f: Finding) -> str:
    if f.malicious:
        return "10.0"
    return f"{f.cvss if f.cvss is not None else _SCORE.get(f.severity, 0.0):.1f}"


def _uri(target: str) -> str:
    """A target as a relative URI: a path keeps its slashes; an image name such as 'owner/app:1.0 (debian 12)'
    is escaped, as SARIF wants a URI."""
    return quote(target.strip().lstrip("/"), safe="/._-@~+") or "target"


def _message(f: Finding) -> str:
    parts = [f"{f.package} {f.installed}: {f.vuln_id}"]
    if f.malicious:
        parts.append("this package version is listed as malware: treat the artifact as compromised")
    if f.title:
        parts.append(f.title)
    if f.fixed_versions:
        parts.append(f"fixed in {', '.join(f.fixed_versions)}")
    if f.kev:
        parts.append("listed in CISA KEV (known exploited)")
    return ". ".join(p.rstrip(".") for p in parts) + "."


def _suppression(f: Finding) -> dict | None:
    if f.decision_status in ("not_affected", "fixed"):
        why = f"assessor decision: {f.decision_status}" + (f" ({f.decision_notes})" if f.decision_notes else "")
        return {"kind": "external", "status": "accepted", "justification": why}
    if f.triage_group == "aside":
        return {"kind": "external", "status": "accepted",
                "justification": f"set aside by oss-intake: {f.triage_reason or f.excluded or 'evidence'}"}
    return None


def build(findings: list[Finding], version: str, target_name: str) -> dict[str, Any]:
    rules: dict[str, dict] = {}
    results = []
    for f in findings:
        rule = rules.setdefault(f.vuln_id, {
            "id": f.vuln_id,
            "shortDescription": {"text": (f.title or f.vuln_id)[:1024]},
            "properties": {"tags": ["security", "vulnerability", *(["malicious"] if f.malicious else [])],
                           "security-severity": _score(f)},
            **({"helpUri": f.url} if f.url else {}),
        })
        # The rule carries the highest score any of its findings has (GitHub reads severity from the rule).
        if float(_score(f)) > float(rule["properties"]["security-severity"]):
            rule["properties"]["security-severity"] = _score(f)
        targets = [t for t in (f.target or "").split(";") if t.strip()] or [target_name]
        key = "\0".join((f.vuln_id, f.pkg_type, f.package, f.installed, *sorted(targets)))
        result: dict[str, Any] = {
            "ruleId": f.vuln_id,
            "level": _level(f),
            "message": {"text": _message(f)},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": _uri(t)},
                                                "region": {"startLine": 1}}} for t in targets],
            # The same finding on the next run is the same alert, not a new one.
            "partialFingerprints": {"ossIntakeFinding/v1": hashlib.sha256(key.encode()).hexdigest()},
            "properties": {k: v for k, v in {
                "package": f.package, "installedVersion": f.installed, "purl": f.purl or None,
                "severity": f.severity, "fixedVersions": f.fixed_versions or None, "kev": f.kev or None,
                "epss": f.epss, "triage": f.triage_group or None}.items() if v is not None},
        }
        if (s := _suppression(f)) is not None:
            result["suppressions"] = [s]
        results.append(result)
    # The schema and project addresses only name things in the file: nothing is fetched from them (unlike the
    # module-level URL constants elsewhere, which are services oss-intake calls).
    return {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "oss-intake", "version": version, "informationUri": "https://github.com/ntavakol/OSS-Intake",
                                "rules": list(rules.values())}},
            "results": results,
        }],
    }
