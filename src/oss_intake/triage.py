"""Suggested triage groups: where an engineer should look first, with the reason for each finding.

Groups, first match wins:
  act        Act now: in CISA KEV, or a ready-to-use exploit exists (Metasploit module or Nuclei template)
  review     Review: a published exploit (Exploit-DB), EPSS 0.1 or more, or a critical finding whose
             advisory states no conditions
  conditions Check conditions: the advisory says it applies only under conditions (quoted in findings.csv);
             the assessor confirms whether they hold in the deployment
  routine    Routine: none of the above; patch in the normal cycle
  aside      Set aside: only with evidence the tool has (kernel CVEs on kernel header packages, or the
             installed version already matches a fix apart from a build label)

This is a reading order, not a risk rating, and never a statement that a finding carries no risk.
"""

from __future__ import annotations

from .models import SEVERITY_ORDER, Finding

ORDER = ["act", "review", "conditions", "routine", "aside"]
LABEL = {"act": "Act now", "review": "Review", "conditions": "Check conditions", "routine": "Routine",
         "aside": "Set aside"}
MEANING = {
    "act": "Malicious package, exploited in the wild, or a ready-to-use exploit exists",
    "review": "Published exploit, notable exploitation probability, or a critical that applies without conditions",
    "conditions": "The advisory says it applies only under stated conditions; confirm whether they hold",
    "routine": "No exploit indexed, low exploitation probability, no stated conditions; normal patch cycle",
    "aside": "The tool has evidence it does not apply (kernel header package, already fixed, or govulncheck "
             "shows the vulnerable function is not in the binary)",
}
EPSS_REVIEW = 0.1


def classify(f: Finding) -> tuple[str, str]:
    if f.excluded == "kernel-headers":
        return "aside", "kernel CVE on a kernel header package; containers use the host kernel"
    if f.likely_fixed:
        return "aside", "installed version matches a listed fix apart from a build label"
    if f.malicious:
        return "act", ("malicious package (OpenSSF malicious packages, or advisory classed CWE-506); "
                       "the package itself is malware")
    if f.reachability == "not reachable":
        return "aside", f.reachability_note + (" (note: listed in CISA KEV)" if f.kev else "")
    if f.kev:
        return "act", "listed in CISA KEV (exploited in the wild)"
    if f.exploit_level == "weaponised":
        ref = next((r for r in f.exploit_refs if r.startswith(("metasploit:", "nuclei:"))), "")
        return "act", "ready-to-use exploit" + (f" ({ref})" if ref else "")
    if f.exploit_level == "public":
        return "review", "published exploit in Exploit-DB"
    if f.epss is not None and f.epss >= EPSS_REVIEW:
        return "review", f"EPSS {f.epss:.2f}"
    if f.conditions:
        return "conditions", "advisory states when it applies; see the conditions column"
    if f.severity == "CRITICAL":
        return "review", "critical, and the advisory states no conditions"
    if f.reachability == "reachable":
        return "review", f.reachability_note
    return "routine", "no exploit indexed, EPSS below 0.1, no stated conditions"


def apply(findings: list[Finding]) -> dict:
    counts = {g: {"total": 0, "with_fix": 0} for g in ORDER}
    for f in findings:
        f.triage_group, f.triage_reason = classify(f)
        counts[f.triage_group]["total"] += 1
        if f.fixed_versions:
            counts[f.triage_group]["with_fix"] += 1
    return {"groups": counts, "exploits_checked": any(f.exploit_level for f in findings)}


def rank_key(f: Finding) -> tuple:
    """Top-findings order: triage group first, then severity, missed fixes, and how long a fix has existed."""
    group = ORDER.index(f.triage_group) if f.triage_group in ORDER else ORDER.index("routine")
    return (group, -SEVERITY_ORDER[f.severity], not f.fix_available_at_release, not f.has_fix,
            -(f.days_fix_available or 0), f.vuln_id)
