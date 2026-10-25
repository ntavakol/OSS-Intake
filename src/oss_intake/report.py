"""Report writers: CSV (findings), Markdown (summary), JSON (automation), HTML (self-contained)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from .models import SEVERITIES, SEVERITY_ORDER, Finding

CAVEAT = (
    "Scanner results are version matching, not proof of exploitability. A finding means a component "
    "version is listed as affected; it does not show that the vulnerable code is reachable or exposed "
    "in your deployment. Use the triage columns in findings.csv to record reachability decisions."
)
HEURISTIC_NOTE = (
    "The likelihood suggestion is a configurable heuristic built from observable signals. It is a "
    "starting point for an assessor, not a risk rating."
)
CSV_FIELDS = [
    "id", "aliases", "severity", "cvss", "cvss_version", "cvss_source", "package", "pkg_type", "installed",
    "fixed_versions",
    "fix_version_used", "fix_published", "fix_date_source", "fix_available_at_release", "days_fix_available",
    "cve_published", "cve_published_before_release", "kev", "epss", "epss_percentile", "sources",
    "source_severity", "target",
    "exploit_level", "exploit_refs", "conditions",
    "title", "url", "note", "triage_reachable", "triage_status", "triage_notes",
]


def finding_row(f: Finding) -> dict:
    return {
        "id": f.vuln_id,
        "aliases": ";".join(sorted(f.aliases)),
        "severity": f.severity,
        "cvss": "" if f.cvss is None else f"{f.cvss:.1f}",
        "cvss_version": f.cvss_version,
        "cvss_source": f.cvss_source,
        "package": f.package,
        "pkg_type": f.pkg_type,
        "installed": f.installed,
        "fixed_versions": ";".join(f.fixed_versions),
        "fix_version_used": f.fix_version_used or "",
        "fix_published": f.fix_published.date().isoformat() if f.fix_published else "",
        "fix_date_source": f.fix_date_source,
        "fix_available_at_release": _tri(f.fix_available_at_release),
        "days_fix_available": "" if f.days_fix_available is None else f.days_fix_available,
        "cve_published": f.published.date().isoformat() if f.published else "",
        "cve_published_before_release": _tri(f.published_before_release),
        "kev": "yes" if f.kev else "",
        "epss": "" if f.epss is None else f"{f.epss:.4f}",
        "epss_percentile": "" if f.epss_percentile is None else f"{f.epss_percentile:.3f}",
        "sources": ";".join(sorted(f.sources)),
        "source_severity": ";".join(f"{k}:{v}" for k, v in sorted(f.source_severity.items())),
        "target": f.target,
        "exploit_level": f.exploit_level,
        "exploit_refs": ";".join(f.exploit_refs),
        "conditions": f.conditions,
        "title": f.title,
        "url": f.url,
        "note": f.note,
        "triage_reachable": "",
        "triage_status": "",
        "triage_notes": "",
    }


def _tri(v: bool | None) -> str:
    return "" if v is None else ("yes" if v else "no")


def _csv_safe(value: object) -> object:
    """Neutralise spreadsheet formula injection from untrusted advisory text."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def write_csv(path: Path, findings: list[Finding]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_FIELDS)
        w.writeheader()
        for f in findings:
            w.writerow({k: _csv_safe(v) for k, v in finding_row(f).items()})


def to_json(a: dict, findings: list[Finding]) -> dict:
    out = {k: v for k, v in a.items()}
    out["findings"] = [finding_row(f) for f in findings]
    out["caveats"] = [CAVEAT, HEURISTIC_NOTE]
    return out


def write_json(path: Path, a: dict, findings: list[Finding]) -> None:
    path.write_text(json.dumps(to_json(a, findings), indent=2, default=str), encoding="utf-8")


# ---------- Shared summary model used by Markdown and HTML ----------

def release_used(lag: dict, health: dict) -> str:
    date = (lag.get("release_date") or "")[:10]
    src = lag.get("release_date_source") or ""
    if src == "image build date":
        return f"no matching release; image build date {date} used"
    tag = (health.get("scanned_release") or {}).get("tag") or "n/a"
    return tag + (f" ({date})" if date else "") + (f", from {src}" if src else "")


def cvss_text(f: Finding) -> str:
    """'9.8 (3.1, nvd)'; v4 scores are marked so they are not read on the v3 scale."""
    if f.cvss is None:
        return "n/a"
    detail = ", ".join(x for x in (f.cvss_version, f.cvss_source) if x)
    return f"{f.cvss:.1f}" + (f" ({detail})" if detail else "")


CVSS_NOTE = ("CVSS: the highest v3.x base score any source reported, with its version and source database; a v4 "
             "score is shown only when no source has a v3 score. Sources can disagree, and a distro's severity "
             "rating can differ from an upstream CVSS score.")


EXPLOIT_LABEL = {"kev": "known exploited", "weaponised": "weaponised", "public": "public exploit",
                 "poc": "proof of concept", "none": "none indexed", "": "not checked"}
EXPLOIT_NOTE = ("Exploit: the strongest public evidence found. Known exploited = CISA KEV; weaponised = a Metasploit "
                "module or Nuclei template; public exploit = Exploit-DB; proof of concept = GitHub repositories only "
                "(noisy, some fake or malicious). 'None indexed' means none was found in these sources, not that "
                "none exists.")


def exploit_text(f: Finding) -> str:
    return EXPLOIT_LABEL.get(f.exploit_level, f.exploit_level)


def lag_note(lag: dict) -> str:
    return (f"A fix counts as existing before the release only if the fixed dependency version was published at "
            f"least {lag['grace_days']} days before the project's release date. 'Unshipped' counts fixes public "
            f"for {lag['unshipped_days']} days or more while the scanned release is still the latest. Fix dates "
            "come from deps.dev and Packagist for language packages (GitHub release dates for Go modules deps.dev "
            "lacks), from Debian advisories (DSA, DLA) and point releases, Ubuntu Security Notices and "
            "Launchpad publishing history, Red Hat "
            "advisories (RHSA), Alpine aports commits, and the Go release history for the Go standard library. "
            "Amazon Linux has no dated source yet and is counted as unknown; see the fix date coverage table.")

def _v(x: object, suffix: str = "") -> str:
    return "n/a" if x is None or x == "" else f"{x}{suffix}"


def summary_sections(a: dict, findings: list[Finding], top: int) -> list[tuple[str, list]]:
    """Return [(heading, blocks)] where a block is ('p', text) or ('table', headers, rows)."""
    lag, health, sc = a["lag"], a["health"], a["scorecard"]
    inp = a["inputs"]
    secs: list[tuple[str, list]] = []

    scope_rows = [["Image", _v(inp.get("image"))], ["Repository", _v(inp.get("repo"))],
                  ["Release used for lag", release_used(lag, health)],
                  ["Assessment date", a["as_of"][:10]]]
    for name, s in a["scanners"].items():
        if s.get("enabled"):
            detail = s.get("version") or s.get("detail") or ""
            if s.get("db_updated"):
                detail += f", DB {str(s['db_updated'])[:10]}"
            if "hash_verified" in s:
                detail += ", hash verified" if s["hash_verified"] else ", hash NOT verified"
            scope_rows.append([f"Source: {name}", detail])
    secs.append(("Scope", [("table", ["Item", "Value"], scope_rows), ("p", CAVEAT)]))

    sev_rows = []
    for s in SEVERITIES:
        sev_rows.append([s, lag["by_severity"].get(s, 0), lag["with_fix_by_severity"].get(s, 0),
                         lag["fix_available_at_release_by_severity"].get(s, 0)])
    sev_rows.append(["Total", lag["total"], lag["with_fix"], lag["fix_available_at_release"]])
    secs.append(("Findings", [("table", ["Severity", "Findings", "Fix exists upstream",
                                         "Fix existed before release"], sev_rows)]))

    lag_rows = [
        ["Findings with an upstream fix", lag["with_fix"]],
        ["Fix publication date found", f"{lag['fix_date_known']} (unknown: {lag['fix_date_unknown']})"],
        [f"Fix existed at least {lag['grace_days']} days before the release (not shipped)",
         lag["fix_available_at_release"]],
        [f"Fix published within {lag['grace_days']} days before the release (not counted)", lag["fix_within_grace"]],
        [f"Fix public {lag['unshipped_days']}+ days with no newer release (unshipped)",
         ("n/a (scanned release is not the latest)" if lag.get("scanned_is_latest") is False
          else _v(lag["unshipped"])) + ("" if lag["unshipped"] is None else
                                 f" (critical {lag['unshipped_by_severity']['CRITICAL']}, "
                                 f"high {lag['unshipped_by_severity']['HIGH']})")],
        ["Likely already fixed (build label mismatch)", lag["likely_fixed_label_match"]],
        ["Kernel CVEs on kernel header packages (excluded: containers use the host kernel)",
         lag.get("excluded_kernel_headers", 0)],
        ["Fix published after the release", lag["fix_after_release"]],
        ["CVE published before the release (secondary)", lag["cve_published_before_release"]],
        ["Median days a fix has been available", _v(lag["median_days_fix_available"])],
        ["Longest days a fix has been available", _v(lag["max_days_fix_available"])],
    ]
    o = lag.get("oldest_available_fix")
    if o:
        lag_rows.append(["Oldest available fix", f"{o['id']} in {o['package']}: {o['fix_version']} "
                                                 f"published {o['fix_published']} ({o['days']} days)"])
    lag_rows.append(["Known exploited (CISA KEV) with fix", lag["kev_with_fix"]])
    if lag.get("exploits_checked"):
        by = lag["exploit_with_fix_by_level"]
        lag_rows.append(["Findings with a fix and a ready-to-use exploit (Metasploit or Nuclei)", by["weaponised"]])
        lag_rows.append(["Findings with a fix and a published exploit (Exploit-DB)", by["public"]])
        lag_rows.append(["Findings with a fix and only GitHub proofs of concept", by["poc"]])
    if lag.get("epss_scored"):
        lag_rows.append(["Highest EPSS among findings with a fix (30-day exploitation probability)",
                         f"{lag['max_epss_with_fix']:.3f}" if lag.get("max_epss_with_fix") is not None else "n/a"])
    cov = a.get("coverage") or []
    if cov:
        cov_rows = [[c["ecosystem"], c["with_fix"], c["dated"], f"{c['percent']}%",
                     ", ".join(f"{k} {v}" for k, v in c["sources"].items()) or "none", c["gap"]] for c in cov]
        secs.append(("Fix date coverage", [
            ("table", ["Ecosystem", "Findings with fix", "Dated", "Coverage", "Date sources", "Why not dated"],
             cov_rows),
            ("p", "Release-lag numbers only count dated findings. Where coverage is low, the lag metrics and "
                  "the likelihood suggestion understate what the scanners found for that ecosystem.")]))
    secs.append(("Release lag", [("table", ["Metric", "Value"], lag_rows), ("p", lag_note(lag))]))

    h_rows = [["Latest release", _v((health.get("latest_release") or {}).get("tag"))
               + (f" ({health['latest_release']['date'][:10]})" if health.get("latest_release") else "")],
              ["Days since latest release", _v(health.get("days_since_latest_release"))],
              ["Stable releases in last 365 days", _v(health.get("releases_last_365d"))],
              ["Median days between releases", _v(health.get("median_days_between_releases"))],
              ["Scanned release is latest", _v({True: "yes", False: "no"}.get(health.get("scanned_is_latest")))],
              ["Archived", _v({True: "yes", False: "no"}.get(health.get("archived")))],
              ["Days since last push", _v(health.get("days_since_push"))]]
    if sc.get("status") == "ok":
        h_rows.append(["OpenSSF Scorecard", f"{sc.get('score')} / 10 ({sc.get('date')})"])
        if sc.get("low_checks"):
            h_rows.append(["Scorecard checks scoring 0 to 3", ", ".join(sc["low_checks"])])
    else:
        h_rows.append(["OpenSSF Scorecard", sc.get("note") or sc.get("status", "n/a")])
    secs.append(("Project health", [("table", ["Signal", "Value"], h_rows)]))

    wf = health.get("workflows") or {}
    if wf.get("status") == "ok":
        checked = str(wf["files"]) + (f" ({wf['files_skipped']} more not checked)" if wf["files_skipped"] else "")
        w_rows = [["Workflow files checked", checked],
                  ["Action references", wf["uses_total"]],
                  ["Pinned to a full commit SHA", _v(wf["pinned_percent"], "%")],
                  ["Known-bad action versions", len(wf["known_bad"]) or "none"],
                  ["Files without a top-level permissions block",
                   ", ".join(wf["no_top_level_permissions"]) or "none"],
                  ["Files granting write-all", ", ".join(wf["write_all"]) or "none"],
                  ["Files using pull_request_target", ", ".join(wf["pull_request_target"]) or "none"],
                  ["pull_request_target that also checks out PR code",
                   ", ".join(wf.get("pull_request_target_pr_code", [])) or "none"]]
        blocks = [("table", ["Check", "Result"], w_rows)]
        for kb in wf["known_bad"]:
            blocks.append(("p", f"{kb['file']}: {kb['uses']} ({kb['reference']}). {kb['note']}"))
        blocks.append(("p", "These checks describe how exposed the project's own releases are to tampering in CI. "
                            "They do not change the likelihood suggestion."))
        secs.append(("Project CI hygiene (GitHub Actions)", blocks))
    elif wf.get("status") in ("none", "error"):
        secs.append(("Project CI hygiene (GitHub Actions)", [("p", wf.get("note", ""))]))

    lk = a.get("likelihood")
    if lk:
        secs.append(("Likelihood suggestion (heuristic)", [
            ("p", f"Suggested likelihood: {lk['level']} ({lk['label']}). {lk['reason']}."
                  + (" Custom rules were used." if lk.get("custom_config") else " Default rules were used.")),
            ("p", "Driven by: " + _drivers(lag)),
            ("p", "Confidence: " + lk.get("confidence", "normal")
                  + ("" if not lk.get("confidence_reasons") else
                     ". Treat a low level as 'not enough evidence', not 'low risk': "
                     + "; ".join(lk["confidence_reasons"]) + ".")),
            ("p", HEURISTIC_NOTE)]
            + ([("p", "The scanned release is not the project's latest (newer: "
                      + ", ".join(health.get("newer_stable_releases", [])[:5])
                      + "). The unshipped metric only applies to a latest release, so the main question here is "
                        "whether to adopt a newer version; assess that version too.")]
               if health.get("scanned_is_latest") is False else [])))

    ag = a.get("agreement") or {}
    if len(ag.get("enabled", [])) > 1:
        rows = [[s, ag["by_source"].get(s, 0), ag["only"].get(s, 0)] for s in ag["enabled"]]
        rows.append(["All sources", ag.get("all_enabled", 0), ""])
        secs.append(("Source agreement", [("table", ["Source", "Findings seen", "Seen only by this source"],
                                           rows), (
            "p", "Trivy and Grype detect packages independently. OSV is queried with the package list "
                 "from Trivy, so it is an independent database check, not an independent detector. "
                 "Single-source findings deserve a closer look rather than automatic dismissal.")]))

    rows = []
    ranked = sorted(findings, key=lambda f: (f.likely_fixed or bool(f.excluded), -SEVERITY_ORDER[f.severity],
                                             not f.fix_available_at_release, not f.has_fix,
                                             -(f.days_fix_available or 0), f.vuln_id))
    for f in ranked[:top]:
        before = ("likely fixed" if f.likely_fixed else "excluded" if f.excluded else "no fix" if not f.has_fix
                  else (_tri(f.fix_available_at_release) or "unknown"))
        rows.append([f.vuln_id, f.severity, cvss_text(f), exploit_text(f), f.package, f.installed,
                     f.fix_version_used or ";".join(f.fixed_versions) or "none", before, _v(f.days_fix_available)])
    if rows:
        secs.append((f"Top {len(rows)} findings", [("table", ["ID", "Severity", "CVSS", "Exploit", "Package",
                                                               "Installed", "Fix", "Fix before release",
                                                               "Days fix available"],
                                                     rows), ("p", CVSS_NOTE), ("p", EXPLOIT_NOTE),
                                                    ("p", "Full list, with each advisory's conditions: findings.csv")]))
    if a.get("warnings"):
        secs.append(("Warnings", [("list", a["warnings"])]))
    return secs


def _describe(e: dict) -> str:
    where = "found only by Grype from a binary" if e["sources"] == ["grype"] and e["pkg_type"] in ("binary", "") \
        else ("found only by " + e["sources"][0] if len(e["sources"]) == 1 else "found by " + ", ".join(e["sources"]))
    epss = f", EPSS {e['epss']:.2f}" if e.get("epss") is not None else ""
    return f"{e['id']} in {e['package']} ({e['severity']}{epss}; {where})"


def _drivers(lag: dict) -> str:
    parts = []
    if lag.get("kev_findings"):
        parts.append("known exploited: " + "; ".join(_describe(e) for e in lag["kev_findings"]))
    if lag.get("top_epss_findings"):
        parts.append("highest EPSS: " + "; ".join(_describe(e) for e in lag["top_epss_findings"]))
    return (". ".join(parts) + ". Check these components first; they may not be the project's own code.") \
        if parts else "no KEV or EPSS signal; see the release lag table."


def _md_cell(x: object) -> str:
    return str(x).replace("|", "\\|").replace("\n", " ")


def write_markdown(path: Path, a: dict, findings: list[Finding], top: int = 25) -> None:
    title = a["inputs"].get("image") or a["inputs"].get("repo") or "assessment"
    lines = [f"# OSS intake assessment: {title}", "",
             f"Generated by oss-intake {a['tool']['version']} on {a['generated_at'][:19]}Z", ""]
    for heading, blocks in summary_sections(a, findings, top):
        lines += [f"## {heading}", ""]
        for b in blocks:
            if b[0] == "p":
                lines += [b[1], ""]
            elif b[0] == "list":
                lines += [f"- {_md_cell(i)}" for i in b[1]] + [""]
            else:
                _, headers, rows = b
                lines.append("| " + " | ".join(headers) + " |")
                lines.append("|" + "|".join("---" for _ in headers) + "|")
                lines += ["| " + " | ".join(_md_cell(c) for c in r) + " |" for r in rows]
                lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_html(path: Path, a: dict, findings: list[Finding], top: int = 50) -> None:
    from . import report_html

    lag = a["lag"]
    report_html.write(path, a, findings, top, CAVEAT, HEURISTIC_NOTE, lag_note(lag))
