"""Report writers: CSV (findings), Markdown (summary), JSON (automation), HTML (self-contained)."""

from __future__ import annotations

import csv
import html
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
    "id", "aliases", "severity", "cvss", "package", "pkg_type", "installed", "fixed_versions",
    "fix_version_used", "fix_published", "fix_available_at_release", "days_fix_available",
    "cve_published", "cve_published_before_release", "kev", "sources", "source_severity", "target",
    "title", "url", "note", "triage_reachable", "triage_status", "triage_notes",
]


def finding_row(f: Finding) -> dict:
    return {
        "id": f.vuln_id,
        "aliases": ";".join(sorted(f.aliases)),
        "severity": f.severity,
        "cvss": "" if f.cvss is None else f"{f.cvss:.1f}",
        "package": f.package,
        "pkg_type": f.pkg_type,
        "installed": f.installed,
        "fixed_versions": ";".join(f.fixed_versions),
        "fix_version_used": f.fix_version_used or "",
        "fix_published": f.fix_published.date().isoformat() if f.fix_published else "",
        "fix_available_at_release": _tri(f.fix_available_at_release),
        "days_fix_available": "" if f.days_fix_available is None else f.days_fix_available,
        "cve_published": f.published.date().isoformat() if f.published else "",
        "cve_published_before_release": _tri(f.published_before_release),
        "kev": "yes" if f.kev else "",
        "sources": ";".join(sorted(f.sources)),
        "source_severity": ";".join(f"{k}:{v}" for k, v in sorted(f.source_severity.items())),
        "target": f.target,
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

def _v(x: object, suffix: str = "") -> str:
    return "n/a" if x is None or x == "" else f"{x}{suffix}"


def summary_sections(a: dict, findings: list[Finding], top: int) -> list[tuple[str, list]]:
    """Return [(heading, blocks)] where a block is ('p', text) or ('table', headers, rows)."""
    lag, health, sc = a["lag"], a["health"], a["scorecard"]
    inp = a["inputs"]
    secs: list[tuple[str, list]] = []

    scope_rows = [["Image", _v(inp.get("image"))], ["Repository", _v(inp.get("repo"))],
                  ["Release used for lag", _v((health.get("scanned_release") or {}).get("tag"))
                   + (f" ({lag['release_date'][:10]})" if lag.get("release_date") else "")],
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
         _v(lag["unshipped"]) + ("" if lag["unshipped"] is None else
                                 f" (critical {lag['unshipped_by_severity']['CRITICAL']}, "
                                 f"high {lag['unshipped_by_severity']['HIGH']})")],
        ["Likely already fixed (build label mismatch)", lag["likely_fixed_label_match"]],
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
    secs.append(("Release lag", [("table", ["Metric", "Value"], lag_rows), (
        "p", f"A fix counts as existing before the release only if the fixed dependency version was "
             f"published at least {lag['grace_days']} days before the project's release date. 'Unshipped' "
             f"counts fixes public for {lag['unshipped_days']} days or more while the scanned release is "
             "still the latest. Fix dates come from deps.dev for language packages; OS packages have no "
             "fix date and are counted as unknown.")]))

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

    lk = a.get("likelihood")
    if lk:
        secs.append(("Likelihood suggestion (heuristic)", [
            ("p", f"Suggested likelihood: {lk['level']} ({lk['label']}). {lk['reason']}."
                  + (" Custom rules were used." if lk.get("custom_config") else " Default rules were used.")),
            ("p", HEURISTIC_NOTE)]))

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
    ranked = sorted(findings, key=lambda f: (f.likely_fixed, -SEVERITY_ORDER[f.severity],
                                             not f.fix_available_at_release, not f.has_fix,
                                             -(f.days_fix_available or 0), f.vuln_id))
    for f in ranked[:top]:
        before = ("likely fixed" if f.likely_fixed else "no fix" if not f.has_fix
                  else (_tri(f.fix_available_at_release) or "unknown"))
        rows.append([f.vuln_id, f.severity, f.package, f.installed,
                     f.fix_version_used or ";".join(f.fixed_versions) or "none", before, _v(f.days_fix_available)])
    if rows:
        secs.append((f"Top {len(rows)} findings", [("table", ["ID", "Severity", "Package", "Installed", "Fix",
                                                               "Fix before release", "Days fix available"],
                                                     rows), ("p", "Full list: findings.csv")]))
    if a.get("warnings"):
        secs.append(("Warnings", [("list", a["warnings"])]))
    return secs


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


_CSS = """
:root{--bg:#fff;--fg:#1b1f24;--muted:#57606a;--line:#d0d7de;--head:#f6f8fa;--accent:#0b5cad}
@media (prefers-color-scheme: dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9da7b3;--line:#30363d;
--head:#161b22;--accent:#58a6ff}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,Segoe UI,sans-serif;
margin:0 auto;max-width:1100px;padding:24px 16px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.15rem;margin:28px 0 8px;color:var(--accent)}
p{color:var(--muted);max-width:80ch}.meta{color:var(--muted);font-size:.85rem}
.wrap{overflow-x:auto}table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{border:1px solid var(--line);padding:6px 8px;text-align:left;vertical-align:top}
th{background:var(--head)}td{font-variant-numeric:tabular-nums}
"""


def write_html(path: Path, a: dict, findings: list[Finding], top: int = 50) -> None:
    e = html.escape
    title = a["inputs"].get("image") or a["inputs"].get("repo") or "assessment"
    parts = ["<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
             "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
             f"<title>OSS intake: {e(title)}</title><style>{_CSS}</style></head><body>",
             f"<h1>OSS intake assessment: {e(title)}</h1>",
             f"<div class=\"meta\">Generated by oss-intake {e(a['tool']['version'])} on "
             f"{e(a['generated_at'][:19])}Z</div>"]
    for heading, blocks in summary_sections(a, findings, top):
        parts.append(f"<h2>{e(heading)}</h2>")
        for b in blocks:
            if b[0] == "p":
                parts.append(f"<p>{e(b[1])}</p>")
            elif b[0] == "list":
                parts.append("<ul>" + "".join(f"<li>{e(str(i))}</li>" for i in b[1]) + "</ul>")
            else:
                _, headers, rows = b
                parts.append("<div class=\"wrap\"><table><thead><tr>"
                             + "".join(f"<th>{e(h)}</th>" for h in headers) + "</tr></thead><tbody>")
                parts += ["<tr>" + "".join(f"<td>{e(str(c))}</td>" for c in r) + "</tr>" for r in rows]
                parts.append("</tbody></table></div>")
    parts.append("</body></html>")
    path.write_text("".join(parts), encoding="utf-8")
