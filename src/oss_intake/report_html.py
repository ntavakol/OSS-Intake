"""Self-contained HTML report: summary tiles, severity bar, colour-coded tables, no scripts.

Colours follow fixed thresholds so every report is coloured the same way:
  days a fix has been available  red 90+, amber 30 to 89, green under 30
  CVSS                           critical 9.0+, red 7.0+, amber 4.0+, green below
  EPSS (highest with a fix)      red 0.5+, amber 0.1+, green below
  OpenSSF Scorecard              red below 5, amber below 7, green 7+
  fix-date coverage              green 90%+, amber 50%+, red below
Every value is escaped; nothing from scanner or advisory data is emitted as markup.
"""

from __future__ import annotations

import html
from pathlib import Path

from .models import SEVERITIES, Finding
from .triage import LABEL as TRIAGE_LABEL
from .triage import MEANING as TRIAGE_MEANING
from .triage import ORDER as TRIAGE_ORDER
from .triage import rank_key

_e = html.escape


class Raw(str):
    """Markup built here from escaped parts; emitted as is."""


def _cell(c: object) -> str:
    return c if isinstance(c, Raw) else _e("" if c is None else str(c))


def _dot(tone: str) -> Raw:
    return Raw(f'<span class="dot {tone}"></span>') if tone else Raw("")


def _metric(label: str, value: object, tone: str = "", html_value: bool = False) -> list:
    return [Raw(_dot(tone or "n") + _e(label)), (value if html_value else _cell(value), tone)]


def _code(x: object) -> Raw:
    return Raw(f"<code>{_e(str(x))}</code>")


def _pill(sev: str) -> Raw:
    cls = {"CRITICAL": "p-crit", "HIGH": "p-high", "MEDIUM": "p-med", "LOW": "p-low"}.get(sev, "p-unk")
    return Raw(f'<span class="pill {cls}">{_e(sev)}</span>')


def _title(a: dict) -> str:
    from .report import report_title

    return report_title(a)


def _attr(cls: str) -> str:
    return f' class="{cls}"' if cls else ""


def _table(headers: list[str], rows: list[list], num: set[int] = frozenset(), row_cls: list[str] | None = None) -> str:
    out = ['<div class="wrap"><table><thead><tr>']
    out += [f"<th{_attr('num' if i in num else '')}>{_e(h)}</th>" for i, h in enumerate(headers)]
    out.append("</tr></thead><tbody>")
    for ri, r in enumerate(rows):
        rc = (row_cls or [""] * len(rows))[ri]
        out.append(f"<tr{_attr(rc)}>")
        for i, c in enumerate(r):
            tone = ""
            if isinstance(c, tuple):
                c, tone = c
            cls = " ".join(x for x in ("num" if i in num else "", tone) if x)
            out.append(f"<td{_attr(cls)}>{_cell(c)}</td>")
        out.append("</tr>")
    out.append("</tbody></table></div>")
    return "".join(out)


def _section(title: str, body: str, extra_cls: str = "") -> str:
    return f"<section{_attr(extra_cls)}><h2>{_e(title)}</h2>{body}</section>"


def _note(text: str) -> str:
    return f'<p class="note">{_e(text)}</p>'


# ---------- thresholds ----------

def tone_days(d: int | None) -> str:
    if d is None:
        return ""
    return "r" if d >= 90 else "a" if d >= 30 else "g"


def tone_cvss(s: float | None) -> str:
    if s is None:
        return ""
    return "c" if s >= 9.0 else "r" if s >= 7.0 else "a" if s >= 4.0 else "g"


def tone_epss(s: float | None) -> str:
    if s is None:
        return ""
    return "r" if s >= 0.5 else "a" if s >= 0.1 else "g"


def tone_scorecard(s: float | None) -> str:
    if s is None:
        return ""
    return "r" if s < 5 else "a" if s < 7 else "g"


def tone_coverage(p: int) -> str:
    return "g" if p >= 90 else "a" if p >= 50 else "r"


def tone_level(level: int | None) -> str:
    return {1: "g", 2: "g", 3: "a", 4: "r", 5: "c"}.get(level or 0, "n")


def _count_tone(n: int | None, tone: str) -> str:
    return tone if n else "g" if n == 0 else ""


def _plural(n: int, word: str) -> str:
    return f"{n} {word}" + ("" if n == 1 else "s")


# ---------- sections ----------

def _tiles(a: dict) -> str:
    lag, sc, lk = a["lag"], a["scorecard"], a.get("likelihood")
    bys, fixs = lag["by_severity"], lag["with_fix_by_severity"]
    tiles = []
    if lk:
        tiles.append((tone_level(lk["level"]), "Likelihood (heuristic)", str(lk["level"]), lk["label"]))
    crit, high = bys.get("CRITICAL", 0), bys.get("HIGH", 0)
    tiles.append(("c" if crit else "g", "Critical", str(crit),
                  "all fixable upstream" if crit and fixs.get("CRITICAL", 0) == crit
                  else f"{fixs.get('CRITICAL', 0)} fixable upstream"))
    tiles.append(("r" if high else "g", "High", str(high),
                  "all fixable upstream" if high and fixs.get("HIGH", 0) == high
                  else f"{fixs.get('HIGH', 0)} fixable upstream"))
    if lag.get("unshipped") is not None:
        u = lag["unshipped"]
        us = lag["unshipped_by_severity"]
        tiles.append(("r" if u else "g", f"Unshipped fixes {lag['unshipped_days']}+ days", str(u),
                      f"critical {us['CRITICAL']}, high {us['HIGH']}"))
    else:
        tiles.append(("a" if lag["fix_available_at_release"] else "g", "Fix existed before release",
                      str(lag["fix_available_at_release"]), "not shipped in the scanned release"))
    if sc.get("status") == "ok":
        tiles.append((tone_scorecard(sc.get("score")), "OpenSSF Scorecard",
                      Raw(f'{_e(str(sc.get("score")))}<span class="of">/10</span>'),
                      _plural(len(sc.get("low_checks") or []), "check") + " scoring 0 to 3"))
    kev = lag["kev_with_fix"]
    parts = []
    if lag.get("exploits_checked"):
        parts.append(f"weaponised {lag['exploit_with_fix_by_level']['weaponised']}")
    if lag.get("max_epss_with_fix") is not None:
        parts.append(f"max EPSS {lag['max_epss_with_fix']:.3f}")
    weap = lag.get("exploit_with_fix_by_level", {}).get("weaponised", 0) if lag.get("exploits_checked") else 0
    tiles.append(("r" if kev else "a" if weap else "g", "CISA KEV", str(kev), ", ".join(parts) or "with a fix"))
    out = ['<div class="tiles">']
    for tone, k, v, s in tiles:
        out.append(f'<div class="tile {tone}"><div class="k">{_e(k)}</div><div class="v">{_cell(v)}</div>'
                   f'<div class="s">{_e(s)}</div></div>')
    out.append("</div>")
    return "".join(out)


def _severity(a: dict, caveat: str) -> str:
    lag = a["lag"]
    total = lag["total"] or 0
    colours = {"CRITICAL": "var(--crit)", "HIGH": "var(--red)", "MEDIUM": "var(--amber)", "LOW": "var(--green)",
               "UNKNOWN": "var(--grey)"}
    body = []
    if total:
        body.append(f'<div class="bar" title="{total} findings">')
        for s in SEVERITIES:
            n = lag["by_severity"].get(s, 0)
            if n:
                body.append(f'<span style="width:{100 * n / total:.2f}%;background:{colours[s]}"></span>')
        body.append('</div><div class="legend">')
        body += [f'<span><span class="dot" style="background:{colours[s]}"></span>{_e(s.title())} '
                 f'{lag["by_severity"].get(s, 0)}</span>' for s in SEVERITIES]
        body.append("</div>")
    rows, rcls = [], []
    for s in SEVERITIES:
        before = lag["fix_available_at_release_by_severity"].get(s, 0)
        tone = ("r" if s in ("CRITICAL", "HIGH") else "a") if before else ""
        rows.append([_pill(s), lag["by_severity"].get(s, 0), lag["with_fix_by_severity"].get(s, 0), (before, tone)])
        rcls.append({"CRITICAL": "row-crit", "HIGH": "row-high", "MEDIUM": "row-med"}.get(s, ""))
    rows.append([Raw("<b>Total</b>"), Raw(f"<b>{total}</b>"), Raw(f"<b>{lag['with_fix']}</b>"),
                 Raw(f"<b>{lag['fix_available_at_release']}</b>")])
    rcls.append("")
    body.append(_table(["Severity", "Findings", "Fix exists upstream", "Fix existed before release"], rows,
                       {1, 2, 3}, rcls))
    body.append(_note(caveat))
    return _section("Findings by severity", "".join(body))


def _driver_item(e: dict) -> str:
    where = ("found only by Grype from a binary" if e["sources"] == ["grype"] and e["pkg_type"] in ("binary", "")
             else ", ".join(e["sources"]))
    epss = f", EPSS {e['epss']:.2f}" if e.get("epss") is not None else ""
    return f"<li>{_pill(e['severity'])} {_code(e['id'])} in {_code(e['package'])}{_e(epss)} ({_e(where)})</li>"


def _likelihood(a: dict, heuristic_note: str) -> str:
    lk, lag, health = a.get("likelihood"), a["lag"], a["health"]
    if not lk:
        return ""
    tone = tone_level(lk["level"])
    scale = "".join(f'<i class="{"on " + tone_level(i) if i <= lk["level"] else ""}"></i>' for i in range(1, 6))
    text = (f"{lk['reason']}. " + ("Custom rules were used." if lk.get("custom_config") else "Default rules were used.")
            + f" Confidence: {lk.get('confidence', 'normal')}.")
    body = [f'<div class="likely"><div><div class="score {tone}"><b>{lk["level"]}</b><small>{_e(lk["label"])}'
            f'</small></div><div class="scale" aria-label="{lk["level"]} of 5">{scale}</div></div>'
            f'<div class="why"><div>{_e(text)}</div>']
    if lk.get("confidence_reasons"):
        body.append(_note("Treat a low level as 'not enough evidence', not 'low risk': "
                          + "; ".join(lk["confidence_reasons"]) + "."))
    for key, label in (("kev_findings", "Known exploited (CISA KEV)"),
                       ("weaponised_findings", "Ready-to-use exploit: Metasploit or Nuclei"),
                       ("top_epss_findings", "Highest EPSS")):
        if lag.get(key):
            body.append(f'<div class="sub"><b>Driven by ({_e(label)}):</b></div><ul>'
                        + "".join(_driver_item(e) for e in lag[key]) + "</ul>")
    if health.get("scanned_is_latest") is False:
        body.append(_note("The scanned release is not the project's latest (newer: "
                          + ", ".join(health.get("newer_stable_releases", [])[:5])
                          + "). The unshipped metric only applies to a latest release, so the main question is "
                            "whether to adopt a newer version; assess that version too."))
    body.append(_note("Check these components first; they may not be the project's own code. " + heuristic_note))
    body.append("</div></div>")
    return _section("Likelihood suggestion (heuristic)", "".join(body))


def _lag(a: dict, lag_note: str) -> str:
    lag = a["lag"]
    g = lag["grace_days"]
    rows = [_metric("Findings with an upstream fix", lag["with_fix"]),
            _metric("Fix publication date found", f"{lag['fix_date_known']} (unknown: {lag['fix_date_unknown']})",
                    "a" if lag["fix_date_unknown"] else ""),
            _metric(f"Fix existed at least {g} days before the release (not shipped)", lag["fix_available_at_release"],
                    _count_tone(lag["fix_available_at_release"], "r")),
            _metric(f"Fix published within {g} days before the release (not counted)", lag["fix_within_grace"],
                    "a" if lag["fix_within_grace"] else "")]
    if lag.get("scanned_is_latest") is False:
        rows.append(_metric(f"Fix public {lag['unshipped_days']}+ days with no newer release (unshipped)",
                            "n/a (scanned release is not the latest)"))
    elif lag["unshipped"] is not None:
        us = lag["unshipped_by_severity"]
        rows.append(_metric(f"Fix public {lag['unshipped_days']}+ days with no newer release (unshipped)",
                            f"{lag['unshipped']} (critical {us['CRITICAL']}, high {us['HIGH']})",
                            _count_tone(lag["unshipped"], "r")))
    rows += [_metric("Likely already fixed (build label mismatch)", lag["likely_fixed_label_match"]),
             _metric("Kernel CVEs on kernel header packages (excluded: containers use the host kernel)",
                     lag.get("excluded_kernel_headers", 0)),
             _metric("Fix published after the release", lag["fix_after_release"]),
             _metric("CVE published before the release (secondary)", lag["cve_published_before_release"])]
    med, mx = lag["median_days_fix_available"], lag["max_days_fix_available"]
    rows.append(_metric("Median days a fix has been available", "n/a" if med is None else med,
                        tone_days(None if med is None else int(med))))
    rows.append(_metric("Longest days a fix has been available", "n/a" if mx is None else mx, tone_days(mx)))
    o = lag.get("oldest_available_fix")
    if o:
        rows.append(_metric("Oldest available fix", Raw(f"{_code(o['id'])} in {_code(o['package'])}: "
                                                        f"{_e(str(o['fix_version']))} published "
                                                        f"{_e(str(o['fix_published']))} ({o['days']} days)"),
                            "", html_value=True))
    rows.append(_metric("Known exploited (CISA KEV) with fix", lag["kev_with_fix"],
                        "r" if lag["kev_with_fix"] else "g"))
    if lag.get("exploits_checked"):
        by = lag["exploit_with_fix_by_level"]
        rows.append(_metric("With fix and a ready-to-use exploit (Metasploit or Nuclei)", by["weaponised"],
                            "r" if by["weaponised"] else "g"))
        rows.append(_metric("With fix and a published exploit (Exploit-DB)", by["public"],
                            "a" if by["public"] else "g"))
        rows.append(_metric("With fix and only GitHub proofs of concept", by["poc"]))
    if lag.get("epss_scored"):
        m = lag.get("max_epss_with_fix")
        rows.append(_metric("Highest EPSS among findings with a fix (30-day exploitation probability)",
                            "n/a" if m is None else f"{m:.3f}", tone_epss(m)))
    return _section("Release lag", _table(["Metric", "Value"], rows, {1}) + _note(lag_note))


def _yes_no(v: object) -> str:
    return {True: "yes", False: "no"}.get(v, "n/a")


def _health(a: dict) -> str:
    health, sc = a["health"], a["scorecard"]
    lr = health.get("latest_release") or {}
    days, med = health.get("days_since_latest_release"), health.get("median_days_between_releases")
    if days is None:
        t_days = ""
    elif days > 365 or (med and days > 2 * med):
        t_days = "r"
    elif med and days > med:
        t_days = "a"
    else:
        t_days = "g"
    n365 = health.get("releases_last_365d")
    push = health.get("days_since_push")
    rows = [["Latest release", (lr.get("tag") or "n/a") + (f" ({lr['date'][:10]})" if lr.get("date") else "")],
            _metric("Days since latest release", "n/a" if days is None else days, t_days),
            _metric("Stable releases in last 365 days", "n/a" if n365 is None else n365,
                    "" if n365 is None else "g" if n365 >= 2 else "a" if n365 == 1 else "r"),
            ["Median days between releases", "n/a" if med is None else med],
            _metric("Scanned release is latest", _yes_no(health.get("scanned_is_latest")),
                    {True: "g", False: "a"}.get(health.get("scanned_is_latest"), "")),
            _metric("Archived", _yes_no(health.get("archived")),
                    {True: "r", False: "g"}.get(health.get("archived"), "")),
            _metric("Days since last push", "n/a" if push is None else push,
                    "" if push is None else "g" if push < 90 else "a" if push < 365 else "r")]
    if sc.get("status") == "ok":
        rows.append(_metric("OpenSSF Scorecard", f"{sc.get('score')} / 10 ({sc.get('date')})",
                            tone_scorecard(sc.get("score"))))
        if sc.get("low_checks"):
            rows.append([Raw(_dot("r") + "Scorecard checks scoring 0 to 3"), ", ".join(sc["low_checks"])])
    else:
        rows.append(["OpenSSF Scorecard", sc.get("note") or sc.get("status", "n/a")])
    return _section("Project health", _table(["Signal", "Value"], rows))


def _ci(a: dict) -> str:
    wf = a["health"].get("workflows") or {}
    if wf.get("status") in ("none", "error"):
        return _section("Project CI hygiene (GitHub Actions)", _note(wf.get("note", "")))
    if wf.get("status") != "ok":
        return ""
    pin = wf["pinned_percent"]
    files = str(wf["files"]) + (f" ({wf['files_skipped']} more not checked)" if wf["files_skipped"] else "")

    def listed(xs: list[str], tone: str) -> tuple:
        return (Raw(", ".join(str(_code(x)) for x in xs)), tone) if xs else ("none", "g")

    rows = [["Workflow files checked", files], ["Action references", wf["uses_total"]],
            _metric("Pinned to a full commit SHA", "n/a" if pin is None else f"{pin}%",
                    "" if pin is None else "g" if pin == 100 else "a" if pin >= 50 else "r"),
            [Raw(_dot("r" if wf["known_bad"] else "g") + "Known-bad action versions"),
             (len(wf["known_bad"]), "r") if wf["known_bad"] else ("none", "g")]]
    for label, key, tone in (("Files without a top-level permissions block", "no_top_level_permissions", "a"),
                             ("Files granting write-all", "write_all", "r"),
                             ("Files using pull_request_target", "pull_request_target", "n"),
                             ("pull_request_target that also checks out PR code", "pull_request_target_pr_code", "r")):
        v = listed(wf.get(key, []), tone)
        rows.append([Raw(_dot(v[1]) + _e(label)), v])
    body = _table(["Check", "Result"], rows)
    for kb in wf["known_bad"]:
        body += _note(f"{kb['file']}: {kb['uses']} ({kb['reference']}). {kb['note']}")
    body += _note("pull_request_target on its own is the usual, safe way to label or comment on pull requests; it "
                  "becomes a risk when the same workflow checks out and runs the pull request's code. "
                  "These checks describe how exposed the project's own releases are to tampering in CI. "
                  "They do not change the likelihood suggestion.")
    return _section("Project CI hygiene (GitHub Actions)", body)


def _coverage(a: dict) -> str:
    cov = a.get("coverage") or []
    if not cov:
        return ""
    rows = [[c["ecosystem"], c["with_fix"], c["dated"], (f"{c['percent']}%", tone_coverage(c["percent"])),
             ", ".join(f"{k} {v}" for k, v in c["sources"].items()) or "none", c["gap"]] for c in cov]
    headers = ["Ecosystem", "With fix", "Dated", "Coverage", "Date sources", "Why not dated"]
    if not any(c["gap"] for c in cov):
        rows, headers = [r[:5] for r in rows], headers[:5]
    return _section("Fix date coverage", _table(headers, rows, {1, 2, 3}) + _note(
        "Release-lag numbers only count dated findings. Where coverage is low, the lag metrics and the likelihood "
        "suggestion understate what the scanners found for that ecosystem."))


def _agreement(a: dict) -> str:
    ag = a.get("agreement") or {}
    if len(ag.get("enabled", [])) <= 1:
        return ""
    rows = [[s, ag["by_source"].get(s, 0), (ag["only"].get(s, 0), "a" if ag["only"].get(s, 0) else "")]
            for s in ag["enabled"]]
    rows.append([Raw("<b>All sources</b>"), Raw(f"<b>{ag.get('all_enabled', 0)}</b>"), ""])
    return _section("Source agreement", _table(["Source", "Findings seen", "Seen only by this source"], rows, {1, 2})
                    + _note("Trivy and Grype detect packages independently. OSV is queried with the package list "
                            "from Trivy, so it is an independent database check, not an independent detector. "
                            "Single-source findings deserve a closer look rather than automatic dismissal."))


def _scope(a: dict) -> str:
    inp, lag, health = a["inputs"], a["lag"], a["health"]
    from .report import release_used

    rel = release_used(lag, health)
    target = (["Artifact", Raw(f"{_code(inp['path'])} ({_e(str(inp.get('path_kind')))})")] if inp.get("path")
              else ["Image", _code(inp["image"]) if inp.get("image") else "n/a"])
    rows = [target,
            ["Repository", _code(inp["repo"]) if inp.get("repo") else "n/a"],
            ["Release used for lag", rel], ["Assessment date", a["as_of"][:10]]]
    for name, s in a["scanners"].items():
        if not s.get("enabled"):
            continue
        detail = _e(str(s.get("version") or s.get("detail") or ""))
        if s.get("db_updated"):
            detail += f", DB {_e(str(s['db_updated'])[:10])}"
        if "hash_verified" in s:
            detail += (', <span class="g">hash verified</span>' if s["hash_verified"]
                       else ', <span class="a">hash NOT verified</span>')
        rows.append([f"Source: {name}", Raw(detail)])
    return _section("Scope", _table(["Item", "Value"], rows))


def _top(findings: list[Finding], top: int) -> str:
    ranked = sorted(findings, key=rank_key)[:top]
    if not ranked:
        return ""
    rows, rcls = [], []
    for f in ranked:
        if f.likely_fixed:
            before = ("likely fixed", "")
        elif f.excluded:
            before = ("excluded", "")
        elif not f.has_fix:
            before = ("no fix", "")
        else:
            before = ({True: ("yes", "r"), False: ("no", "")}.get(f.fix_available_at_release, ("unknown", "")))
        if f.cvss is None:
            cvss = ("n/a", "muted")
        else:
            tip = "CVSS " + (f.cvss_version or "version unknown") + (f" from {f.cvss_source}" if f.cvss_source else "")
            v4 = '<small class="v4"> v4</small>' if f.cvss_version.startswith("4") else ""
            cvss = (Raw(f'<span title="{_e(tip)}">{f.cvss:.1f}</span>{v4}'), tone_cvss(f.cvss))
        days = f.days_fix_available
        vid = Raw(_e(f.vuln_id) + (f' <span class="cond" title="{_e(f.conditions)}">if</span>' if f.conditions else ""))
        sev_cvss = Raw(f'<span class="nw">{_pill(f.severity)} {_cell(cvss[0])}</span>')
        rows.append([_group_pill(f.triage_group, f.triage_reason), (vid, "mono nw"), (sev_cvss, cvss[1]),
                     _exploit_pill(f), (f.package, "mono"),
                     (f.installed, "mono"),
                     (f.fix_version_used or ";".join(f.fixed_versions) or "none", "mono"), before,
                     ("n/a" if days is None else days, tone_days(days))])
        rcls.append({"CRITICAL": "row-crit", "HIGH": "row-high", "MEDIUM": "row-med"}.get(f.severity, ""))
    legend = ('<div class="legend"><span>Days fix available:</span><span><span class="dot r"></span>90+ days</span>'
              '<span><span class="dot a"></span>30 to 89 days</span><span><span class="dot g"></span>under 30 days'
              '</span><span>Before release: "yes" means the fix existed but was not shipped</span>'
              '<span>CVSS: highest v3.x score across sources; hover for version and source; '
              '"v4" marks a v4 score used because no v3 score exists</span>'
              '<span><span class="cond">if</span> the advisory says it applies only under conditions; hover to read '
              'them</span></div>')
    return _section(f"Top {len(rows)} findings", legend + _table(
        ["Group", "ID", "Severity, CVSS", "Exploit", "Package", "Installed", "Fix", "Before release",
         "Days available"],
        rows, {8}, rcls) + _note("Exploit: the strongest public evidence found. Weaponised = a Metasploit module "
                                    "or Nuclei template; public = Exploit-DB; proof of concept = GitHub repositories "
                                    "only (noisy: some are fake, malicious or not exploits at all, so open the "
                                    "repositories listed on hover or in findings.csv). 'None indexed' means "
                                    "none was found in these sources, not that none exists.")
        + _note("Full list, with every CVSS score, EPSS value, exploit reference and advisory condition: "
                "findings.csv"), "top")


_GROUP_PILL = {"act": "p-crit", "review": "p-high", "conditions": "p-med", "routine": "p-unk", "aside": "p-low"}


def _group_pill(group: str, reason: str = "") -> object:
    if group not in _GROUP_PILL:
        return ""
    tip = f' title="{_e(reason)}"' if reason else ""
    return Raw(f'<span class="pill {_GROUP_PILL[group]}"{tip}>{_e(TRIAGE_LABEL[group])}</span>')


def _triage(a: dict) -> str:
    t = a.get("triage") or {}
    if not t.get("groups"):
        return ""
    rows = [[_group_pill(g), t["groups"][g]["total"], t["groups"][g]["with_fix"], TRIAGE_MEANING[g]]
            for g in TRIAGE_ORDER]
    body = _table(["Group", "Findings", "With fix", "Meaning"], rows, {1, 2})
    body += _note("A suggested reading order, not a risk rating. No group, 'Set aside' included, says a finding "
                  "carries no risk; 'Set aside' is used only where the tool has evidence. Hover a group in the "
                  "findings table for its reason; "
                  "record the assessor's decisions in the triage columns of findings.csv.")
    if not t.get("exploits_checked"):
        body += _note("Exploit sources were not checked (--no-exploits or --offline), so 'Act now' can only come "
                      "from CISA KEV.")
    return _section("Suggested triage", body)


_EXPLOIT_PILL = {"kev": ("p-crit", "KEV"), "weaponised": ("p-high", "weaponised"), "public": ("p-med", "public"),
                 "poc": ("p-unk", "PoC only")}


def _exploit_pill(f: Finding) -> object:
    if f.exploit_level in _EXPLOIT_PILL:
        cls, text = _EXPLOIT_PILL[f.exploit_level]
        tip = "; ".join(f.exploit_refs[:4])
        return Raw(f'<span class="pill {cls}" title="{_e(tip)}">{_e(text)}</span>')
    text = {"none": "none indexed", "nocve": "no CVE ID"}.get(f.exploit_level, "not checked")
    return (text, "muted")


def write(path: Path, a: dict, findings: list[Finding], top: int, caveat: str, heuristic_note: str,
          lag_note: str) -> None:
    title = _title(a) or "assessment"
    lk = a.get("likelihood")
    accent = tone_level(lk["level"]) if lk else "n"
    parts = ['<!doctype html><html lang="en"><head><meta charset="utf-8">',
             '<meta name="viewport" content="width=device-width, initial-scale=1">',
             f"<title>OSS intake: {_e(title)}</title><style>{CSS}</style></head><body><div class=\"page\">",
             f'<header class="{accent}"><h1>OSS intake assessment: <span class="img">{_e(title)}</span></h1>'
             f'<div class="meta">Generated by oss-intake {_e(a["tool"]["version"])} on {_e(a["generated_at"][:19])}Z'
             f' · Assessment date {_e(a["as_of"][:10])}</div></header>',
             _tiles(a), _severity(a, caveat), _triage(a), _likelihood(a, heuristic_note), _lag(a, lag_note),
             f'<div class="grid2">{_health(a)}{_ci(a)}</div>',
             f'<div class="grid2">{_coverage(a)}{_agreement(a)}</div>',
             _scope(a), _top(findings, top)]
    if a.get("warnings"):
        parts.append(_section("Warnings", "<ul>" + "".join(f"<li>{_e(str(w))}</li>" for w in a["warnings"])
                              + "</ul>", "warn"))
    parts.append(f'<footer>oss-intake {_e(a["tool"]["version"])} · {_e(title)}</footer></div></body></html>')
    path.write_text("".join(parts), encoding="utf-8")


CSS = """
:root{--bg:#f5f7fa;--card:#fff;--fg:#1b1f24;--muted:#57606a;--line:#d8dee4;--head:#eef1f4;--accent:#0b5cad;
--crit:#7a0b16;--crit-bg:#fbe3e6;--red:#c62828;--red-bg:#fdecea;--amber:#b26a00;--amber-bg:#fff4e0;
--green:#1e7b34;--green-bg:#e6f4ea;--grey:#6b7280;--grey-bg:#eef0f3;--on-crit:#fff}
@media (prefers-color-scheme: dark){:root:not([data-theme="light"]){--bg:#0d1117;--card:#161b22;--fg:#e6edf3;
--muted:#9da7b3;--line:#30363d;--head:#1c232c;--accent:#58a6ff;--crit:#ff8a95;--crit-bg:#3d0f15;--red:#ff7b72;
--red-bg:#3a1714;--amber:#f0b44c;--amber-bg:#3a2a0c;--green:#56d364;--green-bg:#12301b;--grey:#9da7b3;
--grey-bg:#21262d;--on-crit:#2a0a0e}}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;margin:0}
.page{max-width:1120px;margin:0 auto;padding:28px 16px 48px}
header{border-left:6px solid var(--grey);background:var(--card);border-radius:10px;padding:18px 20px;
box-shadow:0 1px 2px rgba(0,0,0,.06)}
header.g{border-left-color:var(--green)}header.a{border-left-color:var(--amber)}
header.r{border-left-color:var(--red)}header.c{border-left-color:var(--crit)}
h1{font-size:1.45rem;margin:0 0 4px;word-break:break-word}
h1 .img,code,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
h1 .img{font-weight:600}code,td.mono{font-size:.85em}
.meta{color:var(--muted);font-size:.85rem}
h2{font-size:1.1rem;margin:0 0 10px;color:var(--accent)}
section{background:var(--card);border-radius:10px;padding:18px 20px;margin-top:18px;
box-shadow:0 1px 2px rgba(0,0,0,.06);min-width:0}
p.note{color:var(--muted);font-size:.88rem;max-width:90ch;margin:10px 0 0}
.wrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:.9rem}
th,td{border-bottom:1px solid var(--line);padding:7px 10px;text-align:left;vertical-align:top}
th{background:var(--head);font-weight:600;white-space:nowrap}
td{font-variant-numeric:tabular-nums}td.num,th.num{text-align:right}
tbody tr:hover{background:var(--head)}
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:18px}
.tile{background:var(--card);border-radius:10px;padding:14px 16px;border-top:5px solid var(--grey);
box-shadow:0 1px 2px rgba(0,0,0,.06)}
.tile .k{font-size:.78rem;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
.tile .v{font-size:1.7rem;font-weight:700;line-height:1.2;margin-top:2px}
.tile .v .of{font-size:1rem}.tile .s{font-size:.8rem;color:var(--muted)}
.tile.c{border-top-color:var(--crit)}.tile.c .v{color:var(--crit)}
.tile.r{border-top-color:var(--red)}.tile.r .v{color:var(--red)}
.tile.a{border-top-color:var(--amber)}.tile.a .v{color:var(--amber)}
.tile.g{border-top-color:var(--green)}.tile.g .v{color:var(--green)}
.pill{display:inline-block;padding:1px 9px;border-radius:999px;font-size:.75rem;font-weight:700;
letter-spacing:.03em;white-space:nowrap}
.p-crit{background:var(--crit);color:var(--on-crit)}td.nw{white-space:nowrap}
.p-high{background:var(--red-bg);color:var(--red);border:1px solid var(--red)}
.p-med{background:var(--amber-bg);color:var(--amber);border:1px solid var(--amber)}
.p-low{background:var(--green-bg);color:var(--green);border:1px solid var(--green)}
.p-unk{background:var(--grey-bg);color:var(--grey);border:1px solid var(--grey)}
td.c,span.c{color:var(--crit);font-weight:700}td.r,span.r{color:var(--red);font-weight:600}
td.a,span.a{color:var(--amber);font-weight:600}td.g,span.g{color:var(--green);font-weight:600}
td.muted{color:var(--muted);font-size:.85em}span.nw{white-space:nowrap}
section.top table{font-size:.85rem}
section.top th{white-space:normal;vertical-align:bottom}section.top th,section.top td{padding:7px 8px}
.cond{display:inline-block;margin-left:4px;padding:0 5px;border:1px solid var(--line);border-radius:4px;
font-size:.72em;color:var(--muted);font-family:system-ui,sans-serif;cursor:help}small.v4{font-size:.7em;font-weight:600;color:var(--muted)}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px;vertical-align:middle}
.dot.c{background:var(--crit)}.dot.r{background:var(--red)}.dot.a{background:var(--amber)}
.dot.g{background:var(--green)}.dot.n{background:var(--grey)}
tr.row-crit td:first-child{box-shadow:inset 4px 0 0 var(--crit)}
tr.row-high td:first-child{box-shadow:inset 4px 0 0 var(--red)}
tr.row-med td:first-child{box-shadow:inset 4px 0 0 var(--amber)}
.bar{display:flex;height:16px;border-radius:8px;overflow:hidden;margin:4px 0 12px;background:var(--grey-bg)}
.bar span{display:block}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:.82rem;color:var(--muted);margin-bottom:12px}
.likely{display:flex;gap:16px;align-items:flex-start;flex-wrap:wrap}.why{flex:1;min-width:240px}
.sub{margin-top:8px}
.score{width:104px;padding:0 6px;text-align:center;height:92px;border-radius:12px;display:flex;
flex-direction:column;align-items:center;
justify-content:center;background:var(--grey-bg);border:2px solid var(--grey);color:var(--grey)}
.score b{font-size:2.2rem;line-height:1}.score small{font-size:.78rem;font-weight:600}
.score.g{background:var(--green-bg);border-color:var(--green);color:var(--green)}
.score.a{background:var(--amber-bg);border-color:var(--amber);color:var(--amber)}
.score.r{background:var(--red-bg);border-color:var(--red);color:var(--red)}
.score.c{background:var(--crit-bg);border-color:var(--crit);color:var(--crit)}
.scale{display:flex;gap:4px;margin-top:8px;width:104px}
.scale i{display:block;flex:1;min-width:14px;height:8px;border-radius:4px;background:var(--grey-bg)}
.scale i.on.g{background:var(--green)}.scale i.on.a{background:var(--amber)}
.scale i.on.r{background:var(--red)}.scale i.on.c{background:var(--crit)}
.likely ul{margin:6px 0 0;padding-left:20px}.likely li{margin:3px 0}
.grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:18px;margin-top:18px}
.grid2 section{margin-top:0}
.warn{border-left:5px solid var(--amber)}.warn ul{margin:0;padding-left:20px}
footer{color:var(--muted);font-size:.8rem;margin-top:24px;text-align:center}
@media (max-width:480px){.grid2{grid-template-columns:1fr}}
@media print{body{background:#fff}section,header,.tile{box-shadow:none;border:1px solid #ccc}
tbody tr:hover{background:none}}
"""
