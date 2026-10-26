"""One-page executive summary of a package inventory scan (executive-summary.html).

For someone who will not read the findings: how much open source is in use, how much of it needs action and who
owns it, what upgrading would change, and (with --decisions pointing at the previous findings.csv) what changed
since the last run. Every number links back to packages.csv and findings.csv for the detail.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from .models import Finding, parse_datetime
from .report_html import CSS, Raw, _e, _group_pill, _note, _section, _table

STALE_DAYS = 365
TOP = 10


def _n(count: int, one: str, many: str) -> str:
    """'1 package needs' / '3 packages need'."""
    return f"{count} {one if count == 1 else many}"


def _ids(f: Finding) -> set[str]:
    return {i.upper() if i.upper().startswith(("CVE-", "GHSA-", "MAL-")) else i for i in {f.vuln_id, *f.aliases}}


def compute(rows: list[dict], findings: list[Finding], as_of: datetime,
            previous: set[tuple[str, str]] | None) -> dict:
    stale = []
    for r in rows:
        published = parse_datetime(r.get("latest_published") or "")
        if published and (as_of - published).days > STALE_DAYS:
            stale.append(r)

    def after(key: str) -> tuple[int, int]:
        total = crit = 0
        for r in rows:
            left = r.get(key)
            if r["malicious"]:
                continue  # removed
            if left is not None:
                total, crit = total + left["total"], crit + left["critical"]
            else:
                total, crit = total + r["findings"], crit + r["critical"]
        return total, crit

    upgrade_checked = any(r.get("upgrade_left") is not None for r in rows)
    latest_checked = any(r.get("latest") for r in rows)
    out = {
        "packages": len(rows),
        "with_findings": sum(1 for r in rows if r["findings"]),
        "act_now": sum(1 for r in rows if r["group_key"] == "act"),
        "malicious": sum(1 for r in rows if r["malicious"]),
        "kev": sum(1 for r in rows if r["kev"]),
        "with_critical": sum(1 for r in rows if r["critical"]),
        "stale": len(stale) if latest_checked else None,
        "stale_packages": [f"{r['package']} (latest {r['latest']}, {r['latest_published'][:10]})" for r in stale],
        "now": (sum(r["findings"] for r in rows), sum(r["critical"] for r in rows)),
        "at_fix": after("upgrade_left") if upgrade_checked else None,
        "at_latest": after("latest_left") if latest_checked else None,
        "fix_clears_all": sum(1 for r in rows if (r.get("upgrade_left") or {}).get("total") == 0),
        "previous": None,
    }
    if previous is not None:
        current = {(i, f.package.lower()) for f in findings for i in _ids(f)}
        new = [f for f in findings if not any((i, f.package.lower()) in previous for i in _ids(f))]
        current_primary = {(f.vuln_id.upper() if f.vuln_id.upper().startswith(("CVE-", "GHSA-", "MAL-"))
                            else f.vuln_id, f.package.lower()) for f in findings}
        resolved = {k for k in previous if k not in current and k not in current_primary}
        out["previous"] = {"new": len(new), "resolved": len(resolved),
                           "new_act": sum(1 for f in new if f.triage_group == "act"),
                           "new_list": [f"{f.vuln_id} in {f.package} {f.installed}" for f in
                                        sorted(new, key=lambda f: (f.triage_group != "act", f.vuln_id))[:8]]}
    owners: dict[str, dict] = {}
    label_key = next((k for k in ("owner", "team", "system", "application") if any(k in r["labels"] for r in rows)),
                     None)
    if label_key:
        for r in rows:
            o = owners.setdefault(r["labels"].get(label_key) or "(none)",
                                  {"packages": 0, "act_now": 0, "with_findings": 0})
            o["packages"] += 1
            o["with_findings"] += bool(r["findings"])
            o["act_now"] += r["group_key"] == "act"
    out["owner_column"], out["owners"] = label_key, owners
    return out


def _action(r: dict) -> str:
    if r["malicious"]:
        return "remove: malicious release" + (f"; latest {r['latest']}" if r.get("latest") else "")
    if r["upgrade_to"]:
        left = r.get("upgrade_left")
        extra = "" if left is None else (" (clears all known)" if left["total"] == 0 else
                                         f" ({left['total']} known remain)")
        return f"upgrade to {r['upgrade_to']}{extra}" + (" · major" if r.get("upgrade_major") else "")
    if r["no_fix"]:
        return "no fix listed: mitigate or replace"
    return ""


def _why(r: dict) -> str:
    parts = []
    if r["malicious"]:
        parts.append("malicious release")
    if r["kev"]:
        parts.append(f"{r['kev']} known exploited")
    if r["critical"]:
        parts.append(f"{r['critical']} critical")
    if r["high"]:
        parts.append(f"{r['high']} high")
    return ", ".join(parts) or _n(r["findings"], "finding", "findings")


def write(path: Path, a: dict, rows: list[dict], s: dict) -> None:
    from .inventory_report import label_text

    title = Path(a["inputs"].get("path") or "inventory").name
    lead = (f"{_n(s['packages'], 'open source package', 'open source packages')} checked. "
            + _n(s["act_now"], "needs", "need") + " action now"
            + (f" ({s['malicious']} malicious)" if s["malicious"] else "")
            + ", " + _n(s["with_critical"], "has", "have") + " critical vulnerabilities"
            + (", and " + _n(s["stale"], "has", "have") + " had no release for over a year"
               if s["stale"] is not None else "") + ".")
    tiles = [("c" if s["act_now"] else "g", "Act now", s["act_now"], "malicious or known exploited"),
             ("c" if s["malicious"] else "g", "Malicious", s["malicious"], "remove, do not patch"),
             ("r" if s["with_critical"] else "g", "With critical", s["with_critical"],
              "package" if s["with_critical"] == 1 else "packages"),
             ("a" if s["stale"] else "g", "No release in a year", "n/a" if s["stale"] is None else s["stale"],
              "possibly unmaintained"),
             ("n", "Packages checked", s["packages"], f"{s['with_findings']} with findings")]
    tile_html = '<div class="tiles">' + "".join(
        f'<div class="tile {t}"><div class="k">{_e(k)}</div><div class="v">{_e(str(v))}</div>'
        f'<div class="s">{_e(sub)}</div></div>' for t, k, v, sub in tiles) + "</div>"
    parts = [f'<!doctype html><html lang="en"><head><meta charset="utf-8">'
             f'<meta name="viewport" content="width=device-width, initial-scale=1">'
             f"<title>Open source risk summary: {_e(title)}</title><style>{CSS}</style></head><body>"
             f'<div class="page"><header class="{"c" if s["act_now"] else "a" if s["with_findings"] else "g"}">'
             f"<h1>Open source risk summary</h1><div class=\"meta\">{_e(title)} · assessed {_e(a['as_of'][:10])}"
             f" · oss-intake {_e(a['tool']['version'])}</div></header>",
             tile_html, _section("In one line", f"<p>{_e(lead)}</p>")]
    upg = [["Now", s["now"][0], s["now"][1]]]
    if s["at_fix"]:
        upg.append(["After upgrading to the minimum fix versions", *s["at_fix"]])
    if s["at_latest"]:
        upg.append(["After upgrading to the latest releases", *s["at_latest"]])
    if len(upg) > 1:
        parts.append(_section("If the packages are upgraded", _table(
            ["Known vulnerabilities", "Total", "Critical"], upg, num={1, 2})
            + _note(f"The minimum fix clears every known vulnerability for "
                    f"{_n(s['fix_clears_all'], 'package', 'packages')}. "
                    "Malicious releases are counted as removed. Fewer known vulnerabilities is not proof that "
                    "a version is safe, and a major-version upgrade may need code changes.")))
    if s["previous"]:
        p = s["previous"]
        body = _table(["Since the previous run", "Count"],
                      [["New findings", p["new"]], ["of which Act now", p["new_act"]],
                       ["Findings no longer present", p["resolved"]]], num={1})
        if p["new_list"]:
            body += _note("New: " + "; ".join(p["new_list"]) + (" ..." if p["new"] > len(p["new_list"]) else ""))
        parts.append(_section("What changed", body))
    flagged = [r for r in rows if r["findings"]][:TOP]
    if flagged:
        trows = [[_group_pill(r["group_key"]), Raw(f'<span class="mono">{_e(r["package"])}</span> '
                                                   f'<span class="mono">{_e(r["version"])}</span>'),
                  _why(r), _action(r), label_text(r["labels"])] for r in flagged]
        parts.append(_section(f"Top {len(flagged)} packages to act on", _table(
            ["Group", "Package", "Why", "Action", "Labels"], trows)))
    if s["owners"]:
        orows = [[k, v["packages"], v["with_findings"], v["act_now"]]
                 for k, v in sorted(s["owners"].items(), key=lambda kv: (-kv[1]["act_now"], -kv[1]["with_findings"],
                                                                         kv[0]))]
        parts.append(_section(f"By {s['owner_column']}", _table(
            [s["owner_column"].capitalize(), "Packages", "With findings", "Act now"], orows, num={1, 2, 3})))
    if s["stale_packages"]:
        parts.append(_section("No release for over a year", _note(
            "; ".join(s["stale_packages"][:15]) + (" ..." if len(s["stale_packages"]) > 15 else "")
            + ". A project with no recent release may be finished, or abandoned; check before relying on it.")))
    parts.append(_section("About these numbers", _note(
        "Scanner results are version matching against public advisory databases (OSV), not proof of "
        "exploitability. Detail for every package is in packages.csv and report.html, and for every finding in "
        "findings.csv, where assessor decisions are recorded and carried to the next run.")))
    parts.append(f'<footer>oss-intake {_e(a["tool"]["version"])} · {_e(title)}</footer></div></body></html>')
    path.write_text("".join(parts), encoding="utf-8")
