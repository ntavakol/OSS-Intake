"""The --fail-on gates: which conditions a run met, and which it could not evaluate.

A gate whose check did not run must never pass: not_evaluated names those, and the run fails with exit 1 rather
than passing. Findings set aside (by evidence or an assessor's decision) do not count, except a malicious package,
which no decision sets aside."""

from __future__ import annotations

from . import checks


def not_evaluated(wanted: list[str], age_info: dict, registry: dict | None, args,
                  check_info: dict | None = None, details_missing: int = 0) -> list[tuple[str, str]]:
    """Gates whose check did not (fully) run: a CI gate must not pass because nothing was looked at."""
    out: list[tuple[str, str]] = []
    for gate in ("critical", "high"):
        if gate in wanted and details_missing:
            out.append((gate, f"advisory details for {details_missing} finding(s) could not be loaded, so their "
                              "severity is unknown"))
    chk = check_info or {}  # state_of treats None and {} alike: every source counts as checked
    # 'act' comes from malicious package data, CISA KEV and the exploit indexes (unless --no-exploits was chosen).
    act_sources = ("malicious", "kev") if args.no_exploits else ("malicious", "kev", "exploits")
    for gate, sources in (("malicious", ("malicious",)), ("kev", ("kev",)), ("act", act_sources)):
        missing = [n for n in sources if checks.state_of(chk, n) != checks.CHECKED]
        if gate in wanted and missing:
            out.append((gate, "; ".join(f"{checks.LABEL[n]} {checks.describe(chk, n)}" for n in missing)))
    ext = getattr(args, "extension_info", None)
    if ext and ext["removed_list"]["status"] != "checked":
        for gate in ("malicious", "act"):
            if gate in wanted and not any(g == gate for g, _ in out):
                out.append((gate, f"the VS Code Marketplace removal list was {ext['removed_list']['detail']}"))
    if "recent" in wanted and age_info.get("status") != "ok" and not age_info.get("recent"):
        out.append(("recent", age_info.get("reason") or f"{age_info.get('errors', 0)} lookups failed, "
                                                         f"{age_info.get('skipped_limit', 0)} over the limit"))
    # A version deps.dev covers but has no date for may be new: one only hours old is often not indexed yet,
    # which is the case --fail-on recent is for, so the gate cannot pass on it (Ned, 7 Nov: option C). A
    # registry deps.dev does not cover at all (RubyGems, CRAN) is left to --fail-on unknown-age, or this gate
    # would fail on every run for those projects.
    elif "recent" in wanted and not age_info.get("recent") and age_info.get("unknown"):
        named = age_info.get("unknown_purls") or []
        more = age_info["unknown"] - len(named)
        out.append(("recent", f"{age_info['unknown']} package version(s) in registries deps.dev covers have no "
                              "release date there yet, as for a release only hours old: "
                              + ", ".join(named) + (f" and {more} more" if more > 0 else "")))
    if "unknown-age" in wanted and age_info.get("status") != "ok" and not unknown_age(age_info):
        out.append(("unknown-age", age_info.get("reason") or f"{age_info.get('errors', 0)} lookups failed, "
                                                              f"{age_info.get('skipped_limit', 0)} over the limit"))
    # Only a match or a mismatch is an answer: a file the registry check cannot read or place, or a version the
    # registry does not have, was not compared, and a gate must not pass on a comparison that did not happen.
    status = str((registry or {}).get("status") or "")
    if "mismatch" in wanted and args.path_kind == "artifact" and status not in ("match", "mismatch"):
        # The registry check's own detail says why (no checksum published, file not in the release, HTTP status);
        # the status alone can mislead, as a registry outage can look like "not published".
        why = {"error": "the registry lookup failed", "not_published": "no matching published file was found",
               "unsupported": "the registry check does not cover this kind of file",
               "unknown": "the file was not compared"}.get(status, "the file was not compared")
        detail = (registry or {}).get("detail")
        out.append(("mismatch", f"{why}{f' ({detail})' if detail else ''}"))
    return out


def unknown_age(age_info: dict) -> bool:
    return bool(age_info.get("unknown_purls") or age_info.get("unsupported_purls"))


def hidden_warnings(args, all_findings: list, shown: list, age_info: dict) -> list[str]:
    """A --fail-on condition met only by findings --min-severity left out of the reports, named so that exit 3
    is never left without a finding to explain it."""
    shown_ids = {id(f) for f in shown}
    hidden = [f for f in all_findings if id(f) not in shown_ids]
    out = []
    for t in args.fail_on_set:
        if t in met([t], all_findings, age_info, None) and t not in met([t], shown, age_info, None):
            names = sorted({f"{f.vuln_id} ({f.package} {f.installed})" for f in hidden
                            if met([t], [f], {}, None)})
            out.append(f"--fail-on {t} is met by {len(names)} finding(s) below --min-severity {args.min_severity}, "
                       "which the reports leave out: " + ", ".join(names[:10])
                       + (f" and {len(names) - 10} more" if len(names) > 10 else ""))
    return out


def met(wanted: list[str], findings: list, age_info: dict, registry: dict | None,
          extensions: dict | None = None, unchecked: int = 0) -> list[str]:
    """The --fail-on conditions met. Findings set aside (evidence or an assessor decision) do not count, except
    a malicious package, which no decision sets aside. An extension the Marketplace removed as malware counts
    as malicious."""
    live = [f for f in findings if f.triage_group != "aside"]
    removed = any(e["malicious"] for e in (extensions or {}).get("extensions", []))
    met = {
        "malicious": removed or any(f.malicious for f in findings),
        "kev": any(f.kev for f in live),
        "act": any(f.triage_group == "act" for f in live),
        "critical": any(f.severity == "CRITICAL" for f in live),
        "high": any(f.severity in ("CRITICAL", "HIGH") for f in live),
        "recent": bool(age_info.get("recent")),
        "unknown-age": unknown_age(age_info),
        "mismatch": bool(registry and registry.get("status") == "mismatch"),
        "unchecked": unchecked > 0,
    }
    return [w for w in wanted if met[w]]
