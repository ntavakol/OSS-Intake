"""Assessing the findings a scan produced, and writing the reports: stages 3 to 5 of a scan.

Merges what every source found, looks up project health, fix dates, KEV, EPSS, exploits and release age, applies
the assessor's decisions, triages, measures release lag and likelihood, writes the reports and decides the exit
code. --min-severity only shortens the reports: the gates and likelihood see every finding."""

from __future__ import annotations

import itertools
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import (
    __version__,
    checks,
    conditions,
    coverage,
    decisions,
    exec_summary,
    gates,
    inputs,
    inventory_report,
    jsonsafe,
    lag,
    likelihood,
    merge,
    reachability,
    release_age,
    report,
    safewrite,
    scanning,
    triage,
    upgrade,
    vscode,
)
from .enrich import (
    advisories,
    alpine,
    debian_releases,
    debian_tracker,
    epss,
    exploits,
    fixdates,
    github_releases,
    golang_stdlib,
    kev,
    packagist,
    redhat,
    ubuntu,
    ubuntu_launchpad,
)
from .health import releases, scorecard, workflows
from .http import HttpError
from .models import SEVERITY_ORDER, parse_datetime
from .options import EXIT_ERROR, EXIT_OK, EXIT_THRESHOLD, FAIL_ON, OUTPUT_FILES, image_tag, log


def shown_path(p: str | Path | None) -> str | None:
    """A local path as the reports give it: under the home folder as ~/..., anywhere else by its name only, so a
    report shared with others does not carry the user's name or folder layout."""
    if not p:
        return None
    path = Path(p).expanduser()
    try:
        return "~/" + path.resolve().relative_to(Path.home().resolve()).as_posix()
    except (ValueError, OSError, RuntimeError):
        return path.name or str(p)


def _target_name(path: str) -> str:
    """The --path target's name: "." and ".." are named by the folder they stand for."""
    p = Path(path).expanduser()
    try:
        return p.resolve().name or str(p)
    except (OSError, RuntimeError):
        return p.name or str(p)


def network_info(net) -> dict:
    """Requests made and cache use, so a slow or fast run can be explained."""
    if net is None:
        return {"status": "offline"}
    out: dict = {"requests": getattr(net, "requests_made", None)}
    cache = getattr(net, "cache", None)
    out["cache"] = {**cache.stats(), "folder": shown_path(cache.folder)} if cache is not None else None
    return out


def assess(args, chosen, out, net, scanners_meta, warnings, groups, trivy_report, scan_info, formats, as_of,
            release_override, lk_cfg):
    """Stages 3 to 5 of a scan, in order: merge, project health, the release date, enrichment, release age,
    decisions, which checks ran, triage and --min-severity, lag and likelihood, the reports, then the exit code.
    warnings is shared by every step and ends up in every report, in the order the steps add to it."""
    findings, reach_stats, flagged, flag_at = _merge(args, groups, warnings)
    enabled = [s for s in ("trivy", "grype", "osv") if scanners_meta[s].get("enabled")]
    health, sc = _health(args, net, as_of, warnings)
    release_date, release_date_source = _release_date(args, findings, health, scan_info, release_override,
                                                      warnings)
    fd_stats, kev_info, epss_info, exploit_info = _enrich(args, net, findings, warnings)
    age_info = _release_age(args, net, trivy_report, as_of, warnings)
    is_latest = health.get("scanned_is_latest") if not release_override else None
    decision_info = _apply_decisions(args, findings, warnings)
    check_info, n_missing_live = _checks(args, findings, kev_info, epss_info, exploit_info, warnings)
    findings, all_findings, triage_info = _shown(args, findings, check_info, age_info, warnings)
    warnings[flag_at:flag_at] = flag_warnings(findings, flagged)
    lag_m, lk = _lag_and_likelihood(args, findings, all_findings, release_date, as_of, is_latest, check_info,
                                    lk_cfg, health, sc, warnings)
    doc, pkg_rows = _document(args, net, findings, all_findings, as_of, scanners_meta, scan_info, enabled,
                              fd_stats, kev_info, epss_info, exploit_info, triage_info, check_info,
                              decision_info, age_info, reach_stats, lag_m, release_date_source, health, sc,
                              lk, warnings)
    written = _write_reports(args, out, formats, doc, findings, all_findings, pkg_rows, decision_info, as_of)
    _remove_stale(args, out, written)
    return _finish(args, out, findings, all_findings, pkg_rows, age_info, check_info, n_missing_live, lag_m, lk,
                   written, warnings)


def _merge(args, groups: list, warnings: list[str]):
    """Merge what every source found; mark malicious packages and flag findings to leave out of lag."""
    findings = merge.merge(*groups)
    reach_stats = reachability.apply(findings, getattr(args, "reach_results", {}) or {},
                                     verified=bool(getattr(args, "govulncheck_sha256", None)))
    for f in findings:
        f.conditions = conditions.extract(f.description)
    # A malicious finding (MAL- entry or CWE-506) on a package version marks every finding on it: GitHub and
    # other advisories for the same malware often do not list the MAL- ID as an alias. Malicious-package
    # entries often carry no severity; they are kept whatever --min-severity says.
    mal_keys = {(f.package, f.installed) for f in findings if f.malicious}
    for f in findings:
        if (f.package, f.installed) in mal_keys:
            f.malicious_package = True
    bad = sorted({f"{f.package}@{f.installed}" for f in findings if f.malicious})
    if bad:
        listed = ", ".join(bad[:10]) + (f" and {len(bad) - 10} more" if len(bad) > 10 else "")
        warnings.insert(0, f"MALICIOUS PACKAGE: {len(bad)} package(s) are listed as malware (OpenSSF malicious "
                           f"packages, or an advisory classed as embedded malicious code, CWE-506): {listed}. "
                           "Treat the artifact as compromised, not as a patching task")
    lag.flag_label_matches(findings)
    if not args.include_kernel_headers:
        lag.flag_kernel_headers(findings)
    lag.flag_no_newer_fix(findings)
    flagged = {"kh": {id(f) for f in findings if f.excluded == "kernel-headers"},
               "older": {id(f) for f in findings if f.note.startswith("No listed fix (")},
               "label": {id(f) for f in findings if f.likely_fixed}}
    flag_at = len(warnings)  # their warnings go here, counted once --min-severity has chosen what is shown
    return findings, reach_stats, flagged, flag_at


def _health(args, net, as_of: datetime, warnings: list[str]):
    """3. Project health: GitHub releases, Scorecard and the project's own workflows."""
    # 3. Project health.
    health: dict = {}
    sc: dict = {"status": "skipped"}
    if args.repo and net:
        try:
            name_tag = (inputs.version_from_name(Path(args.path)) if args.path_kind == "artifact" else None)
            health = releases.fetch(net, args.repo, as_of, image_tag(args.image) if args.image else name_tag,
                                    args.release_tag)
            warnings += health.get("warnings", [])
        except HttpError as exc:
            warnings.append(f"GitHub lookup failed: {exc}")
        if not args.no_scorecard:
            try:
                sc = scorecard.fetch(net, args.repo)
            except HttpError as exc:
                sc = {"status": "error", "note": str(exc)}
        if not args.no_workflows:
            health["workflows"] = workflows.fetch(net, args.repo)
            if health["workflows"].get("status") == "partial":
                warnings.append("Project workflow audit is partial (workflow files checked: "
                                + workflows.files_audited(health["workflows"]) + ")")
            for kb in health["workflows"].get("known_bad", []):
                warnings.append(f"Project workflow {kb['file']} uses {kb['uses']}, a known-bad action version "
                                f"({kb['reference']})")
    elif args.repo:
        warnings.append("--offline: release cadence and Scorecard skipped")
    return health, sc


def _release_date(args, findings: list, health: dict, scan_info: dict, release_override, warnings: list[str]):
    """The date release lag is measured against: --release-date, the matched GitHub release or the image build."""
    release_date = release_override or parse_datetime((health.get("scanned_release") or {}).get("date"))
    release_date_source = "--release-date" if release_override else ("GitHub release" if release_date else None)
    if release_override:
        if not health.get("scanned_release"):
            health["scanned_release"] = {}
        health["scanned_release"]["tag"] = args.release_tag or "(set by --release-date)"
    image_created = parse_datetime(scan_info.get("image_created"))
    if not release_date and image_created and not args.no_image_date:
        # Lag against the build date answers "were fixes available when this image was built and
        # left out?". That is a fair question for an image, but not the same as a project release.
        release_date, release_date_source = image_created, "image build date"
        health["scanned_release"] = {"tag": "(image build date)", "date": image_created.isoformat(),
                                     "matched": False}
        warnings.append(f"No release date from GitHub or --release-date; using the image build date "
                        f"{image_created.date().isoformat()} for release-lag metrics. The unshipped metric "
                        "needs a matched release and stays unavailable. Use --no-image-date to disable.")
    if findings and not release_date:
        if args.repo and args.offline:
            hint = "--offline skips the GitHub lookup; drop --offline or pass --release-date."
        elif args.repo:
            hint = "the GitHub release lookup did not return a date; pass --release-tag or --release-date."
        else:
            hint = "pass --repo, or --release-date."
        if args.path_kind != "inventory":  # an inventory has no single release to compare against
            warnings.append("No release date known, so 'fix existed before release' cannot be computed: " + hint)
    return release_date, release_date_source


def _enrich(args, net, findings: list, warnings: list[str]):
    """4. Enrichment: fix dates, CISA KEV, exploits and EPSS."""
    # 4. Enrichment.
    fd_stats: dict = {}
    kev_info: dict = {"status": "skipped"}
    epss_info: dict = {"status": "skipped"}
    exploit_info: dict = {"status": "skipped"}
    if net and findings:
        # Most severe first: some sources cap their lookups, and --min-severity no longer limits what is looked up.
        ranked = sorted(findings, key=lambda f: -SEVERITY_ORDER[f.severity])
        if not args.no_fix_dates:
            fd_stats = fixdates.enrich(net, ranked)
            if fd_stats.get("errors"):
                warnings.append(f"deps.dev lookups failed for {fd_stats['errors']} package versions")
            deb = debian_tracker.enrich(net, ranked)
            fd_stats["debian_tracker"] = deb
            if deb.get("errors"):
                warnings.append("Debian security tracker lists could not be loaded; Debian fix dates fall back to OSV")
            dpr = debian_releases.enrich(net, ranked)
            fd_stats["debian_point_release"] = dpr
            if dpr.get("errors"):
                warnings.append("Debian point release ChangeLog could not be loaded; point-release fixes stay undated")
            rh = redhat.enrich(net, ranked)
            fd_stats["redhat"] = rh
            if rh.get("errors"):
                warnings.append(f"Red Hat advisory lookups failed for {rh['errors']} advisories; dates may be partial")
            ubu = ubuntu.enrich(net, ranked)
            fd_stats["ubuntu"] = ubu
            ulp = ubuntu_launchpad.enrich(net, ranked)
            if ubu.get("errors"):
                what = ("the OSV package query failed" if ubu.get("query_failed")
                        else f"{ubu['errors']} of {ubu['notices_total']} Ubuntu notice lookups in OSV failed")
                covered = (" Launchpad publishing history was used for the rest." if not ulp.get("errors")
                           else " Some Ubuntu fix dates may be missing.")
                warnings.append(what[0].upper() + what[1:] + "." + covered)
            fd_stats["ubuntu_launchpad"] = ulp
            if ulp.get("errors"):
                warnings.append("Launchpad publishing history lookups failed; some Ubuntu fix dates may be missing")
            if ulp.get("skipped_limit"):
                warnings.append(f"{ulp['skipped_limit']} Ubuntu fix dates skipped to cap Launchpad requests")
            alp = alpine.enrich(net, ranked)
            fd_stats["alpine"] = alp
            if alp.get("skipped_limit"):
                warnings.append(f"{alp['skipped_limit']} Alpine fix dates skipped to stay within GitHub rate limits")
            if alp.get("errors"):
                warnings.append("Alpine aports history lookups failed for some packages (set GITHUB_TOKEN for "
                                "higher GitHub API limits)")
            adv = advisories.enrich(net, ranked)
            fd_stats["advisory"] = adv
            if adv.get("errors"):
                warnings.append(f"OSV advisory lookups failed for {adv['errors']} distro advisories")
            pk = packagist.enrich(net, ranked)
            fd_stats["packagist"] = pk
            if pk.get("errors"):
                warnings.append(f"Packagist lookups failed for {pk['errors']} PHP packages")
            gos = golang_stdlib.enrich(net, ranked)
            fd_stats["go_stdlib"] = gos
            if gos.get("errors"):
                warnings.append("Go release history (go.dev) could not be loaded; Go standard library fixes stay "
                                "undated")
            ghr = github_releases.enrich(net, ranked)
            fd_stats["github_release"] = ghr
            if ghr.get("skipped_limit"):
                warnings.append(f"{ghr['skipped_limit']} Go fix dates skipped to stay within GitHub rate limits; "
                                "set GITHUB_TOKEN to look them all up")
        if not args.no_kev:
            try:
                ids, version = kev.load(net)
                kev_info = {"status": "ok" if ids else "unavailable", "catalog_version": version,
                            "matches": kev.apply(findings, ids)}
                if not ids:
                    warnings.append("CISA KEV catalogue could not be loaded; KEV signals are absent")
            except HttpError as exc:
                kev_info = {"status": "error", "note": str(exc)}
                warnings.append(f"CISA KEV catalogue unavailable: {exc}")
        if not args.no_exploits:
            exploit_info = exploits.enrich(net, ranked)
            if exploit_info["failed"]:
                warnings.append("Exploit sources could not be loaded: " + ", ".join(exploit_info["failed"])
                                + "; exploit levels are partial")
            if exploit_info["poc_skipped"]:
                warnings.append(f"Proof-of-concept lookups capped or failed for {exploit_info['poc_skipped']} "
                                "finding(s); their exploit level is 'not checked'")
        if not args.no_epss:
            epss_info = {"status": "ok", **epss.enrich(net, ranked)}
            if epss_info["errors"]:
                warnings.append(f"EPSS lookups failed for {epss_info['errors']} batch(es); EPSS signals are partial")
    return fd_stats, kev_info, epss_info, exploit_info


def _release_age(args, net, trivy_report: dict | None, as_of: datetime, warnings: list[str]):
    """Which package versions are new (--release-age-days), from their published dates."""
    age_info: dict = {"status": "skipped", "days": args.release_age_days,
                      "reason": "--offline" if not net else "--release-age-days 0", "recent": []}
    purls = scanning.language_purls(args, trivy_report) if net and args.release_age_days else []
    unlisted = (scanning.osv_mod.unlisted_language_results(trivy_report)
                if trivy_report is not None and not (getattr(args, "inventory", None)
                                                     and args.path_kind == "inventory") else [])
    if net and args.release_age_days and not purls and unlisted:
        age_info = {"status": "not checked", "days": args.release_age_days, "recent": [],
                    "reason": f"Trivy listed no packages for {', '.join(unlisted[:3])} (a report made with "
                              "--list-all-pkgs=false?), so no package version could be checked"}
    elif net and args.release_age_days and not purls and trivy_report is not None:
        # The scan ran and found only distro packages: nothing a registry release date applies to.
        age_info = {"status": "ok", "days": args.release_age_days, "recent": [], "checked": 0, "unknown": 0,
                    "unsupported": 0, "errors": 0, "skipped_limit": 0, "published": {}, "unknown_purls": [],
                    "unsupported_purls": [], "unchecked_purls": [], "reason": "no language packages"}
    elif net and args.release_age_days and not purls:
        age_info = {"status": "not checked", "days": args.release_age_days, "recent": [],
                    "reason": "no package list to check (needs a Trivy scan or an inventory)"}
    elif net and args.release_age_days:
        # A date-only --as-of means the whole of that day.
        as_of_end = as_of + timedelta(days=1, seconds=-1) if args.as_of and "T" not in args.as_of else as_of
        age_info = release_age.check(net, purls, as_of_end, args.release_age_days, limit=args.release_age_max,
                                     as_of_given=bool(args.as_of))
        if unlisted and age_info.get("status") == "ok":
            # Trivy did not list what those results contain, so a version only hours old may be among them unseen.
            age_info["status"] = "partial"
            age_info["reason"] = (f"Trivy listed no packages for {', '.join(unlisted[:3])} (a report made with "
                                  "--list-all-pkgs=false?), so only packages with findings were checked")
        age_warning = release_age.warning(age_info)
        if age_warning:
            warnings.append(age_warning)
        if age_info["skipped_limit"]:
            warnings.append(f"Release dates were looked up for the first {args.release_age_max} package versions "
                            f"only; {age_info['skipped_limit']} were not checked for being new")
        if age_info["unknown"]:
            warnings.append(f"{age_info['unknown']} package version(s) have no release date on deps.dev (not "
                            "indexed yet, which is likely for a release only hours old, or not public), so they "
                            "were not checked for being new")
        if age_info["errors"]:
            warnings.append(f"deps.dev release date lookups failed for {age_info['errors']} package version(s), "
                            "so they were not checked for being new")
    return age_info


def _apply_decisions(args, findings: list, warnings: list[str]):
    """The assessor's decisions from an earlier run (--decisions)."""
    decision_info = None
    if args.decision_list is not None:
        decision_info = decisions.apply(findings, args.decision_list)
        if decision_info["ignored_malicious"]:
            warnings.append(f"{decision_info['ignored_malicious']} decision(s) to set aside a malicious package were "
                            "ignored: a malicious package is removed, not accepted")
        if decision_info["stale"]:
            warnings.append(f"{decision_info['stale']} decision(s) were made for a different installed version; they "
                            "still apply but are marked for review")
    return decision_info


def _checks(args, findings: list, kev_info: dict, epss_info: dict, exploit_info: dict, warnings: list[str]):
    """Which sources were checked in full, so a gap never reads as a clean result."""
    skipped_by = {}
    for name, flag in (("kev", "no_kev"), ("exploits", "no_exploits"), ("epss", "no_epss")):
        skipped_by[name] = "--offline" if args.offline else f"--{flag.replace('_', '-')}" if getattr(args, flag) \
            else "not run"
    check_info = checks.compute(len(findings), kev_info, epss_info, exploit_info,
                                getattr(args, "malicious_check", None) or checks.state(checks.CHECKED), skipped_by)
    n_missing = sum(1 for f in findings if f.details_unavailable)
    # Findings an assessor (or evidence) set aside do not count for KEV, EPSS and the severity gates, as in gates.met;
    # whether an advisory is malware still matters, since no decision sets a malicious package aside.
    n_missing_live = sum(1 for f in findings if f.details_unavailable and triage.classify(f)[0] != "aside")
    if n_missing:
        # Their CVE aliases (KEV, EPSS) and CWEs (malware) are unknown, so those checks did not fully run.
        for name, n in (("kev", n_missing_live), ("epss", n_missing_live), ("malicious", n_missing)):
            if n and check_info[name]["state"] == checks.CHECKED:
                check_info[name] = checks.state(checks.PARTIAL, f"advisory details for {n} finding(s) "
                                                                "could not be loaded")
        warnings.append(f"advisory details for {n_missing} finding(s) could not be loaded from OSV, so their "
                        "severity, fix and CVE aliases are unknown; re-run later")
    gap_warning = checks.warning(check_info)
    if gap_warning:
        lead = sum(1 for _ in itertools.takewhile(
            lambda w: w.startswith(("ARTIFACT DOES NOT MATCH", "MALICIOUS PACKAGE")), warnings))
        warnings.insert(lead, gap_warning)  # after the malware and tampering alerts, before everything else
    return check_info, n_missing_live


def _shown(args, findings: list, check_info: dict, age_info: dict, warnings: list[str]):
    """Triage, then --min-severity: (findings the reports show, every finding, triage counts of those shown)."""
    triage_info = triage.apply(findings, check_info)
    # --min-severity only shortens the reports: it is applied once KEV, exploits and triage are known, keeps what
    # needs action or could not be fully checked, and the gates still see every finding (threat model, 6 Nov).
    all_findings = findings
    floor = SEVERITY_ORDER[args.min_severity]
    findings = [f for f in findings if f.malicious or f.triage_group == "act" or f.details_unavailable
                or SEVERITY_ORDER[f.severity] >= floor]
    if len(findings) < len(all_findings):
        triage_info = triage.apply(findings, check_info)  # the counts the reports show
        warnings.extend(gates.hidden_warnings(args, all_findings, findings, age_info))
    return findings, all_findings, triage_info


def _lag_and_likelihood(args, findings: list, all_findings: list, release_date, as_of: datetime, is_latest, check_info:
                        dict, lk_cfg, health: dict, sc: dict, warnings: list[str]):
    """Release lag of the findings shown; likelihood from every finding, as it is a gate too."""
    lag_m = lag.compute(findings, release_date, as_of, args.grace_days, args.unshipped_days, is_latest)
    lag_m["exploits_checked"] = checks.is_checked(check_info, "exploits") and bool(findings)
    # For the likelihood gate: a source that failed (or loaded only in part) leaves its metric unknown, so a rule
    # on it cannot be read as not met. One the user turned off is their choice, already reported: read as before.
    for name in ("kev", "malicious", "epss", "exploits"):
        lag_m[f"{name}_ok"] = (checks.state_of(check_info, name) == checks.CHECKED
                               or checks.turned_off(check_info, name))
    # Likelihood is a gate too (--fail-on-likelihood), so it is worked out from every finding, not only those the
    # reports show.
    lag_all = lag_m
    if lk_cfg and len(findings) < len(all_findings):
        lag_all = lag.compute(all_findings, release_date, as_of, args.grace_days, args.unshipped_days, is_latest)
        lag_all["exploits_checked"] = checks.is_checked(check_info, "exploits")
        for name in ("kev", "malicious", "epss", "exploits"):
            lag_all[f"{name}_ok"] = (checks.state_of(check_info, name) == checks.CHECKED
                                     or checks.turned_off(check_info, name))
    lk = likelihood.evaluate(lk_cfg, likelihood.metrics(lag_all, health, sc)) if lk_cfg else None
    if lk and lag_all is not lag_m:
        shown_lk = likelihood.evaluate(lk_cfg, likelihood.metrics(lag_m, health, sc))
        if shown_lk["level"] != lk["level"]:
            warnings.append(f"likelihood is {lk['level']} ({lk['label']}) from every finding; the findings shown, "
                            f"without those below --min-severity {args.min_severity}, would give "
                            f"{shown_lk['level']} ({shown_lk['label']})")
    return lag_m, lk


def _document(args, net, findings: list, all_findings: list, as_of: datetime, scanners_meta: dict, scan_info: dict,
              enabled: list[str], fd_stats: dict, kev_info: dict, epss_info: dict, exploit_info: dict, triage_info:
              dict, check_info: dict, decision_info, age_info: dict, reach_stats: dict, lag_m: dict,
              release_date_source, health: dict, sc: dict, lk, warnings: list[str]):
    """The assessment every report is written from, and the per-package rows for an inventory."""
    if args.extension_info:
        vscode.attribute(args.extension_info, findings)
    assessment = {
        "tool": {"name": "oss-intake", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "as_of": as_of.isoformat(),
        # The target by its name: the reports describe what was assessed, not where it sat on this machine.
        "inputs": {"image": args.image, "path": _target_name(args.path) if args.path else None,
                   "path_kind": args.path_kind, "repo": args.repo,
                   "packages": [e["purl"] for e in args.inventory] if args.package else None,
                   "image_src": args.image_src, "platform": args.platform,
                   "release_tag": args.release_tag, "release_date": args.release_date,
                   "min_severity": args.min_severity, "format": args.input_format},
        "scanners": scanners_meta,
        "scan_info": scan_info,
        "agreement": merge.source_agreement(findings, enabled),
        "fix_dates": fd_stats,
        "kev": kev_info,
        "epss": epss_info,
        "exploits": exploit_info,
        "triage": triage_info,
        "checks": check_info,
        "decisions": decision_info,
        "registry_check": getattr(args, "registry_result", None),
        "release_age": age_info,
        "network": network_info(net),
        "reachability": reach_stats if args.reachability else {"status": "skipped"},
        "lag": {**lag_m, "release_date_source": release_date_source},
        "coverage": coverage.compute(findings, looked_up=bool(net) and not args.no_fix_dates),
        "health": health,
        "scorecard": sc,
        "likelihood": lk,
        "warnings": warnings,
    }
    if args.extension_info:
        assessment["extensions"] = args.extension_info
    if args.sbom_info:
        assessment["sbom"] = args.sbom_info
    pkg_rows = None
    if args.path_kind == "inventory":
        pkg_rows = inventory_report.package_rows(args.inventory, all_findings)  # every finding, as the gates
        recent = {r["purl"]: r for r in age_info.get("recent") or []}
        for r in pkg_rows:
            hit = recent.get(r["purl"])
            r["new_release"] = (f"yes, {hit['age_days']} day{'' if hit['age_days'] == 1 else 's'} old" if hit
                                else "")
            r["published"] = (age_info.get("published") or {}).get(r["purl"], "")
        up = (upgrade.enrich(net, pkg_rows, latest=not args.no_latest, os_queries=args.os_queries) if net
              else {"status": "skipped"})
        if up.get("status") == "failed":
            warnings.append(f"Upgrade check failed, so remaining vulnerabilities are not shown: {up.get('error')}")
        assessment["inventory"] = {**inventory_report.summary(pkg_rows), "upgrade": up, "rows": pkg_rows,
                                   "executive": exec_summary.compute(pkg_rows, findings, as_of, args.previous)}
    return assessment, pkg_rows


def _write_reports(args, out: Path, formats: list[str], assessment: dict, findings: list, all_findings: list, pkg_rows,
                   decision_info, as_of: datetime):
    """5. Reports: the files asked for with --formats, packages.csv for an inventory, VEX with --decisions."""
    # 5. Reports.
    written = []
    if "csv" in formats:
        report.write_csv(out / "findings.csv", findings)
        written.append("findings.csv")
    if pkg_rows is not None:
        inventory_report.write_csv(out / "packages.csv", pkg_rows, report.csv_safe)
        written.append("packages.csv")
        if inventory_report.write_systems_csv(out / "package-systems.csv", pkg_rows, report.csv_safe):
            written.append("package-systems.csv")
        if "html" in formats:
            exec_summary.write(out / "executive-summary.html", assessment, pkg_rows,
                               assessment["inventory"]["executive"])
            written.append("executive-summary.html")
    vex = decisions.openvex(all_findings, __version__, as_of.isoformat()) if decision_info else None
    if vex:
        safewrite.write_text(out / "openvex.json", json.dumps(vex, indent=2))
        written.append("openvex.json")
        cdx = decisions.cyclonedx_vex(all_findings, __version__, as_of.isoformat())
        safewrite.write_text(out / "vex.cdx.json", json.dumps(cdx, indent=2))
        written.append("vex.cdx.json")
    if "md" in formats:
        report.write_markdown(out / "summary.md", assessment, findings, args.top)
        written.append("summary.md")
    if "json" in formats:
        report.write_json(out / "assessment.json", assessment, findings)
        written.append("assessment.json")
    if "html" in formats:
        report.write_html(out / "report.html", assessment, findings, max(args.top, 50))
        written.append("report.html")
    return written


MANIFEST = ".oss-intake-files.json"  # in --out: the files the last run wrote, so the next can tell its own


def _remove_stale(args, out: Path, written: list[str]) -> None:
    """Remove the reports the last run left in --out that this run did not write again (openvex.json from a run
    with --decisions, report.html when HTML is no longer asked for, a scanner's raw output when it is now
    imported), so none of them is taken for a current result. Only files the last run's manifest names as its
    own are touched (a summary.md the user keeps there is not), only regular files, never a file this run read;
    then this run's manifest replaces it."""
    current = set(written) | set(getattr(args, "raw_written", None) or [])
    try:
        before = jsonsafe.loads((out / MANIFEST).read_text(encoding="utf-8")).get("files")
    except (OSError, ValueError, AttributeError, RecursionError):
        before = None
    earlier = [n for n in before if isinstance(n, str) and n in OUTPUT_FILES] if isinstance(before, list) else []
    # A file this run read is never removed (raw/trivy.json re-imported with --from-trivy-json into its folder).
    given = []
    for v in vars(args).values():
        for x in (v if isinstance(v, (list, tuple)) else [v]):
            if isinstance(x, (str, Path)) and x and not str(x).startswith("-"):
                given.append(Path(x).expanduser())

    def read_this_run(p: Path) -> bool:
        for g in given:
            try:
                if g.is_file() and os.path.samefile(g, p):
                    return True
            except OSError:
                pass
        return False

    removed = []
    for name in earlier:
        p = out / name
        if name not in current and p.is_file() and not p.is_symlink() and not read_this_run(p):
            try:
                p.unlink()
                removed.append(name)
            except OSError as exc:
                log(f"warning: {name} from an earlier run could not be removed ({exc}); it is not from this run",
                    args.quiet, force=True)
    if removed:
        log(f"removed {', '.join(removed)} from an earlier run, as this run did not write them", args.quiet)
    kept = sorted(current | {n for n in earlier if (out / n).is_file()} - set(removed))
    try:
        safewrite.write_text(out / MANIFEST, json.dumps({"tool": "oss-intake", "files": kept}, indent=1))
    except OSError as exc:
        log(f"warning: {MANIFEST} could not be written ({exc}), so the next run cannot tell its reports",
            args.quiet, force=True)


def _finish(args, out: Path, findings: list, all_findings: list, pkg_rows, age_info: dict, check_info: dict,
            n_missing_live: int, lag_m: dict, lk, written: list[str], warnings: list[str]):
    """The summary line, verdicts and warnings, then the gates: the exit code."""
    sev = lag_m["by_severity"]
    print(f"findings={lag_m['total']} critical={sev['CRITICAL']} high={sev['HIGH']} "
          f"with_fix={lag_m['with_fix']} fix_before_release={lag_m['fix_available_at_release']} "
          f"fix_date_unknown={lag_m['fix_date_unknown']}"
          + (f" likelihood={lk['level']}({lk['label']},confidence={lk['confidence']})" if lk else "")
          + (f" not_checked={','.join(checks.gaps(check_info))}" if checks.gaps(check_info) else ""))
    if args.package and pkg_rows is not None:
        for line in verdicts(pkg_rows, all_findings, age_info):
            print(line)
    for w in warnings:
        log(f"warning: {w}", args.quiet)
    log(f"wrote {', '.join(written)} to {out}", args.quiet)
    registry, extensions = getattr(args, "registry_result", None), getattr(args, "extension_info", None)
    n_unchecked = (len((getattr(args, "sbom_info", None) or {}).get("not_checked") or [])
                   + len(getattr(args, "renv_unchecked", None) or []))
    tripped = gates.met(args.fail_on_set, all_findings, age_info, registry, extensions, n_unchecked)
    hidden_only = {t for t in tripped
                   if t not in gates.met([t], findings, age_info, registry, extensions, n_unchecked)}
    for t in tripped:
        log(f"--fail-on {t}: found {FAIL_ON[t]}"
            + (f" (only among findings below --min-severity {args.min_severity}, left out of the reports; "
               "the warnings name them)" if t in hidden_only else ""), args.quiet, force=True)
        if t == "unknown-age":
            listed = (age_info.get("unknown_purls") or []) + (age_info.get("unsupported_purls") or [])
            log("  " + ", ".join(listed[:5]) + (f" and {len(listed) - 5} more" if len(listed) > 5 else ""),
                args.quiet, force=True)
    unknown = gates.not_evaluated(args.fail_on_set, age_info, getattr(args, "registry_result", None), args, check_info,
                            n_missing_live)
    for t, why in unknown:
        log(f"--fail-on {t}: could not be evaluated ({why}); failing rather than passing", args.quiet, force=True)
    # A gate that tripped can still have skipped some versions: name them, so accepting what tripped it does not
    # also accept what was never looked at.
    unchecked = age_info.get("unchecked_purls") or []
    if unchecked and {"recent", "unknown-age"} & set(args.fail_on_set) and \
            not any(t in ("recent", "unknown-age") for t, _ in unknown):
        log(f"--fail-on: {len(unchecked)} version(s) were not looked up (lookup failed or over --release-age-max), "
            "so they were not checked for being new: " + ", ".join(unchecked[:5])
            + (f" and {len(unchecked) - 5} more" if len(unchecked) > 5 else ""), args.quiet, force=True)
    lk_met = bool(lk and args.fail_on_likelihood and lk["level"] and lk["level"] >= args.fail_on_likelihood)
    if lk and args.fail_on_likelihood and not lk_met and (lk.get("could_be") or 0) >= args.fail_on_likelihood:
        # A rule at or above the threshold could not be decided: its evidence did not load (KEV, malicious
        # packages, EPSS, exploit indexes, a release, Scorecard), so the gate cannot pass on the lower result.
        log(f"--fail-on-likelihood {args.fail_on_likelihood}: could not be evaluated (likelihood is "
            f"{lk['level'] or 'no rule matched'}, but a level {lk['could_be']} rule depends on what was not "
            f"checked: {', '.join(lk['unchecked'])}); failing rather than passing", args.quiet, force=True)
        unknown = [*unknown, ("likelihood", "inputs not checked")]
    if unknown and not tripped and not lk_met:
        return EXIT_ERROR
    if lk_met:
        return EXIT_THRESHOLD
    return EXIT_THRESHOLD if tripped else EXIT_OK


def verdicts(rows: list[dict], findings: list, age_info: dict, shown: int = 20) -> list[str]:
    """One plain line per package for --package runs: what it is, and what to do. Findings set aside (evidence
    or an assessor decision) are not counted as open, as for --fail-on; a version deps.dev does not know is not
    reported as clean, since it is most likely a misspelt name or version."""
    by_purl: dict[str, list] = {}
    for f in findings:
        by_purl.setdefault(f.purl or "", []).append(f)
    not_found = set(age_info.get("unknown_purls") or [])
    out = []
    for r in rows[:shown]:
        what = f"  {r['package']} {r['version']} ({r['ecosystem']}): "
        if r["malicious"]:
            out.append(what + "MALICIOUS release. Remove it.")
            continue
        if not r["findings"]:
            out.append(what + ("not on deps.dev (misspelt, or too new to be indexed); no advisories match it"
                               if r["purl"] in not_found else "no known vulnerabilities"))
            continue
        known = f"{r['findings']} known vulnerabilit{'y' if r['findings'] == 1 else 'ies'}"
        live = [f for f in by_purl.get(r["purl"], []) if f.triage_group != "aside"]
        aside = r["findings"] - len(live)
        if not live:
            out.append(what + known + ", all set aside (see findings.csv)")
            continue
        parts = [f"{len(live)} known vulnerabilit{'y' if len(live) == 1 else 'ies'}" + (
            f" ({aside} more set aside)" if aside else "")]
        critical = sum(1 for f in live if f.severity == "CRITICAL")
        kev = sum(1 for f in live if f.kev)
        if critical:
            parts.append(f"{critical} critical")
        if kev:
            parts.append(f"{kev} known exploited")
        # The minimum fix and what it leaves are worked out from every finding, set aside or not: say so.
        if r.get("upgrade_to") and any(f.fixed_versions for f in live):
            left = (r.get("upgrade_left") or {}).get("total")
            counting = ", counting those set aside" if aside else ""
            fix = f"; upgrade to at least {r['upgrade_to']}" + (
                f" ({left} still known in {r['upgrade_to']}{counting})" if left
                else " (clears all known)" if left == 0
                else f" ({r['no_fix']} with no fixed version yet{counting})" if r["no_fix"] else "")
        elif any(f.details_unavailable for f in live):
            fix = "; fix data unavailable (advisory details could not be loaded from OSV)"
        else:
            fix = "; no fixed version yet"
        out.append(what + ", ".join(parts) + fix)
    if len(rows) > shown:
        out.append(f"  ... and {len(rows) - shown} more in packages.csv")
    return out


def flag_warnings(shown: list, flagged: dict[str, set[int]]) -> list[str]:
    """The warnings for findings lag.flag_* marked, counted over the findings the reports show."""
    out = []
    n_kh, n_older, n_label = (sum(1 for f in shown if id(f) in flagged[k]) for k in ("kh", "older", "label"))
    if n_kh:
        out.append(f"{n_kh} kernel CVE finding(s) on kernel header packages (e.g. linux-libc-dev) are "
                   "excluded from lag and likelihood: containers use the host kernel. They remain in "
                   "findings.csv; --include-kernel-headers keeps them in")
    if n_older:
        out.append(f"{n_older} finding(s) list only fixes at or below the installed version; noted in "
                   "findings.csv for manual review and left without a fix date")
    if n_label:
        out.append(f"{n_label} finding(s) have an installed version equal to a listed fix apart from a "
                   "build label (e.g. .jre11); flagged as likely already fixed and excluded from lag")
    return out
