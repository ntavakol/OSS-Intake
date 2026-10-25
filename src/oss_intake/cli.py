"""Command line entry point."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, conditions, coverage, inputs, integrity, lag, likelihood, merge, report, triage
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
from .http import Http, HttpError, RequestsHttp
from .models import SEVERITY_ORDER, parse_datetime
from .scanners import ScannerError, find_executable, load_json_bytes
from .scanners import grype as grype_mod
from .scanners import osv as osv_mod
from .scanners import trivy as trivy_mod

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_THRESHOLD = 0, 1, 2, 3

# Docker reference grammar, simplified. Anchored and cannot start with '-', which also
# prevents a crafted value being read by the scanner as a command line option.
_IMAGE_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?/)?"
    r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$"
)
_REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")
_FORMATS = {"csv", "md", "json", "html"}
_SCANNERS = {"trivy", "grype", "osv"}
_SUBCOMMANDS = {"scan", "doctor", "verify"}


class UsageError(Exception):
    pass


def log(msg: str, quiet: bool = False) -> None:
    if not quiet:
        print(f"[oss-intake] {msg}", file=sys.stderr)


# ---------------------------------------------------------------- validation

def validate_image(value: str) -> str:
    v = value.strip()
    if not _IMAGE_RE.match(v):
        raise UsageError(f"--image '{value}' is not a valid image reference (e.g. owner/name:1.2.3)")
    last = v.rsplit("/", 1)[-1]
    if ":" not in last and "@" not in last:
        raise UsageError("--image must include an explicit tag or digest; 'latest' by omission is not assessed")
    return v


def image_tag(image: str) -> str | None:
    last = image.split("@", 1)[0].rsplit("/", 1)[-1]
    return last.split(":", 1)[1] if ":" in last else None


def validate_repo(value: str) -> str:
    v = value.strip()
    v = re.sub(r"^(https?://)?(www\.)?github\.com/", "", v).removesuffix(".git").strip("/")
    if not _REPO_RE.match(v):
        raise UsageError(f"--repo '{value}' must be a GitHub repository as owner/name")
    return v


def validate_date(value: str | None, flag: str) -> datetime | None:
    if value is None:
        return None
    dt = parse_datetime(value)
    if not dt or not re.match(r"^\d{4}-\d{2}-\d{2}", value):
        raise UsageError(f"{flag} must be a date as YYYY-MM-DD")
    return dt


def csv_set(value: str, allowed: set[str], flag: str) -> list[str]:
    items = [x.strip().lower() for x in value.split(",") if x.strip()]
    bad = [x for x in items if x not in allowed]
    if bad or not items:
        raise UsageError(
            f"{flag}: unknown value(s) {', '.join(bad) or '(empty)'}; allowed: {', '.join(sorted(allowed))}")
    return list(dict.fromkeys(items))


def prepare_out(path: str) -> Path:
    out = Path(path).expanduser()
    try:
        out.mkdir(parents=True, exist_ok=True)
        (out / "raw").mkdir(exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=out, prefix=".write-test-", delete=True):
            pass
    except OSError as exc:
        raise UsageError(f"--out {out} is not writable: {exc}") from None
    return out


# ---------------------------------------------------------------- parser

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="oss-intake",
        description="Assess third-party open source software before adoption: known vulnerabilities, "
                    "release lag (fixes available upstream but not shipped) and project health.",
    )
    p.add_argument("--version", action="version", version=f"oss-intake {__version__}")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="assess an image and/or repository (default command)")
    s.add_argument("--image", help="container image with an explicit tag or digest, e.g. owner/name:1.2.3")
    s.add_argument("--path", help="assess a file or directory instead of an image: a JAR, WAR or binary, a "
                                  "folder of built artifacts, a lockfile (requirements.txt, package-lock.json, "
                                  "pom.xml, ...) or an R renv.lock")
    s.add_argument("--repo", help="GitHub repository owner/name for release cadence and Scorecard")
    s.add_argument("--out", required=True, help="output directory")
    s.add_argument("--scanners", default="auto",
                   help="comma list of trivy,grype,osv. 'auto' (default) = trivy + osv, plus grype if found")
    s.add_argument("--image-src", choices=["docker", "containerd", "podman", "remote"],
                   help="where scanners read the image; 'remote' pulls from the registry without Docker")
    s.add_argument("--platform", default="linux/amd64",
                   help="image platform both scanners must use (default linux/amd64, so an Apple Silicon "
                        "host scans the same variant as a typical server); pass '' for scanner defaults")
    for tool in ("trivy", "grype"):
        s.add_argument(f"--{tool}-path", help=f"explicit path to the {tool} executable")
        s.add_argument(f"--{tool}-version", help=f"required {tool} version; the run fails on mismatch")
        s.add_argument(f"--{tool}-sha256", help=f"expected SHA-256 of the {tool} executable")
        s.add_argument(f"--{tool}-cosign-bundle", help=f"Sigstore bundle to verify the {tool} executable "
                                                      "(requires cosign on PATH)")
        s.add_argument(f"--{tool}-cosign-identity", help="certificate identity regexp override")
        s.add_argument(f"--{tool}-arg", action="append", default=[], metavar="ARG",
                       help=f"extra argument passed to {tool} (repeatable), e.g. --{tool}-arg=--db-repository=...")
        s.add_argument(f"--from-{tool}-json", metavar="FILE",
                       help=f"use an existing {tool} JSON report instead of running {tool}")
    s.add_argument("--release-tag", help="GitHub release tag that the image corresponds to")
    s.add_argument("--release-date", help="release date (YYYY-MM-DD) to use for lag, overrides GitHub")
    s.add_argument("--grace-days", type=int, default=lag.DEFAULT_GRACE_DAYS,
                   help="a fix must predate the release by this many days to count as missed (default 14)")
    s.add_argument("--unshipped-days", type=int, default=lag.DEFAULT_UNSHIPPED_DAYS,
                   help="days a fix must be public, with no newer release, to count as unshipped (default 90)")
    s.add_argument("--no-image-date", action="store_true",
                   help="do not fall back to the image build date when no release date is known")
    s.add_argument("--include-kernel-headers", action="store_true",
                   help="count kernel CVEs on kernel header packages (linux-libc-dev...) in lag and likelihood")
    s.add_argument("--as-of", help="assessment date (YYYY-MM-DD) for reproducible reports; default today")
    s.add_argument("--min-severity", default="UNKNOWN", type=str.upper, choices=list(SEVERITY_ORDER),
                   help="drop findings below this severity")
    s.add_argument("--formats", default="csv,md,json,html", help="comma list of csv,md,json,html")
    s.add_argument("--sbom", action="store_true", help="also write a CycloneDX SBOM from Trivy to raw/")
    s.add_argument("--offline", action="store_true",
                   help="no network enrichment (OSV, deps.dev, GitHub, Scorecard, KEV); scanners may still pull")
    s.add_argument("--no-fix-dates", action="store_true", help="skip deps.dev fix date lookups")
    s.add_argument("--no-kev", action="store_true", help="skip the CISA KEV catalogue")
    s.add_argument("--no-epss", action="store_true", help="skip FIRST EPSS exploit probability scores")
    s.add_argument("--no-exploits", action="store_true",
                   help="skip public exploit availability (Metasploit, Nuclei, Exploit-DB, GitHub proofs of concept)")
    s.add_argument("--no-workflows", action="store_true",
                   help="skip the audit of the project's GitHub Actions workflows")
    s.add_argument("--no-scorecard", action="store_true", help="skip OpenSSF Scorecard")
    s.add_argument("--likelihood", action="store_true", help="include the 5x5 likelihood heuristic")
    s.add_argument("--likelihood-config", metavar="FILE", help="custom likelihood rules (JSON); implies --likelihood")
    s.add_argument("--fail-on-likelihood", type=int, choices=range(1, 6), metavar="N",
                   help="exit 3 if the suggested likelihood is >= N (implies --likelihood)")
    s.add_argument("--timeout", type=int, default=1800, help="per scanner timeout in seconds (default 1800)")
    s.add_argument("--top", type=int, default=25, help="findings listed in the summary (default 25)")
    s.add_argument("--quiet", action="store_true", help="only print errors and the final summary")

    d = sub.add_parser("doctor", help="show scanner paths, versions, hashes and known-bad status")
    d.add_argument("--trivy-path")
    d.add_argument("--grype-path")

    v = sub.add_parser("verify", help="verify a downloaded file against a checksums file, hash or cosign bundle")
    v.add_argument("--file", required=True)
    g = v.add_mutually_exclusive_group(required=True)
    g.add_argument("--checksums", help="sha256sum-style checksums file (e.g. trivy_0.76.1_checksums.txt)")
    g.add_argument("--sha256", help="expected SHA-256")
    v.add_argument("--name", help="entry name in the checksums file (default: the file's name)")
    v.add_argument("--cosign-bundle", help="also verify a Sigstore bundle with cosign")
    v.add_argument("--cosign-identity", help="certificate identity regexp")
    return p


# ---------------------------------------------------------------- commands

def cmd_doctor(args: argparse.Namespace) -> int:
    rows = []
    for tool, mod in (("trivy", trivy_mod), ("grype", grype_mod)):
        try:
            path = find_executable(tool, getattr(args, f"{tool}_path"))
            info = mod.version_info(path)
            bad = integrity.known_bad_entry(tool, info["version"])
            rows.append({"tool": tool, "path": path, "version": info["version"],
                         "sha256": integrity.sha256_file(path),
                         "known_bad": bool(bad), "known_bad_reference": (bad or {}).get("reference")})
        except ScannerError as exc:
            rows.append({"tool": tool, "error": str(exc)})
    report_ = {"oss_intake": __version__, "python": sys.version.split()[0], "scanners": rows,
               "cosign_on_path": bool(shutil.which("cosign")),
               "github_token_set": bool(os.environ.get("GITHUB_TOKEN"))}
    print(json.dumps(report_, indent=2))
    return EXIT_ERROR if any(r.get("known_bad") for r in rows) else EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    if not Path(args.file).is_file():
        raise UsageError(f"--file {args.file} not found")
    if args.checksums:
        digest = integrity.verify_against_checksums(args.file, args.checksums, args.name)
    else:
        digest = integrity.verify_sha256(args.file, args.sha256)
    print(f"OK sha256 {digest}  {Path(args.file).name}")
    if args.cosign_bundle:
        if not args.cosign_identity:
            raise UsageError("--cosign-identity is required with --cosign-bundle in verify mode")
        integrity.cosign_verify_blob(args.file, args.cosign_bundle, args.cosign_identity)
        print("OK cosign signature")
    return EXIT_OK


def _resolve_scanners(args: argparse.Namespace) -> tuple[list[str], list[str]]:
    warnings: list[str] = []
    if args.scanners == "auto":
        chosen = ["trivy"]
        if args.from_grype_json or shutil.which("grype") or args.grype_path:
            chosen.append("grype")
        else:
            warnings.append("grype not found; running without the Grype cross-check")
        if not args.offline:
            chosen.append("osv")
    else:
        chosen = csv_set(args.scanners, _SCANNERS, "--scanners")
        if "osv" in chosen and args.offline:
            raise UsageError("--scanners includes osv but --offline was given")
    if "osv" in chosen and "trivy" not in chosen:
        raise UsageError("osv needs the package list from trivy; include trivy or drop osv")
    return chosen, warnings


def _run_or_load(tool: str, mod, args: argparse.Namespace, out: Path, scanners_meta: dict) -> dict:
    loaded = getattr(args, f"from_{tool}_json")
    if loaded:
        data = load_json_bytes(Path(loaded).read_bytes(), loaded)
        scanners_meta[tool] = {"enabled": True, "detail": f"imported from {Path(loaded).name}", "imported": True}
        return data
    path = find_executable(tool, getattr(args, f"{tool}_path"))
    info = mod.version_info(path)
    check = integrity.check_binary(
        tool, path, info["version"], getattr(args, f"{tool}_version"), getattr(args, f"{tool}_sha256"),
        getattr(args, f"{tool}_cosign_bundle"), getattr(args, f"{tool}_cosign_identity"))
    scanners_meta[tool] = {"enabled": True, **info, **check.as_dict()}
    target = args.path if args.path else args.image
    log(f"running {tool} {info['version']} on {target}", args.quiet)
    if args.path:
        extra = getattr(args, f"{tool}_arg")
        if tool == "trivy":
            raw = mod.scan_path(path, inputs.trivy_mode(args.path_kind), str(args.scan_target), extra, args.timeout)
        else:
            raw = mod.scan_path(path, str(args.scan_target), extra, args.timeout)
    else:
        raw = mod.scan(path, args.image, args.image_src, getattr(args, f"{tool}_arg"), args.timeout,
                       args.platform or None)
    (out / "raw" / f"{tool}.json").write_bytes(raw)
    if tool == "trivy" and args.sbom and not args.path:
        (out / "raw" / "sbom.cdx.json").write_bytes(
            mod.sbom(path, args.image, args.image_src, args.trivy_arg, args.timeout, args.platform or None))
    return load_json_bytes(raw, tool)


def cmd_scan(args: argparse.Namespace, http: Http | None = None) -> int:
    # 1. Validate everything before doing any work.
    if not args.image and not args.repo and not args.path:
        raise UsageError("give --image, --path or --repo")
    if args.image and args.path:
        raise UsageError("give --image or --path, not both")
    if args.image:
        args.image = validate_image(args.image)
    args.path_kind, args.scan_target, tmp_dir = None, None, None
    if args.path:
        p = Path(args.path).expanduser()
        if not p.exists():
            raise UsageError(f"--path {args.path} not found")
        args.path = str(p)
        args.path_kind = inputs.classify(p)
    if args.repo:
        args.repo = validate_repo(args.repo)
    formats = csv_set(args.formats, _FORMATS, "--formats")
    as_of = validate_date(args.as_of, "--as-of") or datetime.now(timezone.utc)
    release_override = validate_date(args.release_date, "--release-date")
    if args.likelihood_config or args.fail_on_likelihood:
        args.likelihood = True
    lk_cfg = likelihood.load_config(args.likelihood_config) if args.likelihood else None
    for flag in ("from_trivy_json", "from_grype_json", "trivy_cosign_bundle", "grype_cosign_bundle"):
        val = getattr(args, flag)
        if val and not Path(val).is_file():
            raise UsageError(f"--{flag.replace('_', '-')} {val} not found")
    if args.path_kind == "renv":
        chosen, warnings = ([] if args.offline else ["osv"]), []
        if args.offline:
            raise UsageError("an renv.lock is checked against OSV, which needs the network; drop --offline")
    else:
        chosen, warnings = _resolve_scanners(args) if (args.image or args.path) else ([], [])
    if args.image is None and args.path is None and (args.from_trivy_json or args.from_grype_json):
        raise UsageError("--from-*-json needs --image or --path to label the report")
    out = prepare_out(args.out)
    if args.path and args.path_kind != "renv" and not (args.from_trivy_json and args.from_grype_json):
        args.scan_target, tmp_dir = inputs.stage(Path(args.path), args.path_kind)
    log(f"plan: {'path=' + args.path + ' (' + args.path_kind + ')' if args.path else 'image=' + (args.image or '-')} "
        f"repo={args.repo or '-'} sources={','.join(chosen) or '-'} "
        f"image-src={args.image_src or 'scanner default'} "
        f"platform={args.platform or 'scanner default'} out={out} formats={','.join(formats)}", args.quiet)

    net = None if args.offline else (http or RequestsHttp())
    scanners_meta: dict = {s: {"enabled": False} for s in ("trivy", "grype", "osv")}

    # 2. Scanners. Integrity failures abort; scanner failures abort (a partial scan is misleading).
    try:
        trivy_report, groups, scan_info = _scan(args, chosen, out, net, scanners_meta, warnings)
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
    return _assess(args, chosen, out, net, scanners_meta, warnings, groups, trivy_report, scan_info, formats,
                   as_of, release_override, lk_cfg)


def _scan(args, chosen, out, net, scanners_meta, warnings):
    groups: list = []
    trivy_report = None
    scan_info: dict = {}
    if args.path_kind == "renv":
        purls, skipped = inputs.renv_purls(Path(args.path))
        if skipped:
            warnings.append(f"{len(skipped)} renv package(s) not from CRAN were not checked (OSV's R advisories "
                            f"cover CRAN): {', '.join(skipped[:8])}{' ...' if len(skipped) > 8 else ''}")
        if net and purls:
            try:
                groups.append(osv_mod.scan(net, purls))
                scanners_meta["osv"] = {"enabled": True, "detail": f"{len(purls)} CRAN packages queried"}
            except HttpError as exc:
                warnings.append(f"OSV lookup failed: {exc}")
        return None, groups, scan_info
    if "trivy" in chosen:
        trivy_report = _run_or_load("trivy", trivy_mod, args, out, scanners_meta)
        f, scan_info = trivy_mod.parse(trivy_report)
        groups.append(f)
    if "grype" in chosen:
        g, _ = grype_mod.parse(_run_or_load("grype", grype_mod, args, out, scanners_meta))
        groups.append(g)
    if "osv" in chosen and trivy_report is not None and net:
        purls = osv_mod.purls_from_trivy(trivy_report)
        try:
            o = osv_mod.scan(net, purls)
            groups.append(o)
            scanners_meta["osv"] = {"enabled": True, "detail": f"{len(purls)} packages queried"}
        except HttpError as exc:
            warnings.append(f"OSV lookup failed, continuing without it: {exc}")
        if not purls:
            if any(r.get("Class") == "lang-pkgs" for r in trivy_report.get("Results") or []):
                warnings.append("Trivy found language packages but listed none in the report, so OSV had "
                                "nothing to query (was the report generated with --list-all-pkgs=false?)")
            else:
                warnings.append("No language packages in the image (OS packages only), so OSV was not queried; "
                                "Trivy and Grype cover OS packages")
    return trivy_report, groups, scan_info


def _assess(args, chosen, out, net, scanners_meta, warnings, groups, trivy_report, scan_info, formats, as_of,
            release_override, lk_cfg):

    findings = merge.merge(*groups)
    for f in findings:
        f.conditions = conditions.extract(f.description)
    findings = [f for f in findings if SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[args.min_severity]]
    n_label = lag.flag_label_matches(findings)
    if not args.include_kernel_headers:
        n_kh = lag.flag_kernel_headers(findings)
        if n_kh:
            warnings.append(f"{n_kh} kernel CVE finding(s) on kernel header packages (e.g. linux-libc-dev) are "
                            "excluded from lag and likelihood: containers use the host kernel. They remain in "
                            "findings.csv; --include-kernel-headers keeps them in")
    n_older = lag.flag_no_newer_fix(findings)
    if n_older:
        warnings.append(f"{n_older} finding(s) list only fixes at or below the installed version; noted in "
                        "findings.csv for manual review and left without a fix date")
    if n_label:
        warnings.append(f"{n_label} finding(s) have an installed version equal to a listed fix apart from a "
                        "build label (e.g. .jre11); flagged as likely already fixed and excluded from lag")
    enabled = [s for s in ("trivy", "grype", "osv") if scanners_meta[s].get("enabled")]

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
            for kb in health["workflows"].get("known_bad", []):
                warnings.append(f"Project workflow {kb['file']} uses {kb['uses']}, a known-bad action version "
                                f"({kb['reference']})")
    elif args.repo:
        warnings.append("--offline: release cadence and Scorecard skipped")

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
        warnings.append("No release date known, so 'fix existed before release' cannot be computed: " + hint)

    # 4. Enrichment.
    fd_stats: dict = {}
    kev_info: dict = {"status": "skipped"}
    epss_info: dict = {"status": "skipped"}
    exploit_info: dict = {"status": "skipped"}
    if net and findings:
        if not args.no_fix_dates:
            fd_stats = fixdates.enrich(net, findings)
            if fd_stats.get("errors"):
                warnings.append(f"deps.dev lookups failed for {fd_stats['errors']} package versions")
            deb = debian_tracker.enrich(net, findings)
            fd_stats["debian_tracker"] = deb
            if deb.get("errors"):
                warnings.append("Debian security tracker lists could not be loaded; Debian fix dates fall back to OSV")
            dpr = debian_releases.enrich(net, findings)
            fd_stats["debian_point_release"] = dpr
            if dpr.get("errors"):
                warnings.append("Debian point release ChangeLog could not be loaded; point-release fixes stay undated")
            rh = redhat.enrich(net, findings)
            fd_stats["redhat"] = rh
            if rh.get("errors"):
                warnings.append(f"Red Hat advisory lookups failed for {rh['errors']} advisories; dates may be partial")
            ubu = ubuntu.enrich(net, findings)
            fd_stats["ubuntu"] = ubu
            ulp = ubuntu_launchpad.enrich(net, findings)
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
            alp = alpine.enrich(net, findings)
            fd_stats["alpine"] = alp
            if alp.get("skipped_limit"):
                warnings.append(f"{alp['skipped_limit']} Alpine fix dates skipped to stay within GitHub rate limits")
            if alp.get("errors"):
                warnings.append("Alpine aports history lookups failed for some packages (set GITHUB_TOKEN for "
                                "higher GitHub API limits)")
            adv = advisories.enrich(net, findings)
            fd_stats["advisory"] = adv
            if adv.get("errors"):
                warnings.append(f"OSV advisory lookups failed for {adv['errors']} distro advisories")
            pk = packagist.enrich(net, findings)
            fd_stats["packagist"] = pk
            if pk.get("errors"):
                warnings.append(f"Packagist lookups failed for {pk['errors']} PHP packages")
            gos = golang_stdlib.enrich(net, findings)
            fd_stats["go_stdlib"] = gos
            if gos.get("errors"):
                warnings.append("Go release history (go.dev) could not be loaded; Go standard library fixes stay "
                                "undated")
            ghr = github_releases.enrich(net, findings)
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
            exploit_info = exploits.enrich(net, findings)
            if exploit_info["failed"]:
                warnings.append("Exploit sources could not be loaded: " + ", ".join(exploit_info["failed"])
                                + "; exploit levels are partial")
            if exploit_info["poc_skipped"]:
                warnings.append(f"Proof-of-concept lookups capped or failed for {exploit_info['poc_skipped']} "
                                "finding(s); their exploit level is 'not checked'")
        if not args.no_epss:
            epss_info = {"status": "ok", **epss.enrich(net, findings)}
            if epss_info["errors"]:
                warnings.append(f"EPSS lookups failed for {epss_info['errors']} batch(es); EPSS signals are partial")

    if args.grace_days < 0 or args.unshipped_days < 0:
        raise UsageError("--grace-days and --unshipped-days must be zero or more")
    is_latest = health.get("scanned_is_latest") if not release_override else None
    triage_info = triage.apply(findings)
    lag_m = lag.compute(findings, release_date, as_of, args.grace_days, args.unshipped_days, is_latest)
    lk = likelihood.evaluate(lk_cfg, likelihood.metrics(lag_m, health, sc)) if lk_cfg else None

    assessment = {
        "tool": {"name": "oss-intake", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "as_of": as_of.isoformat(),
        "inputs": {"image": args.image, "path": args.path, "path_kind": args.path_kind, "repo": args.repo,
                   "image_src": args.image_src, "platform": args.platform,
                   "release_tag": args.release_tag, "release_date": args.release_date,
                   "min_severity": args.min_severity},
        "scanners": scanners_meta,
        "scan_info": scan_info,
        "agreement": merge.source_agreement(findings, enabled),
        "fix_dates": fd_stats,
        "kev": kev_info,
        "epss": epss_info,
        "exploits": exploit_info,
        "triage": triage_info,
        "lag": {**lag_m, "release_date_source": release_date_source},
        "coverage": coverage.compute(findings),
        "health": health,
        "scorecard": sc,
        "likelihood": lk,
        "warnings": warnings,
    }

    # 5. Reports.
    written = []
    if "csv" in formats:
        report.write_csv(out / "findings.csv", findings)
        written.append("findings.csv")
    if "md" in formats:
        report.write_markdown(out / "summary.md", assessment, findings, args.top)
        written.append("summary.md")
    if "json" in formats:
        report.write_json(out / "assessment.json", assessment, findings)
        written.append("assessment.json")
    if "html" in formats:
        report.write_html(out / "report.html", assessment, findings, max(args.top, 50))
        written.append("report.html")

    sev = lag_m["by_severity"]
    print(f"findings={lag_m['total']} critical={sev['CRITICAL']} high={sev['HIGH']} "
          f"with_fix={lag_m['with_fix']} fix_before_release={lag_m['fix_available_at_release']} "
          f"fix_date_unknown={lag_m['fix_date_unknown']}"
          + (f" likelihood={lk['level']}({lk['label']},confidence={lk['confidence']})" if lk else ""))
    for w in warnings:
        log(f"warning: {w}", args.quiet)
    log(f"wrote {', '.join(written)} to {out}", args.quiet)
    if lk and args.fail_on_likelihood and lk["level"] and lk["level"] >= args.fail_on_likelihood:
        return EXIT_THRESHOLD
    return EXIT_OK


def main(argv: list[str] | None = None, http: Http | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in _SUBCOMMANDS and argv[0] not in ("-h", "--help", "--version"):
        argv.insert(0, "scan")  # 'oss-intake --image ...' works without the subcommand
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return EXIT_USAGE
    try:
        if args.command == "doctor":
            return cmd_doctor(args)
        if args.command == "verify":
            return cmd_verify(args)
        return cmd_scan(args, http)
    except UsageError as exc:
        print(f"oss-intake: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (ScannerError, integrity.IntegrityError, likelihood.ConfigError, HttpError, OSError) as exc:
        print(f"oss-intake: error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
