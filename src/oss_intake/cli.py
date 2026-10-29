"""Command line entry point."""

from __future__ import annotations

import argparse
import itertools
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

from . import (
    __version__,
    checks,
    conditions,
    coverage,
    decisions,
    exec_summary,
    inputs,
    integrity,
    inventory_report,
    lag,
    likelihood,
    merge,
    reachability,
    registry_check,
    release_age,
    report,
    sbom,
    triage,
    upgrade,
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
from .http import Http, HttpError, RequestsHttp, ResponseCache, default_cache_dir
from .models import SEVERITY_ORDER, parse_datetime
from .scanners import ReportShapeError, ScannerError, check_report, find_executable, load_json_bytes
from .scanners import govulncheck as govuln_mod
from .scanners import grype as grype_mod
from .scanners import osv as osv_mod
from .scanners import trivy as trivy_mod

EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_THRESHOLD = 0, 1, 2, 3
FAIL_ON = {
    "malicious": "a malicious package",
    "kev": "a finding in CISA KEV",
    "act": "a finding in Act now",
    "critical": "a critical finding",
    "high": "a high or critical finding",
    "recent": "a package version published within --release-age-days",
    "mismatch": "an artifact that does not match its registry checksum",
}

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


def log(msg: str, quiet: bool = False, force: bool = False) -> None:
    if force or not quiet:
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
        raise UsageError(f"{flag} must be a real date as YYYY-MM-DD (got {value!r})")
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
        prog="oss-intake", allow_abbrev=False,  # B23: --offlin must not silently mean --offline
        description="Assess third-party open source software before adoption: known vulnerabilities, "
                    "release lag (fixes available upstream but not shipped) and project health.",
    )
    p.add_argument("--version", action="version", version=f"oss-intake {__version__}")
    sub = p.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="assess an image and/or repository (default command)", allow_abbrev=False)
    s.add_argument("--image", help="container image with an explicit tag or digest, e.g. owner/name:1.2.3")
    s.add_argument("--path", help="assess a file or directory instead of an image: a JAR, WAR or binary, a "
                                  "folder of built artifacts, a lockfile (requirements.txt, package-lock.json, "
                                  "pom.xml, ...), an R renv.lock, or a package inventory .csv (columns "
                                  "ecosystem,name,version or purl, plus any label columns such as owner)")
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
        s.add_argument(f"--{tool}-archive", metavar="FILE",
                       help=f"the release archive the {tool} executable came from: the executable must be "
                            f"byte-for-byte the one inside it; the cosign bundle is checked against this archive "
                            f"(or against --{tool}-checksums)")
        s.add_argument(f"--{tool}-checksums", metavar="FILE",
                       help=f"the release checksums file, which must list --{tool}-archive; with a cosign bundle "
                            "that signs the checksums file (Grype publishes only this)")
        s.add_argument(f"--{tool}-cosign-bundle", help=f"Sigstore bundle for the {tool} release archive, or for "
                                                      f"--{tool}-checksums (requires cosign on PATH)")
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
    s.add_argument("--formats", default="csv,md,json,html",
                   help="comma list of csv,md,json,html (findings.csv is always written)")
    s.add_argument("--sbom", action="store_true", help="also write a CycloneDX SBOM from Trivy to raw/")
    s.add_argument("--offline", action="store_true",
                   help="no network enrichment (OSV, deps.dev, GitHub, Scorecard, KEV); scanners may still pull")
    s.add_argument("--no-fix-dates", action="store_true", help="skip deps.dev fix date lookups")
    s.add_argument("--no-kev", action="store_true", help="skip the CISA KEV catalogue")
    s.add_argument("--no-epss", action="store_true", help="skip FIRST EPSS exploit probability scores")
    s.add_argument("--reachability", action="store_true",
                   help="check Go binaries with govulncheck (must be installed): is the vulnerable function in the "
                        "binary? Images need Docker or crane to copy the binaries out")
    s.add_argument("--govulncheck-path", help="path to the govulncheck executable")
    s.add_argument("--govulncheck-sha256", help="expected SHA-256 of the govulncheck executable, checked before it "
                                                "runs (S9)")
    s.add_argument("--govulncheck-version", help="required govulncheck version; the run fails on mismatch")
    s.add_argument("--label", action="append", default=[], metavar="KEY=VALUE",
                   help="package inventories and SBOMs: label every package that has no such label yet, e.g. "
                        "--label owner='Web team' (repeatable); labels group packages.csv and the executive summary")
    s.add_argument("--decisions", metavar="FILE",
                   help="carry assessor decisions into this run: a findings.csv from an earlier run with the "
                        "triage_status, triage_notes and triage_reachable columns filled in, or an OpenVEX .json")
    s.add_argument("--no-registry-check", action="store_true",
                   help="--path on a JAR, wheel, sdist or npm .tgz: skip comparing its hash with the checksum the "
                        "registry (Maven Central, PyPI, npm) publishes for that version")
    s.add_argument("--no-latest", action="store_true",
                   help="package inventories: skip looking up each package's latest release on deps.dev (one "
                        "request per package); the minimum fix version is still checked")
    s.add_argument("--no-exploits", action="store_true",
                   help="skip public exploit availability (Metasploit, Nuclei, Exploit-DB, GitHub proofs of concept)")
    s.add_argument("--no-workflows", action="store_true",
                   help="skip the audit of the project's GitHub Actions workflows")
    s.add_argument("--no-scorecard", action="store_true", help="skip OpenSSF Scorecard")
    s.add_argument("--likelihood", action="store_true", help="include the 5x5 likelihood heuristic")
    s.add_argument("--likelihood-config", metavar="FILE", help="custom likelihood rules (JSON); implies --likelihood")
    s.add_argument("--fail-on-likelihood", type=int, choices=range(1, 6), metavar="N",
                   help="exit 3 if the suggested likelihood is >= N (implies --likelihood)")
    s.add_argument("--fail-on", metavar="LIST", default="",
                   help="exit 3 if any of these is found, for CI: " + ", ".join(FAIL_ON) + " (comma separated; "
                        "findings set aside by evidence or an assessor decision do not count)")
    s.add_argument("--release-age-days", type=int, default=release_age.DEFAULT_DAYS, metavar="N",
                   help=f"flag package versions published fewer than N days ago (default {release_age.DEFAULT_DAYS}; "
                        "0 turns it off): new releases are when compromised versions are live, before advisories "
                        "exist. One deps.dev request per language package")
    s.add_argument("--release-age-max", type=int, default=release_age.MAX_LOOKUPS, metavar="N",
                   help=f"look up release dates for at most N package versions, after duplicates are merged "
                        f"(default {release_age.MAX_LOOKUPS}); the rest are reported as not checked")
    s.add_argument("--cache-dir", metavar="DIR",
                   help="keep slowly changing lookups (advisory details for a day, release dates for 30 days) "
                        "here between runs (default: the user cache folder)")
    s.add_argument("--no-cache", action="store_true",
                   help="fetch everything fresh and keep nothing; what affects a version is always fetched fresh")
    s.add_argument("--timeout", type=int, default=1800, help="per scanner timeout in seconds (default 1800)")
    s.add_argument("--top", type=int, default=25, help="findings listed in the summary (default 25)")
    s.add_argument("--quiet", action="store_true", help="only print errors and the final summary")

    d = sub.add_parser("doctor", help="show scanner paths, versions, hashes and known-bad status", allow_abbrev=False)
    d.add_argument("--trivy-path")
    d.add_argument("--grype-path")

    v = sub.add_parser("verify", help="verify a downloaded file against a checksums file, hash or cosign bundle",
                       allow_abbrev=False)
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
            digest = integrity.sha256_file(path)  # recorded before the binary is run
            info = mod.version_info(path)
            bad = integrity.known_bad_entry(tool, info["version"])
            rows.append({"tool": tool, "path": path, "version": info["version"], "sha256": digest,
                         "known_bad": bool(bad), "known_bad_reference": (bad or {}).get("reference"),
                         "note": "doctor ran --version on this binary without a pinned hash; compare sha256 with "
                                 "the release checksums (oss-intake verify) before trusting it"})
        except ScannerError as exc:
            rows.append({"tool": tool, "error": str(exc)})
    report_ = {"oss_intake": __version__, "python": sys.version.split()[0], "scanners": rows,
               "cosign_on_path": bool(shutil.which("cosign")),
               "github_token_set": bool(os.environ.get("GITHUB_TOKEN"))}
    print(json.dumps(report_, indent=2))
    return EXIT_ERROR if any(r.get("known_bad") for r in rows) else EXIT_OK


def cmd_verify(args: argparse.Namespace) -> int:
    # Every option is checked before anything is hashed, so OK is never printed for a run that then fails.
    if not Path(args.file).is_file():
        raise UsageError(f"--file {args.file} not found")
    for flag in ("checksums", "cosign_bundle"):
        val = getattr(args, flag)
        if val and not Path(val).is_file():
            raise UsageError(f"--{flag.replace('_', '-')} {val} not found")
    if args.cosign_bundle and not args.cosign_identity:
        raise UsageError("--cosign-identity is required with --cosign-bundle in verify mode (verify does not know "
                         "which project signed the file)")
    if args.cosign_identity and not args.cosign_bundle:
        raise UsageError("--cosign-identity needs --cosign-bundle")
    if args.sha256:
        try:
            integrity.normalise_hash(args.sha256)
        except integrity.IntegrityError as exc:
            raise UsageError(f"--sha256: {exc}") from None
    if args.checksums:
        digest = integrity.verify_against_checksums(args.file, args.checksums, args.name)
    else:
        digest = integrity.verify_sha256(args.file, args.sha256)
    print(f"OK sha256 {digest}  {Path(args.file).name}")
    if args.cosign_bundle:
        integrity.cosign_verify_blob(args.file, args.cosign_bundle, args.cosign_identity)
        print("OK cosign signature")
    return EXIT_OK


_LABEL_KEY = re.compile(r"^[a-z][a-z0-9_ -]{0,39}$")


def _labels(values: list[str]) -> dict[str, str]:
    """--label owner=Web team -> {"owner": "Web team"}. Keys are column names in packages.csv."""
    out: dict[str, str] = {}
    for v in values:
        key, sep, value = v.partition("=")
        key, value = key.strip().lower(), value.strip()
        if not sep or not value or not _LABEL_KEY.match(key):
            raise UsageError(f"--label {v!r}: use key=value, with a key of letters, digits, spaces, - or _")
        if key in inputs.INVENTORY_KEYS or key in inventory_report.BASE_FIELDS or key in (
                "labels", "compare_version", "upgrade_version"):
            raise UsageError(f"--label {key} is a column oss-intake fills in (packages.csv); use another name")
        out[key] = value
    return out


def _ineffective_options(args, chosen: list[str]) -> list[str]:
    """Options that would have no effect in this run (B22): say so instead of ignoring them silently."""
    out = []
    run_live = [t for t in ("trivy", "grype") if t in chosen and not getattr(args, f"from_{t}_json")]
    if args.sbom and (args.path or "trivy" not in run_live):
        out.append("--sbom has no effect: the SBOM is written only when Trivy scans an image in this run")
    for t in ("trivy", "grype"):
        if getattr(args, f"{t}_arg") and t not in run_live:
            out.append(f"--{t}-arg has no effect: {t} does not run (its report is imported, or it is not selected)")
    if args.image_src and not run_live:
        out.append("--image-src has no effect: no scanner pulls the image in this run")
    if args.release_tag and not args.repo:
        out.append("--release-tag has no effect without --repo")
    for t in ("trivy", "grype"):
        pins = [f"--{t}-{o.replace('_', '-')}" for o in ("sha256", "version", "archive", "checksums", "cosign_bundle")
                if getattr(args, f"{t}_{o}")]
        if pins and t not in run_live:
            out.append(f"{', '.join(pins)} {'has' if len(pins) == 1 else 'have'} no effect: {t} does not run")
    gv = [f"--govulncheck-{o}" for o in ("path", "sha256", "version") if getattr(args, f"govulncheck_{o}")]
    if gv and not args.reachability:
        out.append(f"{', '.join(gv)} {'has' if len(gv) == 1 else 'have'} no effect without --reachability")
    return out


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


def _image_parts(ref: str) -> tuple[str, str, str]:
    """(repository, tag, digest) with Docker Hub's implied prefixes removed; tag or digest may be ''."""
    ref, _, digest = ref.strip().lower().partition("@")
    for prefix in ("docker.io/library/", "docker.io/", "index.docker.io/library/", "index.docker.io/", "library/"):
        if ref.startswith(prefix):
            ref = ref[len(prefix):]
            break
    name, tag = ref, ""
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = ref.rsplit(":", 1)
    return name, tag, digest


def _same_image(a: str, b: str) -> bool:
    """False only when the two references are known to differ: another repository, two different digests, or
    two different tags. A tag on one side and only a digest on the other cannot be compared, so it is not flagged."""
    (na, ta, da), (nb, tb, db) = _image_parts(a), _image_parts(b)
    if na != nb:
        return False
    if da and db:
        return da == db
    if da or db:
        return True if not (ta and tb) else ta == tb
    return (ta or "latest") == (tb or "latest")


def _run_or_load(tool: str, mod, args: argparse.Namespace, out: Path, scanners_meta: dict,
                 warnings: list[str] | None = None) -> dict:
    loaded = getattr(args, f"from_{tool}_json")
    if loaded:
        try:
            data = load_json_bytes(Path(loaded).read_bytes(), f"--from-{tool}-json {Path(loaded).name}")
            check_report(data, tool, f"--from-{tool}-json {Path(loaded).name}")
        except (ReportShapeError, ScannerError) as exc:
            raise UsageError(str(exc)) from None
        named = (data.get("ArtifactName") if tool == "trivy"
                 else ((data.get("source") or {}).get("target") or {}).get("userInput")
                 if isinstance((data.get("source") or {}).get("target"), dict) else None)
        if named and args.image and not _same_image(str(named), args.image) and warnings is not None:
            warnings.append(f"The imported {tool.capitalize()} report is for {named}, but the report is labelled "
                            f"{args.image} (--image); check that the right file was imported")
        scanners_meta[tool] = {"enabled": True, "detail": f"imported from {Path(loaded).name}", "imported": True}
        return data
    path = find_executable(tool, getattr(args, f"{tool}_path"))
    # A pinned hash or signature is checked before the binary runs at all, so a swapped binary never executes.
    release = integrity.verify_before_run(
        tool, path, getattr(args, f"{tool}_sha256"), getattr(args, f"{tool}_cosign_bundle"),
        getattr(args, f"{tool}_cosign_identity"), getattr(args, f"{tool}_archive"),
        getattr(args, f"{tool}_checksums"))
    info = mod.version_info(path)
    check = integrity.check_binary(
        tool, path, info["version"], getattr(args, f"{tool}_version"), getattr(args, f"{tool}_sha256"),
        getattr(args, f"{tool}_cosign_bundle"), getattr(args, f"{tool}_cosign_identity"), verified=True)
    if release.get("binary_matches_archive") and (release.get("signed") or release.get("checksums")):
        # The executable was verified through the release chain; the generic "no pinned hash" note does not apply.
        check.notes = [n for n in check.notes if "hash not verified" not in n]
        check.hash_verified = True
    if release.get("note"):
        check.notes.append(release["note"])
    scanners_meta[tool] = {"enabled": True, **info, **check.as_dict(), **({"release": release} if release else {})}
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
    data = load_json_bytes(raw, f"{tool} output")
    try:
        check_report(data, tool, f"{tool} output")
    except ReportShapeError as exc:
        raise ScannerError(str(exc)) from None
    return data


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
    # findings.csv is always written: the reports point to it and the assessor records decisions in it.
    formats = list(dict.fromkeys(["csv", *csv_set(args.formats, _FORMATS, "--formats")]))
    as_of = validate_date(args.as_of, "--as-of") or datetime.now(timezone.utc)
    release_override = validate_date(args.release_date, "--release-date")
    if args.likelihood_config or args.fail_on_likelihood:
        args.likelihood = True
    args.fail_on_set = csv_set(args.fail_on, set(FAIL_ON), "--fail-on") if args.fail_on else []
    for tool in ("trivy", "grype", "govulncheck"):  # a malformed pinned hash is an input error (exit 2)
        value = getattr(args, f"{tool}_sha256")
        if value:
            try:
                integrity.normalise_hash(value)
            except integrity.IntegrityError as exc:
                raise UsageError(f"--{tool}-sha256: {exc}") from None
    if args.release_age_max < 1:
        raise UsageError("--release-age-max must be 1 or more (use --release-age-days 0 to turn the check off)")
    if args.no_cache and args.cache_dir:
        raise UsageError("--cache-dir and --no-cache cannot be used together")
    if args.release_age_days < 0:
        raise UsageError("--release-age-days must be zero or more (0 turns the check off)")
    # B23: numbers are range-checked before any work.
    if args.grace_days < 0 or args.unshipped_days < 0:
        raise UsageError("--grace-days and --unshipped-days must be zero or more")
    if args.top < 1:
        raise UsageError("--top must be 1 or more")
    if args.timeout < 1:
        raise UsageError("--timeout must be at least 1 second")
    # A gate on a check that will not run would always pass, so it is refused up front.
    if "recent" in args.fail_on_set and (args.offline or not args.release_age_days):
        raise UsageError("--fail-on recent needs the release date check, which "
                         + ("--offline" if args.offline else "--release-age-days 0") + " turns off")
    if "mismatch" in args.fail_on_set and (args.offline or args.no_registry_check):
        raise UsageError("--fail-on mismatch needs the registry checksum check, which "
                         + ("--offline" if args.offline else "--no-registry-check") + " turns off")
    lk_cfg = likelihood.load_config(args.likelihood_config) if args.likelihood else None
    # Decisions are validated before anything is scanned, like every other input.
    args.decision_list = decisions.load(Path(args.decisions)) if args.decisions else None
    args.previous = decisions.previous_findings(Path(args.decisions)) if args.decisions else None
    for tool in ("trivy", "grype"):
        if getattr(args, f"{tool}_checksums") and not getattr(args, f"{tool}_archive"):
            raise UsageError(f"--{tool}-checksums needs --{tool}-archive (the archive it lists)")
        if getattr(args, f"{tool}_cosign_bundle") and not getattr(args, f"{tool}_archive"):
            raise UsageError(f"--{tool}-cosign-bundle needs --{tool}-archive: {tool} signs its release archive "
                             "or checksums file, not the extracted executable, so the signature is checked on the "
                             "archive and the executable compared with the one inside it")
    for flag in ("from_trivy_json", "from_grype_json", "trivy_cosign_bundle", "grype_cosign_bundle",
                 "trivy_archive", "grype_archive", "trivy_checksums", "grype_checksums"):
        val = getattr(args, flag)
        if val and not Path(val).is_file():
            raise UsageError(f"--{flag.replace('_', '-')} {val} not found")
    args.os_queries, args.sbom_info, args.input_format = None, None, None
    args.label_list = _labels(args.label)
    if args.path_kind == "sbom":
        # An SBOM is a package inventory in another format: read and validate it all, then treat it as one.
        args.inventory, args.os_queries, args.sbom_info = sbom.read(Path(args.path))
        args.path_kind = "inventory"
        nc = args.sbom_info["not_checked"]
        if nc:
            why: dict[str, int] = {}
            for c in nc:
                why[c["reason"]] = why.get(c["reason"], 0) + 1
            top = "; ".join(f"{n} {r}" for r, n in sorted(why.items(), key=lambda kv: -kv[1])[:4])
            args.sbom_warning = (f"{len(nc)} of {args.sbom_info['components']} SBOM components were not checked "
                                 f"({top}); they are listed in the report, not counted as clean")
        if not args.inventory:
            raise UsageError(f"{Path(args.path).name}: none of the {args.sbom_info['components']} components can "
                             "be checked; see the reasons with --quiet off")
        args.input_format = ", ".join(f"{k} ({v} file{'s' if v != 1 else ''})"
                                      for k, v in sorted(args.sbom_info["formats"].items()))
    if args.path_kind in ("renv", "inventory"):
        chosen, warnings = ([] if args.offline else ["osv"]), []
        if getattr(args, "sbom_warning", None):
            warnings.append(args.sbom_warning)
        if args.offline:
            raise UsageError(f"{Path(args.path).name} is checked against OSV, which needs the network; "
                             "drop --offline")
        if args.path_kind == "inventory" and args.sbom_info is None:
            args.inventory = inputs.inventory(Path(args.path))  # validates every row before any lookup
            args.input_format = "CSV inventory"
        unused = set(args.label_list)
        for e in args.inventory if args.path_kind == "inventory" else []:
            # A label the package already has (an inventory column, the SBOM's system) is kept: --label fills in.
            unused -= {k for k in args.label_list if not e["labels"].get(k)}
            e["labels"] = {**args.label_list, **{k: v for k, v in e["labels"].items() if v}}
        for k in sorted(unused):
            warnings.append(f"--label {k} has no effect: every package already has a {k} label"
                            + (" (from the SBOM)" if args.sbom_info else ""))
    else:
        chosen, warnings = _resolve_scanners(args) if (args.image or args.path) else ([], [])
    if args.label_list and args.path_kind != "inventory":
        raise UsageError("--label applies to a package inventory or SBOM (--path *.csv, *.json or a folder of "
                         "SBOMs)")
    if args.image is None and args.path is None and (args.from_trivy_json or args.from_grype_json):
        raise UsageError("--from-*-json needs --image or --path to label the report")
    warnings += _ineffective_options(args, chosen)
    # The scanners that will run must exist before anything is written (B24: no empty output folder left behind).
    for tool in ("trivy", "grype"):
        if tool in chosen and not getattr(args, f"from_{tool}_json"):
            find_executable(tool, getattr(args, f"{tool}_path"))
    out = prepare_out(args.out)
    scanned_offline = args.from_trivy_json and args.from_grype_json
    try:
        if args.path and args.path_kind not in ("renv", "inventory") and not scanned_offline:
            args.scan_target, tmp_dir = inputs.stage(Path(args.path), args.path_kind)
        return _plan_and_scan(args, chosen, out, http, warnings, formats, as_of, release_override, lk_cfg)
    finally:  # S8: the temporary copy of the artifact is removed whatever happens
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)


def _network_info(net) -> dict:
    """Requests made and cache use, so a slow or fast run can be explained."""
    if net is None:
        return {"status": "offline"}
    out: dict = {"requests": getattr(net, "requests_made", None)}
    cache = getattr(net, "cache", None)
    out["cache"] = cache.stats() if cache is not None else None
    return out


def _plan_and_scan(args, chosen, out, http, warnings, formats, as_of, release_override, lk_cfg) -> int:
    log(f"plan: {'path=' + args.path + ' (' + args.path_kind + ')' if args.path else 'image=' + (args.image or '-')} "
        f"repo={args.repo or '-'} sources={','.join(chosen) or '-'} "
        + (f"image-src={args.image_src or 'scanner default'} platform={args.platform or 'scanner default'} "
           if args.image else "")
        + f"out={out} formats={','.join(formats)}", args.quiet)

    cache = None if args.no_cache or args.offline or http else ResponseCache(
        Path(args.cache_dir).expanduser() if args.cache_dir else default_cache_dir())
    if cache is not None and (why := cache.unsafe_reason()):
        warnings.append(f"The lookup cache was not used: {why}, so its answers could have been planted. "
                        "Use a folder only you can write to (--cache-dir), or --no-cache")
        cache = None
    net = None if args.offline else (http or RequestsHttp(cache=cache))
    scanners_meta: dict = {s: {"enabled": False} for s in ("trivy", "grype", "osv")}

    # Is the artifact the file the project released? Checked against the registry before scanning.
    args.registry_result = None
    if args.path and args.path_kind == "artifact" and net and not args.no_registry_check:
        args.registry_result = registry_check.check(net, Path(args.path))
        if args.registry_result["status"] == "mismatch":
            warnings.insert(0, "ARTIFACT DOES NOT MATCH THE REGISTRY: "
                               + registry_check.summary(args.registry_result)
                               + ". Treat the file as untrusted until you know where it came from")
        elif args.registry_result["status"] == "error":
            warnings.append("Registry checksum lookup failed: " + registry_check.summary(args.registry_result))
    # 2. Scanners. Integrity failures abort; scanner failures abort (a partial scan is misleading).
    trivy_report, groups, scan_info = _scan(args, chosen, out, net, scanners_meta, warnings)
    return _assess(args, chosen, out, net, scanners_meta, warnings, groups, trivy_report, scan_info, formats,
                   as_of, release_override, lk_cfg)


def _scan(args, chosen, out, net, scanners_meta, warnings):
    groups: list = []
    trivy_report = None
    scan_info: dict = {}
    without_osv = "; only advisories classed CWE-506 by Trivy or Grype are seen"
    if "osv" in chosen or args.path_kind in ("renv", "inventory"):
        args.malicious_check = checks.state(checks.NOT_CHECKED, "OSV was not queried")
    elif args.offline:
        args.malicious_check = checks.state(checks.PARTIAL, "OSV not queried with --offline" + without_osv)
    else:
        args.malicious_check = checks.state(checks.PARTIAL, "OSV not in --scanners" + without_osv)
    if args.path_kind == "inventory":
        labels = {e["purl"]: e["labels"] for e in args.inventory}
        if net:
            try:
                found = osv_mod.scan(net, list(labels), args.os_queries)
            except HttpError as exc:
                # OSV is the only source here: a report without it would read as clean. Runtime failure: exit 1.
                raise ScannerError(f"OSV lookup failed, so the inventory could not be checked: {exc}") from None
            for f in found:
                f.labels = dict(labels.get(f.purl or "", {}))
            groups.append(found)
            scanners_meta["osv"] = {"enabled": True, "detail": f"{len(labels)} packages queried"}
            args.malicious_check = checks.state(checks.CHECKED)
        return None, groups, scan_info
    if args.path_kind == "renv":
        purls, skipped = inputs.renv_purls(Path(args.path))
        if skipped:
            warnings.append(f"{len(skipped)} renv package(s) not from CRAN were not checked (OSV's R advisories "
                            f"cover CRAN): {', '.join(skipped[:8])}{' ...' if len(skipped) > 8 else ''}")
        if net and purls:
            try:
                groups.append(osv_mod.scan(net, purls))
                scanners_meta["osv"] = {"enabled": True, "detail": f"{len(purls)} CRAN packages queried"}
                args.malicious_check = checks.state(checks.CHECKED)
            except HttpError as exc:
                # OSV is the only source for renv.lock: without it nothing was checked, so stop rather than
                # write a report that reads as clean.
                raise ScannerError(f"OSV lookup failed, so {Path(args.path).name} could not be checked: {exc}") \
                    from None
        elif not purls:
            args.malicious_check = checks.state(checks.CHECKED, "no CRAN packages to look up")
        return None, groups, scan_info
    if "trivy" in chosen:
        trivy_report = _run_or_load("trivy", trivy_mod, args, out, scanners_meta, warnings)
        f, scan_info = trivy_mod.parse(trivy_report)
        groups.append(f)
    if "grype" in chosen:
        g, _ = grype_mod.parse(_run_or_load("grype", grype_mod, args, out, scanners_meta, warnings))
        groups.append(g)
    args.reach_results = {}
    if args.reachability and trivy_report is not None:
        args.reach_results = _govulncheck(args, trivy_report, scanners_meta, warnings)
    if "osv" in chosen and trivy_report is not None and net:
        purls = osv_mod.purls_from_trivy(trivy_report)
        try:
            o = osv_mod.scan(net, purls)
            groups.append(o)
            scanners_meta["osv"] = {"enabled": True, "detail": f"{len(purls)} packages queried"}
            args.malicious_check = checks.state(
                checks.CHECKED, "" if purls else "no language packages; OSV malicious package data covers "
                                                 "language packages")
        except HttpError as exc:
            warnings.append(f"OSV lookup failed, continuing without it: {exc}")
            args.malicious_check = checks.state(checks.PARTIAL, "OSV lookup failed" + without_osv)
        if not purls:
            if any(r.get("Class") == "lang-pkgs" for r in trivy_report.get("Results") or []):
                warnings.append("Trivy found language packages but listed none in the report, so OSV had "
                                "nothing to query (was the report generated with --list-all-pkgs=false?)")
            else:
                warnings.append("No language packages in the image (OS packages only), so OSV was not queried; "
                                "Trivy and Grype cover OS packages")
    return trivy_report, groups, scan_info


def _govulncheck(args, trivy_report: dict, scanners_meta: dict, warnings: list[str]) -> dict:
    targets = sorted({r.get("Target", "") for r in trivy_report.get("Results") or []
                      if r.get("Type") == "gobinary" and r.get("Target")})
    targets = [t for t in targets if govuln_mod.safe_relpath(t)]
    if not targets:
        warnings.append("--reachability: no Go binaries in the scan, so govulncheck had nothing to check")
        return {}
    try:
        gv = govuln_mod.find(args.govulncheck_path)
    except ScannerError as exc:
        warnings.append(f"--reachability skipped: {exc}")
        return {}
    # Pinned like Trivy and Grype: hash before it runs, version after; a mismatch stops the run (S9).
    if args.govulncheck_sha256:
        integrity.verify_sha256(gv, args.govulncheck_sha256)
    try:
        info = govuln_mod.version_info(gv)
    except ScannerError as exc:
        warnings.append(f"--reachability skipped: {exc}")
        return {}
    if args.govulncheck_version and info["version"].lstrip("vV") != args.govulncheck_version.lstrip("vV"):
        raise integrity.IntegrityError(f"govulncheck version {info['version']} does not match the pinned version "
                                       f"{args.govulncheck_version}")
    scanners_meta["govulncheck"] = {"enabled": True, **info, "sha256": integrity.sha256_file(gv),
                                    "hash_verified": bool(args.govulncheck_sha256),
                                    "detail": f"{len(targets)} Go binaries"}
    results: dict = {}
    with tempfile.TemporaryDirectory(prefix="oss-intake-go-") as td:
        if args.path:
            base = Path(args.scan_target) if args.scan_target else None
            located = {t: base / t for t in targets} if base else {}
        else:
            try:
                used: dict = {}
                copied = govuln_mod.extract_from_image(args.image, targets, args.platform or None, Path(td),
                                                       args.timeout, used)
                if used.get("path"):
                    used["sha256"] = integrity.sha256_file(used["path"])
                    scanners_meta["govulncheck"]["copied_with"] = used
            except ScannerError as exc:
                warnings.append(f"--reachability skipped: {exc}")
                return {}
            located = {t: Path(td) / t.lstrip("/") for t in copied}
        for t, local in located.items():
            if not local.is_file():
                continue
            try:
                results[t] = govuln_mod.scan_binary(gv, local, args.timeout)
            except ScannerError as exc:
                warnings.append(f"govulncheck could not analyse {t}: {exc}")
    missing = len(targets) - len(results)
    if missing:
        warnings.append(f"govulncheck checked {len(results)} of {len(targets)} Go binaries; the rest could not be "
                        "copied or analysed, and their findings have no reachability evidence")
    return results


def _assess(args, chosen, out, net, scanners_meta, warnings, groups, trivy_report, scan_info, formats, as_of,
            release_override, lk_cfg):

    findings = merge.merge(*groups)
    reach_stats = reachability.apply(findings, getattr(args, "reach_results", {}) or {})
    for f in findings:
        f.conditions = conditions.extract(f.description)
    # A malicious finding (MAL- entry or CWE-506) on a package version marks every finding on it: GitHub and
    # other advisories for the same malware often do not list the MAL- ID as an alias. Malicious-package
    # entries often carry no severity; they are kept whatever --min-severity says.
    mal_keys = {(f.package, f.installed) for f in findings if f.malicious}
    for f in findings:
        if (f.package, f.installed) in mal_keys:
            f.malicious_package = True
    findings = [f for f in findings
                if f.malicious or SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[args.min_severity]]
    bad = sorted({f"{f.package}@{f.installed}" for f in findings if f.malicious})
    if bad:
        listed = ", ".join(bad[:10]) + (f" and {len(bad) - 10} more" if len(bad) > 10 else "")
        warnings.insert(0, f"MALICIOUS PACKAGE: {len(bad)} package(s) are listed as malware (OpenSSF malicious "
                           f"packages, or an advisory classed as embedded malicious code, CWE-506): {listed}. "
                           "Treat the artifact as compromised, not as a patching task")
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
        if args.path_kind != "inventory":  # an inventory has no single release to compare against
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

    age_info: dict = {"status": "skipped", "days": args.release_age_days,
                      "reason": "--offline" if not net else "--release-age-days 0", "recent": []}
    purls = _language_purls(args, trivy_report) if net and args.release_age_days else []
    if net and args.release_age_days and not purls:
        age_info = {"status": "not checked", "days": args.release_age_days, "recent": [],
                    "reason": "no package list to check (needs a Trivy scan or an inventory)"}
    elif net and args.release_age_days:
        # A date-only --as-of means the whole of that day.
        as_of_end = as_of + timedelta(days=1, seconds=-1) if args.as_of and "T" not in args.as_of else as_of
        age_info = release_age.check(net, purls, as_of_end, args.release_age_days, limit=args.release_age_max)
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
    is_latest = health.get("scanned_is_latest") if not release_override else None
    decision_info = None
    if args.decision_list is not None:
        decision_info = decisions.apply(findings, args.decision_list)
        if decision_info["ignored_malicious"]:
            warnings.append(f"{decision_info['ignored_malicious']} decision(s) to set aside a malicious package were "
                            "ignored: a malicious package is removed, not accepted")
        if decision_info["stale"]:
            warnings.append(f"{decision_info['stale']} decision(s) were made for a different installed version; they "
                            "still apply but are marked for review")
    skipped_by = {}
    for name, flag in (("kev", "no_kev"), ("exploits", "no_exploits"), ("epss", "no_epss")):
        skipped_by[name] = "--offline" if args.offline else f"--{flag.replace('_', '-')}" if getattr(args, flag) \
            else "not run"
    check_info = checks.compute(len(findings), kev_info, epss_info, exploit_info,
                                getattr(args, "malicious_check", None) or checks.state(checks.CHECKED), skipped_by)
    gap_warning = checks.warning(check_info)
    if gap_warning:
        lead = sum(1 for _ in itertools.takewhile(
            lambda w: w.startswith(("ARTIFACT DOES NOT MATCH", "MALICIOUS PACKAGE")), warnings))
        warnings.insert(lead, gap_warning)  # after the malware and tampering alerts, before everything else
    triage_info = triage.apply(findings, check_info)
    lag_m = lag.compute(findings, release_date, as_of, args.grace_days, args.unshipped_days, is_latest)
    lag_m["exploits_checked"] = checks.is_checked(check_info, "exploits") and bool(findings)
    lk = likelihood.evaluate(lk_cfg, likelihood.metrics(lag_m, health, sc)) if lk_cfg else None

    assessment = {
        "tool": {"name": "oss-intake", "version": __version__},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "as_of": as_of.isoformat(),
        "inputs": {"image": args.image, "path": args.path, "path_kind": args.path_kind, "repo": args.repo,
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
        "network": _network_info(net),
        "reachability": reach_stats if args.reachability else {"status": "skipped"},
        "lag": {**lag_m, "release_date_source": release_date_source},
        "coverage": coverage.compute(findings, looked_up=bool(net) and not args.no_fix_dates),
        "health": health,
        "scorecard": sc,
        "likelihood": lk,
        "warnings": warnings,
    }
    if args.sbom_info:
        assessment["sbom"] = args.sbom_info
    pkg_rows = None
    if args.path_kind == "inventory":
        pkg_rows = inventory_report.package_rows(args.inventory, findings)
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
    vex = decisions.openvex(findings, __version__, as_of.isoformat()) if decision_info else None
    if vex:
        (out / "openvex.json").write_text(json.dumps(vex, indent=2), encoding="utf-8")
        written.append("openvex.json")
        cdx = decisions.cyclonedx_vex(findings, __version__, as_of.isoformat())
        (out / "vex.cdx.json").write_text(json.dumps(cdx, indent=2), encoding="utf-8")
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

    sev = lag_m["by_severity"]
    print(f"findings={lag_m['total']} critical={sev['CRITICAL']} high={sev['HIGH']} "
          f"with_fix={lag_m['with_fix']} fix_before_release={lag_m['fix_available_at_release']} "
          f"fix_date_unknown={lag_m['fix_date_unknown']}"
          + (f" likelihood={lk['level']}({lk['label']},confidence={lk['confidence']})" if lk else "")
          + (f" not_checked={','.join(checks.gaps(check_info))}" if checks.gaps(check_info) else ""))
    for w in warnings:
        log(f"warning: {w}", args.quiet)
    log(f"wrote {', '.join(written)} to {out}", args.quiet)
    tripped = _gate(args.fail_on_set, findings, age_info, getattr(args, "registry_result", None))
    for t in tripped:
        log(f"--fail-on {t}: found {FAIL_ON[t]}", args.quiet, force=True)
    unknown = _gate_unknown(args.fail_on_set, age_info, getattr(args, "registry_result", None), args)
    for t, why in unknown:
        log(f"--fail-on {t}: could not be evaluated ({why}); failing rather than passing", args.quiet, force=True)
    if unknown and not tripped:
        return EXIT_ERROR
    if lk and args.fail_on_likelihood and lk["level"] and lk["level"] >= args.fail_on_likelihood:
        return EXIT_THRESHOLD
    return EXIT_THRESHOLD if tripped else EXIT_OK


def _language_purls(args, trivy_report: dict | None) -> list[str]:
    """Every language package version the run knows about, with or without findings (a compromised release is
    new and usually has no advisory yet)."""
    if getattr(args, "inventory", None) and args.path_kind == "inventory":
        return [e["purl"] for e in args.inventory]
    if trivy_report is not None:
        return osv_mod.purls_from_trivy(trivy_report)
    return []


def _gate_unknown(wanted: list[str], age_info: dict, registry: dict | None, args) -> list[tuple[str, str]]:
    """Gates whose check did not (fully) run: a CI gate must not pass because nothing was looked at."""
    out = []
    if "recent" in wanted and age_info.get("status") != "ok" and not age_info.get("recent"):
        out.append(("recent", age_info.get("reason") or f"{age_info.get('errors', 0)} lookups failed, "
                                                         f"{age_info.get('skipped_limit', 0)} over the limit"))
    if "mismatch" in wanted and args.path_kind == "artifact" and (registry or {}).get("status") == "error":
        out.append(("mismatch", "the registry lookup failed"))
    return out


def _gate(wanted: list[str], findings: list, age_info: dict, registry: dict | None) -> list[str]:
    """The --fail-on conditions met. Findings set aside (evidence or an assessor decision) do not count, except
    a malicious package, which no decision sets aside."""
    live = [f for f in findings if f.triage_group != "aside"]
    met = {
        "malicious": any(f.malicious for f in findings),
        "kev": any(f.kev for f in live),
        "act": any(f.triage_group == "act" for f in live),
        "critical": any(f.severity == "CRITICAL" for f in live),
        "high": any(f.severity in ("CRITICAL", "HIGH") for f in live),
        "recent": bool(age_info.get("recent")),
        "mismatch": bool(registry and registry.get("status") == "mismatch"),
    }
    return [w for w in wanted if met[w]]


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
    except (UsageError, inputs.InputError) as exc:
        print(f"oss-intake: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except (ScannerError, integrity.IntegrityError, likelihood.ConfigError, HttpError, OSError) as exc:
        print(f"oss-intake: error: {exc}", file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
