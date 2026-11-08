"""Command line options: the parser, the checks on option values, and which scanners a run uses.

Everything here runs before any work is done, so a bad option is refused (exit 2, UsageError) before anything is
scanned, looked up or written."""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

from . import __version__, inputs, inventory_report, lag, release_age
from .models import SEVERITY_ORDER, parse_datetime

# Exit codes: 0 clean, 1 a scanner, integrity, configuration, HTTP or OS error (or a gate that could not be
# evaluated), 2 a usage or input error, 3 a --fail-on or --fail-on-likelihood gate met.
EXIT_OK, EXIT_ERROR, EXIT_USAGE, EXIT_THRESHOLD = 0, 1, 2, 3

FAIL_ON = {
    "malicious": "a malicious package",
    "kev": "a finding in CISA KEV",
    "act": "a finding in Act now",
    "critical": "a critical finding",
    "high": "a high or critical finding",
    "recent": "a package version published within --release-age-days",
    "unknown-age": "a package version whose release date could not be found (not on deps.dev, or not indexed "
                   "yet, as for a release only hours old), so it could not be checked for being new",
    "mismatch": "an artifact that does not match its registry checksum",
    "unchecked": "an SBOM component or renv.lock package that could not be checked (a type no source covers, no "
                 "version, or not from CRAN), so a clean result would not cover it",
}


# Docker reference grammar, simplified. Anchored and cannot start with '-', which also
# prevents a crafted value being read by the scanner as a command line option.
_IMAGE_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?(?::[0-9]{1,5})?/)?"
    r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*(?:/[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*)*"
    r"(?::[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})?(?:@sha256:[a-f0-9]{64})?$"
)


_REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/[A-Za-z0-9._-]{1,100}$")


FORMATS = {"csv", "md", "json", "html", "sarif"}
# Every file a scan writes into --out. One the last run wrote (as its manifest, .oss-intake-files.json, says) that
# this run did not write is removed at the end, so it cannot be taken for a current result; nothing else is
# touched.
OUTPUT_FILES = ("findings.csv", "packages.csv", "package-systems.csv", "executive-summary.html", "openvex.json",
                "vex.cdx.json", "summary.md", "assessment.json", "report.html",
                "findings.sarif", "raw/trivy.json", "raw/grype.json", "raw/sbom.cdx.json")


SCANNERS = {"trivy", "grype", "osv"}


SUBCOMMANDS = {"scan", "doctor", "verify"}


class UsageError(Exception):
    pass


def log(msg: str, quiet: bool = False, force: bool = False) -> None:
    if force or not quiet:
        print(f"[oss-intake] {msg}", file=sys.stderr)


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


_SEGMENT = r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})"
_GITLAB_RE = re.compile(rf"^gitlab\.com/{_SEGMENT}(?:/{_SEGMENT}){{1,19}}$")
_CODEBERG_RE = re.compile(rf"^codeberg\.org/{_SEGMENT}/{_SEGMENT}$")


def validate_repo(value: str) -> str:
    """--repo as owner/name for GitHub (with or without github.com/), or gitlab.com/group[/subgroup]/name or
    codeberg.org/owner/name, which keep their host (forge_of tells them apart)."""
    v = re.sub(r"^https?://", "", value.strip()).removesuffix(".git").strip("/")
    v = re.sub(r"^(www\.)?github\.com/", "", v)
    if _GITLAB_RE.match(v) or _CODEBERG_RE.match(v):
        return v
    if not _REPO_RE.match(v):
        raise UsageError(f"--repo '{value}' must be a repository as owner/name (GitHub), gitlab.com/group/name or "
                         "codeberg.org/owner/name")
    return v


def forge_of(repo: str) -> str:
    """'github', 'gitlab' or 'codeberg' for a --repo value validate_repo accepted."""
    return "gitlab" if repo.startswith("gitlab.com/") else "codeberg" if repo.startswith("codeberg.org/") else "github"


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
    s.add_argument("--package", action="append", default=[], metavar="ECOSYSTEM:NAME@VERSION",
                   help="check one package version, e.g. npm:chalk@5.6.1 or pkg:pypi/django@2.2.0 (repeatable); "
                        "no scanner needed: checked against OSV like an inventory")
    s.add_argument("--repo", help="the project's repository for release cadence and Scorecard: owner/name on "
                                  "GitHub, or gitlab.com/group/name, or codeberg.org/owner/name")
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
        s.add_argument(f"--{tool}-cosign-certificate", metavar="FILE",
                       help=f"instead of a bundle: the signing certificate for --{tool}-checksums (Grype publishes "
                            f"checksums.txt.pem), with --{tool}-cosign-signature; checked against the Sigstore "
                            "transparency log, so it needs the network")
        s.add_argument(f"--{tool}-cosign-signature", metavar="FILE",
                       help=f"the signature that goes with --{tool}-cosign-certificate (Grype publishes "
                            "checksums.txt.sig)")
        s.add_argument(f"--{tool}-cosign-identity", help="certificate identity regexp override")
        s.add_argument(f"--{tool}-arg", action="append", default=[], metavar="ARG",
                       help=f"extra argument passed to {tool} (repeatable), e.g. --{tool}-arg=--db-repository=...")
        s.add_argument(f"--from-{tool}-json", metavar="FILE",
                       help=f"use an existing {tool} JSON report instead of running {tool}")
    s.add_argument("--release-tag", help="the release tag (on GitHub, GitLab or Codeberg) the input corresponds to")
    s.add_argument("--release-date", help="release date (YYYY-MM-DD) to use for lag, overrides GitHub")
    s.add_argument("--grace-days", type=int, default=lag.DEFAULT_GRACE_DAYS,
                   help="a fix must predate the release by this many days to count as missed (default 14)")
    s.add_argument("--unshipped-days", type=int, default=lag.DEFAULT_UNSHIPPED_DAYS,
                   help="days a fix must be public, with no newer release, to count as unshipped (default 90)")
    s.add_argument("--no-image-date", action="store_true",
                   help="do not use the image build date: no fall back to it when no release date is known, and "
                        "no OS package lag against a rebuild")
    s.add_argument("--include-kernel-headers", action="store_true",
                   help="for a container image, count kernel CVEs on kernel header packages (linux-libc-dev...) in lag "
                        "and likelihood; for other targets they always count")
    s.add_argument("--as-of", help="assessment date (YYYY-MM-DD) for reproducible reports; default today")
    s.add_argument("--utc", action="store_true",
                   help="date the assessment by today in UTC, not your local date (the generated time is always "
                        "UTC); no effect with --as-of")
    s.add_argument("--min-severity", default="UNKNOWN", type=str.upper, choices=list(SEVERITY_ORDER),
                   help="leave findings below this severity out of the reports (malicious ones, those in Act now and "
                        "those whose details could not be loaded are kept; --fail-on and likelihood still see every "
                        "finding)")
    s.add_argument("--formats", default="csv,md,json,html",
                   help="comma list of csv,md,json,html,sarif (findings.csv is always written; sarif, for "
                        "code-scanning dashboards, only when asked for)")
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
                   help="skip looking up each vulnerable package's latest release on deps.dev for the upgrade "
                        "comparison (one request per package); the minimum fix version is still checked")
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
    s.add_argument("--max-db-age-days", type=int, default=None, metavar="N",
                   help="stop the run (exit 1) when the vulnerability database Trivy or Grype used is older than N "
                        "days, or its age cannot be told: findings from an old database miss recent advisories. "
                        "Judged after the scan's own update. Off by default; not for an imported Trivy report")
    s.add_argument("--release-age-max", type=int, default=release_age.MAX_LOOKUPS, metavar="N",
                   help=f"look up release dates for at most N package versions, after duplicates are merged "
                        f"(default {release_age.MAX_LOOKUPS}); the rest are reported as not checked")
    s.add_argument("--cache-dir", metavar="DIR",
                   help="keep slowly changing lookups (advisory details for a day, release dates for 30 days) "
                        "here between runs (default: the user cache folder)")
    s.add_argument("--scanner-env", action="append", default=[], metavar="NAME",
                   help="Pass this environment variable on to the scanners and helpers oss-intake starts (a pattern "
                        "such as 'AWS_*' is allowed; repeatable). They get only what they need otherwise, so "
                        "registry credentials from the environment (ECR, ACR, GCR) need this. Never the GitHub "
                        "token")
    s.add_argument("--trust-cache-dir", action="store_true",
                   help="Windows: use --cache-dir outside your user profile, confirming that only you can write to "
                        "it. What the folder's permissions show is not overridden, on Windows or elsewhere")
    s.add_argument("--no-cache", action="store_true",
                   help="fetch everything fresh and keep nothing; what affects a version is always fetched fresh")
    s.add_argument("--timeout", type=int, default=1800, help="per scanner timeout in seconds (default 1800)")
    s.add_argument("--top", type=int, default=25, help="findings listed in the summary (default 25)")
    s.add_argument("--quiet", action="store_true", help="only print errors and the final summary")

    d = sub.add_parser("doctor", help="show scanner paths, versions, hashes and known-bad status", allow_abbrev=False)
    d.add_argument("--trivy-path", help="explicit path to the trivy executable")
    d.add_argument("--grype-path", help="explicit path to the grype executable")

    v = sub.add_parser("verify", help="verify a downloaded file against a checksums file, hash or cosign bundle",
                       allow_abbrev=False)
    v.add_argument("--file", required=True, help="the downloaded file to check")
    g = v.add_mutually_exclusive_group(required=True)
    g.add_argument("--checksums", help="sha256sum-style checksums file (e.g. trivy_0.76.1_checksums.txt)")
    g.add_argument("--sha256", help="expected SHA-256")
    v.add_argument("--name", help="entry name in the checksums file (default: the file's name)")
    v.add_argument("--cosign-bundle", help="also verify a Sigstore bundle with cosign")
    v.add_argument("--cosign-identity", help="certificate identity regexp")
    return p


_LABEL_KEY = re.compile(r"^[a-z][a-z0-9_ -]{0,39}$")


def labels(values: list[str]) -> dict[str, str]:
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


def ineffective_options(args, chosen: list[str]) -> list[str]:
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
        pins = [f"--{t}-{o.replace('_', '-')}" for o in ("sha256", "version", "archive", "checksums", "cosign_bundle",
                                                             "cosign_certificate", "cosign_signature")
                if getattr(args, f"{t}_{o}")]
        if pins and t not in run_live:
            out.append(f"{', '.join(pins)} {'has' if len(pins) == 1 else 'have'} no effect: {t} does not run")
    gv = [f"--govulncheck-{o}" for o in ("path", "sha256", "version") if getattr(args, f"govulncheck_{o}")]
    if gv and not args.reachability:
        out.append(f"{', '.join(gv)} {'has' if len(gv) == 1 else 'have'} no effect without --reachability")
    if args.include_kernel_headers and not args.image and getattr(args, "path_kind", "") != "inventory":
        out.append("--include-kernel-headers has no effect: kernel header CVEs are set aside only for a container "
                   "image, so on this target they already count")
    if args.trust_cache_dir and sys.platform != "win32":
        out.append("--trust-cache-dir has no effect here: folder permissions are read on this system, and what "
                   "they show is not overridden")
    return out


def refuse_gates_without_their_check(args: argparse.Namespace, chosen: list[str]) -> None:
    """A gate on a check that will not run would always pass (or always fail), so it is refused up front."""
    wanted = set(args.fail_on_set)
    if wanted and not (args.image or args.path or args.package):
        raise UsageError("--fail-on needs packages to check: give --image, --path or --package")
    kev_off = "--offline" if args.offline else "--no-kev" if args.no_kev else ""
    for gate in ("kev", "act"):
        if gate in wanted and kev_off:
            raise UsageError(f"--fail-on {gate} needs the CISA KEV check, which {kev_off} turns off")
    if "mismatch" in wanted and not (args.path and args.path_kind == "artifact"):
        # An image, --package, a folder, lockfile, SBOM or package list has no single file to compare.
        what = Path(args.path).name if args.path else ("an image" if args.image else "--package")
        raise UsageError(f"--fail-on mismatch needs a single file to compare with its registry (a JAR, WAR, wheel, "
                         f"sdist or npm .tgz); {what} is not one")
    if args.max_db_age_days is not None:
        if args.max_db_age_days < 0:
            raise UsageError("--max-db-age-days must be zero or more")
        if args.from_trivy_json:
            raise UsageError("--max-db-age-days cannot be checked for an imported Trivy report (--from-trivy-json): "
                             "the report does not say how old Trivy's database was")
        if not {"trivy", "grype"} & set(chosen):
            raise UsageError("--max-db-age-days needs Trivy or Grype: no scanner database is used on this run")
    if "unchecked" in wanted and not (getattr(args, "sbom_info", None) is not None or args.path_kind == "renv"):
        # Scanners do not say what they could not read in an image or folder, so the gate could never be met.
        raise UsageError("--fail-on unchecked needs an SBOM or an renv.lock (--path): only they list what could not "
                         "be checked")
    osv_off = args.path_kind not in ("renv", "inventory") and "osv" not in chosen
    for gate in ("malicious", "act"):
        if gate in wanted and osv_off:
            raise UsageError(f"--fail-on {gate} needs OSV malicious package data: "
                             + ("--offline turns it off" if args.offline else "add osv to --scanners"))


def resolve_scanners(args: argparse.Namespace) -> tuple[list[str], list[str]]:
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
        chosen = csv_set(args.scanners, SCANNERS, "--scanners")
        if "osv" in chosen and args.offline:
            raise UsageError("--scanners includes osv but --offline was given")
    if "osv" in chosen and "trivy" not in chosen:
        raise UsageError("osv needs the package list from trivy; include trivy or drop osv")
    return chosen, warnings
