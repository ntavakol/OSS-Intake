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

from . import (
    __version__,
    assessment,
    decisions,
    inputs,
    integrity,
    likelihood,
    openvsx,
    registry_check,
    sbom,
    scanning,
    vscode,
)
from .http import Http, HttpError, RequestsHttp, ResponseCache, default_cache_dir, folder_write_reason
from .options import (  # noqa: F401  (validate_*, image_tag and the _-prefixed names: kept importable from cli)
    EXIT_ERROR,
    EXIT_OK,
    EXIT_THRESHOLD,
    EXIT_USAGE,
    FAIL_ON,
    FORMATS,
    OUTPUT_FILES,
    SCANNERS,
    SUBCOMMANDS,
    UsageError,
    build_parser,
    csv_set,
    image_tag,
    ineffective_options,
    labels,
    log,
    refuse_gates_without_their_check,
    resolve_scanners,
    validate_date,
    validate_image,
    validate_repo,
)
from .scanners import ScannerError, set_extra_env
from .scanners import grype as grype_mod
from .scanners import trivy as trivy_mod

# Names the tests and scripts use from cli, from before options.py.
_FORMATS, _SCANNERS, _labels = FORMATS, SCANNERS, labels
_same_image = scanning.same_image


def prepare_out(path: str) -> Path:
    out = Path(path).expanduser()
    # A symbolic link where a report goes would be followed and its target overwritten: refused before any work.
    links = [n for n in ("raw", ".oss-intake-files.json", *OUTPUT_FILES) if (out / n).is_symlink()]
    if links:
        raise UsageError(f"--out {out} has a symbolic link where a report is written ({', '.join(links)}); "
                         "remove it, or choose another folder")
    try:
        out.mkdir(parents=True, exist_ok=True)
        (out / "raw").mkdir(exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=out, prefix=".write-test-", delete=True):
            pass
    except OSError as exc:
        raise UsageError(f"--out {out} is not writable: {exc}") from None
    return out


# ---------------------------------------------------------------- commands

def cmd_doctor(args: argparse.Namespace) -> int:
    rows = []
    for tool, mod in (("trivy", trivy_mod), ("grype", grype_mod)):
        try:
            path = scanning.find_executable(tool, getattr(args, f"{tool}_path"))
            digest = integrity.sha256_file(path)  # recorded before the binary is run
            embedded = integrity.embedded_version(tool, path)
            bad = integrity.known_bad_entry(tool, embedded) if embedded else None
            if bad:
                rows.append({"tool": tool, "path": path, "version": embedded, "sha256": digest, "known_bad": True,
                             "known_bad_reference": bad.get("reference"),
                             "note": "not run: the version was read from the binary's Go build information"})
                continue
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


def validate_scanner_env(pat: str) -> None:
    """A --scanner-env value: a variable name or a pattern of letters, digits, _, * and ?, not wildcards alone."""
    if not re.fullmatch(r"[A-Za-z0-9_*?()]+", pat or "") or pat.strip("*?") == "":
        raise UsageError(f"--scanner-env {pat!r}: name an environment variable or a pattern such as 'AWS_*' "
                         "(letters, digits, _, * and ?; not * alone)")


def cmd_scan(args: argparse.Namespace, http: Http | None = None) -> int:
    """--extension is downloaded, once every option has been checked, to a temporary folder and then assessed as
    --path on the .vsix; the folder is removed whatever happens."""
    args.extension = getattr(args, "extension", None)
    args.ext_tmp = None
    if args.extension:
        if args.image or args.path or args.package:
            raise UsageError("give --extension on its own, not with --image, --path or --package")
        if args.offline:
            raise UsageError("--extension downloads from Open VSX, which needs the network; drop --offline")
        try:
            openvsx.parse_id(args.extension)
        except ValueError as exc:
            raise UsageError(f"--extension {args.extension}: {exc}") from None
        args.ext_tmp = Path(tempfile.mkdtemp(prefix="oss-intake-ext-"))
    try:
        return _cmd_scan(args, http)
    finally:
        if args.ext_tmp:
            shutil.rmtree(args.ext_tmp, ignore_errors=True)


def _cmd_scan(args: argparse.Namespace, http: Http | None = None) -> int:
    # 1. Validate everything before doing any work.
    if not args.image and not args.repo and not args.path and not args.package and not args.extension:
        raise UsageError("give --image, --path, --package or --repo")
    if args.image and args.path:
        raise UsageError("give --image or --path, not both")
    if args.package and (args.image or args.path):
        raise UsageError("give --package on its own, not with --image or --path")
    if args.image:
        args.image = validate_image(args.image)
    args.path_kind, args.scan_target, tmp_dir, compare_tmp = None, None, None, None
    if args.extension:
        args.path_kind = "vscode"  # downloaded after every other check (below, before staging)
    if args.path:
        p = Path(args.path).expanduser()
        if not p.exists():
            raise UsageError(f"--path {args.path} not found")
        if not (p.is_file() or p.is_dir()):  # a device such as /dev/zero would be copied until the disk fills
            raise UsageError(f"--path {args.path} is not a file or folder")
        args.path = str(p)
        args.path_kind = inputs.classify(p)
    if args.compare_with:
        old = Path(args.compare_with).expanduser()
        if args.path_kind != "vscode" or (args.path and not vscode.is_single(Path(args.path))):
            raise UsageError("--compare-with needs --path to one VS Code extension (a .vsix or its folder)")
        if not old.exists() or not vscode.is_single(old):
            raise UsageError(f"--compare-with {args.compare_with}: not a VS Code extension (a .vsix or its folder)")
        args.compare_with = str(old)
    if args.repo:
        args.repo = validate_repo(args.repo)
    # findings.csv is always written: the reports point to it and the assessor records decisions in it.
    formats = list(dict.fromkeys(["csv", *csv_set(args.formats, FORMATS, "--formats")]))
    if "pdf" in formats:
        from . import report_pdf

        if pdf_missing := report_pdf.missing():
            raise UsageError(pdf_missing)
    # Without --as-of, today is the assessor's local date (the report shows as_of's date), not UTC's, unless --utc
    # asks for UTC throughout (a team across time zones, or a pipeline comparing runs).
    now = datetime.now(timezone.utc)
    as_of = validate_date(args.as_of, "--as-of") or (now if args.utc else now.astimezone())
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
    for pat in args.scanner_env:
        validate_scanner_env(pat)
    set_extra_env(args.scanner_env)  # also when cmd_scan is called without main()
    if args.trust_cache_dir and not args.cache_dir:
        raise UsageError("--trust-cache-dir needs --cache-dir: the default cache folder is in your user profile")
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
    for gate in ("recent", "unknown-age"):
        if gate in args.fail_on_set and (args.offline or not args.release_age_days):
            raise UsageError(f"--fail-on {gate} needs the release date check, which "
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
        cert, sig = getattr(args, f"{tool}_cosign_certificate"), getattr(args, f"{tool}_cosign_signature")
        if bool(cert) != bool(sig):
            raise UsageError(f"--{tool}-cosign-certificate and --{tool}-cosign-signature go together")
        if cert and getattr(args, f"{tool}_cosign_bundle"):
            raise UsageError(f"--{tool}-cosign-bundle or --{tool}-cosign-certificate with a signature, not both")
        if cert and args.offline:
            raise UsageError(f"--{tool}-cosign-certificate is checked against the Sigstore transparency log, which "
                             "--offline does not reach; use a bundle, which holds its own log entry")
        if cert and not getattr(args, f"{tool}_checksums"):
            raise UsageError(f"--{tool}-cosign-certificate needs --{tool}-checksums and --{tool}-archive: the "
                             "certificate and signature are for the release checksums file")
        if getattr(args, f"{tool}_cosign_bundle") and not getattr(args, f"{tool}_archive"):
            raise UsageError(f"--{tool}-cosign-bundle needs --{tool}-archive: {tool} signs its release archive "
                             "or checksums file, not the extracted executable, so the signature is checked on the "
                             "archive and the executable compared with the one inside it")
    for flag in ("from_trivy_json", "from_grype_json", "trivy_cosign_bundle", "grype_cosign_bundle",
                 "trivy_archive", "grype_archive", "trivy_checksums", "grype_checksums", "trivy_cosign_certificate",
                 "grype_cosign_certificate", "trivy_cosign_signature", "grype_cosign_signature"):
        val = getattr(args, flag)
        if val and not Path(val).is_file():
            raise UsageError(f"--{flag.replace('_', '-')} {val} not found")
    args.os_queries, args.sbom_info, args.input_format = None, None, None
    args.label_list = labels(args.label)
    if args.package:
        try:
            args.inventory = inputs.packages(args.package)
        except inputs.InputError as exc:
            raise UsageError(str(exc)) from None
        args.path_kind = "inventory"
        args.input_format = f"{len(args.inventory)} package{'s' if len(args.inventory) != 1 else ''} (--package)"
    if args.path_kind == "sbom":
        # An SBOM is a package inventory in another format: read and validate it all, then treat it as one.
        args.inventory, args.os_queries, args.sbom_info = sbom.read(Path(args.path))
        args.sbom_extensions = args.sbom_info.pop("vscode_extensions", [])
        args.path_kind = "inventory"
        nc = args.sbom_info["not_checked"]
        if nc:
            why: dict[str, int] = {}
            for c in nc:
                why[c["reason"]] = why.get(c["reason"], 0) + 1
            top = "; ".join(f"{n} {r}" for r, n in sorted(why.items(), key=lambda kv: -kv[1])[:4])
            args.sbom_warning = (f"{len(nc)} of {args.sbom_info['components']} SBOM components were not checked "
                                 f"({top}); they are listed in the report, not counted as clean")
        if not args.inventory and not args.sbom_extensions:
            raise UsageError(f"{Path(args.path).name}: none of the {args.sbom_info['components']} components can "
                             "be checked; see the reasons with --quiet off")
        args.input_format = ", ".join(f"{k} ({v} file{'s' if v != 1 else ''})"
                                      for k, v in sorted(args.sbom_info["formats"].items()))
    if args.path_kind in ("renv", "inventory"):
        chosen, warnings = ([] if args.offline else ["osv"]), []
        if getattr(args, "sbom_warning", None):
            warnings.append(args.sbom_warning)
        if args.offline:
            raise UsageError(f"{Path(args.path).name if args.path else '--package'} is checked against OSV, "
                             "which needs the network; drop --offline")
        if args.path_kind == "inventory" and args.sbom_info is None and not args.package:
            args.inventory = inputs.inventory(Path(args.path))  # validates every row before any lookup
            args.input_format = "Excel inventory" if Path(args.path).suffix.lower() == ".xlsx" else "CSV inventory"
        unused = set(args.label_list)
        for e in args.inventory if args.path_kind == "inventory" else []:
            # A label the package already has (an inventory column, the SBOM's system) is kept: --label fills in.
            unused -= {k for k in args.label_list if not e["labels"].get(k)}
            e["labels"] = {**args.label_list, **{k: v for k, v in e["labels"].items() if v}}
        for k in sorted(unused):
            warnings.append(f"--label {k} has no effect: every package already has a {k} label"
                            + (" (from the SBOM)" if args.sbom_info else ""))
    else:
        chosen, warnings = resolve_scanners(args) if (args.image or args.path or args.extension) else ([], [])
    if args.label_list and args.path_kind != "inventory":
        raise UsageError("--label applies to a package inventory or SBOM, or to --package")
    refuse_gates_without_their_check(args, chosen)
    if args.image is None and args.path is None and not args.extension and (args.from_trivy_json
                                                                             or args.from_grype_json):
        raise UsageError("--from-*-json needs --image or --path to label the report")
    warnings += ineffective_options(args, chosen)
    # The scanners that will run must exist before anything is written (B24: no empty output folder left behind).
    for tool in ("trivy", "grype"):
        if tool in chosen and not getattr(args, f"from_{tool}_json"):
            scanning.find_executable(tool, getattr(args, f"{tool}_path"))
    scanned_offline = args.from_trivy_json and args.from_grype_json
    if args.path_kind == "vscode":
        if args.extension:  # every option is valid: now it is worth downloading
            vsix, args.extension_download = openvsx.download(http or RequestsHttp(), args.extension, args.ext_tmp)
            args.path = str(vsix)
        # A .vsix is unpacked here, before anything is written: one that breaks a limit is refused (exit 2). The
        # extension's own files are read even when the scanners' reports are imported.
        args.scan_target, tmp_dir = inputs.stage(Path(args.path), "vscode")
        if args.compare_with:
            try:
                args.compare_target, compare_tmp = inputs.stage(Path(args.compare_with), "vscode")
            except BaseException:
                if tmp_dir:
                    shutil.rmtree(tmp_dir, ignore_errors=True)
                raise
    try:
        out = prepare_out(args.out)
        args.raw_written = []  # the raw scanner files this run writes; _remove_stale keeps only these
        if args.path and args.path_kind not in ("renv", "inventory", "vscode") and not scanned_offline:
            args.scan_target, tmp_dir = inputs.stage(Path(args.path), args.path_kind)
        return _plan_and_scan(args, chosen, out, http, warnings, formats, as_of, release_override, lk_cfg)
    finally:  # S8: the temporary copy of the artifact is removed whatever happens
        for t in (tmp_dir, compare_tmp):
            if t:
                shutil.rmtree(t, ignore_errors=True)


def _private_paths(reason: str, folder: Path) -> str:
    """A folder check's reason as the reports may show it: the folder (or the one above it) it starts with is given
    as the reports give every local path, under the home folder as ~/..., elsewhere by its name only
    (assessment.shown_path), not as an absolute path."""
    for p in [folder, *folder.parents]:
        if reason.startswith(f"{p} "):
            return f"{assessment.shown_path(p)} {reason[len(str(p)) + 1:]}"
    return reason


def _plan_and_scan(args, chosen, out, http, warnings, formats, as_of, release_override, lk_cfg) -> int:
    target = ("path=" + args.path + " (" + args.path_kind + ")" if args.path
              else f"packages={len(args.inventory)}" if args.package else "image=" + (args.image or "-"))
    log(f"plan: {target} "
        f"repo={args.repo or '-'} sources={','.join(chosen) or '-'} "
        + (f"image-src={args.image_src or 'scanner default'} platform={args.platform or 'scanner default'} "
           if args.image else "")
        + f"out={out} formats={','.join(formats)}", args.quiet)

    cache = None if args.no_cache or args.offline or http else ResponseCache(
        Path(args.cache_dir).expanduser() if args.cache_dir else default_cache_dir())
    if cache is not None and (why := cache.unsafe_reason(operator_trusted=args.trust_cache_dir)):
        warnings.append(f"The lookup cache was not used: {_private_paths(why, cache.folder)}, so its answers could "
                        "have been planted. "
                        "Use a folder only you can write to (--cache-dir), or --no-cache")
        cache = None
    elif cache is not None and args.trust_cache_dir and cache.unsafe_reason():
        log(f"using the cache in {cache.folder} on your word (--trust-cache-dir): it is outside your user profile",
            args.quiet)
        cache.operator_trusted = True
    if why := folder_write_reason(out.resolve()):
        # Warned, not refused (Ned, 8 Nov): reports are written by rename, so nothing is written through a planted
        # link; what is left is another user replacing or deleting the reports after the run.
        shown = _private_paths(why, out.resolve())
        warnings.append(f"The output folder is not private: {shown}, so another user could replace or delete these "
                        "reports after the run. Use --out with a folder only you can write to")
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
    # VS Code extensions: the removal list and what their own files show; nothing in them is run.
    args.extension_info = None
    if args.path_kind == "vscode":
        args.extension_info = vscode.assess(Path(args.scan_target), net, staged=Path(args.path).is_file())
        if getattr(args, "extension_download", None):
            args.extension_info["download"] = args.extension_download
        if args.compare_with:
            new = args.extension_info["extensions"][0]
            old = vscode.assess(Path(args.compare_target), None, staged=Path(args.compare_with).is_file())
            diff = vscode.compare(old["extensions"][0], new)
            args.extension_info["changes"] = diff
            warnings.extend(vscode.change_warnings(diff, new["id"]))
    elif getattr(args, "sbom_extensions", None):
        # VS Code extensions an SBOM lists (the osquery collector's vscode_extensions): the removal list and Open
        # VSX by ID and version, for each system that has them; their files are not seen.
        args.extension_info = vscode.assess_listed(args.sbom_extensions, net)
    if args.extension_info:
        alerts, more = vscode.warnings(args.extension_info)
        warnings[:0] = alerts
        warnings.extend(more)
        # 2. Scanners. Integrity failures abort; scanner failures abort (a partial scan is misleading).
    trivy_report, groups, scan_info = scanning.run(args, chosen, out, net, scanners_meta, warnings)
    return assessment.assess(args, chosen, out, net, scanners_meta, warnings, groups, trivy_report, scan_info, formats,
                   as_of, release_override, lk_cfg)


def main(argv: list[str] | None = None, http: Http | None = None) -> int:
    """Entry point: parse argv (scan is assumed when no subcommand is given) and run doctor, verify or scan.
    Returns the exit code: EXIT_USAGE (2) with no command or on a usage or input error, EXIT_ERROR (1) on a scanner,
    integrity, likelihood config, HTTP or OS error; each error is printed to stderr."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] not in SUBCOMMANDS and argv[0] not in ("-h", "--help", "--version"):
        argv.insert(0, "scan")  # 'oss-intake --image ...' works without the subcommand
    parser = build_parser()
    args = parser.parse_args(argv)
    set_extra_env(getattr(args, "scanner_env", None))  # this run's only, also when main() is called again
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
    except Exception as exc:  # noqa: BLE001 - the last resort: input nothing above expected, never a traceback
        # A run that fails this way assessed nothing, so it exits 1 like any check that could not run (never 0).
        # OSS_INTAKE_DEBUG=1 shows the traceback, for a bug report.
        if os.environ.get("OSS_INTAKE_DEBUG"):
            raise
        print(f"oss-intake: error: unexpected {type(exc).__name__}: {exc}. This is a bug in oss-intake: please "
              "report it at https://github.com/ntavakol/OSS-Intake/issues (OSS_INTAKE_DEBUG=1 shows the details)",
              file=sys.stderr)
        return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
