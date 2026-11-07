"""Running the scanners, or loading their imported reports, and querying OSV: stage 2 of a scan.

Every check on a scanner binary (pinned hash, signature, release archive, known-bad version) happens before it
runs. A scanner that fails stops the run (exit 1): a partial scan would read as fewer findings. OSV is the only
source for an inventory, SBOM, package list or renv.lock, so a failed lookup stops those runs too."""

from __future__ import annotations

import argparse
import tempfile
from pathlib import Path

from . import checks, inputs, integrity
from .http import HttpError
from .options import UsageError, log
from .scanners import ReportShapeError, ScannerError, check_report, find_executable, load_json_bytes
from .scanners import govulncheck as govuln_mod
from .scanners import grype as grype_mod
from .scanners import osv as osv_mod
from .scanners import trivy as trivy_mod

__all__ = ["find_executable", "image_parts", "language_purls", "parse_report", "run", "run_govulncheck",
           "run_or_load", "same_image"]


def image_parts(ref: str) -> tuple[str, str, str]:
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


def same_image(a: str, b: str) -> bool:
    """False only when the two references are known to differ: another repository, two different digests, or
    two different tags. A tag on one side and only a digest on the other cannot be compared, so it is not flagged."""
    (na, ta, da), (nb, tb, db) = image_parts(a), image_parts(b)
    if na != nb:
        return False
    if da and db:
        return da == db
    if da or db:
        return True if not (ta and tb) else ta == tb
    return (ta or "latest") == (tb or "latest")


def run_or_load(tool: str, mod, args: argparse.Namespace, out: Path, scanners_meta: dict,
                 warnings: list[str] | None = None) -> dict:
    loaded = getattr(args, f"from_{tool}_json")
    if loaded:
        try:
            inputs.check_size(Path(loaded), inputs.MAX_REPORT_BYTES, f"--from-{tool}-json")
        except inputs.InputError as exc:
            raise UsageError(str(exc)) from None
        try:
            data = load_json_bytes(Path(loaded).read_bytes(), f"--from-{tool}-json {Path(loaded).name}")
            check_report(data, tool, f"--from-{tool}-json {Path(loaded).name}")
        except (ReportShapeError, ScannerError) as exc:
            raise UsageError(str(exc)) from None
        named = (data.get("ArtifactName") if tool == "trivy"
                 else ((data.get("source") or {}).get("target") or {}).get("userInput")
                 if isinstance((data.get("source") or {}).get("target"), dict) else None)
        if named and args.image and not same_image(str(named), args.image) and warnings is not None:
            warnings.append(f"The imported {tool.capitalize()} report is for {named}, but the report is labelled "
                            f"{args.image} (--image); check that the right file was imported")
        scanners_meta[tool] = {"enabled": True, "detail": f"imported from {Path(loaded).name}", "imported": True}
        return data
    path = integrity.private_copy(find_executable(tool, getattr(args, f"{tool}_path")))
    # A pinned hash or signature is checked before the binary runs at all, so a swapped binary never executes;
    # it is checked on a copy only this run can change, which is also what runs (private_copy).
    release = integrity.verify_before_run(
        tool, path, getattr(args, f"{tool}_sha256"), getattr(args, f"{tool}_cosign_bundle"),
        getattr(args, f"{tool}_cosign_identity"), getattr(args, f"{tool}_archive"),
        getattr(args, f"{tool}_checksums"))
    integrity.refuse_known_bad_before_run(tool, path)  # from the file's Go build info, before it runs
    info = mod.version_info(path)
    check = integrity.check_binary(
        tool, path, info["version"], getattr(args, f"{tool}_version"), getattr(args, f"{tool}_sha256"),
        getattr(args, f"{tool}_cosign_bundle"), getattr(args, f"{tool}_cosign_identity"), verified=True)
    unsigned = bool(release.get("binary_matches_archive") and release.get("checksums")
                    and not release.get("signed") and not check.hash_verified)
    if release.get("binary_matches_archive") and release.get("signed"):
        # The executable was verified through a signed release chain; the generic "no pinned hash" note does not
        # apply. A checksums file nothing signed is not enough: it could have been swapped with the archive.
        check.notes = [n for n in check.notes if "hash not verified" not in n]
        check.hash_verified = True
    elif unsigned:
        check.notes = [n for n in check.notes if "hash not verified" not in n]  # the release note says why
    if release.get("note"):
        check.notes.append(release["note"])
    scanners_meta[tool] = {"enabled": True, **info, **check.as_dict(), **({"release": release} if release else {}),
                           **({"hash_unsigned": True} if unsigned else {})}
    scanners_meta[tool]["path"] = Path(path).name  # identified by version and SHA-256, not where it is installed
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
    raw_written = getattr(args, "raw_written", None)
    if raw_written is not None:
        raw_written.append(f"raw/{tool}.json")
    if tool == "trivy" and args.sbom and not args.path:
        (out / "raw" / "sbom.cdx.json").write_bytes(
            mod.sbom(path, args.image, args.image_src, args.trivy_arg, args.timeout, args.platform or None))
        if raw_written is not None:
            raw_written.append("raw/sbom.cdx.json")
    data = load_json_bytes(raw, f"{tool} output")
    try:
        check_report(data, tool, f"{tool} output")
    except ReportShapeError as exc:
        raise ScannerError(str(exc)) from None
    return data


def parse_report(tool: str, mod, report: dict, args: argparse.Namespace):
    """mod.parse(report); a report that cannot be parsed is a usage error (exit 2) when the user imported it."""
    try:
        return mod.parse(report)
    except ScannerError as exc:
        if getattr(args, f"from_{tool}_json"):
            raise UsageError(f"--from-{tool}-json {Path(getattr(args, f'from_{tool}_json')).name}: {exc}") from exc
        raise


def run(args, chosen, out, net, scanners_meta, warnings):
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
        trivy_report = run_or_load("trivy", trivy_mod, args, out, scanners_meta, warnings)
        f, scan_info = parse_report("trivy", trivy_mod, trivy_report, args)
        groups.append(f)
    if "grype" in chosen:
        g, _ = parse_report("grype", grype_mod, run_or_load("grype", grype_mod, args, out, scanners_meta,
                                                                warnings), args)
        groups.append(g)
    args.reach_results = {}
    if args.reachability and trivy_report is not None:
        args.reach_results = run_govulncheck(args, trivy_report, scanners_meta, warnings)
    if "osv" in chosen and trivy_report is not None and net:
        purls = osv_mod.purls_from_trivy(trivy_report)
        unlisted = osv_mod.unlisted_language_results(trivy_report)
        try:
            o = osv_mod.scan(net, purls)
            groups.append(o)
            scanners_meta["osv"] = {"enabled": True, "detail": f"{len(purls)} packages queried"}
            args.malicious_check = checks.state(
                checks.PARTIAL, f"Trivy listed no packages for {', '.join(unlisted[:3])}"
                + (f" and {len(unlisted) - 3} more" if len(unlisted) > 3 else "")
                + " (a report made with --list-all-pkgs=false?), so only packages with findings were queried"
            ) if unlisted else checks.state(
                checks.CHECKED, "" if purls else "no language packages; OSV malicious package data covers "
                                                 "language packages")
        except HttpError as exc:
            warnings.append(f"OSV lookup failed, continuing without it: {exc}")
            args.malicious_check = checks.state(checks.PARTIAL, "OSV lookup failed" + without_osv)
        if unlisted:
            warnings.append(f"Trivy found language packages in {len(unlisted)} place(s) but listed none, so OSV "
                            "and the release-age check saw only packages with findings (was the report generated "
                            "with --list-all-pkgs=false?)")
        elif not purls:
            if args.image:
                warnings.append("No language packages in the image (OS packages only), so OSV was not queried; "
                                "Trivy and Grype cover OS packages")
            else:
                warnings.append(f"No language packages found in {Path(args.path).name or args.path}, so OSV was "
                                "not queried")
    return trivy_report, groups, scan_info


def run_govulncheck(args, trivy_report: dict, scanners_meta: dict, warnings: list[str]) -> dict:
    targets = sorted({r.get("Target", "") for r in trivy_report.get("Results") or []
                      if r.get("Type") == "gobinary" and r.get("Target")})
    targets = [t for t in targets if govuln_mod.safe_relpath(t)]
    if not targets:
        warnings.append("--reachability: no Go binaries in the scan, so govulncheck had nothing to check")
        return {}
    try:
        gv = integrity.private_copy(govuln_mod.find(args.govulncheck_path))
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
                    used["path"] = Path(used["path"]).name
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


def language_purls(args, trivy_report: dict | None) -> list[str]:
    """Every language package version the run knows about, with or without findings (a compromised release is
    new and usually has no advisory yet)."""
    if getattr(args, "inventory", None) and args.path_kind == "inventory":
        return [e["purl"] for e in args.inventory]
    if trivy_report is not None:
        return osv_mod.purls_from_trivy(trivy_report)
    return []
