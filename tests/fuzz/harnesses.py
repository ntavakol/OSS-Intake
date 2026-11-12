"""Fuzz targets: one per parser of untrusted input (docs/threat-model.md, "User inputs" and "Public services").

Each target takes bytes and may only raise the errors the CLI reports cleanly (EXPECTED): anything else, a hang
or running out of memory is a bug. fuzz.py runs them under Atheris (Linux); tests/test_fuzz_harnesses.py runs
them on their seeds and on simple mutations of those, without Atheris, on every platform.
"""

from __future__ import annotations

import atexit
import contextlib
import io
import json
import os
import shutil
import struct
import tempfile
import zipfile
from pathlib import Path

from oss_intake import cli, conditions, decisions, inputs, integrity, likelihood, merge, sbom, vscode, zipsign

# cli.main turns an unexpected exception into exit 1 for users; the fuzzer must see it as the crash it is.
os.environ["OSS_INTAKE_DEBUG"] = "1"
from oss_intake.enrich import debian_releases, debian_tracker, exploits, golang_stdlib
from oss_intake.models import Finding
from oss_intake.scanners import (
    ReportShapeError,
    ScannerError,
    check_report,
    govulncheck,
    grype,
    load_json_bytes,
    report_kind,
    trivy,
)

# The errors the CLI reports cleanly (exit 2 or 1) that a parser may raise. HttpError is not one: the targets
# below get no network, so a target that raised it would be calling out.
EXPECTED = (inputs.InputError, ScannerError, ReportShapeError, integrity.IntegrityError, likelihood.ConfigError)

_TMP = Path(tempfile.mkdtemp(prefix="oss-intake-fuzz-"))
atexit.register(shutil.rmtree, _TMP, True)
SEP = b"\x00\x00"  # separates the files of a structured input (see vsix_files)

# Where each part of a vsix_files input goes inside the extension.
VSIX_MEMBERS = ("extension/package.json", "extension/yarn.lock", "extension/sbom.spdx.json",
                "extension/node_modules/dep/package.json", "extension/pnpm-lock.yaml", "extension/out/extension.js")
_VSIXMANIFEST = ('<PackageManifest><Metadata><Identity Language="en-US" Id="ext" Version="1.2.3" '
                 'Publisher="example" /></Metadata></PackageManifest>')


def _file(data: bytes, name: str) -> Path:
    p = _TMP / name
    p.write_bytes(data)
    return p


def sbom_file(data: bytes) -> None:
    p = _file(data, "input.json")
    if sbom.is_sbom(p):
        sbom.read(p)


def inventory_csv(data: bytes) -> None:
    inputs.inventory(_file(data, "inventory.csv"))


def decisions_file(data: bytes) -> None:
    """A findings.csv or an OpenVEX document, by the first byte, as an assessor would pass either."""
    decisions.load(_file(data, "decisions.json" if data[:1] in (b"{", b"[") else "decisions.csv"))


def renv_lock(data: bytes) -> None:
    inputs.renv_purls(_file(data, "renv.lock"))


def scanner_report(data: bytes) -> None:
    """A Trivy or Grype JSON report, as imported with --from-*-json."""
    report = load_json_bytes(data, "fuzz")
    kind = report_kind(report)
    if kind in ("trivy", "grype"):
        check_report(report, kind, "fuzz")
        (trivy if kind == "trivy" else grype).parse(report)


# One finding to attribute, so vscode.attribute reads the extension's node_modules, shipped SBOMs and lockfiles.
_FINDING = Finding(vuln_id="CVE-2099-0001", package="left-pad", installed="1.3.0", severity="HIGH",
                   purl="pkg:npm/left-pad@1.3.0", pkg_type="npm", target="/extension/package-lock.json")


def _assess_vsix(path: Path) -> None:
    """As the CLI does: classify the path (inputs.classify), unpack it into a fresh folder with limits
    (inputs.stage), assess it, attribute a finding to it and make its warnings (cli)."""
    staged = Path(tempfile.mkdtemp(dir=_TMP))
    try:
        if inputs.classify(path) != "vscode":
            return
        vscode.unpack(path, staged / path.stem)
        info = vscode.assess(staged, None, staged=True)
        vscode.attribute(info, [_FINDING])
        vscode.warnings(info)
    finally:
        shutil.rmtree(staged, ignore_errors=True)


def scanner_report_run(data: bytes) -> None:
    """A Trivy or Grype report imported into a whole offline run (cli.main), so values that parse but break later
    stages (merging, triage, conditions, reports) are reached too. Any exit code is fine; an exception is not."""
    report = _file(data, "report.json")
    try:
        doc = json.loads(data)
    except (ValueError, RecursionError):
        doc = None
    tool = "grype" if isinstance(doc, dict) and "matches" in doc else "trivy"
    out = Path(tempfile.mkdtemp(dir=_TMP))
    try:
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["--image", "owner/app:1.0", "--out", str(out), f"--from-{tool}-json", str(report),
                      "--scanners", tool, "--offline", "--as-of", "2026-11-01", "--quiet"])
    finally:
        shutil.rmtree(out, ignore_errors=True)


def osv_advisory(data: bytes) -> None:
    """The bytes as an OSV advisory (from the service or a cache entry) for a package OSV says it affects."""
    from oss_intake.scanners import osv

    try:
        advisory = json.loads(data)
    except (ValueError, RecursionError):
        advisory = None

    class Http:
        def post_json(self, url, body):
            return 200, {"results": [{"vulns": [{"id": "GHSA-fuzz-0001"}]} for _ in body["queries"]]}

        def get_json(self, url, params=None):
            return 200, advisory

        def prefetch(self, urls):
            pass

    for f in osv.scan(Http(), ["pkg:npm/left-pad@1.3.0", "pkg:deb/debian/openssl@3.0.11-1?distro=debian-12"],
                      {"pkg:deb/debian/openssl@3.0.11-1?distro=debian-12": {
                          "ecosystem": "Debian:12", "name": "openssl", "version": "3.0.11-1",
                          "os_release": "debian 12"}}):
        merge.merge([f])  # as the CLI does next with every finding
        conditions.extract(f.description)


def vsix_archive(data: bytes) -> None:
    """The bytes as a .vsix: zip handling and safe unpacking, then the extension's files."""
    _assess_vsix(_file(data, "input.vsix"))


def vsix_files(data: bytes) -> None:
    """The bytes as the files of a well-formed .vsix (split on SEP, in VSIX_MEMBERS order), so the fuzzer reaches
    the manifest, indicator, lockfile, SBOM and dependency readers instead of stopping at the zip format."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("extension.vsixmanifest", _VSIXMANIFEST)
        for name, part in zip(VSIX_MEMBERS, data.split(SEP), strict=False):
            z.writestr(name, part)
    _assess_vsix(_file(buf.getvalue(), "files.vsix"))


def _plugin_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("demo/lib/demo.jar", b"jar bytes")
    return buf.getvalue()


PLUGIN_ZIP = _plugin_zip()
SIGNATURE_STATUSES = {"verified", "not_jetbrains", "unsigned", "failed", "not_checked"}


def framed(proto: bytes, data: bytes = PLUGIN_ZIP) -> tuple[bytes, bytes, bytes, bytes]:
    """(the zip with proto as its signing block's message, and the unsigned zip's three digested sections:
    before the block, the central directory, the end record with its offset where the block starts)."""
    eocd = data.rfind(b"PK\x05\x06")
    cd_size, cd_offset = struct.unpack_from("<II", data, eocd + 12)
    before, cd, end = data[:cd_offset], data[cd_offset:cd_offset + cd_size], bytearray(data[eocd:])
    size = len(proto) + 24
    block = struct.pack("<Q", size) + proto + struct.pack("<QQQ", size, zipsign._MAGIC_LO, zipsign._MAGIC_HI)
    struct.pack_into("<I", end, 16, len(before) + len(block))
    original = bytearray(end)
    struct.pack_into("<I", original, 16, len(before))
    return before + block + cd + bytes(end), before, cd, bytes(original)


def plugin_signature(data: bytes) -> None:
    """A plugin file's JetBrains signing block (zipsign.check): the bytes as the whole file, and as the message in a
    well-formed block, so the fuzzer reaches the block reader rather than stopping at the zip layout. The check
    returns a verdict for any file and never raises. (The fuzzing job has no cryptography: certificates and
    signatures are checked by the unit tests.)"""
    for path in (_file(data, "plugin.zip"), _file(framed(data)[0], "framed.zip")):
        got = zipsign.check(path, trusted=b"")
        if got["status"] not in SIGNATURE_STATUSES:
            raise AssertionError(got)


def checksums(data: bytes) -> None:
    integrity.parse_checksums(data)


def likelihood_config(data: bytes) -> None:
    likelihood.load_config(str(_file(data, "likelihood.json")))


def govulncheck_output(data: bytes) -> None:
    govulncheck.analyse(govulncheck.parse_stream(data.decode("utf-8", "replace")))


def service_data(data: bytes) -> None:
    """Text from public services: Debian, Go release notes, the exploit indexes and the Marketplace removal list.
    Their callers treat ValueError as the source failing."""
    text = data.decode("utf-8", "replace")
    debian_releases.parse(text)
    debian_tracker.parse(text)
    debian_tracker.parse_versions(text)
    golang_stdlib.parse(text)
    exploits.parse_nuclei(text)
    vscode.parse_removed(text)
    try:
        exploits.parse_exploitdb(text)
    except ValueError:
        pass
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return
    if isinstance(doc, dict):
        exploits.parse_metasploit(doc)


TARGETS = {f.__name__: f for f in (sbom_file, inventory_csv, decisions_file, renv_lock, scanner_report,
                                   scanner_report_run, osv_advisory, vsix_archive, vsix_files, checksums,
                                   likelihood_config, govulncheck_output, service_data, plugin_signature)}


def run(name: str):
    """The Atheris entry point for TARGETS[name]: the CLI's own errors are expected, anything else is a crash."""
    target = TARGETS[name]

    def one(data: bytes) -> None:
        try:
            target(data)
        except EXPECTED:
            pass
    return one
