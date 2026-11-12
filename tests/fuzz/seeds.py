"""Starting inputs for each fuzz target, built from the test fixtures when needed so that no file here is named
like a project's dependencies (OpenSSF Scorecard and OSV-Scanner would read it as ours)."""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

from oss_intake import likelihood, zipsign

from .harnesses import _VSIXMANIFEST, PLUGIN_ZIP, SEP, VSIX_MEMBERS, framed

FIX = Path(__file__).resolve().parent.parent / "fixtures"
_SBOMS = sorted((FIX / "sbom").glob("*-fixture.json"))
_PKG = {"name": "ext", "publisher": "example", "version": "1.2.3", "engines": {"vscode": "^1.90.0"},
        "main": "./out/extension.js"}
_YARN = b'# yarn lockfile v1\n\n"left-pad@^1.0.0", left-pad@1:\n  version "1.3.0"\n  resolved "x"\n'
_PNPM = b"lockfileVersion: '9.0'\npackages:\n  /left-pad@1.3.0:\n    resolution: {integrity: x}\n"
_VEX = {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "x", "author": "a", "timestamp": "2026-01-01T00:00:00Z",
        "version": 1, "statements": [{"vulnerability": {"name": "CVE-2099-0001", "aliases": ["GHSA-x"]},
                                      "products": [{"@id": "pkg:npm/left-pad@1.3.0"}], "status": "not_affected",
                                      "justification": "component_not_present"}]}


def _vsix(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("extension.vsixmanifest", _VSIXMANIFEST)
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def _pb(number: int, value: int | bytes) -> bytes:
    def varint(n: int) -> bytes:
        out = bytearray()
        while True:
            out.append((n & 0x7F) | (0x80 if n > 0x7F else 0))
            n >>= 7
            if not n:
                return bytes(out)
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    return varint(number << 3 | 2) + varint(len(value)) + value


def _signing_block() -> bytes:
    """A signing block message for PLUGIN_ZIP with its real SHA-256 digest and a signer whose certificate and
    signature are placeholders: it reads, matches the file, and stops at the signer."""
    _, before, cd, end = framed(b"")
    digest = zipsign._chunked(None, [before, cd, end], {"sha256"})["sha256"]
    signer = _pb(1, b"0\x82placeholder certificate") + _pb(2, _pb(1, 0) + _pb(2, b"placeholder signature"))
    return _pb(1, 1) + _pb(2, _pb(1, _pb(1, 0) + _pb(2, digest)) + _pb(2, signer))


def seeds(name: str) -> list[bytes]:
    if name == "sbom_file":
        return [p.read_bytes() for p in _SBOMS]
    if name == "inventory_csv":
        return [(Path(__file__).resolve().parents[2] / "examples" / "inventory" / "packages.sample.csv").read_bytes(),
                b"purl,system\npkg:npm/left-pad@1.3.0,web\npkg:pypi/requests@2.31.0,api\n",
                b"ecosystem,name,version\nnpm,left-pad,1.3.0\n"]
    if name == "decisions_file":
        return [json.dumps(_VEX).encode(),
                b"id,package,installed,triage_status,triage_notes\nCVE-2099-0001,left-pad,1.3.0,not_affected,ok\n"]
    if name == "renv_lock":
        return [(FIX / "inputs" / "renv_fixture.json").read_bytes()]
    if name in ("scanner_report", "scanner_report_run"):
        return [(FIX / "trivy.json").read_bytes(), (FIX / "grype.json").read_bytes()]
    if name == "osv_advisory":
        return [(FIX / n).read_bytes() for n in ("osv_GHSA-test-0001-aaaa.json", "osv_GHSA-test-0006-cccc.json",
                                                  "osv_USN-9999-1.json")]
    spdx = next(p for p in _SBOMS if ".spdx-" in p.name).read_bytes()
    files = [json.dumps(_PKG).encode(), _YARN, spdx, b'{"name": "dep", "version": "2.0.0"}', _PNPM,
             b"exports.activate = () => {};"]
    if name == "vsix_archive":
        return [_vsix(dict(zip(VSIX_MEMBERS, files, strict=True)))]
    if name == "vsix_files":
        return [SEP.join(files), SEP.join(files[:2])]
    if name == "checksums":
        return [b"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  oss-intake-0.15.0.tar.gz\n"
                b"60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752 *tool.zip\r\n"]
    if name == "likelihood_config":
        return [json.dumps(likelihood.DEFAULT_CONFIG).encode()]
    if name == "govulncheck_output":
        return [b'{"config": {"go_version": "go1.22", "scan_level": "symbol"}}\n'
                b'{"osv": {"id": "GO-2099-0001", "aliases": ["CVE-2099-1"]}}\n'
                b'{"finding": {"osv": "GO-2099-0001", "trace": [{"module": "m", "package": "p", "function": "f"}]}}\n']
    if name == "service_data":
        return [(FIX / n).read_bytes() for n in ("exploitdb.csv", "debian_DLA_list.txt", "vscode_removed.md",
                                                  "metasploit.json", "go_release.html",
                                                  "amazon/al2023-updateinfo.xml")]
    if name == "plugin_signature":
        return [PLUGIN_ZIP, _signing_block()]
    raise KeyError(name)
