"""Starting inputs for each fuzz target, built from the test fixtures when needed so that no file here is named
like a project's dependencies (OpenSSF Scorecard and OSV-Scanner would read it as ours)."""

from __future__ import annotations

import base64
import io
import json
import struct
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


# A Manifest V3 extension that reaches every manifest check: permissions of each grade, site access, content
# scripts, pages other sites can reach, policies, an update address that is not a store, settings overrides.
_EXT_MANIFEST = {
    "manifest_version": 3, "name": "__MSG_name__", "version": "1.0", "default_locale": "en",
    "permissions": ["cookies", "tabs", "storage", "notAPermission"], "optional_permissions": ["history"],
    "host_permissions": ["<all_urls>", "https://example.com/*"],
    "content_scripts": [{"matches": ["*://*/*"], "js": ["cs.js"], "run_at": "document_start", "all_frames": True,
                         "world": "MAIN"}],
    "externally_connectable": {"ids": ["*"], "matches": ["https://example.com/*"]},
    "web_accessible_resources": [{"resources": ["img/*"], "matches": ["<all_urls>"]}],
    "content_security_policy": {"extension_pages": "script-src 'self' 'wasm-unsafe-eval'",
                                "sandbox": "sandbox allow-scripts; script-src 'self' 'unsafe-eval' https://x.example"},
    "update_url": "https://updates.example.net/crx",
    "chrome_settings_overrides": {"homepage": "https://example.com"}, "chrome_url_overrides": {"newtab": "n.html"},
    "key": base64.b64encode(b"an example public key").decode(),  # built here: a literal reads as a secret
}
_MESSAGES = b'{"name": {"message": "Example extension"}}'
# Code that reaches every code signal: eval, a string timer, importScripts from the web, executeScript with code,
# the packer, _0x names, a long encoded string and a web address.
_EXT_CODE = (b"eval(x); setTimeout('go()', 1); importScripts('https://cdn.example.com/w.js');\n"
             b"chrome.tabs.executeScript(1, {code: c}); eval(function(p,a,c,k,e,d){return p}('',0,0,[],0,{}));\n"
             + b" ".join(b"var _0x%04x=1;" % i for i in range(25)) + b"\nvar b='" + b"QUJD" * 600
             + b"'; fetch('https://api.example.com/v1');\n")


def _crx(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, data in members.items():
            z.writestr(n, data)
    header = b"\x12\x00"  # a header the reader skips: its checks are on the zip after it
    return b"Cr24" + struct.pack("<II", 3, len(header)) + header + buf.getvalue()


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
    if name == "crx_archive":
        return [_crx({"manifest.json": json.dumps(_EXT_MANIFEST).encode(), "_locales/en/messages.json": _MESSAGES,
                      "cs.js": b"console.log(1);"})]
    if name == "ext_manifest":
        return [SEP.join([b"// comment\n" + json.dumps(_EXT_MANIFEST, indent=1).encode(), _MESSAGES, _EXT_CODE,
                          b'<script src="https://cdn.example.com/a.js"></script>']),
                SEP.join([json.dumps({**_EXT_MANIFEST, "manifest_version": 2,
                                      "content_security_policy": "script-src 'self' https://cdn.example.com"}).encode()])]
    raise KeyError(name)
