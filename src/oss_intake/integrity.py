"""Scanner binary integrity: version policy, known-bad versions, SHA-256 and optional cosign.

Lessons applied from the March 2026 Trivy compromise (CVE-2026-33634):
  * never install or trust "latest"; the user pins the version they expect
  * refuse known-malicious versions outright
  * compare hashes over raw bytes; GitHub serves checksum files as
    application/octet-stream, so they are parsed from bytes with explicit decoding
  * signature verification is delegated to cosign when the user supplies a bundle
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# Release workflows that sign the official binaries (Sigstore keyless, GitHub OIDC).
DEFAULT_COSIGN_IDENTITY = {
    "trivy": r"^https://github\.com/aquasecurity/trivy/",
    "grype": r"^https://github\.com/anchore/grype/",
}


class IntegrityError(Exception):
    pass


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def normalise_hash(value: str | bytes) -> str:
    if isinstance(value, bytes):
        value = value.decode("ascii", errors="strict")
    v = value.strip().lower()
    if v.startswith("sha256:"):
        v = v[7:]
    if not _HEX64.match(v):
        raise IntegrityError("expected a 64 character hexadecimal SHA-256 value")
    return v


def parse_checksums(data: bytes) -> dict[str, str]:
    """Parse a sha256sum-style file supplied as BYTES.

    Handles UTF-8 BOM, CRLF line endings, binary-mode '*' prefixes and blank lines.
    Returns {filename: lowercase_hex}.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("parse_checksums expects bytes; read the file with 'rb' or response.content")
    text = bytes(data).decode("utf-8-sig")
    out: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        digest, name = parts[0].lower(), parts[1].strip()
        if name.startswith("*"):
            name = name[1:]
        if _HEX64.match(digest):
            out[name] = digest
    return out


def verify_against_checksums(file_path: str | Path, checksums_path: str | Path,
                             name: str | None = None) -> str:
    file_path = Path(file_path)
    with open(checksums_path, "rb") as fh:
        table = parse_checksums(fh.read())
    key = name or file_path.name
    if key not in table:
        raise IntegrityError(f"{key} is not listed in {Path(checksums_path).name}")
    actual = sha256_file(file_path)
    if actual != table[key]:
        raise IntegrityError(f"SHA-256 mismatch for {key}: expected {table[key]}, got {actual}")
    return actual


def verify_sha256(file_path: str | Path, expected: str) -> str:
    want = normalise_hash(expected)
    actual = sha256_file(file_path)
    if actual != want:
        raise IntegrityError(f"SHA-256 mismatch for {Path(file_path).name}: expected {want}, got {actual}")
    return actual


def load_known_bad() -> dict:
    with resources.files("oss_intake").joinpath("data/known_bad.json").open("rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def known_bad_entry(tool: str, version: str) -> dict | None:
    v = version.strip().lstrip("vV")
    for entry in load_known_bad().get("tools", {}).get(tool, []):
        if v in entry.get("versions", []):
            return entry
    return None


def cosign_verify_blob(file_path: str | Path, bundle: str | Path, identity_regexp: str,
                       oidc_issuer: str = "https://token.actions.githubusercontent.com") -> None:
    cosign = shutil.which("cosign")
    if not cosign:
        raise IntegrityError("cosign was requested (--cosign-bundle) but is not on PATH")
    cmd = [cosign, "verify-blob", "--bundle", str(bundle),
           "--certificate-identity-regexp", identity_regexp,
           "--certificate-oidc-issuer", oidc_issuer, str(file_path)]
    proc = subprocess.run(cmd, capture_output=True, timeout=120)
    if proc.returncode != 0:
        msg = proc.stderr.decode("utf-8", errors="replace").strip().splitlines()
        raise IntegrityError("cosign verification failed: " + (msg[-1] if msg else "no output"))


@dataclass
class BinaryCheck:
    tool: str
    path: str
    version: str
    sha256: str
    hash_verified: bool
    signature_verified: bool
    expected_version: str | None
    notes: list[str]

    def as_dict(self) -> dict:
        return dict(self.__dict__)


def check_binary(tool: str, path: str, version: str, expected_version: str | None,
                 expected_sha256: str | None, cosign_bundle: str | None,
                 cosign_identity: str | None) -> BinaryCheck:
    """Apply the policy. Raises IntegrityError on any failure; never warns-and-continues."""
    notes: list[str] = []
    bad = known_bad_entry(tool, version)
    if bad:
        raise IntegrityError(
            f"{tool} {version} is on the known-bad list ({bad.get('reference')}): {bad.get('note')} "
            "Do not use it. Install a known-good version and verify its checksum."
        )
    if expected_version and version.lstrip("vV") != expected_version.lstrip("vV"):
        raise IntegrityError(f"{tool} version {version} does not match the pinned version {expected_version}")
    if not expected_version:
        notes.append(f"{tool} version not pinned; pass --{tool}-version to enforce it")
    digest = sha256_file(path)
    hash_ok = False
    if expected_sha256:
        verify_sha256(path, expected_sha256)
        hash_ok = True
    else:
        notes.append(f"{tool} binary hash not verified; pass --{tool}-sha256 to enforce it")
    sig_ok = False
    if cosign_bundle:
        cosign_verify_blob(path, cosign_bundle, cosign_identity or DEFAULT_COSIGN_IDENTITY[tool])
        sig_ok = True
    return BinaryCheck(tool, path, version, digest, hash_ok, sig_ok, expected_version, notes)
