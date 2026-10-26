"""Scanner binary integrity: version policy, known-bad versions, SHA-256 and optional cosign.

Lessons applied from the March 2026 Trivy compromise (CVE-2026-33634):
  * never install or trust "latest"; the user pins the version they expect
  * refuse known-malicious versions outright
  * compare hashes over raw bytes; GitHub serves checksum files as
    application/octet-stream, so they are parsed from bytes with explicit decoding
  * signature verification is delegated to cosign when the user supplies a bundle

What the projects sign: Trivy signs each release archive (trivy_X_Linux-64bit.tar.gz.sigstore.json) and its
checksums file; Grype signs only its checksums file. Neither signs the extracted executable. So a signature is
checked on the archive (or on the checksums file, which must then list the archive), and the executable that will
run must be byte-for-byte the one inside that archive.
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


MAX_MEMBER_BYTES = 1024 * 1024 * 1024  # a scanner executable is ~200 MB; anything near 1 GB is not one


def archive_member_sha256(archive: str | Path, names: tuple[str, ...]) -> tuple[str, str]:
    """SHA-256 of the first regular file in a .tar.gz/.tgz or .zip release archive whose base name is one of
    names (trivy, trivy.exe), streamed without extracting anything to disk. Returns (member name, hex)."""
    import tarfile
    import zipfile
    from functools import partial

    archive = Path(archive)
    h = hashlib.sha256()
    try:
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as z:
                for info in z.infolist():
                    if not info.is_dir() and info.filename.rsplit("/", 1)[-1] in names:
                        if info.file_size > MAX_MEMBER_BYTES:
                            raise IntegrityError(f"{info.filename} in {archive.name} is implausibly large")
                        with z.open(info) as fh:
                            for chunk in iter(partial(fh.read, 1 << 20), b""):
                                h.update(chunk)
                        return info.filename, h.hexdigest()
        else:
            with tarfile.open(archive, "r:*") as t:
                for m in t:
                    if m.isfile() and m.name.rsplit("/", 1)[-1] in names:
                        if m.size > MAX_MEMBER_BYTES:
                            raise IntegrityError(f"{m.name} in {archive.name} is implausibly large")
                        fh = t.extractfile(m)
                        for chunk in iter(partial(fh.read, 1 << 20), b""):
                            h.update(chunk)
                        return m.name, h.hexdigest()
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError) as exc:
        raise IntegrityError(f"{archive.name} is not a readable release archive: {exc}") from None
    raise IntegrityError(f"{archive.name} contains no {' or '.join(names)} executable")


def verify_before_run(tool: str, path: str, expected_sha256: str | None, cosign_bundle: str | None,
                      cosign_identity: str | None, archive: str | None = None,
                      checksums: str | None = None) -> dict:
    """Checks that need nothing from the binary itself, done before it is executed even once (its --version
    included). Raises IntegrityError on any mismatch. Returns what was verified, for the report.

    The chain, when given: the cosign bundle signs the checksums file (Grype, and Trivy's checksums) or else the
    archive (Trivy); the checksums file lists the archive's SHA-256; the executable equals the archive's member."""
    done: dict = {}
    if expected_sha256:
        verify_sha256(path, expected_sha256)
    identity = cosign_identity or DEFAULT_COSIGN_IDENTITY[tool]
    if archive:
        if checksums:
            if cosign_bundle:
                cosign_verify_blob(checksums, cosign_bundle, identity)
                done["signed"] = Path(checksums).name
            with open(checksums, "rb") as fh:
                table = parse_checksums(fh.read())
            actual_archive = sha256_file(archive)
            # Matched by name, or by hash when the archive was saved under another name (curl -o): the signed
            # table vouches for the bytes either way.
            if table.get(Path(archive).name) != actual_archive and actual_archive not in table.values():
                raise IntegrityError(f"{Path(archive).name} (sha256 {actual_archive}) is not listed in "
                                     f"{Path(checksums).name}")
            done["archive_sha256"] = actual_archive
            done["checksums"] = Path(checksums).name
        elif cosign_bundle:
            cosign_verify_blob(archive, cosign_bundle, identity)
            done["signed"] = Path(archive).name
            done["archive_sha256"] = sha256_file(archive)
        member, member_hash = archive_member_sha256(archive, (tool, f"{tool}.exe"))
        actual = sha256_file(path)
        if actual != member_hash:
            raise IntegrityError(f"{Path(path).name} is not the {tool} executable in {Path(archive).name}: "
                                 f"{actual} here, {member_hash} in the archive ({member})")
        done.update(archive=Path(archive).name, binary_matches_archive=True)
        if not (checksums or cosign_bundle):
            done["note"] = (f"the {tool} executable matches {Path(archive).name}, but nothing vouches for the "
                            f"archive itself; add --{tool}-checksums and --{tool}-cosign-bundle")
    elif cosign_bundle:
        # A bundle without an archive can only be checked against the executable itself, which the projects do
        # not sign; kept for executables someone signs directly.
        cosign_verify_blob(path, cosign_bundle, identity)
        done["signed"] = Path(path).name
    return done


def check_binary(tool: str, path: str, version: str, expected_version: str | None,
                 expected_sha256: str | None, cosign_bundle: str | None,
                 cosign_identity: str | None, verified: bool = False) -> BinaryCheck:
    """Apply the policy. Raises IntegrityError on any failure; never warns-and-continues. verified=True means
    verify_before_run already checked the hash and signature, so they are not checked (or cosign run) again."""
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
        if not verified:
            verify_sha256(path, expected_sha256)
        hash_ok = True
    else:
        notes.append(f"{tool} binary hash not verified; pass --{tool}-sha256 to enforce it")
    sig_ok = False
    if cosign_bundle:
        if not verified:
            cosign_verify_blob(path, cosign_bundle, cosign_identity or DEFAULT_COSIGN_IDENTITY[tool])
        sig_ok = True
    return BinaryCheck(tool, path, version, digest, hash_ok, sig_ok, expected_version, notes)
