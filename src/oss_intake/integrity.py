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
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import IO, cast

_HEX64 = re.compile(r"^[0-9a-f]{64}$")

# The release workflows that sign the official releases (Sigstore keyless, GitHub OIDC), as the signing
# certificates name them: Trivy's reusable release workflow run for a version tag, Grype's release workflow on
# main (read from the certificates of Trivy 0.70.0 and 0.76.1 and Grype 0.80.0 to 0.104.0). Any other workflow or
# ref in the repository (a branch, or a less guarded workflow that can also get a signing certificate) is refused.
DEFAULT_COSIGN_IDENTITY = {
    "trivy": r"^https://github\.com/aquasecurity/trivy/\.github/workflows/reusable-release\.yaml"
             r"@refs/tags/v[0-9]+\.[0-9]+\.[0-9]+$",
    "grype": r"^https://github\.com/anchore/grype/\.github/workflows/release\.yaml@refs/heads/main$",
}


class IntegrityError(Exception):
    """Raised when a hash, checksum file or cosign check fails or cannot be carried out."""
    pass


def sha256_file(path: str | Path) -> str:
    """SHA-256 of the file's contents as lowercase hex, read in 1 MiB chunks."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def normalise_hash(value: str | bytes) -> str:
    """A SHA-256 value (str or ASCII bytes, optional "sha256:" prefix) as 64 lowercase hex characters.
    Raises IntegrityError if it is not a SHA-256 hex value (non-ASCII bytes raise UnicodeDecodeError)."""
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
    try:
        text = bytes(data).decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise IntegrityError(f"checksums file is not UTF-8 text: {exc.reason} at byte {exc.start}") from None
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
    """Check a file against its line in a sha256sum-style checksums file, looked up by name (default: the file's name).
    Returns the actual SHA-256; raises IntegrityError if the name is not listed or the hash differs."""
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
    """Check a file's SHA-256 against an expected value (normalised by normalise_hash). Returns the actual hash;
    raises IntegrityError on a mismatch or a malformed expected value."""
    want = normalise_hash(expected)
    actual = sha256_file(file_path)
    if actual != want:
        raise IntegrityError(f"SHA-256 mismatch for {Path(file_path).name}: expected {want}, got {actual}")
    return actual


def load_known_bad() -> dict:
    """The bundled data/known_bad.json (known compromised tool versions and GitHub Actions), parsed."""
    with resources.files("oss_intake").joinpath("data/known_bad.json").open("rb") as fh:
        return json.loads(fh.read().decode("utf-8"))


def known_bad_entry(tool: str, version: str) -> dict | None:
    """The known_bad.json entry that lists this version of the tool (a leading v is ignored), or None."""
    v = version.strip().lstrip("vV")
    for entry in load_known_bad().get("tools", {}).get(tool, []):
        if v in entry.get("versions", []):
            return entry
    return None


COSIGN_TIMEOUT = 120  # seconds


def cosign_verify_blob(file_path: str | Path, bundle: str | Path | None, identity_regexp: str,
                       oidc_issuer: str = "https://token.actions.githubusercontent.com",
                       certificate: str | Path | None = None, signature: str | Path | None = None) -> None:
    """Verify a file against a Sigstore bundle, or a certificate and signature (as Grype publishes:
    checksums.txt.pem and .sig, checked against the transparency log, so this needs the network), by running
    cosign verify-blob with the certificate identity regexp and OIDC issuer (default GitHub Actions),
    COSIGN_TIMEOUT seconds at most. Returns None on success; raises IntegrityError if cosign is not on PATH, does
    not finish in time, or verification fails."""
    cosign = shutil.which("cosign")
    if not cosign:
        from .scanners import missing

        raise IntegrityError(missing("cosign", ", which a cosign bundle or signature needs", path_option=False))
    if bundle:
        material = ["--bundle", str(bundle)]
    elif certificate and signature:
        material = ["--certificate", str(certificate), "--signature", str(signature)]
    else:
        raise IntegrityError("a cosign check needs a bundle, or a certificate and a signature")
    cmd = [cosign, "verify-blob", *material,
           "--certificate-identity-regexp", identity_regexp,
           "--certificate-oidc-issuer", oidc_issuer, str(file_path)]
    from .scanners import ScannerError, capped_run

    try:
        proc = capped_run(cmd, COSIGN_TIMEOUT, max_stdout=1024 * 1024)
    except ScannerError as exc:  # it wrote far more than a verification ever does
        raise IntegrityError(f"cosign: {exc}, so the signature was not verified") from None
    except OSError as exc:
        raise IntegrityError(f"could not run cosign: {exc}") from None
    except subprocess.TimeoutExpired:
        raise IntegrityError(f"cosign did not finish within {COSIGN_TIMEOUT} seconds, so the signature was not "
                             "verified") from None
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
                        fh = cast(IO[bytes], t.extractfile(m))  # m.isfile(): extractfile returns a file
                        for chunk in iter(partial(fh.read, 1 << 20), b""):
                            h.update(chunk)
                        return m.name, h.hexdigest()
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError) as exc:
        raise IntegrityError(f"{archive.name} is not a readable release archive: {exc}") from None
    raise IntegrityError(f"{archive.name} contains no {' or '.join(names)} executable")


_PRIVATE_DIRS: list[str] = []


def _remove_private_dirs() -> None:
    for d in _PRIVATE_DIRS:
        shutil.rmtree(d, ignore_errors=True)


def private_copy(path: str) -> str:
    """A copy of the executable at path in a folder only this user can write to (0700, removed at exit), to check
    and run in its place: whoever can write to the scanner's own folder could otherwise swap the file between
    its check and its run (external audit SEC-06). The copy keeps the file's name, so the program sees itself
    as before."""
    import atexit

    temp = tempfile.gettempdir()
    flag = getattr(os, "ST_NOEXEC", 0)  # Linux only
    if flag and hasattr(os, "statvfs"):
        try:
            noexec = bool(os.statvfs(temp).f_flag & flag)
        except OSError:
            noexec = False
        if noexec:  # as CIS hardening mounts /tmp: the copy could not run
            raise IntegrityError(f"{temp} does not allow programs to run (mounted noexec), so {Path(path).name} "
                                 "cannot be copied there to be checked and run; set TMPDIR to a folder only you "
                                 "can write to that allows it, such as ~/.cache/oss-intake-tmp")
    try:
        folder = tempfile.mkdtemp(prefix="oss-intake-bin-")
    except OSError as exc:
        raise IntegrityError(f"could not make a private folder to check and run {Path(path).name} in: "
                             f"{exc}") from None
    if not _PRIVATE_DIRS:
        atexit.register(_remove_private_dirs)
    _PRIVATE_DIRS.append(folder)
    dest = Path(folder) / Path(path).name
    try:
        shutil.copyfile(path, dest)
        os.chmod(dest, 0o700)
    except OSError as exc:
        raise IntegrityError(f"could not copy {Path(path).name} to check and run it: {exc}") from None
    return str(dest)


def verify_before_run(tool: str, path: str, expected_sha256: str | None, cosign_bundle: str | None,
                      cosign_identity: str | None, archive: str | None = None,
                      checksums: str | None = None, cosign_certificate: str | None = None,
                      cosign_signature: str | None = None) -> dict:
    """Checks that need nothing from the binary itself, done before it is executed even once (its --version
    included). Raises IntegrityError on any mismatch. Returns what was verified, for the report.

    The chain, when given: the cosign bundle signs the checksums file (Grype, and Trivy's checksums) or else the
    archive (Trivy); the checksums file lists the archive's SHA-256; the executable equals the archive's member."""
    done: dict = {}
    if expected_sha256:
        verify_sha256(path, expected_sha256)
    identity = cosign_identity or DEFAULT_COSIGN_IDENTITY[tool]
    signed_with = cosign_bundle or cosign_certificate  # a bundle, or a certificate and signature (Grype)

    def cosign(file: str) -> None:
        if cosign_bundle:
            cosign_verify_blob(file, cosign_bundle, identity)
        else:
            cosign_verify_blob(file, None, identity, certificate=cosign_certificate, signature=cosign_signature)

    # What to add to sign the chain: both publish a bundle for their checksums file (Grype since 0.120.0; before
    # that, a certificate and signature, which cosign's --certificate and --signature check: deprecated in cosign).
    sign_hint = (f"--{tool}-cosign-bundle (Grype 0.120.0 and later; for an earlier release, add "
                 f"--{tool}-cosign-certificate and --{tool}-cosign-signature)" if tool == "grype"
                 else f"--{tool}-cosign-bundle")
    if archive:
        if checksums:
            if signed_with:
                cosign(checksums)
                done["signed"] = Path(checksums).name
                if cosign_certificate:
                    done["deprecated"] = (
                        f"{Path(checksums).name} was verified with a certificate and signature, which cosign has "
                        f"deprecated and may stop accepting; {tool} 0.120.0 and later publish "
                        f"{tool}_<version>_checksums.txt.sigstore.json: use --{tool}-cosign-bundle with it")
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
        elif signed_with:
            cosign(archive)
            done["signed"] = Path(archive).name
            done["archive_sha256"] = sha256_file(archive)
        member, member_hash = archive_member_sha256(archive, (tool, f"{tool}.exe"))
        actual = sha256_file(path)
        if actual != member_hash:
            raise IntegrityError(f"{Path(path).name} is not the {tool} executable in {Path(archive).name}: "
                                 f"{actual} here, {member_hash} in the archive ({member})")
        done.update(archive=Path(archive).name, binary_matches_archive=True)
        if not (checksums or signed_with):
            done["note"] = (f"the {tool} executable matches {Path(archive).name}, but nothing vouches for the "
                            f"archive itself; add --{tool}-checksums and {sign_hint}")
        elif checksums and not done.get("signed"):
            # Whoever could swap the archive could also swap a checksums file nothing has signed.
            done["note"] = (f"the {tool} executable matches {Path(archive).name}, which is listed in "
                            f"{Path(checksums).name}, but nothing has signed {Path(checksums).name}, so the hash "
                            f"is not verified; add {sign_hint}")
    elif signed_with:
        # A bundle without an archive can only be checked against the executable itself, which the projects do
        # not sign; kept for executables someone signs directly.
        cosign(path)
        done["signed"] = Path(path).name
    return done


# The Go module each scanner is built from. Go binaries record the main module and its version in their build
# information ("mod\t<path>\t<version>"), so the version can be read from the file without running it.
GO_MODULES = {"trivy": "github.com/aquasecurity/trivy", "grype": "github.com/anchore/grype"}
_CHUNK = 1 << 20


def embedded_version(tool: str, path: str) -> str | None:
    """The version in the binary's Go build information (v0.76.1+dirty -> 0.76.1), read without executing it;
    None when the tool is not a known Go module or the file carries no such record."""
    module = GO_MODULES.get(tool)
    if not module:
        return None
    marker = f"mod\t{module}\t".encode()
    tail = b""
    try:
        with open(path, "rb") as fh:
            while chunk := fh.read(_CHUNK):
                buf = tail + chunk
                start = 0
                while (i := buf.find(marker, start)) >= 0:
                    rest = buf[i + len(marker):i + len(marker) + 64]
                    if b"\t" not in rest and len(rest) < 64:
                        more = fh.read(64)
                        rest, buf = rest + more, buf + more
                    m = re.match(rb"v?(\d+\.\d+\.\d+[0-9A-Za-z.-]*)(?:\+[0-9A-Za-z.-]+)?\t", rest)
                    if m:
                        return m.group(1).decode()
                    start = i + 1  # an unstamped record such as (devel): keep looking
                tail = buf[-(len(marker) + 64):]
    except OSError:
        return None
    return None


def refuse_known_bad_before_run(tool: str, path: str) -> str | None:
    """Raise IntegrityError when the version recorded in the binary is on the known-bad list, so a known-bad
    release never runs, even without a pinned hash. Returns the embedded version, or None if there is none."""
    version = embedded_version(tool, path)
    bad = known_bad_entry(tool, version) if version else None
    if bad:
        raise IntegrityError(
            f"{tool} {version} is on the known-bad list ({bad.get('reference')}): {bad.get('note')} "
            "It was not run (the version was read from the file). Do not use it. Install a known-good version and "
            "verify its checksum."
        )
    return version


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
