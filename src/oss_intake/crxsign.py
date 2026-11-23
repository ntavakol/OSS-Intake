"""The CRX3 signature on a browser extension's .crx file, checked as Chromium checks it before installing one
(components/crx_file/crx_verifier.cc).

A CRX3 file is "Cr24", the format version (3), the header's size, the header (a protobuf message), then the zip.
The header holds key proofs (an RSA or ECDSA public key with its signature) and the signed data, which names the
extension's ID. Every proof signs "CRX3 SignedData\\x00", the signed data's size (4 bytes, little-endian), the signed
data and the whole zip. Chromium installs a file only when every proof verifies and one of them is by the key the
ID comes from (the developer's key: the ID is the first 16 bytes of that key's SHA-256, each hex digit written as a
to p). A file from the Chrome Web Store carries a second proof, by the store's own key, which Chromium pins by its
SHA-256; that is the proof that the file is the one the store reviewed and served.

The result is "verified" (every proof verifies and the developer's proof is there; "store" says whether the Chrome
Web Store's proof is there too), "failed" (anything Chromium would refuse, or a header that cannot be read), or
"not_checked" (the signatures extra is not installed). Without the extra, what needs no cryptography is still
checked (the header, the developer's key matching the ID): a file that fails those fails. A check that could not
be made is never reported as verified.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from . import zipsign

# The SHA-256 of the Chrome Web Store's public key, as Chromium pins it (kPublisherKeyHash in crx_verifier.cc).
STORE_KEY_SHA256 = bytes.fromhex("61f7f2a6bfcf74cd0bc1fe2497cc9b04254c658f79f2145392867ea8366367cf")
CONTEXT = b"CRX3 SignedData\x00"
MAX_PROOFS = 16
MAX_KEY_BYTES = 16 * 1024
_ZIP_END_RECORDS = (b"PK\x05\x06", b"PK\x06\x07", b"PK\x06\x06")  # Chromium refuses a header that holds one


def extension_id(public_key: bytes) -> str:
    """The extension ID a public key gives (Chromium's id_util::GenerateId)."""
    return "".join(chr(ord("a") + int(c, 16)) for c in hashlib.sha256(public_key).hexdigest()[:32])


def _crypto():
    try:
        from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils
    except ImportError:
        return None
    return InvalidSignature, UnsupportedAlgorithm, hashes, serialization, ec, padding, rsa, utils


def _failed(detail: str, **more) -> dict:
    return {"status": "failed", "detail": detail, "id": "", "store": False, "other_keys": [], **more}


def check(path: Path) -> dict:
    """The CRX3 signature of the .crx at path: status, detail, id (the ID its developer's key gives, when that key
    signed it), store (the Chrome Web Store's proof is there and verifies), other_keys (the SHA-256 of any other
    signing key)."""
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            head = fh.read(12)
            if len(head) < 12 or head[:4] != b"Cr24":
                return _failed("not a CRX file")
            version, header_size = struct.unpack("<II", head[4:12])
            if version != 3 or header_size > 1024 * 1024 or 12 + header_size > size:
                return _failed("the header is not a CRX3 header within the limits")
            header = fh.read(header_size)
            archive_at = 12 + header_size
    except OSError as exc:
        return _failed(f"the file could not be read ({exc})")
    if any(rec in header for rec in _ZIP_END_RECORDS):
        return _failed("the header contains a zip end record, so the zip a reader finds may not be the one signed "
                       "(Chromium refuses such a file)")
    try:
        fields = zipsign._fields(header)
        rsa_proofs = [zipsign._fields(b) for b in zipsign._bytes(fields, 2)]
        ec_proofs = [zipsign._fields(b) for b in zipsign._bytes(fields, 3)]
        signed_list = zipsign._bytes(fields, 10000)
        signed = signed_list[-1] if signed_list else b""  # optional field: the last one counts, as in protobuf
        ids = zipsign._bytes(zipsign._fields(signed), 1)
    except zipsign._Unreadable as exc:
        return _failed(f"the header cannot be read: {exc}")
    declared = ids[-1] if ids else b""
    if len(declared) != 16:
        return _failed("the signed data does not name a 16-byte extension ID")
    declared_id = "".join(chr(ord("a") + int(c, 16)) for c in declared.hex())
    proofs = []
    for kind, group in (("rsa", rsa_proofs), ("ecdsa", ec_proofs)):
        for p in group:
            keys, sigs = zipsign._bytes(p, 1), zipsign._bytes(p, 2)
            proofs.append((kind, keys[-1] if keys else b"", sigs[-1] if sigs else b""))
    if not proofs:
        return _failed("the file carries no signature")
    if len(proofs) > MAX_PROOFS:
        return _failed(f"the file carries {len(proofs)} signatures, more than {MAX_PROOFS}")
    if any(len(k) > MAX_KEY_BYTES for _, k, _ in proofs):
        return _failed("a signing key is too large to be one")
    if not any(extension_id(k) == declared_id for _, k, _ in proofs):
        return _failed(f"no signature is by the key the extension's ID ({declared_id}) comes from (Chromium refuses "
                       "such a file)", id=declared_id)
    store = any(hashlib.sha256(k).digest() == STORE_KEY_SHA256 for _, k, _ in proofs)
    others = sorted({hashlib.sha256(k).hexdigest() for _, k, _ in proofs
                     if extension_id(k) != declared_id and hashlib.sha256(k).digest() != STORE_KEY_SHA256})
    c = _crypto()
    if c is None:
        from .openvsx import INSTALL_SIGNATURES

        return {"status": "not_checked", "detail": f"checking the signatures needs the signatures extra: "
                                                   f"{INSTALL_SIGNATURES}",
                "id": declared_id, "store": False, "store_claimed": store, "other_keys": others}
    invalid_signature, unsupported, hashes, serialization, ec, padding, rsa, utils = c
    digest = hashlib.sha256()
    digest.update(CONTEXT + struct.pack("<I", len(signed)) + signed)
    try:
        with open(path, "rb") as fh:
            fh.seek(archive_at)
            while chunk := fh.read(1 << 20):
                digest.update(chunk)
    except OSError as exc:
        return _failed(f"the file could not be read ({exc})")
    message = digest.digest()
    for kind, key_bytes, signature in proofs:
        try:
            key = serialization.load_der_public_key(key_bytes)
        except (ValueError, TypeError, unsupported):
            return _failed(f"a signing key ({kind}) cannot be read")
        try:
            if kind == "rsa" and isinstance(key, rsa.RSAPublicKey):
                key.verify(signature, message, padding.PKCS1v15(), utils.Prehashed(hashes.SHA256()))
            elif kind == "ecdsa" and isinstance(key, ec.EllipticCurvePublicKey):
                key.verify(signature, message, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
            else:
                return _failed(f"a {kind} signature comes with a key of another kind")
        except invalid_signature:
            who = ("the developer's key" if extension_id(key_bytes) == declared_id
                   else "the Chrome Web Store's key" if hashlib.sha256(key_bytes).digest() == STORE_KEY_SHA256
                   else "another key")
            return _failed(f"the signature by {who} does not verify: the file was changed after it was signed",
                           id=declared_id)
        except (ValueError, TypeError, unsupported) as exc:
            return _failed(f"a signature could not be checked ({type(exc).__name__})")
    detail = ("signed by its developer's key and by the Chrome Web Store" if store
              else "signed by its developer's key only, not by the Chrome Web Store")
    return {"status": "verified", "detail": detail, "id": declared_id, "store": store, "other_keys": others}
