"""Write CRX3 files as Chromium's crx_creator and the Chrome Web Store do: a CrxFileHeader with key proofs (RSA
PKCS#1 v1.5 or ECDSA P-256, both over SHA-256) and the signed data naming the ID, then the zip. Keys are made here;
a "store" key stands in for the Chrome Web Store's (tests point crxsign.STORE_KEY_SHA256 at it)."""

from __future__ import annotations

import hashlib
import io
import struct
import zipfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from oss_intake.crxsign import CONTEXT, extension_id


def _pb(number: int, value: bytes) -> bytes:
    def varint(n: int) -> bytes:
        out = bytearray()
        while True:
            out.append((n & 0x7F) | (0x80 if n > 0x7F else 0))
            n >>= 7
            if not n:
                return bytes(out)
    return varint(number << 3 | 2) + varint(len(value)) + value


def spki(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def zip_of(members: dict[str, str | bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


def sign(archive: bytes, developer, others=(), crx_id: bytes | None = None, extra_header: bytes = b"") -> bytes:
    """A CRX3 file of archive, signed by the developer's key (whose key gives the ID, unless crx_id overrides it)
    and by each of others."""
    if crx_id is None:
        crx_id = hashlib.sha256(spki(developer)).digest()[:16]
    signed = _pb(1, crx_id)
    message = CONTEXT + struct.pack("<I", len(signed)) + signed + archive
    proofs = b""
    for key in (developer, *others):
        if isinstance(key, rsa.RSAPrivateKey):
            proofs += _pb(2, _pb(1, spki(key)) + _pb(2, key.sign(message, padding.PKCS1v15(), hashes.SHA256())))
        else:
            proofs += _pb(3, _pb(1, spki(key)) + _pb(2, key.sign(message, ec.ECDSA(hashes.SHA256()))))
    header = proofs + extra_header + _pb(10000, signed)
    return b"Cr24" + struct.pack("<II", 3, len(header)) + header + archive


def id_of(key) -> str:
    return extension_id(spki(key))
