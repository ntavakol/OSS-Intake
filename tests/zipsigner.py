"""A signer for tests, as JetBrains' marketplace-zip-signer signs (ZipSigner.kt): the signing block before the
central directory, the end record's offset moved past it, a second signer added to an already signed file with the
same digests. Needs cryptography (import it after pytest.importorskip)."""

from __future__ import annotations

import datetime
import hashlib
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID


def _pb_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _read_varint(buf: bytes, i: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        b = buf[i]
        i += 1
        value |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return value, i


def _read_pb(buf: bytes) -> list[tuple[int, int | bytes]]:
    """The fields of a protobuf message this signer wrote (varints and length-delimited only)."""
    out: list[tuple[int, int | bytes]] = []
    i = 0
    while i < len(buf):
        key, i = _read_varint(buf, i)
        if key & 7 == 0:
            value, i = _read_varint(buf, i)
            out.append((key >> 3, value))
        else:
            size, i = _read_varint(buf, i)
            out.append((key >> 3, buf[i:i + size]))
            i += size
    return out


def _pb(number: int, value: int | bytes) -> bytes:
    if isinstance(value, int):
        return _pb_varint(number << 3) + _pb_varint(value)
    return _pb_varint(number << 3 | 2) + _pb_varint(len(value)) + value


DIGEST_IDS = {"sha256": 0, "sha512": 1, "sha384": 2}


def _key(kind: str = "rsa"):
    return (ec.generate_private_key(ec.SECP384R1()) if kind == "ec"
            else rsa.generate_private_key(public_exponent=65537, key_size=2048))


def _cert(name: str, key, issuer_name: str | None = None, issuer_key=None, ca: bool = False):
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name or name)])
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now)
               .not_valid_after(now + datetime.timedelta(days=3650))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    return builder.sign(issuer_key or key, hashes.SHA256())


def make_pki():
    """A root (standing in for JetBrains' certificate), an intermediate, a leaf under it, and an author's own
    self-signed certificate."""
    root_key, mid_key, leaf_key, author_key = _key(), _key(), _key(), _key()
    root = _cert("Test Root", root_key, ca=True)
    mid = _cert("Test Intermediate", mid_key, "Test Root", root_key, ca=True)
    leaf = _cert("Test Marketplace", leaf_key, "Test Intermediate", mid_key)
    author = _cert("Plugin Author", author_key)
    der = lambda c: c.public_bytes(serialization.Encoding.DER)  # noqa: E731
    return {"root": der(root), "chain": [der(leaf), der(mid), der(root)], "leaf_key": leaf_key,
            "author": [der(author)], "author_key": author_key, "mid": der(mid), "root_key": root_key}


def _sections(data: bytes):
    """(before the block, the block or b"", central directory, end record), as ZipUtils finds them."""
    eocd = data.rfind(b"PK\x05\x06")
    cd_size, cd_offset = struct.unpack_from("<II", data, eocd + 12)
    block = b""
    if cd_offset >= 32 and data[cd_offset - 16:cd_offset] == struct.pack("<QQ", 0x20676953204B5040,
                                                                             0x3234206B636F6C42):
        size = struct.unpack_from("<Q", data, cd_offset - 24)[0]
        block = data[cd_offset - size - 8:cd_offset]
    return data[:cd_offset - len(block)], block, data[cd_offset:cd_offset + cd_size], data[eocd:]


def _end(eocd: bytes, offset: int) -> bytes:
    out = bytearray(eocd)
    struct.pack_into("<I", out, 16, offset)
    return bytes(out)


def _digest(alg: str, before: bytes, cd: bytes, eocd: bytes) -> bytes:
    chunks = [s[i:i + 1024 * 1024] for s in (before, cd, _end(eocd, len(before)))
              for i in range(0, len(s), 1024 * 1024)]
    out = b"\x5a" + struct.pack("<I", len(chunks))
    for c in chunks:
        out += hashlib.new(alg, b"\x5a" + struct.pack("<I", len(c)) + c).digest()
    return out


def _sign_bytes(key, data: bytes, alg: str) -> bytes:
    h = {"sha256": hashes.SHA256(), "sha512": hashes.SHA512(), "sha384": hashes.SHA384()}[alg]
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return key.sign(data, ec.ECDSA(h))
    return key.sign(data, padding.PKCS1v15(), h)


def sign(data: bytes, certs: list[bytes], key, alg: str = "sha256", *, version: int = 1,
         digest_id: int | None = None, sig_id: int | None = None) -> bytes:
    """data signed, as ZipSigner.sign does: an existing block's digests and signers are kept, a new signer is added."""
    before, block, cd, eocd = _sections(data)
    digests: list[tuple[int, bytes]] = []
    signers: list[bytes] = []
    if block:
        content = _read_pb(next(v for n, v in _read_pb(block[8:-24]) if n == 2))
        for n, d in content:
            if n == 1:
                f = dict(_read_pb(d))
                digests.append((f.get(1, 0), f[2]))
        signers = [v for n, v in content if n == 2]
    if not any(i == DIGEST_IDS[alg] for i, _ in digests):
        digests.append((DIGEST_IDS[alg], _digest(alg, before, cd, eocd)))
    value = next(v for i, v in digests if i == DIGEST_IDS[alg])
    sig_alg = sig_id if sig_id is not None else {"sha256": 0, "sha512": 2, "sha384": 4}[alg]
    signer = b"".join(_pb(1, c) for c in certs) + _pb(2, _pb(1, sig_alg) + _pb(2, _sign_bytes(key, value, alg)))
    signers.append(signer)
    content = b"".join(_pb(1, _pb(1, digest_id if digest_id is not None else i) + _pb(2, v)) for i, v in digests)
    content += b"".join(_pb(2, s) for s in signers)
    proto = _pb(1, version) + _pb(2, content)
    size = len(proto) + 24
    new_block = struct.pack("<Q", size) + proto + struct.pack("<QQQ", size, 0x20676953204B5040, 0x3234206B636F6C42)
    return before + new_block + cd + _end(eocd, len(before) + len(new_block))
