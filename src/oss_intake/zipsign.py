"""The JetBrains Marketplace signature on a plugin file (.zip or .jar).

The Marketplace signs every plugin file it serves with a signing block placed just before the zip's central
directory, in the scheme of JetBrains' marketplace-zip-signer (github.com/JetBrains/marketplace-zip-signer): a
protobuf message with a digest of the file (SHA-2 over 1 MB chunks of the bytes before the block, the central
directory, and the end record as it would be without the block) and one or more signers, each with signatures of
that digest and an X.509 certificate chain. The plugin's author may sign it too; the Marketplace adds its own
signer, whose chain ends at the "JetBrains CA 2200" certificate the IDE ships (bundled here, from
intellij-community's plugin-signature-verifier/resources/ca.crt).

The check is the IDE's (PluginSignatureVerifierImpl with ZipVerifier): every digest matches, every signature is
made by its chain's first certificate, each certificate in a chain is signed by the next, and one chain ends at
JetBrains' certificate. Like the IDE, it does not look at certificate dates or revocation. It needs the
cryptography package (the signatures extra). Nothing in the file is run or unpacked.
"""

from __future__ import annotations

import hashlib
import struct
from importlib import resources
from pathlib import Path

_MAGIC_LO = 0x20676953204B5040  # "@PK Sig "
_MAGIC_HI = 0x3234206B636F6C42  # "Block 42"
_FOOTER = 24  # block size (u64), then the two magic values
_EOCD_SIG = 0x06054B50
_EOCD_MIN = 22
_CHUNK = 1024 * 1024
MAX_BLOCK = 1024 * 1024  # a real block holds a few certificates and signatures: a few KB
MAX_SIGNERS = 16
MAX_ITEMS = 16  # certificates or signatures per signer, digests per block

JETBRAINS_CA_SHA256 = "69f9cf4e57198db4a346f6eff75b192f16bf146cf0640fbb80d0c495bcc005d3"

# The protobuf enums (marketplace-zip-signer's zip_metadata.proto): digest and signature algorithm IDs.
_DIGESTS = {0: ("sha256", "SHA-256"), 1: ("sha512", "SHA-512"), 2: ("sha384", "SHA-384")}
_SIGNATURES = {0: ("rsa", "sha256"), 2: ("rsa", "sha512"), 3: ("dsa", "sha256"), 4: ("ecdsa", "sha384")}


class _Unreadable(Exception):
    """The signing block is there but cannot be read as the scheme defines it."""


class _Layout(Exception):
    """The file's zip records cannot be found or are out of range (not a zip, a zip64 file, a damaged one)."""


class _Unsupported(Exception):
    """The signing block uses something this check does not know (a newer scheme or algorithm)."""


# ------------------------------------------------------------------------------------------- protobuf

def _varint(buf: bytes, i: int) -> tuple[int, int]:
    value = shift = 0
    while True:
        if i >= len(buf) or shift > 63:
            raise _Unreadable("a number in the signing block is cut off")
        b = buf[i]
        i += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, i
        shift += 7


def _fields(buf: bytes) -> list[tuple[int, int | bytes]]:
    """A protobuf message's fields as (number, value): an int for a varint, bytes for a length-delimited one.
    Fixed-size fields are skipped, as a reader that does not know them would."""
    out: list[tuple[int, int | bytes]] = []
    i = 0
    while i < len(buf):
        key, i = _varint(buf, i)
        number, wire = key >> 3, key & 7
        if number == 0:
            raise _Unreadable("a field in the signing block has number 0")
        if wire == 0:
            value, i = _varint(buf, i)
            out.append((number, value))
        elif wire == 2:
            size, i = _varint(buf, i)
            if size > len(buf) - i:
                raise _Unreadable("a field in the signing block runs past its end")
            out.append((number, buf[i:i + size]))
            i += size
        elif wire in (1, 5):
            i += 8 if wire == 1 else 4
            if i > len(buf):
                raise _Unreadable("a field in the signing block runs past its end")
        else:
            raise _Unreadable(f"the signing block has a field of unknown wire type {wire}")
    return out


def _bytes(fields: list, number: int) -> list[bytes]:
    # A known field sent with another wire type is an unknown field to protobuf: skipped, as Java's reader does.
    return [v for n, v in fields if n == number and isinstance(v, bytes)]


def _int(fields: list, number: int) -> int:
    """A uint32 or enum (int32) field, as Java reads it: the low 32 bits; a missing one is 0, the last one wins."""
    got = [v for n, v in fields if n == number and isinstance(v, int)]
    return (got[-1] & 0xFFFFFFFF) if got else 0


def _parse(block: bytes) -> tuple[list[tuple[int, bytes]], list[tuple[list[bytes], list[tuple[int, bytes]]]]]:
    """(digests as (algorithm ID, bytes), signers as (DER certificates, signatures as (algorithm ID, bytes)))."""
    top = _fields(block)
    version = _int(top, 1)
    if version != 1:
        raise _Unsupported(f"signature scheme version {version} (this check knows version 1)")
    # Repeated occurrences of a message field are merged (their fields concatenated), as protobuf does.
    content = _fields(b"".join(_bytes(top, 2)))
    digests = []
    for d in _bytes(content, 1)[:MAX_ITEMS + 1]:
        f = _fields(d)
        digests.append((_int(f, 1), (_bytes(f, 2) or [b""])[-1]))
    signers = []
    raw_signers = _bytes(content, 2)
    if len(raw_signers) > MAX_SIGNERS:
        raise _Unreadable(f"the signing block has more than {MAX_SIGNERS} signers")
    for s in raw_signers:
        f = _fields(s)
        certs, sigs = _bytes(f, 1), []
        for sd in _bytes(f, 2):
            g = _fields(sd)
            sigs.append((_int(g, 1), (_bytes(g, 2) or [b""])[-1]))
        if len(certs) > MAX_ITEMS or len(sigs) > MAX_ITEMS:
            raise _Unreadable(f"a signer has more than {MAX_ITEMS} certificates or signatures")
        signers.append((certs, sigs))
    if len(digests) > MAX_ITEMS:
        raise _Unreadable(f"the signing block has more than {MAX_ITEMS} digests")
    return digests, signers


# ------------------------------------------------------------------------------------------- zip layout

def _read(fh, offset: int, size: int) -> bytes:
    fh.seek(offset)
    data = fh.read(size)
    if len(data) != size:
        raise _Unreadable("the file is shorter than its zip records say")
    return data


def _eocd(fh, size: int) -> tuple[int, int, int]:
    """(end record offset, central directory offset, central directory size), as the signer finds them: the end
    record whose comment length matches its distance from the end of the file, nearest the end. The digest does
    not cover bytes between the central directory and the end record, so check() refuses a signed file with any
    (zipfile finds the directory from the end record, so such bytes could be a second directory it reads)."""
    if size < _EOCD_MIN:
        raise _Layout("the file is too short to be a zip")
    tail_size = min(size, _EOCD_MIN + 0xFFFF)
    tail = _read(fh, size - tail_size, tail_size)
    for comment in range(tail_size - _EOCD_MIN + 1):
        at = tail_size - _EOCD_MIN - comment
        sig, cd_size, cd_offset, comment_len = struct.unpack_from("<I8xIIH", tail, at)
        if sig == _EOCD_SIG and comment_len == comment:
            eocd = size - tail_size + at
            if cd_offset > eocd or cd_offset + cd_size > eocd:
                raise _Layout("the zip's central directory is out of range (a zip64 file, or a damaged one)")
            return eocd, cd_offset, cd_size
    raise _Layout("the zip's end record was not found")


def _chunked(fh, sections: list[tuple[int, int] | bytes], algorithms: set[str]) -> dict[str, bytes]:
    """The scheme's digest: 0x5a, the chunk count (u32), then each 1 MB chunk's hash of 0x5a, its length (u32) and
    its bytes, over the sections in order (file ranges, or bytes)."""
    def chunks():
        for sec in sections:
            if isinstance(sec, bytes):
                for i in range(0, len(sec), _CHUNK):
                    yield sec[i:i + _CHUNK]
                continue
            start, length = sec
            for i in range(0, length, _CHUNK):
                yield _read(fh, start + i, min(_CHUNK, length - i))

    count = sum(((len(s) if isinstance(s, bytes) else s[1]) + _CHUNK - 1) // _CHUNK for s in sections)
    out = {a: bytearray(b"\x5a" + struct.pack("<I", count)) for a in algorithms}
    for chunk in chunks():
        prefix = b"\x5a" + struct.pack("<I", len(chunk))
        for a in algorithms:
            out[a] += hashlib.new(a, prefix + chunk).digest()
    return {a: bytes(v) for a, v in out.items()}


# ------------------------------------------------------------------------------------------- the check

def _crypto():
    """The cryptography pieces the check needs, or None when the signatures extra is not installed."""
    try:
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, padding, rsa
    except ImportError:
        return None
    return x509, InvalidSignature, hashes, dsa, ec, ed448, ed25519, padding, rsa


def jetbrains_ca() -> bytes:
    """JetBrains' certificate (DER), checked against its pinned SHA-256."""
    pem = resources.files("oss_intake").joinpath("data/jetbrains-ca-2200.pem").read_bytes()
    from base64 import b64decode

    body = b"".join(line for line in pem.splitlines() if line and not line.startswith(b"-----"))
    der = b64decode(body, validate=True)
    if hashlib.sha256(der).hexdigest() != JETBRAINS_CA_SHA256:
        raise RuntimeError("the bundled JetBrains certificate does not match its pinned SHA-256")
    return der


def _verify_signature(c, key, signature: bytes, data: bytes, kind: str, digest: str) -> None:
    x509, invalid, hashes, dsa, ec, ed448, ed25519, padding, rsa = c
    h = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}[digest]()
    if kind == "rsa" and isinstance(key, rsa.RSAPublicKey):
        key.verify(signature, data, padding.PKCS1v15(), h)
    elif kind == "ecdsa" and isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(signature, data, ec.ECDSA(h))
    elif kind == "dsa" and isinstance(key, dsa.DSAPublicKey):
        key.verify(signature, data, h)
    else:
        raise invalid  # the certificate's key is not the kind the signature says


def _signed_by(c, cert, issuer) -> bool:
    """Whether cert's signature verifies with issuer's key (the IDE's Certificate.verify: the signature only)."""
    x509, invalid, hashes, dsa, ec, ed448, ed25519, padding, rsa = c
    try:
        key = issuer.public_key()  # an unknown key algorithm raises UnsupportedAlgorithm
        if isinstance(key, rsa.RSAPublicKey):
            params = cert.signature_algorithm_parameters
            key.verify(cert.signature, cert.tbs_certificate_bytes,
                       params if isinstance(params, (padding.PKCS1v15, padding.PSS)) else padding.PKCS1v15(),
                       cert.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        elif isinstance(key, dsa.DSAPublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, cert.signature_hash_algorithm)
        elif isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            key.verify(cert.signature, cert.tbs_certificate_bytes)
        else:
            return False
    except Exception:  # noqa: BLE001 - any failure to verify (wrong key, unsupported hash) is "not signed by"
        return False
    return True


def _name(cert) -> str:
    try:
        return cert.subject.rfc4514_string()[:200]
    except Exception:  # noqa: BLE001 - an odd subject is shown as unreadable, not fatal
        return "(unreadable subject)"


def check(path: Path, trusted: bytes | None = None) -> dict:
    """The Marketplace signature on a plugin file. Returns {"status", "detail", "signers"}: verified (signed, and one
    signer's chain ends at JetBrains' certificate), not_jetbrains (validly signed, but by none chaining to
    JetBrains: an author's own signature only), unsigned (no signing block, or one with no signer), failed (a
    signing block is there but the file does not match it: changed after signing, or the block is damaged), or
    not_checked (the block uses something this check does not know, or the signatures need the extra: the digest,
    which needs only hashlib, is checked without it). Never raises on a bad file."""
    trusted = trusted if trusted is not None else jetbrains_ca()
    try:
        with path.open("rb") as fh:
            size = path.stat().st_size
            eocd, cd_offset, cd_size = _eocd(fh, size)
            gap = eocd - (cd_offset + cd_size)
            if cd_offset < _FOOTER + 8:
                return {"status": "unsigned", "detail": "the file has no signing block", "signers": []}
            block_size, lo, hi = struct.unpack("<QQQ", _read(fh, cd_offset - _FOOTER, _FOOTER))
            # A malformed footer or header counts as no block, as the signer reads it.
            total = block_size + 8
            if (lo, hi) != (_MAGIC_LO, _MAGIC_HI) or block_size < _FOOTER or total > cd_offset:
                return {"status": "unsigned", "detail": "the file has no signing block", "signers": []}
            start = cd_offset - total
            if struct.unpack("<Q", _read(fh, start, 8))[0] != block_size:
                return {"status": "unsigned", "detail": "the file has no signing block", "signers": []}
            if gap:
                return {"status": "failed", "detail": f"the file has {gap} byte(s) between its central directory "
                                                      "and end record, which the signature does not cover (a "
                                                      "signer never leaves any)", "signers": []}
            if total - 32 > MAX_BLOCK:
                raise _Unreadable(f"the signing block is over {MAX_BLOCK // 1024} KB")
            digests, signers = _parse(_read(fh, start + 8, total - 32))
            if not digests:
                raise _Unreadable("the signing block has no digest")
            known: dict[str, list[bytes]] = {}
            for alg, value in digests:
                if alg not in _DIGESTS:
                    raise _Unsupported(f"digest algorithm {alg}")
                known.setdefault(_DIGESTS[alg][0], []).append(value)
            # The end record as it would be without the block: its central directory offset is where the block
            # starts.
            end = bytearray(_read(fh, eocd, size - eocd))
            struct.pack_into("<I", end, 16, start)
            actual = _chunked(fh, [(0, start), (cd_offset, cd_size), bytes(end)], set(known))
        for name, values in known.items():
            if any(v != actual[name] for v in values):
                return {"status": "failed", "detail": f"the file does not match its signed {name.upper()} digest: it "
                                                      "was changed after it was signed", "signers": []}
        if not signers:
            return {"status": "unsigned", "detail": "the file's signing block has no signer", "signers": []}
        c = _crypto()
        if c is None:
            return {"status": "not_checked", "detail": "the file matches its signed digest, but checking who signed "
                                                       "it needs the signatures extra", "signers": []}
        x509 = c[0]
        chains = []
        for certs, sigs in signers:
            if not sigs:
                raise _Unreadable("a signer has no signatures")
            if not certs:
                raise _Unreadable("a signer has no certificates")
            try:
                chain = [x509.load_der_x509_certificate(d) for d in certs]
            except Exception as exc:  # noqa: BLE001 - ValueError, InvalidVersion, anything a hostile DER causes
                raise _Unreadable(f"a certificate cannot be read ({type(exc).__name__})") from None
            for alg, signature in sigs:
                if alg not in _SIGNATURES:
                    raise _Unsupported(f"signature algorithm {alg}")
                kind, dg = _SIGNATURES[alg]
                if dg not in actual:
                    return {"status": "failed", "detail": f"a signature uses a {dg.upper()} digest the block does "
                                                          "not hold", "signers": []}
                try:
                    _verify_signature(c, chain[0].public_key(), signature, actual[dg], kind, dg)
                except Exception:  # noqa: BLE001 - invalid, or the key cannot make this kind of signature
                    return {"status": "failed", "detail": f"a signature by {_name(chain[0])} does not verify",
                            "signers": []}
            if not all(_signed_by(c, a, b) for a, b in zip(chain, chain[1:], strict=False)):
                return {"status": "failed", "detail": f"the certificate chain of {_name(chain[0])} is broken",
                        "signers": []}
            chains.append((chain, certs))
    except _Unsupported as exc:
        return {"status": "not_checked", "detail": f"the signing block uses {exc}, which this check does not know",
                "signers": []}
    except _Layout as exc:
        return {"status": "not_checked", "detail": f"the file's zip layout could not be read: {exc}", "signers": []}
    except _Unreadable as exc:
        return {"status": "failed", "detail": f"the signing block cannot be read: {exc}", "signers": []}
    except (OSError, ValueError, struct.error) as exc:
        return {"status": "not_checked", "detail": f"the file could not be read ({type(exc).__name__}: {exc})"[:300],
                "signers": []}
    except Exception as exc:  # noqa: BLE001 - "never raises on a bad file": anything else is no verdict either
        return {"status": "not_checked", "detail": f"the signature could not be checked ({type(exc).__name__})",
                "signers": []}
    names = [_name(chain[0]) for chain, _ in chains]
    if any(certs[-1] == trusted for _, certs in chains):
        return {"status": "verified", "detail": "signed by the JetBrains Marketplace (its chain ends at JetBrains' "
                                                "certificate)", "signers": names}
    return {"status": "not_jetbrains", "detail": "validly signed, but not by the JetBrains Marketplace (no chain "
                                                 "ends at JetBrains' certificate)", "signers": names}
