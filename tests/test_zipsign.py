"""The JetBrains Marketplace signature check (zipsign.py), against files signed here the way JetBrains'
marketplace-zip-signer signs them (ZipSigner.kt: the block before the central directory, the end record's offset
moved past it, a second signer added to an already signed file with the same digests)."""

from __future__ import annotations

import hashlib
import io
import struct
import zipfile

import pytest

from oss_intake import zipsign

x509 = pytest.importorskip("cryptography.x509")
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

from .zipsigner import _cert, _end, _key, _sections, make_pki, sign  # noqa: E402


@pytest.fixture(scope="module")
def pki():
    return make_pki()


def plugin_zip(extra: bytes = b"", comment: bytes = b"") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("demo/lib/demo.jar", b"jar bytes" + extra)
        z.writestr("demo/lib/other.jar", b"other")
        z.comment = comment
    return buf.getvalue()


def check(tmp_path, data: bytes, pki, name: str = "p.zip") -> dict:
    p = tmp_path / name
    p.write_bytes(data)
    return zipsign.check(p, trusted=pki["root"])


# ------------------------------------------------------------------------------------------- results


def test_marketplace_signed_file_verifies(tmp_path, pki):
    signed = sign(plugin_zip(), pki["chain"], pki["leaf_key"])
    got = check(tmp_path, signed, pki)
    assert got["status"] == "verified", got
    assert got["signers"] == ["CN=Test Marketplace"]
    # Still an ordinary zip to every reader.
    with zipfile.ZipFile(io.BytesIO(signed)) as z:
        assert z.read("demo/lib/demo.jar") == b"jar bytes"


def test_author_then_marketplace_signature(tmp_path, pki):
    """An author signs, then the Marketplace adds its signer with the same digest."""
    by_author = sign(plugin_zip(), pki["author"], pki["author_key"])
    assert check(tmp_path, by_author, pki)["status"] == "not_jetbrains"
    both = sign(by_author, pki["chain"], pki["leaf_key"])
    got = check(tmp_path, both, pki)
    assert got["status"] == "verified"
    assert got["signers"] == ["CN=Plugin Author", "CN=Test Marketplace"]


def test_unsigned_zip(tmp_path, pki):
    assert check(tmp_path, plugin_zip(), pki)["status"] == "unsigned"


def test_ecdsa_sha384_signer(tmp_path, pki):
    key = _key("ec")
    mid_key = _key()
    mid = _cert("Mid2", mid_key, "Test Root", pki["root_key"], ca=True)
    leaf = _cert("EC Signer", key, "Mid2", mid_key).public_bytes(serialization.Encoding.DER)
    chain = [leaf, mid.public_bytes(serialization.Encoding.DER), pki["root"]]
    got = check(tmp_path, sign(plugin_zip(), chain, key, "sha384"), pki)
    assert got["status"] == "verified", got


def test_sha512_and_large_file_over_several_chunks(tmp_path, pki):
    big = plugin_zip(extra=bytes(range(256)) * 12000)  # about 3 MB, stored: several 1 MB chunks
    assert len(big) > 2 * 1024 * 1024
    got = check(tmp_path, sign(big, pki["chain"], pki["leaf_key"], "sha512"), pki)
    assert got["status"] == "verified", got


def test_zip_with_comment(tmp_path, pki):
    got = check(tmp_path, sign(plugin_zip(comment=b"a comment"), pki["chain"], pki["leaf_key"]), pki)
    assert got["status"] == "verified", got


@pytest.mark.parametrize("where", ["entry", "central_directory", "end_record"])
def test_changed_after_signing_fails(tmp_path, pki, where):
    signed = bytearray(sign(plugin_zip(comment=b"comment"), pki["chain"], pki["leaf_key"]))
    at = {"entry": signed.find(b"jar bytes"), "central_directory": signed.rfind(b"demo/lib/other.jar"),
          "end_record": signed.rfind(b"comment")}[where]
    signed[at] ^= 1
    got = check(tmp_path, bytes(signed), pki)
    assert got["status"] == "failed", got
    assert "changed after it was signed" in got["detail"]


def test_signature_that_does_not_verify_fails(tmp_path, pki):
    other_key = _key()
    got = check(tmp_path, sign(plugin_zip(), pki["chain"], other_key), pki)
    assert got["status"] == "failed"
    assert "does not verify" in got["detail"]


def test_broken_chain_fails(tmp_path, pki):
    """The leaf and its signature are fine, but the next certificate did not sign it."""
    chain = [pki["chain"][0], pki["author"][0], pki["root"]]
    got = check(tmp_path, sign(plugin_zip(), chain, pki["leaf_key"]), pki)
    assert got["status"] == "failed"
    assert "chain" in got["detail"]


def test_chain_not_ending_at_jetbrains_is_not_verified(tmp_path, pki):
    """A valid chain to another root: signed, but not by the Marketplace."""
    got = check(tmp_path, sign(plugin_zip(), pki["chain"][:2], pki["leaf_key"]), pki)
    assert got["status"] == "not_jetbrains"


def test_damaged_block_fails(tmp_path, pki):
    signed = sign(plugin_zip(), pki["chain"], pki["leaf_key"])
    before, block, cd, eocd = _sections(signed)
    # A length inside the protobuf now runs past the end.
    damaged = block[:8] + b"\x12\xff\xff\x03" + block[12:]
    got = check(tmp_path, before + damaged + cd + eocd, pki)
    assert got["status"] == "failed"
    assert "cannot be read" in got["detail"]


@pytest.mark.parametrize("kw, words", [({"version": 2}, "scheme version 2"), ({"digest_id": 9}, "digest algorithm 9"),
                                       ({"sig_id": 7}, "signature algorithm 7")])
def test_unknown_scheme_or_algorithm_is_not_checked(tmp_path, pki, kw, words):
    got = check(tmp_path, sign(plugin_zip(), pki["chain"], pki["leaf_key"], **kw), pki)
    assert got["status"] == "not_checked"
    assert words in got["detail"]


def test_without_the_extra_it_is_not_checked(tmp_path, pki, monkeypatch):
    monkeypatch.setattr(zipsign, "_crypto", lambda: None)
    got = check(tmp_path, sign(plugin_zip(), pki["chain"], pki["leaf_key"]), pki)
    assert got["status"] == "not_checked"
    assert "signatures extra" in got["detail"]


def test_the_digest_is_checked_without_the_extra(tmp_path, pki, monkeypatch):
    """hashlib is enough to see a file changed after signing: that verdict does not wait for the extra."""
    monkeypatch.setattr(zipsign, "_crypto", lambda: None)
    signed = bytearray(sign(plugin_zip(), pki["chain"], pki["leaf_key"]))
    signed[signed.find(b"jar bytes")] ^= 1
    assert check(tmp_path, bytes(signed), pki)["status"] == "failed"
    assert check(tmp_path, plugin_zip(), pki)["status"] == "unsigned"


def test_a_block_with_no_signer_is_unsigned(tmp_path, pki):
    """Digests but no signer: nothing says who made it, as the IDE treats it."""
    signed = sign(plugin_zip(), pki["chain"], pki["leaf_key"])
    before, block, cd, eocd = _sections(signed)
    proto = block[8:-24]
    # Rebuild the block keeping only its digests (field 1 of the content).
    from .zipsigner import _pb, _read_pb
    content = next(v for n, v in _read_pb(proto) if n == 2)
    digests_only = b"".join(_pb(1, v) for n, v in _read_pb(content) if n == 1)
    new = _pb(1, 1) + _pb(2, digests_only)
    size = len(new) + 24
    nb = struct.pack("<Q", size) + new + struct.pack("<QQQ", size, 0x20676953204B5040, 0x3234206B636F6C42)
    got = check(tmp_path, before + nb + cd + _end(eocd, len(before) + len(nb)), pki)
    assert got["status"] == "unsigned" and "no signer" in got["detail"]


def test_not_a_zip_is_not_checked(tmp_path, pki):
    """No zip records is not evidence of a changed file: the check could not be made."""
    got = check(tmp_path, b"not a zip at all, just text " * 3, pki)
    assert got["status"] == "not_checked"
    assert "zip layout" in got["detail"]


def test_block_size_lies_are_no_block(tmp_path, pki):
    """A footer whose size runs before the start of the file is read as no block, as the signer reads it."""
    data = plugin_zip()
    before, _, cd, eocd = _sections(data)
    fake = struct.pack("<QQQ", 10 ** 9, 0x20676953204B5040, 0x3234206B636F6C42)
    got = check(tmp_path, before + fake + cd + _end(eocd, len(before) + len(fake)), pki)
    assert got["status"] == "unsigned"


def test_bundled_jetbrains_certificate():
    der = zipsign.jetbrains_ca()
    assert hashlib.sha256(der).hexdigest() == zipsign.JETBRAINS_CA_SHA256
    cert = x509.load_der_x509_certificate(der)
    assert cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "JetBrains CA 2200"


def test_default_trust_is_jetbrains_only(tmp_path, pki):
    """Signed by the test root: valid, but not JetBrains', so not verified by default."""
    p = tmp_path / "p.zip"
    p.write_bytes(sign(plugin_zip(), pki["chain"], pki["leaf_key"]))
    assert zipsign.check(p)["status"] == "not_jetbrains"
