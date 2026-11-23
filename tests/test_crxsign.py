"""The CRX3 signature check (crxsign.py), against files signed here as Chromium's crx_creator and the Chrome Web
Store sign them (tests/crxsigner.py). The rules are Chromium's crx_verifier.cc: every proof verifies, one is by the
key the ID comes from, a store file also carries the store's proof, and a header holding a zip end record is
refused."""

from __future__ import annotations

import hashlib
import json
import struct

import pytest

from oss_intake import crxsign

pytest.importorskip("cryptography")
from .crxsigner import _pb, ec_key, id_of, rsa_key, sign, spki, zip_of  # noqa: E402

MANIFEST = json.dumps({"manifest_version": 3, "name": "Signed example", "version": "1.0.0"})


@pytest.fixture(scope="module")
def keys():
    return {"dev": rsa_key(), "store": rsa_key(), "other": ec_key(), "ec_dev": ec_key()}


@pytest.fixture
def store_is(monkeypatch, keys):
    monkeypatch.setattr(crxsign, "STORE_KEY_SHA256", hashlib.sha256(spki(keys["store"])).digest())


def check(tmp_path, data: bytes) -> dict:
    p = tmp_path / "x.crx"
    p.write_bytes(data)
    return crxsign.check(p)


def archive() -> bytes:
    return zip_of({"manifest.json": MANIFEST, "bg.js": "console.log(1);"})


def test_a_store_file_verifies(tmp_path, keys, store_is):
    got = check(tmp_path, sign(archive(), keys["dev"], [keys["store"]]))
    assert got["status"] == "verified" and got["store"] and got["id"] == id_of(keys["dev"])
    assert got["other_keys"] == [] and "Chrome Web Store" in got["detail"]


def test_a_developer_signed_file_verifies_but_is_not_the_stores(tmp_path, keys, store_is):
    got = check(tmp_path, sign(archive(), keys["dev"]))
    assert got["status"] == "verified" and not got["store"] and "developer's key only" in got["detail"]


def test_an_ecdsa_developer_key_and_another_signer(tmp_path, keys, store_is):
    got = check(tmp_path, sign(archive(), keys["ec_dev"], [keys["other"]]))
    assert got["status"] == "verified" and got["id"] == id_of(keys["ec_dev"])
    assert got["other_keys"] == [hashlib.sha256(spki(keys["other"])).hexdigest()]


def test_the_real_chrome_web_store_key_hash_is_pinned():
    # From Chromium's components/crx_file/crx_verifier.cc (kPublisherKeyHash).
    assert crxsign.STORE_KEY_SHA256.hex() == "61f7f2a6bfcf74cd0bc1fe2497cc9b04254c658f79f2145392867ea8366367cf"


@pytest.mark.parametrize("where", ["archive", "signed_data"])
def test_changed_after_signing_fails(tmp_path, keys, store_is, where):
    data = bytearray(sign(archive(), keys["dev"], [keys["store"]]))
    if where == "archive":
        data[data.find(b"console.log") + 1] ^= 1
    else:
        hsize = struct.unpack("<I", data[8:12])[0]
        header = bytes(data[12:12 + hsize])
        at = header.rfind(_pb(10000, b"")[:3])  # the signed data's field key
        data[12 + at + 6] ^= 1  # a byte of the 16-byte ID inside it
    got = check(tmp_path, bytes(data))
    assert got["status"] == "failed", got


def test_a_signature_by_the_store_that_does_not_verify_fails(tmp_path, keys, store_is):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding

    body = archive()
    signed = _pb(1, hashlib.sha256(spki(keys["dev"])).digest()[:16])
    message = crxsign.CONTEXT + struct.pack("<I", len(signed)) + signed + body
    dev_sig = keys["dev"].sign(message, padding.PKCS1v15(), hashes.SHA256())
    store_sig = keys["store"].sign(b"something else", padding.PKCS1v15(), hashes.SHA256())
    header = (_pb(2, _pb(1, spki(keys["dev"])) + _pb(2, dev_sig))
              + _pb(2, _pb(1, spki(keys["store"])) + _pb(2, store_sig)) + _pb(10000, signed))
    got = check(tmp_path, b"Cr24" + struct.pack("<II", 3, len(header)) + header + body)
    assert got["status"] == "failed" and "Chrome Web Store's key does not verify" in got["detail"]


def test_an_id_no_signer_owns_fails(tmp_path, keys):
    got = check(tmp_path, sign(archive(), keys["dev"], crx_id=b"\x01" * 16))
    assert got["status"] == "failed" and "no signature is by the key" in got["detail"]


def test_a_zip_end_record_in_the_header_fails(tmp_path, keys):
    got = check(tmp_path, sign(archive(), keys["dev"], extra_header=_pb(7, b"PK\x05\x06" + b"\0" * 18)))
    assert got["status"] == "failed" and "zip end record" in got["detail"]


@pytest.mark.parametrize("header, words", [
    (b"\x12\xff\xff\x03", "cannot be read"),
    (_pb(10000, _pb(1, b"short")), "16-byte extension ID"),
    (_pb(10000, _pb(1, b"\x00" * 16)), "no signature"),
])
def test_headers_that_cannot_be_trusted_fail(tmp_path, header, words):
    data = b"Cr24" + struct.pack("<II", 3, len(header)) + header + archive()
    got = check(tmp_path, data)
    assert got["status"] == "failed" and words in got["detail"]


def test_a_key_of_the_wrong_kind_fails(tmp_path, keys):
    # An EC key placed among the RSA proofs, with its ID made to match.
    ec = keys["ec_dev"]
    crx_id = hashlib.sha256(spki(ec)).digest()[:16]
    signed = _pb(10000, _pb(1, crx_id))
    header = _pb(2, _pb(1, spki(ec)) + _pb(2, b"sig")) + signed
    got = check(tmp_path, b"Cr24" + struct.pack("<II", 3, len(header)) + header + archive())
    assert got["status"] == "failed" and "key of another kind" in got["detail"]


def test_an_unreadable_key_fails(tmp_path):
    key = b"not a key"
    signed = _pb(10000, _pb(1, hashlib.sha256(key).digest()[:16]))
    header = _pb(2, _pb(1, key) + _pb(2, b"sig")) + signed
    got = check(tmp_path, b"Cr24" + struct.pack("<II", 3, len(header)) + header + archive())
    assert got["status"] == "failed" and "cannot be read" in got["detail"]


def test_too_many_signatures_fail(tmp_path, keys, monkeypatch):
    monkeypatch.setattr(crxsign, "MAX_PROOFS", 1)
    got = check(tmp_path, sign(archive(), keys["dev"], [keys["store"]]))
    assert got["status"] == "failed" and "more than 1" in got["detail"]


def test_without_the_extra_the_structure_is_still_checked(tmp_path, keys, monkeypatch, store_is):
    monkeypatch.setattr(crxsign, "_crypto", lambda: None)
    got = check(tmp_path, sign(archive(), keys["dev"], [keys["store"]]))
    assert got["status"] == "not_checked" and "signatures extra" in got["detail"]
    assert got["id"] == id_of(keys["dev"]) and not got["store"] and got["store_claimed"]
    assert check(tmp_path, sign(archive(), keys["dev"], crx_id=b"\x02" * 16))["status"] == "failed"


def test_not_a_crx_and_wrong_versions_fail(tmp_path):
    assert check(tmp_path, b"PK\x03\x04 not a crx")["status"] == "failed"
    assert check(tmp_path, b"Cr24" + struct.pack("<II", 2, 0) + b"PK")["status"] == "failed"
