"""Open VSX (open-vsx.org), the extension registry VSCodium, Cursor and other VS Code builds install from.

Three uses: an extension's metadata (whether its publisher is verified, downloads, when this version was published),
looked up for each extension assessed; and downloading one exact version by its ID (--extension), checked against
the SHA-256 Open VSX publishes for it; and Open VSX's signature on a .vsix, checked when the optional
`signatures` extra (cryptography) is installed. Open VSX signs every file it serves with its own Ed25519 key
(the signature over the whole .vsix, in a .sigzip next to it, as node-ovsx-sign writes it). That shows the file
is the one Open VSX signed, wherever it was fetched from; the key is Open VSX's, fetched from it, so it does not
guard against Open VSX itself. The VS Code Marketplace's own API is not used: it is unofficial, and its
terms tie it to Microsoft's products (and its signatures need Microsoft's proprietary vsce-sign).
"""

from __future__ import annotations

import hashlib
import io
import re
import zipfile
from pathlib import Path
from urllib.parse import quote, urlparse

from .http import Http, HttpError, prefetch
from .inputs import InputError

API = "https://open-vsx.org/api"
MAX_VSIX_BYTES = 500 * 1024 * 1024  # the largest extensions are a few hundred MB
MAX_LOOKUPS = 300  # metadata lookups per run (a folder of installed extensions)
MAX_SIGZIP_BYTES = 1024 * 1024  # a .sigzip holds a 64-byte signature and a manifest of the files' hashes
INSTALL_SIGNATURES = "pip install 'oss-intake[signatures]'"
# publisher.name@version, as VS Code shows an extension's ID; the version exact, never "latest".
_ID = re.compile(r"^(?P<ns>[A-Za-z0-9][\w-]{0,99})\.(?P<name>[A-Za-z0-9][\w.-]{0,199})@(?P<version>\d[\w.+-]{0,99})$")


def parse_id(value: str) -> tuple[str, str, str]:
    """('publisher', 'name', 'version') from publisher.name@version. ValueError otherwise."""
    m = _ID.match(value.strip())
    if not m:
        raise ValueError("use publisher.name@version, e.g. redhat.java@1.36.0 (an exact version)")
    return m.group("ns"), m.group("name"), m.group("version")


def _ns_name(ext_id: str) -> tuple[str, str]:
    ns, _, name = ext_id.partition(".")
    return ns, name


def _url(ns: str, name: str, version: str | None = None) -> str:
    return f"{API}/{quote(ns, safe='')}/{quote(name, safe='')}" + (f"/{quote(version, safe='')}" if version else "")


def summary(data: object) -> dict:
    """What the report shows of an Open VSX extension answer."""
    if not isinstance(data, dict):
        return {"found": False}
    by = data.get("publishedBy")
    return {"found": True, "version": str(data.get("version") or ""),
            "verified": data.get("verified") is True,
            "downloads": data.get("downloadCount") if isinstance(data.get("downloadCount"), int) else None,
            "published": str(data.get("timestamp") or "")[:10],
            "published_by": str(by.get("loginName") or "") if isinstance(by, dict) else "",
            "review_status": str(data.get("reviewStatus") or ""),
            "pre_release": data.get("preRelease") is True}


def lookup(http: Http, extensions: list[dict]) -> dict:
    """Open VSX metadata for each extension (its exact version), added as e["open_vsx"]. Returns stats."""
    usable = [e for e in extensions if "." in e["id"] and e["version"]]
    todo = usable[:MAX_LOOKUPS]
    prefetch(http, [_url(*_ns_name(e["id"]), e["version"]) for e in todo])
    stats = {"looked_up": 0, "found": 0, "errors": 0, "skipped_limit": len(usable) - len(todo),
             "skipped_no_id": len(extensions) - len(usable)}
    for e in todo:
        ns, name = _ns_name(e["id"])
        try:
            status, data = http.get_json(_url(ns, name, e["version"]))
        except HttpError:
            stats["errors"] += 1
            continue
        # Only a 404 says Open VSX does not have it; any other failure is a lookup that could not be made.
        if status == 404:
            e["open_vsx"] = {"found": False}
        elif status == 200 and isinstance(data, dict):
            e["open_vsx"] = summary(data)
        else:
            stats["errors"] += 1
            continue
        stats["looked_up"] += 1
        stats["found"] += e["open_vsx"]["found"]
    return stats


def _ed25519():
    """cryptography's Ed25519 public key class and InvalidSignature, or None when the extra is not installed."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
    except ImportError:
        return None
    return Ed25519PublicKey, InvalidSignature, load_pem_public_key


def check_signature(http: Http, data: dict, body: bytes) -> dict:
    """Open VSX's signature on body (the .vsix), from the version's answer (data). Returns {"status": ...}:
    verified, failed (the signature does not match: the file is not the one Open VSX signed), unsigned (Open VSX
    gives no signature for this version), or not_checked (the extra is missing, or the signature or key could not
    be fetched or read), with a detail. Never raises on a failed check: the caller decides."""
    got = data.get("files")
    files: dict = got if isinstance(got, dict) else {}
    sig_url, key_url = files.get("signature"), files.get("publicKey")
    if not (isinstance(sig_url, str) and isinstance(key_url, str)):
        return {"status": "unsigned", "detail": "Open VSX gives no signature for this version"}
    if any(urlparse(u).scheme != "https" for u in (sig_url, key_url)):
        return {"status": "not_checked", "detail": "Open VSX's signature or key link is not https"}
    crypto = _ed25519()
    if crypto is None:
        return {"status": "not_checked", "detail": f"the signature check needs the signatures extra: "
                                                   f"{INSTALL_SIGNATURES}"}
    key_class, invalid, load_key = crypto
    try:
        st, sigzip = http.get_bytes(sig_url, MAX_SIGZIP_BYTES)
        kst, pem = http.get_text(key_url)
    except HttpError as exc:
        return {"status": "not_checked", "detail": f"Open VSX's signature could not be fetched ({exc})"}
    if st != 200 or kst != 200:
        return {"status": "not_checked",
                "detail": f"Open VSX's signature or key returned HTTP {st if st != 200 else kst}"}
    try:
        with zipfile.ZipFile(io.BytesIO(sigzip)) as z:
            member = z.getinfo(".signature.sig")
            if member.file_size > 1024:
                raise ValueError("the signature is over 1 KB")
            signature = z.read(member)
        key = load_key((pem or "").encode("ascii", errors="strict"))
        if not isinstance(key, key_class):
            raise ValueError("Open VSX's key is not an Ed25519 key")
    except (zipfile.BadZipFile, KeyError, ValueError, UnicodeError, TypeError) as exc:
        return {"status": "not_checked", "detail": f"Open VSX's signature or key could not be read ({exc})"}
    try:
        key.verify(signature, body)
    except invalid:
        return {"status": "failed", "detail": "the file does not match Open VSX's Ed25519 signature for it"}
    return {"status": "verified", "detail": "Open VSX's Ed25519 signature matches"}


def check_file(http: Http, ext_id: str, version: str, path: Path) -> dict:
    """Open VSX's signature for a .vsix assessed from a file (--path): it applies only when the file is the one
    Open VSX serves for that version (same SHA-256); a build from the VS Code Marketplace is another file."""
    ns, name = _ns_name(ext_id)
    if not (ns and name and version):
        return {"status": "not_checked", "detail": "the extension has no publisher.name ID and version"}
    try:
        status, data = http.get_json(_url(ns, name, version))
        if status == 404:
            return {"status": "not_on_open_vsx", "detail": "Open VSX does not have this version"}
        if status != 200 or not isinstance(data, dict):
            return {"status": "not_checked", "detail": f"Open VSX returned HTTP {status}"}
        got = data.get("files")
        files: dict = got if isinstance(got, dict) else {}
        sha_url = files.get("sha256")
        st, text = http.get_text(sha_url) if isinstance(sha_url, str) and sha_url.startswith("https://") else (0, "")
    except HttpError as exc:
        return {"status": "not_checked", "detail": f"Open VSX could not be reached ({exc})"}
    want = re.match(r"^\s*([0-9a-fA-F]{64})\b", text or "") if st == 200 else None
    body = path.read_bytes()
    if not want:
        return {"status": "not_checked", "detail": "Open VSX's SHA-256 for this version could not be read"}
    if hashlib.sha256(body).hexdigest() != want.group(1).lower():
        return {"status": "other_build", "detail": "this file is not the one Open VSX serves for this version (a "
                                                   "VS Code Marketplace build, say), so Open VSX's signature does "
                                                   "not apply to it"}
    return check_signature(http, data, body)


def download(http: Http, ident: str, dest: Path) -> tuple[Path, dict]:
    """Download one exact version of an extension from Open VSX into dest and check it against the SHA-256 Open VSX
    publishes for that file. Returns (the .vsix, its metadata summary). InputError when it is not there, has no
    published hash, or the hash does not match; HttpError when Open VSX cannot be reached."""
    ns, name, version = parse_id(ident)
    status, data = http.get_json(_url(ns, name, version))
    if status == 404:
        raise InputError(f"--extension {ident}: not found on Open VSX")
    if status != 200 or not isinstance(data, dict):
        raise HttpError(f"Open VSX returned HTTP {status}" + ("" if status != 200 else " with an unreadable answer")
                        + f" for {ident}")
    files = data.get("files")
    files = files if isinstance(files, dict) else {}
    links: dict[str, str] = {}
    for what in ("download", "sha256"):
        u = files.get(what)
        if not isinstance(u, str) or urlparse(u).scheme != "https":
            raise InputError(f"--extension {ident}: Open VSX gives no https {what} link for it, so it cannot be "
                             "downloaded and checked")
        links[what] = u
    link, sha_link = links["download"], links["sha256"]
    st, text = http.get_text(sha_link)
    want = re.match(r"^\s*([0-9a-fA-F]{64})\b", text or "") if st == 200 else None
    if not want:
        raise InputError(f"--extension {ident}: Open VSX's SHA-256 for it could not be read (HTTP {st})")
    st, body = http.get_bytes(link, MAX_VSIX_BYTES)
    if st != 200:
        raise HttpError(f"Open VSX download of {ident} returned HTTP {st}")
    got = hashlib.sha256(body).hexdigest()
    if got != want.group(1).lower():
        raise InputError(f"--extension {ident}: the download does not match Open VSX's SHA-256 ({got} is not "
                         f"{want.group(1).lower()}); nothing was assessed")
    sig = check_signature(http, data, body)
    if sig["status"] == "failed":
        raise InputError(f"--extension {ident}: {sig['detail']}; nothing was assessed")
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / f"{ns}.{name}-{version}.vsix"
    path.write_bytes(body)
    # One version can have a build per platform; Open VSX answers with one of them, named here.
    target = data.get("targetPlatform")
    return path, {**summary(data), "sha256": got, "source": _url(ns, name, version),
                  "target_platform": target if isinstance(target, str) else "", "signature": sig}
