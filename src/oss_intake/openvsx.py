"""Open VSX (open-vsx.org), the extension registry VSCodium, Cursor and other VS Code builds install from.

Two uses: an extension's metadata (whether its publisher is verified, downloads, when this version was published),
looked up for each extension assessed; and downloading one exact version by its ID (--extension), checked against
the SHA-256 Open VSX publishes for it. The VS Code Marketplace's own API is not used: it is unofficial, and its
terms tie it to Microsoft's products.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import quote, urlparse

from .http import Http, HttpError, prefetch
from .inputs import InputError

API = "https://open-vsx.org/api"
MAX_VSIX_BYTES = 500 * 1024 * 1024  # the largest extensions are a few hundred MB
MAX_LOOKUPS = 300  # metadata lookups per run (a folder of installed extensions)
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
    todo = [e for e in extensions if "." in e["id"] and e["version"]][:MAX_LOOKUPS]
    prefetch(http, [_url(*_ns_name(e["id"]), e["version"]) for e in todo])
    stats = {"looked_up": 0, "found": 0, "errors": 0, "skipped_limit": max(0, len(extensions) - len(todo))}
    for e in todo:
        ns, name = _ns_name(e["id"])
        try:
            status, data = http.get_json(_url(ns, name, e["version"]))
        except HttpError:
            stats["errors"] += 1
            continue
        stats["looked_up"] += 1
        e["open_vsx"] = summary(data) if status == 200 else {"found": False}
        stats["found"] += e["open_vsx"]["found"]
    return stats


def download(http: Http, ident: str, dest: Path) -> tuple[Path, dict]:
    """Download one exact version of an extension from Open VSX into dest and check it against the SHA-256 Open VSX
    publishes for that file. Returns (the .vsix, its metadata summary). InputError when it is not there, has no
    published hash, or the hash does not match; HttpError when Open VSX cannot be reached."""
    ns, name, version = parse_id(ident)
    status, data = http.get_json(_url(ns, name, version))
    if status == 404 or not isinstance(data, dict):
        raise InputError(f"--extension {ident}: not found on Open VSX (HTTP {status})")
    if status != 200:
        raise HttpError(f"Open VSX returned HTTP {status} for {ident}")
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
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / f"{ns}.{name}-{version}.vsix"
    path.write_bytes(body)
    return path, {**summary(data), "sha256": got, "source": _url(ns, name, version)}
