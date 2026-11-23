"""Browser extensions for Chromium browsers (Chrome, Edge, Brave): a .crx file, an unpacked extension's folder, one
installed extension, or every extension installed in a browser profile.

The checks are static: what an extension's manifest asks for and how it is set up, read from its files. Nothing in
it is run, and what it does once running is not assessed. An extension is assessed on:
- the permissions and site access it asks for, each graded by what it lets the extension do;
- how it is set up: content scripts on every site, scripts that run before the page's own, pages that other
  sites or extensions can reach, its content security policy, where it updates from, settings it replaces;
- whether it is on oss-intake's known-bad list (integrity.known_bad_extension);
- the packages it ships, which the scanners check like any other (only those a package.json or lockfile
  describes: a library copied in as a plain .js file is not recognised).

A .crx is untrusted input: its header is read with fixed limits, and the zip after it is unpacked with the .vsix
limits (vscode.extract). A browser profile is only read, never written, and only its Extensions folder: the
profile's Preferences and the extensions' stored data hold personal data and are not opened.

Not flagged, on purpose: 'wasm-unsafe-eval' in a content security policy (Manifest V3 allows it by default, and
every extension that uses WebAssembly needs it), and an extension without an update_url (an unpacked copy, or one
installed by hand or by policy, has none).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import math
import os
import re
import shutil
import struct
import sys
from pathlib import Path

from . import jsonsafe
from .inputs import InputError

BROWSERS = {"chrome": "Chrome", "edge": "Edge", "brave": "Brave"}
# The default profile of each browser, under the user's home folder (macOS, Linux) or %LOCALAPPDATA% (Windows).
_PROFILE = {
    "chrome": {"darwin": "Library/Application Support/Google/Chrome/Default",
               "linux": ".config/google-chrome/Default", "win32": "Google/Chrome/User Data/Default"},
    "edge": {"darwin": "Library/Application Support/Microsoft Edge/Default",
             "linux": ".config/microsoft-edge/Default", "win32": "Microsoft/Edge/User Data/Default"},
    "brave": {"darwin": "Library/Application Support/BraveSoftware/Brave-Browser/Default",
              "linux": ".config/BraveSoftware/Brave-Browser/Default",
              "win32": "BraveSoftware/Brave-Browser/User Data/Default"},
}
# The stores' update addresses, as an installed extension's manifest records them.
STORE_UPDATE_URLS = {
    "https://clients2.google.com/service/update2/crx": "Chrome Web Store",
    "https://edge.microsoft.com/extensionwebstorebase/v1/crx": "Edge Add-ons",
}

CRX_MAGIC = b"Cr24"
MAX_CRX_BYTES = 500 * 1024 * 1024
MAX_CRX_HEADER = 1024 * 1024  # a real header holds a few keys and signatures: a few KB
MAX_MANIFEST_BYTES = 5_000_000
MAX_MESSAGES_BYTES = 5_000_000
MAX_EXTENSIONS = 2000  # in one profile
MAX_VERSIONS = 20  # version folders of one installed extension
MAX_ROWS = 50  # permissions, patterns or sources kept per item in a report
ID_RE = re.compile(r"^[a-p]{32}$")
# An installed extension's version folder: its version, then "_" and a number the browser adds.
_VERSION_FOLDER = re.compile(r"^(?P<version>[0-9][0-9.]{0,40})_(?P<n>[0-9]{1,6})$")
_MSG = re.compile(r"^__MSG_([A-Za-z0-9_@]{1,200})__$")

# ------------------------------------------------------------------------------------------- permissions

# Each permission an extension can ask for, graded by what it lets the extension do, with the reason shown in the
# report. A name not in this table is listed as "not graded", never dropped.
PERMISSIONS: dict[str, tuple[str, str]] = {
    "debugger": ("high", "attaches to tabs as a debugger: it can read and change every page and its network traffic"),
    "nativeMessaging": ("high", "talks to programs installed on the computer, outside the browser's sandbox"),
    "proxy": ("high", "can send all your browsing through a proxy it chooses"),
    "management": ("high", "can list, turn off and uninstall your other extensions"),
    "cookies": ("high", "can read and change cookies, sign-in sessions included, on the sites it can reach"),
    "webRequestBlocking": ("high", "can block and change web requests as they happen (Manifest V2)"),
    "webAuthenticationProxy": ("high", "can stand in for the browser's handling of passkeys and security keys"),
    "userScripts": ("high", "can run user scripts that are not part of the extension's own code"),
    "clipboardRead": ("high", "can read what you copy"),
    "desktopCapture": ("high", "can capture your screen and windows"),
    "tabCapture": ("high", "can capture what a tab shows and plays"),
    "webRequest": ("medium", "sees the web requests made to the sites it can reach"),
    "scripting": ("medium", "can run scripts in the pages of the sites it can reach"),
    "tabs": ("medium", "sees the address and title of every tab"),
    "webNavigation": ("medium", "sees every page you open"),
    "history": ("medium", "can read and change your browsing history"),
    "bookmarks": ("medium", "can read and change your bookmarks"),
    "downloads": ("medium", "can start, read and open downloads"),
    "browsingData": ("medium", "can delete your browsing data"),
    "sessions": ("medium", "sees recently closed tabs, and tabs on your other devices"),
    "privacy": ("medium", "can change the browser's privacy settings"),
    "contentSettings": ("medium", "can change per-site settings such as camera, location and JavaScript"),
    "pageCapture": ("medium", "can save whole pages"),
    "geolocation": ("medium", "can ask for your location"),
    "declarativeNetRequestWithHostAccess": ("medium", "can block and redirect requests on the sites it can reach"),
    "declarativeNetRequestFeedback": ("medium", "sees which of its rules matched which requests"),
    "identity": ("medium", "can sign you in to services with your browser account"),
    "identity.email": ("medium", "can read your browser account's email address"),
    "topSites": ("low", "sees your most visited sites"),
    "declarativeNetRequest": ("low", "can block and redirect requests by rules the browser applies"),
    "activeTab": ("low", "reaches only the tab you use it on, when you use it"),
    "clipboardWrite": ("low", "can change what is on the clipboard"),
    "contextMenus": ("low", "adds items to the right-click menu"),
    "notifications": ("low", "shows notifications"),
    "storage": ("low", "stores its own data"),
    "unlimitedStorage": ("low", "stores its own data without a size limit"),
    "alarms": ("low", "runs code on a schedule"),
    "idle": ("low", "sees when the computer is idle"),
    "offscreen": ("low", "uses a hidden page of its own"),
    "sidePanel": ("low", "shows a side panel"),
    "search": ("low", "can run a search with your default search engine"),
    "tts": ("low", "speaks text"),
    "fontSettings": ("low", "can change font settings"),
    "power": ("low", "can keep the computer awake"),
    "favicon": ("low", "reads sites' icons"),
}
ALL_SITES = "high", "can read and change every site you visit"
SOME_SITES = "medium", "can read and change the sites listed"
TIERS = ("high", "medium", "low", "not graded")
_ALL_HOSTS = re.compile(r"^(?:<all_urls>|(?:\*|https?|wss?|ftp|file)://\*(?::(?:\*|[0-9]{1,5}))?/.*"
                        r"|(?:\*|https?|wss?)://\*(?::(?:\*|[0-9]{1,5}))?)$")

# What a manifest is checked for, besides its permissions. Each is a signal for a person to look at, not a verdict.
SIGNALS = {
    "mv2": "Uses Manifest V2: Chrome turned MV2 extensions off in Chrome 138 (July 2025) and removed support in "
           "Chrome 139; Edge is turning them off for consumers by the end of 2026 and for managed devices in early "
           "2027. MV2 has none of MV3's limits, such as the ban on code loaded from the internet",
    "manifest-version": "Declares a manifest version Chromium browsers do not support",
    "cs-all-sites": "Runs a content script in every site you visit",
    "cs-start": "Runs a content script before the page's own scripts (run_at document_start)",
    "cs-all-frames": "Runs a content script in every frame of a page, embedded ones included (all_frames)",
    "cs-main-world": "Runs a content script in the page's own JavaScript, shared with the page (world MAIN)",
    "external-any": "Any other extension can send it messages (externally_connectable ids \"*\")",
    "external-pages": "Web pages can send it messages (externally_connectable matches)",
    "web-accessible": "Web pages can load some of its files, which also tells a site it is installed",
    "csp-eval": "Its content security policy allows eval ('unsafe-eval'): code built from text at run time",
    "csp-remote": "Its content security policy lets its pages load scripts from the internet",
    "csp-sandbox": "Its sandboxed pages may use eval or load scripts from the internet (they cannot use the "
                   "browser's extension APIs, but can send messages to pages that can)",
    "update-url": "Updates from a server that is not a store: whoever runs it can change the extension without "
                  "store review",
    "overrides-settings": "Replaces your search engine, home page or startup pages (chrome_settings_overrides)",
    "overrides-page": "Replaces a browser page, such as the new tab page (chrome_url_overrides)",
    "identity": "Its files do not agree on what it is (the folder name, its key or its version)",
}
SIGNAL_TIER = {"mv2": "medium", "manifest-version": "medium", "cs-all-sites": "high", "cs-start": "medium",
               "cs-all-frames": "low", "cs-main-world": "medium", "external-any": "medium",
               "external-pages": "low", "web-accessible": "low", "csp-eval": "high", "csp-remote": "high",
               "csp-sandbox": "medium", "update-url": "high", "overrides-settings": "high",
               "overrides-page": "medium", "identity": "high"}
# What the extension's own files are checked for: heuristics, reported as signals with each place they were seen.
CODE_SIGNALS = {
    "code-eval": ("medium", "Runs code built from text at run time (eval or new Function)"),
    "code-string-timer": ("medium", "Passes text to setTimeout or setInterval, which runs it as code"),
    "code-import-remote": ("high", "Loads a script from the internet into a worker (importScripts with a web address)"),
    "code-remote-script": ("high", "Loads a script from the internet into a page (a script tag or src with a web "
                                   "address)"),
    "code-execute-string": ("high", "Runs text as code in a tab (executeScript with code, Manifest V2)"),
    "code-packed": ("medium", "Packed code (the eval(function(p,a,c,k,e,...)) packer), which hides what it does"),
    "code-obfuscated": ("medium", "Obfuscated code (many _0x names, as javascript-obfuscator writes them)"),
    "code-high-entropy": ("medium", "A long string of near-random characters, which can hide a payload"),
    "code-blob": ("low", "A long encoded string (base64 or hex), which can hide a payload"),
    "code-hidden": ("high", "Hidden characters that can carry code, or characters that reorder how text reads"),
}
MAX_HITS = 20  # places kept per signal
READ_FILE_BYTES = 20_000_000
READ_TOTAL_BYTES = 400_000_000  # for one run, across every extension
MAX_FILES = 50_000
MINIFIED_LINE = 5_000  # a line this long is not code a person wrote to be read
_STRING_TIMER = re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*['\"`]")
_IMPORT_REMOTE = re.compile(r"\bimportScripts\s*\(\s*['\"`]https?://", re.I)
_REMOTE_SCRIPT = re.compile(r"<script\b[^>]{0,500}?\bsrc\s*=\s*['\"]?(?:https?:)?//|"
                            r"\.src\s*=\s*['\"`]https?://[^'\"`\s]{1,500}?\.js\b", re.I)
_EXECUTE_STRING = re.compile(r"\bexecuteScript\s*\([^)]{0,300}?\bcode\s*:")
_PACKED = re.compile(r"eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e\s*,")
_OBFUSCATOR_NAME = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
OBFUSCATOR_NAMES = 20  # distinct _0x names in one file
HIGH_ENTROPY_CHARS = 200
HIGH_ENTROPY_BITS = 5.2
# Addresses that are names of standards, not places an extension talks to.
_NAMESPACE_HOSTS = {"www.w3.org", "w3.org", "schema.org", "json-schema.org", "purl.org", "ns.adobe.com",
                    "schemas.microsoft.com", "schemas.openxmlformats.org", "www.apache.org", "opensource.org"}
MAX_HOSTS = 1000

# Script sources in a policy that load nothing from the internet. Anything else (a host, a scheme such as https:,
# *) is a remote source; localhost is allowed for development and is not counted.
_LOCAL_SOURCES = re.compile(r"^(?:'self'|'none'|'wasm-unsafe-eval'|'unsafe-eval'|'unsafe-inline'|'strict-dynamic'|"
                            r"'report-sample'|'nonce-[^']*'|'sha(?:256|384|512)-[^']*'|blob:|filesystem:|"
                            r"(?:https?://)?(?:localhost|127\.0\.0\.1)(?::[0-9]+)?(?:/.*)?)$", re.I)


# ------------------------------------------------------------------------------------------- reading a manifest

def lenient_json(text: str) -> str:
    """The text as strict JSON, read as Chromium reads a manifest (JSON_PARSE_CHROMIUM_EXTENSIONS): // and /* */
    comments removed, raw carriage returns and newlines inside strings escaped, \\xNN escapes turned into \\u00NN;
    trailing commas, which Chromium refuses, are also dropped, so nothing it reads is missed here. Linear in the
    length of the text."""
    out: list[str] = []
    i, n = 0, len(text)
    in_str = False
    while i < n:
        c = text[i]
        if in_str:
            if c == "\\" and i + 1 < n:
                if text[i + 1] == "x" and re.fullmatch(r"[0-9A-Fa-f]{2}", text[i + 2:i + 4]):
                    out.append("\\u00" + text[i + 2:i + 4])  # Chromium's \xNN escape
                    i += 4
                    continue
                out.append(c + text[i + 1])
                i += 2
                continue
            if c in "\r\n":
                out.append("\\r" if c == "\r" else "\\n")  # Chromium allows these two raw in a string
                i += 1
                continue
            out.append(c)
            if c == '"':
                in_str = False
            i += 1
        elif c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif c == "/" and text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif c == "/" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
        else:
            out.append(c)
            i += 1
    # Trailing commas: a comma whose next non-space character closes an object or array.
    stripped = "".join(out)
    result: list[str] = []
    in_str = False
    i, n = 0, len(stripped)
    while i < n:
        c = stripped[i]
        if in_str:
            result.append(c)
            if c == "\\" and i + 1 < n:
                result.append(stripped[i + 1])
                i += 2
                continue
            in_str = c != '"'
        elif c == '"':
            in_str = True
            result.append(c)
        elif c == ",":
            j = i + 1
            while j < n and stripped[j] in " \t\r\n":
                j += 1
            if j >= n or stripped[j] not in "}]":
                result.append(c)
        else:
            result.append(c)
        i += 1
    return "".join(result)


def parse_manifest(raw: bytes) -> dict | None:
    """A manifest.json as an extension's manifest: an object with a name, a version and a whole-number
    manifest_version. None for anything else (unreadable, too deep, or another kind of manifest.json)."""
    if len(raw) > MAX_MANIFEST_BYTES:
        return None
    try:
        text = raw.decode("utf-8-sig")
        data = jsonsafe.loads(lenient_json(text))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None
    if not isinstance(data, dict):
        return None
    mv = data.get("manifest_version")
    if isinstance(mv, bool) or not isinstance(mv, int):
        return None
    if not isinstance(data.get("name"), str) or not isinstance(data.get("version"), str):
        return None
    return data


def read_manifest(folder: Path) -> tuple[dict, str] | None:
    """(the manifest, its text) for an extension's folder, or None when the folder is not one."""
    p = folder / "manifest.json"
    try:
        if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_MANIFEST_BYTES:
            return None
        raw = p.read_bytes()
    except (OSError, ValueError):
        return None
    data = parse_manifest(raw)
    return None if data is None else (data, raw.decode("utf-8-sig", "replace"))


def _messages(folder: Path, data: dict) -> dict[str, str]:
    """The default locale's messages (_locales/<default_locale>/messages.json), keyed in lower case as the browser
    looks them up, for names written as __MSG_key__."""
    locale = data.get("default_locale")
    if not isinstance(locale, str) or not re.fullmatch(r"[A-Za-z]{2,3}(?:[_-][A-Za-z0-9]{1,8}){0,3}", locale):
        return {}
    p = folder / "_locales" / locale / "messages.json"
    try:
        if p.is_symlink() or not p.is_file() or p.stat().st_size > MAX_MESSAGES_BYTES:
            return {}
        return parse_messages(p.read_bytes())
    except OSError:
        return {}


def parse_messages(raw: bytes) -> dict[str, str]:
    """A messages.json: key -> message, keys in lower case. {} for anything unreadable."""
    if len(raw) > MAX_MESSAGES_BYTES:
        return {}
    try:
        data = jsonsafe.loads(lenient_json(raw.decode("utf-8-sig")))
    except (UnicodeDecodeError, ValueError, RecursionError):
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(k).lower(): v["message"] for k, v in data.items()
            if isinstance(v, dict) and isinstance(v.get("message"), str)}


def _localised(value: object, messages: dict[str, str]) -> str:
    """A manifest string, with __MSG_key__ replaced by the default locale's message when there is one."""
    if not isinstance(value, str):
        return ""
    m = _MSG.match(value)
    if m:
        return messages.get(m.group(1).lower(), value)[:300]
    return value[:300]


def id_from_key(key: object) -> str | None:
    """The extension ID a manifest's key gives: the first 16 bytes of the SHA-256 of the public key, each hex digit
    written as a to p. None when there is no key or it is not base64."""
    if not isinstance(key, str) or not key.strip() or len(key) > 100_000:
        return None
    try:
        der = base64.b64decode("".join(key.split()), validate=True)
    except (binascii.Error, ValueError):
        return None
    if not der:
        return None
    return "".join(chr(ord("a") + int(c, 16)) for c in hashlib.sha256(der).hexdigest()[:32])


# ------------------------------------------------------------------------------------------- what the input is

def is_crx(path: Path) -> bool:
    """A file that starts as a .crx does ("Cr24"), whatever it is called."""
    try:
        if not path.is_file():
            return False
        with open(path, "rb") as fh:
            return fh.read(4) == CRX_MAGIC
    except OSError:
        return False


def _id_folder_versions(folder: Path) -> list[Path]:
    """The version folders (1.2.3_0) of an installed extension's ID folder that hold a manifest.json."""
    try:
        children = sorted(p for p in folder.iterdir() if p.is_dir() and not p.is_symlink()
                          and _VERSION_FOLDER.match(p.name) and (p / "manifest.json").is_file())
    except OSError:
        return []
    return children[:MAX_VERSIONS]


def _is_id_folder(folder: Path) -> bool:
    return bool(ID_RE.match(folder.name)) and bool(_id_folder_versions(folder))


def find(path: Path) -> list[Path]:
    """The extension folders path is or holds: an extension's own folder; an installed extension's ID folder (its
    version folders); a profile's Extensions folder (every ID folder in it); or a profile folder (its Extensions
    folder). A version folder whose manifest cannot be read is included, so the report can say it was not checked.
    Empty when there are none."""
    if not path.is_dir():
        return []
    if read_manifest(path) is not None:
        return [path]
    if ID_RE.match(path.name):
        return _id_folder_versions(path)
    holder = path / "Extensions" if (path / "Extensions").is_dir() and not (path / "Extensions").is_symlink() \
        else path
    found: list[Path] = []
    try:
        children = sorted(p for p in holder.iterdir() if p.is_dir() and not p.is_symlink() and ID_RE.match(p.name))
    except OSError:
        return []
    for child in children:
        found.extend(_id_folder_versions(child))
        if len(found) > MAX_EXTENSIONS:
            raise InputError(f"{holder.name} holds more than {MAX_EXTENSIONS} extensions; assess fewer at a time")
    return found


def is_single(path: Path) -> bool:
    """One extension: a .crx, or one extension's own folder."""
    return is_crx(path) or (path.is_dir() and read_manifest(path) is not None)


def is_browser_input(path: Path) -> bool:
    return is_crx(path) if path.is_file() else bool(find(path))


def profile_dir(browser: str, platform: str | None = None, home: Path | None = None,
                environ: dict | None = None) -> Path:
    """The default profile folder of a browser on this system (platform, home and environ for tests)."""
    platform = platform or sys.platform
    key = "win32" if platform.startswith("win") else "darwin" if platform == "darwin" else "linux"
    env = os.environ if environ is None else environ
    rel = _PROFILE[browser][key]
    if key == "win32":
        base = env.get("LOCALAPPDATA")
        if not base:
            raise InputError("LOCALAPPDATA is not set, so the browser's profile cannot be found; give --path to its "
                             "profile folder")
        return Path(base, *rel.split("/"))
    return (home or Path.home()).joinpath(*rel.split("/"))


# ------------------------------------------------------------------------------------------- .crx files

def crx_header(path: Path) -> tuple[int, bytes, int]:
    """(format version, the header's protobuf bytes, where the zip starts) of a .crx. InputError for anything that
    is not a CRX3 file within the limits."""
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            head = fh.read(12)
            if len(head) < 12 or head[:4] != CRX_MAGIC:
                raise InputError(f"{path.name} is not a .crx file (no Cr24 header)")
            version, header_size = struct.unpack("<II", head[4:12])
            if version == 2:
                raise InputError(f"refused: {path.name} is an old CRX2 file, which current Chromium browsers do "
                                 "not install")
            if version != 3:
                raise InputError(f"refused: {path.name} is CRX version {version}; only CRX3 is read")
            if header_size > MAX_CRX_HEADER:
                raise InputError(f"refused: {path.name} has a {header_size}-byte header, more than {MAX_CRX_HEADER}")
            if 12 + header_size >= size:
                raise InputError(f"refused: {path.name}'s header runs past the end of the file")
            header = fh.read(header_size)
    except OSError as exc:
        raise InputError(f"cannot read {path.name}: {exc}") from None
    if size > MAX_CRX_BYTES:
        raise InputError(f"refused: {path.name} is larger than {MAX_CRX_BYTES} bytes")
    return version, header, 12 + header_size


def unpack(path: Path, dest: Path) -> Path:
    """Stage a .crx in dest: the zip after its header copied out, then unpacked with the .vsix limits into
    dest/<name>. Returns that folder. InputError when the file breaks a limit or holds no extension manifest."""
    from . import vscode

    _, _, offset = crx_header(path)
    payload = dest / ".crx-payload"
    payload.mkdir(parents=True)
    zipped = payload / path.name  # named after the .crx, so a refusal names the file the user gave
    try:
        with open(path, "rb") as src, open(zipped, "wb") as out:
            src.seek(offset)
            shutil.copyfileobj(src, out, 1 << 20)
        folder = dest / "extension"  # a fixed name: one taken from the file (".x.crx") could be skipped as hidden
        try:
            vscode.extract(zipped, folder, label=path.name)
        except InputError:
            raise
        except vscode.ZIP_ERRORS as exc:  # a damaged, encrypted or oddly compressed file is the input's fault
            raise InputError(f"refused: {path.name} could not be unpacked ({type(exc).__name__}: {exc})") from None
    finally:
        shutil.rmtree(payload, ignore_errors=True)
    if read_manifest(folder) is None:
        raise InputError(f"{path.name} has no manifest.json with a name, a version and a manifest_version: not a "
                         "browser extension")
    return folder


# ------------------------------------------------------------------------------------------- the checks

def _strings(value: object) -> list[str]:
    return [x for x in value if isinstance(x, str)] if isinstance(value, list) else []


def _line_of(raw: str, key: str) -> int | None:
    at = raw.find(f'"{key}"')
    return raw.count("\n", 0, at) + 1 if at >= 0 else None


def is_all_sites(pattern: str) -> bool:
    return bool(_ALL_HOSTS.match(pattern.strip()))


def _is_host(entry: str) -> bool:
    return entry == "<all_urls>" or "://" in entry


def permissions(data: dict) -> list[dict]:
    """Every permission and site pattern the manifest asks for, graded: name, kind (api or site), optional, tier,
    why. Manifest V2 lists sites among its permissions; V3 lists them in host_permissions."""
    out: list[dict] = []
    seen: set[tuple[str, bool]] = set()
    for key, optional in (("permissions", False), ("optional_permissions", True), ("host_permissions", False),
                          ("optional_host_permissions", True)):
        for name in _strings(data.get(key)):
            name = name.strip()[:300]
            if not name or (name, optional) in seen:
                continue
            seen.add((name, optional))
            if _is_host(name):
                tier, why = ALL_SITES if is_all_sites(name) else SOME_SITES
                out.append({"name": name, "kind": "site", "optional": optional, "tier": tier, "why": why})
            else:
                tier, why = PERMISSIONS.get(name, ("not graded", "not in oss-intake's table: look it up"))
                out.append({"name": name, "kind": "api", "optional": optional, "tier": tier, "why": why})
    order = {t: i for i, t in enumerate(TIERS)}
    out.sort(key=lambda p: (order[p["tier"]], p["optional"], p["kind"], p["name"]))
    return out


def _csp_sources(policy: str) -> tuple[bool, list[str]]:
    """(allows unsafe-eval, the remote script sources) of a policy: every directive that governs scripts
    (script-src, script-src-elem, script-src-attr, worker-src), or default-src when there is none."""
    directives: dict[str, list[str]] = {}
    for part in policy.split(";"):
        words = part.split()
        if words:
            directives.setdefault(words[0].lower(), words[1:])
    governing = [d for d in ("script-src", "script-src-elem", "script-src-attr", "worker-src") if d in directives]
    sources = [x for d in governing for x in directives[d]] if governing else directives.get("default-src", [])
    remote = list(dict.fromkeys(x for x in sources if not _LOCAL_SOURCES.match(x)))
    return "'unsafe-eval'" in (s.lower() for s in sources), remote[:MAX_ROWS]


def checks(data: dict, raw: str) -> list[dict]:
    """The manifest's signals: id, title, tier, where (manifest.json and a line) and a detail."""
    found: dict[str, dict] = {}

    def add(kind: str, key: str, detail: str) -> None:
        if kind in found:
            found[kind]["detail"] = (found[kind]["detail"] + "; " + detail)[:600] if detail else found[kind]["detail"]
            return
        found[kind] = {"id": kind, "title": SIGNALS[kind], "tier": SIGNAL_TIER[kind], "file": "manifest.json",
                       "line": _line_of(raw, key), "detail": detail[:600]}

    mv = data.get("manifest_version")
    if mv == 2:
        add("mv2", "manifest_version", "manifest_version 2")
    elif mv != 3:
        add("manifest-version", "manifest_version", f"manifest_version {mv}")
    scripts = data.get("content_scripts")
    for i, cs in enumerate(scripts if isinstance(scripts, list) else []):
        if not isinstance(cs, dict):
            continue
        matches = _strings(cs.get("matches"))
        where = f"content script {i + 1}"
        broad = [m for m in matches if is_all_sites(m)]
        if broad:
            add("cs-all-sites", "content_scripts", f"{where}: {', '.join(broad[:5])}")
        if cs.get("run_at") == "document_start":
            add("cs-start", "content_scripts", where)
        if cs.get("all_frames") is True:
            add("cs-all-frames", "content_scripts", where)
        if isinstance(cs.get("world"), str) and cs["world"].upper() == "MAIN":
            add("cs-main-world", "content_scripts", where)
    ec = data.get("externally_connectable")
    if isinstance(ec, dict):
        ids, sites = _strings(ec.get("ids")), _strings(ec.get("matches"))
        if "*" in ids:
            add("external-any", "externally_connectable", 'ids "*"')
        if sites:
            add("external-pages", "externally_connectable", ", ".join(sites[:10])
                + (f" and {len(sites) - 10} more" if len(sites) > 10 else ""))
    war = data.get("web_accessible_resources")
    if isinstance(war, list) and war:
        # V2 lists files, reachable from every site; V3 lists objects, each with the sites that can load them.
        if all(isinstance(x, str) for x in war):
            add("web-accessible", "web_accessible_resources", f"{len(war)} file pattern(s), from every site")
        else:
            for entry in war:
                if isinstance(entry, dict):
                    broad = [m for m in _strings(entry.get("matches")) if is_all_sites(m)]
                    if broad:
                        files = _strings(entry.get("resources"))
                        add("web-accessible", "web_accessible_resources",
                            f"{', '.join(files[:5]) or 'files'} from every site")
    csp = data.get("content_security_policy")
    pages, sandbox = "", ""
    if isinstance(csp, str):  # Manifest V2
        pages = csp
    elif isinstance(csp, dict):  # Manifest V3
        pages = str(csp["extension_pages"]) if isinstance(csp.get("extension_pages"), str) else ""
        sandbox = str(csp["sandbox"]) if isinstance(csp.get("sandbox"), str) else ""
    sb = data.get("sandbox")
    if isinstance(sb, dict) and isinstance(sb.get("content_security_policy"), str):  # V2's sandbox policy
        sandbox = sandbox or sb["content_security_policy"]
    if pages:
        evals, remote = _csp_sources(pages)
        refused = " (Chrome does not load a Manifest V3 extension whose policy allows this)" if mv == 3 else ""
        if evals:
            add("csp-eval", "content_security_policy", "'unsafe-eval' in its pages' policy" + refused)
        if remote:
            add("csp-remote", "content_security_policy", ", ".join(remote[:10]) + refused)
    if sandbox:
        evals, remote = _csp_sources(sandbox)
        if evals or remote:
            add("csp-sandbox", "content_security_policy",
                ", ".join((["'unsafe-eval'"] if evals else []) + remote[:10]))
    update = data.get("update_url")
    if isinstance(update, str) and update.strip() and update.strip().rstrip("/") not in STORE_UPDATE_URLS:
        add("update-url", "update_url", update.strip()[:300])
    so = data.get("chrome_settings_overrides")
    if isinstance(so, dict):
        what = [k for k in ("search_provider", "homepage", "startup_pages") if so.get(k)]
        if what:
            add("overrides-settings", "chrome_settings_overrides", ", ".join(what))
    uo = data.get("chrome_url_overrides")
    if isinstance(uo, dict) and uo:
        add("overrides-page", "chrome_url_overrides", ", ".join(str(k)[:40] for k in list(uo)[:5]))
    order = {t: i for i, t in enumerate(TIERS)}
    return sorted(found.values(), key=lambda s: (order[s["tier"]], s["id"]))


def _highest(tiers: list[str]) -> str:
    for t in TIERS:
        if t in tiers:
            return t
    return "none"


def _entropy(text: str) -> float:
    counts: dict[str, int] = {}
    for c in text:
        counts[c] = counts.get(c, 0) + 1
    n = len(text)
    return -sum(k / n * math.log2(k / n) for k in counts.values())


def _referenced(data: dict) -> set[str]:
    """The files the manifest tells the browser to load (scripts, pages), as paths inside the extension: these are
    read whatever their name or bytes."""
    names: list[object] = []
    bg = data.get("background")
    if isinstance(bg, dict):
        names += [bg.get("service_worker"), bg.get("page"), *_strings(bg.get("scripts"))]
    scripts = data.get("content_scripts")
    for cs in scripts if isinstance(scripts, list) else []:
        if isinstance(cs, dict):
            names += _strings(cs.get("js"))
    for key in ("action", "browser_action", "page_action"):
        if isinstance(data.get(key), dict):
            names.append(data[key].get("default_popup"))
    if isinstance(data.get("options_ui"), dict):
        names.append(data["options_ui"].get("page"))
    if isinstance(data.get("side_panel"), dict):
        names.append(data["side_panel"].get("default_path"))
    if isinstance(data.get("sandbox"), dict):
        names += _strings(data["sandbox"].get("pages"))
    if isinstance(data.get("chrome_url_overrides"), dict):
        names += list(data["chrome_url_overrides"].values())
    names += [data.get("options_page"), data.get("devtools_page")]
    return {str(n).split("?")[0].split("#")[0].replace("\\", "/").lstrip("/") for n in names
            if isinstance(n, str) and n.strip()}


def _binary(head: bytes) -> bool:
    """Not text: the start is not UTF-8 (allowing a character cut off at the end). A NUL alone does not make a
    file binary: a browser runs a UTF-8 script that holds one."""
    for cut in range(4):
        try:
            head[:len(head) - cut].decode("utf-8")
            return False
        except UnicodeDecodeError:
            continue
    return True


def code_checks(folder: Path, budget: list[int], referenced: set[str] | None = None) -> dict:
    """The extension's own files read as text (binary files and source maps excepted, nothing run): the code
    signals with each place seen, the web hosts each file names, and facts about how readable the code is."""
    from . import vscode

    hits: dict[str, list[dict]] = {}
    hosts: dict[str, list[str]] = {}
    all_hosts: set[str] = set()
    hosts_capped = False
    unread: list[str] = []
    minified: list[str] = []
    files = longest = read = 0
    node_modules = False
    referenced = referenced or set()

    def add(kind: str, file: str, line: int | None, detail: str) -> bool:
        bucket = hits.setdefault(kind, [])
        if len(bucket) < MAX_HITS:
            bucket.append({"file": file, "line": line, "detail": detail[:200]})
        return len(bucket) < MAX_HITS

    for p in vscode._files(folder):
        files += 1
        if files > MAX_FILES:
            unread.append(f"more than {MAX_FILES} files: the rest were not read")
            break
        if p.is_symlink() or not p.is_file():
            continue
        rel = p.relative_to(folder).as_posix()
        node_modules = node_modules or rel.startswith("node_modules/") or "/node_modules/" in rel
        named = rel in referenced
        if not named and (rel == "manifest.json" or rel.startswith("_metadata/") or p.suffix.lower() == ".map"):
            continue  # checked as a manifest; the store's signed hashes; source maps (their sources do not run)
        try:
            with open(p, "rb") as fh:
                head = fh.read(8192)
            size = p.stat().st_size
        except OSError:
            continue
        if not named and _binary(head):
            continue
        if size > READ_FILE_BYTES or budget[0] <= 0:
            unread.append(rel)
            continue
        budget[0] -= size
        try:
            text = p.read_bytes().decode("utf-8", "replace")
        except OSError:
            continue
        read += 1
        where = vscode._Lines(text)
        line_max = max((len(x) for x in text.split("\n")), default=0)
        longest = max(longest, line_max)
        if line_max >= MINIFIED_LINE:
            minified.append(rel)
        for kind, rx in (("code-eval", vscode._EVAL), ("code-string-timer", _STRING_TIMER),
                         ("code-import-remote", _IMPORT_REMOTE), ("code-remote-script", _REMOTE_SCRIPT),
                         ("code-execute-string", _EXECUTE_STRING), ("code-packed", _PACKED),
                         ("code-hidden", vscode._INVISIBLE), ("code-hidden", vscode._BIDI)):
            for m in rx.finditer(text):
                detail = (f"{len(m.group(0))} hidden character(s)" if kind == "code-hidden"
                          else m.group(0).strip())
                if not add(kind, rel, where(m.start()), detail):
                    break
        names = set(_OBFUSCATOR_NAME.findall(text))
        if len(names) >= OBFUSCATOR_NAMES:
            at = _OBFUSCATOR_NAME.search(text)
            add("code-obfuscated", rel, where(at.start()) if at else None, f"{len(names)} distinct _0x names")
        for m in vscode._RUN.finditer(text):
            run = m.group(0)
            if len(run) < HIGH_ENTROPY_CHARS or vscode._DATA_URI.search(text, max(0, m.start() - 80), m.start()):
                continue
            if len(run) >= vscode.BLOB_CHARS:
                if not add("code-blob", rel, where(m.start()), f"{len(run)} characters"):
                    break
            elif _entropy(run) >= HIGH_ENTROPY_BITS:
                if not add("code-high-entropy", rel, where(m.start()), f"{len(run)} characters"):
                    break
        found: list[str] = []
        in_file: set[str] = set()  # beside the list, so each address is checked in constant time
        for m in vscode._URL.finditer(text):
            h = m.group(1).lower()
            if h in _NAMESPACE_HOSTS or h in in_file:
                continue
            in_file.add(h)
            if h not in all_hosts and len(all_hosts) >= MAX_HOSTS:
                hosts_capped = True
                break
            all_hosts.add(h)
            found.append(h)
        if found:
            hosts[rel] = sorted(found)[:100]
    signals = []
    for kind, seen in hits.items():
        tier, title = CODE_SIGNALS[kind]
        first = seen[0]
        signals.append({"id": kind, "title": title, "tier": tier, "file": first["file"], "line": first["line"],
                        "detail": f"{len(seen)}{'+' if len(seen) >= MAX_HITS else ''} place(s); first: "
                                  f"{first['detail']}", "seen": seen, "capped": len(seen) >= MAX_HITS})
    return {"signals": signals, "hosts_by_file": hosts, "hosts_all": sorted(all_hosts), "hosts_capped": hosts_capped,
            "node_modules": node_modules,
            "facts": {"files_read": read, "minified_files": minified[:50],
                      "minified_total": len(minified), "longest_line": longest, "not_read": unread[:20],
                      "not_read_total": len(unread)}}


def analyse(folder: Path, rel: str = "", budget: list[int] | None = None) -> dict:
    """One extension: identity, graded permissions and signals. rel is its folder relative to what was given (to
    match findings to it)."""
    got = read_manifest(folder)
    installed = _VERSION_FOLDER.match(folder.name) and ID_RE.match(folder.parent.name)
    folder_id = folder.parent.name if installed else ""
    if got is None:
        return {"id": folder_id, "name": "", "version": "", "folder": rel or folder.name, "unreadable": True,
                "permissions": [], "signals": [], "tier": "none", "known_bad": None, "hosts_by_file": {},
                "hosts_all": [], "hosts_capped": False, "content_matches": []}
    data, raw = got
    messages = _messages(folder, data)
    key_id = id_from_key(data.get("key"))
    ext_id = folder_id or key_id or ""
    signals = checks(data, raw)
    mismatch = []
    if folder_id and key_id and key_id != folder_id:
        mismatch.append(f"the folder is {folder_id}; its key gives {key_id}")
    if installed:
        vm = _VERSION_FOLDER.match(folder.name)
        if vm and vm.group("version") != data["version"]:
            mismatch.append(f"the folder is version {vm.group('version')}; manifest.json says {data['version']}")
    if mismatch:
        signals.insert(0, {"id": "identity", "title": SIGNALS["identity"], "tier": SIGNAL_TIER["identity"],
                           "file": folder.name, "line": None, "detail": "; ".join(mismatch)})
    code = code_checks(folder, budget if budget is not None else [READ_TOTAL_BYTES], _referenced(data))
    order = {t: i for i, t in enumerate(TIERS)}
    signals += sorted(code["signals"], key=lambda x: (order[x["tier"]], x["id"]))
    perms = permissions(data)
    scripts = data.get("content_scripts")
    # Every pattern, for --compare-with (the manifest is capped at 5 MB); removed before the reports (attribute).
    matches = sorted({m for cs in (scripts if isinstance(scripts, list) else []) if isinstance(cs, dict)
                      for m in _strings(cs.get("matches"))})
    given = data.get("update_url")
    update = given if isinstance(given, str) else ""
    author = data.get("author")
    if isinstance(author, dict):
        author = author.get("email")
    return {
        "id": ext_id, "id_from_key": key_id or "", "name": _localised(data.get("name"), messages),
        "version": data["version"][:100], "manifest_version": data.get("manifest_version"),
        "description": _localised(data.get("description"), messages)[:300],
        "author": str(author)[:200] if isinstance(author, str) else "",
        "homepage": str(data.get("homepage_url"))[:300] if isinstance(data.get("homepage_url"), str) else "",
        "update_url": update.strip()[:300],
        "update_source": STORE_UPDATE_URLS.get(update.strip().rstrip("/"), "not a store" if update.strip()
                                               else "none given"),
        "folder": rel or folder.name, "installed": bool(installed),
        "permissions": perms, "signals": signals, "content_matches": matches,
        "hosts_by_file": code["hosts_by_file"], "hosts_all": code["hosts_all"], "hosts_capped": code["hosts_capped"],
        "code_facts": code["facts"], "node_modules": code["node_modules"],
        "tier": _highest([p["tier"] for p in perms if not p["optional"]] + [s["tier"] for s in signals]),
        "known_bad": None,
    }


# ------------------------------------------------------------------------------------------- the whole input

def assess(target: Path, staged: bool = False, browser: str | None = None) -> dict:
    """Every extension under target, each checked against the known-bad list. staged: target is the temporary
    folder a .crx was unpacked into (one extension). browser: the browser whose default profile was read."""
    from . import integrity

    folders = [p for p in target.iterdir() if p.is_dir() and not p.name.startswith(".")] if staged else find(target)
    found = []
    budget = [READ_TOTAL_BYTES]  # shared, as for VS Code: one run reads at most this much code
    for f in folders:
        try:
            rel = f.relative_to(target).as_posix()
        except ValueError:
            rel = f.name
        found.append(analyse(f, "" if staged else rel, budget))
    listed = integrity.load_known_bad()
    for e in found:
        e["known_bad"] = integrity.known_bad_extension(e["id"], e["version"]) if e["id"] else None
    single = staged or read_manifest(target) is not None or (bool(ID_RE.match(target.name)) and len(found) == 1)
    return {"extensions": found, "single": single, "browser": BROWSERS.get(browser or ""),
            "known_bad_list": {"updated": listed.get("updated"),
                               "entries": len(listed.get("browser_extensions") or [])}}


def apply_signature(info: dict, crx: Path) -> None:
    """For a staged .crx (one extension): check its CRX3 signature (crxsign.check) and keep it on info. The browser
    installs a .crx under the ID its signer's key gives, replacing any key in the manifest, so a verified signature's
    ID is the extension's ID, and a manifest key that gives another is an identity signal. Without the signatures
    extra the signature's ID is only a claim: the extension is looked up in the known-bad list under both IDs."""
    from . import crxsign, integrity

    sig = crxsign.check(crx)
    info["signature"] = sig
    if not sig["id"] or sig["status"] not in ("verified", "not_checked") or len(info["extensions"]) != 1:
        return
    e = info["extensions"][0]
    if e.get("unreadable"):
        return
    claimed = e["id"]
    if claimed and claimed != sig["id"]:
        e["signals"].insert(0, {"id": "identity", "title": SIGNALS["identity"], "tier": SIGNAL_TIER["identity"],
                                "file": "manifest.json", "line": None,
                                "detail": f"its manifest's key gives {claimed}; the browser installs it under its "
                                          f"signer's ID {sig['id']}"})
        e["tier"] = "high"
    ids = [sig["id"]] + ([claimed] if claimed and claimed != sig["id"] and sig["status"] == "not_checked" else [])
    e["id"] = sig["id"]
    e["known_bad"] = next((hit for hit in (integrity.known_bad_extension(i, e["version"]) for i in ids) if hit), None)


def attribute(info: dict, findings: list) -> None:
    """Count each extension's findings: everything scanned for one extension; otherwise by the start of the path
    (Trivy's paths start at the folder given; Grype's with "/")."""
    exts = info["extensions"]
    only = exts[0] if info.get("single") and len(exts) == 1 else None
    for e in exts:
        e["findings"] = {"total": 0, "critical": 0, "high": 0, "malicious": 0}
        e.pop("hosts_all", None)  # for --compare-with only: the report lists hosts by file
        e.pop("content_matches", None)
    unmatched = 0
    for f in findings:
        owners = [only] if only else []
        for t in (f.target or "").split(";"):
            path = t.replace("\\", "/").lstrip("/")
            for e in exts:
                if e["folder"] and (path == e["folder"] or path.startswith(e["folder"] + "/")) \
                        and not any(o is e for o in owners):
                    owners.append(e)
        if not owners:
            unmatched += 1
        for e in owners:
            c = e["findings"]
            c["total"] += 1
            c["critical"] += f.severity == "CRITICAL"
            c["high"] += f.severity == "HIGH"
            c["malicious"] += bool(f.malicious)
    info["unmatched"] = unmatched


def compare(old: dict, new: dict) -> dict:
    """What an update changed, for two versions of one extension (analyse() results): permissions and site
    patterns added and removed, new content-script sites, new web hosts in the code, new code signals, and a
    changed update address, author or homepage. drift: the update asks for more (a permission or site pattern
    added, optional ones included, or a new update address), which --fail-on permission-drift fails on."""
    def perm_set(e: dict) -> set[tuple[str, bool]]:
        return {(p["name"], p["optional"]) for p in e["permissions"]}

    op, np = perm_set(old), perm_set(new)
    added = sorted(np - op)
    removed = sorted(op - np)
    sites_added = sorted(set(new.get("content_matches", [])) - set(old.get("content_matches", [])))
    hosts_full = not old.get("hosts_capped") and not new.get("hosts_capped")
    hosts_added = sorted(set(new.get("hosts_all", [])) - set(old.get("hosts_all", []))) if hosts_full else []
    ok = {s["id"]: s for s in old["signals"]}
    signals_added = [{"id": s["id"], "title": s["title"], "tier": s["tier"],
                      "where": s["file"] + (f":{s['line']}" if s["line"] else "")}
                     for s in new["signals"] if s["id"] not in ok]
    grew = [{"id": s["id"], "title": s["title"], "from": len(ok[s["id"]]["seen"]), "to": len(s["seen"])}
            for s in new["signals"] if s["id"] in ok and "seen" in s and "seen" in ok[s["id"]]
            and not ok[s["id"]].get("capped") and len(s["seen"]) > len(ok[s["id"]]["seen"])]
    changed = {k: (old.get(k, ""), new.get(k, "")) for k in ("update_url", "author", "homepage")
               if old.get(k, "") != new.get(k, "")}
    return {
        "from_version": old["version"], "to_version": new["version"],
        "same_extension": not (old["id"] and new["id"]) or old["id"] == new["id"],
        "permissions_added": [{"name": n, "optional": o} for n, o in added],
        "permissions_removed": [{"name": n, "optional": o} for n, o in removed],
        "content_sites_added": sites_added,
        "hosts_added": hosts_added[:100], "hosts_added_total": len(hosts_added), "hosts_not_compared": not hosts_full,
        "signals_added": signals_added, "signals_grew": grew,
        "changed": {k: {"from": a, "to": b} for k, (a, b) in changed.items()},
        "drift": bool(added or sites_added or "update_url" in changed),
    }


def change_warnings(diff: dict, name: str) -> list[str]:
    """Warnings for what an update adds that is worth a person's look. name: the extension, without its version
    (name_and_id); the versions come from diff."""
    out = []
    if not diff["same_extension"]:
        out.append(f"--compare-with names a different extension than {name}: the comparison may mean little")
    adds = []
    if diff["permissions_added"]:
        adds.append("permissions " + ", ".join(p["name"] + (" (optional)" if p["optional"] else "")
                                               for p in diff["permissions_added"][:10]))
    if diff["content_sites_added"]:
        adds.append("content scripts on " + ", ".join(diff["content_sites_added"][:5]))
    if diff["signals_added"]:
        adds.append("; ".join(s["title"].split(" (")[0] for s in diff["signals_added"][:5]))
    if diff["hosts_added_total"]:
        adds.append(f"{diff['hosts_added_total']} new web host(s) in its code")
    if adds:
        out.append(f"{name} {diff['to_version']} adds since {diff['from_version']}: {'; '.join(adds)}. Read what "
                   "changed before you take the update")
    for key, words in (("update_url", "update address"), ("author", "author"), ("homepage", "homepage")):
        if key in diff["changed"]:
            c = diff["changed"][key]
            out.append(f"{name} {diff['to_version']} changes its {words} from {c['from'] or 'none'} to "
                       f"{c['to'] or 'none'}: check who publishes it now")
    if diff["hosts_not_compared"]:
        out.append(f"--compare-with could not compare web hosts (over {MAX_HOSTS} in a version)")
    return out


def name_and_id(e: dict) -> str:
    return f"{e.get('name') or e.get('id') or e['folder']} ({e['id'] or 'no ID'})"


def label(e: dict) -> str:
    return f"{name_and_id(e)} {e.get('version', '')}".strip()


def warnings(info: dict) -> tuple[list[str], list[str]]:
    """(alerts for the top of the report, ordinary warnings)."""
    alerts, other = [], []
    for e in info["extensions"]:
        kb = e.get("known_bad")
        if kb:
            alerts.append(f"BROWSER EXTENSION ON THE KNOWN-BAD LIST: {label(e)}: {kb['note']} ({kb['reference']}). "
                          "Remove it everywhere and treat machines that ran it as compromised")
        if e.get("unreadable"):
            other.append(f"The manifest.json of {e['folder']} could not be read, so that extension was not checked")
            continue
        for s in e["signals"]:
            if s["id"] == "identity":
                other.append(f"{label(e)}: its files do not agree on what it is ({s['detail']}): it may have been "
                             "changed after it was installed")
            elif s["id"] == "update-url":
                other.append(f"{label(e)} updates from {s['detail']}, not from a store: whoever runs that server can "
                             "change it without store review")
    sig = info.get("signature")
    if sig and info["extensions"]:
        name = label(info["extensions"][0])
        if sig["status"] == "failed":
            alerts.append(f"CRX SIGNATURE DOES NOT MATCH: {name}: {sig['detail']}. Do not install it; find out where "
                          "this file came from")
        elif sig["status"] == "verified" and not sig["store"]:
            other.append(f"{name} is signed by its developer's key only, not by the Chrome Web Store: it did not come "
                         "from the Chrome Web Store as is (another store, a self-hosted update server, or a "
                         "developer's own build)")
        elif sig["status"] == "not_checked":
            other.append(f"The CRX signature of {name} was not checked: {sig['detail']}")
    return alerts, other
