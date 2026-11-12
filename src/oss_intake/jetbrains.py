"""JetBrains IDE plugins: a plugin file (.zip or .jar), one installed plugin, or an IDE's plugins folder.

A plugin is a folder with a lib/ of jars, one of which holds META-INF/plugin.xml (its ID, name, version, vendor
and the IDE builds it supports); a small plugin can be that one jar. The scanners find the libraries the jars
bundle; this module reads each plugin's identity and looks it up on the JetBrains Marketplace: its vendor and
whether the vendor is verified, whether the Marketplace has blocked it, and when this version was published.
Nothing in a plugin is run.

--jetbrains-plugin ID@VERSION downloads one exact version from the Marketplace (free and paid plugins alike: a
paid plugin's licence is checked by the IDE, not at download). The Marketplace publishes no checksum; it signs each
plugin file instead (a signing block in the zip, chained to JetBrains' certificate), and with the signatures extra
that signature is checked as the IDE checks it (zipsign.py): a download that does not match it, or has none, or
has someone else's, is refused, and a plugin file given with --path gets the same check. An installed plugin the
IDE unpacked has lost its signature; one installed as a single .jar keeps it. The Marketplace answers were
captured from the live service on 9 Nov 2026 (plugins/{id}, plugins/intellij/{xmlId}, plugins/{id}/updates,
plugin/download).
"""

from __future__ import annotations

import hashlib
import io
import re
import shutil
import xml.etree.ElementTree as ET  # noqa: S405 - plugin.xml is size-capped; expat refuses entity expansion bombs
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

from . import zipsign
from .http import Http, HttpError, prefetch
from .inputs import InputError

MARKETPLACE = "https://plugins.jetbrains.com"
MAX_PLUGINS = 500  # plugins in one IDE's folder
MAX_JARS = 400  # jars read in one plugin's lib/ for plugin.xml
MAX_PLUGIN_XML = 2 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 500 * 1024 * 1024
MAX_LOOKUPS = 300
UPDATES_PAGE = 100  # versions asked for at once; a version older than these is "not among the latest"
UNPACKED = {"status": "unpacked", "detail": "installed: the IDE unpacked the plugin file, and its signature does not "
                                         "survive that", "signers": []}
# xmlId@version as the Marketplace writes them; the version exact.
_ID = re.compile(r"^(?P<id>[A-Za-z0-9][\w.\-]{0,199})@(?P<version>[0-9A-Za-z][\w.+\-]{0,99})$")


def parse_id(value: str) -> tuple[str, str]:
    m = _ID.match(value.strip())
    if not m:
        raise ValueError("use the plugin's ID and an exact version, e.g. mobi.hsz.idea.gitignore@4.5.7")
    return m.group("id"), m.group("version")


# ------------------------------------------------------------------------------------------- reading

def _plugin_xml(jar: Path | bytes) -> bytes | None:
    """META-INF/plugin.xml from a jar (a path or its bytes), or None."""
    try:
        with zipfile.ZipFile(io.BytesIO(jar) if isinstance(jar, bytes) else jar) as z:
            info = z.getinfo("META-INF/plugin.xml")
            if info.file_size > MAX_PLUGIN_XML:
                return None
            with z.open(info) as fh:
                return fh.read(MAX_PLUGIN_XML + 1)[:MAX_PLUGIN_XML]
    except (KeyError, zipfile.BadZipFile, OSError, ValueError, NotImplementedError, RuntimeError, EOFError):
        return None
    except Exception:  # noqa: BLE001 - a damaged jar (a bad deflate stream, say) is not a plugin.xml
        return None


def read_identity(xml: bytes) -> dict | None:
    """The plugin's identity from its plugin.xml: id (the name when there is no id, as the IDE does), name,
    version, vendor, since and until builds. None when it is not a plugin.xml."""
    try:
        root = ET.fromstring(xml)  # noqa: S314
    except ET.ParseError:
        return None
    if root.tag != "idea-plugin":
        return None

    def text(tag: str) -> str:
        el = root.find(tag)
        return (el.text or "").strip()[:200] if el is not None and el.text else ""

    name = text("name")
    ident = text("id") or name
    if not ident:
        return None
    vendor = root.find("vendor")
    build = root.find("idea-version")
    return {"id": ident, "name": name or ident, "version": text("version"),
            "vendor": ((vendor.text or "").strip()[:200] if vendor is not None and vendor.text else ""),
            "vendor_url": (vendor.get("url", "")[:300] if vendor is not None else ""),
            "since_build": (build.get("since-build", "")[:40] if build is not None else ""),
            "until_build": (build.get("until-build", "")[:40] if build is not None else "")}


def _jar_identity(jar: Path | bytes) -> dict | None:
    """The identity in a jar's META-INF/plugin.xml, when it is a JetBrains plugin.xml (root idea-plugin)."""
    xml = _plugin_xml(jar)
    return read_identity(xml) if xml else None


def _identity(folder: Path) -> dict | None:
    """The identity of the plugin in folder (a folder with lib/*.jar), or None when it is not a plugin."""
    lib = folder / "lib"
    if not lib.is_dir() or lib.is_symlink():
        return None
    jars = sorted((p for p in lib.iterdir() if p.suffix.lower() == ".jar" and p.is_file() and not p.is_symlink()),
                  key=lambda p: (not p.stem.casefold().startswith(folder.name.casefold()), p.name))
    for jar in jars[:MAX_JARS]:
        found = _jar_identity(jar)
        if found:
            return {**found, "jar": jar.name, "jars": len(jars)}
    return None


def find_plugins(path: Path) -> list[tuple[Path, dict]]:
    """The plugins path is or holds, with their identities: one plugin folder, or an IDE's plugins folder, whose
    plugins are folders (lib/*.jar) or single jars placed directly in it, as the IDE installs a one-jar plugin."""
    if not path.is_dir():
        return []
    own = _identity(path)
    if own:
        return [(path, own)]
    found: list[tuple[Path, dict]] = []
    for child in sorted(path.iterdir()):
        if child.is_symlink():
            continue
        ident = (_identity(child) if child.is_dir()
                 else _jar_identity(child) if child.is_file() and child.suffix.lower() == ".jar" else None)
        if ident:
            found.append((child, ident))
            if len(found) > MAX_PLUGINS:
                raise InputError(f"{path.name} holds more than {MAX_PLUGINS} plugins; assess fewer at a time")
    return found


def plugin_folders(path: Path) -> list[Path]:
    return [p for p, _ in find_plugins(path)]


MAX_PLUGIN_JAR = 100 * 1024 * 1024  # a jar inside a plugin .zip, read in memory to find plugin.xml


def file_identity(path: Path) -> dict | None:
    """The identity of a plugin file: a .jar with an idea-plugin plugin.xml, or a .zip whose top folder's lib/*.jar
    holds one. None for any other .zip or .jar (a Maven or Tomcat distribution, an ordinary library)."""
    if not path.is_file() or path.suffix.lower() not in (".zip", ".jar"):
        return None
    if path.suffix.lower() == ".jar":
        return _jar_identity(path)
    try:
        with zipfile.ZipFile(path) as z:
            jars = [i for i in z.infolist() if re.match(r"^[^/]+/lib/[^/]+\.jar$", i.filename)]
            for info in jars[:MAX_JARS]:
                if info.file_size > MAX_PLUGIN_JAR:
                    continue
                with z.open(info) as fh:
                    found = _jar_identity(fh.read(MAX_PLUGIN_JAR + 1)[:MAX_PLUGIN_JAR])
                if found:
                    return found
    except Exception:  # noqa: BLE001 - a damaged or odd zip is not a plugin here; staging says why if it matters
        return None
    return None


def is_plugin_input(path: Path) -> bool:
    return file_identity(path) is not None or bool(path.is_dir() and find_plugins(path))


def unpack(path: Path, dest: Path) -> Path:
    """Stage a plugin file in dest, as an installed plugin's folder: a .zip unpacked with the .vsix limits, a .jar
    copied into <name>/lib/. Returns dest. InputError when it breaks a limit or holds no plugin.xml."""
    from . import vscode

    if path.suffix.lower() == ".jar":
        lib = dest / path.stem / "lib"
        lib.mkdir(parents=True)
        shutil.copy2(path, lib / path.name)
    else:
        try:
            vscode.extract(path, dest)
        except InputError:
            raise
        except vscode.ZIP_ERRORS as exc:  # a damaged, encrypted or oddly compressed file is the input's fault
            raise InputError(f"refused: {path.name} could not be unpacked ({type(exc).__name__}: {exc})") from None
    if not plugin_folders(dest):
        raise InputError(f"{path.name} has no plugin.xml in a lib/*.jar: not a JetBrains plugin")
    return dest


# ------------------------------------------------------------------------------------------- Marketplace

def signature(path: Path) -> dict:
    """The JetBrains Marketplace signature on a plugin file (zipsign.check), with how to get the check when the
    signatures extra is missing."""
    from .openvsx import INSTALL_SIGNATURES

    got = zipsign.check(path)
    if got["status"] == "not_checked" and "signatures extra" in got["detail"]:
        got["detail"] += f": {INSTALL_SIGNATURES}"
    return got


def integrity(sig: dict) -> str:
    """What protected a download, in words, from its signature check."""
    if sig["status"] == "verified":
        return "its JetBrains Marketplace signature verifies"
    if sig["status"] == "not_jetbrains":
        return ("it is signed, but not by the JetBrains Marketplace, so its signature does not show it came from "
                "there: HTTPS only")
    if sig["status"] == "unsigned":
        return ("it carries no JetBrains Marketplace signature (and the Marketplace publishes no checksum): "
                "HTTPS only")
    return f"its JetBrains Marketplace signature was not checked ({sig['detail']}): HTTPS only"


def _ms_date(value: object) -> str:
    try:
        return datetime.fromtimestamp(int(str(value)) / 1000, tz=timezone.utc).date().isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def summary(plugin: object, update: object) -> dict:
    """What the report shows of the Marketplace's answers for a plugin and, when found, this version."""
    if not isinstance(plugin, dict):
        return {"found": False}
    got_vendor, got_urls = plugin.get("vendor"), plugin.get("urls")
    vendor: dict = got_vendor if isinstance(got_vendor, dict) else {}
    urls: dict = got_urls if isinstance(got_urls, dict) else {}
    out = {"found": True, "plugin_id": plugin.get("id") if isinstance(plugin.get("id"), int) else None,
           "vendor": str(vendor.get("publicName") or vendor.get("name") or "")[:200],
           "vendor_verified": vendor.get("isVerified") is True,
           "blocked": plugin.get("isBlocked") is True, "hidden": plugin.get("isHidden") is True,
           "pricing": str(plugin.get("pricingModel") or "")[:40],
           "downloads": plugin.get("downloads") if isinstance(plugin.get("downloads"), int) else None,
           "source": str(urls.get("sourceCodeUrl") or "")[:300], "version_found": False}
    if isinstance(update, dict):
        got_author = update.get("author")
        author: dict = got_author if isinstance(got_author, dict) else {}
        out.update({"version_found": True, "published": _ms_date(update.get("cdate")),
                    "channel": str(update.get("channel") or "stable")[:40],
                    "since_until": str(update.get("sinceUntil") or "")[:60],
                    "author": str(author.get("name") or "")[:200]})
    return out


def _lookup_one(http: Http, ident: str, version: str) -> dict | None:
    """The Marketplace's summary for one plugin, {"found": False} when it has no such plugin, None when the
    lookup failed (not a verdict)."""
    st, plugin = http.get_json(f"{MARKETPLACE}/api/plugins/intellij/{quote(ident, safe='')}")
    if st == 404:
        return {"found": False}
    if st != 200 or not isinstance(plugin, dict) or not isinstance(plugin.get("id"), int):
        return None
    update, version_lookup = None, "no version in plugin.xml"
    if version:
        ust, updates = http.get_json(f"{MARKETPLACE}/api/plugins/{plugin['id']}/updates",
                                     params={"version": version, "size": UPDATES_PAGE})
        if ust != 200 or not isinstance(updates, list):
            return {**summary(plugin, None), "version_lookup": f"failed (HTTP {ust})"}
        update = next((u for u in updates if isinstance(u, dict) and u.get("version") == version), None)
        version_lookup = ("found" if update else f"not among the {UPDATES_PAGE} latest versions"
                          if len(updates) >= UPDATES_PAGE else "not on the Marketplace")
    return {**summary(plugin, update), "version_lookup": version_lookup}


def lookup(http: Http, plugins: list[dict]) -> dict:
    """Marketplace metadata for each plugin, as p["marketplace"]. Returns stats."""
    todo = [p for p in plugins if p["id"]][:MAX_LOOKUPS]
    prefetch(http, [f"{MARKETPLACE}/api/plugins/intellij/{quote(p['id'], safe='')}" for p in todo])
    stats = {"looked_up": 0, "found": 0, "errors": 0, "skipped_limit": len(plugins) - len(todo)}
    for p in todo:
        try:
            got = _lookup_one(http, p["id"], p["version"])
        except HttpError:
            got = None
        if got is None:
            stats["errors"] += 1
            continue
        p["marketplace"] = got
        stats["looked_up"] += 1
        stats["found"] += got["found"]
        stats["errors"] += str(got.get("version_lookup", "")).startswith("failed")
    return stats


def download(http: Http, ident: str, dest: Path) -> tuple[Path, dict]:
    """Download one exact version of a plugin from the Marketplace into dest. InputError when the Marketplace has
    no such version (404); HttpError when it cannot be reached."""
    plugin_id, version = parse_id(ident)
    url = f"{MARKETPLACE}/plugin/download?pluginId={quote(plugin_id, safe='')}&version={quote(version, safe='')}"
    st, body = http.get_bytes(url, MAX_DOWNLOAD_BYTES)
    if st == 404:
        raise InputError(f"--jetbrains-plugin {ident}: not found on the JetBrains Marketplace")
    if st != 200:
        raise HttpError(f"the JetBrains Marketplace returned HTTP {st} for {ident}")
    is_jar = body[:2] == b"PK" and _plugin_xml(body) is not None
    dest.mkdir(parents=True, exist_ok=True)
    path = dest / f"{plugin_id}-{version}.{'jar' if is_jar else 'zip'}"
    path.write_bytes(body)
    # HTTPS is the only protection: at least the file must be the plugin and version asked for.
    got = file_identity(path)
    if got is None:
        raise InputError(f"--jetbrains-plugin {ident}: the download is not a JetBrains plugin; nothing was assessed")
    if got["id"] != plugin_id or (got["version"] and got["version"] != version):
        raise InputError(f"--jetbrains-plugin {ident}: the download is {got['id']} {got['version'] or ''}, not the "
                         "plugin and version asked for; nothing was assessed")
    sig = signature(path)
    if sig["status"] == "failed":
        raise InputError(f"--jetbrains-plugin {ident}: the download does not match its JetBrains Marketplace "
                         f"signature ({sig['detail']}); nothing was assessed")
    # The Marketplace signs every file it serves, old versions too (checked on 12 Nov 2026 against
    # mobi.hsz.idea.gitignore 4.5.7 and 4.0.2, from 2020), so a download without its signature, or with someone
    # else's, is not the file the Marketplace signed. Only a check that needs the signatures extra is left to it.
    if sig["status"] in ("unsigned", "not_jetbrains"):
        signers = "; ".join(sig.get("signers") or [])
        raise InputError(f"--jetbrains-plugin {ident}: the download is "
                         + ("not signed" if sig["status"] == "unsigned" else f"signed by {signers}, not")
                         + " by the JetBrains Marketplace, which signs every plugin file it serves; nothing was "
                           "assessed")
    if sig["status"] == "not_checked" and "signatures extra" not in sig["detail"]:
        raise InputError(f"--jetbrains-plugin {ident}: the download's JetBrains Marketplace signature could not be "
                         f"checked ({sig['detail']}); nothing was assessed. A newer oss-intake may know it")
    return path, {"source": url, "sha256": hashlib.sha256(body).hexdigest(), "integrity": integrity(sig),
                  "signature": sig}


# ------------------------------------------------------------------------------------------- assessing

def assess(target: Path, http: Http | None, staged: bool = False, source: Path | None = None,
           source_signature: dict | None = None) -> dict:
    """Each plugin under target: its identity, its Marketplace signature where the file still has one, and, online,
    its Marketplace metadata. "single" (everything scanned is that plugin's) when target is one plugin. source is
    the plugin file target was staged from (its signature is source_signature when already checked)."""
    found = find_plugins(target)
    plugins = [{**ident, "folder": f.name} for f, ident in found]
    got_source = signature(source) if staged and source is not None and not source_signature else None
    for (folder, _), p in zip(found, plugins, strict=True):
        if staged and source is not None:  # every plugin in a file has that file's signature
            p["signature"] = source_signature or got_source
        elif folder.is_file():  # a single-jar plugin, installed as the file the Marketplace served
            p["signature"] = signature(folder)
        else:
            p["signature"] = dict(UNPACKED)
    market = {"status": "not_checked", "detail": "--offline"}
    if http is not None and plugins:
        market = {"status": "checked", **lookup(http, plugins)}
    # Everything scanned is one plugin's only when target is that plugin (its folder, or a staged file's); a folder
    # that holds a plugin and other things (a source checkout with a plugin jar) attributes by path.
    single = len(found) == 1 and (found[0][0] == target or staged)
    return {"plugins": plugins, "single": single, "marketplace": market}


def attribute(info: dict, findings: list) -> None:
    """Count each plugin's findings: everything scanned for one plugin; for an IDE's plugins folder, by the path's
    first folder (Trivy's paths start there; Grype's start with "/")."""
    by_folder = {p["folder"].casefold(): p for p in info["plugins"]}
    only = info["plugins"][0] if info.get("single") and len(info["plugins"]) == 1 else None
    for p in info["plugins"]:
        p["findings"] = {"total": 0, "critical": 0, "high": 0, "malicious": 0}
    unmatched = 0
    for f in findings:
        owners = [only] if only else []
        for t in (f.target or "").split(";"):
            parts = [x for x in t.replace("\\", "/").split("/") if x]
            for part in parts[:2]:  # a staged file sits one folder down
                p = by_folder.get(part.casefold())
                if p is not None and not any(o is p for o in owners):
                    owners.append(p)
        if not owners:
            unmatched += 1
        for p in owners:
            c = p["findings"]
            c["total"] += 1
            c["critical"] += f.severity == "CRITICAL"
            c["high"] += f.severity == "HIGH"
            c["malicious"] += bool(f.malicious)
    info["unmatched"] = unmatched


def warnings(info: dict) -> tuple[list[str], list[str]]:
    """(alerts for the top of the report, ordinary warnings)."""
    alerts, other = [], []
    dl = info.get("download")
    no_extra = 0
    for p in info["plugins"]:
        m = p.get("marketplace") or {}
        if m.get("blocked"):
            alerts.append(f"JETBRAINS MARKETPLACE HAS BLOCKED THIS PLUGIN: {p['id']} {p.get('version', '')}. Find "
                          "out why before using it, and remove it if the reason is a security one")
        sig = p.get("signature") or {}
        name = f"{p['id']} {p.get('version', '')}".strip()
        if sig.get("status") == "failed":
            alerts.append(f"JETBRAINS SIGNATURE DOES NOT MATCH: {name} ({p['folder']}): {sig['detail']}. Do not "
                          "install it; find out where this file came from")
        elif dl:
            continue  # a download's signature is reported with the download, below
        elif sig.get("status") == "not_jetbrains":
            other.append(f"{name} is signed, but not by the JetBrains Marketplace (by "
                         f"{'; '.join(sig.get('signers') or []) or 'no one'}), so nothing shows it came from there")
        elif sig.get("status") == "unsigned":
            other.append(f"{name} carries no JetBrains Marketplace signature: it did not come from the Marketplace "
                         "as is, or its signature was removed")
        elif sig.get("status") == "not_checked":
            if "signatures extra" in sig.get("detail", ""):
                no_extra += 1
            else:
                other.append(f"The JetBrains signature of {name} was not checked: {sig.get('detail', '')}")
    if no_extra:
        from .openvsx import INSTALL_SIGNATURES

        other.append(f"The JetBrains Marketplace signature of {no_extra} plugin file(s) was not checked: the check "
                     f"needs the signatures extra: {INSTALL_SIGNATURES}")
    stats = info.get("marketplace") or {}
    if stats.get("errors"):
        other.append(f"JetBrains Marketplace lookups failed for {stats['errors']} plugin(s): whether they are "
                     "blocked, their vendor or their publication date is not known")
    if stats.get("skipped_limit"):
        other.append(f"{stats['skipped_limit']} plugin(s) over the lookup limit ({MAX_LOOKUPS}) were not checked on "
                     "the JetBrains Marketplace, so a blocked one among them would not be seen")
    if dl and (dl.get("signature") or {}).get("status") != "verified":
        other.append(f"The plugin was downloaded from the JetBrains Marketplace over HTTPS; {dl['integrity']}")
    return alerts, other
