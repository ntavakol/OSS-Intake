"""JetBrains IDE plugins: a plugin file (.zip or .jar), one installed plugin, or an IDE's plugins folder.

A plugin is a folder with a lib/ of jars, one of which holds META-INF/plugin.xml (its ID, name, version, vendor
and the IDE builds it supports); a small plugin can be that one jar. The scanners find the libraries the jars
bundle; this module reads each plugin's identity and looks it up on the JetBrains Marketplace: its vendor and
whether the vendor is verified, whether the Marketplace has blocked it, and when this version was published.
Nothing in a plugin is run.

--jetbrains-plugin ID@VERSION downloads one exact version from the Marketplace (free and paid plugins alike: a
paid plugin's licence is checked by the IDE, not at download). The Marketplace publishes no checksum, and its
signature (a signing block in the zip, chained to JetBrains' certificate) is not checked yet, so the download is
protected by HTTPS only; the report says so. The Marketplace answers were captured from the live service on
9 Nov 2026 (plugins/{id}, plugins/intellij/{xmlId}, plugins/{id}/updates, plugin/download).
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

from .http import Http, HttpError, prefetch
from .inputs import InputError

MARKETPLACE = "https://plugins.jetbrains.com"
MAX_PLUGINS = 500  # plugins in one IDE's folder
MAX_JARS = 400  # jars read in one plugin's lib/ for plugin.xml
MAX_PLUGIN_XML = 2 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 500 * 1024 * 1024
MAX_LOOKUPS = 300
NOT_SIGNED = "the JetBrains Marketplace publishes no checksum, and its signature is not checked yet: HTTPS only"
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


def _identity(folder: Path) -> dict | None:
    """The identity of the plugin in folder (a folder with lib/*.jar), or None when it is not a plugin."""
    lib = folder / "lib"
    if not lib.is_dir() or lib.is_symlink():
        return None
    jars = sorted((p for p in lib.iterdir() if p.suffix.lower() == ".jar" and p.is_file() and not p.is_symlink()),
                  key=lambda p: (not p.stem.casefold().startswith(folder.name.casefold()), p.name))
    for jar in jars[:MAX_JARS]:
        xml = _plugin_xml(jar)
        found = read_identity(xml) if xml else None
        if found:
            return {**found, "jar": jar.name, "jars": len(jars)}
    return None


def plugin_folders(path: Path) -> list[Path]:
    """The plugin folders path is or holds: one plugin, or an IDE's plugins folder (its children)."""
    if not path.is_dir():
        return []
    if _identity(path):
        return [path]
    found = []
    for child in sorted(path.iterdir()):
        if child.is_dir() and not child.is_symlink() and _identity(child):
            found.append(child)
            if len(found) > MAX_PLUGINS:
                raise InputError(f"{path.name} holds more than {MAX_PLUGINS} plugins; assess fewer at a time")
    return found


def is_plugin_file(path: Path) -> bool:
    """A plugin .zip (a top folder with lib/*.jar) or a plugin .jar (with META-INF/plugin.xml)."""
    if not path.is_file() or path.suffix.lower() not in (".zip", ".jar"):
        return False
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
    except (zipfile.BadZipFile, OSError):
        return False
    if path.suffix.lower() == ".jar":
        return "META-INF/plugin.xml" in names
    return any(re.match(r"^[^/]+/lib/[^/]+\.jar$", n) for n in names)


def is_plugin_input(path: Path) -> bool:
    return is_plugin_file(path) or bool(path.is_dir() and plugin_folders(path))


def unpack(path: Path, dest: Path) -> Path:
    """Stage a plugin file in dest, as an installed plugin's folder: a .zip unpacked with the .vsix limits, a .jar
    copied into <name>/lib/. Returns dest. InputError when it breaks a limit or holds no plugin.xml."""
    from . import vscode

    if path.suffix.lower() == ".jar":
        lib = dest / path.stem / "lib"
        lib.mkdir(parents=True)
        shutil.copy2(path, lib / path.name)
    else:
        vscode.extract(path, dest)
    if not plugin_folders(dest):
        raise InputError(f"{path.name} has no plugin.xml in a lib/*.jar: not a JetBrains plugin")
    return dest


# ------------------------------------------------------------------------------------------- Marketplace

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
    update = None
    if version:
        ust, updates = http.get_json(f"{MARKETPLACE}/api/plugins/{plugin['id']}/updates",
                                     params={"version": version, "size": 100})
        if ust == 200 and isinstance(updates, list):
            update = next((u for u in updates if isinstance(u, dict) and u.get("version") == version), None)
    return summary(plugin, update)


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
    return path, {"source": url, "sha256": hashlib.sha256(body).hexdigest(), "integrity": NOT_SIGNED}


# ------------------------------------------------------------------------------------------- assessing

def assess(target: Path, http: Http | None, single: bool) -> dict:
    """Each plugin under target: its identity and, online, its Marketplace metadata."""
    folders = plugin_folders(target)
    if not folders:  # a staged plugin file: its folder is one level down
        folders = [c for c in sorted(target.iterdir()) if c.is_dir() and _identity(c)]
    plugins = []
    for f in folders:
        ident = _identity(f) or {}
        plugins.append({**ident, "folder": f.name})
    market = {"status": "not_checked", "detail": "--offline"}
    if http is not None and plugins:
        market = {"status": "checked", **lookup(http, plugins)}
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
    for p in info["plugins"]:
        m = p.get("marketplace") or {}
        if m.get("blocked"):
            alerts.append(f"JETBRAINS MARKETPLACE HAS BLOCKED THIS PLUGIN: {p['id']} {p.get('version', '')}. Find "
                          "out why before using it, and remove it if the reason is a security one")
    stats = info.get("marketplace") or {}
    if stats.get("errors"):
        other.append(f"JetBrains Marketplace lookups failed for {stats['errors']} plugin(s); their vendor and "
                     "publication date are not known")
    dl = info.get("download")
    if dl:
        other.append(f"The plugin was downloaded from the JetBrains Marketplace over HTTPS; {NOT_SIGNED}")
    return alerts, other
