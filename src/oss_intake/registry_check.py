"""Is this artifact the file the project released? Compare a --path file's hash with the checksum the official
registry publishes for that exact version.

  JAR, WAR, EAR   identity from META-INF/maven/<group>/<artifact>/pom.properties; checksum from Maven Central
                  (.sha512, .sha256, then .sha1, the strongest one published)
  wheel, sdist    identity from the file name; SHA-256 from PyPI's JSON API for that release and file name
  npm .tgz        identity from package/package.json; SHA-512 from the npm registry ("integrity")

Results: match, mismatch (the file is not what the registry serves: rebuilt, repackaged or tampered with),
not_published (the registry has no such version or file), unknown (identity could not be read, or the file
bundles several projects, as a fat JAR does), unsupported (another kind of file), error (lookup failed).
A match proves the file is the published one, not that the published one is safe.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import tarfile
import zipfile
from pathlib import Path
from urllib.parse import quote

from .http import Http, HttpError

MAVEN = "https://repo1.maven.org/maven2"
PYPI = "https://pypi.org/pypi"
NPM = "https://registry.npmjs.org"
_WHEEL = re.compile(r"^(?P<name>[A-Za-z0-9_.]+)-(?P<version>[^-]+)-.+\.whl$")
_SDIST = re.compile(r"^(?P<name>.+?)-(?P<version>\d[^-]*)\.(tar\.gz|zip)$")
MAX_METADATA = 1024 * 1024  # pom.properties and package.json are a few KB; a larger one is not read (S2)
# Identities come from inside the untrusted file, so they must look like real coordinates before they go into a
# registry URL: no path segments, no '..' (S6). A tampered file must not be able to "match" another package.
_MAVEN_PART = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,199}$")
_NPM_NAME = re.compile(r"^(@[A-Za-z0-9_~-][A-Za-z0-9._~-]*/)?[A-Za-z0-9_~-][A-Za-z0-9._~-]{0,213}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+~-]{0,127}$")


def _safe(value: str, pattern: re.Pattern) -> bool:
    return bool(pattern.match(value)) and ".." not in value


def _read_small(data: bytes | None) -> bytes:
    if data is None or len(data) > MAX_METADATA:
        raise ValueError("metadata file too large")
    return data


def _digest(path: Path, algo: str) -> str:
    # SHA-1 only reproduces a checksum the registry itself publishes (old Maven Central releases have nothing
    # stronger); it is never used to decide that something is safe on its own.
    h = hashlib.new(algo, usedforsecurity=algo != "sha1")
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _maven_identity(path: Path) -> tuple[dict | None, str]:
    try:
        with zipfile.ZipFile(path) as z:
            props = [i for i in z.infolist() if i.filename.startswith("META-INF/maven/")
                     and i.filename.endswith("/pom.properties")]
            found = []
            for info in props[:200]:
                if info.file_size > MAX_METADATA:
                    continue  # not a real pom.properties; never decompressed (S2)
                with z.open(info) as fh:
                    raw = _read_small(fh.read(MAX_METADATA + 1))
                kv = {}
                for line in raw.decode("utf-8", "replace").splitlines():
                    if "=" in line and not line.lstrip().startswith("#"):
                        k, _, v = line.partition("=")
                        kv[k.strip()] = v.strip()
                if kv.get("groupId") and kv.get("artifactId") and kv.get("version"):
                    found.append(kv)
    except (zipfile.BadZipFile, OSError, KeyError, ValueError, NotImplementedError, RuntimeError, EOFError) as exc:
        return None, f"not a readable archive ({type(exc).__name__})"
    if not found:
        return None, "no META-INF/maven/.../pom.properties, so the Maven coordinates are unknown"
    own = [kv for kv in found if path.name.startswith(f"{kv['artifactId']}-{kv['version']}")]
    if len(own) == 1:
        return own[0], ""
    if len(found) == 1:
        return found[0], ""
    return None, f"bundles {len(found)} Maven projects (a fat or shaded JAR); none matches the file name"


def _check_maven(http: Http, path: Path) -> dict:
    ident, why = _maven_identity(path)
    if not ident:
        return {"status": "unknown", "detail": why}
    g, a, v = ident["groupId"], ident["artifactId"], ident["version"]
    if not (_safe(g, _MAVEN_PART) and _safe(a, _MAVEN_PART) and _safe(v, _VERSION)):
        return {"status": "unknown", "detail": f"pom.properties holds coordinates that are not valid Maven "
                                               f"coordinates ({g}:{a}:{v}); not looked up"}
    ext = path.suffix.lstrip(".").lower() or "jar"
    base = f"{MAVEN}/{g.replace('.', '/')}/{a}/{v}/{a}-{v}"
    candidates = [f"{base}.{ext}"]
    m = re.match(re.escape(f"{a}-{v}") + r"-(?P<cls>[A-Za-z0-9_.-]+)\." + re.escape(ext) + "$", path.name)
    if m:  # a classifier, e.g. shinyproxy-3.2.4-exec.jar
        candidates.insert(0, f"{base}-{m.group('cls')}.{ext}")
    coords = f"{g}:{a}:{v}"
    for url in candidates:
        for algo in ("sha512", "sha256", "sha1"):
            status, text = http.get_text(f"{url}.{algo}")
            if status == 200 and text and text.strip():
                published = text.split()[0].strip().lower()
                actual = _digest(path, algo)
                return {"status": "match" if actual == published else "mismatch", "registry": "Maven Central",
                        "identity": coords, "algorithm": algo, "published": published, "actual": actual,
                        "url": url.rsplit("/", 1)[1]}
    return {"status": "not_published", "registry": "Maven Central", "identity": coords,
            "detail": "Maven Central has no checksum for this file; it may come from another repository"}


def _check_pypi(http: Http, path: Path) -> dict:
    m = _WHEEL.match(path.name) or _SDIST.match(path.name)
    if not m:
        return {"status": "unknown", "detail": "file name is not a wheel or sdist name"}
    name, version = m.group("name"), m.group("version")
    status, data = http.get_json(f"{PYPI}/{quote(name, safe='')}/{quote(version, safe='')}/json")
    ident = f"{name} {version}"
    if status == 404:
        return {"status": "not_published", "registry": "PyPI", "identity": ident,
                "detail": "PyPI has no such release"}
    if status != 200 or not isinstance(data, dict):
        return {"status": "error", "registry": "PyPI", "identity": ident, "detail": f"HTTP {status}"}
    for f in data.get("urls") or []:
        if f.get("filename") == path.name:
            published = (f.get("digests") or {}).get("sha256", "").lower()
            actual = _digest(path, "sha256")
            return {"status": "match" if actual == published else "mismatch", "registry": "PyPI",
                    "identity": ident, "algorithm": "sha256", "published": published, "actual": actual,
                    "url": path.name}
    return {"status": "not_published", "registry": "PyPI", "identity": ident,
            "detail": f"release {version} has no file named {path.name}"}


def _check_npm(http: Http, path: Path) -> dict:
    try:
        with tarfile.open(path) as t:
            info = t.getmember("package/package.json")
            if info.size > MAX_METADATA:
                raise ValueError("package.json too large")
            member = t.extractfile(info)
            pkg = json.loads(_read_small(member.read(MAX_METADATA + 1)).decode("utf-8")) if member else {}
            if not isinstance(pkg, dict):
                raise ValueError("package.json is not an object")
    except (tarfile.TarError, KeyError, OSError, ValueError, EOFError, RuntimeError) as exc:
        return {"status": "unknown", "detail": f"no readable package/package.json ({type(exc).__name__})"}
    name, version = pkg.get("name"), pkg.get("version")
    if not name or not version:
        return {"status": "unknown", "detail": "package.json has no name or version"}
    name, version = str(name), str(version)
    if not (_safe(name, _NPM_NAME) and _safe(version, _VERSION)):
        return {"status": "unknown", "detail": f"package.json name or version is not a valid npm name and version "
                                               f"({name}@{version}); not looked up"}
    ident = f"{name}@{version}"
    status, data = http.get_json(f"{NPM}/{quote(name, safe='@')}/{quote(version, safe='')}")
    if status == 404:
        return {"status": "not_published", "registry": "npm", "identity": ident,
                "detail": "the npm registry has no such version"}
    if status != 200 or not isinstance(data, dict):
        return {"status": "error", "registry": "npm", "identity": ident, "detail": f"HTTP {status}"}
    dist = data.get("dist") or {}
    integrity = str(dist.get("integrity") or "")
    if integrity.startswith("sha512-"):
        published = base64.b64decode(integrity[7:]).hex()
        algo = "sha512"
    elif dist.get("shasum"):
        published, algo = str(dist["shasum"]).lower(), "sha1"
    else:
        return {"status": "unknown", "registry": "npm", "identity": ident, "detail": "no checksum published"}
    actual = _digest(path, algo)
    return {"status": "match" if actual == published else "mismatch", "registry": "npm", "identity": ident,
            "algorithm": algo, "published": published, "actual": actual, "url": f"{name}-{version}.tgz"}


def _is_sdist(path: Path) -> bool:
    """A Python sdist has PKG-INFO in its top folder; apache-tomcat-9.0.98.tar.gz does not (B20)."""
    try:
        if path.name.lower().endswith(".zip"):
            with zipfile.ZipFile(path) as z:
                names = z.namelist()[:5000]
        else:
            with tarfile.open(path) as t:
                names = []
                for m in t:
                    names.append(m.name)
                    if len(names) >= 5000:
                        break
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError, ValueError, RuntimeError):
        return False
    return any(n.count("/") == 1 and n.endswith("/PKG-INFO") for n in names)


def check(http: Http, path: Path) -> dict:
    name = path.name.lower()
    try:
        if name.endswith((".jar", ".war", ".ear")):
            return _check_maven(http, path)
        if name.endswith(".whl") or (name.endswith((".tar.gz", ".zip")) and _SDIST.match(path.name)
                                     and _is_sdist(path)):
            return _check_pypi(http, path)
        if name.endswith(".tgz"):
            return _check_npm(http, path)
    except HttpError as exc:
        return {"status": "error", "detail": str(exc)}
    except (OSError, ValueError, RuntimeError, NotImplementedError, EOFError) as exc:  # S8: never crash the run
        return {"status": "unknown", "detail": f"the file could not be read ({type(exc).__name__})"}
    return {"status": "unsupported", "detail": "registry checks cover JAR/WAR/EAR, Python wheels and sdists, and "
                                               "npm .tgz files"}


def summary(r: dict) -> str:
    st = r.get("status")
    where = r.get("registry", "the registry")
    if st == "match":
        return f"matches {where} ({r['algorithm']}) for {r['identity']}"
    if st == "mismatch":
        return (f"DOES NOT MATCH {where} for {r['identity']}: {r['algorithm']} {r['actual'][:16]}... here, "
                f"{r['published'][:16]}... published")
    if st == "not_published":
        return f"not published on {where} ({r.get('identity', '')}): {r.get('detail', '')}"
    return f"{st.replace('_', ' ')}: {r.get('detail', '')}"
