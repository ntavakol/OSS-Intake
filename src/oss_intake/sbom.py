"""SBOM input: a CycloneDX or SPDX JSON file, or a folder of them, read as a package inventory.

Recognised by content, not file name: CycloneDX has "bomFormat": "CycloneDX"; SPDX has "spdxVersion". GitHub's
dependency-graph export ({"sbom": {...SPDX...}}) is unwrapped. Each component is read by its package URL:

  CycloneDX  components, including nested ones; metadata.component is the SBOM's subject, not a package
  SPDX       packages, through their PACKAGE-MANAGER purl reference; the described package or the document name
             is the subject

A component with no purl, a purl of a type OSV does not cover, a version range, or an OS package whose distro or
release cannot be told is listed as not checked with the reason; nothing is dropped silently. The subject
becomes the `system` label and a component's supplier the `supplier` label, so packages.csv and the executive
summary group by them. Structural problems (not JSON, not an SBOM, too large) stop the run before any lookup.
"""

from __future__ import annotations

import json
from pathlib import Path

from . import os_packages
from .inputs import InputError, _row_purl
from .models import normalise_purl

MAX_FILE_BYTES = 200 * 1024 * 1024
MAX_FILES = 5000
MAX_COMPONENTS = 500_000
_CDX_SPECS = ("1.2", "1.3", "1.4", "1.5", "1.6", "1.7")


def kind_of(data: object) -> str | None:
    """'cyclonedx', 'spdx' or None."""
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("sbom"), dict) and "spdxVersion" in data["sbom"]:
        return "spdx"
    if data.get("bomFormat") == "CycloneDX":
        return "cyclonedx"
    if str(data.get("spdxVersion", "")).startswith("SPDX-"):
        return "spdx"
    return None


def _peek(path: Path) -> str | None:
    """Cheap content check used to classify --path: is this file an SBOM?"""
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return None
        with open(path, "rb") as fh:
            head = fh.read(4096).decode("utf-8-sig", errors="replace")
    except OSError:
        return None
    if '"bomFormat"' in head and "CycloneDX" in head:
        return "cyclonedx"
    if '"spdxVersion"' in head or ('"sbom"' in head and "SPDX-" in head):
        return "spdx"
    return None


# The only other files an SBOM folder may hold: notes. Nothing that could list packages (a lockfile, a CSV
# inventory, a YAML environment) counts as a note, so a folder holding one is scanned as a folder instead.
_DOC_SUFFIXES = (".md", ".rst")
_DOC_NAMES = ("README", "LICENSE", "NOTICE", "CHANGELOG")


def _is_doc(p: Path) -> bool:
    from .inputs import LOCKFILES

    if LOCKFILES.match(p.name):
        return False
    stem = p.name.upper().split(".", 1)[0]
    return p.suffix.lower() in _DOC_SUFFIXES or (stem in _DOC_NAMES and p.suffix.lower() in ("", ".txt"))


def _iter_files(path: Path):
    """Regular files under a folder, subfolders included (an S3 sync keeps the bucket's folders), in no set order,
    skipping hidden files and folders. Lazy, so a caller can stop at the first file that settles a question."""
    import os

    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for name in files:
            if not name.startswith("."):
                yield Path(root) / name


def _walk(path: Path) -> list[Path]:
    out = []
    for p in _iter_files(path):
        out.append(p)
        if len(out) > MAX_FILES * 2:
            break
    return sorted(out)


def is_sbom(path: Path) -> bool:
    """An SBOM file, or a folder (subfolders included) whose files are all SBOMs, apart from notes such as a
    README. A folder holding anything else, say package.json or a JAR, is an application folder and is scanned.
    A folder that mixes SBOMs with other JSON files is refused by read() with the names, not guessed."""
    if path.is_file():
        return path.suffix.lower() == ".json" and _peek(path) is not None
    if path.is_dir():
        found = False
        for n, p in enumerate(_iter_files(path)):
            if _is_doc(p):
                continue
            # Stop at the first file an SBOM folder would not hold: an application folder is not walked in full.
            if p.suffix.lower() != ".json" or p.name in ("package.json", "composer.json", "tsconfig.json"):
                return False
            if not found and n < 200:
                found = _peek(p) is not None
        return found
    return False


def _load(path: Path) -> dict:
    if path.stat().st_size > MAX_FILE_BYTES:
        raise InputError(f"{path.name} is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB; split it")
    try:
        data = json.loads(path.read_bytes().decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise InputError(f"{path.name} is not valid JSON: {exc}") from None
    kind = kind_of(data)
    if kind is None:
        raise InputError(f"{path.name} is not a CycloneDX or SPDX JSON SBOM")
    if kind == "spdx" and isinstance(data.get("sbom"), dict):
        data = data["sbom"]  # GitHub dependency graph export
    data["_kind"] = kind
    return data


def _props(component: dict) -> dict:
    return {str(p.get("name")): str(p.get("value")) for p in component.get("properties") or []
            if isinstance(p, dict) and p.get("name")}


def _cyclonedx(data: dict) -> tuple[str, list[tuple[str, str, str, dict]]]:
    spec = str(data.get("specVersion", ""))
    if spec not in _CDX_SPECS:
        raise InputError(f"CycloneDX specVersion '{spec}' is not supported ({', '.join(_CDX_SPECS)})")
    meta = (data.get("metadata") or {}).get("component") or {}
    subject = " ".join(x for x in (str(meta.get("name") or ""), str(meta.get("version") or "")) if x)
    out = []
    stack = list(data.get("components") or [])
    while stack:
        c = stack.pop(0)
        if not isinstance(c, dict):
            continue
        stack.extend(c.get("components") or [])
        if not c.get("purl") and (c.get("type") in ("operating-system", "file")
                                  or any(p.get("name") == "aquasecurity:trivy:Class"
                                         for p in c.get("properties") or [] if isinstance(p, dict))):
            continue  # the OS itself, a file, or a scanned target such as a lockfile: not packages
        sup = c.get("supplier")
        supplier = (sup.get("name") if isinstance(sup, dict) else "") or c.get("publisher") or ""
        name = str(c.get("name") or "") + (f" {c.get('version')}" if c.get("version") else "")
        out.append((str(c.get("purl") or ""), name, str(supplier), _props(c)))
    return subject, out


def _spdx(data: dict) -> tuple[str, list[tuple[str, str, str, dict]]]:
    if not str(data.get("spdxVersion", "")).startswith(("SPDX-2.2", "SPDX-2.3")):
        raise InputError(f"SPDX version '{data.get('spdxVersion')}' is not supported (2.2, 2.3)")
    described = set(data.get("documentDescribes") or [])
    described |= {r.get("relatedSpdxElement") for r in data.get("relationships") or []
                  if isinstance(r, dict) and r.get("relationshipType") == "DESCRIBES"
                  and r.get("spdxElementId") == "SPDXRef-DOCUMENT"}
    subject = str(data.get("name") or "")
    out = []
    for p in data.get("packages") or []:
        if not isinstance(p, dict):
            continue
        name = str(p.get("name") or "") + (f" {p.get('versionInfo')}" if p.get("versionInfo") else "")
        # The document describes one root (a repository, an image) or, as Amazon Inspector writes it, each package.
        # Only a single described element is the subject; several are packages like any other.
        if len(described) == 1 and p.get("SPDXID") in described:
            subject = str(p.get("name") or subject)
            continue
        purls = [r.get("referenceLocator") for r in p.get("externalRefs") or [] if isinstance(r, dict)
                 and str(r.get("referenceType", "")).lower() == "purl"
                 and str(r.get("referenceCategory", "")).upper().replace("_", "-") == "PACKAGE-MANAGER"]
        supplier = str(p.get("supplier") or "").removeprefix("Organization: ").removeprefix("Person: ")
        if supplier.upper() == "NOASSERTION":
            supplier = ""
        out.append((str(purls[0]) if purls else "", name, supplier, {}))
    return subject, out


def files_of(path: Path) -> list[Path]:
    if path.is_file():
        return [path]
    files = [p for p in _walk(path) if not _is_doc(p)]
    if len(files) > MAX_FILES:
        raise InputError(f"{path.name} holds more than {MAX_FILES} SBOM files; split the folder")
    others = [str(p.relative_to(path)) for p in files if _peek(p) is None]
    if others:
        raise InputError(f"{path.name} mixes SBOMs with other files ({', '.join(others[:5])}"
                         f"{' ...' if len(others) > 5 else ''}); pass a folder that holds only SBOMs")
    return files


def read(path: Path) -> tuple[list[dict], dict, dict]:
    """Returns (entries [{"purl", "labels"}], OS package queries {purl: query}, info for the report).

    Every file is read and validated before anything is looked up."""
    found: dict[str, dict[str, set[str]]] = {}
    os_queries: dict[str, dict] = {}
    info: dict = {"files": 0, "formats": {}, "components": 0, "packages": 0, "not_checked": []}
    errors: list[str] = []
    for f in files_of(path):
        try:
            data = _load(f)
            subject, comps = (_cyclonedx if data["_kind"] == "cyclonedx" else _spdx)(data)
        except InputError as exc:
            errors.append(str(exc))
            continue
        info["files"] += 1
        fmt = (f"CycloneDX {data.get('specVersion')}" if data["_kind"] == "cyclonedx"
               else str(data.get("spdxVersion")))
        info["formats"][fmt] = info["formats"].get(fmt, 0) + 1
        system = subject or f.stem
        for raw_purl, name, supplier, props in comps:
            info["components"] += 1
            if info["components"] > MAX_COMPONENTS:
                raise InputError(f"more than {MAX_COMPONENTS} components; split the SBOMs into smaller sets")
            purl, why = _purl(raw_purl, props, os_queries)
            if not purl:
                info["not_checked"].append({"component": name or raw_purl, "system": system, "reason": why})
                continue
            labels = found.setdefault(purl, {})
            labels.setdefault("system", set()).add(system)
            if supplier:
                labels.setdefault("supplier", set()).add(supplier)
    if errors:
        shown = "\n  ".join(errors[:20])
        raise InputError(f"{len(errors)} file(s) could not be read as SBOMs; nothing was looked up:\n  {shown}")
    if not found and not info["not_checked"]:
        raise InputError(f"{path.name} lists no components")
    info["packages"] = len(found)
    entries = [{"purl": p, "labels": {k: "; ".join(sorted(v)) for k, v in sorted(lb.items())}}
               for p, lb in sorted(found.items())]
    return entries, os_queries, info


def _purl(raw: str, props: dict, os_queries: dict) -> tuple[str | None, str]:
    """(normalised purl, '') for a checkable component, or (None, why not)."""
    if not raw:
        return None, "no package URL (purl) in the SBOM"
    if not raw.startswith("pkg:") or "/" not in raw[4:]:
        return None, f"'{raw[:80]}' is not a package URL"
    if os_packages.is_os_purl(raw):
        query, why = os_packages.osv_query(raw, props)
        if not query:
            return None, why
        base = normalise_purl(raw.replace("pkg:dpkg/", "pkg:deb/", 1))
        if not base:
            return None, "unreadable package URL"
        # The distro stays in the package's identity: the same version in two releases is two packages.
        purl = f"{base}?distro={query['distro']}"
        os_queries[purl] = query
        return purl, ""
    try:
        return _row_purl({"purl": raw}), ""
    except ValueError as exc:
        return None, str(exc)
