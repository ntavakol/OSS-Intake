"""Assess an artifact or a lockfile directly, without a container image (--path).

Kinds, decided from the path:
  inventory a CSV list of packages (ecosystem, name, version or purl), e.g. exported from a package repository:
            read here and checked against OSV; no scanner is run
  sbom      a CycloneDX or SPDX JSON SBOM, or a folder holding only SBOMs: read as an inventory (see sbom.py)
  renv      an R renv.lock: read here and checked against OSV's CRAN advisories (neither Trivy nor Grype
            reads renv.lock)
  lockfile  a dependency lockfile the scanners understand (Python, npm, Maven, Go, Rust, PHP, Ruby, .NET):
            Trivy 'fs' and Grype 'dir:'
  artifact  any other single file, e.g. a vendor JAR, WAR, EAR or binary: Trivy 'rootfs' and Grype 'dir:'
            (Trivy reads JARs and binaries in rootfs mode, not fs mode)
  dir       a directory of built artifacts (an unpacked application, a lib/ folder): Trivy 'rootfs'.
            For a source checkout, pass the lockfile itself, since rootfs mode skips lockfiles.
A single file is copied into an empty temporary directory so both scanners see exactly that file.
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from pathlib import Path
from urllib.parse import unquote

LOCKFILES = re.compile(
    r"^(requirements[\w.-]*\.txt|poetry\.lock|Pipfile\.lock|uv\.lock|pdm\.lock|package-lock\.json|"
    r"npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|pom\.xml|gradle\.lockfile|go\.mod|go\.sum|Cargo\.lock|"
    r"composer\.lock|Gemfile\.lock|packages\.lock\.json|\w[\w.-]*\.deps\.json)$")


_NAME_VERSION = re.compile(r"(?<![\d.])v?(\d+\.\d+(?:\.\d+){0,2})(?![\d])")


def version_from_name(path: Path) -> str | None:
    """'app-3.2.4-exec.jar' -> '3.2.4', tried against the project's release tags like an image tag."""
    m = _NAME_VERSION.search(path.name)
    return m.group(1) if m else None


class InputError(Exception):
    pass


def classify(path: Path) -> str:
    from . import sbom

    if sbom.is_sbom(path):  # by content: an SBOM file, or a folder that holds only SBOMs
        return "sbom"
    if path.is_dir():
        return "dir"
    if path.name == "renv.lock":
        return "renv"
    if path.suffix.lower() == ".csv":
        return "inventory"
    if LOCKFILES.match(path.name):
        return "lockfile"
    return "artifact"


def trivy_mode(kind: str) -> str:
    return "fs" if kind == "lockfile" else "rootfs"


def stage(path: Path, kind: str) -> tuple[Path, Path | None]:
    """Return (scan target, temporary directory to remove afterwards or None)."""
    if kind == "dir":
        return path, None
    tmp = Path(tempfile.mkdtemp(prefix="oss-intake-"))
    try:
        shutil.copy2(path, tmp / path.name)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return tmp, tmp


def renv_purls(path: Path) -> tuple[list[str], list[str]]:
    """CRAN packages in an renv.lock as purls, plus the names skipped (Bioconductor, GitHub, local sources,
    which OSV's CRAN advisories do not cover)."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise InputError(f"cannot read {path.name} as an renv lockfile: {exc}") from None
    pkgs = data.get("Packages") if isinstance(data, dict) else None
    if not isinstance(pkgs, dict):
        raise InputError(f"{path.name} has no 'Packages' section; is it an renv.lock?")
    purls, skipped = [], []
    for key, p in sorted(pkgs.items()):
        if not isinstance(p, dict):
            continue
        name, version = p.get("Package") or key, p.get("Version")
        source = str(p.get("Source") or p.get("Repository") or "").lower()
        if not version:
            skipped.append(name)
        elif source in ("repository", "cran", "") or "cran" in str(p.get("Repository", "")).lower():
            purls.append(f"pkg:cran/{name}@{version}")
        else:
            skipped.append(f"{name} ({p.get('Source')})")
    return purls, skipped


# --- Package inventory (a CSV list of packages, e.g. exported from Artifactory, Nexus or a spreadsheet) ---

MAX_INVENTORY_ROWS = 500_000  # as many as SBOM components (sbom.MAX_COMPONENTS); one row per host and package
INVENTORY_KEYS = {"purl", "ecosystem", "name", "version"}
# Ecosystem names people use, mapped to purl types that OSV understands.
ECOSYSTEMS = {
    "npm": "npm", "node": "npm", "javascript": "npm",
    "pypi": "pypi", "python": "pypi", "pip": "pypi",
    "maven": "maven", "java": "maven",
    "go": "golang", "golang": "golang",
    "nuget": "nuget", ".net": "nuget", "dotnet": "nuget",
    "cargo": "cargo", "rust": "cargo", "crates.io": "cargo",
    "gem": "gem", "rubygems": "gem", "ruby": "gem",
    "composer": "composer", "packagist": "composer", "php": "composer",
    "cran": "cran", "r": "cran",
    "hex": "hex", "pub": "pub",
}
# Ranges and placeholders, not an installed version: ^1.2, ~1.2, >=1, 1.*, latest, 4.x, 4.1.X, 31.+ (Gradle).
_NOT_A_VERSION = re.compile(r"[\s^~<>=*,|]|^(latest|any|x)$|(^|\.)x$|\+$", re.IGNORECASE)


def _purl_for(ptype: str, name: str, version: str) -> str:
    from urllib.parse import quote

    if ptype == "maven":
        group, sep, artifact = name.replace("/", ":").partition(":")
        if not sep or not group or not artifact:
            raise ValueError("a Maven name must be group:artifact, e.g. org.apache.logging.log4j:log4j-core")
        path = f"{group}/{artifact}"
    elif ptype == "npm" and name.startswith("@"):
        scope, sep, pkg = name.partition("/")
        if not sep or not pkg:
            raise ValueError("a scoped npm name must be @scope/name")
        path = f"{quote(scope)}/{pkg}"
    elif ptype == "pypi":
        path = re.sub(r"[-_.]+", "-", name).lower()  # PEP 503 normalised, as purl and OSV expect
    else:
        path = name
    return f"pkg:{ptype}/{path}@{version}"


def _row_purl(row: dict[str, str]) -> str:
    purl = row.get("purl", "")
    if purl:
        if not purl.startswith("pkg:") or "/" not in purl[4:]:
            raise ValueError(f"purl '{purl}' is not a package URL (pkg:type/name@version)")
        ptype = purl[4:].split("/", 1)[0].lower()
        rest = purl.split("?", 1)[0].split("#", 1)[0]
        tail = rest[4:].split("/", 1)[1]
        # An npm scope's '@' is not a version separator: pkg:npm/@scope/name has no version.
        has_version = "@" in (tail[1:] if tail.startswith("@") else tail)
        version = unquote(rest.rpartition("@")[2]) if has_version else ""  # %5E4.17 is ^4.17
        if ptype not in set(ECOSYSTEMS.values()):
            raise ValueError(f"purl type '{ptype}' is not supported (supported: "
                             f"{', '.join(sorted(set(ECOSYSTEMS.values())))})")
        if not version:
            raise ValueError(f"purl '{purl}' has no version")
        if _NOT_A_VERSION.search(version):
            raise ValueError(f"'{version}' is a version range or placeholder; give the exact installed version")
        path_part = rest[4:].split("/", 1)[1]
        if ptype == "npm" and path_part.startswith("@"):
            path_part = "%40" + path_part[1:]  # pkg:npm/@scope/name -> pkg:npm/%40scope/name, as OSV expects
        if ptype == "pypi":
            name_part, _, ver = path_part.rpartition("@")
            path_part = f"{re.sub(r'[-_.]+', '-', name_part).lower()}@{ver}"  # PEP 503, as OSV matches it
        return f"pkg:{ptype}/{path_part}"
    eco, name, version = row.get("ecosystem", ""), row.get("name", ""), row.get("version", "")
    missing = [k for k, v in (("ecosystem", eco), ("name", name), ("version", version)) if not v]
    if missing:
        raise ValueError(f"missing {', '.join(missing)}")
    ptype = ECOSYSTEMS.get(eco.lower())
    if not ptype:
        raise ValueError(f"unknown ecosystem '{eco}' (use one of: {', '.join(sorted(ECOSYSTEMS))})")
    if _NOT_A_VERSION.search(version):
        raise ValueError(f"'{version}' is a version range or placeholder; give the exact installed version")
    return _purl_for(ptype, name, version)


MAX_PACKAGES = 1000


def _check_name(name: str) -> None:
    """A --package name that cannot exist is an error, not a lookup that comes back clean."""
    if re.search(r"\s", unquote(name)):
        raise ValueError("contains a space")
    if not name.strip("/@") or (name.startswith("@") and "/" not in name):
        raise ValueError("no package name")
    if "@" in name[1:]:
        raise ValueError("'@' in the name; give one version, e.g. npm:chalk@5.6.1")
    if "" in name.removeprefix("@").split("/"):
        raise ValueError("an empty part in the name")


def packages(specs: list[str]) -> list[dict]:
    """--package values -> inventory entries, validated like CSV rows. Each is 'ecosystem:name@version'
    (npm:chalk@5.6.1, pypi:django@2.2.0, maven:org.apache.logging.log4j:log4j-core@2.14.1, npm:@ctrl/tinycolor@4.1.1)
    or a package URL (pkg:npm/chalk@5.6.1)."""
    if len(specs) > MAX_PACKAGES:
        raise InputError(f"more than {MAX_PACKAGES} --package values; put them in a CSV inventory (--path)")
    found: dict[str, None] = {}
    errors = []
    for spec in specs:
        spec = spec.strip()
        try:
            if re.search(r"\s", spec):
                raise ValueError("contains a space")
            if spec[:4].lower() == "pkg:":
                spec = "pkg:" + spec[4:]
                path = spec[4:].split("?", 1)[0].split("#", 1)[0].partition("/")[2]
                scoped = path.startswith("@") and "/" in path  # pkg:npm/@scope/name with no version
                _check_name(unquote(path.rpartition("@")[0] if path.count("@") > scoped else path))
                purl = _row_purl({"purl": spec})
            else:
                eco, sep, rest = spec.partition(":")
                name, at, version = rest.rpartition("@")
                if not sep or not at or not eco or not name or not version:
                    raise ValueError("use ecosystem:name@version, e.g. npm:chalk@5.6.1, or a package URL")
                _check_name(name)
                purl = _row_purl({"ecosystem": eco, "name": name, "version": version})
        except ValueError as exc:
            errors.append(f"--package {spec!r}: {exc}")
            continue
        found.setdefault(purl, None)
    if errors:
        raise InputError("\n  ".join(["invalid --package value(s); nothing was looked up:", *errors]))
    return [{"purl": p, "labels": {}} for p in found]


def inventory(path: Path) -> list[dict]:
    """Read a package inventory CSV. Returns [{"purl", "labels"}], one per distinct package version.

    Columns, case-insensitive: either 'purl', or 'ecosystem', 'name' and 'version'. Any other column (owner,
    system, team...) is kept as a label and carried through to the reports. Every row is validated before
    anything is looked up; any invalid row stops the run with a list of the problems.
    """
    import csv

    try:
        text = path.read_text(encoding="utf-8-sig")  # Excel writes a byte order mark
    except (OSError, UnicodeDecodeError) as exc:
        raise InputError(f"cannot read {path.name}: {exc}. Save it from Excel as 'CSV UTF-8'.") from None
    reader = csv.DictReader(text.splitlines())
    headers = {h: (h or "").strip().lower() for h in reader.fieldnames or []}
    cols = set(headers.values())
    if "purl" not in cols and not {"ecosystem", "name", "version"} <= cols:
        raise InputError(f"{path.name} needs a 'purl' column, or 'ecosystem', 'name' and 'version' columns "
                         f"(found: {', '.join(sorted(c for c in cols if c)) or 'no header row'})")
    from .inventory_report import BASE_FIELDS

    clash = sorted(c for c in cols if c in BASE_FIELDS and c not in INVENTORY_KEYS
                   or c in ("labels", "compare_version", "upgrade_version"))
    if clash:
        raise InputError(f"{path.name}: column(s) {', '.join(clash)} share a name with a column oss-intake fills in "
                         "(packages.csv); rename them, e.g. to inventory_" + clash[0])
    found: dict[str, dict[str, set[str]]] = {}
    errors: list[str] = []
    for n, raw in enumerate(reader, start=2):  # row 1 is the header
        if n - 1 > MAX_INVENTORY_ROWS:
            raise InputError(f"{path.name} has more than {MAX_INVENTORY_ROWS} rows; split it into smaller files")
        row = {headers[k]: (v or "").strip() for k, v in raw.items() if k is not None and headers.get(k)}
        if not any(row.values()):
            continue
        try:
            purl = _row_purl(row)
        except ValueError as exc:
            errors.append(f"row {n}: {exc}")
            continue
        labels = found.setdefault(purl, {})
        for k, v in row.items():
            if k not in INVENTORY_KEYS and v:
                labels.setdefault(k, set()).add(v)
    if errors:
        shown = "\n  ".join(errors[:20])
        more = f"\n  ... and {len(errors) - 20} more" if len(errors) > 20 else ""
        raise InputError(f"{len(errors)} invalid row(s) in {path.name}; nothing was looked up:\n  {shown}{more}")
    if not found:
        raise InputError(f"{path.name} lists no packages")
    return [{"purl": p, "labels": {k: "; ".join(sorted(v)) for k, v in sorted(lb.items())}}
            for p, lb in sorted(found.items())]
