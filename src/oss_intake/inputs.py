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
  dir       a directory: a source checkout or built artifacts (an unpacked application, a lib/ folder). Trivy
            runs in both modes, 'rootfs' for JARs and binaries and 'fs' for lockfiles, and the two are merged;
            Grype 'dir:' reads both kinds itself
A single file is copied into an empty temporary directory so both scanners see exactly that file.
"""

from __future__ import annotations

import io
import re
import shutil
import tempfile
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import unquote

from . import jsonsafe

LOCKFILES = re.compile(
    r"^(requirements[\w.-]*\.txt|poetry\.lock|Pipfile\.lock|uv\.lock|pdm\.lock|package-lock\.json|"
    r"npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|pom\.xml|gradle\.lockfile|go\.mod|go\.sum|Cargo\.lock|"
    r"composer\.lock|Gemfile\.lock|packages\.lock\.json|\w[\w.-]*\.deps\.json)$")


_NAME_VERSION = re.compile(r"(?<![\d.])v?(\d+\.\d+(?:\.\d+){0,2})(?![\d])")


def version_from_name(path: Path) -> str | None:
    """'app-3.2.4-exec.jar' -> '3.2.4', tried against the project's release tags like an image tag."""
    m = _NAME_VERSION.search(path.name)
    return m.group(1) if m else None


MAX_INPUT_BYTES = 200 * 1024 * 1024  # an inventory CSV, renv.lock or decisions file; as an SBOM (sbom.MAX_FILE_BYTES)
MAX_REPORT_BYTES = 1024 * 1024 * 1024  # an imported Trivy or Grype report: a large image's runs to hundreds of MB


def check_size(path: Path, limit: int, what: str) -> None:
    """Refuse a file over limit before it is read whole into memory."""
    try:
        size = path.stat().st_size
    except OSError:
        return  # the read that follows reports it
    if size > limit:
        raise InputError(f"{what} {path.name} is larger than {limit // (1024 * 1024)} MB; split it or trim it")


class InputError(Exception):
    """Raised for an input path or value that cannot be used; the CLI reports it as a usage error."""
    pass


def classify(path: Path) -> str:
    """Kind of input path: "sbom", "vscode" (a .vsix, an installed VS Code extension or a folder of them),
    "jetbrains" (a JetBrains plugin file, one installed plugin or an IDE's plugins folder), "dir",
    "renv" (renv.lock), "inventory" (.csv), "lockfile" or "artifact"."""
    from . import sbom, vscode

    if sbom.is_sbom(path):  # by content: an SBOM file, or a folder that holds only SBOMs
        return "sbom"
    if vscode.is_extension_input(path):  # by content too: a .vsix is a zip with extension/package.json in it
        return "vscode"
    from . import jetbrains

    if jetbrains.is_plugin_input(path):  # a plugin .zip/.jar, one installed plugin or an IDE's plugins folder
        return "jetbrains"
    if path.is_dir():
        return "dir"
    if path.name == "renv.lock":
        return "renv"
    if path.suffix.lower() in (".csv", ".xlsx"):
        return "inventory"
    if LOCKFILES.match(path.name):
        return "lockfile"
    return "artifact"


def trivy_mode(kind: str) -> str:
    """Trivy subcommand for an input kind: "fs" for a lockfile, otherwise "rootfs"."""
    return "fs" if kind == "lockfile" else "rootfs"


def stage(path: Path, kind: str) -> tuple[Path, Path | None]:
    """Return (scan target, temporary directory to remove afterwards or None)."""
    if kind == "dir" or (kind in ("vscode", "jetbrains") and path.is_dir()):
        return path, None
    tmp = Path(tempfile.mkdtemp(prefix="oss-intake-"))
    try:
        if kind == "jetbrains":
            from . import jetbrains

            jetbrains.unpack(path, tmp)  # a plugin file: unpacked with limits, never run
        elif kind == "vscode":
            from . import vscode

            vscode.unpack(path, tmp / path.stem)  # a .vsix: unpacked with limits, never run
        else:
            shutil.copy2(path, tmp / path.name)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    return tmp, tmp


def renv_purls(path: Path) -> tuple[list[str], list[str]]:
    """CRAN packages in an renv.lock as purls, plus the names skipped (Bioconductor, GitHub, local sources,
    which OSV's CRAN advisories do not cover)."""
    check_size(path, MAX_INPUT_BYTES, "renv lockfile")
    try:
        data = jsonsafe.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        raise InputError(f"cannot read {path.name} as an renv lockfile: {exc}") from None
    pkgs = data.get("Packages") if isinstance(data, dict) else None
    if not isinstance(pkgs, dict):
        raise InputError(f"{path.name} has no 'Packages' section; is it an renv.lock?")
    if not pkgs:
        raise InputError(f"{path.name} lists no packages")  # as an empty package list is refused
    purls, skipped, errors = [], [], []
    for key, p in sorted(pkgs.items()):
        if not isinstance(p, dict):
            errors.append(f"{key}: not an object")
            continue
        name, version = p.get("Package") or key, p.get("Version")
        if not isinstance(name, str) or (version is not None and not isinstance(version, str)):
            errors.append(f"{key}: Package and Version must be text")
            continue
        source = str(p.get("Source") or p.get("Repository") or "").lower()
        if not version:
            skipped.append(name)
        elif source in ("repository", "cran", "") or "cran" in str(p.get("Repository", "")).lower():
            try:  # the same name and version rules as a package list: "latest" or "1.4.*" is refused
                purls.append(_row_purl({"ecosystem": "cran", "name": name, "version": version}))
            except ValueError as exc:
                errors.append(f"{key}: {exc}")
        else:
            skipped.append(f"{name} ({p.get('Source')})")
    if errors:
        raise InputError(f"{path.name}: {len(errors)} package(s) cannot be read: " + "; ".join(errors[:10]))
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
# Ranges and placeholders, not an installed version: ^1.2, ~1.2, >=1, 1.*, latest, 4.x, 4.1.X, 31.+ (Gradle), and
# the words a spreadsheet puts where a version is not known (unknown, TBD, N/A, -, ?): OSV knows nothing about
# them, so the package would read as clean.
_NOT_A_VERSION = re.compile(r"[\s^~<>=*,|?]|^(latest|any|x|unknown|tbd|n/?a|none|null|undefined|unspecified|-+)$"
                            r"|(^|\.)x$|\+$", re.IGNORECASE)


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
        if not purl.startswith("pkg:") or "/" not in purl.split("?", 1)[0].split("#", 1)[0][4:]:
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
    ptype = ECOSYSTEMS.get(eco.lower(), "")
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


# An .xlsx is a zip of XML: what it may unpack to is limited before it is opened (a small file can unpack to a
# very large one).
MAX_XLSX_UNPACKED = 4 * MAX_INPUT_BYTES
MAX_XLSX_PARTS = 10_000
# openpyxl reads the shared strings (every distinct text in the workbook) into memory whole, even read-only, at
# several times their size; the worksheets themselves are streamed.
MAX_XLSX_STRINGS = 64 * 1024 * 1024


_SST_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"


def _shared_strings_parts(z, parts: list, name: str) -> list:
    """The parts openpyxl would read as shared strings: found, as openpyxl finds them, by content type in
    [Content_Types].xml (an Override for a part name, or a Default for an extension), not by file name."""
    import xml.etree.ElementTree as ET  # noqa: S405 - expat limits entity expansion; the part is size-checked

    ct = next((p for p in parts if p.filename == "[Content_Types].xml"), None)
    if ct is None or ct.file_size > 1024 * 1024:
        raise InputError(f"cannot read {name} as an Excel workbook: its [Content_Types].xml is missing or over 1 MB")
    try:
        root = ET.fromstring(z.read(ct))  # noqa: S314
    except ET.ParseError:
        raise InputError(f"cannot read {name} as an Excel workbook: its [Content_Types].xml is not XML") from None
    names, exts = set(), set()
    for el in root:
        if el.get("ContentType") == _SST_TYPE:
            if el.tag.endswith("Override") and el.get("PartName"):
                names.add(el.get("PartName", "").lstrip("/").casefold())
            elif el.tag.endswith("Default") and el.get("Extension"):
                exts.add(el.get("Extension", "").casefold())
    return [p for p in parts if p.filename.casefold() in names
            or p.filename.casefold().rpartition(".")[2] in exts or p.filename.casefold().endswith("sharedstrings.xml")]


def _xlsx_rows(path: Path) -> tuple[list[str], Iterator[dict]]:
    """The first worksheet of an .xlsx as a header row and dict rows of text, read with openpyxl (an optional
    extra: pip install 'oss-intake[xlsx]'). Cells are read as their stored values, never as formulas run."""
    import zipfile

    try:
        import openpyxl
    except ImportError:
        raise InputError(f"reading {path.name} needs openpyxl, an optional extra: pip install 'oss-intake[xlsx]' "
                         "(or save the sheet as 'CSV UTF-8')") from None
    try:
        with zipfile.ZipFile(path) as z:
            parts = z.infolist()
            if len(parts) > MAX_XLSX_PARTS or sum(p.file_size for p in parts) > MAX_XLSX_UNPACKED:
                raise InputError(f"{path.name} unpacks to more than {MAX_XLSX_UNPACKED // (1024 * 1024)} MB or "
                                 f"{MAX_XLSX_PARTS} parts; save it as CSV instead")
            if any(p.file_size > MAX_XLSX_STRINGS for p in _shared_strings_parts(z, parts, path.name)):
                raise InputError(f"{path.name} holds more than {MAX_XLSX_STRINGS // (1024 * 1024)} MB of text in its "
                                 "shared strings; save it as CSV instead")
        book = openpyxl.load_workbook(path, read_only=True, data_only=True)
    except InputError:
        raise
    except Exception as exc:  # openpyxl and zipfile raise many kinds for a damaged or non-xlsx file
        raise InputError(f"cannot read {path.name} as an Excel workbook: {exc}") from None
    sheet = book.worksheets[0] if book.worksheets else None
    if sheet is None:
        book.close()
        raise InputError(f"{path.name} has no worksheet")

    def text(v: object) -> str:
        if v is None:
            return ""
        if isinstance(v, float) and v.is_integer():
            return str(int(v))  # a version typed as 2 is stored as 2.0
        return str(v)

    rows = sheet.iter_rows(values_only=True)
    try:
        header = [text(v) for v in next(rows, ())]
    except Exception as exc:
        book.close()
        raise InputError(f"cannot read {path.name}: {exc}") from None
    # Header cells that are empty, or repeat an earlier one, are kept apart so no column overwrites another.
    keys = [h if h and h not in header[:i] else f"\0{i}" for i, h in enumerate(header)]

    def body() -> Iterator[dict]:
        try:
            for r in rows:
                yield {k: text(v) for k, v in zip(keys, r, strict=False)}  # cells past the header are not read
        except Exception as exc:
            raise InputError(f"cannot read {path.name}: {exc}") from None
        finally:
            book.close()

    return keys, body()


def inventory(path: Path) -> list[dict]:
    """Read a package inventory, CSV or the first worksheet of an .xlsx. Returns [{"purl", "labels"}], one per
    distinct package version.

    Columns, case-insensitive: either 'purl', or 'ecosystem', 'name' and 'version'. Any other column (owner,
    system, team...) is kept as a label and carried through to the reports. Every row is validated before
    anything is looked up; any invalid row stops the run with a list of the problems.
    """
    import csv

    check_size(path, MAX_INPUT_BYTES, "inventory")
    if path.suffix.lower() == ".xlsx":
        fieldnames, reader = _xlsx_rows(path)
    else:
        try:
            text = path.read_text(encoding="utf-8-sig")  # Excel writes a byte order mark
        except (OSError, UnicodeDecodeError) as exc:
            raise InputError(f"cannot read {path.name}: {exc}. Save it from Excel as 'CSV UTF-8'.") from None
        # newline="": the csv module splits rows itself, so a quoted line break, or a character str.splitlines()
        # also breaks on (\x85, \x0b, \x1c), stays inside its cell.
        dict_reader = csv.DictReader(io.StringIO(text, newline=""))
        fieldnames, reader = list(dict_reader.fieldnames or []), iter(dict_reader)
    headers = {h: ("" if h.startswith("\0") else (h or "").strip().lower()) for h in fieldnames}
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
