"""VS Code extensions: a .vsix file, an installed extension's folder, or a folder of installed extensions
(~/.vscode/extensions, and the same layout in Cursor and VSCodium).

There is no vulnerability database for extensions, so an extension is assessed on what can be known about it:
- whether the VS Code Marketplace removed it, and why (Microsoft's RemovedPackages list);
- the npm packages it ships, which the scanners and OSV check like any other (scanning.py does that part);
- behaviour indicators found by reading its files: what it can do, not a verdict on whether it does harm;
- whether its code is bundled, which hides its dependencies from the scanners.

Nothing in an extension is run. A .vsix is untrusted input from the internet: it is unpacked with fixed limits on
the number of files, their sizes and how far they expand, and with no absolute paths, no '..', and no links.
"""

from __future__ import annotations

import bisect
import os
import re
import stat
import unicodedata
import zipfile
import zlib
from pathlib import Path, PurePosixPath, PureWindowsPath

from . import jsonsafe
from .http import Http, HttpError
from .inputs import InputError

REMOVED_URL = "https://raw.githubusercontent.com/microsoft/vsmarketplace/main/RemovedPackages.md"
MANIFEST_COPY = ".oss-intake-vsixmanifest"
# The same list as a page to read, for the report (it is never requested).
REMOVED_PAGE = REMOVED_URL.replace("raw.githubusercontent.com", "github.com").replace("/main/", "/blob/main/")

# Unpacking limits. The largest popular extensions are a few hundred MB unpacked with tens of thousands of files.
MAX_FILES = 50_000
MAX_TOTAL_BYTES = 1_000_000_000
MAX_FILE_BYTES = 300_000_000
MAX_RATIO = 200  # a member that expands more than this from its compressed size is refused (a zip bomb)

# Reading limits for the indicators: files are read up to this size, and in total up to this much.
READ_FILE_BYTES = 20_000_000
READ_TOTAL_BYTES = 400_000_000
MAX_HITS = 20  # occurrences kept per indicator
# Every file of the extension's own is read as text unless it is binary (a NUL in its first 8 KB) or a source map
# (which carries its dependencies' sources). Node loads a file of any name as JavaScript, so the suffix is not used.
NOT_READ_SUFFIXES = {".map"}
# Documentation and markup. Every check still runs on them (Node loads a required file of any name as JavaScript),
# but a hit there is labelled, since a mention in prose usually runs nothing.
DOC_SUFFIXES = {".md", ".markdown", ".rst", ".adoc", ".html", ".htm", ".css", ".scss", ".svg", ".yml", ".yaml",
                ".xml", ".toml", ".ini", ".cfg", ".txt", ".lock"}
NATIVE_SUFFIXES = {".node", ".exe", ".dll", ".so", ".dylib", ".wasm"}
NATIVE_MAGIC = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                b"\0asm")
MAX_HOSTS = 1000
# Windows device names, a name that ends in a dot or space included (Windows drops those): COM¹ to COM³ and
# LPT¹ to LPT³ count as devices too, and so do CONIN$, CONOUT$ and CLOCK$.
_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9\u00b9\u00b2\u00b3]|lpt[0-9\u00b9\u00b2\u00b3]"
                       r"|conin\$|conout\$|clock\$)(\..*)?[. ]*$", re.I)
BUNDLE_BYTES = 200_000  # a main file this large with no node_modules folder is taken as bundled

# What a run of an extension is checked for. Each is a signal for a person to look at, not a verdict.
INDICATORS = {
    "activation-all": "Starts with VS Code, whatever is open (activationEvents \"*\")",
    "activation-startup": "Starts once VS Code has started (activationEvents \"onStartupFinished\")",
    "native": "Ships native programs or libraries, which run with your rights outside JavaScript",
    "process": "Starts other programs (child_process)",
    "eval": "Runs code built from text at run time (eval or new Function)",
    "invisible": "Hidden characters that can carry code (Unicode variation selectors or tags, as in GlassWorm)",
    "bidi": "Characters that reorder text, so code can read differently from how it runs (Trojan Source)",
    "blob": "A long encoded string (base64 or hex), which can hide a payload",
    "installs": "Installs other extensions with itself (extensionDependencies or extensionPack)",
    "identity": "Its files do not agree on what it is (package.json, the folder name or the .vsix manifest)",
    "main-outside": "Its main file is outside its own folder (package.json main leads out with ..), so it is not read",
}

_PROCESS = re.compile(r"\bchild_process\b|\b(?:execSync|spawnSync|execFileSync)\s*\(")
_EVAL = re.compile(r"(?<![\w.$])eval\s*\(|\bnew\s+Function\s*\(")
# Runs of the base64 alphabet (hex is a subset), matched whole so the time is linear; the length is checked in
# code. A data: URI for an image or font is ordinary and not counted.
_RUN = re.compile(r"[A-Za-z0-9+/]+={0,2}")
_DATA_URI = re.compile(r"data:(?:image|font|application/(?:font|x-font)[\w.+-]*)[\w/.+-]*;base64,$")
BLOB_CHARS = 2000
# GlassWorm hid its code in long runs of Unicode variation selectors, which display as nothing. A single one is
# ordinary (emoji, CJK variants), so only runs of four or more count, and tag characters except an emoji flag.
_INVISIBLE = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef\u200b-\u200d\u2060-\u2064]{4,}"
                        "|(?<![\U0001f3f4\U000e0000-\U000e007f])[\U000e0000-\U000e007f]+")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
_URL = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
# publisher.name-1.2.3, with an optional platform: the version is split off at the last "-digit" (names can have
# "-3d" in them).
_FOLDER = re.compile(r"^(?P<id>[^/\\]+\.[^/\\]+)-(?P<version>\d[\w.+]*(?:-[\w.+]+)??)"
                     r"(?:-(?:win32|linux|darwin|alpine|web)-\w+)?$")


# --------------------------------------------------------------------------------------------- what the input is

def _manifest(folder: Path) -> dict | None:
    """An extension's package.json, or None when the folder is not an extension (no publisher or engines.vscode)."""
    p = folder / "package.json"
    try:
        if not p.is_file() or p.stat().st_size > 5_000_000:
            return None
        data = jsonsafe.loads(p.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, RecursionError):  # RecursionError: JSON nested deeper than Python can parse
        return None
    if isinstance(data, dict) and data.get("publisher") and isinstance(data.get("engines"), dict) \
            and data["engines"].get("vscode"):
        return data
    return None


def is_vsix(path: Path) -> bool:
    """A .vsix is a zip with extension/package.json in it, whatever the file is called."""
    try:
        if not path.is_file() or not zipfile.is_zipfile(path):
            return False
        with zipfile.ZipFile(path) as z:
            return "extension/package.json" in z.namelist()
    except (OSError, zipfile.BadZipFile, ValueError, RuntimeError, NotImplementedError, zlib.error, EOFError):
        return False


def extension_folders(path: Path) -> list[Path]:
    """The extensions in a folder: the folder itself if it is one, otherwise the extensions directly inside it
    (as in ~/.vscode/extensions). An extension installed as a link to its folder (as for one being developed) is
    included: it is installed, so it is checked. Empty when there are none."""
    if _manifest(path) is not None:
        return [path]
    try:
        children = sorted(p for p in path.iterdir() if p.is_dir())
    except OSError:
        return []
    return [p for p in children if _manifest(p) is not None]


def is_single(path: Path) -> bool:
    """One extension: a .vsix, or an extension's own folder (not a folder of extensions)."""
    return (path.is_file() and is_vsix(path)) or (path.is_dir() and _manifest(path) is not None)


def is_extension_input(path: Path) -> bool:
    return is_vsix(path) if path.is_file() else bool(path.is_dir() and extension_folders(path))


# --------------------------------------------------------------------------------------------- unpacking

def _member_path(name: str) -> PurePosixPath:
    """The member's path inside the destination, refusing anything that could land outside it on any system, or
    that Windows would read as another name: a drive or colon anywhere, a backslash, a root, '..' or '.', an empty
    part, a part ending in a dot or space, a reserved device name, or a control character."""
    bare = name[:-1] if name.endswith("/") else name
    if (not bare or "\\" in name or ":" in name or name.startswith("/") or any(ord(c) < 32 for c in name)
            or PureWindowsPath(bare).drive or PureWindowsPath(bare).root):
        raise InputError(f"refused: the .vsix has an unsafe file name ({name[:120]!r})")
    parts = bare.split("/")
    for part in parts:
        if part in ("", ".", "..") or part != part.rstrip(". ") or _RESERVED.match(part):
            raise InputError(f"refused: the .vsix has a file name that could leave its folder ({name[:120]!r})")
    return PurePosixPath(*parts)


def _same_name(name: str) -> str:
    """The name as a case-insensitive file system (macOS, Windows) sees it, so two members that would land on
    the same file are caught."""
    return unicodedata.normalize("NFC", name.rstrip("/")).casefold()


_ZIP_ERRORS = (zipfile.BadZipFile, zlib.error, NotImplementedError, RuntimeError, EOFError, ValueError, OSError)


def unpack(vsix: Path, dest: Path) -> Path:
    """Unpack a .vsix into dest with the limits above and return the extension's folder (dest/extension).
    Raises InputError, naming the reason, for a file that breaks a limit; nothing is left half-trusted, since
    the caller removes dest either way."""
    try:
        return _unpack(vsix, dest)
    except InputError:
        raise
    except _ZIP_ERRORS as exc:  # a damaged, encrypted or oddly compressed file is the input's fault: exit 2
        raise InputError(f"refused: {vsix.name} could not be unpacked ({type(exc).__name__}: {exc})") from None


def _unpack(vsix: Path, dest: Path) -> Path:
    z = zipfile.ZipFile(vsix)
    with z:
        infos = z.infolist()
        if len(infos) > MAX_FILES:
            raise InputError(f"refused: {vsix.name} has {len(infos)} files, more than {MAX_FILES}")
        total = 0
        seen: set[str] = set()
        for info in infos:
            rel = _member_path(info.filename)
            key = _same_name(info.filename)
            if key in seen:
                raise InputError(f"refused: {vsix.name} has two files that would be the same file on macOS or "
                                 f"Windows ({info.filename[:120]!r}); which one counts depends on the system")
            seen.add(key)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise InputError(f"refused: {vsix.name} contains a link ({info.filename[:120]})")
            if info.is_dir():
                continue
            if info.file_size > MAX_FILE_BYTES:
                raise InputError(f"refused: {info.filename[:120]} in {vsix.name} is larger than {MAX_FILE_BYTES} bytes")
            if info.compress_size and info.file_size / info.compress_size > MAX_RATIO and info.file_size > 1_000_000:
                raise InputError(f"refused: {info.filename[:120]} in {vsix.name} expands more than {MAX_RATIO} "
                                 "times (a zip bomb?)")
            target = dest.joinpath(*rel.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            # Counted as written too, not only from the zip's directory (zipfile also stops at the stated size).
            with z.open(info) as src, open(target, "wb") as out:
                while chunk := src.read(1 << 20):
                    written += len(chunk)
                    total += len(chunk)
                    if written > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                        raise InputError(f"refused: {vsix.name} unpacks to more than the limit "
                                         f"({MAX_FILE_BYTES} bytes a file, {MAX_TOTAL_BYTES} in all)")
                    out.write(chunk)
        manifest = ""
        if "extension.vsixmanifest" in z.namelist():
            with z.open("extension.vsixmanifest") as fh:
                manifest = fh.read(200_000).decode("utf-8", "replace")
    folder = dest / "extension"
    if _manifest(folder) is None:
        raise InputError(f"{vsix.name} has no extension/package.json with a publisher and engines.vscode")
    # Kept beside the unpacked files under a name of ours, replacing any file of that name the .vsix brought.
    kept = dest / MANIFEST_COPY
    if kept.is_dir() and not kept.is_symlink():
        raise InputError(f"refused: {vsix.name} has a folder named {MANIFEST_COPY}")
    kept.unlink(missing_ok=True)
    if manifest:
        kept.write_text(manifest, encoding="utf-8")
    return folder


# --------------------------------------------------------------------------------------------- reading

def _text(path: Path, budget: list[int]) -> str | None:
    """The file as text, or None when it is over the reading limits (the caller lists it as not read)."""
    try:
        size = path.stat().st_size
        if size > READ_FILE_BYTES or budget[0] <= 0:
            return None
        budget[0] -= size
        return path.read_bytes().decode("utf-8", "replace")
    except OSError:
        return None


class _Lines:
    """Line numbers for positions in one text, in O(log n) each after one pass."""

    def __init__(self, text: str) -> None:
        self._nl = [m.start() for m in re.finditer("\n", text)]

    def __call__(self, index: int) -> int:
        return bisect.bisect_left(self._nl, index) + 1


def _files(folder: Path):
    """Every file under folder, in a stable order, without following links to folders (os.walk's default), so a
    link cannot lead the reading outside the extension."""
    for root, dirs, names in os.walk(folder):
        dirs.sort()
        for n in sorted(names):
            yield Path(root) / n


def _line(text: str, index: int) -> int:
    return text.count("\n", 0, index) + 1


def _identity(data: dict) -> dict:
    repo = data.get("repository")
    if isinstance(repo, dict):
        repo = repo.get("url")
    return {"id": f"{data.get('publisher')}.{data.get('name')}", "publisher": str(data.get("publisher")),
            "name": str(data.get("name")), "version": str(data.get("version") or ""),
            "display_name": str(data.get("displayName") or data.get("name") or ""),
            "repository": str(repo) if repo else "", "engine": str(data["engines"].get("vscode") or "")}


def github_repo(url: str) -> str:
    """owner/name from a repository field that points at GitHub, or ''."""
    m = re.search(r"github\.com[/:]([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]+?)(?:\.git)?/?$", url or "")
    if m:
        return f"{m.group(1)}/{m.group(2)}"
    m = re.fullmatch(r"(?:github:)?([A-Za-z0-9][A-Za-z0-9-]{0,38})/([A-Za-z0-9._-]+)", url or "")
    return f"{m.group(1)}/{m.group(2)}" if m else ""


def _vsix_identity(manifest: Path | None) -> dict | None:
    """Publisher, Id and Version from the .vsix manifest's Identity element (read as text: no XML parser runs on
    untrusted input). Only for an unpacked .vsix, whose copy oss-intake wrote itself."""
    if manifest is None or not manifest.is_file() or manifest.is_symlink():
        return None
    m = re.search(r"<Identity\b([^>]{0,2000})>", manifest.read_text(encoding="utf-8", errors="replace"))
    if not m:
        return None
    attrs = dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
    return {"id": f"{attrs.get('Publisher')}.{attrs.get('Id')}", "version": attrs.get("Version", "")}


def _key(extension_id: str) -> str:
    """An extension ID as the removal list is looked up: case, compatibility forms (full-width letters), spaces
    and invisible format characters do not make a listed extension a different one."""
    text = unicodedata.normalize("NFKC", extension_id)
    return "".join(c for c in text if not c.isspace() and unicodedata.category(c) != "Cf").casefold()


MAX_PACKAGES = 20_000


def _note_package(path: Path, packages: set[tuple[str, str]], budget: list[int]) -> None:
    """The npm package (name, version) a node_modules package.json describes, so findings can be matched to the
    extension that ships it (the scanners do not say where in the folder a package is)."""
    try:
        size = path.stat().st_size
        if size > 1_000_000 or budget[0] <= 0:
            return
        budget[0] -= size
        data = jsonsafe.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, RecursionError):
        return
    if isinstance(data, dict) and isinstance(data.get("name"), str) and isinstance(data.get("version"), str):
        packages.add((data["name"], data["version"]))


# Files that list packages rather than install them: an SBOM or a lockfile shipped inside the extension. Trivy
# reports what they list (Pylance ships SPDX SBOMs of its bundled tools), sometimes with no path.
_LISTING = re.compile(r"(?:\.spdx\.json|\.cdx\.json|(?:^|/)bom\.json|(?:^|/)package-lock\.json|"
                      r"(?:^|/)npm-shrinkwrap\.json|(?:^|/)yarn\.lock|(?:^|/)pnpm-lock\.yaml)$", re.I)
_PACKAGE_JSON = re.compile(r"(?:^|/)node_modules/(?:@[^/]+/)?[^/@][^/]*/package\.json$")


def analyse(folder: Path, budget: list[int] | None = None, manifest: Path | None = None,
            dep_budget: list[int] | None = None) -> dict:
    """One extension: its identity and its indicators, each with the files and lines it was seen in. manifest is
    the copy of a .vsix's own manifest, for an unpacked .vsix only."""
    data = _manifest(folder) or {}
    ident = _identity(data)
    budget = budget if budget is not None else [READ_TOTAL_BYTES]
    # Dependencies have a budget of their own, so a large node_modules in one extension cannot leave another
    # extension's own code unread.
    dep_budget = dep_budget if dep_budget is not None else [READ_TOTAL_BYTES]
    hits: dict[str, list[dict]] = {}
    unread: list[str] = []
    ids = [ident["id"]]

    def add(kind: str, file: str, line: int | None, detail: str) -> bool:
        """Record a hit; False once the indicator has its fill, so the caller stops looking."""
        bucket = hits.setdefault(kind, [])
        if len(bucket) < MAX_HITS:
            bucket.append({"file": file, "line": line, "detail": detail[:200]})
        return len(bucket) < MAX_HITS

    raw = (folder / "package.json").read_text(encoding="utf-8-sig", errors="replace")
    lines = _Lines(raw)
    events = data.get("activationEvents") or []
    for ev, kind in (("*", "activation-all"), ("onStartupFinished", "activation-startup")):
        if isinstance(events, list) and ev in events:
            add(kind, "package.json", lines(max(raw.find(f'"{ev}"'), 0)), f'"{ev}"')
    for key in ("extensionDependencies", "extensionPack"):
        listed = data.get(key)
        if isinstance(listed, list) and listed:
            add("installs", "package.json", lines(max(raw.find(f'"{key}"'), 0)),
                f"{key}: {', '.join(str(x) for x in listed[:10])}")
    # The folder name of an installed extension, and a .vsix's own manifest, must name the same extension. Each
    # name is also looked up in the removal list, so a renamed package.json does not hide a listed extension.
    m = _FOLDER.match(folder.name)
    if m:
        ids.append(m.group("id"))
        if _key(m.group("id")) != _key(ident["id"]) or m.group("version") != ident["version"]:
            add("identity", folder.name, None, f"the folder is named {m.group('id')} {m.group('version')}; "
                                               f"package.json says {ident['id']} {ident['version']}")
    vsix = _vsix_identity(manifest)
    if vsix:
        ids.append(vsix["id"])
        if _key(vsix["id"]) != _key(ident["id"]) or vsix["version"] != ident["version"]:
            add("identity", "extension.vsixmanifest", None, f"the manifest says {vsix['id']} {vsix['version']}; "
                                                            f"package.json says {ident['id']} {ident['version']}")

    given_main = str(data.get("main") or data.get("browser") or "")
    main_name, leaves = _inside(given_main)
    if leaves:
        add("main-outside", "package.json", None, f"main is {given_main!r}, which VS Code loads from outside the "
                                                   "extension's folder; that file is not part of what was assessed")
    main_files = {c.resolve() for c in (folder / main_name, folder / f"{main_name}.js") if main_name and _is_file(c)}
    hosts: set[str] = set()
    packages: set[tuple[str, str]] = set()
    listings: list[str] = []
    dep_files: list[tuple[Path, str]] = []
    files = 0
    for p in _files(folder):
        files += 1
        if files > MAX_FILES:
            unread.append(f"more than {MAX_FILES} files: the rest were not read")
            break
        if p.is_symlink() or not p.is_file():
            continue
        rel = p.relative_to(folder).as_posix()
        is_main = p.resolve() in main_files
        # The packages in the top-level node_modules are the extension's dependencies: the scanners check them,
        # and reading their code for these signals would mostly find ordinary libraries doing ordinary things.
        # A node_modules folder anywhere else is the extension's own code.
        in_deps = rel.startswith("node_modules/") and not is_main
        # A package the scanners can see: a package.json directly in a node_modules package folder, at any depth
        # (Trivy reads them all, so a bundled extension can still ship some packages it sees).
        if _PACKAGE_JSON.search(rel) and len(packages) < MAX_PACKAGES:
            _note_package(p, packages, dep_budget)
        if _LISTING.search(rel) and len(listings) < 100:
            listings.append(rel)
        try:
            with open(p, "rb") as fh:
                head = fh.read(8192)
        except OSError:
            continue
        if p.suffix.lower() in NATIVE_SUFFIXES or head.startswith(NATIVE_MAGIC):
            add("native", rel, None, p.suffix.lower() or "a program")
        if not is_main and (p.suffix.lower() in NOT_READ_SUFFIXES or b"\0" in head):
            continue
        if in_deps:
            dep_files.append((p, rel))  # read after the extension's own files, from the dependency budget
            continue
        text = _text(p, budget)
        if text is None:
            unread.append(rel)
            continue
        where = _Lines(text)
        doc = "" if is_main or p.suffix.lower() not in DOC_SUFFIXES else ", in a documentation file"
        for kind, rx in (("process", _PROCESS), ("eval", _EVAL), ("invisible", _INVISIBLE), ("bidi", _BIDI)):
            for hit in rx.finditer(text):
                detail = f"{len(hit.group(0))} hidden character(s)" if kind in ("invisible", "bidi") else hit.group(0)
                if not add(kind, rel, where(hit.start()), detail + doc):
                    break
        for hit in _RUN.finditer(text):
            run = hit.group(0)
            if len(run) >= BLOB_CHARS and not _DATA_URI.search(text, max(0, hit.start() - 80), hit.start()):
                if not add("blob", rel, where(hit.start()), f"{len(run)} characters"):
                    break
        if len(hosts) < MAX_HOSTS:
            hosts.update(h.lower() for h in _URL.findall(text)[:MAX_HOSTS])

    # Dependencies: the scanners check them for known vulnerabilities and malware, but a package of the extension's
    # own (unknown to any database) could carry hidden code, so hidden characters are looked for there too. The
    # other checks are not: ordinary libraries start programs and use eval.
    for p, rel in dep_files:
        if dep_budget[0] <= 0:
            unread.append("node_modules: the reading limit for dependencies was reached")
            break
        text = _text(p, dep_budget)
        if text is None:
            continue
        where = _Lines(text)
        for kind, rx in (("invisible", _INVISIBLE), ("bidi", _BIDI)):
            for hit in rx.finditer(text):
                if not add(kind, rel, where(hit.start()), f"{len(hit.group(0))} hidden character(s), in a dependency"):
                    break
    # Bundled: a large main file. That hides the dependencies of the extension's own code whatever else it ships,
    # so packages the scanners do see are counted separately and do not change it (a stray package.json could
    # otherwise turn the warning off).
    bundled = bool(main_files) and max(f.stat().st_size for f in main_files) >= BUNDLE_BYTES
    return {**ident, "folder": folder.name, "ids_checked": list(dict.fromkeys(ids)),
            "indicators": [{"id": k, "title": INDICATORS[k], "seen": v} for k, v in hits.items()],
            "hosts": sorted(hosts)[:100], "hosts_total": len(hosts),
            "bundled": bundled, "dependencies_visible": not bundled,
            "not_read": unread[:20], "not_read_total": len(unread),
            "packages": sorted(packages), "listings": listings, "root": str(folder)}


# --------------------------------------------------------------------------------------------- removal list

def parse_removed(text: str) -> dict[str, dict]:
    """The removal list's table: lower-cased extension ID -> {"id", "date", "type"}. Rows that are not a table
    row with an ID of the form publisher.name are skipped."""
    out: dict[str, dict] = {}
    for line in text.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 3 or not re.fullmatch(r"[\w-]+\.[\w.-]+", cells[0]) or cells[0] == "Extension Identifier":
            continue
        entry = {"id": cells[0], "date": cells[1], "type": cells[2]}
        old = out.get(_key(cells[0]))
        if old is None or (is_malicious(entry) and not is_malicious(old)):  # a repeated row: malware wins
            out[_key(cells[0])] = entry
    return out


def is_malicious(entry: dict) -> bool:
    """Removed as Malware or Potentially malicious. Impersonation, Typo-squatting, Untrustworthy and Spam are
    warnings: they are often copycats, not proven malware."""
    t = re.sub(r"\s+", "", entry.get("type", "")).lower()
    return "malware" in t or "malicious" in t


def load_removed(http: Http | None) -> tuple[dict[str, dict] | None, str]:
    """(the removal list, "") or (None, why it was not checked)."""
    if http is None:
        return None, "not checked (--offline)"
    try:
        status, text = http.get_text(REMOVED_URL)
    except HttpError as exc:
        return None, f"not checked: {exc}"
    listed = parse_removed(text) if status == 200 else {}
    if status != 200 or len(listed) < 100:  # the list has thousands of rows: anything else is not the list
        return None, f"not checked: the list could not be read (HTTP {status}, {len(listed)} rows)"
    return listed, ""


# --------------------------------------------------------------------------------------------- the whole input

def assess(target: Path, http: Http | None, staged: bool = False) -> dict:
    """Every extension in target, with the removal list's verdict on each. staged: target is the temporary folder
    a .vsix was unpacked into (inputs.stage), which holds exactly one unpacked .vsix laid out as <name>/extension;
    a folder the user gave is never read that way, so a folder named extension inside it cannot stand in for the
    extension itself."""
    budget, dep_budget = [READ_TOTAL_BYTES], [READ_TOTAL_BYTES]
    if staged:
        (unpacked,) = [p for p in target.iterdir() if p.is_dir()]
        found = [analyse(unpacked / "extension", budget, unpacked / MANIFEST_COPY, dep_budget)]
    else:
        found = [analyse(f, budget, None, dep_budget) for f in extension_folders(target)]
    # VS Code keeps an updated extension's old version on disk until it cleans up, listing it in .obsolete.
    # Only a folder of extensions has one: an extension's own folder could bring a .obsolete naming itself.
    old = _obsolete(target) if not staged and _manifest(target) is None else set()
    for e in found:
        e["in_use"] = e["folder"].casefold() not in old
    removed, why = load_removed(http)
    ovsx = {"status": "not_checked", "detail": "--offline"}
    if http is not None and found:
        from . import openvsx

        ovsx = {"status": "checked", **openvsx.lookup(http, found)}
    for e in found:
        hits = [removed[k] for k in map(_key, e["ids_checked"]) if k in removed] if removed is not None else []
        hit = next((h for h in hits if is_malicious(h)), hits[0] if hits else None)
        e["removed"] = hit
        e["malicious"] = bool(hit and is_malicious(hit))
    return {"extensions": found, "single": staged or _manifest(target) is not None,
            "removed_list": {"status": "checked" if removed is not None else "not_checked", "detail": why,
                             "source": REMOVED_PAGE, "entries": len(removed or {})},
            "open_vsx": ovsx}


def _is_file(p: Path) -> bool:
    """is_file that treats a path the system refuses (a name too long, an invalid one) as missing, so one
    extension's odd manifest cannot stop the assessment of the others."""
    try:
        return p.is_file()
    except (OSError, ValueError):
        return False


def _inside(main: str) -> tuple[str, bool]:
    """package.json's main as a path inside the extension's folder, and whether it leads out of it. VS Code joins
    main to the folder, so an absolute main ("/extension.js") or a drive is read inside it, but ".." is
    followed out: that file is not the extension's to read, so ("", True) is returned and it is reported."""
    import posixpath

    main = re.sub(r"^[A-Za-z]:", "", main.replace("\\", "/")).lstrip("/")
    if not main:
        return "", False
    norm = posixpath.normpath(main)
    if norm == ".." or norm.startswith("../"):
        return "", True
    return ("" if norm == "." else norm), False


def _obsolete(folder: Path) -> set[str]:
    """The folder names VS Code lists in .obsolete (old versions it has not removed yet), case-folded."""
    p = folder / ".obsolete"
    try:
        if not p.is_file() or p.stat().st_size > 1_000_000:
            return set()
        data = jsonsafe.loads(p.read_text(encoding="utf-8-sig"))
    except (OSError, ValueError, RecursionError):
        return set()
    return {str(k).casefold() for k, v in data.items() if v} if isinstance(data, dict) else set()


MAX_LISTED = 200_000
_PNPM_ENTRY = re.compile(r"""(?:^|\s)['"]?/?((?:@[\w.-]+/)?[\w.-]+)@(\d[^:'"()\s]*)""", re.M)


def _yarn_pairs(text: str) -> set[tuple[str, str]]:
    """(name, version) from a yarn.lock, read line by line (a regular expression over several lines can be made to
    backtrack without end): an unindented entry line names the package, its indented version line the version."""
    pairs: set[tuple[str, str]] = set()
    name = ""
    for line in text.splitlines():
        if line and not line[0].isspace() and not line.startswith("#"):
            first = line.split(",")[0].strip().strip('"').rstrip(":").strip('"')
            at = first.find("@", 1)  # a scoped name starts with @, so the version range is after the next one
            name = first[:at] if at > 0 else ""
        elif name and line.strip().startswith("version"):
            version = line.strip()[len("version"):].lstrip(": ").strip().strip('"')
            if version:
                pairs.add((name, version))
                if len(pairs) >= MAX_LISTED:
                    break
            name = ""
    return pairs


def _listed(path: Path, budget: list[int]) -> set[tuple[str, str]] | None:
    """The (name, version) pairs an SBOM or lockfile lists, read once; None when it could not be read. JSON is
    walked for objects with a name and a version (SPDX 2 and 3, CycloneDX, package-lock keys); yarn and pnpm
    locks are read with linear-time patterns."""
    text = _text(path, budget)
    if text is None:
        return None
    pairs: set[tuple[str, str]] = set()
    if path.name.endswith((".lock", ".yaml")):
        if path.name.endswith(".lock"):
            return _yarn_pairs(text)
        for m in _PNPM_ENTRY.finditer(text):
            pairs.add((m.group(1), m.group(2)))
            if len(pairs) >= MAX_LISTED:
                break
        return pairs
    try:
        data = jsonsafe.loads(text)
    except (ValueError, RecursionError):
        return set()
    stack = [data]
    while stack and len(pairs) < MAX_LISTED:
        node = stack.pop()
        if isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, dict):
            name = node.get("name")
            version = node.get("version") or node.get("versionInfo") or node.get("software_packageVersion")
            if isinstance(name, str) and isinstance(version, str):
                pairs.add((name, version))
                if isinstance(node.get("group"), str) and node["group"]:  # CycloneDX: group "@scope", name "x"
                    pairs.add((f"{node['group']}/{name}", version))
            for key, value in node.items():
                if len(pairs) >= MAX_LISTED:
                    break
                if isinstance(value, dict) and isinstance(value.get("version"), str) and isinstance(key, str):
                    pairs.add((key.rsplit("node_modules/", 1)[-1], value["version"]))  # package-lock keys
                if isinstance(value, (dict, list)):
                    stack.append(value)
    return pairs


def attribute(info: dict, findings: list) -> None:
    """Match each finding to the extensions that ship its package: npm packages by the name and version found in
    each extension's node_modules, anything else by a target path that starts with the extension's folder.
    Sets "findings" on each extension and "unmatched" on info. A package several extensions ship counts for each."""
    by_package: dict[tuple[str, str], list[dict]] = {}
    for e in info["extensions"]:
        e["findings"] = {"total": 0, "critical": 0, "high": 0, "malicious": 0}
        e["findings_listed"] = 0  # of those, found only in an SBOM or lockfile it ships
        e["packages_seen"] = len(e.get("packages", []))
        for pkg in e.pop("packages", []):
            by_package.setdefault(tuple(pkg), []).append(e)
    by_folder = {e["folder"].casefold(): e for e in info["extensions"]}
    # Each shipped SBOM or lockfile is read once into the package versions it lists.
    budget = [READ_TOTAL_BYTES]
    by_listing: dict[tuple[str, str], list[dict]] = {}
    not_read = 0
    for e in info["extensions"]:
        root = Path(e.pop("root", ""))
        for rel in e.pop("listings", []):
            pairs = _listed(root / rel, budget)
            if pairs is None:
                not_read += 1
                continue
            for pair in pairs:
                owners_of = by_listing.setdefault(pair, [])
                if not any(x is e for x in owners_of):
                    owners_of.append(e)
    # A .vsix or one extension's folder: everything scanned is that extension's (Trivy's paths there do not start
    # with its folder name). Not for a folder of extensions, where other folders may hold other things.
    only = info["extensions"][0] if info.get("single") and len(info["extensions"]) == 1 else None
    unmatched = 0
    for f in findings:
        owners = list(by_package.get((f.package, f.installed), [])) if (f.purl or "").startswith("pkg:npm/") \
            or f.pkg_type in ("node-pkg", "npm") else []
        for t in (f.target or "").split(";"):
            # Trivy's paths start at the extension's folder; Grype's start with "/".
            e = by_folder.get(t.replace("\\", "/").lstrip("/").split("/")[0].casefold())
            if e is not None and not any(x is e for x in owners):
                owners.append(e)
        listed = False
        if not owners:
            # Not installed anywhere on disk: an SBOM or lockfile the extension ships may list it.
            owners = list(by_listing.get((f.package, f.installed), []))
            listed = bool(owners)
        if not owners and only is not None:
            owners = [only]  # one extension: everything scanned is its own (a .vsix's paths start elsewhere)
        if not owners:
            unmatched += 1
        for e in owners:
            e["findings_listed"] += listed
            n = e["findings"]
            n["total"] += 1
            n["critical"] += f.severity == "CRITICAL"
            n["high"] += f.severity == "HIGH"
            n["malicious"] += bool(f.malicious)
    info["unmatched"] = unmatched
    info["listings_not_read"] = not_read


def compare(old: dict, new: dict) -> dict:
    """What an update changed: most extension compromises arrive as an update to one people already trust. old and
    new are analyse() results for two versions of one extension. Lists what the new version adds (indicators,
    native files, web addresses, npm packages) and drops, and whether its publisher, name or repository changed."""
    def kinds(e: dict) -> dict[str, dict]:
        return {i["id"]: i for i in e["indicators"]}

    def native(e: dict) -> set[str]:
        return {s["file"] for i in e["indicators"] if i["id"] == "native" for s in i["seen"]}

    ok, nk = kinds(old), kinds(new)
    added = [{"id": k, "title": nk[k]["title"], "seen": nk[k]["seen"][:3]} for k in nk if k not in ok]
    grew = [{"id": k, "title": nk[k]["title"], "from": len(ok[k]["seen"]), "to": len(nk[k]["seen"])}
            for k in nk if k in ok and len(nk[k]["seen"]) > len(ok[k]["seen"])]
    old_hosts, new_hosts = set(old["hosts"]), set(new["hosts"])
    old_pkgs, new_pkgs = {tuple(p) for p in old["packages"]}, {tuple(p) for p in new["packages"]}
    old_names = {p[0] for p in old_pkgs}
    return {
        "from_version": old["version"], "to_version": new["version"],
        "same_extension": _key(old["id"]) == _key(new["id"]),
        "publisher_changed": old["publisher"] != new["publisher"],
        "repository_changed": old["repository"] != new["repository"],
        "repository_from": old["repository"], "repository_to": new["repository"],
        "indicators_added": added, "indicators_grew": grew,
        "indicators_dropped": [ok[k]["title"] for k in ok if k not in nk],
        "native_added": sorted(native(new) - native(old))[:50],
        # The hosts are read up to MAX_HOSTS per extension and kept up to 100: a host missing from a capped list
        # is not new, so only a full list on both sides says so.
        "hosts_added": sorted(new_hosts - old_hosts)[:100] if old["hosts_total"] <= 100 else [],
        "hosts_not_compared": old["hosts_total"] > 100,
        "packages_added": sorted(p[0] for p in new_pkgs - old_pkgs if p[0] not in old_names)[:200],
        "packages_changed": sorted(f"{n} {v}" for n, v in new_pkgs - old_pkgs if n in old_names)[:200],
        "bundled_from": old["bundled"], "bundled_to": new["bundled"],
    }


def change_warnings(diff: dict, ext_id: str) -> list[str]:
    """Warnings for what an update adds that is worth a person's look."""
    out = []
    if not diff["same_extension"]:
        out.append(f"--compare-with names a different extension than {ext_id}: the comparison may mean little")
    if diff["publisher_changed"] or diff["repository_changed"]:
        what = " and ".join(x for x, c in (("publisher", diff["publisher_changed"]),
                                          ("repository", diff["repository_changed"])) if c)
        out.append(f"{ext_id} {diff['to_version']} changes its {what} since {diff['from_version']}: check who "
                   "publishes it now before you take the update")
    adds = [i["title"].split(" (")[0] for i in diff["indicators_added"]]
    if diff["native_added"]:
        adds.append(f"{len(diff['native_added'])} new native file(s)")
    if diff["hosts_added"]:
        adds.append(f"{len(diff['hosts_added'])} new web address(es)")
    if adds:
        out.append(f"{ext_id} {diff['to_version']} adds since {diff['from_version']}: {'; '.join(adds)}. Read "
                   "what changed before you take the update")
    return out


def warnings(info: dict) -> tuple[list[str], list[str]]:
    """(alerts for the top of the report, ordinary warnings)."""
    alerts, other = [], []
    for e in info["extensions"]:
        hit = e.get("removed")
        if hit and e["malicious"]:
            alerts.append(f"EXTENSION REMOVED FROM THE VS CODE MARKETPLACE AS {hit['type'].upper()}: {e['id']} "
                          f"{e['version']} (removed {hit['date']}). Uninstall it everywhere and treat machines "
                          "that ran it as compromised")
        elif hit:
            other.append(f"{e['id']} {e['version']} was removed from the VS Code Marketplace for {hit['type']} "
                         f"({hit['date']}). It may be a copy of another extension: check who publishes it before you "
                         "keep it")
        if e["bundled"] and e.get("in_use", True):
            other.append(f"{e['id']} {e['version']} bundles its code into one file, so the scanners cannot see its "
                         "dependencies: no findings for it does not mean it has none")
    rl = info["removed_list"]
    if rl["status"] != "checked":
        other.append(f"The VS Code Marketplace removal list was {rl['detail']}, so no extension was checked "
                     "against it")
    return alerts, other
