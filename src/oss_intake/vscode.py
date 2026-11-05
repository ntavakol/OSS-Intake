"""VS Code extensions: a .vsix file, an installed extension's folder, or a folder of installed extensions
(~/.vscode/extensions, and the same layout in Cursor and VSCodium).

There is no vulnerability database for extensions, so an extension is assessed on what can be known about it:
- whether the VS Code Marketplace removed it, and why (Microsoft's RemovedPackages list);
- the npm packages it ships, which the scanners and OSV check like any other (cli.py does that part);
- behaviour indicators found by reading its files: what it can do, not a verdict on whether it does harm;
- whether its code is bundled, which hides its dependencies from the scanners.

Nothing in an extension is run. A .vsix is untrusted input from the internet: it is unpacked with fixed limits on
the number of files, their sizes and how far they expand, and with no absolute paths, no '..', and no links.
"""

from __future__ import annotations

import bisect
import json
import os
import re
import stat
import unicodedata
import zipfile
import zlib
from pathlib import Path, PurePosixPath, PureWindowsPath

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
NATIVE_SUFFIXES = {".node", ".exe", ".dll", ".so", ".dylib", ".wasm"}
NATIVE_MAGIC = (b"MZ", b"\x7fELF", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
                b"\0asm")
MAX_HOSTS = 1000
_RESERVED = re.compile(r"^(con|prn|aux|nul|com[0-9]|lpt[0-9])(\..*)?$", re.I)
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
        data = json.loads(p.read_text(encoding="utf-8-sig"))
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


def _has_dependencies(folder: Path) -> bool:
    """A real node_modules folder with at least one package in it (an empty or linked one shows nothing)."""
    nm = folder / "node_modules"
    if not nm.is_dir() or nm.is_symlink():
        return False
    return any(nm.glob("*/package.json")) or any(nm.glob("@*/*/package.json"))


def analyse(folder: Path, budget: list[int] | None = None, manifest: Path | None = None) -> dict:
    """One extension: its identity and its indicators, each with the files and lines it was seen in. manifest is
    the copy of a .vsix's own manifest, for an unpacked .vsix only."""
    data = _manifest(folder) or {}
    ident = _identity(data)
    budget = budget if budget is not None else [READ_TOTAL_BYTES]
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

    main_name = str(data.get("main") or data.get("browser") or "")
    main_files = {c.resolve() for c in (folder / main_name, folder / f"{main_name}.js") if main_name and c.is_file()}
    hosts: set[str] = set()
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
        try:
            with open(p, "rb") as fh:
                head = fh.read(8192)
        except OSError:
            continue
        if p.suffix.lower() in NATIVE_SUFFIXES or head.startswith(NATIVE_MAGIC):
            add("native", rel, None, p.suffix.lower() or "a program")
        if in_deps or (not is_main and (p.suffix.lower() in NOT_READ_SUFFIXES or b"\0" in head)):
            continue
        text = _text(p, budget)
        if text is None:
            unread.append(rel)
            continue
        where = _Lines(text)
        for kind, rx in (("process", _PROCESS), ("eval", _EVAL), ("invisible", _INVISIBLE), ("bidi", _BIDI)):
            for hit in rx.finditer(text):
                detail = f"{len(hit.group(0))} hidden character(s)" if kind in ("invisible", "bidi") else hit.group(0)
                if not add(kind, rel, where(hit.start()), detail):
                    break
        for hit in _RUN.finditer(text):
            run = hit.group(0)
            if len(run) >= BLOB_CHARS and not _DATA_URI.search(text, max(0, hit.start() - 80), hit.start()):
                if not add("blob", rel, where(hit.start()), f"{len(run)} characters"):
                    break
        if len(hosts) < MAX_HOSTS:
            hosts.update(h.lower() for h in _URL.findall(text)[:MAX_HOSTS])

    bundled = bool(main_files) and not _has_dependencies(folder) and \
        max(f.stat().st_size for f in main_files) >= BUNDLE_BYTES
    return {**ident, "folder": folder.name, "ids_checked": list(dict.fromkeys(ids)),
            "indicators": [{"id": k, "title": INDICATORS[k], "seen": v} for k, v in hits.items()],
            "hosts": sorted(hosts)[:100], "hosts_total": len(hosts),
            "bundled": bundled, "dependencies_visible": not bundled,
            "not_read": unread[:20], "not_read_total": len(unread)}


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
    budget = [READ_TOTAL_BYTES]
    if staged:
        (unpacked,) = [p for p in target.iterdir() if p.is_dir()]
        found = [analyse(unpacked / "extension", budget, unpacked / MANIFEST_COPY)]
    else:
        found = [analyse(f, budget) for f in extension_folders(target)]
    removed, why = load_removed(http)
    for e in found:
        hits = [removed[k] for k in map(_key, e["ids_checked"]) if k in removed] if removed is not None else []
        hit = next((h for h in hits if is_malicious(h)), hits[0] if hits else None)
        e["removed"] = hit
        e["malicious"] = bool(hit and is_malicious(hit))
    return {"extensions": found,
            "removed_list": {"status": "checked" if removed is not None else "not_checked", "detail": why,
                             "source": REMOVED_PAGE, "entries": len(removed or {})}}


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
            other.append(f"{e['id']} was removed from the VS Code Marketplace for {hit['type']} ({hit['date']}). "
                         "It may be a copy of another extension: check who publishes it before you keep it")
        if e["bundled"]:
            other.append(f"{e['id']} bundles its code into one file, so the scanners cannot see its dependencies: "
                         "no findings for it does not mean it has none")
    rl = info["removed_list"]
    if rl["status"] != "checked":
        other.append(f"The VS Code Marketplace removal list was {rl['detail']}, so no extension was checked "
                     "against it")
    return alerts, other
