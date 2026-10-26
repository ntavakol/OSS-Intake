"""govulncheck adapter (opt-in, --reachability): is the vulnerable Go code actually in the binary?

Go's official govulncheck, in binary mode, reads a compiled Go binary's symbol table and reports, for each
Go vulnerability affecting the modules inside it, the deepest level it can confirm:
  3  a vulnerable function is linked into the binary (the code is present and can be called)
  2  a vulnerable package is present, but none of the vulnerable functions are
  1  only the module is present
A vulnerability that govulncheck lists for the binary but confirms below level 3 is evidence that the
vulnerable code is not in that binary. A CVE govulncheck does not mention at all is not evidence either way.

govulncheck is an external executable (golang.org/x/vuln/cmd/govulncheck); it is never bundled. It needs the
Go vulnerability database (vuln.go.dev) over the network.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path

from . import ScannerError, run

NAME = "govulncheck"


def find(explicit: str | None) -> str:
    path = explicit or shutil.which("govulncheck")
    if not path or not Path(path).is_file():
        raise ScannerError("govulncheck not found; install it with "
                           "'go install golang.org/x/vuln/cmd/govulncheck@v1.1.4' or pass --govulncheck-path")
    return path


def version_info(binary: str) -> dict:
    text = run([binary, "-version"], 60).decode("utf-8", "replace")
    m = re.search(r"govulncheck@v?([\w.\-]+)", text)
    db = re.search(r"DB updated:\s*(\S+)", text)
    return {"version": m.group(1) if m else "unknown", "db_updated": db.group(1) if db else None}


def parse_stream(text: str) -> list[dict]:
    """govulncheck -format json writes a stream of (indented) JSON objects, not one document."""
    dec = json.JSONDecoder()
    out, i = [], 0
    while i < len(text):
        while i < len(text) and text[i].isspace():
            i += 1
        if i >= len(text):
            break
        obj, i = dec.raw_decode(text, i)
        out.append(obj)
    return out


def analyse(messages: list[dict]) -> dict[str, dict]:
    """Return {CVE or GO ID: {"level": 0..3, "go_id": ...}} for every vulnerability govulncheck listed."""
    aliases: dict[str, set[str]] = {}
    level: dict[str, int] = {}
    for m in messages:
        osv = m.get("osv")
        if isinstance(osv, dict) and osv.get("id"):
            aliases[osv["id"]] = {a.upper() for a in osv.get("aliases") or []}
            level.setdefault(osv["id"], 0)
        f = m.get("finding")
        if isinstance(f, dict) and f.get("osv"):
            trace = f.get("trace") or [{}]
            top = trace[0] or {}
            lvl = 3 if top.get("function") else 2 if top.get("package") else 1
            level[f["osv"]] = max(level.get(f["osv"], 0), lvl)
    out: dict[str, dict] = {}
    for go_id, lvl in level.items():
        for key in {go_id.upper(), *aliases.get(go_id, set())}:
            if key not in out or lvl > out[key]["level"]:
                out[key] = {"level": lvl, "go_id": go_id}
    return out


def scan_binary(binary: str, target: Path, timeout: int) -> dict[str, dict]:
    raw = run([binary, "-mode=binary", "-format", "json", str(target)], timeout)
    return analyse(parse_stream(raw.decode("utf-8", "replace")))


def safe_relpath(p: str) -> bool:
    """Paths come from the scanned image; never let one point outside the extraction folder."""
    parts = Path(p.lstrip("/")).parts
    return bool(parts) and ".." not in parts and not Path(p.lstrip("/")).is_absolute()


def extract_from_image(image: str, paths: list[str], platform: str | None, dest: Path, timeout: int,
                       used: dict | None = None) -> list[str]:
    """Copy files out of an image with Docker (create + cp) or, failing that, crane export.
    Returns the paths copied, relative to dest. Raises ScannerError when neither tool is available.
    used, when given, records which tool ran and its path, for the report."""
    wanted = [p.lstrip("/") for p in paths if safe_relpath(p)]
    docker = shutil.which("docker")
    if docker:
        if used is not None:
            used.update(tool="docker", path=docker)
        cmd = [docker, "create"] + (["--platform", platform] if platform else []) + [image, "/nonexistent"]
        cid = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if cid.returncode == 0:
            container = cid.stdout.strip()
            copied = []
            try:
                for p in wanted:
                    (dest / p).parent.mkdir(parents=True, exist_ok=True)
                    r = subprocess.run([docker, "cp", f"{container}:/{p}", str(dest / p)], capture_output=True,
                                       timeout=timeout)
                    if r.returncode == 0:
                        copied.append(p)
            finally:
                subprocess.run([docker, "rm", container], capture_output=True, timeout=60)
            return copied
    crane = shutil.which("crane")
    if crane:
        if used is not None:
            used.update(tool="crane", path=crane)
        with tempfile.TemporaryDirectory() as td:
            tar_path = Path(td) / "fs.tar"
            cmd = [crane, "export"] + (["--platform", platform] if platform else []) + [image, str(tar_path)]
            run(cmd, timeout)
            copied = []
            with tarfile.open(tar_path) as tar:
                for member in tar.getmembers():
                    name = member.name.lstrip("./")
                    if name in wanted and member.isfile():
                        out = dest / name
                        out.parent.mkdir(parents=True, exist_ok=True)
                        src = tar.extractfile(member)
                        if src:
                            out.write_bytes(src.read())
                            copied.append(name)
            return copied
    raise ScannerError("--reachability on an image needs Docker or crane to copy the Go binaries out of it")
