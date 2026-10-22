"""Scanner adapters. External scanners are invoked as separate executables; none are bundled."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path


class ScannerError(Exception):
    pass


def find_executable(name: str, explicit: str | None = None) -> str:
    """Resolve a scanner binary. An explicit path wins; otherwise PATH (handles .exe on Windows)."""
    if explicit:
        p = Path(explicit).expanduser()
        if not p.is_file():
            raise ScannerError(f"{name} not found at {p}")
        return str(p.resolve())
    found = shutil.which(name)
    if not found:
        raise ScannerError(
            f"{name} not found on PATH. Install a pinned, checksum-verified release or pass --{name}-path."
        )
    return found


def run(cmd: list[str], timeout: int) -> bytes:
    """Run a command without a shell and return stdout bytes. Raises ScannerError on failure."""
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        raise ScannerError(f"{Path(cmd[0]).name} timed out after {timeout}s") from None
    except OSError as exc:
        raise ScannerError(f"could not run {Path(cmd[0]).name}: {exc}") from None
    if proc.returncode != 0:
        err = proc.stderr.decode("utf-8", errors="replace").strip()
        if not err:
            err = proc.stdout.decode("utf-8", errors="replace").strip() or "(no output; rerun the scanner by hand)"
        tail = err.splitlines()[-5:]
        raise ScannerError(f"{Path(cmd[0]).name} exited {proc.returncode}: " + " | ".join(tail))
    return proc.stdout


def load_json_bytes(data: bytes, what: str) -> dict:
    try:
        return json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScannerError(f"{what} output is not valid JSON: {exc}") from None
