"""Scanner adapters. External scanners are invoked as separate executables; none are bundled."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

# Docker or containerd failing to export a locally stored image (pruned layers, other-platform pulls).
LOCAL_IMAGE_ERROR = re.compile(r"unable to export the image|content digest sha256:[0-9a-f]+: not found|"
                               r"unable to inspect the image", re.IGNORECASE)


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
        msg = f"{Path(cmd[0]).name} exited {proc.returncode}: " + " | ".join(tail)
        if LOCAL_IMAGE_ERROR.search(err):
            msg += (" (the local container engine could not export the image; rerun with --image-src remote to pull "
                    "it from the registry, or remove and re-pull the local copy)")
        raise ScannerError(msg)
    return proc.stdout


def load_json_bytes(data: bytes, what: str) -> dict:
    # Windows PowerShell 5.1 redirection (trivy ... > out.json) writes UTF-16 with a byte order mark.
    encoding = "utf-16" if data[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
    try:
        return json.loads(data.decode(encoding))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ScannerError(f"{what} is not valid JSON: {exc}") from None


def report_kind(data: object) -> str:
    """'trivy', 'grype' or 'unknown', from the shape of a JSON report."""
    if not isinstance(data, dict):
        return "unknown"
    if "SchemaVersion" in data and isinstance(data.get("Results", []), list) and "matches" not in data:
        return "trivy"
    name = (data.get("descriptor") or {}).get("name") if isinstance(data.get("descriptor"), dict) else None
    if "SchemaVersion" not in data and "matches" in data and name in (None, "grype"):
        # Grype writes [] for a clean scan; very old releases wrote null, which only counts with Grype's descriptor.
        if isinstance(data["matches"], list) or (data["matches"] is None and name == "grype"):
            return "grype"
    if data.get("bomFormat") == "CycloneDX" or "spdxVersion" in data:
        return "sbom"
    return "unknown"


def check_report(data: object, tool: str, what: str) -> None:
    """Refuse a report that is not the tool's JSON, so a wrong or empty file never reads as 'no findings'."""
    kind = report_kind(data)
    if kind == tool:
        return
    looks = {"trivy": "a Trivy report", "grype": "a Grype report",
             "sbom": "an SBOM (CycloneDX or SPDX), which lists packages but not vulnerabilities"}.get(kind)
    expected = {"trivy": "a Trivy JSON report (trivy ... --format json), with SchemaVersion and Results",
                "grype": "a Grype JSON report (grype ... -o json), with matches"}[tool]
    raise ReportShapeError(f"{what} is not {expected}" + (f"; it looks like {looks}" if looks else
                                                         "; it has neither shape"))


class ReportShapeError(ValueError):
    pass
