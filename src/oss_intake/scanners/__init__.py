"""Scanner adapters. External scanners are invoked as separate executables; none are bundled."""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path

from .. import jsonsafe

# Docker or containerd failing to export a locally stored image (pruned layers, other-platform pulls).
LOCAL_IMAGE_ERROR = re.compile(r"unable to export the image|content digest sha256:[0-9a-f]+: not found|"
                               r"unable to inspect the image", re.IGNORECASE)


class ScannerError(Exception):
    """Raised when a scanner cannot be run, fails or times out, or its output is not valid JSON."""
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


def path_arg(path: str | Path) -> str:
    """A path as a scanner argument: one starting with '-' (a folder named '-x', or '--config=...') would be read
    as an option, so it is given as './-x'. Absolute paths and others are unchanged."""
    s = str(path)
    return os.path.join(".", s) if s.startswith("-") else s


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
    """Parse JSON bytes that may be UTF-16 with a BOM (PowerShell 5.1 redirection) or UTF-8 with or without a BOM.
    Raises ScannerError naming what if it is not valid JSON."""
    # Windows PowerShell 5.1 redirection (trivy ... > out.json) writes UTF-16 with a byte order mark.
    encoding = "utf-16" if data[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8-sig"
    try:
        return jsonsafe.loads(data.decode(encoding))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ScannerError(f"{what} is not valid JSON: {exc or 'nested too deeply'}") from None


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
    if kind == tool and isinstance(data, dict):
        problem = _shape_problem(data, tool)
        if problem:
            raise ReportShapeError(f"{what} is not a well-formed {tool.capitalize()} report: {problem}")
        # A report that names nothing it scanned and lists nothing is a truncated or hand-made file, not a clean
        # scan: Trivy always writes ArtifactName and Grype its descriptor and source, even when they find nothing.
        named = data.get("ArtifactName") if tool == "trivy" else (data.get("descriptor") or data.get("source"))
        listed = data.get("Results") if tool == "trivy" else data.get("matches")
        if not named and not listed:
            raise ReportShapeError(f"{what} names nothing it scanned and lists nothing (no "
                                   + ("ArtifactName or Results" if tool == "trivy" else "descriptor, source or matches")
                                   + "), so it is not a scan's report and cannot read as clean")
        return
    looks = {"trivy": "a Trivy report", "grype": "a Grype report",
             "sbom": "an SBOM (CycloneDX or SPDX), which lists packages but not vulnerabilities"}.get(kind)
    expected = {"trivy": "a Trivy JSON report (trivy ... --format json), with SchemaVersion and Results",
                "grype": "a Grype JSON report (grype ... -o json), with matches"}[tool]
    raise ReportShapeError(f"{what} is not {expected}" + (f"; it looks like {looks}" if looks else
                                                         "; it has neither shape"))


_STR_FIELDS = {
    "trivy_result": ("Target", "Type", "Class"),
    "trivy_vuln": ("VulnerabilityID", "PkgID", "PkgName", "PkgPath", "InstalledVersion", "FixedVersion", "Severity",
                   "SeveritySource", "PublishedDate", "LastModifiedDate", "Title", "Description", "PrimaryURL"),
    "trivy_pkg": ("ID", "Name", "Version", "SrcName", "SrcVersion", "SrcRelease"),
    "grype_artifact": ("name", "version", "type", "purl"),
    "grype_vuln": ("id", "severity", "namespace", "dataSource", "description"),
}
# Lists of text and objects the readers iterate.
_STR_LISTS = {"trivy_vuln": ("CweIDs", "VendorIDs", "References"), "grype_vuln": ("urls",),
              "grype_artifact": ("cpes",)}
_OBJECTS = {"trivy_vuln": ("PkgIdentifier", "CVSS", "DataSource", "VendorSeverity"), "trivy_pkg": ("Identifier",),
            "grype_vuln": ("fix",), "grype_artifact": ("metadata",)}


def _bad_fields(obj: dict, kind: str) -> str | None:
    for k in _STR_FIELDS[kind]:
        if obj.get(k) is not None and not isinstance(obj[k], str):
            return k
    for k in _STR_LISTS.get(kind, ()):
        v = obj.get(k)
        if v is not None and not (isinstance(v, list) and all(isinstance(e, str) for e in v)):
            return k
    for k in _OBJECTS.get(kind, ()):
        if obj.get(k) is not None and not isinstance(obj[k], dict):
            return k
    for k in ("PkgIdentifier", "Identifier"):
        if isinstance(obj.get(k), dict) and not all(isinstance(obj[k].get(f) or "", str) for f in ("PURL", "UID")):
            return f"{k}.PURL"
    if kind == "grype_vuln" and isinstance(obj.get("fix"), dict):
        fix = obj["fix"]
        if not (isinstance(fix.get("state") or "", str) and isinstance(fix.get("versions") or [], list)
                and all(isinstance(e, str) for e in fix.get("versions") or [])):
            return "fix"
    return None


def _shape_problem(data: dict, tool: str) -> str | None:
    """The first place a report of the right kind has a value of the wrong type, as the fields oss-intake reads
    (here and after parsing) expect; None when it is well formed. Deeper oddities are caught when parsing."""
    def lists(obj: dict, key: str) -> list | None:
        v = obj.get(key)
        return [] if v is None else v if isinstance(v, list) and all(isinstance(e, dict) for e in v) else None

    if tool == "trivy":
        if not isinstance(data.get("Metadata", {}) or {}, dict):
            return "Metadata is not an object"
        results = lists(data, "Results")
        if results is None:
            return "Results must be a list of objects"
        for n, r in enumerate(results, 1):
            if (k := _bad_fields(r, "trivy_result")) is not None:
                return f"result {n}: {k} is not text"
            for key, kind in (("Vulnerabilities", "trivy_vuln"), ("Packages", "trivy_pkg")):
                entries = lists(r, key)
                if entries is None:
                    return f"result {n}: {key} must be a list of objects"
                for m, e in enumerate(entries, 1):
                    if (k := _bad_fields(e, kind)) is not None:
                        return f"result {n}, {key} entry {m}: {k} is not of the right type"
        return None
    matches = lists(data, "matches")
    if matches is None:
        return "matches must be a list of objects"
    for key in ("descriptor", "distro", "source"):
        if not isinstance(data.get(key) or {}, dict):
            return f"{key} is not an object"
    for n, m in enumerate(matches, 1):
        for key, kind in (("artifact", "grype_artifact"), ("vulnerability", "grype_vuln")):
            obj = m.get(key) or {}
            if not isinstance(obj, dict):
                return f"match {n}: {key} is not an object"
            if (k := _bad_fields(obj, kind)) is not None:
                return f"match {n}: {key}.{k} is not of the right type"
        if lists(m, "relatedVulnerabilities") is None:
            return f"match {n}: relatedVulnerabilities must be a list of objects"
        locations = lists(m.get("artifact") or {}, "locations")
        if locations is None or not all(isinstance(loc.get("path") or "", str) for loc in locations):
            return f"match {n}: artifact.locations must be a list of objects with a text path"
    return None


class ReportShapeError(ValueError):
    """Raised when a JSON report is not the expected Trivy or Grype shape; the message says what it looks like."""
    pass
