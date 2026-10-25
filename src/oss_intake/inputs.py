"""Assess an artifact or a lockfile directly, without a container image (--path).

Kinds, decided from the path:
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

LOCKFILES = re.compile(
    r"^(requirements[\w.-]*\.txt|poetry\.lock|Pipfile\.lock|uv\.lock|pdm\.lock|package-lock\.json|"
    r"npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|pom\.xml|gradle\.lockfile|go\.mod|go\.sum|Cargo\.lock|"
    r"composer\.lock|Gemfile\.lock|packages\.lock\.json|\w[\w.-]*\.deps\.json)$")


_NAME_VERSION = re.compile(r"(?<![\d.])v?(\d+\.\d+(?:\.\d+){0,2})(?![\d])")


def version_from_name(path: Path) -> str | None:
    """'shinyproxy-3.2.4-exec.jar' -> '3.2.4', tried against the project's release tags like an image tag."""
    m = _NAME_VERSION.search(path.name)
    return m.group(1) if m else None


class InputError(Exception):
    pass


def classify(path: Path) -> str:
    if path.is_dir():
        return "dir"
    if path.name == "renv.lock":
        return "renv"
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
    shutil.copy2(path, tmp / path.name)
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
