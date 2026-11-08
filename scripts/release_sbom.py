#!/usr/bin/env python3
"""Write a CycloneDX SBOM of an installed oss-intake and the runtime dependencies it pulled in.

The release workflow installs the built wheel and the hash-pinned runtime requirements into a fresh virtual
environment, then runs this script with that environment's Python:

    .venv-sbom/bin/python scripts/release_sbom.py --wheel dist/oss_intake-0.18.0-py3-none-any.whl \\
        --out sbom/oss-intake-0.18.0.cdx.json

The SBOM lists what the release was built and tested with: oss-intake (the subject, with the wheel's SHA-256)
and every distribution its requirements reach in that environment, walked through each package's Requires-Dist.
Optional extras (`extra == ...`) are left out, and so is any requirement that is not installed (one whose
environment marker did not apply). Markers are not evaluated beyond that, and extras a parent asks for
(`requests[socks]`) are not followed: enough for oss-intake, which has no extras, in an environment that holds only
the pinned runtime requirements. Users who resolve the dependency ranges later may get newer versions.
Standard library only, so it runs in the environment it describes without adding anything to it.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata as md
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

SPEC = "1.6"
ROOT = "oss-intake"
_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")
# Common SPDX licence IDs, written as `license.id` so tools resolve them; anything else stays free text (`name`).
SPDX_IDS = {"0BSD", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "LGPL-2.1-or-later", "LGPL-3.0-or-later",
            "MIT", "MPL-2.0", "PSF-2.0", "Python-2.0", "Unlicense"}


def canonical(name: str) -> str:
    """PEP 503 name: lower case, runs of '-', '_' and '.' as one '-'."""
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_names(dist: md.Distribution) -> list[str]:
    """Names of the distribution's requirements that are not behind an optional extra."""
    out = []
    for req in dist.requires or []:
        _, _, marker = req.partition(";")
        if "extra" in marker and re.search(r"\bextra\s*==", marker):
            continue
        m = _NAME.match(req)
        if m:
            out.append(canonical(m.group(1)))
    return out


def _installed() -> dict[str, md.Distribution]:
    found: dict[str, md.Distribution] = {}
    for dist in md.distributions():
        name = _field(dist, "Name")
        if name:
            found.setdefault(canonical(name), dist)
    return found


def _field(dist: md.Distribution, key: str) -> str:
    """A metadata field, or "" (get_all: a missing key is not an error on any supported Python)."""
    return (dist.metadata.get_all(key) or [""])[0]


def _licence(dist: md.Distribution) -> list[dict]:
    expr = _field(dist, "License-Expression")
    if expr:
        return [{"expression": expr}]
    text = _field(dist, "License").strip()
    if text in SPDX_IDS:
        return [{"license": {"id": text}}]
    if text and "\n" not in text and len(text) <= 100:
        return [{"license": {"name": text}}]
    classifiers = [c.split("::")[-1].strip() for c in dist.metadata.get_all("Classifier") or []
                   if c.startswith("License ::")]
    return [{"license": {"name": c}} for c in classifiers]


def _component(dist: md.Distribution) -> dict:
    name, version = canonical(_field(dist, "Name")), dist.version
    comp: dict = {"type": "library", "bom-ref": f"pkg:pypi/{name}@{version}", "name": name, "version": version,
                  "purl": f"pkg:pypi/{name}@{version}"}
    licences = _licence(dist)
    if licences:
        comp["licenses"] = licences
    return comp


def build(wheel: Path, now: datetime | None = None, installed: dict[str, md.Distribution] | None = None) -> dict:
    """The SBOM as a dict. Raises SystemExit with a message if oss-intake or a requirement is not installed."""
    dists = installed if installed is not None else _installed()
    if ROOT not in dists:
        raise SystemExit(f"release_sbom: {ROOT} is not installed in this environment ({sys.executable})")
    order: list[str] = []
    deps: dict[str, list[str]] = {}
    todo = [ROOT]
    while todo:
        name = todo.pop(0)
        if name in deps:
            continue
        reqs = [r for r in requirement_names(dists[name]) if r in dists]
        deps[name] = reqs
        order.append(name)
        todo.extend(r for r in reqs if r not in deps)
    root = _component(dists[ROOT])
    root["type"] = "application"
    root["hashes"] = [{"alg": "SHA-256", "content": hashlib.sha256(wheel.read_bytes()).hexdigest()}]
    ref = {n: _component(dists[n])["bom-ref"] for n in order}
    when = (now or datetime.now(timezone.utc)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": SPEC,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": when,
            "tools": {"components": [{"type": "application", "name": "release_sbom.py",
                                      "description": "oss-intake scripts/release_sbom.py"}]},
            "component": root,
        },
        "components": [_component(dists[n]) for n in order if n != ROOT],
        "dependencies": [{"ref": ref[n], "dependsOn": [ref[r] for r in deps[n]]} for n in order],
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--wheel", required=True, type=Path, help="the built wheel, for the subject's SHA-256")
    p.add_argument("--out", required=True, type=Path, help="where to write the CycloneDX JSON")
    args = p.parse_args(argv)
    bom = build(args.wheel)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(bom, indent=2) + "\n", encoding="utf-8")
    print(f"release_sbom: {len(bom['components'])} components written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
