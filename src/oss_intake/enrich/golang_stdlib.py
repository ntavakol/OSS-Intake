"""Go standard library fix dates from the Go release history page.

deps.dev does not index the standard library, but https://go.dev/doc/devel/release lists every Go release
with its date, one fetch for all versions:

    <p id="go1.22.8">
        go1.22.8
        (released 2024-10-01)

Scanners write the toolchain version differently (Trivy "v1.22.7", Grype "go1.22.7"), so both are normalised
to "1.22.7". Major releases appear as go1.21.0 or, for older ones, go1.20; both are keyed as 1.20.0.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone

from ..http import Http, HttpError
from ..models import Finding
from ..versions import nearest_fix

URL = "https://go.dev/doc/devel/release"
_RELEASE = re.compile(r"\b(go\d+\.\d+(?:\.\d+)?)\s*\(released (\d{4})-(\d{2})-(\d{2})\)")


def norm(v: str) -> str:
    v = v.strip()
    for prefix in ("go", "v"):
        if v.startswith(prefix):
            v = v[len(prefix):]
    parts = v.split(".")
    if len(parts) == 2 and all(p.isdigit() for p in parts):
        v += ".0"
    return v


def parse(text: str) -> dict[str, datetime]:
    out: dict[str, datetime] = {}
    for name, y, m, d in _RELEASE.findall(text):
        out.setdefault(norm(name), datetime(int(y), int(m), int(d), tzinfo=timezone.utc))
    return out


def is_stdlib(f: Finding) -> bool:
    return f.package == "stdlib" and (f.purl or "").startswith("pkg:golang/")


def enrich(http: Http, findings: list[Finding]) -> dict:
    stats = {"candidates": 0, "found": 0, "releases_loaded": 0, "errors": 0}
    todo = [f for f in findings if is_stdlib(f) and not f.fix_published and not f.likely_fixed and f.fixed_versions]
    if not todo:
        return stats
    try:
        status, text = http.get_text(URL)
    except HttpError:
        stats["errors"] += 1
        return stats
    dates = parse(text) if status == 200 and text else {}
    if not dates:
        stats["errors"] += 1
        return stats
    stats["releases_loaded"] = len(dates)
    for f in todo:
        stats["candidates"] += 1
        fix = nearest_fix(norm(f.installed), [norm(v) for v in f.fixed_versions])
        if fix and fix in dates:
            f.fix_published = dates[fix]
            f.fix_version_used = fix
            f.fix_date_source = f"Go release go{fix}"
            stats["found"] += 1
    return stats
