"""Upgrade comparison for an inventory: what is still known to be wrong at the minimum fix version and at the
latest release.

For each package row (see inventory_report.package_rows):
  upgrade_to       the lowest version that fixes every listed vulnerability with a fix (already on the row)
  upgrade_left     known vulnerabilities in that version, checked against OSV (one batched query)
  latest           the package's current default release on deps.dev (skipped with --no-latest)
  latest_left      known vulnerabilities in the latest release
  *_major          the upgrade crosses a major version (or a 0.x minor version), so expect breaking changes

A version with fewer known vulnerabilities is not proven safe: it may simply be less studied, or newer than
the advisories. The report says so.
"""

from __future__ import annotations

import re
from functools import cmp_to_key
from urllib.parse import quote

from . import versions as versions_mod
from .enrich.fixdates import API, _system_and_name
from .http import Http, HttpError
from .scanners import osv as osv_mod

_NUM = re.compile(r"v?(\d+)(?:\.(\d+))?")
# Pre-releases are never suggested as "latest": 3.0.0-beta3, 2.0b1, 1.0.0-rc.1, 5.0.0-M2, 1.2-SNAPSHOT, 1.0.dev3.
_PRERELEASE = re.compile(r"(?i)(alpha|beta|preview|snapshot|milestone|\brc\b|[-.]rc\.?\d|[-.]cr\d|[-.]m\d+$|"
                         r"\.dev\d*|-dev\b|-pre\b|-ea\b|\d(a|b|rc)\d+$)")


def is_prerelease(v: str) -> bool:
    return bool(_PRERELEASE.search(v or ""))


def breaking(current: str, target: str) -> bool:
    """True when moving from current to target crosses a semver compatibility line: a new major version, or a
    new minor version while the major is 0 (0.x releases may break on any minor bump)."""
    a, b = _NUM.match(current or ""), _NUM.match(target or "")
    if not a or not b:
        return False
    a_major, b_major = int(a.group(1)), int(b.group(1))
    if a_major != b_major:
        return b_major > a_major
    if a_major == 0:
        return int(b.group(2) or 0) > int(a.group(2) or 0)
    return False


def _with_version(purl: str, version: str) -> str:
    return f"{purl.rsplit('@', 1)[0]}@{version}"


def latest_version(http: Http, purl: str) -> str | None:
    """The latest stable version of the package on deps.dev, or None if unknown. deps.dev's default version is
    used when it is stable; otherwise (Maven's default can be a beta) the highest stable version is taken."""
    sn = _system_and_name(purl)
    if not sn:
        return None
    status, data = http.get_json(f"{API}/{sn[0]}/packages/{quote(sn[1], safe='')}")
    if status != 200 or not isinstance(data, dict):
        return None
    listed = [((v.get("versionKey") or {}).get("version") or "", bool(v.get("isDefault")))
              for v in data.get("versions") or []]
    default = next((v for v, d in listed if d and v and not is_prerelease(v)), None)
    if default:
        return default
    stable = [v for v, _ in listed if v and not is_prerelease(v)]
    return max(stable, key=cmp_to_key(versions_mod.compare)) if stable else None


def enrich(http: Http, rows: list[dict], latest: bool = True) -> dict:
    info: dict = {"status": "ok", "latest_checked": 0, "latest_unknown": 0, "errors": 0, "latest": latest}
    for r in rows:
        r.update({"upgrade_left": None, "upgrade_major": False, "latest": "", "latest_left": None,
                  "latest_major": False})
        if r["upgrade_to"] and not r["malicious"]:
            r["upgrade_major"] = breaking(r["version"], r["upgrade_to"])
    if latest:
        for r in rows:
            try:
                v = latest_version(http, r["purl"])
            except HttpError:
                info["errors"] += 1
                continue
            if v:
                info["latest_checked"] += 1
                r["latest"] = v
                r["latest_major"] = breaking(r["version"], v)
            else:
                info["latest_unknown"] += 1
    targets: dict[str, set[str]] = {}
    for r in rows:
        if r["upgrade_to"] and not r["malicious"]:
            targets.setdefault(_with_version(r["purl"], r["upgrade_to"]), set()).add("upgrade")
        if r["latest"] and r["latest"] != r["version"]:
            targets.setdefault(_with_version(r["purl"], r["latest"]), set()).add("latest")
    if not targets:
        return info
    try:
        found = osv_mod.scan(http, sorted(targets))
    except HttpError as exc:
        info.update(status="failed", error=str(exc))
        return info
    counts: dict[str, dict] = {}
    for f in found:
        c = counts.setdefault(f.purl or "", {"total": 0, "critical": 0, "malicious": False})
        c["total"] += 1
        c["critical"] += f.severity == "CRITICAL"
        c["malicious"] = c["malicious"] or f.malicious
    empty = {"total": 0, "critical": 0, "malicious": False}
    for r in rows:
        if r["upgrade_to"] and not r["malicious"]:
            r["upgrade_left"] = counts.get(_with_version(r["purl"], r["upgrade_to"]), empty)
        if r["latest"]:
            r["latest_left"] = (counts.get(_with_version(r["purl"], r["latest"]), empty)
                                if r["latest"] != r["version"] else
                                {"total": r["findings"], "critical": r["critical"], "malicious": r["malicious"]})
    return info


def describe(left: dict | None) -> str:
    """'0 known' / '2 known (1 critical)' / 'MALICIOUS'."""
    if left is None:
        return ""
    if left["malicious"]:
        return "malicious"
    return f"{left['total']} known" + (f" ({left['critical']} critical)" if left["critical"] else "")
