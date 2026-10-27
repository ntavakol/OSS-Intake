"""Per-package view of a package inventory scan: one row per package version listed in the inventory,
including the ones with no known vulnerabilities, so the result answers "which of our packages need action".
"""

from __future__ import annotations

import csv
from functools import cmp_to_key
from pathlib import Path
from urllib.parse import unquote

from . import triage, versions
from .models import Finding
from .upgrade import describe

GROUP_ORDER = ["act", "review", "conditions", "routine", "aside"]
BASE_FIELDS = ["group", "ecosystem", "package", "version", "findings", "critical", "high", "malicious", "kev",
               "no_fix", "upgrade_to", "upgrade_left", "upgrade_major", "latest", "latest_left", "latest_major",
               "published", "new_release", "purl"]


def split_purl(purl: str) -> tuple[str, str, str]:
    """pkg:npm/%40ctrl/tinycolor@4.1.1 -> ('npm', '@ctrl/tinycolor', '4.1.1'); Maven names as group:artifact."""
    ptype, rest = purl[4:].split("#", 1)[0].split("?", 1)[0].split("/", 1)
    name, _, version = rest.rpartition("@")
    name, version = unquote(name), unquote(version)
    if ptype in ("deb", "rpm", "apk"):
        name = name.rsplit("/", 1)[-1]  # pkg:deb/ubuntu/libssl3t64 -> libssl3t64, as the distro names it
    return ptype, (name.replace("/", ":") if ptype == "maven" else name), version


def _highest(vs: list[str]) -> str:
    return max(vs, key=cmp_to_key(versions.compare)) if vs else ""


def package_rows(inventory: list[dict], findings: list[Finding]) -> list[dict]:
    by_purl: dict[str, list[Finding]] = {}
    for f in findings:
        by_purl.setdefault(f.purl or "", []).append(f)
    rows = []
    for entry in inventory:
        purl = entry["purl"]
        ptype, name, version = split_purl(purl)
        fs = by_purl.get(purl, [])
        groups = [f.triage_group for f in fs if f.triage_group]
        group = min(groups, key=GROUP_ORDER.index) if groups else ""
        malicious = any(f.malicious for f in fs)
        no_fix = sum(1 for f in fs if not f.fixed_versions)
        # An OS package's fixes are versions of its source package (cpp 4:13.2.0 is built from gcc-defaults
        # 1.214ubuntu1): compare those, not the binary's own version.
        base = next((f.installed for f in fs if f.src_version), version)
        if malicious:
            upgrade = "remove: malicious release"
        else:
            # The lowest version fixed for every finding on its release line, not just the highest nearest fix:
            # with CVE-A fixed in 1.2.9 or 1.3.2 and CVE-B in 1.3.0, 1.3.0 still has CVE-A; 1.3.2 is the answer.
            upgrade = versions.minimum_upgrade(base, [f.fixed_versions for f in fs if f.fixed_versions]) or \
                _highest([v for v in (versions.nearest_fix(base, f.fixed_versions) for f in fs
                                       if f.fixed_versions) if v])
        rows.append({
            "group": triage.LABEL.get(group, "") if group else "",
            "group_key": group,
            "ecosystem": ptype,
            "package": name,
            "version": version,
            "findings": len(fs),
            "critical": sum(1 for f in fs if f.severity == "CRITICAL"),
            "high": sum(1 for f in fs if f.severity == "HIGH"),
            "malicious": malicious,
            "kev": sum(1 for f in fs if f.kev),
            "no_fix": no_fix,
            "upgrade_to": upgrade,
            "compare_version": base,
            "purl": purl,
            "labels": dict(entry.get("labels") or {}),
        })
    rows.sort(key=lambda r: (GROUP_ORDER.index(r["group_key"]) if r["group_key"] else len(GROUP_ORDER),
                             -r["critical"], -r["findings"], r["ecosystem"], r["package"].lower(), r["version"]))
    return rows


def summary(rows: list[dict]) -> dict:
    return {
        "packages": len(rows),
        "with_findings": sum(1 for r in rows if r["findings"]),
        "malicious": sum(1 for r in rows if r["malicious"]),
        "act_now": sum(1 for r in rows if r["group_key"] == "act"),
        "with_critical": sum(1 for r in rows if r["critical"]),
        "without_fix": sum(1 for r in rows if r["no_fix"] and not r["malicious"]),
        "fix_clears_all": sum(1 for r in rows if (r.get("upgrade_left") or {}).get("total") == 0),
        "behind_latest": sum(1 for r in rows if r.get("latest") and r["latest"] != r["version"]),
        "label_columns": sorted({k for r in rows for k in r["labels"]}),
    }


def label_text(labels: dict[str, str]) -> str:
    return " · ".join(f"{k}: {v}" for k, v in labels.items())


def write_csv(path: Path, rows: list[dict], safe) -> None:
    """packages.csv: every package in the inventory, worst first, with its label columns."""
    label_cols = sorted({k for r in rows for k in r["labels"]})
    with open(path, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=BASE_FIELDS + label_cols)
        # Label columns are named by the inventory's author: the header row is guarded like every cell (S3).
        csv.writer(fh).writerow([safe(c) for c in BASE_FIELDS + label_cols])
        for r in rows:
            out = {k: r.get(k, "") for k in BASE_FIELDS}
            out["malicious"] = "yes" if r["malicious"] else ""
            for k in ("upgrade_left", "latest_left"):
                out[k] = describe(r.get(k))
            for k in ("upgrade_major", "latest_major"):
                out[k] = "yes" if r.get(k) else ""
            out.update({k: r["labels"].get(k, "") for k in label_cols})
            w.writerow({k: safe(v) for k, v in out.items()})
