"""Assessor decisions carried between runs (--decisions), and exported as OpenVEX.

The cycle: a run writes findings.csv with empty triage_status, triage_notes and triage_reachable columns; the
assessor fills them in for the findings they have looked at; the next run reads that file with --decisions and
applies each decision to the same vulnerability in the same package, so only new findings need a look. The
new findings.csv comes out pre-filled, so the cycle repeats. An OpenVEX document is accepted too, and every run
with decisions writes openvex.json so other tools (Grype and Trivy read it with --vex) can use them.

Statuses follow OpenVEX: not_affected, affected, fixed, under_investigation. not_affected needs a note that
says why. "mitigated" means a compensating control, not a fix: it is not_affected with the justification
inline_mitigations_already_exist. A decision never sets aside a malicious package.

A decision applies to the same vulnerability in the same package, preferring the one made for the installed
version; one made for another version still applies, marked for review.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import cast

from . import jsonsafe
from .inputs import MAX_INPUT_BYTES, InputError, check_size
from .models import Finding

STATUSES = ("not_affected", "affected", "fixed", "under_investigation")
ALIASES = {
    "not affected": "not_affected", "not_affected": "not_affected", "false positive": "not_affected",
    "false_positive": "not_affected", "not applicable": "not_affected", "n/a": "not_affected",
    "affected": "affected", "accepted": "affected", "risk accepted": "affected", "exploitable": "affected",
    "fixed": "fixed", "patched": "fixed", "mitigated": "not_affected", "compensating control": "not_affected",
    "under investigation": "under_investigation", "under_investigation": "under_investigation",
    "investigating": "under_investigation", "open": "under_investigation",
}
JUSTIFICATIONS = ("component_not_present", "vulnerable_code_not_present", "vulnerable_code_not_in_execute_path",
                  "vulnerable_code_cannot_be_controlled_by_adversary", "inline_mitigations_already_exist")
SETS_ASIDE = ("not_affected", "fixed")
MITIGATED = "inline_mitigations_already_exist"
# The words that mean a mitigation rather than a reason the code is unaffected.
_MITIGATION_WORDS = ("mitigated", "compensating control")


_UNGUARD_START = re.compile(r"^'([\s']*[=+\-@\t\r\uff1d\uff0b\uff0d\uff20])")
_UNGUARD_JOINED = re.compile(r"([;,\t])(\s*)'('*(?:[=@]|[+\-](?!\s|[\d.]*(?:[;,\t]|$))))")


def unguard(value: str) -> str:
    """Undo report.csv_safe exactly: it adds one quote where a formula could start (counting quotes already
    there), so one is removed at the same places."""
    value = _UNGUARD_START.sub(r"\1", value)
    return _UNGUARD_JOINED.sub(r"\1\2\3", value)


def _read_csv(path: Path) -> list[dict]:
    # newline="" keeps line breaks inside quoted cells (multi-line notes) instead of splitting the row.
    check_size(path, MAX_INPUT_BYTES, "decisions file")
    try:
        with open(path, encoding="utf-8-sig", newline="") as fh:
            return list(csv.DictReader(fh))
    except UnicodeDecodeError as exc:
        raise InputError(f"{path.name} is not UTF-8 text: {exc.reason} at byte {exc.start}") from None
    except csv.Error as exc:
        raise InputError(f"{path.name} is not a readable CSV file: {exc}") from None


def _status(value: str) -> str | None:
    return ALIASES.get(" ".join(value.strip().lower().replace("-", " ").split()))


def _ids(*values: str | None) -> set[str]:
    out: set[str] = set()
    for v in values:
        for part in str(v or "").replace(",", ";").split(";"):
            part = part.strip()
            if part:
                out.add(part.upper() if part.upper().startswith(("CVE-", "GHSA-", "MAL-")) else part)
    return out


def _from_csv(path: Path) -> tuple[list[dict], list[str]]:
    rows = _read_csv(path)
    if rows and not {"id", "package", "triage_status"} <= set(rows[0]):
        raise InputError(f"{path.name} is not a findings.csv from oss-intake (needs id, package and "
                         "triage_status columns)")
    out, errors = [], []
    for n, r in enumerate(rows, start=2):
        raw = (r.get("triage_status") or "").strip()
        if not raw:
            continue  # not assessed yet
        status = _status(raw)
        notes = unguard((r.get("triage_notes") or "").strip())
        if not status:
            errors.append(f"row {n}: triage_status '{raw}' is not one of {', '.join(STATUSES)}")
            continue
        if status == "not_affected" and not notes:
            errors.append(f"row {n}: {raw} needs triage_notes saying why ({r.get('id')})")
            continue
        package = unguard((r.get("package") or "").strip())  # '@scope/name was guarded as a formula
        reachable = (r.get("triage_reachable") or "").strip().lower()
        justification = (r.get("triage_justification") or "").strip()
        if justification and justification not in JUSTIFICATIONS:
            errors.append(f"row {n}: triage_justification '{justification}' is not one of {', '.join(JUSTIFICATIONS)}")
            continue
        if " ".join(raw.lower().replace("-", " ").split()) in _MITIGATION_WORDS:
            justification = MITIGATED
        elif not justification and status == "not_affected" and reachable in ("no", "n", "false", "not reachable"):
            justification = "vulnerable_code_not_in_execute_path"
        out.append({"ids": _ids(r.get("id"), r.get("aliases")), "package": package,
                    "pkg_type": (r.get("pkg_type") or "").strip().lower(),
                    "version": unguard((r.get("triage_decided_version") or r.get("installed") or "").strip()),
                    "status": status, "notes": notes, "reachable": reachable,
                    "justification": justification if status == "not_affected" else "",
                    "source": f"{path.name} row {n}"})
    return out, errors


def _purl_name_version(purl: str) -> tuple[str, str]:
    """Package name and version as findings carry them. OS packages (deb, rpm, apk) drop the distro namespace
    (pkg:deb/ubuntu/libc6 is package libc6) and take the epoch qualifier into the version (1:2.3-4)."""
    from urllib.parse import parse_qs, unquote

    from .inventory_report import split_purl

    base, _, query = purl.split("#", 1)[0].partition("?")
    try:
        ptype, name, version = split_purl(base)
    except ValueError:
        return "", ""
    version = unquote(version)  # Debian security versions are encoded in purls: 7.88.1-10%2Bdeb12u14
    if ptype in ("deb", "rpm", "apk"):
        name = name.rsplit("/", 1)[-1]
        epoch = (parse_qs(query).get("epoch") or [""])[0]
        if epoch and epoch != "0" and ":" not in version:
            version = f"{epoch}:{version}"
    return name, version


def _purl_type(purl: str) -> str:
    """'npm' from pkg:npm/..., '' for anything that is not a purl."""
    return purl[4:].split("/", 1)[0].lower() if purl.startswith("pkg:") and "/" in purl[4:] else ""


# pkg_type is in each source's own words (Trivy "jar" or "ubuntu", Grype "java-archive" or "deb", OSV the purl
# type), so a decision recorded from one scanner's findings.csv must still match another's: each is mapped to
# its ecosystem. A type not listed here has no known ecosystem, and its decisions match by name, as before.
_ECOSYSTEM = {t: eco for eco, types in {
    "maven": "maven jar war ear par sar pom gradle sbt java java-archive jenkins-plugin",
    "npm": "npm node-pkg yarn pnpm bun javascript",
    "pypi": "pypi pip pipenv poetry uv python python-pkg python-egg",
    "go": "golang go gomod gobinary go-module",
    "cargo": "cargo rust rust-crate rustbinary",
    "gem": "gem gemspec bundler rubygems",
    "nuget": "nuget dotnet dotnet-core dotnet-deps dotnet-pkg packages-lock",
    "composer": "composer php php-composer php-pear",
    "deb": "deb dpkg debian ubuntu",
    "rpm": "rpm redhat centos rocky alma almalinux amazon fedora oracle ol suse opensuse sles photon cbl-mariner "
           "mariner azurelinux",
    "apk": "apk alpine wolfi chainguard",
    "cran": "cran r r-package",
    "hex": "hex erlang elixir",
    "pub": "pub dart",
    "swift": "swift swiftpm cocoapods",
}.items() for t in types.split()}


def _ecosystem(kind: str) -> str:
    return _ECOSYSTEM.get(kind.strip().lower(), "")


def _known_same_ecosystem(d: dict, f: Finding) -> bool:
    """Both the decision and the finding name an ecosystem, and it is the same one: mapped (Trivy jar and Grype
    java-archive are both maven), or, for a type not mapped (bitnami, conda, generic), written the same way."""
    mine = _ecosystem(d.get("pkg_type") or "") or _ecosystem(d.get("purl_type") or "")
    theirs = _ecosystem(_purl_type(f.purl or "")) or _ecosystem(f.pkg_type or "")
    if mine and theirs:
        return mine == theirs
    raw_mine = {t.strip().lower() for t in (d.get("pkg_type") or "", d.get("purl_type") or "") if t.strip()}
    raw_theirs = {t.strip().lower() for t in (f.pkg_type or "", _purl_type(f.purl or "")) if t.strip()}
    return bool(raw_mine & raw_theirs)


def _same_ecosystem(d: dict, f: Finding) -> bool:
    """A decision applies only in its own ecosystem when both it and the finding have a known one (findings.csv
    has pkg_type, OpenVEX a purl; the finding its purl, else its pkg_type). Otherwise it matches by name."""
    mine = _ecosystem(d.get("pkg_type") or "") or _ecosystem(d.get("purl_type") or "")
    theirs = _ecosystem(_purl_type(f.purl or "")) or _ecosystem(f.pkg_type or "")
    return mine == theirs if mine and theirs else True


def _from_openvex(path: Path) -> tuple[list[dict], list[str]]:
    check_size(path, MAX_INPUT_BYTES, "decisions file")
    try:
        doc = jsonsafe.loads(path.read_text(encoding="utf-8"))
    except (ValueError, RecursionError) as exc:  # UnicodeDecodeError is a ValueError
        raise InputError(f"{path.name} is not valid JSON: {exc or 'nested too deeply'}") from None
    if not isinstance(doc, dict) or "statements" not in doc:
        raise InputError(f"{path.name} is not an OpenVEX document (no 'statements')")
    statements = doc.get("statements") or []
    if not isinstance(statements, list):
        raise InputError(f"{path.name}: 'statements' must be a list")
    out, errors = [], []
    for n, st in enumerate(statements, start=1):
        if not isinstance(st, dict):
            errors.append(f"statement {n}: not an object")
            continue
        vuln = st.get("vulnerability") or {}
        vuln = {"name": vuln} if isinstance(vuln, str) else vuln
        aliases = vuln.get("aliases") or [] if isinstance(vuln, dict) else None
        if not isinstance(vuln, dict) or not isinstance(vuln.get("name"), str) or not isinstance(aliases, list) \
                or not all(isinstance(a, str) for a in aliases):
            errors.append(f"statement {n}: vulnerability must be a name, or an object with a name and a list of "
                          "aliases")
            continue
        products = st.get("products") or []
        if not isinstance(products, list):
            errors.append(f"statement {n}: products must be a list")
            continue
        status = _status(str(st.get("status") or ""))
        if not status:
            errors.append(f"statement {n}: status '{st.get('status')}' is not one of {', '.join(STATUSES)}")
            continue
        notes = str(st.get("impact_statement") or st.get("action_statement") or st.get("status_notes") or "")
        justification = str(st.get("justification") or "")
        if status == "not_affected" and not (notes or justification):
            errors.append(f"statement {n}: not_affected needs a justification or impact_statement")
            continue
        for prod in products:
            pid = prod.get("@id") if isinstance(prod, dict) else str(prod)
            name, version = _purl_name_version(pid or "") if str(pid).startswith("pkg:") else ("", "")
            if not name:
                errors.append(f"statement {n}: product '{pid}' is not a package URL (pkg:...)")
                continue
            out.append({"ids": _ids(vuln["name"], *aliases), "package": name,
                        "purl_type": _purl_type(str(pid or "")),
                        "version": version, "status": status, "notes": notes or justification.replace("_", " "),
                        "reachable": "", "justification": justification, "source": f"{path.name} statement {n}"})
    return out, errors


def previous_findings(path: Path) -> set[tuple[str, str]] | None:
    """Every (vulnerability, package) in an earlier findings.csv, for "what changed since the last run".
    None when the decisions file is not a findings.csv (OpenVEX lists decisions, not findings)."""
    if path.suffix.lower() != ".csv" or not path.is_file():
        return None
    keys: set[tuple[str, str]] = set()
    for r in _read_csv(path):
        ids = _ids(r.get("id"))
        pkg = unguard(r.get("package") or "").lower()
        keys |= {(i, pkg) for i in ids}
    return keys


def load(path: Path) -> list[dict]:
    """Read and validate a decisions file before anything is scanned. Invalid entries stop the run."""
    if not path.is_file():
        raise InputError(f"--decisions {path} not found")
    loader = _from_openvex if path.suffix.lower() == ".json" else _from_csv
    decisions, errors = loader(path)
    if errors:
        shown = "\n  ".join(errors[:20])
        more = f"\n  ... and {len(errors) - 20} more" if len(errors) > 20 else ""
        raise InputError(f"{len(errors)} invalid decision(s) in {path.name}:\n  {shown}{more}")
    return decisions


def apply(findings: list[Finding], decisions: list[dict]) -> dict:
    """Attach each decision to the findings it covers (same vulnerability, by ID or alias, in the same package).
    When several decisions cover one finding, the one made for its installed version wins; otherwise the last one
    in the file applies, marked for review. Returns counts for the report, including decisions no finding used."""
    index: dict[tuple[str, str], list[dict]] = {}
    for d in decisions:
        for i in d["ids"]:
            bucket = index.setdefault((i, d["package"].lower()), [])
            if d not in bucket:
                bucket.append(d)
    used: set[int] = set()
    matched: set[int] = set()  # decisions whose vulnerability and package were found, chosen or not
    info: dict = {"decisions": len(decisions), "applied": 0, "stale": 0, "ignored_malicious": 0,
                  "by_status": {s: 0 for s in STATUSES}, "resolved": []}
    for f in findings:
        pkg = f.package.lower()
        candidates = [d for i in sorted(_ids(f.vuln_id, *f.aliases)) for d in index.get((i, pkg), [])
                      if _same_ecosystem(d, f)]
        if not candidates:
            continue
        matched.update(id(c) for c in candidates)
        d = next((c for c in candidates if c["version"] and c["version"] == f.installed),
                 next((c for c in candidates if not c["version"]), candidates[-1]))
        used.add(id(d))
        if f.malicious and d["status"] in SETS_ASIDE:
            info["ignored_malicious"] += 1
            f.decision_status, f.decision_notes = "", ""
            f.note = (f.note + "; " if f.note else "") + f"decision '{d['status']}' ignored: malicious package"
            continue
        f.decision_status, f.decision_notes = d["status"], d["notes"]
        f.decision_reachable, f.decision_justification = d["reachable"], d["justification"]
        f.decision_version = d["version"]
        f.decision_exact = bool(d["version"] and d["version"] == f.installed and _known_same_ecosystem(d, f))
        info["applied"] += 1
        info["by_status"][d["status"]] += 1
        if d["version"] and f.installed and d["version"] != f.installed:
            info["stale"] += 1
    # Resolved means the vulnerability is no longer found in that package. A decision for another version of a
    # finding that is still present was superseded by a closer one, not resolved.
    for d in decisions:
        if id(d) not in used and id(d) not in matched:
            info["resolved"].append({"ids": sorted(d["ids"]), "package": d["package"], "status": d["status"]})
    return info


def _exported_status(f: Finding) -> tuple[str, str]:
    """The status a VEX file may claim for f, and the notes. Grype, Trivy and Dependency-Track act on a VEX claim
    without review, so a decision is exported as made only when it was made for this version in this ecosystem;
    any other (another version, no version, matched by name alone) goes out as under investigation, saying why."""
    if f.decision_exact or f.decision_status == "under_investigation":
        return f.decision_status, f.decision_notes
    made_for = (f"version {f.decision_version}" if f.decision_version and f.decision_version != f.installed
                else "this version, without a matching package type" if f.decision_version
                else "no stated version")
    why = (f"assessor decided {f.decision_status.replace('_', ' ')} for {made_for}; not yet confirmed for "
           f"{f.installed or 'the installed version'}")
    return "under_investigation", why + (f". Notes: {f.decision_notes}" if f.decision_notes else "")


def _with(f: Finding, status: str, notes: str) -> Finding:
    import dataclasses

    return f if (status, notes) == (f.decision_status, f.decision_notes) else dataclasses.replace(
        f, decision_status=status, decision_notes=notes)


def openvex(findings: list[Finding], tool_version: str, as_of: str) -> dict | None:
    """An OpenVEX v0.2.0 document of the decisions applied in this run, or None if there are none. A decision
    not made for this exact version goes out as under investigation (_exported_status)."""
    statements = []
    for f in findings:
        if not f.decision_status or not f.purl:
            continue
        status, notes = _exported_status(f)
        f = _with(f, status, notes)
        st: dict = {"vulnerability": {"name": f.vuln_id, **({"aliases": sorted(f.aliases)} if f.aliases else {})},
                    "products": [{"@id": f.purl}], "status": f.decision_status}
        if f.decision_status == "not_affected":
            if f.decision_justification in JUSTIFICATIONS:
                st["justification"] = f.decision_justification
            st["impact_statement"] = f.decision_notes or "assessed as not affected"
        elif f.decision_status == "affected":
            st["action_statement"] = f.decision_notes or "assessed as affected"
        elif f.decision_notes:
            st["status_notes"] = f.decision_notes
        statements.append(st)
    if not statements:
        return None
    digest = hashlib.sha256(json.dumps(statements, sort_keys=True).encode()).hexdigest()[:16]
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": f"urn:oss-intake:openvex:{digest}",
            "author": "oss-intake assessor", "role": "assessor",
            "timestamp": as_of or datetime.now(timezone.utc).isoformat(), "version": 1,
            "tooling": f"oss-intake {tool_version}", "statements": statements}


# CycloneDX VEX: for Dependency-Track, which imports CycloneDX VEX rather than OpenVEX.
CDX_STATE = {"not_affected": "not_affected", "affected": "exploitable", "fixed": "resolved",
             "under_investigation": "in_triage"}
CDX_JUSTIFICATION = {"component_not_present": "code_not_present", "vulnerable_code_not_present": "code_not_present",
                     "vulnerable_code_not_in_execute_path": "code_not_reachable",
                     "inline_mitigations_already_exist": "protected_by_mitigating_control"}


def _cdx_source(vid: str) -> dict:
    v = vid.upper()
    if v.startswith("CVE-"):
        return {"name": "NVD", "url": f"https://nvd.nist.gov/vuln/detail/{vid}"}
    if v.startswith("GHSA-"):
        return {"name": "GitHub", "url": f"https://github.com/advisories/{vid}"}
    return {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vid}"}


def cyclonedx_vex(findings: list[Finding], tool_version: str, as_of: str) -> dict | None:
    """A CycloneDX 1.6 VEX document of the decisions applied in this run, or None if there are none.
    Components use the package URL as bom-ref, so a VEX import matches them by purl."""
    import uuid

    from .inventory_report import split_purl

    decided = [f for f in findings if f.decision_status and f.purl]
    if not decided:
        return None
    components: dict[str, dict] = {}
    vulns = []
    for f in decided:
        f = _with(f, *_exported_status(f))
        purl = cast(str, f.purl).split("?", 1)[0].split("#", 1)[0]  # decided holds findings with a purl
        if purl not in components:
            try:
                _, name, version = split_purl(purl)
            except ValueError:
                name, version = f.package, f.installed
            components[purl] = {"type": "library", "bom-ref": purl, "name": name, "version": version, "purl": purl}
        analysis: dict = {"state": CDX_STATE[f.decision_status]}
        if f.decision_status == "not_affected" and f.decision_justification in CDX_JUSTIFICATION:
            analysis["justification"] = CDX_JUSTIFICATION[f.decision_justification]
        if f.decision_notes:
            analysis["detail"] = f.decision_notes
        v: dict = {"bom-ref": f"{f.vuln_id}@{purl}", "id": f.vuln_id, "source": _cdx_source(f.vuln_id),
                   "analysis": analysis, "affects": [{"ref": purl}]}
        refs = [{"id": a, "source": _cdx_source(a)} for a in sorted(f.aliases) if a != f.vuln_id]
        if refs:
            v["references"] = refs
        vulns.append(v)
    body = {"components": list(components.values()), "vulnerabilities": vulns}
    serial = uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(body, sort_keys=True))
    timestamp = as_of if "T" in as_of else f"{as_of}T00:00:00Z"
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{serial}", "version": 1,
            "metadata": {"timestamp": timestamp,
                         "tools": {"components": [{"type": "application", "name": "oss-intake",
                                                   "version": tool_version}]}},
            **body}
