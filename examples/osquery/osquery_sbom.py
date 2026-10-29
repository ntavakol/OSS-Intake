#!/usr/bin/env python3
"""Turn osquery package tables into one CycloneDX SBOM per host, for `oss-intake --path <folder>`.

Three ways in:

  python3 osquery_sbom.py --out sboms                   run osqueryi on this machine
  python3 osquery_sbom.py --out sboms --dir ~/app/.venv  ... and also read packages in these folders
  python3 osquery_sbom.py --out sboms --results osqueryd.snapshots.log
                                                        osquery snapshot logs (osqueryd, Fleet or any log
                                                        pipeline): one SBOM per hostIdentifier
  python3 osquery_sbom.py --out sboms --json saved.json  a saved {"query name": [rows]} object, one host

Tables read: deb_packages, rpm_packages, python_packages, npm_packages, homebrew_packages,
chocolatey_packages, with os_version for the distro. Query names say which table a result came from:
"deb_packages", "pack/oss-intake/python_packages_app" and "oss_intake_npm_packages" all work.

What osquery does not see, and what oss-intake cannot check, is said rather than dropped:
  - python_packages and npm_packages read default locations only (system and user site-packages, global
    node_modules). Application dependencies in a venv or a project's node_modules are missed unless the
    folder is given with --dir (or a WHERE directory = '...' query in the pack).
  - Homebrew, chocolatey and the operating system itself have no advisory data oss-intake can query; they
    are written without a purl and listed in the report as not checked, with the reason.
  - osquery has no Alpine (apk) table.

Home folders are shortened (/Users/ned/app -> ~/app) so user names in paths do not reach reports. The host
name is osquery's hostname, or --host to set your own; host names often carry a user name (Neds-MacBook-Pro).

Standard library only; Python 3.10 or later.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

TOOL_VERSION = "1"
TABLES = ("deb_packages", "rpm_packages", "python_packages", "npm_packages", "homebrew_packages",
          "chocolatey_packages", "os_version", "system_info")
QUERIES = {
    "os_version": "SELECT name, version, major, minor, platform, platform_like, codename FROM os_version",
    "system_info": "SELECT hostname FROM system_info",
    "deb_packages": "SELECT name, version, source, arch, status FROM deb_packages",
    "rpm_packages": "SELECT name, version, release, epoch, arch, source FROM rpm_packages",
    "python_packages": "SELECT p.name, p.version, p.directory FROM users CROSS JOIN python_packages p USING (uid)",
    "npm_packages": "SELECT name, version, directory FROM npm_packages",
    "homebrew_packages": "SELECT name, version, type FROM homebrew_packages",
    "chocolatey_packages": "SELECT name, version FROM chocolatey_packages",
}
NOT_CHECKED = {
    "homebrew_packages": "Homebrew: no advisory database covers Homebrew formulae or casks (OSV, Trivy and Grype "
                         "do not); check what the formula is built from instead",
    "chocolatey_packages": "Chocolatey: no advisory database covers Chocolatey packages",
    "os": "the operating system itself: OSV has no advisories for it; use the vendor's update status",
}
_HOME = re.compile(r"^(/root(?=/|$)"
                   r"|(/var/home|/export/home|/home|/Users)/[^/]+"
                   r"|(\\\\\?\\)?[A-Za-z]:[/\\]users[/\\][^/\\]+)",
                   re.IGNORECASE)
# Python packages the distro installed (python3-yaml puts PyYAML in /usr/lib/python3/dist-packages). The distro
# patches them without changing the upstream version, so a PyPI check would report fixed issues; the deb or rpm
# package covers them.
_OS_PYTHON = re.compile(r"^/usr/(lib|lib64|share)/python[0-9.]*/(dist|site)-packages")
_SRC_PARENS = re.compile(r"^(?P<name>\S+)\s*\((?P<version>[^)]+)\)$")


class CollectorError(Exception):
    pass


# --- reading -------------------------------------------------------------------------------------------------

def table_of(query_name: str) -> str | None:
    """Which table a query reads, from its name: 'deb_packages', 'pack/Global/python_packages_app' (Fleet,
    pack_delimiter /) and 'pack_oss-intake_oss_intake_npm_packages' (osqueryd's default delimiter _)."""
    name = query_name.lower()
    for t in sorted(TABLES, key=len, reverse=True):
        if re.search(rf"(?:^|[/:_-]){t}(?:_[a-z0-9-]+)?$", name):
            return t
    short = {"os": "os_version", "deb": "deb_packages", "rpm": "rpm_packages", "python": "python_packages",
             "npm": "npm_packages", "homebrew": "homebrew_packages", "chocolatey": "chocolatey_packages"}
    return short.get(name)


def group(results: dict[str, list[dict]]) -> dict[str, list[dict]]:
    """{query name: rows} -> {table: rows}, several queries of one table combined."""
    out: dict[str, list[dict]] = {}
    for name, rows in results.items():
        t = table_of(name)
        if t is None:
            continue
        if not isinstance(rows, list):
            raise CollectorError(f"query {name}: expected a list of rows")
        out.setdefault(t, []).extend(r for r in rows if isinstance(r, dict))
    return out


def read_results_log(path: Path) -> dict[str, dict[str, list[dict]]]:
    """osquery snapshot logs (osqueryd.snapshots.log, or Fleet's results; one JSON object per line) ->
    {host: {query name: rows}}, keeping each host's latest snapshot of each query. Both snapshot forms are read:
    one line per snapshot ("snapshot": [rows]) and one line per row ("action": "snapshot", "columns": {...},
    with --logger_snapshot_event_type). Differential results hold changes, not a full list, and are refused."""
    latest: dict[tuple[str, str], tuple[int, list]] = {}
    events: dict[tuple[str, str, int], list] = {}
    for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            raise CollectorError(f"{path.name} line {n}: not JSON") from None
        if not isinstance(rec, dict) or table_of(str(rec.get("name", ""))) is None:
            continue
        host = str(rec.get("hostIdentifier") or (rec.get("decorations") or {}).get("hostname")
                   or "unknown-host")
        when = int(rec.get("unixTime") or 0)
        if rec.get("action") == "snapshot" and isinstance(rec.get("columns"), dict):
            events.setdefault((host, str(rec["name"]), when), []).append(rec["columns"])
            continue
        if "snapshot" not in rec:
            raise CollectorError(f"{path.name} line {n}: query {rec.get('name')} is a differential result "
                                 f"(action {rec.get('action') or 'batch'}); set \"snapshot\": true for it, as "
                                 "oss-intake-pack.conf does")
        key = (host, str(rec["name"]))
        if key not in latest or when >= latest[key][0]:
            latest[key] = (when, rec["snapshot"] or [])
    for (host, name, when), rows in events.items():
        if (host, name) not in latest or when >= latest[(host, name)][0]:
            latest[(host, name)] = (when, rows)
    hosts: dict[str, dict[str, list[dict]]] = {}
    for (host, name), (_, rows) in latest.items():
        hosts.setdefault(host, {})[name] = rows
    if not hosts:
        raise CollectorError(f"{path.name} holds no results from the oss-intake queries (osqueryd writes "
                             "snapshot queries to osqueryd.snapshots.log, not osqueryd.results.log)")
    return hosts


def _sql_string(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def run_local(dirs: list[Path], osqueryi: str = "osqueryi", notes: list[str] | None = None) -> dict[str, list[dict]]:
    exe = shutil.which(osqueryi)
    if not exe:
        raise CollectorError("osqueryi not found on PATH (macOS: brew install --cask osquery)")
    queries = dict(QUERIES)
    for i, d in enumerate(dirs):
        # Folder names are quoted as SQL string literals ('' for '), never pasted in as SQL.
        py_dir, npm_dir = _sql_string(_site_packages(d)), _sql_string(str(d.resolve()))
        queries[f"python_packages_dir{i}"] = (
            "SELECT name, version, directory FROM python_packages WHERE directory = " + py_dir)  # noqa: S608
        queries[f"npm_packages_dir{i}"] = (
            "SELECT name, version, directory FROM npm_packages WHERE directory = " + npm_dir)  # noqa: S608
    out: dict[str, list[dict]] = {}
    for name, sql in queries.items():
        proc = subprocess.run([exe, "--json", sql], capture_output=True, text=True, timeout=600)
        if proc.returncode != 0:
            # A table this platform does not have (deb_packages on macOS) is not an error.
            if "no such table" in proc.stderr:
                continue
            raise CollectorError(f"osqueryi failed on {name}: {proc.stderr.strip()[:300]}")
        try:
            out[name] = json.loads(proc.stdout or "[]")
        except ValueError:
            raise CollectorError(f"osqueryi returned something other than JSON for {name}") from None
    for i, d in enumerate(dirs):
        if not out.get(f"python_packages_dir{i}") and not out.get(f"npm_packages_dir{i}") and notes is not None:
            notes.append(f"--dir {d}: no Python or npm packages found there (give the venv or the folder that "
                         "holds node_modules)")
    return out


def _site_packages(d: Path) -> str:
    """A venv folder, or a project folder holding .venv or venv -> its site-packages folder; else as given."""
    roots = [d, d / ".venv", d / "venv"]
    for cand in [c for r in roots for c in sorted(r.glob("lib/python*/site-packages")) + [r / "Lib" / "site-packages"]]:
        if cand.is_dir():
            return str(cand.resolve())
    return str(d.resolve())


# --- writing -------------------------------------------------------------------------------------------------

def mask_home(path: str) -> str:
    return _HOME.sub("~", path or "")


def _q(v: str) -> str:
    return quote(str(v), safe="")


def _distro(os_rows: list[dict]) -> tuple[str, str]:
    """(platform, release) from os_version: ('ubuntu', '24.04'), ('debian', '12'), ('rocky', '9.3')."""
    if not os_rows:
        return "", ""
    o = os_rows[0]
    platform = str(o.get("platform") or "").lower()
    major, minor = str(o.get("major") or ""), str(o.get("minor") or "")
    if platform == "ubuntu" and major and minor.isdigit():
        return platform, f"{major}.{int(minor):02d}"
    if platform == "debian":
        return platform, major
    return platform, ".".join(x for x in (major, minor) if x)


def _pypi_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _npm_purl(name: str, version: str) -> str:
    if name.startswith("@") and "/" in name:
        scope, _, base = name.partition("/")
        return f"pkg:npm/{_q(scope)}/{_q(base)}@{_q(version)}"
    return f"pkg:npm/{_q(name)}@{_q(version)}"


def _component(name: str, version: str, purl: str | None, props: dict[str, str]) -> dict:
    c: dict = {"type": "library", "name": name, "version": version}
    if purl:
        c["purl"] = purl
    if props:
        c["properties"] = [{"name": k, "value": v} for k, v in props.items()]
    return c


def components(tables: dict[str, list[dict]]) -> tuple[list[dict], list[str]]:
    """(CycloneDX components, notes for the person running the collector)."""
    notes: list[str] = []
    platform, release = _distro(tables.get("os_version", []))
    out: list[dict] = []
    seen: set[tuple] = set()

    def add(c: dict) -> None:
        key = (c.get("purl") or c["name"], c["version"],
               tuple(sorted((p["name"], p["value"]) for p in c.get("properties", []))))
        if key not in seen:
            seen.add(key)
            out.append(c)

    if tables.get("os_version"):
        o = tables["os_version"][0]
        add(_component(str(o.get("name") or platform), str(o.get("version") or ""), None,
                       {"oss-intake:not-checked": NOT_CHECKED["os"]}))

    # dpkg status "want flag state": only config-files and not-installed leave no package files on disk. A
    # half-installed or half-configured package is still there, so it is checked like any other.
    debs = [r for r in tables.get("deb_packages", [])
            if str(r.get("status") or "install ok installed").split()[-1] not in ("config-files", "not-installed")]
    partial = sum(1 for r in debs if not str(r.get("status") or " installed").endswith(" installed"))
    if partial:
        notes.append(f"{partial} deb packages are not fully installed (dpkg status); they are checked anyway")
    deb_ok = platform in ("ubuntu", "debian") and bool(release)
    if debs and not deb_ok:
        if platform == "debian":
            why = "Debian testing or unstable: os_version gives no release number, so no advisory set fits"
        elif platform:
            why = (f"{platform}: oss-intake checks Ubuntu and Debian packages; a derivative has its own release "
                   "numbers")
        else:
            why = "os_version was not collected, so the release is unknown"
        notes.append(f"{len(debs)} deb packages written without a purl: {why}")
    for r in debs:
        name, version = str(r.get("name", "")), str(r.get("version", ""))
        if not name or not version:
            continue
        if not deb_ok:
            add(_component(name, version, None, {"oss-intake:not-checked": why}))
            continue
        epoch, _, plain = version.rpartition(":") if ":" in version else ("", "", version)
        quals = [f"arch={_q(r['arch'])}"] if r.get("arch") else []
        if epoch:
            quals.append(f"epoch={_q(epoch)}")
        quals.append(f"distro={_q(f'{platform}-{release}')}")
        src = str(r.get("source") or "").strip()
        m = _SRC_PARENS.match(src)
        if m:  # 'util-linux (2.39.3-9ubuntu6.6)': built from a source package with its own version
            quals.append(f"upstream={_q(m.group('name') + '@' + m.group('version'))}")
        elif src and src != name:
            quals.append(f"upstream={_q(src)}")
        add(_component(name, version, f"pkg:deb/{platform}/{_q(name)}@{_q(plain)}?{'&'.join(quals)}", {}))

    rpms = tables.get("rpm_packages", [])
    if rpms and not platform:
        notes.append(f"{len(rpms)} rpm packages: os_version was not collected, so the release is unknown")
    for r in rpms:
        name, version, rel = str(r.get("name", "")), str(r.get("version", "")), str(r.get("release", ""))
        if not name or not version:
            continue
        full = f"{version}-{rel}" if rel else version
        if not platform:
            add(_component(name, full, None, {"oss-intake:not-checked": "os_version was not collected, so the "
                                                                        "release is unknown"}))
            continue
        quals = [f"arch={_q(r['arch'])}"] if r.get("arch") else []
        if str(r.get("epoch") or "") not in ("", "0"):
            quals.append(f"epoch={_q(r['epoch'])}")
        quals.append(f"distro={_q(f'{platform}-{release}')}")
        if r.get("source"):
            quals.append(f"upstream={_q(r['source'])}")
        add(_component(name, full, f"pkg:rpm/{platform}/{_q(name)}@{_q(full)}?{'&'.join(quals)}", {}))

    # Leave the distro's own Python packages to its deb or rpm packages only where those are checked.
    os_managed = (bool(debs) and deb_ok) or (bool(rpms) and platform in ("rocky", "almalinux") and bool(release))
    skipped = 0
    for r in tables.get("python_packages", []):
        name, version = str(r.get("name", "")), str(r.get("version", ""))
        if name and version and os_managed and _OS_PYTHON.match(str(r.get("directory") or "")):
            skipped += 1
            continue
        if name and version:
            props = {"oss-intake:label:location": mask_home(str(r.get("directory") or "")).rstrip("/\\")}
            add(_component(name, version, f"pkg:pypi/{_q(_pypi_name(name))}@{_q(version)}",
                           {k: v for k, v in props.items() if v}))
    if skipped:
        notes.append(f"{skipped} Python packages in the distro's own folders left out: the {platform} packages "
                     "that installed them are checked instead")
    for r in tables.get("npm_packages", []):
        name, version = str(r.get("name", "")), str(r.get("version", ""))
        if name and version:
            props = {"oss-intake:label:location": mask_home(str(r.get("directory") or "")).rstrip("/\\")}
            add(_component(name, version, _npm_purl(name, version), {k: v for k, v in props.items() if v}))
    for table in ("homebrew_packages", "chocolatey_packages"):
        for r in tables.get(table, []):
            name, version = str(r.get("name", "")), str(r.get("version", ""))
            if name:
                add(_component(name, version, None, {"oss-intake:not-checked": NOT_CHECKED[table]}))
    return out, notes


def sbom(host: str, tables: dict[str, list[dict]]) -> tuple[dict, list[str]]:
    comps, notes = components(tables)
    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "oss-intake osquery collector",
                                      "version": TOOL_VERSION}]},
            "component": {"type": "device", "name": host},
        },
        "components": comps,
    }
    return doc, notes


def _safe_file_name(host: str, used: set[str]) -> str:
    """A file name for the host, unique even ignoring case (macOS, Windows): 'web 01' and 'web_01' must not
    overwrite each other."""
    import hashlib

    base = re.sub(r"[^A-Za-z0-9._-]+", "_", host).strip("._") or "host"
    name = base
    if name.casefold() in used:
        name = f"{base}-{hashlib.sha256(host.encode()).hexdigest()[:8]}"
    used.add(name.casefold())
    return name


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--results", type=Path, help="osquery snapshot result log (JSON lines), any number of hosts")
    src.add_argument("--json", type=Path, help='a saved {"query name": [rows]} object for one host')
    ap.add_argument("--dir", type=Path, action="append", default=[],
                    help="local run: also read Python and npm packages in this folder (a venv, a project)")
    ap.add_argument("--host", help="host name for the SBOM (default: osquery's hostname)")
    ap.add_argument("--out", type=Path, required=True, help="folder for the SBOM files")
    a = ap.parse_args(argv)
    try:
        if a.dir and (a.results or a.json):
            raise CollectorError("--dir applies to a local run; add WHERE directory queries to the pack instead")
        for d in a.dir:
            if not d.expanduser().is_dir():
                raise CollectorError(f"--dir {d}: not a folder")
        if a.results:
            hosts = read_results_log(a.results)
        else:
            run_notes: list[str] = []
            raw = (json.loads(a.json.read_text(encoding="utf-8")) if a.json
                   else run_local([d.expanduser() for d in a.dir], notes=run_notes))
            if not isinstance(raw, dict):
                raise CollectorError("--json: expected an object of query name to rows")
            info = group(raw).get("system_info") or [{}]
            hosts = {a.host or str(info[0].get("hostname") or "") or "this-host": raw}
        if a.host and len(hosts) > 1:
            raise CollectorError("--host names one host; the results hold several")
        a.out.mkdir(parents=True, exist_ok=True)
        used: set[str] = set()
        for host, results in sorted(hosts.items()):
            doc, notes = sbom(a.host or host, group(results))
            if not a.results:
                notes += run_notes
            target = a.out / f"{_safe_file_name(a.host or host, used)}.cdx.json"
            target.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
            checked = sum(1 for c in doc["components"] if "purl" in c)
            print(f"{target}: {len(doc['components'])} components, {checked} with a purl")
            for n in notes:
                print(f"  note: {n}")
    except (CollectorError, OSError, ValueError, subprocess.TimeoutExpired) as exc:
        print(f"osquery_sbom: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
