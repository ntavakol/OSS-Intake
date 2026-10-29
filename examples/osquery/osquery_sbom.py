#!/usr/bin/env python3
"""Turn osquery package tables into one CycloneDX SBOM per host, for `oss-intake --path <folder>`.

Three ways in:

  python3 osquery_sbom.py --out sboms                   run osqueryi on this machine
  python3 osquery_sbom.py --out sboms --dir ~/app/.venv  ... and also read packages in these folders
  python3 osquery_sbom.py --out sboms --results osqueryd.results.log
                                                        osquery snapshot result logs (osqueryd, Fleet or any
                                                        log pipeline): one SBOM per hostIdentifier
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

Home folders are shortened (/Users/ned/app -> ~/app) so user names do not reach reports. The host name is
osquery's hostname, or --host to set your own (a hostIdentifier for --results).

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
    "python_packages": "SELECT name, version, directory FROM python_packages",
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
_HOME = re.compile(r"^(/root(?=/|$)|(/Users|/home|[A-Za-z]:\\Users)[/\\][^/\\]+)")
# Python packages the distro installed (python3-yaml puts PyYAML in /usr/lib/python3/dist-packages). The distro
# patches them without changing the upstream version, so a PyPI check would report fixed issues; the deb or rpm
# package covers them.
_OS_PYTHON = re.compile(r"^/usr/(lib|lib64|share)/python[0-9.]*/(dist|site)-packages")
_SRC_PARENS = re.compile(r"^(?P<name>\S+)\s*\((?P<version>[^)]+)\)$")


class CollectorError(Exception):
    pass


# --- reading -------------------------------------------------------------------------------------------------

def table_of(query_name: str) -> str | None:
    """'pack/oss-intake/python_packages_app' -> 'python_packages'."""
    last = re.split(r"[/:]", query_name)[-1].lower().removeprefix("oss_intake_").removeprefix("oss-intake_")
    for t in sorted(TABLES, key=len, reverse=True):
        if last == t or last.startswith(t + "_"):
            return t
    short = {"os": "os_version", "deb": "deb_packages", "rpm": "rpm_packages", "python": "python_packages",
             "npm": "npm_packages", "homebrew": "homebrew_packages", "chocolatey": "chocolatey_packages"}
    return short.get(last)


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
    """osquery snapshot result logs (one JSON object per line) -> {host: {query name: rows}}, keeping each
    host's latest snapshot of each query. Differential results cannot give a full list and are refused."""
    latest: dict[tuple[str, str], tuple[int, list]] = {}
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
        if "snapshot" not in rec:
            raise CollectorError(f"{path.name} line {n}: query {rec.get('name')} is a differential result; "
                                 "set \"snapshot\": true for it (see oss-intake-pack.conf)")
        host = str(rec.get("hostIdentifier") or rec.get("decorations", {}).get("hostname") or "unknown-host")
        key = (host, str(rec["name"]))
        when = int(rec.get("unixTime") or 0)
        if key not in latest or when >= latest[key][0]:
            latest[key] = (when, rec["snapshot"] or [])
    hosts: dict[str, dict[str, list[dict]]] = {}
    for (host, name), (_, rows) in latest.items():
        hosts.setdefault(host, {})[name] = rows
    if not hosts:
        raise CollectorError(f"{path.name} holds no results from the oss-intake queries")
    return hosts


def _sql_string(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def run_local(dirs: list[Path], osqueryi: str = "osqueryi") -> dict[str, list[dict]]:
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
    return out


def _site_packages(d: Path) -> str:
    """A venv folder -> its site-packages folder; any other folder as given."""
    for cand in sorted(d.glob("lib/python*/site-packages")) + [d / "Lib" / "site-packages"]:
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

    debs = [r for r in tables.get("deb_packages", []) if str(r.get("status", "install ok installed"))
            .endswith(" installed")]
    if debs and platform not in ("ubuntu", "debian"):
        why = (f"{platform or 'this distro'}: oss-intake checks Ubuntu and Debian packages; a derivative has "
               "its own release numbers" if platform else "os_version was not collected, so the release is "
               "unknown")
        notes.append(f"{len(debs)} deb packages written without a purl: {why}")
    for r in debs:
        name, version = str(r.get("name", "")), str(r.get("version", ""))
        if not name or not version:
            continue
        if platform not in ("ubuntu", "debian"):
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

    os_managed = bool(debs or rpms) and platform not in ("darwin", "windows")
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


def _safe_file_name(host: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", host).strip("._") or "host"


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
            raw = (json.loads(a.json.read_text(encoding="utf-8")) if a.json
                   else run_local([d.expanduser() for d in a.dir]))
            if not isinstance(raw, dict):
                raise CollectorError("--json: expected an object of query name to rows")
            info = group(raw).get("system_info") or [{}]
            hosts = {a.host or str(info[0].get("hostname") or "") or "this-host": raw}
        if a.host and len(hosts) > 1:
            raise CollectorError("--host names one host; the results hold several")
        a.out.mkdir(parents=True, exist_ok=True)
        for host, results in sorted(hosts.items()):
            doc, notes = sbom(a.host or host, group(results))
            target = a.out / f"{_safe_file_name(a.host or host)}.cdx.json"
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
