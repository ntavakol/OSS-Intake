# osquery collector

`osquery_sbom.py` turns [osquery](https://osquery.io)'s package tables into one CycloneDX SBOM per host, which
oss-intake checks like any other SBOM folder. It needs Python 3.10 or later and nothing else; osquery is used,
never bundled.

## One machine

```sh
python3 osquery_sbom.py --out sboms
oss-intake --path sboms --out report
```

osquery's `python_packages` and `npm_packages` tables only read default locations: the system and user
site-packages, and global `node_modules`. Packages in a virtualenv or a project's `node_modules` are not seen
unless you name the folder:

```sh
python3 osquery_sbom.py --out sboms --dir ~/projects/app/.venv --dir ~/projects/web
```

A venv folder, or a project folder holding `.venv` or `venv`, is read through its `site-packages`; any folder
through its `node_modules`. A `--dir` that yields no packages gets a note, so a wrong path is not silent.

## A fleet

Load `oss-intake-pack.conf` as an osquery pack (or add its queries to Fleet). Each query runs daily as a
snapshot, which lists everything installed, not just what changed. Then point the collector at the result
logs:

```sh
python3 osquery_sbom.py --out sboms --results /var/log/osquery/osqueryd.snapshots.log
oss-intake --path sboms --out report
```

osqueryd's filesystem logger writes snapshot queries to `osqueryd.snapshots.log`, not `osqueryd.results.log`.
Both snapshot forms are read: one line per snapshot (the default) and one line per row
(`--logger_snapshot_event_type`). It writes one SBOM per `hostIdentifier`, keeping the latest snapshot of each
query. The default `hostIdentifier` is the host name, so cloned machines that share one (`localhost`) are
merged; set `--host_identifier=uuid` in the fleet's osquery flags to keep them apart. Differential results
(`"snapshot": false`) are refused, because they hold changes, not a full list. Query names only need to contain
the table name (`pack/Global/python_packages_app` works), so you can add your own `WHERE directory = '...'`
queries for application folders.

To check what the collector made of a host, open its `.cdx.json`; every component without a `purl` has an
`oss-intake:not-checked` property with the reason.

## What is checked, and what is not

| osquery table | Checked as | Notes |
|---|---|---|
| `deb_packages` | Ubuntu and Debian advisories in OSV, by source package | Derivatives (Mint, Pop!_OS) use their own release numbers and are listed as not checked |
| `rpm_packages` | Rocky Linux and AlmaLinux advisories in OSV | RHEL, Amazon Linux, CentOS and Fedora are listed with the reason (no usable OSV data) |
| `python_packages` | PyPI | See below for the distro's own folders |
| `npm_packages` | npm | Global packages unless folders are given |
| `homebrew_packages`, `chocolatey_packages`, `os_version` | Not checked | No advisory database covers them; listed in the report, never counted as clean |

osquery has no Alpine (`apk`) table; for Alpine images use [examples/sbom](../sbom) instead.

Home folders are shortened (`/Users/ned/app` becomes `~/app`, `/root/x` becomes `~/x`, Windows
`C:\Users\ned` becomes `~`), so user names in paths do not reach reports; the folder appears as each package's
`location` label in `packages.csv`. Host names are another matter: the host name comes from osquery
(`system_info.hostname`, or the log's `hostIdentifier`) and often carries a user name (`Neds-MacBook-Pro`). Use
`--host` to set your own for one machine, or `--host_identifier=uuid` for a fleet.

Python packages are read for every user (`users CROSS JOIN python_packages`), which needs osquery to run as
root or Administrator to see other users' folders. Packages that the distro itself installed, in
`/usr/lib/python3/dist-packages` and similar, are left to the deb or rpm package only where that package is
checked (Ubuntu, Debian, Rocky Linux, AlmaLinux); elsewhere they are checked as PyPI packages, which may report
issues the distro has patched.
