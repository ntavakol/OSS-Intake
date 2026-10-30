# Nexus collector and gate

`nexus_sbom.py` lists what a [Nexus Repository](https://www.sonatype.com/products/sonatype-nexus-repository)
proxy has cached, as one CycloneDX SBOM per repository, so oss-intake can check every package your developers
and builds have pulled through it. It needs Python 3.10 or later and nothing else.

## What is in the cache

```sh
export NEXUS_USERNAME=reader NEXUS_PASSWORD=...     # or NEXUS_TOKEN; a read-only account is enough
python3 nexus_sbom.py --url https://nexus.example.org --out nexus-sboms
oss-intake --path nexus-sboms/all --out report
```

Every proxy repository in a format oss-intake checks is read (npm, PyPI, Maven, NuGet, RubyGems, Go, Cargo,
CRAN), or only those named with `--repository`. Group repositories are skipped (their members are read), and so
are hosted ones, which hold your own packages that no public advisory database knows (`--include-hosted` lists
them anyway). Docker, apt, yum and other formats are named as not read.

Each SBOM component carries the package URL, the checksums of the cached file (SHA-512, SHA-256, SHA-1), and the
date Nexus first cached it (the `cached` label in packages.csv). Nexus also records which account first pulled
each file; the collector does not copy that.

Credentials are read from the environment, sent only to `--url`, never over plain http except to localhost, and
never printed. `--ca-file` takes the CA bundle of a Nexus with an internal certificate. Nexus pages this API
(often 10 components per page), so a large proxy takes a request per page; `--max-pages` (default 20,000 per
repository) stops a run that would never end. If any repository cannot be read in full, nothing is written.

## The gate: check what is new, on a schedule

With `--state`, the collector remembers what it has seen and also writes the components cached since the last
run to `nexus-sboms/new/`. Run it every few minutes or hourly, and let oss-intake fail on what you will not
accept:

```sh
python3 nexus_sbom.py --url https://nexus.example.org --out nexus-sboms --state nexus-state.json
if [ -n "$(ls nexus-sboms/new)" ]; then
    oss-intake --path nexus-sboms/new --out gate-$(date +%Y%m%d-%H%M) --fail-on malicious,recent,kev
fi
```

Exit code 3 means something matched the `--fail-on` list; send the report to whoever looks after the proxy,
and quarantine or remove the component in Nexus. Which list to use is a policy decision:

| `--fail-on` | Stops | Note |
|---|---|---|
| `malicious` | Releases listed as malicious (OSV, CWE-506 advisories) | Always worth having |
| `recent` | Versions published in the last `--release-age-days` (default 7) | Compromised releases are usually live for hours or days, before any advisory |
| `kev` | Packages with a known exploited vulnerability | |
| `critical` or `high` | Known critical (or high and critical) vulnerabilities | Old versions developers still need will trip this; expect exceptions |

This is an assessment that runs after a package is cached, not a block in front of it: Nexus has already served
the first download. To stop a package before anyone gets it, use Nexus's own firewall features, or route new
versions through a repository that is released only after this check.

## Try it with a throwaway Nexus

`try-nexus.sh` starts Nexus Community Edition in Docker on your machine (localhost only), caches a few
known-vulnerable packages through npm, PyPI and Maven proxies, runs the collector and oss-intake, then caches one
more package and runs the gate on just that one:

```sh
sh try-nexus.sh                    # NEXUS_PORT=18081 sh try-nexus.sh if port 8081 is taken
sh try-nexus.sh --remove           # delete the container and its data
```

Newer Community Edition releases need their licence accepted first; the script stops, links it and gives the
command that accepts it, since that decision is yours.
