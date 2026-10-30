# Nexus collector and gate

`nexus_sbom.py` lists what a [Nexus Repository](https://www.sonatype.com/products/sonatype-nexus-repository)
proxy has cached, as one CycloneDX SBOM per repository, so oss-intake can check every package your developers
and builds have pulled through it. It needs Python 3.10 or later and nothing else.

## What is in the cache

```sh
export NEXUS_USERNAME=reader NEXUS_PASSWORD=...     # a read-only account; for a user token, its name and pass codes
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

Credentials are read from the environment, sent only to `--url` (a redirect is refused rather than followed, so
they cannot reach a login page or another host), never over plain http except to localhost, and never printed.
Without credentials the collector reads anonymously and says so. Either way it lists only what that account can
see: repositories it has no read access to, and components hidden by content selectors, are not listed, so give
the account read access to every proxy you want covered. `--ca-file` takes the CA bundle of a Nexus with an internal certificate. Nexus pages this API
(often 10 components per page), so a large proxy takes a request per page; `--max-pages` (default 20,000 per
repository) stops a run that would never end. If any repository cannot be read in full, nothing is written;
`all/` always holds exactly the repositories of the last run.

## The gate: check what is new, on a schedule

With `--state`, every component not yet accepted goes to `nexus-sboms/new/`. A run never accepts anything:
`--accept` does, after the gate has passed. So a package that failed the gate, or a gate that could not run (OSV
unreachable), is listed again on the next run, until someone deals with it. Run all three steps in one job, every
few minutes or hourly, never two jobs at once on the same state file (the collector refuses a second run):

```sh
python3 nexus_sbom.py --url https://nexus.example.org --out nexus-sboms --state nexus-state.json || exit 1
if [ -n "$(ls nexus-sboms/new)" ]; then
    oss-intake --path nexus-sboms/new --out gate-$(date +%Y%m%d-%H%M) \
        --fail-on malicious,recent,unknown-age,kev || exit $?
fi
python3 nexus_sbom.py --state nexus-state.json --accept
```

Exit code 3 means something matched the `--fail-on` list: send the report to whoever looks after the proxy, and
remove or quarantine the component in Nexus, or accept it knowingly with `--accept`. Exit code 1 means the check
could not run fully; nothing is accepted. A component that leaves the cache and comes back is new again. Which
list to use is a policy decision:

| `--fail-on` | Stops | Note |
|---|---|---|
| `malicious` | Releases listed as malicious (OSV, CWE-506 advisories) | Always worth having |
| `recent` | Versions published in the last `--release-age-days` (default 7) | See the limits below |
| `unknown-age` | Versions with no release date on deps.dev | Closes the gap below; RubyGems and CRAN always trip it |
| `kev` | Packages with a known exploited vulnerability | |
| `critical` or `high` | Known critical (or high and critical) vulnerabilities | Old versions developers still need will trip this; expect exceptions |

What `recent` cannot see: release dates come from deps.dev, which covers npm, PyPI, Maven, NuGet, Go and Cargo
but not RubyGems or CRAN, and which may not list a version published only hours ago, the window in which a
compromised release usually does its harm. `recent` names such versions in a warning but passes them, and once
accepted they are not listed again. `unknown-age` fails on them instead: a version only hours old stays on the
list until deps.dev has a date for it (usually within a day), and is then checked properly. RubyGems and CRAN
versions never get a date, so with `unknown-age` they always need someone to look and `--accept` them.

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
