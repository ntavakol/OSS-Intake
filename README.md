# oss-intake

[![ci](https://github.com/ntavakol/OSS-Intake/actions/workflows/ci.yml/badge.svg)](https://github.com/ntavakol/OSS-Intake/actions/workflows/ci.yml)
[![codeql](https://github.com/ntavakol/OSS-Intake/actions/workflows/codeql.yml/badge.svg)](https://github.com/ntavakol/OSS-Intake/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/ntavakol/OSS-Intake/badge)](https://scorecard.dev/viewer/?uri=github.com/ntavakol/OSS-Intake)
[![PyPI](https://img.shields.io/pypi/v/oss-intake)](https://pypi.org/project/oss-intake/)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/15943/badge)](https://www.bestpractices.dev/projects/15943)

**Evidence for deciding whether to adopt, keep or replace an open source component.** `oss-intake` runs
Trivy and Grype, checks OSV, and turns the results into a reading order: malicious packages and exploited
vulnerabilities first, findings that apply only under stated conditions separately, the rest as routine. It
adds what a scanner alone does not: how long fixes have existed without being shipped, public exploit
evidence, the advisory's own conditions, reachability for Go binaries, and project health.

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/ntavakol/OSS-Intake/main/docs/images/report-dark.png">
  <img alt="oss-intake report on a lockfile with six compromised npm releases: six malicious packages flagged first" src="https://raw.githubusercontent.com/ntavakol/OSS-Intake/main/docs/images/report-light.png" width="900">
</picture>

**[See the live sample report](https://ntavakol.github.io/OSS-Intake/samples/compromised-npm/report.html):**
six trusted npm packages (chalk, debug, @ctrl/tinycolor, ua-parser-js, event-stream, flatmap-stream), one
compromised release of each, all flagged as malicious. Read
[why that is the case for scanning on a schedule](https://ntavakol.github.io/OSS-Intake/), not once at
approval.

## Quickstart

```bash
pipx install oss-intake
# install Trivy and Grype, pinned and verified: see "Install the scanners yourself" below
oss-intake scan --path package-lock.json --out report
oss-intake scan --image <image:tag> --repo <owner/name> --out report
```

Open `report/report.html`. The full list, with triage columns for the assessor, is `report/findings.csv`.

## What it answers

1. **Is any of it malicious?** Package versions known as malware, from the OpenSSF malicious packages
   database or advisories classed as embedded malicious code.
2. **Is it vulnerable, and what matters first?** Known vulnerabilities in a container image, an artifact or a
   lockfile, with exploit evidence and a suggested triage group for each.
3. **Does the project patch?** Whether fixes that exist upstream are being shipped, how long they have been
   available, and how active the project is.

The third question is what a scanner alone does not answer. `oss-intake` measures **release lag**: findings
where the fixed version of a dependency was already published before the project's release, so the project
could have shipped it and did not. It then adds project health signals (release cadence, OpenSSF Scorecard,
CISA KEV membership).

## What it does

- Runs [Trivy](https://github.com/aquasecurity/trivy) and, if installed, [Grype](https://github.com/anchore/grype)
  against an image, and queries [OSV.dev](https://osv.dev) for the language packages Trivy found.
- Merges the results into one row per vulnerability, package and version, recording which sources saw it.
- Looks up when each fixed dependency version was published ([deps.dev](https://deps.dev)) and compares that
  with the project's GitHub release date.
- Reports release cadence from the GitHub API and the OpenSSF Scorecard score where one exists.
- Audits the project's own GitHub Actions workflows: unpinned actions, known-bad action versions (such as the
  compromised `trivy-action` tags), missing or write-all token permissions, and `pull_request_target` triggers.
- Optionally suggests a likelihood value for a 5x5 risk matrix from configurable rules, clearly labelled
  as a heuristic.
- Writes `findings.csv`, `summary.md`, `assessment.json` and a self-contained `report.html`, plus the raw
  scanner output under `raw/` as evidence.
- Applies integrity checks to the scanners it runs: version pinning, a known-bad version list, SHA-256
  verification and optional Sigstore (cosign) verification.

## What it does not do

- **It does not prove exploitability.** Scanners match component versions against advisory databases. A
  finding means a version is listed as affected, not that the vulnerable code is reachable or exposed in your
  deployment. The CSV has `triage_*` columns for the assessor's decisions, which carry over to the next run.
- It does not install, download, bundle or redistribute scanners. You install them; it verifies them.
- It does not assess licences, secrets or misconfiguration, and it does not detect new malware. Package versions
  already known as malware are flagged as malicious: listed in the OpenSSF malicious packages database (OSV `MAL-`
  entries), or covered by an advisory classed as embedded malicious code (CWE-506), as the compromised
  ua-parser-js 0.7.29 and event-stream 3.3.6 releases are.
- It does not give a risk rating. The likelihood suggestion is a starting point for an assessor.
- It does not fix anything or open issues upstream.

## Install

Python 3.10 or later on Windows, macOS or Linux. No administrator rights are needed.

```bash
pipx install oss-intake
```

Releases are published to PyPI from GitHub Actions through trusted publishing, so PyPI shows each file's
provenance (which workflow in this repository built it). Each GitHub release also carries a Sigstore signature
bundle (`.sigstore.json`) for every file, verifiable with [sigstore-python](https://github.com/sigstore/sigstore-python).

Windows PowerShell without pipx:

```powershell
py -m pip install --user pipx
py -m pipx ensurepath
# open a new terminal, then
pipx install oss-intake
```

If `oss-intake` is "not recognized" after `pip install --user`, the per-user Scripts folder is not on PATH.
Either add it, or run the tool through Python, which works everywhere:

```powershell
py -m oss_intake --help
```

### Install the scanners yourself, pinned and verified

Install a specific version of each scanner from its official GitHub release, never "latest", and verify the
download before you extract it. `oss-intake verify` does the hash comparison correctly on any platform
(checksum files are served as `application/octet-stream`; they are parsed as bytes, with BOM and CRLF handled):

```bash
oss-intake verify --file trivy_0.76.1_windows-64bit.zip --checksums trivy_0.76.1_checksums.txt
```

Then record the SHA-256 of the extracted executable and pass it on every run (`oss-intake doctor` prints it):

```bash
oss-intake doctor
```

Or keep the release files and let each run check the whole chain before the scanner executes: the cosign
signature on the checksums file, the archive's SHA-256 in it, and the executable byte-for-byte against the one in
the archive. Trivy and Grype both sign their checksums file (Trivy also each archive); neither signs the
extracted executable.

```bash
oss-intake --image owner/app:1.2.3 --out ./reports --trivy-version 0.76.1 \
  --trivy-archive trivy_0.76.1_Linux-64bit.tar.gz --trivy-checksums trivy_0.76.1_checksums.txt \
  --trivy-cosign-bundle trivy_0.76.1_checksums.txt.sigstore.json
```

Trivy versions 0.69.4, 0.69.5 and 0.69.6 were malicious (CVE-2026-33634, March 2026). `oss-intake` refuses to
run any version on its [known-bad list](https://github.com/ntavakol/OSS-Intake/blob/main/src/oss_intake/data/known_bad.json).

## Usage

```bash
oss-intake --image owner/app:1.2.3 --repo owner/app --out ./reports \
  --image-src remote --trivy-version 0.76.1 --trivy-sha256 <sha256-of-trivy-executable> --likelihood
```

PowerShell (backtick continues a line):

```powershell
$env:GITHUB_TOKEN = "<optional token, raises the GitHub API rate limit>"
oss-intake --image owner/app:1.2.3 --repo owner/app --out .\reports `
  --image-src remote --trivy-version 0.76.1 --trivy-sha256 <sha256> --likelihood
```

Without a container image, assess a file or folder directly with `--path`:

```bash
oss-intake --path ./vendor-app-2.4.1.jar --repo owner/app --out ./reports   # JAR, WAR, EAR or binary
oss-intake --path ./requirements.txt --repo owner/app --release-tag v1.4.0 --out ./reports
oss-intake --path ./renv.lock --repo owner/app --release-tag v1.4.0 --out ./reports
```

A JAR, WAR, EAR or binary is scanned as built artifacts (Trivy `rootfs`, Grype `dir:`), and a version in its
file name is tried as the release tag. A JAR, WAR or EAR, a Python wheel or sdist, or an npm `.tgz` is also
compared with the checksum its registry publishes for that exact version: Maven Central (coordinates from the
archive's `pom.properties`; the strongest of SHA-512, SHA-256 and SHA-1 it publishes), PyPI (SHA-256) or npm
(SHA-512). A mismatch means the file is not the one the project released (rebuilt, repackaged or tampered with)
and leads the report; a match proves only that the file is the published one, not that it is safe. A fat JAR
that bundles several projects cannot be checked this way. `--no-registry-check` or `--offline` skips it. Lockfiles the scanners understand (Python, npm, Maven, Go, Rust, PHP,
Ruby, .NET) are scanned with Trivy `fs`. An R `renv.lock` is read by oss-intake and checked against OSV's CRAN
advisories, since neither scanner reads it; packages from Bioconductor, GitHub or local sources are listed as
not checked. A folder is scanned as built artifacts; for a source checkout, pass its lockfile. Release lag needs
the project's release: `--repo` with `--release-tag`, or `--release-date`.

### Package inventory

To check the open source an organisation already uses, pass a CSV list of packages, for example exported from
Artifactory or Nexus, or kept in a spreadsheet (save it from Excel as "CSV UTF-8"):

```bash
oss-intake --path ./packages.csv --out ./reports
```

To re-scan it every week and get an issue when something new needs action, copy the ready-made GitHub workflow in
[examples/scheduled-rescan](https://github.com/ntavakol/OSS-Intake/tree/main/examples/scheduled-rescan).

```csv
ecosystem,name,version,owner,system
npm,@ctrl/tinycolor,4.1.1,Web team,Customer portal
pypi,django,3.2.0,Data team,Reporting
maven,org.apache.logging.log4j:log4j-core,2.14.1,Platform team,Payments
```

Use either `ecosystem`, `name` and `version` columns, or one `purl` column (`pkg:npm/chalk@5.6.1`). Ecosystems:
npm, pypi, maven (`group:artifact`), go, nuget, cargo, gem, composer, cran, hex and pub, plus common aliases
such as python or java. Versions must be exact: ranges such as `^1.2` or `latest` are rejected. Any other
column (owner, system, team...) is carried through to the reports as a label. Every row is validated first: if
any row is invalid, the run stops and lists each problem with its row number, before anything is looked up.

No scanner is needed: each package version is checked against OSV, so malicious releases are flagged as well as
vulnerable ones. Besides the usual reports, `packages.csv` lists every package, worst first, with its findings
and label columns, and an upgrade comparison:

- **Upgrade to at least:** the lowest version that fixes every listed vulnerability with a fix, and what is
  still known to affect that version (`1.2.0 · 1 known` means the minimum fix is not enough on its own).
- **Latest release:** the package's current release on deps.dev and what is known to affect it. Skip this lookup
  (one request per package) with `--no-latest` to see the current state and the minimum fix only.
- **major:** the upgrade crosses a major version, or a minor version below 1.0, so expect breaking changes.

Fewer known vulnerabilities is not proof that a version is safe: it may be less studied, or newer than the
advisories. The HTML report shows the packages that need attention.

Inventory runs also write `executive-summary.html`: one page for someone who will not read the findings. It
gives the packages checked, how many need action now (malicious or known exploited), have critical
vulnerabilities, or have had no release for over a year; the top packages to act on with the action for each;
totals by owner (from an `owner`, `team`, `system` or `application` column); and the known vulnerabilities now,
after upgrading to the minimum fixes, and after upgrading to the latest releases. When `--decisions` points at
the previous run's `findings.csv`, it also shows what changed since then: new findings and findings no longer
present. Run it on a schedule: a package that was clean when approved can turn
out vulnerable or compromised later. A sample is in
[examples/inventory](https://github.com/ntavakol/OSS-Intake/blob/main/examples/inventory/packages.sample.csv).

All inputs are validated before any scanner runs. The image must carry an explicit tag or digest.

| Option | Purpose |
|---|---|
| `--out` | Output directory (required) |
| `--image` | Image with explicit tag or digest |
| `--path` | A JAR, WAR, binary, folder, lockfile, `renv.lock` or package inventory `.csv` instead of an image |
| `--reachability`, `--govulncheck-path` | Check Go binaries with govulncheck (see Go reachability) |
| `--govulncheck-sha256`, `--govulncheck-version` | Pin govulncheck like the scanners: hash checked before it runs, version after. The Docker or crane executable used to copy binaries out of an image is recorded with its SHA-256 in assessment.json |
| `--repo` | GitHub `owner/name` (a full GitHub URL is accepted) |
| `--image-src remote` | Pull from the registry without Docker installed (Trivy `--image-src remote`, Grype `registry:`) |
| `--platform` | Image platform for both scanners (default `linux/amd64`, so Apple Silicon scans the same variant as a server); `''` uses scanner defaults |
| `--scanners` | `auto` (default: Trivy and OSV, plus Grype if found) or a list such as `trivy,grype,osv` |
| `--trivy-version`, `--grype-version` | Required scanner version; the run fails on mismatch |
| `--trivy-sha256`, `--grype-sha256` | Expected SHA-256 of the executable, checked before it is run at all |
| `--trivy-archive`, `--grype-archive` | The release archive the executable came from; the executable must be byte-for-byte the one inside it |
| `--trivy-checksums`, `--grype-checksums` | The release checksums file, which must list the archive's SHA-256 |
| `--trivy-cosign-bundle`, `--grype-cosign-bundle` | Verify the release's Sigstore bundle with cosign (on PATH): against the checksums file when given, otherwise the archive. Trivy signs its archives and checksums file, Grype only its checksums file; neither signs the extracted executable, so a bundle needs the archive |
| `--trivy-arg`, `--grype-arg` | Pass extra arguments, e.g. `--trivy-arg=--db-repository=ghcr.io/aquasecurity/trivy-db:2` |
| `--from-trivy-json`, `--from-grype-json` | Use an existing JSON report instead of running the scanner; a file that is not that scanner's report is refused (exit 2) |
| `--release-tag`, `--release-date` | Set the release the image corresponds to, when tags do not match |
| `--grace-days` | A fix must predate the release by this many days to count as missed (default 14) |
| `--unshipped-days` | Days a fix must be public, with no newer release, to count as unshipped (default 90) |
| `--as-of` | Fix the assessment date for reproducible reports |
| `--min-severity` | Drop findings below a severity |
| `--formats` | Any of `csv,md,json,html` (default all; `findings.csv` is always written) |
| `--offline` | No network enrichment (OSV, deps.dev, GitHub, Scorecard, KEV, EPSS, exploit sources) |
| `--no-epss`, `--no-kev`, `--no-scorecard`, `--no-fix-dates`, `--no-exploits` | Skip one enrichment source (`--release-age-days 0` skips the new-release check) |
| `--no-latest` | Package inventories: skip the latest-release lookup (the minimum fix is still checked) |
| `--no-registry-check` | Skip comparing a JAR, wheel, sdist or npm `.tgz` with its registry's published checksum |
| `--decisions FILE` | Carry assessor decisions into this run: an earlier `findings.csv` with the triage columns filled in, or OpenVEX |
| `--no-workflows` | Skip the audit of the project's GitHub Actions workflows |
| `--trivy-path`, `--grype-path` | Use a scanner executable that is not on PATH |
| `--trivy-cosign-identity`, `--grype-cosign-identity` | Certificate identity (regexp) the cosign bundle must match |
| `--timeout` | Seconds before a scanner run is abandoned (default 1800) |
| `--top` | Number of findings listed in the summary (default 25; all are in findings.csv) |
| `--quiet` | Print only the result line and errors |
| `--likelihood`, `--likelihood-config FILE` | Add the 5x5 likelihood heuristic, with optional custom rules |
| `--fail-on-likelihood N` | Exit code 3 when the suggestion is N or higher, for pipelines |
| `--fail-on LIST` | Exit code 3 when any is found, for CI: `malicious`, `kev`, `act` (Act now), `critical`, `high` (high or critical), `recent` (a release newer than `--release-age-days`), `mismatch` (registry checksum). Findings set aside by evidence or a decision do not count, apart from malicious packages. A gate whose check is turned off is refused (exit 2); one whose check could not run fully fails with exit 1 rather than passing |
| `--release-age-days N` | Flag language package versions published fewer than N days ago (default 7; `0` turns it off). Compromised releases are usually live only for hours or days, before any advisory exists. One deps.dev request per package version, up to 400 |
| `--sbom` | Also write a CycloneDX SBOM to `raw/` |

Other commands: `oss-intake doctor` (scanner paths, versions, hashes and known-bad status; `--trivy-path` and
`--grype-path` as for `scan`) and `oss-intake verify`, which checks a downloaded file:

| `verify` option | Purpose |
|---|---|
| `--file` | The downloaded file to check (required) |
| `--checksums` | A `sha256sum`-style checksums file from the release, e.g. `trivy_0.76.1_checksums.txt` |
| `--sha256` | An expected SHA-256 instead of a checksums file |
| `--name` | The entry to look up in the checksums file (default: the file's name) |
| `--cosign-bundle`, `--cosign-identity` | Also verify a Sigstore bundle with cosign, against a certificate identity regexp |

Exit codes: `0` success, `1` error (including any integrity failure, a scanner failure, or an OSV outage when OSV
is the only source), `2` invalid input (found before any scanning), `3` a `--fail-on` or `--fail-on-likelihood`
threshold reached.

When a source was not consulted (`--offline`, `--no-kev`, `--no-exploits`, `--no-epss`, a failed download, or no
OSV query), the reports show it as "not checked" in grey rather than as a green zero, the Routine reasons say
which checks did not run, assessment.json records each source's state under `checks`, and the summary line ends
with `not_checked=` and the sources concerned.

`GITHUB_TOKEN` is optional. It is only sent to `api.github.com`, and it is never logged or written to reports.

## How release lag is measured

For each finding with a fix, `oss-intake` picks the nearest fixed version above the installed one (so a fix on
an older branch is not counted for a newer one) and looks up when that version was published.

| Metric | Meaning |
|---|---|
| Fix exists upstream | A fixed version of the dependency is known |
| **Fix existed before release** | The fixed version was published at least `--grace-days` (14) days before the project's release: the project could reasonably have shipped it |
| Fix within grace period | Published in the 14 days before release; shown but not counted as missed |
| **Unshipped** | Forward-looking: the fix has been public for `--unshipped-days` (90) or more and the scanned release is still the project's latest |
| Likely already fixed | Installed version equals a listed fix apart from a build label such as `.jre11`; flagged and excluded from lag |
| Fix published after release | The fix arrived later; this is normal lag for the next release |
| Days a fix has been available | Assessment date minus the fixed version's publish date |
| CVE published before release | Secondary signal. A CVE can be public before any fix exists, so this overstates lag on its own |

Fix dates come from deps.dev for language packages, from Packagist for PHP Composer packages, falling back to the GitHub release date for Go modules
hosted on GitHub that deps.dev does not index. For Debian packages they come from the Debian security advisory
that shipped the fix (DSA or DLA, by the scanner's advisory ID or the exact fixed version), dated from the Debian
security tracker's advisory lists, with OSV as a fallback. Fixes that shipped without an advisory are dated from the
Debian point release (13.6 and so on) that included the fixed version, from the suite's ChangeLog; fixes still in
proposed-updates stay unknown, with a note. For Ubuntu packages they come from the Ubuntu
Security Notice (USN) that fixed the CVE in that release and source package at that version, found through OSV;
failing that, from Launchpad's publishing history: when that exact version was first published to the release in
the Release, Security or Updates pocket.
For RHEL and UBI packages they come from the Red Hat advisory (RHSA) that Trivy reports, dated from Red Hat's
CSAF document. For Alpine packages they come from the aports commit history on the image's release branch: a commit naming the
CVE, or the fixed version for a new upstream release (set `GITHUB_TOKEN`, one request per package).
For the Go standard library they come from the Go release history (go.dev/doc/devel/release).
Packages with no dated source yet, currently Amazon Linux and runtimes detected only from a binary, are counted as
"fix date unknown" rather than guessed. The `fix_date_source` column in findings.csv shows where each date came from.

## Example output

Taken from the synthetic test fixtures (`tests/fixtures`, fictional project `example/webapp`) so it shows
the format, not a judgement of any real project. This section is regenerated from the code by
`scripts/readme_sync.py`, and the test suite fails if it falls out of date. A real report on six compromised npm
releases is in the [live sample](https://ntavakol.github.io/OSS-Intake/samples/compromised-npm/report.html).

<!-- generated:example-output -->
```text
findings=7 critical=2 high=4 with_fix=6 fix_before_release=4 fix_date_unknown=0 likelihood=5(Almost certain,confidence=normal)
```

| Group | ID | Severity | CVSS | Exploit | Package | Installed | Fix | Fix before release | Days fix available |
|---|---|---|---|---|---|---|---|---|---|
| Act now | CVE-2099-0003 | HIGH | 7.5 (3.1, ghsa) | known exploited | io.netty:netty-codec-http | 4.1.100.Final | 4.1.108.Final | yes | 244 |
| Act now | CVE-2099-0005 | HIGH | 7.5 (3.1, ghsa) | weaponised | com.fasterxml.jackson.core:jackson-databind | 2.17.0 | 2.17.1 | yes | 221 |
| Act now | CVE-2099-0002 | HIGH | 7.5 (3.1, ghsa) | weaponised | com.fasterxml.jackson.core:jackson-databind | 2.17.0 | 2.17.2 | no | 129 |
| Review | CVE-2099-0001 | CRITICAL | 9.8 (3.1, ghsa) | none indexed | org.springframework:spring-web | 6.1.10 | 6.1.12 | yes | 290 |
| Review | CVE-2099-0006 | CRITICAL | 9.8 (3.1, ghsa) | public exploit | com.fasterxml.jackson.core:jackson-databind | 2.17.0 | 2.17.3 | no | 113 |
| Routine | CVE-2099-0004 | HIGH | 7.1 (3.1, ghsa) | proof of concept | org.springframework:spring-web | 6.1.10 | none | no fix | n/a |
| Routine | CVE-2099-1000 | MEDIUM | 7.5 (3.1, ghsa) | none indexed | libc6 | 2.39-0ubuntu8.4 | 2.39-0ubuntu8.5 | yes | 254 |
<!-- /generated:example-output -->

The summary also covers scope (scanner versions, database dates, hash verification), project health,
agreement between sources and any warnings. See [docs/validation.md](https://github.com/ntavakol/OSS-Intake/blob/main/docs/validation.md) for checking the
tool against a real public image.

## Exploit availability and advisory conditions

Each finding gets the strongest public exploit evidence found: known exploited (CISA KEV), weaponised (a
Metasploit module or Nuclei template), public (Exploit-DB), proof of concept (GitHub repositories only, which
are noisy and sometimes malicious), or none indexed. "None indexed" means none was found in those sources, not
that none exists; when a source cannot be reached the finding is "not checked" instead. The `conditions`
column quotes the advisory's own statement of when the finding applies (for example "only if the application
uses XsltView"), word for word, so the assessor can check it against the deployment.

## Go reachability (optional)

With `--reachability`, Go binaries in the scan are checked with Go's official
[govulncheck](https://go.dev/doc/security/vuln/) in binary mode, which reports whether a vulnerable function is
actually linked into the binary. Install it yourself (`go install golang.org/x/vuln/cmd/govulncheck@v1.1.4`);
oss-intake never downloads it. For an image, the binaries are copied out with Docker (`docker create` and
`docker cp`) or `crane export`. A finding whose vulnerable functions are absent from every binary it was seen
in is marked "not reachable" and set aside in triage, with the govulncheck ID as the reason; one whose function
is present is marked "reachable". Counts and likelihood do not change: the vulnerable version is still shipped.
This covers Go only; for other languages the advisory conditions are the assessor's guide.

## Suggested triage

Each finding is placed in one group, with its reason, as a reading order for the engineer: **Act now** (a known
malicious package, CISA KEV, or a Metasploit or Nuclei exploit), **Review** (an Exploit-DB exploit, EPSS 0.1 or more, or a critical whose
advisory states no conditions), **Check conditions** (the advisory says when it applies; confirm against the
deployment), **Routine** (none of these) and **Set aside** (only with evidence: a kernel header package, the
installed version already matches a fix, govulncheck shows the vulnerable function is not in the binary, or the
assessor recorded the finding as not affected or fixed). No group says a finding carries no risk.

## Carrying decisions between runs

Scanning on a schedule only works if a finding assessed once does not have to be assessed again. Each run's
`findings.csv` has three columns for the assessor:

| Column | Values |
|---|---|
| `triage_status` | `not_affected`, `affected`, `fixed` or `under_investigation` (OpenVEX statuses; "false positive", "risk accepted", "patched" and "investigating" are accepted too), or `mitigated` for a compensating control: not affected, with the justification `inline_mitigations_already_exist`, never reported as fixed |
| `triage_notes` | Why. Required for `not_affected` and `mitigated`. Line breaks and a leading `-`, `=`, `+` or `@` are kept exactly |
| `triage_reachable` | `no` records that the vulnerable code is not in the execution path |
| `triage_justification` | Optional OpenVEX justification for `not_affected`, e.g. `component_not_present` or `vulnerable_code_not_present`; filled in from an OpenVEX file |

Fill them in for the findings you have assessed, then pass the file to the next run:

```bash
oss-intake --image owner/app:1.5.0 --repo owner/app --out ./reports-2 --decisions ./reports-1/findings.csv
```

Each decision applies to the same vulnerability (by ID or alias) in the same package; when there are decisions for
several versions, the one for the installed version wins. For OS packages an OpenVEX product such as
`pkg:deb/ubuntu/libc6@...` matches package `libc6`. `not_affected` and
`fixed` set the finding aside, with the note as the reason; `affected` and `under_investigation` keep its group
and add the note. A decision made for another installed version still applies but is marked for review, a
decision whose vulnerability is no longer found is listed as resolved, and a decision never sets aside a
malicious package. Decisions are validated before anything is scanned.

The new `findings.csv` comes out with the decisions filled in (and `triage_decided_version`), so the next run
takes it as is and only new findings are blank. Every run with decisions also writes `openvex.json`
([OpenVEX](https://openvex.dev) v0.2.0), which Grype and Trivy can read (`--vex`), and `vex.cdx.json`
(CycloneDX 1.6 VEX) for Dependency-Track. In the CycloneDX file not_affected, affected, fixed and
under_investigation become `not_affected`, `exploitable`, `resolved` and `in_triage`, and components use the package
URL as their reference; an import matches only where the receiving project identifies components by the same
purl. An OpenVEX file is accepted as `--decisions` too.

## Likelihood heuristic

Off by default. With `--likelihood`, the first matching rule wins:

<!-- generated:likelihood-rules -->
| Level | Default rule |
|---|---|
| 5 Almost certain | A package listed as malicious (OpenSSF malicious packages, or a CWE-506 advisory) is present |
| 5 Almost certain | A known-exploited (CISA KEV) vulnerability has a fix the project has not shipped |
| 4 Likely | A finding with an upstream fix has a ready-to-use public exploit (Metasploit module or Nuclei template) |
| 4 Likely | A finding with an upstream fix has a high predicted exploitation probability (EPSS 0.5 or more) |
| 4 Likely | Critical fixes were available before release and the project shows weak upkeep |
| 4 Likely | Critical fixes have been available for a long time and the project has not released since |
| 3 Possible | A finding with an upstream fix has a notable predicted exploitation probability (EPSS 0.1 or more) |
| 3 Possible | A finding with an upstream fix has a published exploit (Exploit-DB) |
| 3 Possible | Critical, or several high, fixes were available before release and not shipped |
| 3 Possible | Critical, or many high, fixes have been available upstream for a long time with no newer release |
| 2 Unlikely | High or critical findings exist with upstream fixes |
| 1 Rare | No high or critical findings with available fixes |
<!-- /generated:likelihood-rules -->

Unknown signals (no Scorecard score, say) never trigger a rule. To use your own rules, copy
`DEFAULT_CONFIG` from [likelihood.py](https://github.com/ntavakol/OSS-Intake/blob/main/src/oss_intake/likelihood.py) into a JSON file and pass
`--likelihood-config`.
<!-- generated:likelihood-metrics -->
The available metrics are `archived`, `critical_fix_at_release`, `critical_fix_unshipped`, `critical_with_fix`, `days_since_latest_release`, `fix_date_unknown`, `high_fix_at_release`, `high_fix_unshipped`, `high_with_fix`, `kev_with_fix`, `malicious`, `max_days_fix_available`, `max_epss_with_fix`, `public_exploit_with_fix`, `release_date_known`, `scanned_is_latest`, `scorecard_score`, `weaponised_with_fix` and `with_fix`.
<!-- /generated:likelihood-metrics -->

## Limitations

- Results depend on the scanners' vulnerability databases and drift as those databases update. The report
  records scanner and database versions so a result can be reproduced or explained.
- Trivy and Grype detect packages independently, so their disagreement is informative. OSV is queried with
  Trivy's package list, so it is an independent database check, not an independent detector.
- Severity is the highest any source reported, which is conservative. Per-source severities are in the CSV.
- Kernel CVEs reported against kernel header packages (`linux-libc-dev` and similar) are excluded from lag and
  likelihood, because a container uses the host's kernel. They stay in findings.csv with a note; assess the host
  kernel separately. Use `--include-kernel-headers` to count them.
- Version comparison is ecosystem-agnostic and approximate. It only affects which fix date is used. Build
  labels (`.jre11`, `-jre`, `-android`) are ignored when comparing.
- Scanners can read a JAR's version without its build label and report an already-fixed build as vulnerable
  (seen with `mssql-jdbc 12.10.2.jre11`). These rows are kept, marked in the `note` column and excluded from lag.
  OSV inherits the same mistake because it is queried with the scanner's version.
- The OpenSSF Scorecard API only covers repositories in its scheduled dataset. "Not scored" is not a
  negative signal.
- Release matching expects GitHub releases whose tags resemble the image tag (`1.2.3`, `v1.2.3`,
  `name-1.2.3`, `release-1.2.3`), and also tries the tag without a variant suffix (`2.528-jdk21` matches
  `jenkins-2.528`). If nothing matches, lag metrics are not computed rather than measured against the
  wrong release. Use `--release-tag` or `--release-date` in that case. Failing both, the image's build date is
  used and labelled "image build date": lag then means "fixes that existed when the image was built"
  (disable with `--no-image-date`).
- Fix dates are unavailable for Amazon Linux and for runtimes found only in binaries. When more than half of the fixes lack
  a date, the likelihood suggestion is marked low confidence: read it as "not enough evidence", not "low risk".
- Only GitHub-hosted projects get health signals in this version.
- Trivy does not catalogue installed R (CRAN) packages, so R libraries inside an image are not assessed.
- Runtimes detected from binaries (`binary` in the coverage table) have no package registry to date fixes
  from, so they always show as "fix date unknown".

Planned work is in [BACKLOG.md](https://github.com/ntavakol/OSS-Intake/blob/main/BACKLOG.md).

## Licence

Apache License 2.0. See [LICENSE](https://github.com/ntavakol/OSS-Intake/blob/main/LICENSE).
