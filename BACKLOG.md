# Backlog

Items agreed for later versions. "Next" is the planned order; the other sections are not ranked.

## Next
- Package inventory input, MVP (see Organisation view).
- Upgrade comparison per package (see Organisation view).
- VEX import, so triage decisions recorded in `findings.csv` carry over to the next run of the same target
  instead of being redone.
- Artifact integrity for `--path` (see Signals).

## Organisation view
Assess the open source an organisation already uses, not one artifact at a time, and re-run it on a schedule:
a package that was clean when approved can later turn out vulnerable or compromised.
- Package inventory input (MVP): a list of packages exported from a package repository (Artifactory, Nexus) or
  kept in a spreadsheet. Columns: ecosystem, name, version, or a single purl column; optional owner/system
  columns are carried through to the report. MVP reads CSV (Excel saves as CSV) so no spreadsheet dependency is
  needed; `.xlsx` directly can follow as an optional extra (openpyxl). Validate every row first and report
  unparseable rows before any network call. No scanner is needed: query OSV (malicious and vulnerable versions)
  and deps.dev (latest version, release dates) per package, in batches. Then CycloneDX and SPDX SBOMs as input,
  which most repositories and Dependency-Track can export.
- Upgrade comparison per package: known vulnerabilities in the installed version against the nearest version
  that fixes them and against the latest release ("2.14.1 to 2.17.1 removes 4 critical, adds none"). Flag a
  major-version jump as a likely breaking change. A newer version only has fewer known vulnerabilities; say so.
- Executive summary report across the inventory: packages and versions in use, how many are malicious, have
  known-exploited or critical vulnerabilities, or are unmaintained (archived, no release in a year); the top
  packages by risk with their owners; and the improvement if each is upgraded (the comparison above, totalled).
  One page, readable without the per-finding detail. Trends between runs need the previous run's results,
  which ties in with VEX import.

## Inputs
- Source checkouts: scan a folder in both Trivy modes (`fs` for lockfiles, `rootfs` for built artifacts) and
  merge, so a whole repository can be passed instead of its lockfile.
- CRAN fix dates for `renv.lock` findings (from CRAN's archive or the CRAN package database), and Bioconductor
  packages (OSV has a Bioconductor ecosystem).
- Non-GitHub forges (GitLab, Codeberg) for release cadence.

## Outputs
- PDF report. Deferred because it needs either a heavy dependency (WeasyPrint, ReportLab) or a headless
  browser, which conflicts with the minimal-dependency goal. Until then, print `report.html` to PDF from a
  browser; the page is self-contained and prints cleanly.
- SARIF output for code-scanning dashboards.
- README screenshots of the HTML report (light and dark, desktop and phone), generated with a script
  (Playwright) so they can be refreshed when the layout changes. The sample uses public, well-known compromised
  releases only; a report on a current named project must never be published.

## Signals
- Artifact integrity for `--path`: compare a JAR's SHA-256 with the checksum the official registry publishes
  for that exact version (Maven Central, PyPI, npm); a mismatch means the file is not what the project released.
- Optional VirusTotal lookup for `--path` artifacts: hash only, never an upload (uploads are shared with
  VirusTotal subscribers), opt-in with the user's own API key. Low value for new supply-chain compromises, which
  are usually unknown to VirusTotal at first; check the API terms for organisational use.
- Vendor rating beside the aggregator score: only where a structured vendor rating exists. Checked on
  CVE-2026-47884: NVD carries only a CISA-ADP 9.8, not Spring's own Medium, which exists only on spring.io. OS
  packages already use the distro's rating through Trivy. Low value until a general source appears.
- Amazon Linux fix dates: Trivy reports no ALAS IDs, so findings would need matching to ALAS by CVE and package.
- Rebuilt images: official images (redis, postgres...) are rebuilt with newer OS packages under the same tag.
  For the OS layer, lag against the image build date may be fairer than against the project's release date;
  consider reporting both.

## Scanner management
- An optional, opt-in scanner downloader: exact version only, SHA-256 against the release checksums file and
  cosign verification both mandatory, never "latest". Deliberately left out so far, because a downloader is
  the riskiest feature a supply-chain tool can have.
- Fetch the known-bad list from a signed location instead of shipping it with each release.

