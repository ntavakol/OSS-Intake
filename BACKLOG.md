# Backlog

Open work only, agreed for later versions. "Next" is the planned order; the other sections are not ranked.
Finished items are removed in the commit that ships them; CHANGELOG.md records what was done and when.

## Next
From the 0.6.0 review (bug and security IDs as in the review). Planned order:

0.7.0, decisions and versions you can trust:
- Decision round-trip: match decisions on id, package and version (B3); strip the deb, rpm and apk namespace and
  read the epoch when loading OpenVEX (B4); export `mitigated` as not_affected with
  `inline_mitigations_already_exist`, not fixed (B14); keep notes exactly, including a leading `-`, `=`, `+`, `@`
  and line breaks (B18, B21).
- Versions and fixes: ignore OSV GIT range hashes as fixes (B5); sort letter patches such as 1.1.1m (B6); pick a
  minimum fix that clears every finding on its branch (B7); normalise PyPI names in a purl column (B8); merge Go
  versions with and without `v` (B19).
- Release-age check: flag a version published in the last N days (default 7), the window in which most
  compromised releases are caught and pulled.
- `--fail-on act,critical` exit code for CI.
- Packaging and project: sdist that can run its tests (B11), exit codes as documented (B16), reject placeholder
  versions such as `4.x` and `31.+` (B17), PyPI summary and classifiers, a Documentation URL, CI on Python 3.10
  to 3.13, issue templates. Rebuild the live sample on each release (B13).

0.8.0, hardening and regular use:
- Untrusted input: size and member limits for archives (S2), CSV and Markdown escaping of all untrusted text
  (S3 to S5), path checks on registry lookups (S6), bounded regex input (S7), temporary copies always removed
  (S8). Pin govulncheck, docker and crane like Trivy and Grype (S9).
- A ready-made scheduled workflow that re-scans an inventory weekly, carries decisions forward and opens an
  issue on new Act now findings.
- Confirm against an official bundle whether `--trivy-cosign-bundle` verifies the right file, and fix it (B10).
- Smaller fixes: only treat a `.tar.gz` as a Python sdist when it has PKG-INFO (B20); warn on options that have no
  effect in the chosen mode (B22); range-check numbers and turn off option abbreviations (B23); create the output
  folder only after the scanners are found (B24).

## Organisation view
Assess the open source an organisation already uses, not one artifact at a time, and re-run it on a schedule:
a package that was clean when approved can later turn out vulnerable or compromised.
- Package inventory input, beyond CSV (done in 0.3.0): `.xlsx` read directly as an optional extra (openpyxl),
  and CycloneDX and SPDX SBOMs as input, which most package repositories and Dependency-Track can export.
- Upgrade comparison for image and lockfile reports (done for inventories in 0.4.0): per package, what is still
  known at the minimum fix and at the latest stable release, with major-version warnings.

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

## Signals
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

