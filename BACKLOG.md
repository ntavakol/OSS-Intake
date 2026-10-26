# Backlog

Open work only, agreed for later versions. "Next" is the planned order; the other sections are not ranked.
Finished items are removed in the commit that ships them; CHANGELOG.md records what was done and when.

## Next
- CycloneDX VEX export (see Organisation view).

## Organisation view
Assess the open source an organisation already uses, not one artifact at a time, and re-run it on a schedule:
a package that was clean when approved can later turn out vulnerable or compromised.
- Package inventory input, beyond CSV (done in 0.3.0): `.xlsx` read directly as an optional extra (openpyxl),
  and CycloneDX and SPDX SBOMs as input, which most package repositories and Dependency-Track can export.
- Upgrade comparison for image and lockfile reports (done for inventories in 0.4.0): per package, what is still
  known at the minimum fix and at the latest stable release, with major-version warnings.
- CycloneDX VEX export beside openvex.json, for Dependency-Track (which imports CycloneDX VEX, not OpenVEX).

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

