# Backlog

Open work only, agreed for later versions. "Next" is the planned order; the other sections are not ranked.
Finished items are removed in the commit that ships them; CHANGELOG.md records what was done and when.

## Next: the organisation view (agreed 28 Oct)
Design: oss-intake reads two inventory formats only, CSV and SBOM (CycloneDX or SPDX JSON). Every other source is
a small collector or a documented recipe that produces one of them, so the core stays vendor-neutral, needs no
vendor API keys, and a new source never touches the scanning code. Package-level sources (purls) come first;
application-level consoles (CrowdStrike, Tenable, Defender) already do CVE matching for installed applications
and are not primary sources (see "Not planned" below).

0.10.0, organisation scale and laptops:
- Each package version is checked once, however many hosts or SBOMs list it, and mapped back: packages.csv and
  the executive summary gain "hosts" (count and names) and the top list is ranked by reach as well as severity.
- A local cache (`--cache-dir`, default under the user cache folder, `--no-cache`) for deps.dev release dates
  and OSV advisory details, with an age limit, so a weekly run does not repeat 100,000 lookups.
- The new-release check's 400-lookup cap becomes configurable, and is applied after de-duplication.
- A synthetic 100,000-row test to keep run time and memory in check.

0.11.0, registry proxy gate:
- Collectors for Artifactory (AQL) and Nexus (REST components API) that list what the proxy has cached, as an
  SBOM or CSV, with "new since the last run".
- A gate recipe: run on new cache entries with `--fail-on malicious,recent` before they are released to
  developers (an assessment the proxy calls, not a proxy).

Not planned: connectors for CrowdStrike Falcon, Tenable One or Microsoft Defender software inventories. They list
installed applications by name, not packages, and already match CVEs for them. Use them to answer "which hosts
run X" once oss-intake has flagged a package.

On every release: rebuild the live sample (`sh examples/compromised-npm/build.sh`) and update the pinned version
in `examples/scheduled-rescan/oss-intake-rescan.yml` (a test checks it matches).

## Organisation view
Assess the open source an organisation already uses, not one artifact at a time, and re-run it on a schedule:
a package that was clean when approved can later turn out vulnerable or compromised.
- Package inventory as `.xlsx`, read directly as an optional extra (openpyxl). SBOM input is planned under Next.
- Dependency-Track as a source: pull every project's SBOM through its API (it already takes oss-intake's VEX).
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

