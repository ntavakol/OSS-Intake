# Backlog

Items agreed for later versions, roughly in priority order.

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
- README screenshots of the HTML report (light and dark, desktop and phone). No real project may be identifiable:
  mask the image, repository and package identifiers. Rendering from the synthetic test fixtures (example/webapp,
  CVE-2099-* IDs) is not enough on its own: they use real library names (spring-web, jackson-databind), so
  package names must be masked there too, or the fixtures given made-up names. Generate them with a script
  (Playwright, already used for checks) so they can be refreshed when the layout changes.
- VEX import, so triage decisions in `findings.csv` can be carried between runs.

## Signals
- Artifact integrity for `--path`: compare a JAR's SHA-256 with the checksum the official registry publishes
  for that exact version (Maven Central, PyPI, npm); a mismatch means the file is not what the project released.
- Optional VirusTotal lookup for `--path` artifacts: hash only, never an upload (uploads are shared with
  VirusTotal subscribers), opt-in with the user's own API key. Low value for new supply-chain compromises, which
  are usually unknown to VirusTotal at first; check the API terms for organisational use.
- Vendor rating beside the aggregator score: only where a structured vendor rating exists. Checked on
  CVE-2026-47884: NVD carries only a CISA-ADP 9.8, not Spring's own Medium, which exists only on spring.io. OS
  packages already use the distro's rating through Trivy. Low value until a general source appears.
- Go reachability: run `govulncheck -mode=binary` (an external executable, like the scanners) on Go binaries
  found in the image, and record whether each Go finding's vulnerable symbol is reachable. Real evidence for
  "not reachable", for Go only (for example gosu in official Docker images).
- Amazon Linux fix dates: Trivy reports no ALAS IDs, so findings would need matching to ALAS by CVE and package.
- Rebuilt images: official images (redis, postgres...) are rebuilt with newer OS packages under the same tag.
  For the OS layer, lag against the image build date may be fairer than against the project's release date;
  consider reporting both.

## Scanner management
- An optional, opt-in scanner downloader: exact version only, SHA-256 against the release checksums file and
  cosign verification both mandatory, never "latest". Deliberately left out of v0.1 because a downloader is the
  riskiest feature a supply-chain tool can have.
- Fetch the known-bad list from a signed location instead of shipping it with each release.

## Publishing
- PyPI release through trusted publishing (OIDC), with build provenance attestations.
