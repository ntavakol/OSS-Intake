# Backlog

Items agreed for later versions, roughly in priority order.

## Inputs
- Standalone artifacts: scan a JAR, WAR or binary directly (`trivy rootfs` / `grype file:`).
- Dependency manifests and lockfiles: `requirements.txt`, `poetry.lock`, `renv.lock`, `package-lock.json`,
  `pom.xml`. Release lag then applies to source releases rather than images.
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
- Vendor rating beside the aggregator score: only where a structured vendor rating exists. Checked on
  CVE-2026-47884: NVD carries only a CISA-ADP 9.8, not Spring's own Medium, which exists only on spring.io. OS
  packages already use the distro's rating through Trivy. Low value until a general source appears.
- Go reachability: run `govulncheck -mode=binary` (an external executable, like the scanners) on Go binaries
  found in the image, and record whether each Go finding's vulnerable symbol is reachable. Real evidence for
  "not reachable", for Go only (for example gosu in official Docker images).
- Triage grouping in the report, building on exploit levels, advisory conditions and govulncheck: act now (KEV or weaponised exploit), check the
  precondition (vendor rates lower, or a feature must be in use), probably noise (evidence of no reachability),
  each with its reasons. The tool never concludes "no risk" without evidence such as govulncheck.
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
