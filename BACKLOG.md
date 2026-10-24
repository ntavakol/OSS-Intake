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
- VEX import, so triage decisions in `findings.csv` can be carried between runs.

## Signals
- Amazon Linux fix dates: Trivy reports no ALAS IDs, so findings would need matching to ALAS by CVE and package.
- Go standard library fix dates from Go release history.
- CVSS provenance: record the CVSS version and the database the score came from (NVD, GHSA, distro) in
  findings.csv and the HTML hover text. Today the report keeps the highest v3.x base score across sources, which
  is cautious but not traceable, and can sit beside a distro severity rating that disagrees with it.
- CVSS v4: use the v4 score, marked as v4, when an advisory publishes no v3 score (common in newer GitHub
  advisories); those findings currently show n/a.

## Scanner management
- An optional, opt-in scanner downloader: exact version only, SHA-256 against the release checksums file and
  cosign verification both mandatory, never "latest". Deliberately left out of v0.1 because a downloader is the
  riskiest feature a supply-chain tool can have.
- Fetch the known-bad list from a signed location instead of shipping it with each release.

## Publishing
- PyPI release through trusted publishing (OIDC), with build provenance attestations.
