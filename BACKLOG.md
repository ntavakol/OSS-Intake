# Backlog

Items agreed for later versions, roughly in priority order.

## Inputs
- Standalone artifacts: scan a JAR, WAR or binary directly (`trivy rootfs` / `grype file:`).
- Dependency manifests and lockfiles: `requirements.txt`, `poetry.lock`, `renv.lock`, `package-lock.json`,
  `pom.xml`. Release lag then applies to source releases rather than images.
- Non-GitHub forges (GitLab, Codeberg) for release cadence.
- Release date from the image itself (OCI `created` annotation) when no GitHub release matches.

## Outputs
- PDF report. Deferred because it needs either a heavy dependency (WeasyPrint, ReportLab) or a headless
  browser, which conflicts with the minimal-dependency goal. Until then, print `report.html` to PDF from a
  browser; the page is self-contained and prints cleanly.
- SARIF output for code-scanning dashboards.
- VEX import, so triage decisions in `findings.csv` can be carried between runs.

## Signals
- Alpine fix dates (secdb has fixed versions but no dates; aports history may).
- Amazon Linux fix dates: Trivy reports no ALAS IDs, so findings would need matching to ALAS by CVE and package.
- Go standard library fix dates from Go release history.

## Scanner management
- An optional, opt-in scanner downloader: exact version only, SHA-256 against the release checksums file and
  cosign verification both mandatory, never "latest". Deliberately left out of v0.1 because a downloader is the
  riskiest feature a supply-chain tool can have.
- Fetch the known-bad list from a signed location instead of shipping it with each release.

## Publishing
- PyPI release through trusted publishing (OIDC), with build provenance attestations.
