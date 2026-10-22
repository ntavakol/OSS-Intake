# Validating against a real public image

Use a public image to check that `oss-intake` matches a manual scanner run. The example below
demonstrates the method; it is not an assessment of the project.

## Reference case

`openanalytics/shinyproxy:3.2.4` (GitHub release `v3.2.4`, published 30 April 2026). A manual Trivy
v0.76.1 scan on 22 October 2026 reported:

- Ubuntu 24.04 base layer: 0 HIGH or CRITICAL
- `/opt/shinyproxy/shinyproxy.jar`: 47 HIGH or CRITICAL findings (40 HIGH, 7 CRITICAL), all with upstream
  fixes listed

Counts will drift as vulnerability databases update.

## Run

```bash
oss-intake --image openanalytics/shinyproxy:3.2.4 --repo openanalytics/shinyproxy \
  --out ./reports/shinyproxy-3.2.4 --image-src remote --min-severity HIGH \
  --trivy-version 0.76.1 --likelihood
```

## Check

1. With `--scanners trivy --offline`, the HIGH and CRITICAL totals in `summary.md` should equal the manual
   Trivy count for the same Trivy version and database date (shown in the Scope table).
2. `assessment.json` should show `health.scanned_release.tag` as `v3.2.4` with `matched: true`.
3. Rows in `findings.csv` with `fix_available_at_release = yes` should have a `fix_published` date
   before 2026-04-30. Spot-check two against the package registry (Maven Central or deps.dev).
4. Findings seen only by Grype or only by OSV are listed in the Source agreement table. Review a sample
   rather than dismissing them.

If your network blocks `mirror.gcr.io`, point Trivy at the GHCR copies of its databases:

```bash
--trivy-arg=--db-repository=ghcr.io/aquasecurity/trivy-db:2 \
--trivy-arg=--java-db-repository=ghcr.io/aquasecurity/trivy-java-db:1
```
