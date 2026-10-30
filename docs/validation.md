# Validating against a real public image

Use a public image to check that `oss-intake` matches a manual scanner run. The example below
demonstrates the method; it is not an assessment of the project.

## Reference case

Pick a public image with GitHub releases, for example `jenkins/jenkins:2.528-jdk21` (repository
`jenkinsci/jenkins`, release tag `jenkins-2.528`). Run Trivy on it yourself first and note the HIGH and
CRITICAL counts per target, with the Trivy version and database date. Counts drift as vulnerability databases
update, so compare runs made on the same day.

## Run

```bash
oss-intake --image jenkins/jenkins:2.528-jdk21 --repo jenkinsci/jenkins --release-tag jenkins-2.528 \
  --out ./reports/jenkins-2.528 --image-src remote --min-severity HIGH \
  --trivy-version 0.76.1 --likelihood
```

## Check

1. With `--scanners trivy --offline`, the HIGH and CRITICAL totals in `summary.md` should equal the manual
   Trivy count for the same Trivy version and database date (shown in the Scope table).
2. `assessment.json` should show `health.scanned_release.tag` as the release you passed, with `matched: true`.
3. Rows in `findings.csv` with `fix_available_at_release = yes` should have a `fix_published` date
   before the release date. Spot-check two against the package registry (Maven Central or deps.dev).
4. Findings seen only by Grype or only by OSV are listed in the Source agreement table. Review a sample
   rather than dismissing them.

If your network blocks `mirror.gcr.io`, point Trivy at the GHCR copies of its databases:

```bash
--trivy-arg=--db-repository=ghcr.io/aquasecurity/trivy-db:2 \
--trivy-arg=--java-db-repository=ghcr.io/aquasecurity/trivy-java-db:1
```
