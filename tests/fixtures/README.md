# Test fixtures

All fixtures in this folder are SYNTHETIC (the `real/` subfolder is the exception, see below). Vulnerability identifiers use the reserved-looking `CVE-2099-*` and
`GHSA-test-*` forms so they cannot be mistaken for real advisories, and the project is the
fictional `example/webapp`. The JSON shapes follow the real Trivy, Grype, OSV, deps.dev,
GitHub, OpenSSF Scorecard and CISA KEV formats so the parsers are exercised realistically.
No test makes a live network call.

`real/` holds trimmed scan output from public container images, produced with
`scripts/extract_regression_fixture.py`. Each file keeps only the rows needed to pin a bug found
on real data (see `tests/test_real_regressions.py`). Image names and install paths are replaced with neutral
ones (`example/spring-app`, `/opt/app/app.jar`); the package data is as the scanner reported it.
