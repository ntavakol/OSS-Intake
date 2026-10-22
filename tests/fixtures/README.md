# Test fixtures

All fixtures are SYNTHETIC. Vulnerability identifiers use the reserved-looking `CVE-2099-*` and
`GHSA-test-*` forms so they cannot be mistaken for real advisories, and the project is the
fictional `example/webapp`. The JSON shapes follow the real Trivy, Grype, OSV, deps.dev,
GitHub, OpenSSF Scorecard and CISA KEV formats so the parsers are exercised realistically.
No test makes a live network call.
