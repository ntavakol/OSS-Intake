# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's private vulnerability reporting:
<https://github.com/ntavakol/OSS-Intake/security/advisories/new> (**Security > Report a vulnerability** on this
repository). Do not open a public issue or disclose the vulnerability publicly before a fix is released.

Include the affected version, steps to reproduce and the impact you expect. You should get an
acknowledgement within 7 days. Confirmed issues are fixed in a new release and credited in the advisory
unless you ask otherwise.

## Supported versions

Only the latest release receives fixes.

## Scope

In scope: the `oss-intake` code, its handling of scanner binaries and their output, its network requests
and the reports it writes (for example injection into CSV or HTML).

Out of scope: vulnerabilities in Trivy, Grype, OSV, deps.dev, GitHub or OpenSSF Scorecard. Report those to
their maintainers.

## Known-bad scanner versions

If you know of a malicious or compromised release of a scanner that `oss-intake` runs, please report it the
same way so it can be added to `src/oss_intake/data/known_bad.json`.

## Design notes

- Scanners run as separate processes without a shell; image references are validated and cannot begin with
  `-`, so they cannot be read as options.
- `GITHUB_TOKEN` is only sent to `api.github.com`, never logged and never written to reports.
- Advisory text is escaped in HTML and neutralised against spreadsheet formula injection in CSV.
- CI actions are pinned by full commit SHA and workflows run with read-only permissions.
