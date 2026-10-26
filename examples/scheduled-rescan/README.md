# Scheduled re-scan

A ready-made GitHub Actions workflow that re-scans a package inventory every week, carries the assessor's
decisions forward, and opens an issue when something new needs action. See the comments at the top of
[`oss-intake-rescan.yml`](oss-intake-rescan.yml) for the repository layout it expects.

```bash
mkdir -p .github/workflows
cp oss-intake-rescan.yml .github/workflows/
```

What it does each week:

1. Installs a pinned version of oss-intake.
2. Runs `oss-intake --path inventory.csv --decisions oss-intake/findings.csv --fail-on act,malicious,recent`.
3. Uploads the reports (executive summary, report, packages.csv, findings.csv) as a build artifact for 90 days.
4. Opens an issue listing the Act now findings (malicious, known exploited, or a ready-to-use exploit) that no
   decision has set aside, and releases under a week old. The issue title carries a fingerprint of that list, so
   the same list is reported once while its issue is open; any change opens a new one.

It needs only `contents: read` and `issues: write`, and never commits. Decisions stay a human step: download
findings.csv from the artifact, fill in the triage columns, and commit it as `oss-intake/findings.csv`.
