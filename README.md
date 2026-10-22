# oss-intake

Assess third-party open source software before you adopt it. `oss-intake` answers two questions for a
security or architecture review:

1. **Is it vulnerable?** Known vulnerabilities in a container image and the dependencies bundled inside it.
2. **Does the project patch?** Whether fixes that exist upstream are being shipped, how long they have been
   available, and how active the project is.

The second question is what a scanner alone does not answer. `oss-intake` measures **release lag**: findings
where the fixed version of a dependency was already published before the project's release, so the project
could have shipped it and did not. It then adds project health signals (release cadence, OpenSSF Scorecard,
CISA KEV membership).

## What it does

- Runs [Trivy](https://github.com/aquasecurity/trivy) and, if installed, [Grype](https://github.com/anchore/grype)
  against an image, and queries [OSV.dev](https://osv.dev) for the language packages Trivy found.
- Merges the results into one row per vulnerability, package and version, recording which sources saw it.
- Looks up when each fixed dependency version was published ([deps.dev](https://deps.dev)) and compares that
  with the project's GitHub release date.
- Reports release cadence from the GitHub API and the OpenSSF Scorecard score where one exists.
- Audits the project's own GitHub Actions workflows: unpinned actions, known-bad action versions (such as the
  compromised `trivy-action` tags), missing or write-all token permissions, and `pull_request_target` triggers.
- Optionally suggests a likelihood value for a 5x5 risk matrix from configurable rules, clearly labelled
  as a heuristic.
- Writes `findings.csv`, `summary.md`, `assessment.json` and a self-contained `report.html`, plus the raw
  scanner output under `raw/` as evidence.
- Applies integrity checks to the scanners it runs: version pinning, a known-bad version list, SHA-256
  verification and optional Sigstore (cosign) verification.

## What it does not do

- **It does not prove exploitability.** Scanners match component versions against advisory databases. A
  finding means a version is listed as affected, not that the vulnerable code is reachable or exposed in your
  deployment. The CSV has empty `triage_*` columns for recording reachability decisions.
- It does not install, download, bundle or redistribute scanners. You install them; it verifies them.
- It does not assess licences, malicious packages, secrets or misconfiguration.
- It does not give a risk rating. The likelihood suggestion is a starting point for an assessor.
- It does not fix anything or open issues upstream.

## Install

Python 3.10 or later on Windows, macOS or Linux. No administrator rights are needed.

```bash
pipx install git+https://github.com/ntavakol/OSS-Intake
```

Windows PowerShell without pipx:

```powershell
py -m pip install --user pipx
py -m pipx ensurepath
# open a new terminal, then
pipx install git+https://github.com/ntavakol/OSS-Intake
```

If `oss-intake` is "not recognized" after `pip install --user`, the per-user Scripts folder is not on PATH.
Either add it, or run the tool through Python, which works everywhere:

```powershell
py -m oss_intake --help
```

### Install the scanners yourself, pinned and verified

Install a specific version of each scanner from its official GitHub release, never "latest", and verify the
download before you extract it. `oss-intake verify` does the hash comparison correctly on any platform
(checksum files are served as `application/octet-stream`; they are parsed as bytes, with BOM and CRLF handled):

```bash
oss-intake verify --file trivy_0.76.1_windows-64bit.zip --checksums trivy_0.76.1_checksums.txt
```

Then record the SHA-256 of the extracted executable and pass it on every run (`oss-intake doctor` prints it):

```bash
oss-intake doctor
```

Trivy versions 0.69.4, 0.69.5 and 0.69.6 were malicious (CVE-2026-33634, March 2026). `oss-intake` refuses to
run any version on its [known-bad list](src/oss_intake/data/known_bad.json).

## Usage

```bash
oss-intake --image owner/app:1.2.3 --repo owner/app --out ./reports \
  --image-src remote --trivy-version 0.76.1 --trivy-sha256 <sha256-of-trivy-executable> --likelihood
```

PowerShell (backtick continues a line):

```powershell
$env:GITHUB_TOKEN = "<optional token, raises the GitHub API rate limit>"
oss-intake --image owner/app:1.2.3 --repo owner/app --out .\reports `
  --image-src remote --trivy-version 0.76.1 --trivy-sha256 <sha256> --likelihood
```

All inputs are validated before any scanner runs. The image must carry an explicit tag or digest.

| Option | Purpose |
|---|---|
| `--image` | Image with explicit tag or digest |
| `--repo` | GitHub `owner/name` (a full GitHub URL is accepted) |
| `--image-src remote` | Pull from the registry without Docker installed (Trivy `--image-src remote`, Grype `registry:`) |
| `--platform` | Image platform for both scanners (default `linux/amd64`, so Apple Silicon scans the same variant as a server); `''` uses scanner defaults |
| `--scanners` | `auto` (default: Trivy and OSV, plus Grype if found) or a list such as `trivy,grype,osv` |
| `--trivy-version`, `--grype-version` | Required scanner version; the run fails on mismatch |
| `--trivy-sha256`, `--grype-sha256` | Expected SHA-256 of the executable |
| `--trivy-cosign-bundle`, `--grype-cosign-bundle` | Verify a Sigstore bundle with cosign (cosign must be on PATH) |
| `--trivy-arg`, `--grype-arg` | Pass extra arguments, e.g. `--trivy-arg=--db-repository=ghcr.io/aquasecurity/trivy-db:2` |
| `--from-trivy-json`, `--from-grype-json` | Use an existing JSON report instead of running the scanner |
| `--release-tag`, `--release-date` | Set the release the image corresponds to, when tags do not match |
| `--grace-days` | A fix must predate the release by this many days to count as missed (default 14) |
| `--unshipped-days` | Days a fix must be public, with no newer release, to count as unshipped (default 90) |
| `--as-of` | Fix the assessment date for reproducible reports |
| `--min-severity` | Drop findings below a severity |
| `--formats` | Any of `csv,md,json,html` (default all) |
| `--offline` | No network enrichment (OSV, deps.dev, GitHub, Scorecard, KEV, EPSS) |
| `--no-epss`, `--no-kev`, `--no-scorecard`, `--no-fix-dates` | Skip one enrichment source |
| `--likelihood`, `--likelihood-config FILE` | Add the 5x5 likelihood heuristic, with optional custom rules |
| `--fail-on-likelihood N` | Exit code 3 when the suggestion is N or higher, for pipelines |
| `--sbom` | Also write a CycloneDX SBOM to `raw/` |

Other commands: `oss-intake doctor` (scanner paths, versions, hashes, known-bad status) and
`oss-intake verify` (check a download against a checksums file, a hash or a cosign bundle).

Exit codes: `0` success, `1` error (including any integrity failure), `2` invalid input, `3` likelihood
threshold reached.

`GITHUB_TOKEN` is optional. It is only sent to `api.github.com`, and it is never logged or written to reports.

## How release lag is measured

For each finding with a fix, `oss-intake` picks the nearest fixed version above the installed one (so a fix on
an older branch is not counted for a newer one) and looks up when that version was published.

| Metric | Meaning |
|---|---|
| Fix exists upstream | A fixed version of the dependency is known |
| **Fix existed before release** | The fixed version was published at least `--grace-days` (14) days before the project's release: the project could reasonably have shipped it |
| Fix within grace period | Published in the 14 days before release; shown but not counted as missed |
| **Unshipped** | Forward-looking: the fix has been public for `--unshipped-days` (90) or more and the scanned release is still the project's latest |
| Likely already fixed | Installed version equals a listed fix apart from a build label such as `.jre11`; flagged and excluded from lag |
| Fix published after release | The fix arrived later; this is normal lag for the next release |
| Days a fix has been available | Assessment date minus the fixed version's publish date |
| CVE published before release | Secondary signal. A CVE can be public before any fix exists, so this overstates lag on its own |

Fix dates come from deps.dev for language packages, falling back to the GitHub release date for Go modules
hosted on GitHub that deps.dev does not index. For Debian packages they come from the Debian security advisory
that shipped the fix (DSA or DLA, as reported by Trivy), dated from the Debian security tracker's advisory lists,
with OSV as a fallback. Debian fixes released in point releases without an advisory stay unknown. For Ubuntu packages they come from the Ubuntu
Security Notice (USN) that fixed the CVE in that release and source package at that version, found through OSV.
For RHEL and UBI packages they come from the Red Hat advisory (RHSA) that Trivy reports, dated from Red Hat's
CSAF document. Packages with no dated source yet, currently Alpine, Amazon Linux and the Go standard library, are counted as "fix date
unknown" rather than guessed. The `fix_date_source` column in findings.csv shows where each date came from.

## Example output

Taken from the synthetic test fixtures (`tests/fixtures`, fictional project `example/webapp`) so it shows
the format, not a judgement of any real project:

```text
findings=7 critical=2 high=4 with_fix=6 fix_before_release=3 fix_date_unknown=1 likelihood=5(Almost certain)
```

| ID | Severity | Package | Installed | Fix | Fix before release | Days fix available |
|---|---|---|---|---|---|---|
| CVE-2099-0001 | CRITICAL | org.springframework:spring-web | 6.1.10 | 6.1.12 | yes | 290 |
| CVE-2099-0006 | CRITICAL | com.fasterxml.jackson.core:jackson-databind | 2.17.0 | 2.17.3 | no | 113 |
| CVE-2099-0003 | HIGH | io.netty:netty-codec-http | 4.1.100.Final | 4.1.108.Final | yes | 244 |
| CVE-2099-0004 | HIGH | org.springframework:spring-web | 6.1.10 | none | no fix | n/a |
| CVE-2099-1000 | MEDIUM | libc6 | 2.39-0ubuntu8.4 | 2.39-0ubuntu8.5 | unknown | n/a |

The summary also covers scope (scanner versions, database dates, hash verification), project health,
agreement between sources and any warnings. See [docs/validation.md](docs/validation.md) for checking the
tool against a real public image.

## Likelihood heuristic

Off by default. With `--likelihood`, the first matching rule wins:

| Level | Default rule |
|---|---|
| 5 Almost certain | A CISA KEV vulnerability has a fix the project has not shipped |
| 4 Likely | A finding with an upstream fix has an EPSS score of 0.5 or more |
| 4 Likely | A critical fix existed before release, and the project has not released for 180 days, is archived or scores under 4 on Scorecard |
| 4 Likely | A critical fix is unshipped and the project has not released for 180 days |
| 3 Possible | A finding with an upstream fix has an EPSS score of 0.1 or more |
| 3 Possible | A critical fix, or 5 or more high fixes, existed before release |
| 3 Possible | A critical fix, or 10 or more high fixes, are unshipped |
| 2 Unlikely | Any high or critical finding has an upstream fix |
| 1 Rare | None of the above |

Unknown signals (no Scorecard score, say) never trigger a rule. To use your own rules, copy
`DEFAULT_CONFIG` from [likelihood.py](src/oss_intake/likelihood.py) into a JSON file and pass
`--likelihood-config`. The available metrics are `critical_fix_at_release`, `high_fix_at_release`,
`critical_with_fix`, `high_with_fix`, `critical_fix_unshipped`, `high_fix_unshipped`, `kev_with_fix`, `max_epss_with_fix`, `max_days_fix_available`, `days_since_latest_release`,
`archived`, `scorecard_score` and `fix_date_unknown`.

## Limitations

- Results depend on the scanners' vulnerability databases and drift as those databases update. The report
  records scanner and database versions so a result can be reproduced or explained.
- Trivy and Grype detect packages independently, so their disagreement is informative. OSV is queried with
  Trivy's package list, so it is an independent database check, not an independent detector.
- Severity is the highest any source reported, which is conservative. Per-source severities are in the CSV.
- Version comparison is ecosystem-agnostic and approximate. It only affects which fix date is used. Build
  labels (`.jre11`, `-jre`, `-android`) are ignored when comparing.
- Scanners can read a JAR's version without its build label and report an already-fixed build as vulnerable
  (seen with `mssql-jdbc 12.10.2.jre11`). These rows are kept, marked in the `note` column and excluded from lag.
  OSV inherits the same mistake because it is queried with the scanner's version.
- The OpenSSF Scorecard API only covers repositories in its scheduled dataset. "Not scored" is not a
  negative signal.
- Release matching expects GitHub releases whose tags resemble the image tag (`1.2.3`, `v1.2.3`,
  `name-1.2.3`, `release-1.2.3`), and also tries the tag without a variant suffix (`2.528-jdk21` matches
  `jenkins-2.528`). If nothing matches, lag metrics are not computed rather than measured against the
  wrong release. Use `--release-tag` or `--release-date` in that case.
- Fix dates are unavailable for OS packages and the Go standard library. When more than half of the fixes lack
  a date, the likelihood suggestion is marked low confidence: read it as "not enough evidence", not "low risk".
- Only GitHub-hosted projects get health signals in this version.

Planned work is in [BACKLOG.md](BACKLOG.md).

## Licence

Apache License 2.0. See [LICENSE](LICENSE).
