# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- Fix date coverage table per ecosystem in every report (and `coverage` in assessment.json), with the reason
  when an ecosystem has no date source, so readers can see how far to trust the lag numbers.
- Regression tests on trimmed real scan output from public images, and `scripts/extract_regression_fixture.py`
  to produce them.
- Ubuntu fix dates from Ubuntu Security Notices in OSV, matched strictly on CVE, release, source package and
  fixed version. Trivy source package fields (`SrcName`, `SrcVersion`, `SrcRelease`) are now kept.

## [0.1.0] - 2026-10-22

First release. Validated against five public images on macOS (ShinyProxy, Grafana, Jenkins, nginx, rocker/shiny), and ShinyProxy also on Windows.

### Added
- `scan` (default command): Trivy, optional Grype cross-check, and OSV queries for container images.
- Merged findings with per-source attribution and severities.
- Release-lag metrics based on fixed-version publication dates from deps.dev.
- Project health from GitHub releases and the OpenSSF Scorecard API; CISA KEV flagging.
- Optional, configurable 5x5 likelihood heuristic and `--fail-on-likelihood` for pipelines.
- CSV, Markdown, JSON and self-contained HTML reports; raw scanner output kept as evidence.
- Scanner integrity: version pinning, known-bad list (Trivy 0.69.4 to 0.69.6, CVE-2026-33634), SHA-256 and
  optional cosign verification.
- `doctor` and `verify` commands.
- Import of existing Trivy and Grype JSON reports.
- `python -m oss_intake` entry point for environments where the console script is not on PATH.
- `--grace-days` (default 14): fixes published just before a release are no longer counted as missed.
- Forward-looking "unshipped" metric (`--unshipped-days`, default 90) and matching likelihood rules at levels 3
  and 4, so fixes that accumulate after a release with no newer release raise the suggestion.
- `note` column in findings.csv.
- `--platform` (default `linux/amd64`) passed to both scanners so they scan the same image variant.
- Fix dates for Debian packages from the DSA and DLA advisories Trivy reports, dated from the Debian security
  tracker's advisory lists (OSV as fallback; it lacks recent DLAs). The `fix_date_source` column shows where
  each date came from. Ubuntu and Alpine stay unknown for now.
- GitHub release dates as a fallback fix date for Go modules hosted on GitHub that deps.dev does not index.
- The likelihood section says when the scanned release is not the project's latest.
- Likelihood confidence (normal or low) with reasons, shown in the summary and on the CLI.

### Fixed during pre-release testing
- Build labels such as `.jre11` made a version sort below its unlabelled form, so the nearest fix could be
  taken from the wrong major version.
- Findings where the installed version equals a listed fix apart from a build label are flagged as likely
  already fixed and excluded from lag.
- The "no release date" warning now gives the actual reason (for example `--offline`).
- Go fix versions were looked up on deps.dev without the required leading `v`, so no Go fix dates were found.
- An unmatched image tag no longer falls back to the latest release date, which overstated lag. Variant
  suffixes such as `-jdk21` and `-alpine` are now stripped when matching release tags.
- Grype ran with `-q`, which hid its error messages.
- Release tags older than the newest 100 releases were not found (seen with Grafana); each candidate tag is now
  looked up directly.
- Likelihood confidence is no longer reported as low when the top level (KEV) fired, since missing evidence
  could only have hidden a higher level.
- The OSV warning for OS-only images no longer suggests a misconfiguration.
- Go modules at v2+ without a `/vN` path (Grafana, Tempo) are retried on deps.dev as `+incompatible` versions.
- Version comparison treated unrecognised suffixes as pre-releases, so Debian security updates
  (`10.42-1+deb12u1`) sorted below the original version (`10.42-1`).
- When no listed fix is newer than the installed version, the finding is flagged for review instead of taking
  its date from an older version.
