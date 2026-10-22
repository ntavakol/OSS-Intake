# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- `python -m oss_intake` entry point for environments where the console script is not on PATH.
- `--grace-days` (default 14): fixes published just before a release are no longer counted as missed.
- Forward-looking "unshipped" metric (`--unshipped-days`, default 90) and matching likelihood rules at levels 3
  and 4, so fixes that accumulate after a release with no newer release raise the suggestion.
- `note` column in findings.csv.

### Fixed
- Build labels such as `.jre11` made a version sort below its unlabelled form, so the nearest fix could be
  taken from the wrong major version.
- Findings where the installed version equals a listed fix apart from a build label are flagged as likely
  already fixed and excluded from lag.
- The "no release date" warning now gives the actual reason (for example `--offline`).

## [0.1.0] - 2026-10-22

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
