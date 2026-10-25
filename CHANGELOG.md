# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.1] - 2026-10-25

First release published to PyPI (`pipx install oss-intake`), built and signed in GitHub Actions. The repository
now runs OpenSSF Scorecard and CodeQL on itself. No change to assessments.

### Added
- The repository runs OpenSSF Scorecard on itself (published results and a README badge) and CodeQL static
  analysis, both with every action pinned by commit SHA and least-privilege permissions.
- Release workflow: a published GitHub release builds the package with hash-pinned tools, publishes it to PyPI
  through trusted publishing (no stored token, with provenance attestations), and attaches Sigstore signatures
  to the release. `pipx install oss-intake` from the first release that runs it.

### Changed
- Package metadata: SPDX licence expression, project links, author. Builds no longer show setuptools
  deprecation warnings.

## [0.2.0] - 2026-10-25

From a vulnerability list to a triaged assessment. Findings are grouped into a suggested reading order (Act
now, Review, Check conditions, Routine, Set aside) with reasons; JARs, binaries and lockfiles can be assessed
without an image; known malicious packages are flagged; and Go binaries can be checked for reachability with
govulncheck. Validated on log4j-core 2.14.1 (Log4Shell in Act now), flatmap-stream 0.1.1 (malicious) and
redis 7.4.1 (121 of 124 Go standard library findings not reachable).

### Added
- `--path`: assess a JAR, WAR, EAR or binary (Trivy `rootfs`, Grype `dir:`), a folder of built artifacts, a
  dependency lockfile the scanners understand (Trivy `fs`), or an R `renv.lock`, read by oss-intake and checked
  against OSV's CRAN advisories. A version in an artifact's file name is tried as the release tag. Single files
  are copied into an empty temporary folder so the scanners see only that file.
- Known malicious packages: findings listed in the OpenSSF malicious packages database (OSV `MAL-` IDs) are
  marked MALICIOUS, placed in Act now, raise a warning naming the packages, trigger likelihood level 5, and are
  kept whatever `--min-severity` says (these entries often carry no severity).
  Every other finding on the same package version is marked too, since GitHub and other advisories for the same
  malware often do not list the `MAL-` ID (seen on flatmap-stream 0.1.1, the 2018 event-stream incident).
- Suggested triage: every finding gets a group and a one-line reason (`suggested_group`, `suggested_reason` in
  findings.csv), and the reports open with a triage table. Act now: CISA KEV or a ready-to-use exploit. Review:
  an Exploit-DB exploit, EPSS 0.1 or more, or a critical whose advisory states no conditions. Check conditions:
  the advisory says when it applies. Routine: none of these. Set aside: only with evidence (kernel header
  package, or already fixed apart from a build label). Top findings are ordered by group. A reading order, not a
  risk rating.

- `--reachability` (opt-in): Go binaries are checked with govulncheck in binary mode, an external executable
  the user installs. Findings whose vulnerable functions are not in any binary they were seen in are marked "not
  reachable" and set aside in triage, with the govulncheck ID; those whose function is present are marked
  "reachable" and reviewed. Image binaries are copied out with Docker or crane. Lag and likelihood do not change.
  On redis 7.4.1, 121 of 124 Go standard library findings (all in gosu) were shown not reachable.
- Proof-of-concept lookups, which are capped per scan, are no longer spent on findings already set aside on
  evidence; the bulk exploit sources still cover them.

### Changed
- The HTML findings table shows severity and CVSS in one column, to fit the new Group column.

## [0.1.9] - 2026-10-25

Public exploit availability and the advisory's own conditions for each finding. Checked against live
Metasploit, Nuclei and GitHub proof-of-concept data (Log4Shell, Spring4Shell, PAN-OS and ActiveMQ come back
weaponised) and on ShinyProxy 3.2.4.

### Added
- Public exploit availability per finding, as the strongest evidence found: known exploited (CISA KEV),
  weaponised (a Metasploit exploit or auxiliary module, or a Nuclei template), public (Exploit-DB), proof of
  concept (GitHub repositories indexed by nomi-sec/PoC-in-GitHub, forks not counted), or none indexed. When a
  source cannot be loaded the level is "not checked", never "none". `exploit_level` and `exploit_refs` columns
  in findings.csv, an Exploit column in the reports, and `--no-exploits` to skip it. About 25 MB is downloaded
  per scan; proof-of-concept files only for findings with no stronger evidence, capped at 300. Proof-of-concept
  hits list the repositories (name and stars), because some are not exploits at all: on ShinyProxy the only
  hit for CVE-2026-47884 was a rating-checker tool. Findings without a CVE ID are marked "no CVE ID".
- Two default likelihood rules: a ready-to-use exploit (Metasploit or Nuclei) on a finding with a fix gives
  level 4; an Exploit-DB entry gives level 3. Proofs of concept alone do not change the likelihood.
- Advisory conditions: the advisory's own "affected only if" sentences, quoted verbatim in a `conditions`
  column and shown on hover in the HTML report (an "if" marker beside the ID). For example CVE-2026-47884
  applies only with XsltView, a "/**" mapping and no explicit view name. The tool does not judge whether the
  conditions hold.

## [0.1.8] - 2026-10-25

CVSS version and source on every score, with v4 used only when no v3 score exists. Used for the
ShinyProxy 3.2.4 assessment, where it showed the 9.8 scores on three Spring CVEs came from GHSA, while
Spring itself rates them Medium or Low.

### Added
- CVSS provenance: findings.csv has `cvss_version` and `cvss_source` (nvd, ghsa, redhat, debian...), the Markdown
  top findings show them next to the score, and the HTML report shows them on hover.
- CVSS v4 scores (from Trivy and Grype) are used when no source gives a v3 score, marked "v4" in the reports. A v3
  score always takes precedence; the two scales are not comparable. OSV publishes vectors only, and v4 needs the
  full lookup tables to score, so OSV contributes v3 only.

### Changed
- Trivy's CVSS is now the highest v3 score across the sources it lists, not the score from the source of its
  severity rating, so the report's "highest across sources" holds for every finding. Where a distro rates a CVE
  lower than NVD, the severity column keeps the distro rating and the CVSS source shows where the score came from.

### Fixed
- `target` listed both the outer archive (Grype: `/opt/shinyproxy/shinyproxy.jar`) and the JAR inside it
  (Trivy: `opt/shinyproxy/shinyproxy.jar/BOOT-INF/lib/...`); only the more specific path is kept now.

## [0.1.7] - 2026-10-25

Ubuntu fixes dated from Launchpad, and a more accurate CI hygiene check. mongo 7.0.14 (Ubuntu 22.04):
every fixable finding dated (Ubuntu 326/326, Go standard library 196/196, Go modules 28/28).

### Added
- Ubuntu fix dates from Launchpad's publishing history when no Ubuntu Security Notice matched: the earliest
  publication of the exact fixed version to the image's release in the Release, Security or Updates pocket.
  On mongo 7.0.14 (Ubuntu 22.04) the probe found every sampled undated fix, most in the Security pocket.

### Changed
- CI hygiene: `pull_request_target` is now reported separately from the risky case, a workflow that also checks
  out the pull request's code. The trigger alone (labelling, commenting) is common and safe, and was presented as
  a concern (seen on Jenkins, whose three such workflows check out no PR code).
- The `target` column in findings.csv lists every location a merged finding was seen in, `;`-separated, instead
  of only the first (for example one Go CVE in each of MongoDB's tool binaries).
- The OSV Ubuntu notice warning says how many lookups failed and whether Launchpad covered them.

## [0.1.6] - 2026-10-25

New HTML report layout with CVSS, and Go standard library fix dates. Validated on redis 7.4.1, traefik v3.1.6,
Keycloak 26.0.5 and mongo 7.0.14: Go standard library coverage 0% to 100% on all three Go images.

### Added
- Go standard library fix dates from the Go release history (go.dev/doc/devel/release), one fetch for all
  versions. Trivy (`v1.22.7`) and Grype (`go1.22.7`) version forms are both handled. In validation the standard
  library was the largest undated group on Go-based images (redis 64, traefik 61, mongo 130 HIGH+ findings).
- `scripts/validate_images.py` also writes report.html for each image.

### Changed
- New HTML report layout: summary tiles, a severity bar, severity pills, and colour-coded values with fixed
  thresholds (days a fix has been available, CVSS, EPSS, Scorecard, fix-date coverage, CI hygiene), light and
  dark mode, and a print style. Still one self-contained file with no scripts.
- The top findings table shows the CVSS v3 base score, in the HTML and Markdown reports.

### Fixed
- Go standard library findings from Trivy (`v1.18.2`) and Grype (`go1.18.2`) for the same binary were not merged,
  so they appeared twice and inflated the Grype-only count (seen on mongo:7.0.14).
- When the image build date stands in for a release, the scope line now says so plainly instead of
  "(image build date) (date), from image build date".

## [0.1.5] - 2026-10-25

Debian fixes without a security advisory are now dated. Nextcloud 31.0.9 (Debian 13): Debian fix date coverage
1,774 of 1,779 (100%), 673 of them from point releases.

### Added
- Debian fixes that shipped without a DSA or DLA are dated from the point release that included the exact fixed
  version, read from the suite's ChangeLog on deb.debian.org. Fixes still in proposed-updates stay undated, with a
  note. On Nextcloud 31.0.9 (Debian 13) most undated Debian fixes were of this kind.
- Debian findings are also matched to an advisory by exact fixed version when the scanner reports no advisory ID,
  or the advisory does not list that CVE.

### Fixed
- `scripts/validate_images.py` stops with a clear message when run with a Python that does not have oss-intake
  installed, instead of reporting every image as failed with no error.

## [0.1.4] - 2026-10-24

Alpine fix dates, and a version comparison fix that affected every distro image.
Node-RED 4.1.0 (Alpine 3.22): Alpine fix date coverage 0% to 86%.

### Added
- Alpine fix dates from the aports commit history (GitHub mirror): the earliest commit on the image's release
  branch that names the CVE, or the fixed version for a new upstream release. Rebuilds of the same version
  (`-r1` and up) need the CVE or exact version in the commit, otherwise they stay unknown.

### Fixed
- Package revisions were compared as part of the version, so Alpine `2.41-r9` sorted above `2.41.6-r0`
  (and Debian `2.41-9` above `2.41.6-1`, RPM likewise), and real fixes were flagged as "no newer fix".
  The upstream version is now compared first, then the revision.
- When the local container engine cannot export an image, the error suggests `--image-src remote`.
- Grype-only OS findings now keep the distro release and source package, so they can be dated.

## [0.1.3] - 2026-10-24

Validated on six more images (UBI 9.6, python:3.13-slim, Superset 5.0.0, rocker/r-ver 4.5.1, Node-RED 4.1.0,
Nextcloud 31.0.9). Most important change: kernel CVEs on kernel header packages no longer drive the likelihood.

### Added
- `scripts/validate_images.py` and `scripts/validate-images.txt`: scan a list of public images and write one
  summary table, for validating changes against real data.
- PHP Composer fix dates from Packagist release times.
- Release tags with a prefix (`R4.5.1`, `server-31.0.9`) match an image tag on the version number, when
  exactly one release carries it.
- The likelihood section names the findings behind it (KEV and highest EPSS), with the component and which
  scanner found them, so a reader can see when a bundled runtime (for example Chrome found by Grype in a
  binary) rather than the project's own code drives the rating.
- Distro advisory IDs from Grype matches are kept, so Grype-only OS findings can be dated.

### Fixed
- Kernel CVEs matched to kernel header packages (`linux-libc-dev`, `kernel-headers`, `linux-headers-*`) drove
  the likelihood to "almost certain" on images where they cannot apply: containers run on the host's kernel.
  They are now kept in findings.csv with a note but excluded from lag and likelihood
  (`--include-kernel-headers` restores the old behaviour).
- The unshipped metric showed 0 for releases that are not the project's latest; it is now n/a, and no longer
  lowers likelihood confidence, since it does not apply.

## [0.1.2] - 2026-10-24

Red Hat family fix dates and an image build date fallback for projects without matching GitHub releases.

### Added
- Red Hat family fix dates (RHEL, UBI) from the RHSA advisories Trivy reports, dated from Red Hat's CSAF
  documents. Amazon Linux gets its own coverage row; Trivy reports no ALAS IDs, so it stays unknown.
- When no GitHub release matches and `--release-date` is not given, the image's build date (OCI config
  `created`) is used as the release date for lag metrics, labelled as such. `--no-image-date` disables it.

## [0.1.1] - 2026-10-22

Fix date coverage for Ubuntu and Debian images, EPSS, and a CI hygiene audit of the assessed project.

### Added
- Fix date coverage table per ecosystem in every report (and `coverage` in assessment.json), with the reason
  when an ecosystem has no date source, so readers can see how far to trust the lag numbers.
- Regression tests on trimmed real scan output from public images, and `scripts/extract_regression_fixture.py`
  to produce them.
- Ubuntu fix dates from Ubuntu Security Notices in OSV, matched strictly on CVE, release, source package and
  fixed version. Trivy source package fields (`SrcName`, `SrcVersion`, `SrcRelease`) are now kept.
- EPSS exploit probability per CVE (FIRST API, `epss` and `epss_percentile` columns, `--no-epss`), with default
  likelihood rules at level 4 (EPSS 0.5 or more on a finding with a fix) and level 3 (0.1 or more).
- Audit of the target project's GitHub Actions workflows: unpinned actions, known-bad action versions
  (`trivy-action` below 0.35.0, `setup-trivy` below 0.2.6), missing or write-all permissions, and
  `pull_request_target` triggers. Reported only; it does not change the likelihood. `--no-workflows` to skip.

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
