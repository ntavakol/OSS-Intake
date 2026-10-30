# Changelog

All notable changes are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.11.1] - 2026-10-31

### Changed
- Neutral example names in the test data, code comments, validation guide and changelog.
- A `NOTICE` file states the copyright holder; it is included in the wheel and sdist with the licence.

## [0.11.0] - 2026-10-30

A Nexus collector and gate, `--fail-on unknown-age`, and download instructions for the collectors.

### Added
- `--fail-on unknown-age`: exit 3 when a language package version has no release date on deps.dev, so it
  could not be checked for being new: a version not indexed yet (likely when it is only hours old, when a
  compromised release does most harm) or one from a registry deps.dev does not cover (RubyGems, CRAN). Distro
  packages and the Go standard library do not count. Opt-in; `recent` is unchanged. Versions that could not be
  looked up (a failed lookup, or over `--release-age-max`) are named in the gate's output even when it trips.
- README: how to download the collectors (not part of the PyPI package) for your version, with SHA-256 sums a
  test keeps in step with the files.
- Nexus collector, `examples/nexus/nexus_sbom.py` (standard library only): lists what Nexus Repository proxies
  have cached as one CycloneDX SBOM per repository (npm, PyPI, Maven, NuGet, RubyGems, Go, Cargo, CRAN), with
  each file's checksums and the date it was cached; with `--state`, what is new since the last run goes to a
  separate folder for a gate, and only `--accept`, run after the gate passes, takes it off that list.
  Credentials come from the environment, never follow a redirect and never go over plain http except to
  localhost; who pulled each package is not copied. `examples/nexus/README.md` has the gate recipe and
  `try-nexus.sh` a throwaway Nexus in Docker to try it on. Tested against a real Nexus Community Edition.
- A replay test of 53 known-vulnerable PyPI and npm versions (`tests/test_recorded_seeds.py`): real OSV answers
  recorded on 30 Oct 2026, run with no network, failing if any expected CVE stops being found.
  `scripts/record_seeds.py` refreshes the recording.

### Fixed
- The new-release check skipped any package named `stdlib` in every ecosystem, not only Go's standard library.
- A scan that found only distro packages reported the new-release check as not run, failing `--fail-on recent`
  with exit 1; there is nothing for it to check, so it passes.
- A deps.dev answer for a version without a release date yet is no longer cached for 30 days.
- The new-release check sent a version with `+` (Go's `+incompatible`) encoded twice, so deps.dev answered
  404 and the version was never checked for being new.

## [0.10.0] - 2026-10-29

Organisation scale: an osquery collector for laptops and servers, parallel lookups, a response cache, and how
many systems each package is on.

### Added
- Large inventories: lookups that can be planned (OSV advisory details, deps.dev fix and release dates, latest
  versions, Ubuntu notices, proof-of-concept lists) are fetched 8 at a time instead of one by one.
- A response cache (`--cache-dir`, default the user cache folder; `--no-cache`): OSV advisory details for a day,
  deps.dev release dates for 30 days, latest versions for a day, proof-of-concept lists for 7 days. Which
  advisories affect a version, KEV, EPSS and the exploit indexes are always fetched fresh. assessment.json
  records the requests made and cache hits under `network`. Only successful answers are kept, never "not
  found"; entries that are not for the URL or are dated in the future are ignored; a cache folder other users
  can write to is not used.
- packages.csv gains `systems`: how many systems (SBOM subjects, or a system or host column) list each package
  version; equally bad packages on more systems rank first. Long host lists are shortened in reports and
  packages.csv, and `package-systems.csv` lists every package and system pair ("which hosts run X").
- `--release-age-max N` (default 400) sets how many release dates are looked up, counted after duplicates
  across hosts are merged.

### Changed
- A package version with no release date on deps.dev (not indexed yet, or not public) is now named in a
  warning as not checked for being new, rather than passing silently.
- An inventory column named like a column oss-intake fills in (`systems`, `findings`, `group`...) is refused
  with the name, instead of overwriting it in packages.csv.
- When several advisory lookups in a row fail, the rest are not attempted, so an unreachable service fails the
  run in seconds rather than one timeout per advisory.
- Package inventories may hold 500,000 rows (was 50,000), as many as SBOM components; a test runs 100,000 rows
  (5,000 versions on 20 hosts) in seconds.
- Proof-of-concept lookups are capped at 1,000 per run (was 300), now that they run in parallel and are cached.
- osquery collector, `examples/osquery/osquery_sbom.py` (standard library only): turns osquery's package tables
  into one CycloneDX SBOM per host, from a local `osqueryi` run (with `--dir` for venvs and project folders),
  from osquery snapshot logs (`osqueryd.snapshots.log` with any pack delimiter, Fleet or any log pipeline; both
  snapshot forms; one SBOM per host, latest snapshot of each query) or from a saved JSON object. deb and rpm packages carry the distro, epoch and source package
  (including dpkg's `source (version)` form); half-installed debs are kept; Python packages the distro
  installed are left to its deb or rpm package where that package is checked; home folders are shortened to
  `~` (Linux, macOS, Windows forms). Homebrew, Chocolatey, the operating system and Debian
  derivatives are written without a purl and listed as not checked with the reason. `oss-intake-pack.conf`
  holds the queries as a daily snapshot pack.
- SBOM input reads two component properties: `oss-intake:not-checked` (the reason a component without a purl
  cannot be checked) and `oss-intake:label:<key>` (a label such as `location`; names of columns oss-intake
  fills in are refused).

## [0.9.0] - 2026-10-28

SBOM input: CycloneDX and SPDX, including OS packages, wherever an inventory CSV worked.

### Added
- `--path` takes a CycloneDX (1.2 to 1.7) or SPDX (2.2, 2.3) JSON SBOM, or a folder of them (subfolders
  included, as an S3 sync leaves them; notes such as a README are allowed, but a folder that also holds a
  lockfile, CSV or YAML file is scanned as an application folder), recognised by content; GitHub's
  dependency-graph export and Amazon Inspector's SPDX (which describes every package) are read as they are. A
  folder mixing SBOMs with other JSON files is refused with their names. It is checked like a package inventory:
  packages.csv, executive summary, upgrade comparison, new-release check, decisions, `--fail-on`.
- OS packages (deb, rpm, apk, and `dpkg` as some tools write it) are checked in OSV under the distro's ecosystem
  and release (Ubuntu, Debian, Alpine, Rocky Linux, AlmaLinux, Wolfi, Chainguard) and by source package
  (`libssl3t64` is looked up as `openssl`), from Syft's `upstream` qualifier or Trivy's source properties, and
  fixes are compared with the source package's version (`cpp` 4:13.2.0 is built from `gcc-defaults` 1.214);
  packages.csv shows the fix as a version of the source (`gcc-defaults 1.214ubuntu2`) and the distro release in
  the ecosystem column (`deb (ubuntu-24.04)`).
  The distro release is part of a package's identity, so the same version in two releases is checked twice. A
  package type that does not match its distro label (an Alpine file system inside an Ubuntu host) is not checked.
  Per-CVE distro records are counted once: a grouped notice (USN, DSA) is dropped only when every CVE it names is
  also returned on its own. Their CVE is used for KEV, EPSS and exploit lookups; multi-CVE notices (Rocky,
  AlmaLinux) keep their own ID and are not matched against KEV or EPSS.
- Components that cannot be checked (no package URL, a version range, an OS release the SBOM does not state, a
  distro OSV has no data for such as Amazon Linux, or Red Hat's per-stream ecosystems) are listed in a "not
  checked" section and warning with the reason, never counted as clean.
- Labels from the SBOM (`system` from its subject, `supplier` from each component) and `--label key=value` for
  inventories and SBOMs, which fills in a label a package does not already have (and says so when every package
  already has it); names of columns oss-intake fills in are refused.
- `examples/sbom`: recipes for Amazon Inspector, Syft, Trivy and the GitHub dependency graph of an organisation.
  The weekly re-scan workflow takes an SBOM file or folder through `INVENTORY`.
- The report's scope shows the input format, e.g. "CycloneDX 1.7 (3 files)".

### Fixed
- Debian and Ubuntu version ordering: a tilde sorts first (`2.4.62-1~deb12u2` is older than `2.4.62-1`) and a
  rebuild suffix is newer (`1.2-3+b1` is newer than `1.2-3`); percent-encoded versions from package URLs
  (`1%3A2.39`) are decoded, and an epoch no longer reads as a major upgrade.
- Percent-encoded version ranges in package URLs (`%5E4.17.0`) are recognised as ranges, not queried as versions.

## [0.8.0] - 2026-10-26

Scanner signatures that can actually pass, hardening against hostile input, and a weekly re-scan workflow.

### Added
- `--trivy-archive`/`--grype-archive` and `--trivy-checksums`/`--grype-checksums`: before the scanner runs,
  cosign checks the release's Sigstore bundle on the checksums file (or the archive), the checksums file must list
  the archive's SHA-256 (matched by name, or by hash when the archive was saved under another name), and the
  executable must be byte-for-byte the one inside the archive. An archive with neither a checksums file nor a
  bundle is compared but noted as unanchored.
- `--govulncheck-sha256` (checked before govulncheck runs) and `--govulncheck-version`. The Docker or crane
  executable used to copy binaries out of an image is recorded with its SHA-256 in assessment.json.
- `examples/scheduled-rescan`: a GitHub workflow that re-scans an inventory weekly, carries decisions forward,
  keeps the reports as an artifact (also when a run fails) and opens an issue listing the Act now findings no
  decision has set aside and releases under a week old. A fingerprint in the issue title means the same list is
  reported once while its issue is open. It needs only `contents: read` and `issues: write` and never commits.
- A warning when `--sbom`, `--trivy-arg`/`--grype-arg`, `--image-src`, `--release-tag`, a scanner pin for a
  scanner that does not run, or a govulncheck option without `--reachability` would have no effect.

### Changed
- `--trivy-cosign-bundle` and `--grype-cosign-bundle` need the matching `--*-archive` (B10). Trivy signs its
  release archives and checksums file and Grype only its checksums file; neither signs the extracted executable,
  so a bundle checked against the executable could never pass on a real release (confirmed on Trivy 0.76.1).
- Option abbreviations are refused (`--offlin` no longer means `--offline`), and `--top`, `--timeout`,
  `--grace-days` and `--unshipped-days` are range checked before any work.

### Fixed
- A `.tar.gz` or `.zip` without PKG-INFO (`apache-tomcat-9.0.98.tar.gz`) was looked up on PyPI and reported as
  not published; it is now unsupported (B20).
- A missing scanner left an empty output folder behind (B24).

### Security
- pom.properties and package.json larger than 1 MB are never read; a small archive could inflate to gigabytes in
  memory (S2).
- `packages.csv` header cells and values joined with `;`, `,` or a tab are guarded against spreadsheet formulas,
  not only a leading `=` (signed numbers such as `-1` are left alone), and reading findings.csv back undoes the
  guard exactly, even for notes that already contain a quote before `=` (S3, S4).
- summary.md escapes Markdown and HTML in every line built from data (title, headings, paragraphs, lists and
  tables), so a package name, tag or advisory title cannot add links, images or raw HTML (S5).
- Registry identities read from inside an artifact must be valid coordinates (no path segments or `..`) and are
  URL-quoted, so a tampered file cannot steer the checksum lookup to another package (S6).
- Advisory text and workflow files are length-capped before pattern matching, which could take seconds on crafted
  input (S7).
- Unreadable archives no longer crash the run, and the temporary copy of an artifact is always removed (S8).
- govulncheck is pinned like Trivy and Grype (S9).

## [0.7.0] - 2026-10-26

Decisions and versions you can trust, a check for brand-new releases, and a CI gate.

### Added
- New-release check: every language package version the run knows about (inventory entries, or the image's or
  lockfile's package list) is looked up on deps.dev, and versions published fewer than `--release-age-days` ago
  (default 7; `0` turns it off) are flagged in a warning, a "New releases" tile and section, the executive summary,
  and `packages.csv` (new `published` and `new_release` columns). Compromised releases are usually live for hours
  or days before they are pulled and before any advisory exists. Up to 400 lookups per run.
- `--fail-on` for CI: exit 3 when any of `malicious`, `kev`, `act`, `critical`, `high`, `recent` or `mismatch` is
  found, naming which. Findings set aside by evidence or an assessor decision do not count; malicious packages
  always do. A gate whose check is turned off (`--offline`, `--release-age-days 0`, `--no-registry-check`) is
  refused, and one whose check could not run fully (deps.dev errors, no package list) exits 1 rather than pass.
- findings.csv column `triage_justification` (optional OpenVEX justification), so decisions survive
  findings.csv to OpenVEX and back unchanged.
- Issue templates; security reports are pointed to private advisories.

### Changed
- **Breaking for existing findings.csv files:** `mitigated` in `triage_status` now means not affected with the
  justification `inline_mitigations_already_exist` (CycloneDX `protected_by_mitigating_control`), not fixed: a
  compensating control is not a fix. A `mitigated` row now needs `triage_notes`; one without stops the run
  (exit 2), where 0.6 read it as `fixed`. Rows already saved as `fixed` are unchanged.
- A decision for another version of a finding that is still present is no longer listed as resolved.
- An inventory's "upgrade to" is the lowest listed fix that is fixed for every finding on its release line.
- PyPI metadata: current summary, Python 3.10 to 3.13 classifiers, Documentation and Sample report links. CI also
  runs Python 3.11 and 3.12.

### Fixed
- Two decisions for one vulnerability in one package at two versions overwrote each other; the one for the
  installed version now wins (B3).
- The tool could not read back its own openvex.json for OS packages (`pkg:deb/ubuntu/libc6` loaded as package
  `ubuntu/libc6`); the distro namespace is dropped, the epoch qualifier read, and encoded versions decoded
  (`7.88.1-10%2Bdeb12u14`) (B4).
- Notes starting with `-`, `=`, `+` or `@` gained a quote, and multi-line notes were flattened, after a round trip
  (B18, B21).
- OSV commit hashes from GIT ranges could become the fix and "upgrade to" version (B5).
- Letter-patched versions sorted wrong (OpenSSL `1.1.1m` below `1.1.1l`), so their fixes were missed; OpenSSL's
  letters past z (`0.9.8za` to `0.9.8zh`) sort after `z`, and PEP 440 pre-releases such as `1.0a` stay before
  `1.0` (B6).
- "Upgrade to at least" could name a version that still had a vulnerability fixed on another release line (B7).
- PyPI names in an inventory `purl` column were not normalised, so OSV's fixes never matched (B8).
- The same Go fix appeared twice when sources disagreed on the `v` prefix (B19).
- The sdist now contains the test fixtures, so its tests run (B11).
- A malformed pinned hash (`--trivy-sha256`, `--grype-sha256`, `verify --sha256`) is an input error, exit 2 (B16).
- Placeholder versions such as `4.x`, `4.1.X` and `31.+` are refused in an inventory (B17).

## [0.6.1] - 2026-10-26

Fixes from the 0.6.0 review: no report may look cleaner than the checks behind it.

### Fixed
- Sources that did not run (CISA KEV, exploit indexes, EPSS, OSV malicious package data) were shown as green
  zeros, and Routine reasons said "no exploit indexed, EPSS below 0.1" even with `--offline`. They now show as
  "not checked" with the reason, Routine reasons name only the checks that ran, a warning says a zero means not
  checked, and the summary line adds `not_checked=`. Fix-date coverage no longer blames an ecosystem when dates
  were not looked up.
- A wrong or empty file given to `--from-trivy-json` or `--from-grype-json` (for example Grype JSON as Trivy, or
  `{}`) gave `findings=0` and exit 0. It is now refused with exit 2, saying what the file looks like (an SBOM is
  named as such). UTF-16 files, as Windows PowerShell 5.1 redirection writes them, are read. An imported Trivy or
  Grype report for a different image than `--image` (another repository, tag or digest) gives a warning.
- An `renv.lock` scan whose OSV lookup failed reported green zeros and exit 0; with OSV its only source, it now
  stops with exit 1, as does an inventory (previously exit 2 there).
- An impossible date (`--as-of 2026-02-30`, or one in scanner, API or Debian and Go release data) crashed the
  run; it is now a usage error, or skipped in data.
- `verify` printed `OK sha256` and then failed on a missing `--cosign-identity`; all options are checked first.

### Security
- With `--trivy-sha256` or `--grype-sha256`, the scanner's hash (and cosign signature, if given) is checked
  before the binary is executed at all; previously its `--version` ran first. Cosign now runs once per scanner,
  not twice. `doctor` records the hash before
  running `--version` and notes that the binary was not verified.

## [0.6.0] - 2026-10-26

Checks that a downloaded artifact is the published one, a one-page summary for an inventory, and VEX for
Dependency-Track.

### Added
- CycloneDX 1.6 VEX export (`vex.cdx.json`) beside openvex.json whenever decisions apply, for Dependency-Track:
  not_affected, affected, fixed and under_investigation map to not_affected, exploitable, resolved and in_triage,
  with justifications where CycloneDX has an equivalent. Validated against the CycloneDX 1.6 JSON schema.
- Executive summary for inventories (`executive-summary.html`): packages checked; how many need action now, have
  critical vulnerabilities, or have had no release for over a year (from the latest release's date on
  deps.dev); the top ten packages to act on, with the action; totals by owner; known vulnerabilities now, at the
  minimum fixes and at the latest releases; and, with `--decisions` from the previous run's findings.csv, new
  findings and findings no longer present.
- Artifact integrity for `--path`: a JAR, WAR or EAR, a Python wheel or sdist, or an npm `.tgz` is compared with
  the checksum its registry publishes for that version (Maven Central via the archive's pom.properties, PyPI,
  npm). A mismatch leads the report with a warning, a "Registry checksum" tile and a red header; the result is
  also in the scope table and assessment.json. `--no-registry-check` skips it.

## [0.5.0] - 2026-10-26

Assess once, not every run: assessor decisions carry over between runs and export as OpenVEX.

### Added
- `--decisions FILE` reads the assessor's decisions from an earlier findings.csv (`triage_status`,
  `triage_notes`, `triage_reachable`) or an OpenVEX document, and applies each to the same vulnerability in the
  same package. `not_affected` and `fixed` set the finding aside with the note as the reason; `affected` and
  `under_investigation` keep the group and add the note. Decisions made for another installed version are marked
  for review, decisions whose vulnerability is gone are listed as resolved, and a malicious package is never set
  aside. Decisions are validated before anything is scanned.
- findings.csv comes out with the decisions filled in, plus `triage_decided_version`, so it feeds the next run.
- `openvex.json` (OpenVEX v0.2.0) is written whenever decisions apply, for Grype or Trivy (`--vex`).
- "Assessor decisions" section in the HTML and Markdown reports, and an "assessor:" marker on decided findings.

### Fixed
- README: the example output, likelihood rules (the malicious-package rule was missing) and metric list are now
  generated from the code by `scripts/readme_sync.py`, and tests fail if they drift. Eight `scan` options and the
  `verify` options were undocumented.
- With `--as-of` before a fix was published, "days a fix has been available" was negative; it is now 0.

## [0.4.0] - 2026-10-26

Is upgrading worth it? Package inventories now compare the installed version with the minimum fix and the latest
release.

### Added
- Upgrade comparison for package inventories: for each package, what is still known to affect the minimum fix
  version (one batched OSV query) and the latest release on deps.dev, and whether either upgrade crosses a major
  version (or a minor version below 1.0). Shown in the Packages section and in packages.csv (`upgrade_left`,
  `upgrade_major`, `latest`, `latest_left`, `latest_major`), with a summary of how many packages the minimum fix
  clears completely.
- `--no-latest` skips the latest-release lookup (one request per package) for faster runs or a current-state
  view; the minimum fix is still checked.
- "Latest release" is the latest stable release: pre-releases (alpha, beta, rc, milestone, snapshot, dev) are
  never suggested, even where deps.dev marks one as the default (log4j-core 3.0.0-beta3). Malicious packages
  also show the latest release, as the clean version to move to.

### Fixed
- Go fix versions from OSV now carry the `v` prefix (`v0.60.0`), matching Go and the installed version.

## [0.3.0] - 2026-10-26

Check the open source an organisation already uses: pass a package inventory instead of an image.

### Added
- Package inventory input: `--path packages.csv` with `ecosystem,name,version` or `purl` columns, exported from a
  package repository (Artifactory, Nexus) or a spreadsheet. Any other column (owner, system, team) is carried
  through as a label. Every row is validated first; invalid rows stop the run with row numbers before anything
  is looked up. Packages are checked against OSV only, so no scanner is needed, and malicious releases are
  flagged as well as vulnerable ones.
- `packages.csv` output for inventories: every package, worst first, with findings, malicious and KEV flags, the
  lowest version that fixes every listed vulnerability with a fix, and its label columns. The HTML and Markdown
  reports gain a Packages section, and the HTML report a "Packages checked" tile.
- `labels` column in findings.csv.
- `examples/inventory/packages.sample.csv`.
- Project site on GitHub Pages with the compromised-npm sample report, README screenshots
  (`scripts/screenshots.py`) and a quickstart.

### Fixed
- An unreadable `renv.lock` or inventory now ends with a clear error instead of a traceback.
- README links are absolute, so they work on PyPI.

## [0.2.4] - 2026-10-26

Malicious packages are now the first thing a report shows.

### Changed
- HTML and Markdown reports show Warnings straight after the summary, not at the end: a malicious package or a
  missing input changes how everything below should be read.
- The HTML report has a "Malicious packages" tile and a red header stripe when any package is malware.
- "Known malicious packages" counts packages, not findings (one package can have several advisories).

### Fixed
- The malicious-package warning listed only five packages and ended in four dots; it now lists up to ten.

### Added
- `examples/compromised-npm/`: a lockfile with six well-known compromised npm releases (chalk, debug,
  @ctrl/tinycolor, ua-parser-js, event-stream, flatmap-stream) and a script that rebuilds the sample report.

## [0.2.3] - 2026-10-26

Compromised releases of trusted packages are now flagged reliably. Found by scanning a lockfile with the
well-known compromised versions of chalk, debug, @ctrl/tinycolor, ua-parser-js and event-stream.

### Fixed
- Malware advisories without an OpenSSF `MAL-` entry were treated as ordinary vulnerabilities: ua-parser-js 0.7.29
  (hijacked in 2021) landed in Routine and event-stream 3.3.6 in Review. Advisories classed as embedded malicious
  code (CWE-506) now mark the package version as malicious (Act now, likelihood 5, warning).
- npm scoped packages: OSV results named `%40ctrl/tinycolor` did not match `@ctrl/tinycolor` from Trivy and
  Grype, so the malicious flag did not reach every finding on the package. Names are now decoded.
- An OSV `MAL-` entry and the GitHub advisory it aliases (GHSA) appeared as two findings for the same release.
  Findings now merge on a shared GHSA ID when there is no CVE.

### Added
- `cwes` column in findings.csv (CWE IDs from Trivy and OSV).

## [0.2.2] - 2026-10-26

Report fixes found by scanning a plain requirements.txt with the PyPI release.

### Fixed
- findings.csv is now always written. The reports point to it for the full list and the triage columns, but
  `--formats html,md` used to leave it out.
- Without a release date, the "Fix existed before release" tile showed a green 0, which read as good news. It now
  shows n/a and says to pass --repo or --release-date.
- Without --repo, Project health was a table of n/a values. It is now one line saying what --repo adds.
- Advisory conditions: sentences that describe how a flaw works ("... is used to recompute ...") are no longer
  quoted as conditions, so those findings stay in Routine. A leading affected-version clause ("In Django 3.2
  before 3.2.19, ...") is dropped and Markdown links keep only their text.
- The plan line no longer prints image-only settings (image source, platform) for --path scans.

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
weaponised) and on a Spring Boot application image.

### Added
- Public exploit availability per finding, as the strongest evidence found: known exploited (CISA KEV),
  weaponised (a Metasploit exploit or auxiliary module, or a Nuclei template), public (Exploit-DB), proof of
  concept (GitHub repositories indexed by nomi-sec/PoC-in-GitHub, forks not counted), or none indexed. When a
  source cannot be loaded the level is "not checked", never "none". `exploit_level` and `exploit_refs` columns
  in findings.csv, an Exploit column in the reports, and `--no-exploits` to skip it. About 25 MB is downloaded
  per scan; proof-of-concept files only for findings with no stronger evidence, capped at 300. Proof-of-concept
  hits list the repositories (name and stars), because some are not exploits at all: on one test image the
  only hit for a CVE was a rating-checker tool. Findings without a CVE ID are marked "no CVE ID".
- Two default likelihood rules: a ready-to-use exploit (Metasploit or Nuclei) on a finding with a fix gives
  level 4; an Exploit-DB entry gives level 3. Proofs of concept alone do not change the likelihood.
- Advisory conditions: the advisory's own "affected only if" sentences, quoted verbatim in a `conditions`
  column and shown on hover in the HTML report (an "if" marker beside the ID). For example CVE-2026-47884
  applies only with XsltView, a "/**" mapping and no explicit view name. The tool does not judge whether the
  conditions hold.

## [0.1.8] - 2026-10-25

CVSS version and source on every score, with v4 used only when no v3 score exists. On a Spring Boot
application image it showed the 9.8 scores on three Spring CVEs came from GHSA, while Spring itself rates
them Medium or Low.

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
- `target` listed both the outer archive (Grype: `/opt/app/app.jar`) and the JAR inside it
  (Trivy: `opt/app/app.jar/BOOT-INF/lib/...`); only the more specific path is kept now.

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

First release. Validated against five public images on macOS (a Spring Boot application, Grafana, Jenkins,
nginx and an R image on Ubuntu), and on Windows.

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
