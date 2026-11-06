# Threat model

What oss-intake protects, where untrusted input enters, and what stops it doing harm. Each section below is one
trust boundary: what crosses it, what is at risk, the threats with the mitigations in the code (by function, so
they can be found and their tests read), and what is left open. The open items that could be fixed are listed at
the end; those agreed for later versions move to BACKLOG.md.

## What oss-intake protects

- **The verdict.** People use the report and the exit code to decide whether to adopt software, and CI gates use
  exit 3 to block it. The worst outcome is a wrong "clean": a check that did not run, or input that was forged,
  reading as no findings. The design rule throughout is that a check which could not run fails the gate (exit 1)
  rather than passing it.
- **The machine running it.** Its files, disk, memory and time, and the code that runs on it: the scanners
  oss-intake starts and anything in the software being assessed, which is never run.
- **The user's secrets.** `GITHUB_TOKEN`, and the paths and names of the user's machine.
- **The reader of the report.** Reports are opened in browsers, Markdown viewers and spreadsheets.

oss-intake has no server, no account and no database. It runs as the user, with the user's rights; nothing it
does needs more.

## Scanner binaries (Trivy, Grype, govulncheck)

**What crosses:** oss-intake starts programs the user installed and reads their JSON output. A scanner release
can be compromised (Trivy 0.69.4 was a malicious release, and 0.69.5 and 0.69.6 malicious image tags), and a
binary on the PATH may not be the one the user meant.
Reports from earlier runs can also be imported (`--from-trivy-json`, `--from-grype-json`).

**Assets at risk:** the machine (a malicious scanner runs as the user) and the verdict (a scanner that reports
nothing, or output that is not what it seems).

| Threat | Mitigation | Where |
|---|---|---|
| A scanner command line is hijacked: shell metacharacters, or an image reference read as an option | Scanners run as an argument list without a shell. Image references must start with a letter or digit and carry a tag or digest, so `-x`, spaces and `;` are refused (exit 2). | `scanners.run`, `options.validate_image` |
| A known-compromised scanner release runs | Its version is read from the Go build information in the file, without running it, and checked against `known_bad.json`; the version the binary reports is checked again. Either match refuses the run. | `integrity.refuse_known_bad_before_run`, `integrity.check_binary` |
| A swapped or tampered binary runs | With `--<tool>-sha256`, a cosign bundle, or the release archive and its checksums, the binary is checked before it runs at all. Without them the report says the hash was not verified. | `integrity.verify_before_run`, `scanning.run_or_load` |
| A scanner that fails, hangs or prints nothing reads as "no findings" | A non-zero exit, a timeout or output that is not JSON stops the run with exit 1. | `scanners.run`, `scanners.load_json_bytes` |
| The wrong file is imported (an SBOM, another tool's report, `{}`), so it reads as clean | An imported report must have the tool's shape, or it is refused, and one that names nothing it scanned and lists nothing is refused too; one for a different image is warned about. | `scanners.check_report`, `scanners.report_kind` |
| A required scanner is missing | Named scanners must be found. With `--scanners auto`, a missing Grype is a warning in the report, not silence. | `scanners.find_executable`, `cli` |

**Left open:**

: `{"SchemaVersion": 2}` with no `Results`, or `{"matches": []}`, is accepted as a
  clean Trivy or Grype report, so a truncated or forged import reads as no findings.
- With `--<tool>-archive` and `--<tool>-checksums` but no signature, the binary is reported as hash verified
  against a checksums file nothing has signed.
- The binary is checked by path and then run by path: someone who can write to it or its folder could replace
  it in between. The binary's own folder is not checked for who can write to it.
- On Windows, `shutil.which` looks in the current folder before the PATH, so a `trivy.exe` there is the one
  found. A pinned hash still stops it.
- govulncheck has no known-bad list and its hash is checked only with `--govulncheck-sha256`, yet with
  `--reachability` its "not reachable" verdict sets a finding aside, ahead of KEV, so it no longer counts for
  any gate. The build-label and kernel-header rules also set findings aside ahead of KEV and malicious packages.
- The default cosign identity accepts a signature from any workflow or ref in the scanner's repository, not only
  its release workflow. cosign itself, and docker and crane (used to get binaries out of an image for
  govulncheck), are found on the PATH and not verified.
- A folder given to `--path` whose name starts with `-` reaches Trivy, and with `--reachability` govulncheck, as
  an option (Grype gets a `dir:` prefix).
- Scanner output size is not limited, and the scanner's vulnerability database age is shown but not enforced.
- Anything wrong inside a scanner (a parser flaw reached by the files it reads) is the scanner's: pin and verify
  it as the guide describes.

## Public services (network)

**What crosses:** JSON and text from OSV, deps.dev, the GitHub API and raw.githubusercontent.com, GitLab, CISA
KEV, FIRST EPSS, OpenSSF Scorecard, the package registries (PyPI, npm, Maven Central, Packagist), Debian, Ubuntu,
Red Hat and go.dev. oss-intake trusts these services for facts, so a wrong answer can change the verdict; it does
not trust them to be up, or to answer in the right shape.

**Assets at risk:** the verdict, the GitHub token, and the run's time and memory.

| Threat | Mitigation | Where |
|---|---|---|
| Traffic is read or changed in transit | Every service URL is fixed in the code as `https://`; certificates are checked by requests. | `http.RequestsHttp`, the callers |
| `GITHUB_TOKEN` leaks to another host or into output | It is read once, attached only when the host is exactly `api.github.com` (a look-alike such as `api.github.com.evil.example` gets none), never put in a URL, and left out of error messages, logs and reports. requests drops it on a redirect to another host. GitHub API responses are never cached. | `http.RequestsHttp._headers`, `http.CACHE_RULES` |
| A service that is down or answers garbage reads as clean | Answers are checked for type before use; an answer of the wrong shape (OSV, KEV with any unreadable entry, the exploit indexes) is treated as that source failing, never as clean. Workflow listing entries that cannot be read are skipped (see open item 4). An OSV failure stops a package-list run, and for an image marks the malicious-package check partial, which fails `--fail-on malicious`. KEV that did not load fails the KEV gates. Release-age and registry errors make those checks partial and their gates fail. A removal list with under 100 rows is not used. | `scanners.osv`, `enrich.kev`, `release_age`, `registry_check`, `vscode.load_removed`, `gates.not_evaluated` |
| OSV leaves some packages out of its answer, so they read as clean | An answer must hold one result object per package asked about, each with its vulnerabilities as a list of objects with an id; a page token that repeats, or more than 200 pages for one package, is an error too. Each is handled as an OSV failure. The Ubuntu fix-date lookup uses the same checks. | `scanners.osv.querybatch` |
| One advisory's details fail to load, and its finding reads as complete | That finding is marked as missing details and put in "review" | `scanners.osv` |
| A service that is down makes the run wait out every timeout | Parallel lookups stop after three connection failures and report the rest as errors (HTTP error statuses do not count). | `http.RequestsHttp.prefetch` |
| A check that needs the network is trusted offline | With `--offline` oss-intake itself fetches nothing (the scanners may still use the network), the cache is off, and gates that need a lookup are refused (exit 2). | `options.refuse_gates_without_their_check` |
| Text from a service attacks the report's reader | See "Reports" below: every value is escaped. | `report`, `report_html` |

**Left open:**

- Responses have no size limit, and the timeout applies to each read rather than the whole request, so a slow
  or huge answer can stall or exhaust a run.
- A redirect to plain `http` on another host is followed for data (the token is dropped).
- Answers are trusted as published: a compromised or mistaken service (a KEV list missing an entry, an advisory
  with the wrong fix version) is passed on. OSV, deps.dev and KEV are not signed.
- Maven Central answering 5xx or 429 for every checksum reads as "not published" rather than as an error
  (`--fail-on mismatch` still fails), and SHA-1 is accepted when it is all Maven has.

## The cache folder

**What crosses:** answers kept on disk between runs (OSV advisory details for a day, deps.dev package data for a
day and release dates for 30 days, PoC-in-GitHub entries for a week). What decides a version's vulnerabilities
(OSV's batch query), KEV, EPSS and the GitHub API are always fetched fresh.

**Assets at risk:** the verdict. A planted entry could give a malicious new release an old date, so the
release-age check misses it, or change an advisory's severity, fix versions, aliases or CWE IDs (CWE-506 is
one way a package is recognised as malware).

| Threat | Mitigation | Where |
|---|---|---|
| Another user plants answers | A folder that others can write to, or that belongs to another user, is not used, with a warning; the folder is created readable by the user only. | `http.ResponseCache.unsafe_reason`, `ResponseCache.put` |
| A stale, misplaced or forged entry is used | An entry is used only if it is for this exact URL, a 200, and not older than its rule or dated in the future. "Not found" is never kept, nor a version without a date. | `http.ResponseCache.get`, `ResponseCache.put` |
| A half-written entry is read | Entries are written to a temporary file and renamed into place. | `http.ResponseCache.put` |
| The user wants nothing kept | `--no-cache` and `--offline` turn it off. | `cli` |

**Left open:**

- The ownership check looks at the folder (or, before it exists, its nearest parent) once, before use: not its
  parents once it exists, its subfolders or entry files, and not again after the check. A folder that already
  exists keeps its permissions.
- On Windows the folder is not checked at all, so a shared `--cache-dir` there is trusted.
- An entry's content is not checked beyond its URL, status and date: anyone who can write as the user can
  rewrite it. (Anyone who can do that can also change oss-intake itself.)

## User inputs

**What crosses:** command-line options and the files the user names: package lists (`--package`, CSV
inventories), SBOMs, decisions files (`--decisions`, a findings.csv or OpenVEX), a likelihood configuration, and
`--path` targets. They usually come from the user, but often from somewhere else first (an SBOM from a vendor, an
inventory exported from a fleet), so they are checked as untrusted.

**Assets at risk:** the verdict (input that suppresses a finding, or passes when it should not), and the run's
memory and time.

| Threat | Mitigation | Where |
|---|---|---|
| Bad input produces a partial run that reads as clean | Inputs are checked before any lookup or scan, and before the output folder is written; an invalid row, package or option stops the run with exit 2 and says which. (An renv.lock is read after the output folder is made, and a bad likelihood configuration exits 1.) | `cli.cmd_scan`, `inputs`, `sbom`, `decisions` |
| A package entry that is not a real version (a range, `latest`, a placeholder) is checked as if it were | Ranges and the placeholders `latest`, `any` and `x` are refused, and a purl must have a known type and a version; `--package` names are checked too. | `inputs._check_name`, `inputs._row_purl` |
| A huge input exhausts memory or time | At most 1,000 `--package` values and 500,000 inventory rows; SBOMs at most 5,000 files and 500,000 components, and a file over 200 MB is not read as an SBOM. Nested SBOM components are walked without recursion. | `inputs.MAX_PACKAGES`, `inputs.MAX_INVENTORY_ROWS`, `sbom` |
| An SBOM whose components cannot be checked reads as clean | Components without a usable purl are counted and listed in the report; an SBOM with nothing checkable is refused. | `sbom.read`, `cli` |
| An SBOM or inventory column takes the place of a report column | Columns and SBOM label names that clash with report columns are refused, and SBOM label values are cut to 300 characters. | `inputs.inventory`, `sbom._label_key` |
| A decision hides a finding that matters | A decision never sets aside a malicious package. `not_affected` and `mitigated` need a note (in OpenVEX, any justification counts). A decision made for another version still applies but is flagged for review. | `decisions.apply`, `triage` |
| A malformed file stops the run with a traceback, or is half read | Deeply nested JSON, fields of the wrong type and text that is not UTF-8 are input errors (exit 2) in SBOMs, inventories, decisions, renv.lock and imported scanner reports, and scanner or configuration errors (exit 1) in live scanner output, govulncheck output, checksums files and likelihood configurations. A list field of another type is refused, never read as empty. Found by fuzzing the parsers, which runs weekly (`.github/workflows/fuzz.yml`); each harness also runs on every push. Service answers other than OSV advisories and the text indexes have no fuzz target yet. | `tests/fuzz/harnesses.py`, `sbom`, `inputs`, `decisions`, `scanners.check_report`, `scanners.trivy.parse`, `scanners.grype.parse`, `scanners.govulncheck.analyse`, `likelihood.validate` |
| A gate is asked for that cannot be checked | A gate whose check is turned off is refused (exit 2); one whose check could not run fails (exit 1). | `options.refuse_gates_without_their_check`, `gates.not_evaluated` |
| `--min-severity` hides what a gate depends on | It is applied after KEV, exploits and triage, keeps findings in Act now, malicious ones and those missing their details, and the gates and likelihood see every finding; a gate met only by findings it left out is named in a warning. | `assessment._shown`, `gates.hidden_warnings` |
| Spreadsheet formulas in an input cell | Kept as text, and neutralised when written to CSV (see "Reports"). | `report.csv_safe` |

**Left open:**

- A decision is matched on the vulnerability ID and the package name only, not the ecosystem: a `fixed`
  decision for npm `lodash` also sets aside a PyPI package of that name with the same advisory. `fixed` needs no
  note, and decisions never expire. A set-aside finding does not count for any gate except `malicious`.
- One decision can cover more than its row suggests: one without a version applies to every version without a
  review flag, and the `aliases` cell extends it to every ID listed there.
- Only a few placeholder words are refused as versions (`unknown`, `TBD` or `N/A` are accepted, and OSV finds
  nothing for them, so they read as clean), and names in CSV inventories and SBOMs are not checked as
  `--package` names are (`pkg:pypi//@1.0` is accepted).
- A single SBOM file over 200 MB is not refused: it is treated as an ordinary file and given to the scanners,
  which find nothing in it.
- `--fail-on recent` passes for a version deps.dev has no date for, which is likely for a release hours old; only
  `--fail-on unknown-age` catches it.
- An SBOM in which most components could not be checked still passes a gate if the rest are clean; the unchecked
  ones are a warning and a list, not a failure.
- Inventory CSVs, decisions files, imported scanner reports and single files given to `--path` have no size
  limit; SBOMs are read whole into memory within their 200 MB limit. Inventory label values are not cut.
- A file symlink inside an SBOM folder is read (folder symlinks are not followed).

## Reports

**What crosses:** what oss-intake writes to the output folder: `summary.md`, `report.html`,
`executive-summary.html`, `findings.csv`, `packages.csv` and the other CSVs, `assessment.json`, OpenVEX and
`vex.cdx.json`, and the raw scanner output. Much of it is text from advisories, package
names and the software being assessed, chosen by whoever wrote it.

**Assets at risk:** the reader (markup or script in a browser or Markdown viewer, formulas in a spreadsheet), the
user's files (where the output is written), and the user's privacy (what the report says about their machine).

| Threat | Mitigation | Where |
|---|---|---|
| Script or markup in the HTML report | Every value is escaped with `html.escape`, quotes included; only markup the code builds itself is not. The report has no scripts and no links built from data, so a `javascript:` URL cannot reach it. | `report_html`, `exec_summary` |
| Markup, links or broken tables in Markdown | Every value is escaped (`` \ ` * _ [ ] ! \| ~ # ``, `<` and `>`), and line breaks become spaces. | `report._md_cell` |
| Spreadsheet formula injection in CSV | A value starting with `=`, `+`, `-`, `@`, a tab or a carriage return (after any leading apostrophes), or with one after a separator inside it, is prefixed with `'`, header row included; signed numbers after a separator are left alone. Decisions read back undo it. | `report.csv_safe`, `decisions.unguard` |
| The token or a scanner option ends up in a report | Neither is written; image references cannot carry credentials. | `cli`, `report` |
| An output folder that cannot be written fails after the work is done | It is created and tested for writing before anything else. | `cli.prepare_out` |

**Left open:**

- Reports are written with an ordinary open, so a symbolic link already in the output folder (`summary.md`
  pointing elsewhere) is followed and its target overwritten. Existing files are replaced without warning.
- Files from an earlier run that this run does not write again (`openvex.json`, `report.html` when HTML is not
  asked for, raw scanner output) stay in the folder and can be taken for current results.
- Paths of the user's machine reach the reports: the `--path` value as given (with `~` expanded) in
  `assessment.json` and the HTML scope table, and in `assessment.json` the scanner's path on live runs and the
  cache folder.
- The CSV guard does not catch a formula after leading spaces or a line break, the full-width `＝`, or `|`.
  Spreadsheets differ in what they treat as a formula.
- Bare URLs in Markdown are made into links by some viewers (they are not made from data in HTML).
- The HTML has no Content-Security-Policy, which would be a second line of defence if escaping ever failed.
- `generated_at` is the time of the run even with `--as-of`, so two runs never give identical reports.

## GitHub Actions (building and releasing oss-intake)

**What crosses:** the repository's workflows run third-party actions and tools, and the release workflow
publishes to PyPI, GitHub releases and GitHub Pages. A compromise here reaches everyone who installs oss-intake.

**Assets at risk:** the published package and site, and the credentials the workflows can use.

| Threat | Mitigation | Where |
|---|---|---|
| A third-party action is changed after it was reviewed | Every action is pinned by full commit SHA with its version as a comment, and the workflow audit flags known-bad action versions. The SLSA generator, which cannot be pinned by SHA, is referenced by an exact release tag. Dependabot proposes updates weekly, after a 7-day cooldown. | `.github/workflows/*.yml`, `health.workflows`, `.github/dependabot.yml` |
| A workflow can do more than it needs | Workflows start with read-only permissions and grant writes per job, only where needed (PyPI publishing, signing, attaching to the release, Pages, code scanning uploads). Checkouts do not keep the token (`persist-credentials: false`). No workflow uses `pull_request_target`, so a pull request from a fork runs without secrets. | the workflows |
| A workflow input injects shell commands | Event values (release tag, dispatch input) reach shell steps through environment variables, not `${{ }}` inside the script, and the Pages tag must match `vX.Y.Z`. | `release.yml`, `pages.yml` |
| Build tools or test tools are tampered with | Every Python package CI and the release install is pinned by version and SHA-256 (`--require-hashes`); gitleaks is downloaded by version and its checksum checked. | `requirements/*.txt`, `ci.yml` |
| A stored publishing token leaks | There is none: PyPI trusted publishing uses the workflow's identity, in a `pypi` environment. | `release.yml` |
| A release does not match its tag, or is tampered with after it is built | The tag must equal the package version. The files and the release SBOM are signed with Sigstore, PyPI records attestations, and SLSA level 3 provenance is attached (`oss-intake-<version>.intoto.jsonl`). | `release.yml` |
| A secret is committed | gitleaks scans the full history on every push to `main` and every pull request. | `ci.yml` |
| A vulnerability or weakness in the code itself | CodeQL on every push to `main`, every pull request and weekly; OpenSSF Scorecard weekly and on every push to `main`; the weekly self-check runs oss-intake on its own dependencies with `--fail-on malicious,kev,high`; the parsers are fuzzed weekly. | `codeql.yml`, `scorecard.yml`, `self-check.yml`, `fuzz.yml` |

**Left open:**

- The tests check pinning in `ci.yml`, `release.yml`, `self-check.yml`, `pages.yml` and the scheduled-rescan
  example, but not in `codeql.yml` or `scorecard.yml`; the release test does not check its top-level
  permissions.
- Python and Node come from setup-python and setup-node by version, and CI installs zsh with apt, unpinned.
- The workflow audit of a project being assessed skips a workflow file that fails to download, and still reports
  the audit as complete.
- `main` accepts direct pushes from the maintainer, without a pull request or passing checks first (branch
  protection with required checks is in the backlog). With one maintainer, the maintainer's GitHub account is the
  single point of trust for code, releases and the site.
- Whether the `pypi` environment requires approval before publishing is a repository setting, not visible or
  tested in the code.

## VS Code extensions (`--path` with a .vsix or an extensions folder)

**What enters:** a `.vsix` file or an installed extension's files, chosen by the user but written by whoever
published the extension. The person running oss-intake is usually checking it precisely because they do not
trust it yet, so every byte of it is treated as hostile.

**Assets at risk:** the files of the user running oss-intake (a hostile archive could try to write outside the
folder it is unpacked into), the machine's disk and memory (an archive that expands without end), the honesty of
the report (an extension that hides what it does, or claims another project's identity), and the user's own
machine if the extension ever ran.

| Threat | Mitigation | Where |
|---|---|---|
| The extension's code runs during the check | Nothing in an extension is run, installed or imported: its files are only read as bytes and text. No XML parser runs on its manifest (a regular expression reads one element). | `vscode.py` |
| Path traversal ("zip slip"): a member named `../x`, `/x`, `C:/x`, `a/D:/x` or with `\` writes outside the folder, on any system | Every member name is checked before anything is written: no colon or backslash anywhere, no root or drive, no empty, `.` or `..` part, no part ending in a dot or space (Windows drops them), no reserved device name (`con`, `nul`, `com1`...), no control character. Any of these refuses the whole file (exit 2). | `vscode._member_path` |
| Two members that are one file on macOS or Windows (`extension/x` and `EXTENSION/x`), so the file checked is not the one installed | Names are compared after Unicode normalisation and case folding; a repeat refuses the whole file. | `vscode.unpack` |
| A damaged, encrypted or oddly compressed archive crashes the run | Read errors are refused as input errors (exit 2), with the reason. | `vscode.unpack` |
| A link inside the archive points outside the folder | Members marked as symbolic links are refused. Inside an installed extension, links are not followed. An extension that is itself installed as a link (as for one being developed) is followed, since it is installed. | `vscode.unpack`, `vscode._files`, `vscode.extension_folders` |
| A folder named `extension` inside an installed extension stands in for it (a decoy that hides the real one and every other extension in the folder) | The `<name>/extension` layout is read only in the temporary folder a `.vsix` was unpacked into; a folder the user gives is read as installed extensions. | `vscode.assess` |
| Zip bomb: a small file that expands to fill the disk | At most 50,000 members, 300 MB a member and 1 GB in all, counted as the bytes are written (not trusted from the archive's directory), and no member over 1 MB that expands more than 200 times. | `vscode.unpack` |
| The archive plants the file oss-intake keeps its manifest copy in | The copy is written after unpacking, replacing any file of that name, and is read only for an unpacked `.vsix`. | `vscode.unpack`, `vscode.assess` |
| An unpacked copy is left behind | It is unpacked into a new temporary folder, removed in a `finally` whatever happens. | `cli.cmd_scan` |
| Reading a huge installed folder, or text crafted to make the checks slow, exhausts memory or time | Files over 20 MB are not read, reading stops at 400 MB in all and at 50,000 files an extension, and what was not read is listed in the report. The patterns are matched in linear time (encoded strings are found as whole runs and measured in code), each indicator stops at 20 hits, and line numbers come from one pass. | `vscode.analyse` |
| Code hidden where it is not read: a main file with an odd name or none, or code under a `node_modules` folder of its own | Every file of the extension's own is read as text unless it is binary or a source map, and its main file always is. Documentation and markup files are checked too (Node loads a required `.txt` or `.md` as JavaScript), with the hits labelled. The top-level `node_modules`, its dependencies, is left to the scanners, except for hidden characters, which are looked for there too (a private package is unknown to any database). | `vscode.analyse` |
| An extension's own `.obsolete` file marks it "old version, not in use", hiding its indicators | `.obsolete` is read only in a folder of extensions, never inside an extension's own folder or a `.vsix`. One in the extensions folder itself needs code that already runs on the machine to write it. | `vscode.assess` |
| Findings matched to the wrong extension, or matching made slow by a crafted SBOM or lockfile | Each shipped SBOM or lockfile is read once, within the reading limit, into the exact package names and versions it lists (JSON walked without recursion, yarn.lock line by line, pnpm with a single-line pattern), and findings are looked up in that, not searched for in the text. One that is over the limit is reported. | `vscode._listed`, `vscode.attribute` |
| An absolute path of the user's machine written into the report | The extension's folder is used only while findings are matched and never reaches `assessment.json`. | `vscode.attribute` |
| Dependencies hidden by bundling make the report look clean | A large main file is reported as bundled whatever else the extension ships (so a stray `package.json` cannot turn the warning off), with a warning that no findings does not mean none. | `vscode.analyse`, `vscode.warnings` |
| Code hidden in invisible characters (GlassWorm) or reordered text (Trojan Source) | Variation selectors, tag characters, runs of zero-width characters and bidirectional controls are reported with file and line. | `vscode.analyse` |
| The extension claims a trusted project's repository, to borrow its health score | The `repository` field is shown as the publisher's claim and never checked automatically; `--repo` is the user's choice. | `report.extensions_section` |
| The extension claims another extension's identity, or rewrites its own to dodge the removal list | A folder name or `.vsix` manifest that disagrees with `package.json` is reported, and every one of those names is looked up in the list. IDs are compared after case folding and Unicode compatibility normalisation, with spaces and invisible format characters removed. | `vscode.analyse`, `vscode._key` |
| The removal list is unavailable, so a malicious extension passes a CI gate | The report says the list was not checked, and `--fail-on malicious` and `act` exit 1 rather than passing. A response with fewer than 100 rows is not taken as the list. | `vscode.load_removed`, `gates.not_evaluated` |
| The report itself is used to attack its reader (a name or path with markup) | Extension names, paths and details go through the same escaping as every other report value. | `report._md_cell`, `report_html` |

**Left open:**

- A copy of listed malware republished under a new name is a different extension: the list does not name it,
  so only the indicators can show it.
- Reading is shared across a folder: an extension early in the order can use up the 400 MB for the extensions'
  own code (dependencies have a 400 MB budget of their own), so later ones are listed as not read rather than
  checked.
- The archive's directory is read whole by Python's zipfile before the member count is checked.
- Trivy reads the unpacked files, so a flaw in Trivy's parsers is exposed to them; pin and verify Trivy as the
  guide describes.
- The Marketplace signature is not checked, so a `.vsix` repackaged after publication is not detected.
- The main file named in package.json is joined to the extension's folder as given, so an absolute `main`
  (`"/extension.js"`) or one with `../` points outside it: the extension's real main file is not found, and
  the warning that its code is bundled can be avoided (VS Code reads `main` relative to the extension).
- The indicators are patterns in text: a determined author can avoid them (by fetching code at run time, for
  example). A clean result means none were found, not that the extension is safe.
- The removal list is fetched over HTTPS from GitHub and trusted as published; it is not signed.
- Bundled code is read for indicators but its dependencies cannot be named, so they are not checked.

## Open items that could be fixed

All of these were agreed for the backlog on 6 Nov; BACKLOG.md has them in order, and each is removed here when
it ships. What is not listed here (a service that answers wrongly, an extension author determined to avoid the
indicators, the single maintainer) are limits of the approach rather than defects.

1. Set nothing aside ahead of KEV or a malicious package (govulncheck's "not reachable", the build-label and
   kernel-header rules), and require govulncheck's hash for `--reachability`.
2. Match decisions on the ecosystem as well as the ID and package name, and refuse more placeholder versions.
3. Make `--fail-on recent` fail for a version with no known date, and report a workflow audit with files missing
   as partial.
4. Report a binary checked against an unsigned checksums file as such, not as hash verified.
5. Refuse to write a report through a symbolic link, and remove stale report files the run did not write.
6. Size limits for inventories, decisions files, imported reports and service responses, and a total deadline
   for each request; refuse an SBOM over its size limit instead of passing it to the scanners.
7. Check the cache folder's subfolders and entries for ownership, and check it on Windows.
8. Pass `--path` folders to Trivy and govulncheck so a name starting with `-` cannot be read as an option.
9. Extend the workflow pinning tests to `codeql.yml` and `scorecard.yml`.
10. Write paths relative to the target, not absolute local paths, in `assessment.json` and the HTML report.
11. Resolve a VS Code extension's `main` inside its folder as VS Code does (an absolute path or `../` does not
    leave it), so the bundled check cannot be avoided.
