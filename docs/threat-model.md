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
| The published known-bad list is replaced to hide a compromised scanner release | It is used only when cosign verifies its Sigstore signature against OSS-Intake's own workflows (known-bad.yml on main, pages.yml at a release); a failed check is warned about and the shipped list used. It only adds entries: a shipped entry is never dropped, so a replaced or stale list cannot remove one, and a published list older than the shipped one is not used. Each entry is checked for its form, here and before the workflow signs it, so a malformed entry cannot break a run. pages.yml publishes main's list when it is newer than the release's. | `integrity.refresh_known_bad`, `integrity.load_known_bad` |
| A known-compromised scanner release runs | Its version is read from the Go build information in the file, without running it, and checked against `known_bad.json`; the version the binary reports is checked again. Either match refuses the run. | `integrity.refuse_known_bad_before_run`, `integrity.check_binary` |
| A swapped or tampered binary runs | With `--<tool>-sha256`, a cosign bundle (or, for Grype, the certificate and signature it publishes instead), or the release archive and its checksums, the binary is checked before it runs at all. It is first copied into a folder only this run can write to, and that copy is both checked and run, so the file cannot be swapped between its check and its run. Without them the report says the hash was not verified; checked only against a checksums file nothing has signed, it says that, not hash verified. | `integrity.cosign_verify_blob`, `integrity.verify_before_run`, `scanning.run_or_load` |
| A `--path` named like an option (`--config=x.yaml`) changes what the scanner does | A path starting with `-` is given to Trivy and govulncheck as `./-...`; Grype gets it after its `dir:` prefix. | `scanners.path_arg` |
| A scanner that fails, hangs or prints nothing reads as "no findings" | A non-zero exit, a timeout or output that is not JSON stops the run with exit 1. | `scanners.run`, `scanners.load_json_bytes` |
| The wrong file is imported (an SBOM, another tool's report, `{}`), so it reads as clean | An imported report must have the tool's shape, or it is refused, and one that names nothing it scanned and lists nothing is refused too; one for a different image is warned about. | `scanners.check_report`, `scanners.report_kind` |
| A broken or hostile program floods its output | What every program oss-intake starts writes is collected up to a limit (1 GB of output, 1 MB of error output for a scanner; 1 MB for docker and cosign); past it the program is killed and the step fails. | `scanners.capped_run` |
| A program oss-intake starts (a swapped scanner, docker, crane, cosign) steals credentials from the environment | Every program gets only an allowlist: what any program needs (path, home and temporary folders, locale, proxy and CA settings, the Windows essentials) and its own tool's settings (`TRIVY_*` for Trivy only, and so on). Cloud credentials, publishing tokens, the SSH agent and anything else are passed on only when the user names them with `--scanner-env`, and the GitHub token variables never are. It is not a sandbox: the program runs as the user and can read their files. | `scanners.child_env`, `scanners.BASE_ENV`, `scanners.TOOL_ENV` |
| govulncheck is pointed at the wrong file, or reads too little to judge | Binaries are copied out of an image following links inside the image (`docker cp -L`), and a copy that is still a link or lands outside the work folder is not analysed. Output that does not state a symbol-level scan gives no verdict, as only that level can show a function is absent. | `scanners.govulncheck.extract_from_image`, `_analyse` |
| A required scanner is missing | Named scanners must be found. With `--scanners auto`, a missing Grype is a warning in the report, not silence. | `scanners.find_executable`, `cli` |

**Left open:**

- The binary is checked by path and then run by path: someone who can write to it or its folder could replace
  it in between. The binary's own folder is not checked for who can write to it.
- On Windows, `shutil.which` looks in the current folder before the PATH, so a `trivy.exe` there is the one
  found. A pinned hash still stops it.
- govulncheck has no known-bad list, and with `--govulncheck-sha256` its "not reachable" verdict sets a finding
  aside, so it no longer counts for the severity gates (never a malicious or CISA KEV finding, which come first).
  Without the pin the verdict is shown but sets nothing aside. A kernel CVE on a kernel header package is set
  aside, even in KEV, only for a container target (`--image`, or SBOMs that all describe an image): a container
  runs on the host's kernel. For a folder, an artifact or another SBOM (a host or VM image) it counts like any
  finding (decided 8 Nov). The image claim comes from the SBOM itself, so an SBOM from an untrusted source that
  calls itself an image has those findings set aside; `--include-kernel-headers` counts them.
- The default cosign identity is the scanner's release workflow as its signing certificates name it (Trivy's
  `reusable-release.yaml` for a version tag, Grype's `release.yaml` on main); if a project moves its signing to
  another workflow, verification fails until oss-intake is updated or `--*-cosign-identity` is given. cosign
  itself, and docker and crane (used to get binaries out of an image for govulncheck), are found on the PATH and
  not verified.
- The scanner's vulnerability database age is shown, and enforced only with `--max-db-age-days` (off by default),
  which stops the run when the database the scan used (after its own update) is older, or its build date cannot
  be read.
- Each scanner is copied to a private temporary folder to be checked and run. Where the temporary folder does not
  allow programs to run (`/tmp` mounted noexec, as under CIS hardening) the run stops and says to set `TMPDIR`;
  on Windows, an application control policy that blocks programs in `%TEMP%` has the same effect and is not
  detected.
- Anything wrong inside a scanner (a parser flaw reached by the files it reads) is the scanner's: pin and verify
  it as the guide describes.

## Public services (network)

**What crosses:** JSON and text from OSV, deps.dev, the GitHub API and raw.githubusercontent.com, GitLab (exploit
indexes, and a GitLab `--repo`'s releases), Codeberg (a Codeberg `--repo`'s releases), CISA
KEV, FIRST EPSS, OpenSSF Scorecard, the package registries (PyPI, npm, Maven Central, Packagist), Debian, Ubuntu,
Red Hat and go.dev. oss-intake trusts these services for facts, so a wrong answer can change the verdict; it does
not trust them to be up, or to answer in the right shape.

**Assets at risk:** the verdict, the GitHub token, and the run's time and memory.

| Threat | Mitigation | Where |
|---|---|---|
| Traffic is read or changed in transit | Every service URL is fixed in the code as `https://`; certificates are checked by requests. | `http.RequestsHttp`, the callers |
| `GITHUB_TOKEN` leaks to another host or into output | It is read once, attached only when the host is exactly `api.github.com` (a look-alike such as `api.github.com.evil.example` gets none), never put in a URL, and left out of error messages, logs and reports. requests drops it on a redirect to another host. GitHub API responses are never cached. | `http.RequestsHttp._headers`, `http.CACHE_RULES` |
| A service that is down or answers garbage reads as clean | Answers are checked for type before use; an answer of the wrong shape (OSV, KEV with any unreadable entry, the exploit indexes) is treated as that source failing, never as clean. Workflow listing entries of the wrong shape are skipped; a listed workflow file that cannot be downloaded or decoded makes the audit partial, named in a warning and the reports. An OSV failure stops a package-list run, and for an image marks the malicious-package check partial, which fails `--fail-on malicious`; so does a Trivy report that lists no packages for a language result, which also makes release age partial. KEV that did not load fails the KEV gates. Release-age and registry errors make those checks partial and their gates fail. A removal list with under 100 rows is not used. | `scanners.osv`, `enrich.kev`, `release_age`, `registry_check`, `vscode.load_removed`, `health.workflows`, `gates.not_evaluated` |
| OSV leaves some packages out of its answer, so they read as clean | An answer must hold one result object per package asked about, each with its vulnerabilities as a list of objects with an id; a page token that repeats, or more than 200 pages for one package, is an error too. Each is handled as an OSV failure. The Ubuntu fix-date lookup uses the same checks. | `scanners.osv.querybatch` |
| One advisory's details fail to load, and its finding reads as complete | That finding is marked as missing details and put in "review" | `scanners.osv` |
| A service that is down makes the run wait out every timeout | Parallel lookups stop after three connection failures and report the rest as errors (HTTP error statuses do not count). | `http.RequestsHttp.prefetch` |
| A slow or huge answer stalls or exhausts the run | Every answer is read in chunks: over its source's limit (32 MB for an API, 128 MB for a bulk index read from a repository), or still arriving after 5 minutes (or twice the timeout, if longer), it is a failed request, so that source counts as failed, never as clean. | `http.RequestsHttp._body`, `http.answer_limit`, `http.DEADLINE_SECONDS` |
| A redirect sends the package list elsewhere, or downgrades to plain http | Redirects are followed by hand. A request with a body (the OSV batch query, which carries the package list) is never redirected: a redirect is a failed request. A GET follows at most 5, and only to https; the GitHub token goes only to api.github.com at each hop. | `http.RequestsHttp._send` |
| A check that needs the network is trusted offline | With `--offline` oss-intake itself fetches nothing (the scanners may still use the network), the cache is off, and gates that need a lookup are refused (exit 2). | `options.refuse_gates_without_their_check` |
| Text from a service attacks the report's reader | See "Reports" below: every value is escaped. | `report`, `report_html` |

**Left open:**

- An answer is held in memory up to its source's limit (32 MB or 128 MB), and a slow service can take up to the 5
  minute deadline per request (lookups run in parallel, so a run is not that times the number of lookups). The deadline is
  checked as data arrives, so it can be passed by up to one read timeout; with urllib3 1.26 (urllib3 2 is
  pinned) it is checked only once each 64 KiB has arrived.
- Answers are trusted as published: a compromised or mistaken service (a KEV list missing an entry, an advisory
  with the wrong fix version) is passed on. OSV, deps.dev and KEV are not signed.
- Maven Central answering 5xx or 429 for every checksum reads as "not published" rather than as an error
  (`--fail-on mismatch` still fails), and SHA-1 is accepted when it is all Maven has.

## The cache folder

**What crosses:** answers kept on disk between runs (OSV advisory details for a day, deps.dev package data for a
day and release dates for 30 days, PoC-in-GitHub entries for a week, Ubuntu publication dates from Launchpad for
30 days once published, Alpine aports commit histories for a day). What decides a version's vulnerabilities
(OSV's batch query), KEV, EPSS and the GitHub releases list are always fetched fresh.

**Assets at risk:** the verdict. A planted entry could give a malicious new release an old date, so the
release-age check misses it, or change an advisory's severity, fix versions, aliases or CWE IDs (CWE-506 is
one way a package is recognised as malware).

| Threat | Mitigation | Where |
|---|---|---|
| Another user plants answers | A folder that others can write to, or that belongs to another user, is not used, with a warning, and nor is one below a folder like that (a shared folder with the sticky bit, such as `/tmp`, is fine above it). Group write counts as others' unless the group is the user's own private group (as with umask 002 on Fedora, RHEL, Debian and Ubuntu). The folder, and any parent it has to make, is created readable by the user only, and entries are written for the user only, whatever the umask. An entry, or the subfolder holding it, that is a link, another user's or writable by others is ignored. On Windows each folder's security descriptor is read: a folder another account (anyone but the user, SYSTEM, Administrators and TrustedInstaller) may add to or re-permission, or that a folder above lets another account move away, is not used, nor one owned by another account. A deny entry is not weighed and an unknown right counts as every right, so the check errs towards refusing. As the descriptors can still miss a way in (entries and subfolders are not checked one by one on Windows, nor junctions or accounts with the backup or restore privilege), only a folder inside the user's profile is used, unless the operator confirms a `--cache-dir` outside it with `--trust-cache-dir` (logged and recorded in `assessment.json`). What the permissions show is never overridden. When the descriptors cannot be read, the profile rule alone decides. | `http.ResponseCache.unsafe_reason`, `winacl.write_reason`, `http._trusted`, `ResponseCache.get`, `ResponseCache.put` |
| A stale, misplaced or forged entry is used | An entry is used only if it is for this exact URL, a 200, and not older than its rule or dated in the future. "Not found" is never kept, nor a version without a date. | `http.ResponseCache.get`, `ResponseCache.put` |
| A half-written entry is read | Entries are written to a temporary file and renamed into place. | `http.ResponseCache.put` |
| The user wants nothing kept | `--no-cache` and `--offline` turn it off. | `cli` |

**Left open:**

- The folder is checked once, before use, and each entry as it is read, so a change between the check and the
  read is not seen. A folder that already exists keeps its permissions.
- On Windows a folder inside the user's profile is trusted without reading its permissions, so one someone gave
  other users write access to is still used.
- An entry's content is not checked beyond its URL, status and date: anyone who can write as the user can
  rewrite it. (Anyone who can do that can also change oss-intake itself.)

## User inputs

**What crosses:** command-line options and the files the user names: package lists (`--package`, CSV
and `.xlsx` inventories), SBOMs, decisions files (`--decisions`, a findings.csv or OpenVEX), a likelihood configuration, and
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
| A VEX file passes an unconfirmed decision to other tools | Grype, Trivy and Dependency-Track act on VEX without review, so `openvex.json` and `vex.cdx.json` state a decision as made only when it was made for the installed version in a named ecosystem; any other goes out as under investigation, saying why. | `decisions._exported_status` |
| A malformed file stops the run with a traceback, or is half read | Deeply nested JSON, fields of the wrong type and text that is not UTF-8 are input errors (exit 2) in SBOMs, inventories, decisions, renv.lock and imported scanner reports, and scanner or configuration errors (exit 1) in live scanner output, govulncheck output, checksums files and likelihood configurations. A list field of another type is refused, never read as empty. Found by fuzzing the parsers, which runs weekly (`.github/workflows/fuzz.yml`); each harness also runs on every push. Service answers other than OSV advisories and the text indexes have no fuzz target yet. | `tests/fuzz/harnesses.py`, `sbom`, `inputs`, `decisions`, `scanners.check_report`, `scanners.trivy.parse`, `scanners.grype.parse`, `scanners.govulncheck.analyse`, `likelihood.validate` |
| A gate is asked for that cannot be checked | A gate whose check is turned off is refused (exit 2); one whose check could not run fails (exit 1). | `options.refuse_gates_without_their_check`, `gates.not_evaluated` |
| `--fail-on-likelihood` passes because a source did not load | Evidence from a source that failed on the run (KEV, malicious package data, EPSS, exploit indexes) is unknown, not 0; when a rule at or above the threshold depends on it, the gate fails (exit 1), naming it. A source turned off by choice, and release health without `--repo`, read as before (the latter as low confidence). | `likelihood.evaluate` (`could_be`), `assessment._finish` |
| `--min-severity` hides what a gate depends on | It is applied after KEV, exploits and triage, keeps findings in Act now, malicious ones and those missing their details, and the gates and likelihood see every finding; a gate met only by findings it left out is named in a warning. | `assessment._shown`, `gates.hidden_warnings` |
| Spreadsheet formulas in an input cell | Kept as text, and neutralised when written to CSV (see "Reports"). An `.xlsx` cell is read as its stored value; a formula is never evaluated. | `report.csv_safe`, `inputs._xlsx_rows` |
| An `.xlsx` that unpacks to far more than its size (a zip bomb) | Its parts are counted and their unpacked size added up (at most 800 MB and 10,000 parts) before openpyxl opens it, read-only. The worksheets are streamed, but openpyxl reads the shared strings (the workbook's text) into memory whole, at several times their size, so that part is limited to 64 MB. The XML inside is parsed by openpyxl with Python's expat, which limits entity expansion. | `inputs._xlsx_rows` |

**Left open:**

- A decision without an ecosystem (a findings.csv with no `pkg_type`, or one written by hand) is matched on the
  vulnerability ID and package name only, so it can cover a package of the same name in another ecosystem.
  `fixed` needs no note, and decisions never expire. A set-aside finding does not count for any gate except
  `malicious`.
- One decision can cover more than its row suggests: one without a version applies to every version without a
  review flag, and the `aliases` cell extends it to every ID listed there.
- Names in CSV inventories and SBOMs are not checked as `--package` names are (`pkg:pypi//@1.0` is accepted).
- `--fail-on recent` passes for a version in a registry deps.dev does not cover at all (RubyGems, CRAN), as it
  would otherwise fail on every run; `--fail-on unknown-age` catches those. A version in a registry deps.dev
  covers but has no date for (as for a release hours old) makes the gate fail with exit 1.
- An SBOM in which most components could not be checked still passes a gate if the rest are clean, unless
  `--fail-on unchecked` is given; without it the unchecked ones are a warning and a list, not a failure. The same
  holds for renv.lock packages not from CRAN. A .csv package list, an image and a folder have no such list.
- Single files given to `--path` other than SBOMs have no size limit (the scanners read them). Inventories,
  decisions files, renv.lock files and SBOMs are read whole into memory within their 200 MB limit, and imported
  scanner reports within 1 GB. Inventory label values are not cut.
- A file symlink inside an SBOM folder is read (folder symlinks are not followed).

## Reports

**What crosses:** what oss-intake writes to the output folder: `summary.md`, `report.html`, `report.pdf`,
`executive-summary.html`, `findings.csv`, `packages.csv` and the other CSVs, `assessment.json`, OpenVEX and
`vex.cdx.json`, and the raw scanner output. Much of it is text from advisories, package
names and the software being assessed, chosen by whoever wrote it.

**Assets at risk:** the reader (markup or script in a browser or Markdown viewer, formulas in a spreadsheet), the
user's files (where the output is written), and the user's privacy (what the report says about their machine).

| Threat | Mitigation | Where |
|---|---|---|
| Script or markup in the HTML report | Every value is escaped with `html.escape`, quotes included; only markup the code builds itself is not. The report has no scripts and no links built from data, so a `javascript:` URL cannot reach it. | `report_html`, `exec_summary` |
| The PDF renderer is made to fetch a URL or read a local file named in the report (an image or stylesheet in a value) | Values are escaped as for the HTML report, which the PDF is rendered from, and WeasyPrint is given a URL fetcher that reads only `data:` URIs: `file:`, `http:` and every other scheme is refused, so rendering reaches no network and no file. | `report_pdf._fetcher` |
| Markup, links or broken tables in Markdown | Every value is escaped (`` \ ` * _ [ ] ! \| ~ # ``, `<` and `>`), and line breaks become spaces. | `report._md_cell` |
| Spreadsheet formula injection in CSV | A value starting with `=`, `+`, `-`, `@`, a tab or a carriage return (after any leading apostrophes), or with one after a separator inside it, is prefixed with `'`, header row included; signed numbers after a separator are left alone. Decisions read back undo it. | `report.csv_safe`, `decisions.unguard` |
| The token or a scanner option ends up in a report | Neither is written; image references cannot carry credentials. | `cli`, `report` |
| A report shared with others gives away the user's name or folders | The target is given by its name, the scanner and the tools used to copy files out of an image by their names (with version and SHA-256), and the cache folder from `~` or by its name; no absolute local path is written. | `assessment.shown_path`, `assessment._document`, `scanning.run_or_load` |
| An output folder that cannot be written fails after the work is done | It is created and tested for writing before anything else. | `cli.prepare_out` |
| Reports in a folder other users can write to are replaced after the run | A warning in the reports names the folder (as the reports give paths) and why (POSIX permissions, or the Windows security descriptor); the folders above it are checked too. | `http.folder_write_reason` |
| Another user on the machine reads the reports (host names, packages, findings) | Every report and raw scanner file is created with mode 0o600 (owner only); the umask can only make it stricter. Windows ignores the mode: the file takes the output folder's permissions. | `safewrite.MODE` |
| A report is written through a symbolic link, or an old report is read as current | A symbolic link where a report or `raw/` goes stops the run (exit 2) before any work, and each report is written to a new file beside it and moved into place, which replaces a link placed later (symbolic or hard) rather than writing through it, and never leaves half a file (`safewrite`). At the end, report files the last run left that this run did not write are removed: only files that run listed as its own in `.oss-intake-files.json` (a `summary.md` of the user's own is never touched), never a file this run read (a re-imported `raw/trivy.json`). | `cli.prepare_out`, `assessment._remove_stale`, `options.OUTPUT_FILES` |

**Left open:**

- Existing reports are replaced without warning. An output folder other users can write to (or replace through a
  folder above it) is warned about, not refused (decided 8 Nov): reports are written by rename, so nothing is
  written through a planted link, but another user can still replace or delete them after the run.
- Paths inside the target as the scanners report them (a lockfile's path within the scanned folder) are kept,
  as they say where a finding is; so are the names of the target, the scanner and, outside the home folder,
  the cache folder.
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
| A third-party action is changed after it was reviewed | Every action is pinned by full commit SHA with its version as a comment, and the workflow audit flags known-bad action versions. The SLSA generator, which cannot be pinned by SHA (it checks that it is called by a release tag, and its provenance does not verify otherwise), is referenced by an exact release tag. That is an accepted risk (external audit CI-01; accepted 7 Nov 2026, to be reviewed by 7 May 2027 or at the generator's next major release, whichever comes first): if the tag were moved to other code, the release job would run it with permission to sign and attach files to the release. The packages on PyPI are built and published by oss-intake's own SHA-pinned jobs, which the generator cannot change. Dependabot proposes updates weekly, after a 7-day cooldown. | `.github/workflows/*.yml`, `health.workflows`, `.github/dependabot.yml` |
| A workflow can do more than it needs | Workflows start with read-only permissions and grant writes per job, only where needed (PyPI publishing, signing, attaching to the release, Pages, code scanning uploads). Checkouts do not keep the token (`persist-credentials: false`). No workflow uses `pull_request_target`, so a pull request from a fork runs without secrets. | the workflows |
| A workflow input injects shell commands | Event values (release tag, dispatch input) reach shell steps through environment variables, not `${{ }}` inside the script, and the Pages tag must match `vX.Y.Z`. | `release.yml`, `pages.yml` |
| Build tools or test tools are tampered with | Every Python package CI and the release install is pinned by version and SHA-256 (`--require-hashes`); gitleaks is downloaded by version and its checksum checked. | `requirements/*.txt`, `ci.yml` |
| A stored publishing token leaks | There is none: PyPI trusted publishing uses the workflow's identity, in a `pypi` environment. | `release.yml` |
| A release does not match its tag, or is tampered with after it is built | The tag must equal the package version. The files and the release SBOM are signed with Sigstore, PyPI records attestations, and SLSA level 3 provenance is attached (`oss-intake-<version>.intoto.jsonl`). | `release.yml` |
| A secret is committed | gitleaks scans the full history on every push to `main` and every pull request. | `ci.yml` |
| A vulnerability or weakness in the code itself | CodeQL on every push to `main`, every pull request and weekly; OpenSSF Scorecard weekly and on every push to `main`; the weekly self-check runs oss-intake on its own dependencies with `--fail-on malicious,kev,high`; the parsers are fuzzed weekly. | `codeql.yml`, `scorecard.yml`, `self-check.yml`, `fuzz.yml` |

**Left open:**

- The pinning test reads the workflow files as text, as the audit of other projects does; it does not check
  what a pinned action itself pulls in (a container image or a script it downloads).
- Python and Node come from setup-python and setup-node by version, and CI installs zsh with apt, unpinned.
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
| Dependencies hidden by bundling make the report look clean | A large main file is reported as bundled whatever else the extension ships (so a stray `package.json` cannot turn the warning off), with a warning that no findings does not mean none. The main file is found inside the extension's folder as VS Code reads it (an absolute `main` or a drive is read inside it); a `main` that leads out of the folder with `..`, which VS Code follows, is reported as an indicator, as that file is not read. | `vscode.analyse`, `vscode.warnings` |
| Code hidden in invisible characters (GlassWorm) or reordered text (Trojan Source) | Variation selectors, tag characters, runs of zero-width characters and bidirectional controls are reported with file and line. | `vscode.analyse` |
| The extension claims a trusted project's repository, to borrow its health score | The `repository` field is shown as the publisher's claim and never checked automatically; `--repo` is the user's choice. | `report.extensions_section` |
| The extension claims another extension's identity, or rewrites its own to dodge the removal list | A folder name or `.vsix` manifest that disagrees with `package.json` is reported, and every one of those names is looked up in the list. IDs are compared after case folding and Unicode compatibility normalisation, with spaces and invisible format characters removed. | `vscode.analyse`, `vscode._key` |
| The removal list is unavailable, so a malicious extension passes a CI gate | The report says the list was not checked, and `--fail-on malicious` and `act` exit 1 rather than passing. A response with fewer than 100 rows is not taken as the list. | `vscode.load_removed`, `gates.not_evaluated` |
| A `--extension` download is corrupted or swapped on the way | The file is checked against the SHA-256 Open VSX publishes for it before anything is unpacked; a mismatch, a missing hash or a link that is not https stops the run (exit 2) with nothing assessed. The ID must be `publisher.name@version` with an exact version, so the file name made from it cannot leave the temporary folder. The download is capped at 500 MB and removed after the run. | `openvsx.download`, `cli.cmd_scan` |
| An extension an SBOM lists (a fleet's osquery data) passes the removal-list gate unchecked | Each is looked up by ID (normalised as for a folder) and version; if the list cannot be read, `--fail-on malicious` and `act` fail rather than pass. Only the ID is known, so an extension that renamed itself is not caught this way; its files are not read. | `sbom.read`, `vscode.assess_listed`, `gates.not_evaluated` |
| An `--extension` download, or Open VSX's published SHA-256 with it, was altered after Open VSX signed the file | With the `signatures` extra, Open VSX's Ed25519 signature over the whole file is checked; a mismatch refuses the download (exit 2). A `--path` file whose SHA-256 is Open VSX's gets the same check, and a mismatch leads the report; a file with another SHA-256 (another build, or an altered copy) is reported as one the signature does not apply to. A signature or key that cannot be fetched or read is "not checked", never "verified". The key comes from Open VSX, so this does not guard against Open VSX itself. | `openvsx.check_signature`, `openvsx.check_file` |
| A JetBrains plugin file or folder attacks the tool reading it (a zip bomb, links, a hostile plugin.xml) | A plugin .zip is unpacked with the .vsix limits (no links, no paths that leave the folder or clash by name, size and ratio limits); a plugin.xml is read only up to 2 MB, from at most 400 jars per plugin, with expat (no external entities; entity expansion bounded); at most 500 plugins per folder. Nothing in a plugin is run. | `jetbrains.unpack`, `jetbrains._plugin_xml`, `jetbrains.read_identity` |
| A `--jetbrains-plugin` download, or a plugin file given with `--path`, is altered | With the signatures extra, the Marketplace's signature is checked as the IDE checks it: the file's chunked digest, each signature, each certificate signed by the next, and a chain ending at JetBrains' certificate (bundled, pinned by SHA-256). A download that does not match is refused (exit 2); a file that does not match leads the report. A signed file with bytes between its central directory and end record fails (the digest does not cover them, and a zip reader could take a second directory from there). The Marketplace signs every file it serves (old versions too: checked against a 2020 version), so a download whose signing block was removed, or replaced by another signer's, is refused as well; for a file given with `--path`, whose origin is unknown, that is a warning naming who signed it. Without the extra, only the digest and the block's presence are checked, and someone able to change the file can recompute the digest: HTTPS only, as the report says. The signing block is read with limits (1 MB, 16 signers, 16 certificates or signatures each) by a small protobuf reader, which is fuzzed (`plugin_signature`); nothing in the file is run. Not covered: certificate dates and revocation (the IDE does not check them either), and an installed plugin the IDE unpacked, which has lost its signature. Without the extra, HTTPS only, and the report says so. | `zipsign.check`, `jetbrains.download`, `jetbrains.assess` |
| Open VSX metadata makes an extension look trusted | Verification, publisher and downloads are shown as Open VSX states them, next to the indicators; they change no verdict and no gate. | `openvsx.summary`, `report.extensions_section` |
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
- The indicators are patterns in text: a determined author can avoid them (by fetching code at run time, for
  example). A clean result means none were found, not that the extension is safe.
- The removal list is fetched over HTTPS from GitHub and trusted as published; it is not signed.
- A `--extension` download's SHA-256 comes from Open VSX too, so it shows the file is the one Open VSX serves,
  not that Open VSX itself was not compromised. Open VSX's own signature (`.sigzip`) is not checked.
- Bundled code is read for indicators but its dependencies cannot be named, so they are not checked.

## Open items that could be fixed

The open items agreed on 6 Nov are all fixed (CHANGELOG.md). What is not listed here (a
service that answers wrongly, an extension author determined to avoid the indicators, the single maintainer)
are limits of the approach rather than defects.
