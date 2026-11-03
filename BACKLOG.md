# Backlog

Open work only, agreed for later versions. "Next" is the planned order; the other sections are not ranked.
Finished items are removed in the commit that ships them; CHANGELOG.md records what was done and when.

## Next release (agreed 31 Oct)
- A cosign timeout ends `oss-intake verify --cosign-bundle` (and a scan with a cosign bundle) with a Python
  traceback. `integrity.cosign_verify_blob` runs cosign with a 120-second timeout but does not catch
  `subprocess.TimeoutExpired`, and `cli.main` does not either. Fix: raise IntegrityError ("cosign did not finish
  in 120 s"), exit 1. Found 3 Nov while adding docstrings. Start with a test that fails on the current code.

## Next: quality and credibility (from the code review of 3 Nov, in this order)
1. An SBOM with every release: a CycloneDX SBOM of the built wheel's runtime dependencies, attached to the
   GitHub release before the Sigstore signing step so it is signed with the other files, and a README section
   on verifying the release files and the SBOM.
2. Type checking: mypy (not strict) in CI, blocking. On 3 Nov it reports 66 errors in 24 files, mostly
   optional values used without a check and counters in dicts typed as `object`; fix each or justify it inline.
   Add the command to CONTRIBUTING.md and CLAUDE.md.
3. `docs/threat-model.md`: assets, trust boundaries (scanner binaries, public APIs, user inputs, report
   outputs, the cache folder, GitHub Actions), threats and the existing mitigations; gaps become backlog items.
   Linked from SECURITY.md.
4. Split `cli.py` (1,275 lines) after type checking is in place: argument parsing and dispatch stay in `cli.py`,
   the pipeline stages move to their own modules. No behaviour change, exit codes unchanged, existing tests
   unmodified (names they import from `cli` stay importable). Plan agreed before work starts.

## Next: the organisation view (agreed 28 Oct)
Design: oss-intake reads two inventory formats only, CSV and SBOM (CycloneDX or SPDX JSON). Every other source is
a small collector or a documented recipe that produces one of them, so the core stays vendor-neutral, needs no
vendor API keys, and a new source never touches the scanning code. Package-level sources (purls) come first;
application-level consoles (CrowdStrike, Tenable, Defender) already do CVE matching for installed applications
and are not primary sources (see "Not planned" below). Shipped: SBOM input (0.9.0), organisation scale and the
osquery collector (0.10.0), the Nexus collector and gate recipe (`examples/nexus`). What comes next is to be
agreed.

Not planned: connectors for CrowdStrike Falcon, Tenable One or Microsoft Defender software inventories. They list
installed applications by name, not packages, and already match CVEs for them. Use them to answer "which hosts
run X" once oss-intake has flagged a package.

On every release: rebuild the live sample (`sh examples/compromised-npm/build.sh`) and update the pinned version
in `examples/scheduled-rescan/oss-intake-rescan.yml` (a test checks it matches).

## Organisation view
Assess the open source an organisation already uses, not one artifact at a time, and re-run it on a schedule:
a package that was clean when approved can later turn out vulnerable or compromised.
- Artifactory collector (AQL), the same as the Nexus one (`examples/nexus`). Later (30 Oct): to be built and
  tested during a JFrog 14-day cloud trial, since there is no Artifactory instance to test against until then.
- Package inventory as `.xlsx`, read directly as an optional extra (openpyxl).
- Dependency-Track as a source: pull every project's SBOM through its API (it already takes oss-intake's VEX).
- Upgrade comparison for image and lockfile reports (done for inventories in 0.4.0): per package, what is still
  known at the minimum fix and at the latest stable release, with major-version warnings.

## Inputs
- Source checkouts: scan a folder in both Trivy modes (`fs` for lockfiles, `rootfs` for built artifacts) and
  merge, so a whole repository can be passed instead of its lockfile.
- CRAN fix dates for `renv.lock` findings (from CRAN's archive or the CRAN package database), and Bioconductor
  packages (OSV has a Bioconductor ecosystem).
- Non-GitHub forges (GitLab, Codeberg) for release cadence.

## Outputs
- PDF report. Deferred because it needs either a heavy dependency (WeasyPrint, ReportLab) or a headless
  browser, which conflicts with the minimal-dependency goal. Until then, print `report.html` to PDF from a
  browser; the page is self-contained and prints cleanly.
- SARIF output for code-scanning dashboards.

## Signals
- Optional VirusTotal lookup for `--path` artifacts: hash only, never an upload (uploads are shared with
  VirusTotal subscribers), opt-in with the user's own API key. Low value for new supply-chain compromises, which
  are usually unknown to VirusTotal at first; check the API terms for organisational use.
- Vendor rating beside the aggregator score: only where a structured vendor rating exists. Checked on
  CVE-2026-47884: NVD carries only a CISA-ADP 9.8, not Spring's own Medium, which exists only on spring.io. OS
  packages already use the distro's rating through Trivy. Low value until a general source appears.
- Amazon Linux fix dates: Trivy reports no ALAS IDs, so findings would need matching to ALAS by CVE and package.
- Rebuilt images: official images (redis, postgres...) are rebuilt with newer OS packages under the same tag.
  For the OS layer, lag against the image build date may be fairer than against the project's release date;
  consider reporting both.

## Scanner management
- An optional, opt-in scanner downloader: exact version only, SHA-256 against the release checksums file and
  cosign verification both mandatory, never "latest". Deliberately left out so far, because a downloader is
  the riskiest feature a supply-chain tool can have.
- Fetch the known-bad list from a signed location instead of shipping it with each release.

## Performance
- GET requests with query parameters skip the response cache and prefetched results
  (`http.RequestsHttp.get_json` builds the URL and goes straight to the network): GitHub releases, Launchpad and
  Alpine aports lookups. EPSS is meant to be fetched fresh and stays that way. Speed only, not correctness; no rush
  (agreed 3 Nov).
