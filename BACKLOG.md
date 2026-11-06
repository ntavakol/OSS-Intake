# Backlog

Open work only, agreed for later versions. "Next" is the planned order; the other sections are not ranked.
Finished items are removed in the commit that ships them; CHANGELOG.md records what was done and when.

## Next: the threat model's open items (agreed 6 Nov, in this order)
Open items 1 to 10 of `docs/threat-model.md`. Each fix comes with a test that fails without it.
1. Require govulncheck's hash for `--reachability`, or set nothing aside on its verdict without it (an existing
   test expects "not reachable" to set a finding aside without a hash, so this needs Ned's OK). Malicious and
   CISA KEV findings are no longer set aside by the evidence rules (6 Nov), except a kernel header CVE in KEV,
   which an existing test keeps set aside on purpose; also Ned's call.
2. Make `--fail-on recent` fail for a version with no known date, and report a workflow audit with files missing
   as partial.
3. Report a binary checked against an unsigned checksums file as such, not as hash verified.
4. Refuse to write a report through a symbolic link, and remove stale report files the run did not write.
5. Size limits for inventories, decisions files, imported reports and service responses, and a total deadline for
   each request; refuse an SBOM over its size limit instead of passing it to the scanners.
6. Check the cache folder's subfolders and entries for ownership, and check it on Windows.
7. Pass `--path` folders to Trivy and govulncheck so a name starting with `-` cannot be read as an option.
8. Extend the workflow pinning tests to `codeql.yml` and `scorecard.yml`.
9. Write paths relative to the target, not absolute local paths, in `assessment.json` and the HTML report.
10. Resolve a VS Code extension's `main` inside its folder as VS Code does (an absolute path or `../` does not
    leave it), so the bundled check cannot be avoided (agreed 6 Nov).

## Later: when commits are less frequent (agreed 6 Nov)
- Branch protection with required status checks: changes reach main only through a pull request whose CI has
  passed (Scorecard Branch-Protection is 3 with the current ruleset, which blocks force-push and deletion).
  Means working through pull requests instead of pushing to main, so it waits until changes are less frequent.

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

## VS Code extensions (agreed 5 Nov; files and folders shipped first)
- Download by ID (`vscode:publisher.name@1.2.3`), from Open VSX's public API only: the VS Code Marketplace's API
  is unofficial and its terms tie it to Microsoft's products.
- Compare two versions of an extension: what changed in an update (new indicators, new web addresses, new
  native files, a new publisher), since most extension compromises arrive as an update to a trusted one.
- Fleet input from osquery's `vscode_extensions` table, through the existing osquery collector: the removal list
  check for every machine, by ID and version.
- Open VSX metadata (publisher verification, downloads, last update) for extensions from Cursor and VSCodium.
- Check the Marketplace signature of a `.vsix`.
- JetBrains plugins (plugins.jetbrains.com has a public API).

## Outputs
- PDF report. Deferred because it needs either a heavy dependency (WeasyPrint, ReportLab) or a headless
  browser, which conflicts with the minimal-dependency goal. Until then, print `report.html` to PDF from a
  browser; the page is self-contained and prints cleanly.
- SARIF output for code-scanning dashboards.
- Report date and time in UTC on request (for example `--utc`): the reports show local time by default (0.13.0);
  a team in several time zones, or a pipeline comparing runs, may want UTC throughout. Day counts already use
  UTC dates.

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
