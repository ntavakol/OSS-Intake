# Backlog

Open work only, agreed for later versions. "Next" is the planned order; the other sections are not ranked.
Finished items are removed in the commit that ships them; CHANGELOG.md records what was done and when.

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
- Dependency-Track as a source: pull every project's SBOM through its API (it already takes oss-intake's VEX).

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

## Signals
- Optional VirusTotal lookup for `--path` artifacts (parked 8 Nov): hash only, never an upload (uploads are
  shared with VirusTotal subscribers), opt-in with the user's own key, read from `VT_API_KEY` (never an option,
  never logged), paced to the public API's 4 requests a minute by default. Users bring their own key: VirusTotal's
  public API is for free, non-commercial use, and a hash-only workflow at work needs a premium key, so the guide
  must say which key fits which use (and the VirusTotal terms, now under Google Cloud's, be read first). Tested
  by the maintainer with a personal key on his own machine only, never in CI; tests use recorded answers. Low
  value for new supply-chain compromises, which are usually unknown to VirusTotal at first.
- YARA scanning (agreed 8 Nov): match the files oss-intake already reads (`--path` artifacts, `.vsix` and
  installed extensions) against rules the user supplies (`--yara-rules DIR`), each match a finding with the rule
  and the file. `yara-x` as an optional extra. No rules are shipped (the common public sets have restrictive
  licences, and shipped rules would need keeping current). Rule files are input: size and time limits, and a
  rule that does not compile is a clear error. Not rule generation: for a known-bad package the hash is the
  better indicator.
- Amazon Linux fix dates: Trivy reports no ALAS IDs, so findings would need matching to ALAS by CVE and package.
- Rebuilt images: official images (redis, postgres...) are rebuilt with newer OS packages under the same tag.
  For the OS layer, lag against the image build date may be fairer than against the project's release date;
  consider reporting both.

## Scanner management
- Fetch the known-bad list from a signed location instead of shipping it with each release.
- Grype signature without cosign's deprecated flags (agreed 8 Nov): `--grype-cosign-certificate` and
  `--grype-cosign-signature` call `cosign verify-blob --certificate --signature`, which cosign marks deprecated
  in favour of `--bundle` with `--trusted-root`. Before cosign removes them, build a Sigstore bundle from Grype's
  `.pem` and `.sig` and the transparency log entry, and verify that instead; or switch if Grype starts
  publishing bundles.
