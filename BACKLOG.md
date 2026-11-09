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
- Bioconductor packages in an `renv.lock` (OSV has a Bioconductor ecosystem).

## VS Code extensions (agreed 5 Nov; files and folders shipped first)
- JetBrains plugins (plugins.jetbrains.com has a public API).

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
  Kept here (8 Nov): AWS publishes no ALAS API, only the RSS feeds and the bulletin pages, and their format has
  not been checked against real samples yet.

## Scanner management
- Fetch the known-bad list from a signed location instead of shipping it with each release.
