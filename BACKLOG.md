# Backlog

Items agreed for later versions, roughly in priority order.

## Inputs
- Standalone artifacts: scan a JAR, WAR or binary directly (`trivy rootfs` / `grype file:`).
- Dependency manifests and lockfiles: `requirements.txt`, `poetry.lock`, `renv.lock`, `package-lock.json`,
  `pom.xml`. Release lag then applies to source releases rather than images.
- Non-GitHub forges (GitLab, Codeberg) for release cadence.

## Outputs
- PDF report. Deferred because it needs either a heavy dependency (WeasyPrint, ReportLab) or a headless
  browser, which conflicts with the minimal-dependency goal. Until then, print `report.html` to PDF from a
  browser; the page is self-contained and prints cleanly.
- SARIF output for code-scanning dashboards.
- README screenshots of the HTML report (light and dark, desktop and phone). No real project may be identifiable:
  mask the image, repository and package identifiers. Rendering from the synthetic test fixtures (example/webapp,
  CVE-2099-* IDs) is not enough on its own: they use real library names (spring-web, jackson-databind), so
  package names must be masked there too, or the fixtures given made-up names. Generate them with a script
  (Playwright, already used for checks) so they can be refreshed when the layout changes.
- VEX import, so triage decisions in `findings.csv` can be carried between runs.

## Signals
- Vendor rating beside the aggregator score: show the vendor's own severity or CVSS (the CNA score in NVD
  records, vendor entries in GHSA and OSV) next to the highest score. On ShinyProxy 3.2.4 four Spring
  "criticals" (GHSA 9.8) were rated Medium or Low by Spring; showing both would have flagged them.
- Go reachability: run `govulncheck -mode=binary` (an external executable, like the scanners) on Go binaries
  found in the image, and record whether each Go finding's vulnerable symbol is reachable. Real evidence for
  "not reachable", for Go only (for example gosu in official Docker images).
- Advisory preconditions: show the advisory's own "affected only if" text verbatim beside the finding, with a
  link, without interpreting it (Spring advisories state these explicitly).
- Triage grouping in the report, once the above exist: act now (KEV or weaponised exploit), check the
  precondition (vendor rates lower, or a feature must be in use), probably noise (evidence of no reachability),
  each with its reasons. The tool never concludes "no risk" without evidence such as govulncheck.
- Exploit availability per finding, beside CVSS and EPSS: report the strongest evidence found, as a level with an
  "as of" date: in CISA KEV > Metasploit module or Nuclei template (weaponised) > Exploit-DB entry > GitHub
  proof of concept only > none indexed. Sources that need no key and can be fetched in bulk: Metasploit's
  modules metadata file (CVE references per module), the nuclei-templates repository, Exploit-DB's CSV (CVE
  column), and the nomi-sec PoC-in-GitHub index. Optional with a token: VulnCheck KEV and XDB (validated
  proofs of concept). GitHub proofs of concept are noisy (fake, sometimes malicious), so they rank lowest.
  Wording must say that "none indexed" is not evidence that no exploit exists. Decide whether weaponised
  levels feed the likelihood rules (for example Metasploit or Nuclei on a fixable finding gives level 4).
  Probe each source's current file format before building.
- Amazon Linux fix dates: Trivy reports no ALAS IDs, so findings would need matching to ALAS by CVE and package.
- Rebuilt images: official images (redis, postgres...) are rebuilt with newer OS packages under the same tag.
  For the OS layer, lag against the image build date may be fairer than against the project's release date;
  consider reporting both.

## Scanner management
- An optional, opt-in scanner downloader: exact version only, SHA-256 against the release checksums file and
  cosign verification both mandatory, never "latest". Deliberately left out of v0.1 because a downloader is the
  riskiest feature a supply-chain tool can have.
- Fetch the known-bad list from a signed location instead of shipping it with each release.

## Publishing
- PyPI release through trusted publishing (OIDC), with build provenance attestations.
