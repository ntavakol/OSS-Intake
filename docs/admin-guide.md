# oss-intake admin guide

Step by step: how to get each common result with the
[command builder](https://ntavakol.github.io/OSS-Intake/builder/). Each section says when to use it, what you
need, what to pick in the builder, the command it gives you, and what to read in the report. Every example has a
link that opens the builder with it already filled in, so you can change it to your own names and copy.

For every option and how the numbers are worked out, see the [guide](guide.md).

- [Before you start](#before-you-start)
- [The quickest way: paste what you were given](#the-quickest-way-paste-what-you-were-given)
- [Check a container image](#check-a-container-image)
- [Check a project's dependencies (a lockfile)](#check-a-projects-dependencies-a-lockfile)
- [Check a file you downloaded or built](#check-a-file-you-downloaded-or-built)
- [Check an SBOM or a package list](#check-an-sbom-or-a-package-list)
- [Check a few packages by name](#check-a-few-packages-by-name)
- [Check a GitHub project's health](#check-a-github-projects-health)
- [Block a CI pipeline](#block-a-ci-pipeline)
- [Re-run and keep your earlier decisions](#re-run-and-keep-your-earlier-decisions)
- [Reading any report](#reading-any-report)

## Before you start

1. Install oss-intake: `pipx install oss-intake` (on Windows without pipx, see
   [Install](guide.md#install)). Check it with `oss-intake --version`.
2. For a container image, a lockfile or a file you downloaded, install
   [Trivy](https://github.com/aquasecurity/trivy), pinned and verified as the guide describes in
   [Install the scanners yourself](guide.md#install-the-scanners-yourself-pinned-and-verified). Grype is optional.
   Package names, package lists and SBOMs need no scanner.
3. Optional: set `GITHUB_TOKEN` to raise the GitHub rate limit when you use `--repo`. It is only sent to
   api.github.com.
4. Open the [command builder](https://ntavakol.github.io/OSS-Intake/builder/). It opens on **Guided**. In the
   **Command** panel, **bash / zsh** (macOS, Linux) or **PowerShell** (Windows) sets the quoting.

On Windows the builder starts on PowerShell, elsewhere on bash / zsh. The builder has four steps: **1. What are you checking?**, **2. Details**, **3. What do you want back?** and
**4. Review**. **Next** stays unavailable until the step is complete, and says why. **4. Review** starts with
**Before you run it** (what the computer needs, with commands to copy) and **After it runs** (which file to open
and what to read first). Beside every step,
**What this command will do** says what the command checks, what it sends where, when it fails and what it does
not check. Read it before you copy.

## The quickest way: paste what you were given

Most checks start from something someone sent you: a link, an install command, a package name or a file. Paste
it into **Paste what you were given** at the top of the first step, and press Enter or **Set it up**. The builder
says what it recognised (for example "an npm package: chalk 5.6.1"), fills in the details and a folder name for
the report, and moves on to **3. What do you want back?**. Check the details, then carry on as in the sections
below.

| You paste | It sets up |
|---|---|
| `https://www.npmjs.com/package/chalk/v/5.6.1` or `npm install chalk@5.6.1` | the npm package chalk 5.6.1 |
| `https://pypi.org/project/requests/2.34.2/` or `pip install requests==2.34.2` | the PyPI package requests 2.34.2 |
| `npm install chalk@5.6.1 debug@4.4.2` | both packages, in one check |
| A Maven Central or mvnrepository link to a version | that Maven package |
| `docker pull nginx:1.27`, `nginx:1.27`, or a Docker Hub tag link | the container image nginx:1.27 |
| `https://github.com/owner/name` | the GitHub project's health |
| `package-lock.json`, `requirements.txt`, `app-2.4.1.jar`, `packages.csv`, `sbom.cdx.json` | the matching file check |

When it needs one more thing, it asks with buttons: "Which kind of package is chalk 5.6.1?" or "Is owner/app a
GitHub project or a container image?". When it cannot help, it says why and what to do instead, for example:

- a link or command with no version, or with a range such as `^5.0.0` or `latest`: oss-intake checks one exact
  version, and the page looks nothing up, so it cannot find one for you;
- an image with no tag;
- `package.json` or `build.gradle`: these list ranges, so it tells you which lockfile to check instead;
- a VS Code Marketplace link: oss-intake cannot check an installed extension, so check its source's lockfile;
- a browser extension: oss-intake does not check browser extensions.

## Check a container image

**When:** before you run a third-party image, or to see what a vendor's image ships.

**You need:** Trivy. The scanners read the image from Docker (or another local runtime) or pull it from the
registry.

1. In **1. What are you checking?**, pick **A container image**, then **Next**.
2. In **Which image?**, type the image with an explicit tag or digest, such as `owner/app:1.2.3`. An image
   without a tag is refused: "latest" changes under you.
3. Leave **Where should the scanners read it from?** on **Let the scanners choose**, or pick **remote** if you
   have no Docker.
4. In **Where is the source on GitHub?**, type the project, such as `owner/app`. This adds release cadence, the
   OpenSSF Scorecard, the workflow audit and release lag. Leave it empty if you do not know it.
5. **Next**. In **3. What do you want back?**, keep **A report to read**, and set **Folder for the report**.
6. **Next**, read **4. Review**, then **Copy** in the Command panel.

[Open this example in the builder](https://ntavakol.github.io/OSS-Intake/builder/#what=image&cmd=scan&image=owner%2Fapp%3A1.2.3&repo=owner%2Fapp&out=report-app)

```bash
oss-intake --image owner/app:1.2.3 --repo owner/app --out report-app
```

**Read the result:** open `report-app/report.html`. Malicious packages come first, then the **Act now** group
(known exploited, or a ready-made exploit). **Fix existed before release** counts fixes the project could have
shipped and did not; it needs a GitHub release whose tag matches the image tag (otherwise the image's build
date is used, and the report says so).

**Make it stronger:** in **All options**, under **Scanners and image**, set `--trivy-version` and
`--trivy-sha256` so a swapped scanner is refused before it runs. **What this command will do** lists this under
**Doesn't check** until you do.

## Check a project's dependencies (a lockfile)

**When:** before you adopt a library or tool from its source: an npm project, a Python project, or a VS Code
extension's source code.

**You need:** Trivy, and the project's lockfile: `package-lock.json`, `requirements.txt`, `poetry.lock`,
`pom.xml`, `go.sum`, `Cargo.lock` and others. If an npm project has only `package.json`, make the lockfile
without running its code: `npm install --package-lock-only --ignore-scripts`. Only the file is read: nothing is
downloaded or installed.

1. Pick **A project's dependency list**, then **Next**.
2. In **Where is it?**, type the path to the lockfile, such as `~/projects/web-app/package-lock.json`.
3. In **Where is the source on GitHub?**, type the project, such as `owner/web-app`.
4. **Next**, keep **A report to read**, set **Folder for the report**, **Next**, review and **Copy**.

[Open this example in the builder](https://ntavakol.github.io/OSS-Intake/builder/#what=lockfile&cmd=scan&path=%7E%2Fprojects%2Fweb-app%2Fpackage-lock.json&repo=owner%2Fweb-app&out=report-web-app)

```bash
oss-intake --path ~/projects/web-app/package-lock.json --repo owner/web-app --out report-web-app
```

**Read the result:** `report.html`, as for an image. A clean result covers the listed dependencies only: not the
project's own code, and not whether what you install (a VS Code `.vsix` from the Marketplace, say) was built from
this source. **Doesn't check** in the builder says so for this choice.

## Check a file you downloaded or built

**When:** you were sent a JAR, a wheel, an npm `.tgz` or a binary, and want to know what is in it and whether it
is the file the project published.

**You need:** Trivy. For a JAR, WAR, wheel, sdist or npm `.tgz`, oss-intake also compares the file with the
checksum its registry (Maven Central, PyPI or npm) publishes for that version.

1. Pick **A file or folder you downloaded or built**, then **Next**.
2. In **Where is it?**, type the path, such as `~/Downloads/app-2.4.1.jar`, and the project in **Where is the
   source on GitHub?** if you know it.
3. **Next**. To fail when the file is not the published one, pick **A pass or fail check, for CI** and tick
   **A package is known malware** and **The file doesn't match the checksum its registry publishes**.
4. Set **Folder for the report**, **Next**, review and **Copy**.

[Open this example in the builder](https://ntavakol.github.io/OSS-Intake/builder/#what=artifact&cmd=scan&path=%7E%2FDownloads%2Fapp-2.4.1.jar&repo=owner%2Fapp&out=report-app-jar&fail_on=malicious%2Cmismatch)

```bash
oss-intake --path ~/Downloads/app-2.4.1.jar --repo owner/app --out report-app-jar --fail-on malicious,mismatch
```

**Read the result:** a checksum mismatch leads the report: the file is not the one the project released
(rebuilt, repackaged or tampered with). The exit code is 3 for a mismatch or malware, and 1 if the file could not
be compared (a binary, a JAR without its Maven details, or a version the registry does not have). A match proves
only that the file is the published one, not that it is safe.

## Check an SBOM or a package list

**When:** you want to know whether any of the software you already run is affected: from Artifactory or Nexus,
a spreadsheet, or SBOMs from your build or your hosts.

**You need:** no scanner. A CycloneDX or SPDX SBOM, a folder of them, or a `.csv` with `ecosystem,name,version`
(or `purl`) columns. Extra columns such as `owner` or `system` become labels in the reports.

1. Pick **An SBOM or a package list**, then **Next**.
2. In **Where is it?**, type the path, such as `packages.csv` or a folder of SBOMs.
3. Optional: in **Labels (optional)**, add `owner=Web team` to label every package that has no owner yet.
4. **Next**, keep **A report to read**, set **Folder for the report**, **Next**, review and **Copy**.

[Open this example in the builder](https://ntavakol.github.io/OSS-Intake/builder/#what=inventory&cmd=scan&path=packages.csv&out=report-inventory&label=owner%3DWeb+team)

```bash
oss-intake --path packages.csv --out report-inventory --label 'owner=Web team'
```

**Read the result:** `executive-summary.html` is the page for a manager: how many packages need action now, the
top packages to act on, and totals by owner. `packages.csv` lists every package, worst first, with the minimum
upgrade that fixes what is known and what the latest release still has. Every row is validated before anything
is looked up, so a typo stops the run with its row number.

## Check a few packages by name

**When:** someone asks "are we affected by the compromised chalk release?", or you want to check a version
before you pin it.

**You need:** nothing but oss-intake. No file, no scanner.

1. Pick **Specific packages**, then **Next**.
2. In **Which packages?**, type one per row, such as `npm:chalk@5.6.1`, then **Add another --package** for
   `pypi:requests@2.34.2`. A purl such as `pkg:pypi/django@2.2.0` also works.
3. **Next**, keep **A report to read**, set **Folder for the report**, **Next**, review and **Copy**.

[Open this example in the builder](https://ntavakol.github.io/OSS-Intake/builder/#what=package&cmd=scan&package=npm%3Achalk%405.6.1&package=pypi%3Arequests%402.34.2&out=report-packages)

```bash
oss-intake --package npm:chalk@5.6.1 --package pypi:requests@2.34.2 --out report-packages
```

**Read the result:** the terminal prints one verdict line per package, such as
`chalk 5.6.1 (npm): MALICIOUS release. Remove it.` The full report is in the folder, with
`executive-summary.html` for sharing.

## Check a GitHub project's health

**When:** before you depend on a project at all: does it release, is it maintained, are its own builds safe?

**You need:** the project's `owner/name` on GitHub.

1. Pick **Just a GitHub project's health**, then **Next**.
2. In **Where is the source on GitHub?**, type `owner/name`.
3. **Next**, set **Folder for the report**, **Next**, review and **Copy**. No packages are checked, so there is
   no pass or fail check on findings here.

[Open this example in the builder](https://ntavakol.github.io/OSS-Intake/builder/#what=repo&cmd=scan&repo=owner%2Fname&out=report-health)

```bash
oss-intake --repo owner/name --out report-health
```

**Read the result:** the **Project health** section: days since the last release and the last push, releases in
the last year, whether it is archived, the OpenSSF Scorecard (if the project is in its dataset; "not scored" is
not a bad sign), and the audit of its GitHub Actions workflows (unpinned or known-bad actions).

## Block a CI pipeline

**When:** you want a build to stop if a dependency is malware, is known to be exploited, or has a high or
critical vulnerability.

**You need:** whatever the input needs (Trivy for a lockfile, as here). The CI job runs oss-intake and checks its
exit code.

1. Pick what the pipeline checks, here **A project's dependency list**, and give its path, here
   `package-lock.json` (relative to where the job runs).
2. In **3. What do you want back?**, pick **A pass or fail check, for CI**, and tick the gates. The three marked
   **recommended** are a good start: **A package is known malware**, **A vulnerability is known to be exploited
   (CISA KEV)** and **A high or critical vulnerability**.
3. Optional: **Also fail if the suggested likelihood is at least** adds a gate on the 1 to 5 likelihood heuristic.
4. Set **Folder for the report**, **Next**, review and **Copy**.

[Open this example in the builder](https://ntavakol.github.io/OSS-Intake/builder/#what=lockfile&cmd=scan&path=package-lock.json&out=report&fail_on=malicious%2Ckev%2Chigh)

```bash
oss-intake --path package-lock.json --out report --fail-on malicious,kev,high
```

**Exit codes:** 0 passed, 3 a gate was hit, 1 a check a gate needs could not run (the run fails rather than
pass on a check that did not happen), 2 the command was refused before any work. Keep the `report` folder as a
build artifact, so whoever looks at a failed build can see why. For a weekly re-scan that opens an issue when
something new needs action, copy the ready-made workflow in
[examples/scheduled-rescan](../examples/scheduled-rescan/).

## Re-run and keep your earlier decisions

**When:** you assessed the findings once (not affected, fixed, under investigation) and want the next run to
show only what is new.

1. Open the earlier run's `findings.csv` in a spreadsheet and fill in `triage_status` (`not_affected`,
   `affected`, `fixed` or `under_investigation`) and `triage_notes` for the findings you assessed. Save it as CSV.
2. In the builder, set up the same check as before, then open **All options**. Your choices carry over.
3. In the **Evidence sources** group, set `--decisions` to the earlier `findings.csv`, and give the new run its
   own folder.
4. **Copy**.

[Open this example in the builder](https://ntavakol.github.io/OSS-Intake/builder/#view=form&cmd=scan&path=packages.csv&out=report-2&decisions=report-1%2Ffindings.csv)

```bash
oss-intake --path packages.csv --out report-2 --decisions report-1/findings.csv
```

**Read the result:** findings you marked `not_affected` or `fixed` are set aside with your note as the reason;
the new `findings.csv` comes out with your decisions filled in, so only new findings are blank. A decision never
sets aside a malicious package. The run also writes `openvex.json` and `vex.cdx.json` for other tools.

## Reading any report

Every run writes `findings.csv` (always), and by default `summary.md`, `assessment.json` and `report.html` to the
folder you chose. Start with `report.html`:

1. **Warnings** at the top: anything that was not checked, and why. "Not checked" in grey is not a clean zero.
2. **Malicious packages:** remove them; do not patch.
3. **Suggested triage:** **Act now** (malware, known exploited, a ready-made exploit), then **Review**, then
   **Check conditions** (the advisory says when it applies; compare with how you run it), then **Routine**.
4. **Top findings:** each with its fix, how long the fix has been available, and its exploit evidence.

A finding means a component version is listed as affected. It does not prove the vulnerable code is reachable
where you run it: that is the assessor's call, recorded in `findings.csv` and carried to the next run.
