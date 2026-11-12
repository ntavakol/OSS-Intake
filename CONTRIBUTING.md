# Contributing

Thanks for helping. Issues and pull requests are welcome. Start with [docs/architecture.md](docs/architecture.md):
the pipeline, the modules, the data model and how to add a scanner, an enricher or a collector.

## Development setup

```bash
git clone https://github.com/ntavakol/OSS-Intake
cd OSS-Intake
python -m venv .venv
# Linux/macOS: source .venv/bin/activate    Windows: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m ruff check .
python -m mypy
python -m pytest
python -m coverage run -m pytest && python -m coverage report   # what CI checks: fails below the floor
```

Optional: scan what you are about to commit for secrets with [gitleaks](https://github.com/gitleaks/gitleaks)
(CI scans the full history on every push and pull request). Install a release from
[gitleaks releases](https://github.com/gitleaks/gitleaks/releases), check its SHA-256 against the release's
checksums file (`oss-intake verify --file <archive> --checksums <checksums file>` does this), then add it as a
pre-commit hook. This replaces any pre-commit hook you already have:

```bash
printf '#!/bin/sh\nexec gitleaks git --pre-commit --staged --redact --no-banner\n' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

The test and lint tools CI uses are pinned with hashes in `requirements/dev.txt`, compiled from
`requirements/dev.in` with [uv](https://docs.astral.sh/uv/) for every platform and supported Python version.
Dependabot does not update them, because it cannot compile them that way. To update one, change its version in
`requirements/dev.in`, then regenerate, keeping the four comment lines at the top of `dev.txt`:

```bash
{ head -4 requirements/dev.txt; uv pip compile --universal --generate-hashes --python-version 3.10 --no-header \
    --no-annotate requirements/dev.in; } > dev.txt.new && mv dev.txt.new requirements/dev.txt
```

Check that `git diff requirements/dev.txt` changes only what you meant to, and that the Windows (`colorama`) and
Python 3.10 (`exceptiongroup`, `tomli`) pins are still there.

## Rules

- **Tests come with the change.** New functionality must add automated tests that cover it, and a bug fix must
  add a test that fails without the fix. CI (`ruff`, `mypy` and `pytest` on Linux, macOS and Windows, a coverage
  floor, and a gitleaks scan of the full history) must pass before a change is merged or released. If a test fixture
  trips gitleaks (an advisory that quotes an example key, say), add its fingerprint to `.gitleaksignore` with
  the reason; never commit a real secret, even one already revoked.
- **No live network calls in tests.** Use fixtures in `tests/fixtures` and the `FakeHttp` helper. It fails
  the test if code reaches an unexpected URL.
- **Fixtures are synthetic.** Use `CVE-2099-*` and `GHSA-test-*` identifiers and fictional projects so
  fixtures cannot be mistaken for real advisories.
  The exception is `tests/fixtures/real`, which holds trimmed output from public images only.
- **Fixtures and examples must not use file names that dependency scanners recognise** (`*.cdx.json`,
  `*.spdx.json`, `bom.json`, `package-lock.json`, `requirements*.txt` and the like). OSV-Scanner, which OpenSSF
  Scorecard runs over the whole repository, reads them as the project's own dependencies, and the fixtures are
  vulnerable on purpose. Use `*.cdx-fixture.json`, `*.spdx-fixture.json` or `*.sample.json`; oss-intake reads
  SBOMs by content. `test_fixtures_and_examples_do_not_look_like_the_projects_dependencies` lists the names.
- **No secrets, internal hostnames, employer or customer names** in code, fixtures, examples or commit
  messages.
- **Keep dependencies minimal.** The runtime depends on `requests` only. Discuss new dependencies in an issue
  first.
- **Pin GitHub Actions by full commit SHA** with the version as a trailing comment, and keep workflow
  permissions at `contents: read` unless a job truly needs more.
- **Cross-platform.** Use `pathlib`, pass subprocess arguments as lists (never `shell=True`), and open files
  with an explicit encoding.
- Style: write plainly and avoid em dashes in documentation and output.
- Add a `CHANGELOG.md` entry under "Unreleased" for user-visible changes.
- The command builder (`site/builder/`) is generated from the CLI's own parser. After adding or changing an
  option, run `python scripts/export_options.py` and add the option to a group in `site/builder/ui-groups.json`;
  the tests fail until both are done. Cross-option checks the CLI makes are mirrored in
  `site/builder/rules.json`, and each rule's example is run through the CLI. The JavaScript tests need only
  Node 22 or later (no packages): `node --test tests/builder/*.test.mjs`.
- The builder's guided questions and "What this command will do" are in `site/builder/wizard.json`. When an
  option the questions offer changes meaning, change its sentence there. A new service the code calls (a
  module-level `https://` URL constant) must be added to its `services`, so the page can say what is contacted;
  a test fails until it is. `tests/fixtures/wizard_summaries.json` holds the summary for a few hundred commands:
  after a deliberate change, regenerate it with `UPDATE_SUMMARIES=1 node --test tests/builder/summaries.test.mjs`
  and read its diff, since every changed line must be true of what the CLI does. `docs/admin-guide.md` names the
  builder's labels and links to filled-in examples; the tests fail if a label changes or a link stops giving the
  command shown, so update the guide with the builder.
- The README is a short introduction; reference material goes in `docs/guide.md`. Parts of the guide are
  generated from the code (example output, likelihood rules and metrics). After changing the report format or the
  likelihood rules, run `python scripts/readme_sync.py`; the tests fail until you do. Every `scan` and `verify`
  option must also be documented in the guide.

## Validating against real images

`scripts/validate_images.py` runs oss-intake over a list of public images and writes one summary table:

```bash
python scripts/validate_images.py scripts/validate-images.txt --out reports-validate \
  --trivy-sha256 <hash> --grype-sha256 <hash>
```

Share `reports-validate/summary.md` when reporting a problem. Edit the list to add images.

## Adding a real-image regression test

When a real image exposes a bug, trim its raw scan into a fixture and pin the bug with a test:

```bash
python scripts/extract_regression_fixture.py <name> <reports-dir>/raw --match <package-substring> --os-sample 3
```

Fixtures in `tests/fixtures/real` come only from public images and keep only the rows a test needs.

## Fuzzing

`tests/fuzz/harnesses.py` has fuzz targets for the parsers of files a user gives (SBOMs, inventories, decisions
files, renv.lock, scanner reports, also imported into a whole offline run, .vsix files as an archive and as the
files inside one, a JetBrains plugin file's signing block, Amazon Linux repository metadata), and for checksums files, likelihood configurations, govulncheck output, OSV advisories and
text from other public services. A target may raise only the errors the CLI reports cleanly; anything else, a
hang over 10 seconds or using over 2 GB is a bug. Answers from the other services (KEV, EPSS, deps.dev, the
distro trackers, the GitHub API) have no target yet.

- Every push runs each target on its seeds and simple mutations of them, without Atheris, on every platform
  (`tests/test_fuzz_harnesses.py`). A new target must be added to the matrix in `.github/workflows/fuzz.yml`.
- `.github/workflows/fuzz.yml` fuzzes each target with [Atheris](https://github.com/google/atheris) for three
  minutes every week, and on demand (Actions, fuzz, Run workflow). A failing input is kept as the job's artifact.

Atheris runs on Linux x86_64 only (it has no macOS, Windows or Arm wheels). On a Mac, run it in an x86_64
container from the repository folder (on Apple silicon it is emulated, so slower). This fuzzes the SBOM reader
for five minutes as your own user, installs into the container only, and leaves any failing input in
`fuzz-out/`:

```bash
mkdir -p fuzz-out && docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD":/src -w /src python:3.13 bash -c '
  python -m venv /tmp/v &&
  /tmp/v/bin/pip install -q --require-hashes -r requirements/dev.txt -r requirements/fuzz.txt &&
  PYTHONPATH=src /tmp/v/bin/python tests/fuzz/fuzz.py sbom_file -max_total_time=300 -timeout=10 \
    -rss_limit_mb=2048 -artifact_prefix=fuzz-out/'
```

To replay an input, pass the file instead of the time limit: the target runs it once and shows the traceback.
For an input the weekly job kept, first download its artifact into `fuzz-out/` (the job's page in Actions, or
`gh run download` with the run's ID and `-n fuzz-` plus the target's name). For the SBOM target:

```bash
docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" -e HOME=/tmp \
  -v "$PWD":/src -w /src python:3.13 bash -c '
  python -m venv /tmp/v &&
  /tmp/v/bin/pip install -q --require-hashes -r requirements/dev.txt -r requirements/fuzz.txt &&
  PYTHONPATH=src /tmp/v/bin/python tests/fuzz/fuzz.py sbom_file fuzz-out/crash-*'
```

Fix each one as a bug, with a test that fails without the fix (the tests at the end of `tests/test_units.py`
are examples). To update Atheris, change `requirements/fuzz.in` and regenerate `requirements/fuzz.txt` with the
command in its first lines.

## Adding a known-bad scanner version

Edit `src/oss_intake/data/known_bad.json`, include a public reference (CVE, GHSA or vendor advisory), and add a
test case to `tests/test_units.py`.
