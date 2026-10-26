# Contributing

Thanks for helping. Issues and pull requests are welcome.

## Development setup

```bash
git clone https://github.com/ntavakol/OSS-Intake
cd OSS-Intake
python -m venv .venv
# Linux/macOS: source .venv/bin/activate    Windows: .venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
python -m ruff check .
python -m pytest
```

## Rules

- **Tests come with the change.** New functionality must add automated tests that cover it, and a bug fix must
  add a test that fails without the fix. CI (`ruff` and `pytest` on Linux, macOS and Windows) must pass before
  a change is merged or released.
- **No live network calls in tests.** Use fixtures in `tests/fixtures` and the `FakeHttp` helper. It fails
  the test if code reaches an unexpected URL.
- **Fixtures are synthetic.** Use `CVE-2099-*` and `GHSA-test-*` identifiers and fictional projects so
  fixtures cannot be mistaken for real advisories.
  The exception is `tests/fixtures/real`, which holds trimmed output from public images only.
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
- Parts of the README are generated from the code (example output, likelihood rules and metrics). After changing
  the report format or the likelihood rules, run `python scripts/readme_sync.py`; the tests fail until you do.
  Every `scan` and `verify` option must also appear in the README.

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

## Adding a known-bad scanner version

Edit `src/oss_intake/data/known_bad.json`, include a public reference (CVE, GHSA or vendor advisory), and add a
test case to `tests/test_units.py`.
