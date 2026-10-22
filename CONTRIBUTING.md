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

- **No live network calls in tests.** Use fixtures in `tests/fixtures` and the `FakeHttp` helper. It fails
  the test if code reaches an unexpected URL.
- **Fixtures are synthetic.** Use `CVE-2099-*` and `GHSA-test-*` identifiers and fictional projects so
  fixtures cannot be mistaken for real advisories.
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

## Adding a known-bad scanner version

Edit `src/oss_intake/data/known_bad.json`, include a public reference (CVE, GHSA or vendor advisory), and add a
test case to `tests/test_units.py`.
