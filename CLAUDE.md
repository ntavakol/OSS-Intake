# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
python -m pip install -e ".[dev]"          # dev install (CI uses: pip install --require-hashes -r requirements/dev.txt)
python -m ruff check .                     # lint (line length 120, rules E,F,W,I,B,UP,S)
python -m pytest                           # full suite; no network needed
python -m pytest tests/test_units.py::test_readme_generated_sections_are_current   # one test
python -m pytest -k osv                    # tests matching a name
python scripts/readme_sync.py              # regenerate README sections derived from code (--check to verify)
```

To exercise the full pipeline without Trivy, Grype or network (the pattern `readme_sync.py` and the end-to-end
tests use): call `cli.main([... "--from-trivy-json", "tests/fixtures/trivy.json", "--from-grype-json",
"tests/fixtures/grype.json", "--as-of", "2026-10-22"], http=FakeHttp())` with `FakeHttp` from `tests/conftest.py`.

CI runs ruff and pytest on Linux, macOS and Windows, Python 3.10 to 3.13. `requirements/dev.txt` is hash-pinned and
regenerated from `requirements/dev.in` with the `uv pip compile` command in its header.

## Architecture

`oss-intake` is a CLI (`src/oss_intake/cli.py`, entry `cli:main`, subcommands `scan`, `verify`, `doctor`; `main`
inserts `scan` when the first argument is not a subcommand) that runs external scanners, merges their output,
enriches it from public APIs and writes reports.

The `scan` pipeline in `cli.py` runs in numbered stages: `cmd_scan` validates every input before any work is done
(bad input exits 2, before an output folder is created) -> `_plan_and_scan` (response cache, registry checksum check
of artifacts) -> `_scan` -> `_assess` (malicious marking, 3. project health, 4. enrichment, 5. reports).
Exit codes: 0 ok, 1 error, 2 usage, 3 `--fail-on` threshold hit.

- **Input**: `inputs.classify()` decides what `--path` is (artifact, lockfile, renv, inventory CSV, SBOM folder...).
  `sbom.py`, `os_packages.py` and `inventory_report.py` handle the organisation-inventory paths.
- **Scanners** (`scanners/`): `trivy`, `grype`, `osv`, `govulncheck`. Each turns its tool's JSON into
  `models.Finding` objects. `--from-trivy-json` / `--from-grype-json` load saved output instead of running a tool;
  tests rely on this. `integrity.py` pins scanner versions, checks SHA-256 / cosign and refuses versions in
  `data/known_bad.json` *before* a binary executes.
- **Merge** (`merge.py`): one row per vulnerability, package and version, keyed via `models.canonical_id` (aliases),
  recording which sources saw it.
- **Enrichment** (`enrich/`): fix publish dates (deps.dev, distro trackers for Debian/Ubuntu/Alpine/Red Hat),
  KEV, EPSS, exploit evidence, advisory text. **Health** (`health/`): release cadence, Scorecard, workflow audit.
- **Analysis**: `lag.py` (release lag: fix published before the project's release), `triage.py` (groups
  act/review/conditions/routine/aside), `conditions.py`, `reachability.py`, `likelihood.py` (rule-based
  heuristic, `DEFAULT_CONFIG`), `decisions.py` (assessor decisions / OpenVEX carried between runs).
- **Output**: `report.py` (csv, md, json, VEX) and `report_html.py` (self-contained HTML), plus `exec_summary.py`.
- **Network**: all HTTP goes through the `http.Http` interface (`RequestsHttp` in production, with `ResponseCache`
  and parallel `prefetch`). `cli.main(argv, http=...)` accepts an injected `Http`, which is how tests run offline.

## How to work here

- Plan before coding anything beyond a trivial fix: what changes, which files, the interface, how it is tested;
  wait for approval. An approved plan may cover several commits. Stay in scope: suggest unrelated tidying
  separately. Ask rather than guess; never invent options, endpoints or library features.
- A bug fix comes with a test that fails without the fix; run it against the old code and say so.
- Never change or delete an existing test to make it pass; flag it and wait for agreement.
- No timing thresholds that depend on machine speed (the Windows runners are slow); compare with a baseline.
- Dangerous patterns need approval: `eval`/`exec`, `shell=True`, commands built from strings, disabled TLS
  verification, unsafe deserialisation, credentials sent anywhere but their own host (including redirects).
- Commands for the maintainer to paste: zsh on macOS, no `<placeholders>`, steps chained with `&&`.
- Finish with a summary: files changed, tests added, ruff and pytest results, what to check by hand.
- Never rewrite published history or force-push (the `main` ruleset forbids it anyway).

## Rules from CONTRIBUTING.md

- Every change ships with tests; a bug fix needs a test that fails without it.
- No live network calls in tests: use `tests/conftest.py::FakeHttp`, which routes URLs to `tests/fixtures` and
  raises on any unexpected URL. Add a route there when new code calls a new endpoint.
- Fixtures are synthetic (`CVE-2099-*`, `GHSA-test-*`, project `example/webapp`). Exception: `tests/fixtures/real`,
  trimmed output from public images made with `scripts/extract_regression_fixture.py` (tests in
  `test_real_regressions.py`). `test_recorded_seeds.py` replays recorded real OSV answers (refresh with
  `scripts/record_seeds.py`).
- Runtime dependency is `requests` only; raise new dependencies in an issue first.
- Cross-platform: `pathlib`, subprocess args as lists (never `shell=True`), explicit `encoding=` on file opens.
- GitHub Actions pinned by full commit SHA with the version as a trailing comment; workflow permissions
  `contents: read` unless a job needs more.
- No secrets, internal hostnames, employer or customer names anywhere, including commit messages.
- Write plainly; no em dashes in docs or tool output.
- User-visible changes get a `CHANGELOG.md` entry under "Unreleased".
- README is partly generated (`<!-- generated:NAME -->` blocks: example output, likelihood rules and metrics).
  After changing report format or likelihood rules, run `python scripts/readme_sync.py`; tests fail until you do.
  Every `scan` and `verify` option must be mentioned in the README (a test checks this).
- Adding a known-bad scanner version: edit `src/oss_intake/data/known_bad.json` with a public reference and add a
  case to `tests/test_units.py`.

## Releases

Before a release, an independent review (a reviewer that did not write the change) looks for real bugs;
fixes come with tests that fail without them. Tag and publish only after CI passes on that exact commit (find
the run with `gh run list --workflow ci --commit $(git rev-parse HEAD)`).

Publishing a GitHub release triggers `.github/workflows/release.yml` (PyPI trusted publishing plus Sigstore
signatures). Version lives in both `pyproject.toml` and `src/oss_intake/__init__.py`. On release, also rebuild the live sample
(`sh examples/compromised-npm/build.sh`) and update the pinned version in
`examples/scheduled-rescan/oss-intake-rescan.yml` (a test checks it matches). `BACKLOG.md` holds agreed open work;
finished items are removed in the commit that ships them.

`reports*/` folders in the repo root are local scan output and are gitignored.
