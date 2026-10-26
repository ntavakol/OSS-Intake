"""Regenerate the README sections that are derived from the code, so they cannot drift.

    python scripts/readme_sync.py          # rewrite README.md in place
    python scripts/readme_sync.py --check  # exit 1 if README.md is out of date (the test suite does this too)

Each generated section sits between <!-- generated:NAME --> and <!-- /generated:NAME --> markers:
  example-output     the summary line and findings table from a run on the synthetic test fixtures
  likelihood-rules   the default likelihood rules, from likelihood.DEFAULT_CONFIG
  likelihood-metrics the metric names a custom likelihood configuration can use
"""

from __future__ import annotations

import contextlib
import io
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
AS_OF = "2026-10-22"  # the same date the end-to-end tests use
_BLOCK = re.compile(r"(<!-- generated:([\w-]+) -->\n)(.*?)(<!-- /generated:\2 -->)", re.S)


def _example_output() -> str:
    sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
    from oss_intake import cli
    from tests.conftest import FIX, FakeHttp

    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "reports"
        argv = ["--image", "example/webapp:2.0.0", "--repo", "example/webapp", "--out", str(out),
                "--from-trivy-json", str(FIX / "trivy.json"), "--from-grype-json", str(FIX / "grype.json"),
                "--scanners", "trivy,grype,osv", "--as-of", AS_OF, "--likelihood", "--quiet", "--formats", "md"]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            cli.main(argv, http=FakeHttp())
        summary_line = next(line for line in stdout.getvalue().splitlines() if line.startswith("findings="))
        md = (out / "summary.md").read_text(encoding="utf-8")
    table = re.search(r"^## Top \d+ findings\n\n((?:\|.*\n)+)", md, re.M).group(1)
    return f"```text\n{summary_line}\n```\n\n{table}"


def _likelihood_rules() -> str:
    sys.path[:0] = [str(ROOT / "src")]
    from oss_intake import likelihood

    cfg = likelihood.DEFAULT_CONFIG
    rows = [f"| {r['level']} {cfg['scale'][str(r['level'])]} | {r['reason']} |" for r in cfg["rules"]]
    return "| Level | Default rule |\n|---|---|\n" + "\n".join(rows) + "\n"


def _likelihood_metrics() -> str:
    sys.path[:0] = [str(ROOT / "src")]
    from oss_intake import likelihood

    names = sorted(likelihood.metrics({}, {}, {"status": "skipped"}))
    return "The available metrics are " + ", ".join(f"`{n}`" for n in names[:-1]) + f" and `{names[-1]}`.\n"


GENERATORS = {"example-output": _example_output, "likelihood-rules": _likelihood_rules,
              "likelihood-metrics": _likelihood_metrics}


def render(text: str) -> str:
    found = {m.group(2) for m in _BLOCK.finditer(text)}
    missing = set(GENERATORS) - found
    if missing:
        raise SystemExit(f"README.md lacks generated sections: {', '.join(sorted(missing))}")
    return _BLOCK.sub(lambda m: m.group(1) + GENERATORS[m.group(2)]() + m.group(4), text)


def main(argv: list[str]) -> int:
    text = README.read_text(encoding="utf-8")
    new = render(text)
    if "--check" in argv:
        if new != text:
            print("README.md is out of date: run python scripts/readme_sync.py", file=sys.stderr)
            return 1
        return 0
    README.write_text(new, encoding="utf-8")
    print("README.md updated" if new != text else "README.md already current")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
