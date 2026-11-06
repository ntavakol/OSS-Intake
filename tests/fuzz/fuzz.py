"""Fuzz one parser with Atheris (Linux x86_64, Python 3.13; Atheris has no macOS, Windows or Arm wheels).

    python tests/fuzz/fuzz.py TARGET [CORPUS_DIR] [libFuzzer options, e.g. -max_total_time=180]

TARGET is one of tests/fuzz/harnesses.py TARGETS. Without a corpus folder, the target's seeds (seeds.py) are
written to a temporary one, removed at the end (pass a folder to keep what the run finds). A crash, a hang
(-timeout) or running out of memory (-rss_limit_mb) stops the run with the input saved as crash-*, timeout-* or
oom-* (-artifact_prefix=DIR/ chooses where); replay it with python tests/fuzz/fuzz.py TARGET THAT_FILE.
CONTRIBUTING.md has the details.
"""

import atexit
import shutil
import sys
import tempfile
from pathlib import Path

import atheris

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # the repository root, for tests.fuzz

with atheris.instrument_imports(include=["oss_intake", "zipfile"]):  # zipfile: coverage from the .vsix format
    from tests.fuzz import harnesses, seeds


def main() -> None:
    if len(sys.argv) < 2 or sys.argv[1] not in harnesses.TARGETS:
        sys.exit(f"usage: fuzz.py TARGET [CORPUS_DIR] [libFuzzer options]; targets: {', '.join(harnesses.TARGETS)}")
    name = sys.argv.pop(1)
    if not any(not a.startswith("-") for a in sys.argv[1:]):
        corpus = Path(tempfile.mkdtemp(prefix=f"corpus-{name}-"))
        atexit.register(shutil.rmtree, corpus, True)  # pass a folder to keep the corpus the run grows
        for n, data in enumerate(seeds.seeds(name)):
            (corpus / f"seed-{n}").write_bytes(data)
        sys.argv.insert(1, str(corpus))
    atheris.Setup(sys.argv, harnesses.run(name))
    atheris.Fuzz()


if __name__ == "__main__":
    main()
