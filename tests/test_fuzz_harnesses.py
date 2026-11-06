"""The fuzz harnesses (tests/fuzz) run on every push and every platform, without Atheris, so a harness that a
code change breaks fails here at once rather than in the weekly fuzzing job. Each target is run on its seeds and
on simple mutations of them: truncated, with bytes flipped, nested deeply and empty."""

import re
from pathlib import Path

import pytest

from .fuzz import harnesses, seeds

ROOT = Path(__file__).resolve().parent.parent


def _mutations(data: bytes) -> list[bytes]:
    flipped = bytes(b ^ 0x55 if i % 7 == 0 else b for i, b in enumerate(data[:4096]))
    return [data, data[: len(data) // 2], data[:1], flipped, b"", b"[" * 5000 + data, data + b"\xff\xfe"]


@pytest.mark.parametrize("name", sorted(harnesses.TARGETS))
def test_harness_runs_on_its_seeds_and_simple_mutations(name):
    target = harnesses.run(name)
    found = seeds.seeds(name)
    assert found, f"{name} has no seeds"
    for data in found:
        for m in _mutations(data):
            target(m)  # raises anything but the CLI's own errors


@pytest.mark.parametrize("name", sorted(harnesses.TARGETS))
def test_seeds_are_accepted_as_valid_input(name):
    """A seed that is itself refused would start the fuzzer at an error path."""
    for data in seeds.seeds(name):
        harnesses.TARGETS[name](data)


def test_every_target_is_fuzzed_in_ci():
    wf = ROOT / ".github" / "workflows" / "fuzz.yml"
    if not wf.exists():
        pytest.skip("workflows are not in the sdist")
    m = re.search(r"target:\s*\[([^\]]*)\]", wf.read_text(encoding="utf-8"))
    assert m, "fuzz.yml has no target matrix"
    assert sorted(t.strip() for t in m.group(1).split(",")) == sorted(harnesses.TARGETS)


def test_fuzz_workflow_is_pinned_and_read_only():
    from oss_intake.health import workflows
    from oss_intake.integrity import load_known_bad

    wf = ROOT / ".github" / "workflows" / "fuzz.yml"
    if not wf.exists():
        pytest.skip("workflows are not in the sdist")
    text = wf.read_text(encoding="utf-8")
    r = workflows.analyse("fuzz.yml", text, load_known_bad()["actions"])
    assert r["uses"] >= 3 and r["unpinned"] == [] and r["known_bad"] == []
    assert r["top_level_permissions"] and not r["write_all"] and not r["pull_request_target"]
    assert "contents: write" not in text and "secrets." not in text
    # The dispatch input reaches the shell through an environment variable and is checked as a number.
    uses_input = [ln.strip() for ln in text.splitlines() if "github.event.inputs" in ln]
    assert uses_input and all(ln.startswith("SECONDS_EACH:") for ln in uses_input)
