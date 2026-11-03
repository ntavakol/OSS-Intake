"""The command builder (site/builder/) against the real CLI.

options.json is generated from the parser; rules.json and ui-groups.json are maintained by hand. These tests make
sure all three agree with oss_intake.cli, and that every command in tests/fixtures/builder_golden.json (the
commands builder.js must produce, checked by tests/builder/*.test.mjs under Node) is valid CLI input.
"""

from __future__ import annotations

import importlib.util
import json
import re
import shlex
from pathlib import Path

import pytest

from oss_intake import __version__, cli

ROOT = Path(__file__).resolve().parent.parent
BUILDER = ROOT / "site" / "builder"
pytestmark = pytest.mark.skipif(not BUILDER.is_dir(), reason="the site is not in the sdist")

# Options whose name suggests a secret would need a reviewed decision: the builder must never offer a field for
# a secret (a link would carry it), and should point to an environment variable instead. None exist today.
SECRET_WORDS = re.compile(r"token|key|secret|password|passwd|credential", re.I)
SECRET_ALLOW: set[str] = set()


def _load(name: str):
    return json.loads((BUILDER / name).read_text(encoding="utf-8"))


def _export_module():
    spec = importlib.util.spec_from_file_location("export_options", ROOT / "scripts" / "export_options.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_options_json_is_current():
    """Rerun `python scripts/export_options.py` after changing any CLI option."""
    assert _export_module().main(["--check"]) == 0


def test_options_cover_every_cli_option():
    import argparse

    data = _load("options.json")
    assert data["version"] == __version__
    parser = cli.build_parser()
    sub = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    for name, sp in sub.choices.items():
        want = {a.dest for a in sp._actions if not isinstance(a, argparse._HelpAction)}
        have = {o["dest"] for o in data["commands"][name]["options"]}
        assert have == want, name


def test_every_option_is_placed_in_a_group():
    data, groups = _load("options.json"), _load("ui-groups.json")
    for name, cmd in data["commands"].items():
        placed = [d for g in groups["commands"][name]["groups"] for d in g["options"]]
        assert sorted(placed) == sorted(o["dest"] for o in cmd["options"]), f"{name}: add or remove in ui-groups.json"
        assert len(placed) == len(set(placed)), f"{name}: an option is in two groups"


def test_presets_use_real_options_and_valid_values():
    data, groups = _load("options.json"), _load("ui-groups.json")
    for preset in groups["presets"]:
        opts = {o["dest"]: o for o in data["commands"][preset["command"]]["options"]}
        assert preset["values"] and set(preset["values"]) <= set(opts), preset["name"]
        cli.build_parser().parse_args([preset["command"], *_args(opts, preset["values"])])


def test_no_option_takes_a_secret():
    for name, cmd in _load("options.json")["commands"].items():
        for o in cmd["options"]:
            if SECRET_WORDS.search(o["dest"]):
                assert f"{name}.{o['dest']}" in SECRET_ALLOW, f"{o['flag']} looks like a secret: see SECRET_ALLOW"


def _args(opts: dict, values: dict) -> list[str]:
    """A preset's values as argv, in the simplest form (the golden tests check the builder's own output)."""
    out: list[str] = []
    for dest, v in values.items():
        o = opts[dest]
        if o["kind"] == "flag":
            out.append(o["flag"])
        elif o["kind"] == "repeatable":
            out += [f"{o['flag']}={x}" for x in v]
        else:
            out.append(f"{o['flag']}={v}")
    return out


def _run(argv: list[str], tmp_path: Path, capsys) -> tuple[int, str]:
    f = tmp_path / "exists.json"
    f.write_text("{}", encoding="utf-8")
    argv = [a.replace("{out}", str(tmp_path / "out")).replace("{file}", str(f)) for a in argv]
    from .conftest import FakeHttp

    code = cli.main(argv, http=FakeHttp())
    return code, capsys.readouterr().err


@pytest.mark.parametrize("rule", _load("rules.json")["rules"] if BUILDER.is_dir() else [], ids=lambda r: r["id"])
def test_each_rule_is_what_the_cli_refuses(rule, tmp_path, capsys):
    """Each rule's example is refused by the CLI before any work (exit 2), with the rule's message."""
    from .conftest import FakeHttp

    http = FakeHttp()
    argv = [a.replace("{out}", str(tmp_path / "out")) for a in rule["args"]]
    f = tmp_path / "exists.json"
    f.write_text("{}", encoding="utf-8")
    argv = [a.replace("{file}", str(f)) for a in argv]
    code = cli.main([rule["command"], *argv], http=http)
    err = capsys.readouterr().err
    assert code == cli.EXIT_USAGE and rule["message"] in err, err
    assert http.calls == []


@pytest.mark.parametrize("rule", _load("rules.json")["rules"] if BUILDER.is_dir() else [], ids=lambda r: r["id"])
def test_each_rule_stays_quiet_where_the_cli_accepts(rule, tmp_path, capsys, monkeypatch):
    """The nearest command the CLI accepts (ok_args) must not get the rule's message: a rule that fired there
    would stop the builder from copying a valid command. The run may still fail later (no scanner installed, or
    the stand-in network), which is not what this checks."""
    from .conftest import FakeHttp

    f = tmp_path / "exists.json"
    f.write_text("{}", encoding="utf-8")
    argv = [a.replace("{out}", str(tmp_path / "out")).replace("{file}", str(f)) for a in rule["ok_args"]]
    monkeypatch.setattr(cli, "find_executable", lambda *a, **k: (_ for _ in ()).throw(cli.ScannerError("stop")))
    try:
        cli.main([rule["command"], *argv], http=FakeHttp())
    except Exception:  # noqa: BLE001, S110 - anything after validation is past what this test is about
        pass
    assert rule["message"] not in capsys.readouterr().err


def _fields():
    return _load("rules.json")["fields"] if BUILDER.is_dir() else []


def _field_argv(field: dict, value: str) -> list[str]:
    flag = "--" + field["dest"].replace("_", "-")
    if field["command"] == "verify":
        return ["verify", "--file", "{file}", f"{flag}={value}"]
    base = [] if field["dest"] in ("image", "package") else ["--image", "owner/app:1.0"]
    return [field["command"], *base, f"{flag}={value}", "--out", "{out}"]


@pytest.mark.parametrize("field", _fields(), ids=lambda f: f"{f['dest']}:{f['message'][:20]}")
def test_field_checks_match_the_cli(field, tmp_path, capsys):
    """Each field check's invalid examples are refused by the CLI with its message (exit 2), and its valid
    examples are accepted by the CLI's own validator for that option."""
    for value in field["invalid"]:
        code, err = _run(_field_argv(field, value), tmp_path, capsys)
        assert code == cli.EXIT_USAGE and field["message"] in err, (value, err)
    for value in field["valid"]:
        dest = field["dest"]
        if dest == "image":
            cli.validate_image(value)
        elif dest == "repo":
            cli.validate_repo(value)
        elif field.get("date"):
            cli.validate_date(value, dest)
        elif "list_of" in field:
            if value != "auto":
                cli.csv_set(value, set(field["list_of"]) - {"auto"}, dest)
        elif dest.endswith("sha256") or dest == "sha256":
            from oss_intake import integrity

            integrity.normalise_hash(value)
        elif dest == "label":
            cli._labels([value])
        elif dest == "package":
            from oss_intake import inputs

            inputs.packages([value])
        else:
            pytest.fail(f"no validator for {dest}: add one here")


def test_list_checks_match_the_cli_lists():
    from oss_intake import inputs, inventory_report

    fields = _load("rules.json")["fields"]
    reserved = next(f["not_keys"] for f in fields if "not_keys" in f)
    assert set(reserved) == set(inputs.INVENTORY_KEYS) | set(inventory_report.BASE_FIELDS) | {
        "labels", "compare_version", "upgrade_version"}  # as cli._labels refuses them
    lists = {f["dest"]: set(f["list_of"]) for f in fields if "list_of" in f}
    assert lists["fail_on"] == set(cli.FAIL_ON)
    assert lists["formats"] == cli._FORMATS
    assert lists["scanners"] == cli._SCANNERS | {"auto"}


def test_golden_commands_are_valid_cli_input():
    """The commands builder.js must produce (tests/builder) parse, and the bash form splits into the same argv."""
    cases = json.loads((ROOT / "tests" / "fixtures" / "builder_golden.json").read_text(encoding="utf-8"))["cases"]
    assert cases
    for case in cases:
        if case.get("invalid"):
            continue
        argv = case["args"]
        cmd = argv if argv[:1] and argv[0] in ("verify", "doctor") else ["scan", *argv]
        cli.build_parser().parse_args(cmd)
        assert shlex.split(case["bash"]) == ["oss-intake", *argv], case["name"]


def test_site_is_published_from_release_tags():
    """The builder's options must match what is on PyPI, so the site is published from a release tag, and
    pages.yml refuses a tag that options.json was not generated for."""
    from oss_intake import integrity
    from oss_intake.health import workflows as wf

    path = ROOT / ".github" / "workflows" / "pages.yml"
    if not path.exists():
        pytest.skip("workflows are not in the sdist")
    text = path.read_text(encoding="utf-8")
    res = wf.analyse("pages.yml", text, integrity.load_known_bad()["actions"])
    assert res["unpinned"] == [] and res["known_bad"] == [] and not res["write_all"]
    assert "release:" in text and "push:" not in text
    assert "ref: ${{ github.event.release.tag_name || inputs.tag }}" in text
    assert "site/builder/options.json is for" in text


def test_page_loads_no_third_party_code():
    """No CDN, no inline script or style, no innerHTML: the Content Security Policy and the code agree."""
    html = (BUILDER / "index.html").read_text(encoding="utf-8")
    assert "script-src 'self'" in html and "unsafe-inline" not in html and "unsafe-eval" not in html
    assert not re.search(r"<script(?![^>]*\bsrc=)", html) and "<style" not in html and " style=" not in html
    assert not re.search(r"https?://(?!github\.com/ntavakol/)", html.replace("http-equiv", ""))
    for js in BUILDER.glob("*.js"):
        code = js.read_text(encoding="utf-8")
        for bad in ("innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "new Function", "document.write"):
            assert bad not in code, f"{js.name}: {bad}"
        assert not re.search(r"""(?:import|fetch)\s*\(?\s*["']https?:""", code), js.name


@pytest.mark.parametrize("kwargs", [{"nargs": 2}, {"action": "store_const", "const": 5}, {"action": "count"},
                                    {"action": "append", "type": int}, {"type": float}])
def test_export_refuses_an_option_kind_it_does_not_know(kwargs):
    """A new kind of option must stop the export, not be offered as a plain text field."""
    import argparse

    action = argparse.ArgumentParser().add_argument("--x", **kwargs)
    with pytest.raises(SystemExit, match="not supported"):
        _export_module()._kind(action)
