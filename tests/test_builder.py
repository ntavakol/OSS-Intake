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

from oss_intake import __version__, cli, scanning

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
    monkeypatch.setattr(scanning, "find_executable", lambda *a, **k: (_ for _ in ()).throw(cli.ScannerError("stop")))
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


# ---------------------------------------------------------------- the guided wizard (wizard.json)

def _wizard_offers(wiz: dict, target: dict) -> list[str]:
    """As wizard.js offered(): the target's fields, its GitHub project, the output folder and the gates."""
    out = [*target["fields"], *(["repo"] if target["repo"] else []), "out"]
    return out + (["fail_on"] if target["gates"] else []) + ["fail_on_likelihood"]


def test_wizard_offers_real_options_and_the_clis_gates():
    wiz, scan = _load("wizard.json"), _load("options.json")["commands"]["scan"]
    dests = {o["dest"] for o in scan["options"]}
    assert set(wiz["fields"]) <= dests
    for t in wiz["targets"]:
        assert set(_wizard_offers(wiz, t)) <= dests, t["id"]
        assert set(_wizard_offers(wiz, t)) - {"fail_on"} <= set(wiz["fields"]), f"{t['id']}: give it a wizard label"
        assert set(t["gates"]) <= set(cli.FAIL_ON), t["id"]
    assert [g["id"] for g in wiz["gates"]] == list(cli.FAIL_ON), "one wizard gate per --fail-on value, in order"


def _refers(cond) -> set[str]:
    """The options a condition looks at (not the "what" answer)."""
    op, arg = next(iter(cond.items()))
    if op in ("all", "any"):
        return set().union(*(_refers(c) for c in arg))
    if op == "not":
        return _refers(arg)
    if op == "set":
        return {arg}
    if op == "none":
        return set(arg)
    return set() if op == "what" else {arg[0]}


def test_every_option_the_wizard_offers_has_a_summary_line():
    """'What this command will do' must say something for each option the wizard offers, so it cannot fall
    behind what the wizard sets: a summary line looks at the option or shows its value."""
    wiz = _load("wizard.json")
    offered = {d for t in wiz["targets"] for d in _wizard_offers(wiz, t)}
    for dest in sorted(offered):
        said = (dest in _refers(line["when"]) or "{" + dest + "}" in line["text"] for line in wiz["summary"])
        assert any(said), dest


def test_wizard_knows_the_lockfile_names():
    """kindOf reads a file name as the CLI does (inputs.classify)."""
    from oss_intake import inputs

    assert _load("wizard.json")["lockfile_names"] == inputs.LOCKFILES.pattern


def _wizard(key: str) -> list:
    return _load("wizard.json")[key] if BUILDER.is_dir() else []


def _kind_files(tmp_path: Path) -> dict[str, str]:
    lock = tmp_path / "package-lock.json"
    lock.write_text(FILES["package-lock.json"], encoding="utf-8")
    csv_ = tmp_path / "packages.csv"
    csv_.write_text("ecosystem,name,version\nnpm,chalk,5.6.1\n", encoding="utf-8")
    renv = tmp_path / "renv.lock"
    renv.write_text(json.dumps({"R": {"Version": "4.4.1"}, "Packages": {"jsonlite": {
        "Package": "jsonlite", "Version": "1.8.0", "Source": "Repository", "Repository": "CRAN"}}}), encoding="utf-8")
    jar = tmp_path / "app.jar"
    jar.write_bytes(b"PK\x05\x06" + b"\x00" * 18)  # an empty zip
    return {"{lockfile}": str(lock), "{csv}": str(csv_), "{renv}": str(renv), "{jar}": str(jar),
            "{out}": str(tmp_path / "out")}


@pytest.mark.parametrize("rule", _wizard("kind_rules"), ids=lambda r: r["id"])
def test_each_kind_rule_is_what_the_cli_refuses(rule, tmp_path, capsys, monkeypatch):
    """The checks the wizard makes from the kind of file: its example is refused by the CLI (exit 2, with the
    message), and its ok_args are not refused with that message."""
    from .conftest import FakeHttp

    names = _kind_files(tmp_path)
    for args in [rule["args"], *rule.get("more_args", [])]:
        http = FakeHttp()
        code = cli.main([names.get(a, a) for a in args], http=http)
        err = capsys.readouterr().err
        assert code == cli.EXIT_USAGE and rule["message"] in err, (args, err)
        assert http.calls == []
    monkeypatch.setattr(scanning, "find_executable", lambda *a, **k: (_ for _ in ()).throw(cli.ScannerError("stop")))
    for args in [rule["ok_args"], *rule.get("more_ok_args", [])]:
        cli.main([names.get(a, a) for a in args], http=FakeHttp())
        assert rule["message"] not in capsys.readouterr().err, args


def test_wizard_services_are_every_host_the_code_calls():
    """The summary's 'Contacts' list names every service oss-intake calls: each host in a module-level URL
    constant in src/ must be in wizard.json's services, and each listed host must be one the code calls."""
    hosts = set()
    for py in (ROOT / "src" / "oss_intake").rglob("*.py"):
        for m in re.finditer(r'^[A-Z_]+ = f?"https://([^/"{]+)', py.read_text(encoding="utf-8"), re.M):
            hosts.add(m.group(1))
    listed = {h for s in _load("wizard.json")["services"] for h in s["hosts"]}
    assert hosts == listed


# Files the wizard's golden commands name, created in tmp_path for the run.
FILES = {
    "package-lock.json": '{"lockfileVersion": 3, "packages": {"": {"name": "x"}}}',
    "sbom.cdx.json": json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        {"type": "library", "name": "chalk", "version": "5.6.1", "purl": "pkg:npm/chalk@5.6.1"}]}),
}


def _wizard_cases():
    path = ROOT / "tests" / "fixtures" / "wizard_golden.json"
    return json.loads(path.read_text(encoding="utf-8"))["cases"] if path.exists() else []


@pytest.mark.parametrize("case", _wizard_cases(), ids=lambda c: c["name"])
def test_wizard_commands_are_accepted_by_the_cli(case, tmp_path, capsys, monkeypatch):
    """Each command the wizard builds (checked under Node) gets past the CLI's own checks: it parses, and the
    run does not stop with a usage error. The file it names is created first; no scanner is run."""
    from .conftest import FakeHttp

    argv = shlex.split(case["bash"])[1:]
    cli.build_parser().parse_args(["scan", *argv])
    monkeypatch.chdir(tmp_path)
    path = case["values"].get("path")
    if path:  # the shell would expand ~; here the file is in tmp_path
        p = tmp_path / Path(path).name
        p.write_text(FILES.get(p.name, "x"), encoding="utf-8")
        argv = [str(p) if a == path else a for a in argv]
    # No scanner is run: finding one stops the run with a runtime error (exit 1), after every usage check.
    monkeypatch.setattr(scanning, "find_executable", lambda *a, **k: (_ for _ in ()).throw(cli.ScannerError("stop")))
    code = cli.main(argv, http=FakeHttp())
    assert code in (cli.EXIT_OK, cli.EXIT_ERROR, cli.EXIT_THRESHOLD), capsys.readouterr().err


@pytest.mark.parametrize("rule", _wizard("kind_cautions"), ids=lambda r: r["id"])
def test_each_kind_caution_is_a_gate_that_can_only_fail(rule, tmp_path, capsys):
    """A gate the wizard refuses for a kind of file: the CLI accepts it, but its check never runs for that kind,
    so the run always ends with exit 1."""
    from .conftest import FakeHttp

    names = _kind_files(tmp_path)
    code = cli.main([names.get(a, a) for a in rule["args"]], http=FakeHttp())
    err = capsys.readouterr().err
    assert code == cli.EXIT_ERROR and rule["cli_says"] in err, err


def test_admin_guide_commands_parse():
    """Every command in docs/admin-guide.md is one the CLI's parser accepts (the Node tests check each one is
    what the builder makes from the link above it)."""
    path = ROOT / "docs" / "admin-guide.md"
    if not path.exists():
        pytest.skip("docs are not in the sdist")
    commands = re.findall(r"^```bash\n(oss-intake [^\n]+)\n```", path.read_text(encoding="utf-8"), re.M)
    assert len(commands) >= 8
    for c in commands:
        cli.build_parser().parse_args(["scan", *shlex.split(c)[1:]])


def test_paste_box_results_are_valid_cli_input():
    """Every package, image and repository the builder's paste box produces (tests/fixtures/detect_cases.json,
    checked against detect.js under Node) is accepted by the CLI's own validation."""
    from oss_intake import inputs

    path = ROOT / "tests" / "fixtures" / "detect_cases.json"
    cases = json.loads(path.read_text(encoding="utf-8"))["cases"]
    ready = [c for c in cases if c["status"] == "ok"]
    ready += [x for c in cases for x in c.get("choices", []) if x["status"] == "ok"]
    assert len(ready) >= 30
    for r in ready:
        v = r["values"]
        if "package" in v:
            inputs.packages(v["package"])
        if "image" in v:
            cli.validate_image(v["image"])
        if "repo" in v:
            cli.validate_repo(v["repo"])


def test_paste_box_knows_the_clis_ecosystems():
    from oss_intake import inputs

    assert _load("wizard.json")["ecosystems"] == inputs.ECOSYSTEMS


def test_paste_box_uses_the_clis_version_rule():
    """The paste box refuses what --package refuses as not one version (ranges, placeholders, latest)."""
    from oss_intake import inputs

    assert _load("wizard.json")["version_not_allowed"] == inputs._NOT_A_VERSION.pattern
    assert inputs._NOT_A_VERSION.flags & re.IGNORECASE
