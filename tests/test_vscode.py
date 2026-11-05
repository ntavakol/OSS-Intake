"""VS Code extensions: recognising them, unpacking a .vsix safely, the indicators, the removal list, and the run
through the CLI. Every extension here is built by the test; nothing is downloaded or run."""

import json
import stat
import zipfile

import pytest

from oss_intake import cli, inputs, vscode

from .conftest import FakeHttp

AS_OF = "2026-10-22"
HIDDEN = "".join(chr(0xE0100 + i) for i in range(6))  # Unicode variation selectors, the GlassWorm way
BIDI = chr(0x202E)


def manifest(publisher="example", name="ext", version="1.2.3", **extra):
    return {"name": name, "publisher": publisher, "version": version, "engines": {"vscode": "^1.90.0"},
            "main": "./out/extension.js", **extra}


def make_vsix(path, files=None, pkg=None, vsixmanifest=None):
    """A .vsix as vsce writes it: extension.vsixmanifest at the top, the extension under extension/."""
    pkg = pkg or manifest()
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("extension/package.json", json.dumps(pkg, indent=2))
        ident = vsixmanifest or (pkg["publisher"], pkg["name"], pkg["version"])
        z.writestr("extension.vsixmanifest", f'<PackageManifest><Metadata><Identity Language="en-US" '
                                             f'Id="{ident[1]}" Version="{ident[2]}" Publisher="{ident[0]}" />'
                                             "</Metadata></PackageManifest>")
        for name, data in (files or {"extension/out/extension.js": "exports.activate = () => {};"}).items():
            z.writestr(name, data)
    return path


def make_folder(root, folder="example.ext-1.2.3", pkg=None, files=None):
    d = root / folder
    d.mkdir(parents=True)
    (d / "package.json").write_text(json.dumps(pkg or manifest(), indent=2), encoding="utf-8")
    for name, data in (files or {"out/extension.js": "exports.activate = () => {};"}).items():
        p = d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return d


# ------------------------------------------------------------------------------------------ what the input is

def test_recognised_by_content(tmp_path):
    vsix = make_vsix(tmp_path / "anything.zip")
    assert vscode.is_vsix(vsix) and inputs.classify(vsix) == "vscode"
    plain = tmp_path / "plain.zip"
    with zipfile.ZipFile(plain, "w") as z:
        z.writestr("package.json", "{}")
    assert inputs.classify(plain) == "artifact"
    one = make_folder(tmp_path / "exts")
    assert inputs.classify(one) == "vscode"
    make_folder(tmp_path / "exts", "other.thing-2.0.0", manifest("other", "thing", "2.0.0"))
    assert inputs.classify(tmp_path / "exts") == "vscode"  # a folder of installed extensions
    assert [p.name for p in vscode.extension_folders(tmp_path / "exts")] == ["example.ext-1.2.3",
                                                                             "other.thing-2.0.0"]
    node = tmp_path / "web"
    node.mkdir()
    (node / "package.json").write_text('{"name": "web", "version": "1.0.0"}', encoding="utf-8")
    assert inputs.classify(node) == "dir"  # an ordinary npm project is not an extension


# ------------------------------------------------------------------------------------------ unpacking

def _zip(path, members):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("extension/package.json", json.dumps(manifest()))
        for m in members:
            if isinstance(m, zipfile.ZipInfo):
                z.writestr(m, "x")
            else:
                z.writestr(m, "x")
    return path


@pytest.mark.parametrize("name", ["../evil.js", "extension/../../evil.js", "/etc/evil", "C:/evil.js",
                                  "extension\\..\\evil.js"])
def test_unpack_refuses_paths_that_leave_the_folder(tmp_path, name):
    vsix = _zip(tmp_path / "x.vsix", [name])
    with pytest.raises(inputs.InputError, match="refused"):
        vscode.unpack(vsix, tmp_path / "out")
    assert not (tmp_path / "evil.js").exists()


def test_unpack_refuses_links(tmp_path):
    link = zipfile.ZipInfo("extension/link")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    with pytest.raises(inputs.InputError, match="link"):
        vscode.unpack(_zip(tmp_path / "x.vsix", [link]), tmp_path / "out")


def test_unpack_limits(tmp_path, monkeypatch):
    vsix = make_vsix(tmp_path / "x.vsix", {f"extension/f{i}.js": "1" for i in range(10)})
    monkeypatch.setattr(vscode, "MAX_FILES", 5)
    with pytest.raises(inputs.InputError, match="more than 5"):
        vscode.unpack(vsix, tmp_path / "a")
    monkeypatch.setattr(vscode, "MAX_FILES", 50_000)
    big = make_vsix(tmp_path / "big.vsix", {"extension/big.js": "a" * 3_000_000})
    with pytest.raises(inputs.InputError, match="zip bomb"):  # 3 MB of one letter compresses far beyond 200:1
        vscode.unpack(big, tmp_path / "b")
    monkeypatch.setattr(vscode, "MAX_RATIO", 10**9)
    monkeypatch.setattr(vscode, "MAX_TOTAL_BYTES", 1_000_000)
    with pytest.raises(inputs.InputError, match="more than the limit"):
        vscode.unpack(big, tmp_path / "c")


def test_unpack_needs_an_extension(tmp_path):
    p = tmp_path / "x.vsix"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("extension/package.json", '{"name": "x"}')
    with pytest.raises(inputs.InputError, match="publisher and engines.vscode"):
        vscode.unpack(p, tmp_path / "out")


def test_planted_manifest_copy_is_replaced(tmp_path):
    """The .vsix cannot supply the file the manifest is copied to."""
    vsix = make_vsix(tmp_path / "x.vsix", {"extension/out/extension.js": "1",
                                            vscode.MANIFEST_COPY: '<Identity Id="ext" Version="1.2.3" '
                                                                  'Publisher="example" />'},
                     vsixmanifest=("other", "ext", "9.9.9"))
    folder = vscode.unpack(vsix, tmp_path / "out")
    kinds = {i["id"] for i in vscode.analyse(folder)["indicators"]}
    assert "identity" in kinds


# ------------------------------------------------------------------------------------------ indicators

def test_indicators_with_file_and_line(tmp_path):
    code = "\n".join(["const cp = require('child_process');", "eval(atob(x));", "const p = new Function('a', b);",
                      f"const s = '{HIDDEN}';", f"// {BIDI} reordered", "fetch('https://collect.example.net/x');",
                      "const blob = '" + "QUJD" * 600 + "';"])
    d = make_folder(tmp_path, pkg=manifest(activationEvents=["*", "onStartupFinished"],
                                           extensionDependencies=["other.dep"]),
                    files={"out/extension.js": code, "bin/helper": b"\x7fELF\x02\x01" + b"\0" * 20,
                           "native/addon.node": b"\0"})
    e = vscode.analyse(d)
    got = {i["id"]: i["seen"] for i in e["indicators"]}
    assert set(got) == {"activation-all", "activation-startup", "installs", "process", "eval", "invisible", "bidi",
                        "blob", "native"}
    assert got["process"][0] == {"file": "out/extension.js", "line": 1, "detail": "child_process"}
    assert [s["line"] for s in got["eval"]] == [2, 3]
    assert got["invisible"][0]["line"] == 4 and got["bidi"][0]["line"] == 5 and got["blob"][0]["line"] == 7
    assert {s["file"] for s in got["native"]} == {"bin/helper", "native/addon.node"}
    assert got["installs"][0]["detail"] == "extensionDependencies: other.dep"
    assert e["hosts"] == ["collect.example.net"]
    assert (e["id"], e["version"]) == ("example.ext", "1.2.3")


def test_ordinary_code_raises_nothing(tmp_path):
    """Emoji (one variation selector), a method called eval, and a dependency starting programs are not flagged."""
    code = f"const ok = 'thumbs {chr(0x1F44D)}{chr(0xFE0F)}'; model.eval(x); exports.activate = () => {{}};"
    d = make_folder(tmp_path, pkg=manifest(activationEvents=["onLanguage:python"]),
                    files={"out/extension.js": code,
                           "node_modules/dep/index.js": "require('child_process').exec('x'); eval(y);"})
    e = vscode.analyse(d)
    assert e["indicators"] == [] and e["dependencies_visible"] and not e["bundled"]


def test_native_files_in_dependencies_are_flagged(tmp_path):
    d = make_folder(tmp_path, files={"out/extension.js": "1", "node_modules/dep/build/addon.node": b"\0"})
    assert [s["file"] for i in vscode.analyse(d)["indicators"] for s in i["seen"]] == [
        "node_modules/dep/build/addon.node"]


def test_bundled_code_hides_dependencies(tmp_path):
    d = make_folder(tmp_path, files={"out/extension.js": "x" * vscode.BUNDLE_BYTES})
    e = vscode.analyse(d)
    assert e["bundled"] and not e["dependencies_visible"]
    alerts, other = vscode.warnings({"extensions": [{**e, "removed": None, "malicious": False}],
                                     "removed_list": {"status": "checked", "detail": "", "source": "", "entries": 1}})
    assert alerts == [] and any("cannot see its dependencies" in w for w in other)


def test_folder_name_must_match(tmp_path):
    d = make_folder(tmp_path, folder="ms-python.python-2024.1.0", pkg=manifest("evil", "python", "2024.1.0"))
    (seen,) = [i["seen"] for i in vscode.analyse(d)["indicators"] if i["id"] == "identity"]
    assert "package.json says evil.python 2024.1.0" in seen[0]["detail"]
    ok = make_folder(tmp_path, folder="example.ext-1.2.3-darwin-arm64")
    assert vscode.analyse(ok)["indicators"] == []


def test_links_are_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.js").write_text("require('child_process')", encoding="utf-8")
    d = make_folder(tmp_path / "exts")
    try:
        (d / "linked").symlink_to(outside, target_is_directory=True)
        (d / "link.js").symlink_to(outside / "secret.js")
    except OSError:
        pytest.skip("no symbolic links here")
    assert vscode.analyse(d)["indicators"] == []


def test_reading_limit_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(vscode, "READ_FILE_BYTES", 5)
    e = vscode.analyse(make_folder(tmp_path))
    assert sorted(e["not_read"]) == ["out/extension.js", "package.json"] and e["not_read_total"] == 2


@pytest.mark.parametrize("url,repo", [("https://github.com/owner/app.git", "owner/app"),
                                      ("git+https://github.com/owner/app", "owner/app"),
                                      ("git@github.com:owner/app.git", "owner/app"), ("owner/app", "owner/app"),
                                      ("https://gitlab.com/owner/app", ""), ("", "")])
def test_github_repo(url, repo):
    assert vscode.github_repo(url) == repo


# ------------------------------------------------------------------------------------------ removal list

def test_removal_list(fixtures):
    listed = vscode.parse_removed((fixtures / "vscode_removed.md").read_text(encoding="utf-8"))
    assert len(listed) == 124
    assert listed["badpub.stealer"] == {"id": "BadPub.Stealer", "date": "11/4/2099", "type": "Potentially malicious"}
    assert [vscode.is_malicious(listed[k]) for k in ("badpub.evil-theme", "badpub.stealer", "copycat.prettier-copy",
                                                     "spammy.ext")] == [True, True, False, True]


def test_removal_list_that_cannot_be_read_is_not_checked():
    class Short(FakeHttp):
        def get_text(self, url):
            return 200, "| a.b | 1/1/2099 | Malware |"

    listed, why = vscode.load_removed(Short())
    assert listed is None and "could not be read" in why
    assert vscode.load_removed(None) == (None, "not checked (--offline)")


# ------------------------------------------------------------------------------------------ through the CLI

def scan(tmp_path, fixtures, target, http, *extra):
    out = tmp_path / "reports"
    argv = ["--path", str(target), "--out", str(out), "--from-trivy-json", str(fixtures / "trivy.json"),
            "--from-grype-json", str(fixtures / "grype.json"), "--as-of", AS_OF, *extra]
    return cli.main(argv, http=http), out


def test_removed_malware_leads_the_report_and_fails_the_gate(tmp_path, fixtures, capsys):
    vsix = make_vsix(tmp_path / "evil.vsix", pkg=manifest("badpub", "evil-theme", "0.0.1"))
    code, out = scan(tmp_path, fixtures, vsix, FakeHttp(), "--fail-on", "malicious")
    assert code == cli.EXIT_THRESHOLD
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert a["inputs"]["path_kind"] == "vscode"
    (e,) = a["extensions"]["extensions"]
    assert e["malicious"] and e["removed"]["type"] == "Malware"
    assert a["warnings"][0].startswith("EXTENSION REMOVED FROM THE VS CODE MARKETPLACE AS MALWARE: badpub.evil-theme")
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "VS Code extensions (1)" in html and "REMOVED as Malware" in html
    assert "VS Code extensions (1)" in (out / "summary.md").read_text(encoding="utf-8")


def test_impersonation_is_a_warning_not_a_gate(tmp_path, fixtures):
    vsix = make_vsix(tmp_path / "copy.vsix", pkg=manifest("copycat", "prettier-copy", "1.0.0"))
    code, out = scan(tmp_path, fixtures, vsix, FakeHttp(), "--fail-on", "malicious")
    assert code == cli.EXIT_OK
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert any("removed from the VS Code Marketplace for Impersonation" in w for w in a["warnings"])
    assert not a["warnings"][0].startswith("EXTENSION REMOVED")


def test_installed_extensions_folder(tmp_path, fixtures):
    root = tmp_path / "extensions"
    make_folder(root)
    make_folder(root, "badpub.stealer-2.0.0", manifest("BadPub", "Stealer", "2.0.0"))
    code, out = scan(tmp_path, fixtures, root, FakeHttp())
    assert code == cli.EXIT_OK
    exts = json.loads((out / "assessment.json").read_text(encoding="utf-8"))["extensions"]["extensions"]
    assert [(e["id"], e["malicious"]) for e in exts] == [("BadPub.Stealer", True), ("example.ext", False)]


def test_list_unavailable_fails_the_gate_rather_than_passing(tmp_path, fixtures, capsys):
    vsix = make_vsix(tmp_path / "ok.vsix")
    code, out = scan(tmp_path, fixtures, vsix, FakeHttp(fail_hosts=("raw.githubusercontent.com/microsoft",)),
                     "--fail-on", "malicious")
    assert code == cli.EXIT_ERROR
    assert "removal list was not checked" in capsys.readouterr().err
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert a["extensions"]["removed_list"]["status"] == "not_checked"


def test_offline_says_the_list_was_not_checked(tmp_path, fixtures):
    code, out = scan(tmp_path, fixtures, make_vsix(tmp_path / "ok.vsix"), None, "--offline")
    assert code == cli.EXIT_OK
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert any("removal list was not checked (--offline)" in w for w in a["warnings"])


def test_hostile_vsix_is_refused_before_anything_is_written(tmp_path, fixtures, capsys):
    vsix = _zip(tmp_path / "evil.vsix", ["../evil.js"])
    code, out = scan(tmp_path, fixtures, vsix, FakeHttp())
    assert code == cli.EXIT_USAGE and not out.exists()
    assert "refused" in capsys.readouterr().err


def test_mismatch_gate_is_refused_for_an_extension(tmp_path, fixtures):
    code, _ = scan(tmp_path, fixtures, make_vsix(tmp_path / "ok.vsix"), FakeHttp(), "--fail-on", "mismatch")
    assert code == cli.EXIT_USAGE
