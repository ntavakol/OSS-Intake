"""VS Code extensions: recognising them, unpacking a .vsix safely, the indicators, the removal list, and the run
through the CLI. Every extension here is built by the test; nothing is downloaded or run."""

import json
import stat
import time
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
                                  "extension\\..\\evil.js", "extension/D:/evil.js", "extension/C:evil.js",
                                  "extension/a./b.js", "extension/a /b.js", "extension/con.txt", "extension/./a.js",
                                  "extension//a.js", "extension/\x01.js", "extension/LPT1"])
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


def test_unpack_refuses_names_that_collide_without_case(tmp_path):
    """On macOS and Windows these are one file, and which one wins depends on the order: refused outright."""
    p = tmp_path / "x.vsix"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("extension/package.json", json.dumps(manifest("badpub", "evil-theme", "0.0.1")))
        z.writestr("EXTENSION/package.json", json.dumps(manifest()))
    with pytest.raises(inputs.InputError, match="same file on macOS or Windows"):
        vscode.unpack(p, tmp_path / "out")


@pytest.mark.parametrize("damage", ["crc", "encrypted", "method"])
def test_damaged_archives_are_refused_not_crashed(tmp_path, damage):
    p = make_vsix(tmp_path / "x.vsix", {"extension/out/extension.js": "exports.a = 1;" * 50})
    data = bytearray(p.read_bytes())
    if damage == "crc":  # corrupt the compressed bytes just after the member's local header
        data[data.find(b"extension/out/extension.js") + 40] ^= 0xFF
    else:
        # zipfile reads the flags and the method from the central directory entry, which ends the file.
        at = data.rfind(b"PK\x01\x02", 0, data.rfind(b"extension/out/extension.js"))
        if damage == "encrypted":
            data[at + 8] |= 0x01  # general purpose flag: encrypted
        else:
            data[at + 10] = 99  # compression method 99 (AES), which zipfile cannot read
    p.write_bytes(bytes(data))
    with pytest.raises(inputs.InputError, match="refused|cannot|no extension"):
        vscode.unpack(p, tmp_path / "out")


def test_deeply_nested_package_json_is_not_an_extension(tmp_path):
    d = tmp_path / "x"
    d.mkdir()
    (d / "package.json").write_text("[" * 100_000, encoding="utf-8")
    assert vscode.extension_folders(d) == [] and inputs.classify(d) == "dir"


def test_planted_manifest_copy_is_ignored(tmp_path):
    """A .vsix without a manifest cannot supply the copy oss-intake keeps: the planted one is removed."""
    p = tmp_path / "x.vsix"
    with zipfile.ZipFile(p, "w") as z:
        z.writestr("extension/package.json", json.dumps(manifest()))
        z.writestr(vscode.MANIFEST_COPY, '<Identity Id="other" Version="9" Publisher="someone" />')
    stage = tmp_path / "stage"
    vscode.unpack(p, stage / "x")
    (e,) = vscode.assess(stage, None, staged=True)["extensions"]
    assert e["indicators"] == []


def test_vsix_manifest_must_agree(tmp_path):
    p = make_vsix(tmp_path / "x.vsix", vsixmanifest=("other", "ext", "9.9.9"))
    stage = tmp_path / "stage"
    vscode.unpack(p, stage / "x")
    (e,) = vscode.assess(stage, None, staged=True)["extensions"]
    assert [i["id"] for i in e["indicators"]] == ["identity"]
    assert "other.ext" in e["ids_checked"]


def test_a_folder_named_extension_is_not_taken_for_the_extension(tmp_path):
    """Only an unpacked .vsix is read as <name>/extension: in a folder the user gives, a decoy extension/ folder
    must not replace the real extension (or hide the others)."""
    root = tmp_path / "exts"
    evil = make_folder(root, "badpub.evil-theme-0.0.1", manifest("badpub", "evil-theme", "0.0.1"))
    make_folder(evil, "extension", manifest("ms-python", "python", "2024.1.0"))
    make_folder(root, "example.good-1.0.0", manifest("example", "good", "1.0.0"))
    ids = [e["id"] for e in vscode.assess(root, None)["extensions"]]
    assert ids == ["badpub.evil-theme", "example.good"]
    assert [e["id"] for e in vscode.assess(evil, None)["extensions"]] == ["badpub.evil-theme"]


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


@pytest.mark.parametrize("main,path", [("./out/main.txt", "out/main.txt"), ("./out/extension", "out/extension"),
                                       ("./out/node_modules/core/index.js", "out/node_modules/core/index.js")])
def test_own_code_is_read_whatever_it_is_called(tmp_path, main, path):
    """Node loads a file of any name as JavaScript, and a node_modules folder inside the extension's own code is
    still its own code."""
    d = make_folder(tmp_path, pkg=manifest(main=main), files={path: "require('child_process'); eval(x);"})
    assert {i["id"] for i in vscode.analyse(d)["indicators"]} == {"process", "eval"}


def test_text_files_of_any_name_are_read(tmp_path):
    d = make_folder(tmp_path, files={"out/extension.js": "1", "out/payload.dat": "A" * 3000})
    assert [i["id"] for i in vscode.analyse(d)["indicators"]] == ["blob"]


def test_ordinary_code_raises_nothing(tmp_path):
    """Emoji (one variation selector), a method called eval, and a dependency starting programs are not flagged."""
    code = f"const ok = 'thumbs {chr(0x1F44D)}{chr(0xFE0F)}'; model.eval(x); exports.activate = () => {{}};"
    d = make_folder(tmp_path, pkg=manifest(activationEvents=["onLanguage:python"]),
                    files={"out/extension.js": code,
                           "node_modules/dep/index.js": "require('child_process').exec('x'); eval(y);"})
    e = vscode.analyse(d)
    assert e["indicators"] == [] and e["dependencies_visible"] and not e["bundled"]


def test_emoji_flags_variants_and_data_uris_raise_nothing(tmp_path):
    england = chr(0x1F3F4) + "".join(chr(0xE0000 + ord(c)) for c in "gbeng") + chr(0xE007F)
    cjk = chr(0x845B) + chr(0xE0100)  # an ideographic variation sequence
    font = "url(data:font/woff2;base64," + "A" * 5000 + ")"
    d = make_folder(tmp_path, files={"out/extension.js": f"const a = '{england}', b = '{cjk}'; const c = '{font}';"})
    assert vscode.analyse(d)["indicators"] == []
    d2 = make_folder(tmp_path, "example.ext-2.0.0", manifest(version="2.0.0"),
                     files={"out/extension.js": "x = '" + "".join(chr(0xE0000 + ord(c)) for c in "hidden") + "'"})
    assert [i["id"] for i in vscode.analyse(d2)["indicators"]] == ["invisible"]


def test_reading_time_is_linear_on_crafted_text(tmp_path):
    """Runs of the base64 alphabet just short of a blob, and many blobs, must not make the reading slow (it is
    compared with ordinary code of the same size, not with a fixed time)."""
    size = 1_000_000
    crafted = ("A" * 1999 + "!") * (size // 2000) + ("B" * 2001 + "\n") * 200
    ordinary = ("const value = compute(a, b) + 1;\n" * (size // 34))
    timings = []
    for i, text in enumerate((ordinary, crafted)):
        d = make_folder(tmp_path, f"example.ext{i}-1.2.3", manifest(name=f"ext{i}"), files={"out/extension.js": text})
        start = time.perf_counter()
        vscode.analyse(d)
        timings.append(time.perf_counter() - start)
    assert timings[1] < 20 * max(timings[0], 0.02), timings


def test_native_files_in_dependencies_are_flagged(tmp_path):
    d = make_folder(tmp_path, files={"out/extension.js": "1", "node_modules/dep/build/addon.node": b"\0"})
    assert [s["file"] for i in vscode.analyse(d)["indicators"] for s in i["seen"]] == [
        "node_modules/dep/build/addon.node"]


def test_an_empty_node_modules_does_not_make_a_bundle_visible(tmp_path):
    d = make_folder(tmp_path, files={"out/extension.js": "x" * vscode.BUNDLE_BYTES, "node_modules/.keep": ""})
    assert vscode.analyse(d)["bundled"]


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
    for name in ("vscode-3d-viewer", "ext-2fa", "language-x86-64-assembly"):
        d = make_folder(tmp_path, folder=f"example.{name}-1.0.0", pkg=manifest(name=name, version="1.0.0"))
        assert vscode.analyse(d)["indicators"] == [], name


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


def test_listed_ids_are_found_however_they_are_written(fixtures, tmp_path):
    text = (fixtures / "vscode_removed.md").read_text(encoding="utf-8")
    root = tmp_path / "exts"
    for i, publisher in enumerate(["badpub ", "bad" + chr(0x200B) + "pub", chr(0xFF42) + "adpub"]):
        make_folder(root, f"x{i}.y-1.0.0", manifest(publisher, "evil-theme", "1.0.0"))

    class List(FakeHttp):
        def get_text(self, url):
            return 200, text

    assert [e["malicious"] for e in vscode.assess(root, List())["extensions"]] == [True, True, True]


def test_the_folder_name_is_looked_up_too(fixtures, tmp_path):
    """package.json renamed after install does not hide an extension the list names by its folder."""
    root = tmp_path / "exts"
    make_folder(root, "badpub.evil-theme-0.0.1", manifest("innocent", "theme", "0.0.1"))
    (e,) = vscode.assess(root, FakeHttp())["extensions"]
    assert e["malicious"] and {i["id"] for i in e["indicators"]} == {"identity"}


def test_a_repeated_row_keeps_the_malware_verdict():
    rows = "\n".join(["| a.b | 1/1/2099 | Impersonation |", "| A.B | 2/1/2099 | Malware |",
                      "| a.b | 3/1/2099 | Spam |"])
    assert vscode.parse_removed(rows)["a.b"]["type"] == "Malware"


def test_linked_extensions_are_checked(tmp_path):
    real = make_folder(tmp_path / "dev", "badpub.evil-theme-0.0.1", manifest("badpub", "evil-theme", "0.0.1"))
    root = tmp_path / "exts"
    root.mkdir()
    try:
        (root / "badpub.evil-theme-0.0.1").symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("no symbolic links here")
    assert [e["id"] for e in vscode.assess(root, None)["extensions"]] == ["badpub.evil-theme"]


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


def test_list_unavailable_is_named_for_the_act_gate_too(tmp_path, fixtures, capsys):
    vsix = make_vsix(tmp_path / "ok.vsix")
    scan(tmp_path, fixtures, vsix, FakeHttp(fail_hosts=("raw.githubusercontent.com/microsoft",)), "--fail-on", "act")
    assert "--fail-on act: could not be evaluated (the VS Code Marketplace removal list was not checked" \
        in capsys.readouterr().err


def test_extension_strings_are_escaped_in_the_reports(tmp_path, fixtures):
    evil = "<script>alert(1)</script>"
    vsix = make_vsix(tmp_path / "x.vsix", pkg=manifest("pub", "x", "1.0.0", repository=evil,
                                                       extensionPack=["[a](https://evil.example)"]))
    _, out = scan(tmp_path, fixtures, vsix, FakeHttp())
    html = (out / "report.html").read_text(encoding="utf-8")
    assert evil not in html and "&lt;script&gt;" in html
    md = (out / "summary.md").read_text(encoding="utf-8")
    assert evil not in md and "&lt;script&gt;alert(1)" in md
    assert "[a](https://evil.example)" not in md and "\\[a\\](https://evil.example)" in md  # an inert link


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


# ------------------------------------------------------------------------------------------ after a real run

def test_old_versions_vs_code_has_not_deleted_yet(tmp_path, fixtures):
    """VS Code lists replaced versions in .obsolete: they are checked against the list but not shown as installs."""
    root = tmp_path / "exts"
    bundle = {"out/extension.js": "x" * vscode.BUNDLE_BYTES}
    make_folder(root, "example.ext-1.2.3", files=bundle)
    make_folder(root, "example.ext-1.3.0", manifest(version="1.3.0"), files=bundle)
    (root / ".obsolete").write_text('{"example.ext-1.2.3": true}', encoding="utf-8")
    info = vscode.assess(root, None)
    assert [(e["version"], e["in_use"]) for e in info["extensions"]] == [("1.2.3", False), ("1.3.0", True)]
    _, other = vscode.warnings(info)
    assert [w for w in other if "bundles" in w] == [
        "example.ext 1.3.0 bundles its code into one file, so the scanners cannot see its dependencies: no "
        "findings for it does not mean it has none"]
    _, out = scan(tmp_path, fixtures, root, FakeHttp())
    md = (out / "summary.md").read_text(encoding="utf-8")
    assert "1.2.3 (old version, not in use)" in md and "1 old version VS Code has replaced" in md


def test_findings_are_matched_to_the_extension_that_ships_them(tmp_path):
    from oss_intake.models import Finding

    root = tmp_path / "exts"
    make_folder(root, "example.a-1.0.0", manifest(name="a", version="1.0.0"),
                files={"out/extension.js": "1", "node_modules/@scope/lib/package.json":
                       '{"name": "@scope/lib", "version": "2.0.0"}'})
    make_folder(root, "example.b-1.0.0", manifest(name="b", version="1.0.0"),
                files={"out/extension.js": "1", "node_modules/@scope/lib/package.json":
                       '{"name": "@scope/lib", "version": "3.0.0"}'})
    info = vscode.assess(root, None)
    findings = [Finding("CVE-2099-1", "@scope/lib", "2.0.0", "CRITICAL", purl="pkg:npm/%40scope/lib@2.0.0"),
                Finding("CVE-2099-2", "rand", "0.8.5", "LOW", pkg_type="cargo",
                        target="example.b-1.0.0/dist/manifest.spdx.json"),
                Finding("CVE-2099-3", "other", "1.0.0", "HIGH", purl="pkg:npm/other@1.0.0")]
    vscode.attribute(info, findings)
    a, b = info["extensions"]
    assert a["findings"] == {"total": 1, "critical": 1, "high": 0, "malicious": 0}
    assert b["findings"]["total"] == 1 and info["unmatched"] == 1
    assert "packages" not in a  # the package list is only for matching, not for the report
    assert a["packages_seen"] == 1


def test_packages_in_nested_node_modules_are_matched(tmp_path):
    """Trivy reads a node_modules folder at any depth, so a bundled extension can still ship packages it sees."""
    from oss_intake.models import Finding

    make_folder(tmp_path, files={"out/extension.js": "x" * vscode.BUNDLE_BYTES,
                                 "dist/node_modules/@azure/msal-node/package.json":
                                 '{"name": "@azure/msal-node", "version": "5.3.1"}',
                                 "dist/node_modules/@azure/msal-node/lib/x/package.json": '{"name": "no"}'})
    info = vscode.assess(tmp_path, None)
    (e,) = info["extensions"]
    assert e["bundled"]  # a large main file stays bundled whatever else it ships (changed with Ned's OK)
    vscode.attribute(info, [Finding("CVE-2099-1", "@azure/msal-node", "5.3.1", "HIGH",
                                    purl="pkg:npm/%40azure/msal-node@5.3.1")])
    assert e["findings"]["high"] == 1 and e["packages_seen"] == 1 and info["unmatched"] == 0


def test_findings_from_an_sbom_an_extension_ships_are_matched_to_it(tmp_path):
    """Pylance ships SPDX SBOMs of its bundled tools; Trivy reports what they list as "Node.js", with no path."""
    from oss_intake.models import Finding

    root = tmp_path / "exts"
    spdx = json.dumps({"@graph": [{"type": "software_Package", "name": "@azure/msal-node",
                                   "software_packageVersion": "5.3.1"}]}, indent=2)
    make_folder(root, "example.lsp-1.0.0", manifest(name="lsp", version="1.0.0"),
                files={"out/extension.js": "1", "dist/bin/_manifest/spdx_3.0/manifest.spdx.json": spdx})
    make_folder(root, "example.other-1.0.0", manifest(name="other", version="1.0.0"))
    info = vscode.assess(root, None)
    vscode.attribute(info, [Finding("CVE-2099-1", "@azure/msal-node", "5.3.1", "HIGH", pkg_type="node-pkg",
                                    target="Node.js"),
                            Finding("CVE-2099-2", "@azure/msal-node", "9.9.9", "HIGH", pkg_type="node-pkg",
                                    target="Node.js")])
    lsp, other = info["extensions"]
    assert lsp["findings"]["total"] == 1 and lsp["findings_listed"] == 1
    assert other["findings"]["total"] == 0 and info["unmatched"] == 1
    assert "root" not in lsp and "listings" not in lsp


def test_documentation_mentioning_child_process_is_labelled(tmp_path):
    """Node loads a required .md or .txt as JavaScript, so documentation files are checked too, with the hit
    labelled (changed with Ned's OK after the 0.15.0 review)."""
    d = make_folder(tmp_path, files={"out/extension.js": "require('./payload.txt')",
                                     "out/payload.txt": "require('child_process').execSync(x); eval(y);",
                                     "docs/hidden.md": f"text {HIDDEN}"})
    got = {i["id"]: i["seen"] for i in vscode.analyse(d)["indicators"]}
    assert set(got) == {"process", "eval", "invisible"}
    assert got["process"][0]["detail"] == "child_process, in a documentation file"


def test_a_folder_with_no_packages_is_not_called_an_image(tmp_path, fixtures):
    """The OSV warning named "the image" for any input with no language packages, folders included."""
    folder = tmp_path / "reports"
    folder.mkdir()
    (folder / "report.html").write_text("<html></html>", encoding="utf-8")
    trivy, grype = tmp_path / "t.json", tmp_path / "g.json"
    trivy.write_text('{"SchemaVersion": 2, "ArtifactName": "reports", "Results": []}', encoding="utf-8")
    grype.write_text('{"matches": [], "source": {"type": "directory"}}', encoding="utf-8")
    out = tmp_path / "out"
    cli.main(["--path", str(folder), "--out", str(out), "--from-trivy-json", str(trivy), "--from-grype-json",
              str(grype), "--as-of", AS_OF], http=FakeHttp())
    warnings = json.loads((out / "assessment.json").read_text(encoding="utf-8"))["warnings"]
    assert "No language packages found in reports, so OSV was not queried" in warnings
    assert not any("in the image" in w for w in warnings)


# ------------------------------------------------------------------------------------------ pre-release review

def _finding(name, version, **kw):
    from oss_intake.models import Finding

    return Finding(f"CVE-2099-{abs(hash((name, version))) % 10000}", name, version, kw.pop("severity", "HIGH"), **kw)


def test_every_shipped_listing_is_read_from_its_extension(tmp_path, monkeypatch):
    """Two SBOMs in one extension: both read from the extension's folder, not the current directory."""
    root = tmp_path / "exts"
    make_folder(root, "example.lsp-1.0.0", manifest(name="lsp", version="1.0.0"), files={
        "out/extension.js": "1",
        "a/one.spdx.json": json.dumps({"packages": [{"name": "one", "versionInfo": "1.0.0"}]}),
        "b/two.cdx.json": json.dumps({"components": [{"group": "@scope", "name": "two", "version": "2.0.0"}]})})
    make_folder(root, "example.none-1.0.0", manifest(name="none", version="1.0.0"))
    monkeypatch.chdir(tmp_path)
    info = vscode.assess(root, None)
    vscode.attribute(info, [_finding("one", "1.0.0", pkg_type="node-pkg"),
                            _finding("@scope/two", "2.0.0", pkg_type="node-pkg")])
    lsp, none = info["extensions"]
    assert lsp["findings"]["total"] == 2 and lsp["findings_listed"] == 2 and info["unmatched"] == 0
    for e in (lsp, none):
        assert not {"root", "listings", "packages"} & set(e), e.keys()


def test_no_local_path_reaches_the_assessment(tmp_path, fixtures):
    root = tmp_path / "exts"
    make_folder(root)
    _, out = scan(tmp_path, fixtures, root, FakeHttp())
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    for e in a["extensions"]["extensions"]:
        assert not {"root", "listings", "packages"} & set(e)
        assert str(root) not in json.dumps(e)


def test_lockfiles_are_read_for_the_versions_they_list(tmp_path):
    root = tmp_path / "exts"
    make_folder(root, files={
        "out/extension.js": "1",
        "a/package-lock.json": json.dumps({"packages": {"node_modules/@azure/msal-node": {"version": "5.3.1"}}}),
        "b/yarn.lock": '"left-pad@^1.0.0":\n  version "1.3.0"\n  resolved "x"\n',
        "c/pnpm-lock.yaml": "packages:\n  /@scope/lib@2.0.0:\n    resolution: {}\n  'other@3.1.0':\n    x: 1\n"})
    info = vscode.assess(root, None)
    vscode.attribute(info, [_finding(n, v, pkg_type="node-pkg") for n, v in (
        ("@azure/msal-node", "5.3.1"), ("left-pad", "1.3.0"), ("@scope/lib", "2.0.0"), ("other", "3.1.0"))])
    assert info["extensions"][0]["findings_listed"] == 4


def test_a_listing_names_the_whole_package_not_part_of_it(tmp_path):
    """A finding for "ms" or "3" must not match a listing of "items" 2.1.3."""
    root = tmp_path / "exts"
    make_folder(root, "example.a-1.0.0", manifest(name="a", version="1.0.0"), files={
        "out/extension.js": "1", "sbom.spdx.json": json.dumps({"packages": [{"name": "items",
                                                                              "versionInfo": "2.1.3"}]})})
    make_folder(root, "example.b-1.0.0", manifest(name="b", version="1.0.0"))
    info = vscode.assess(root, None)
    vscode.attribute(info, [_finding("ms", "2.1.3", pkg_type="node-pkg"), _finding("3", "2.1.3", pkg_type="npm")])
    assert info["extensions"][0]["findings"]["total"] == 0 and info["unmatched"] == 2


def test_matching_against_listings_is_not_slow_on_crafted_text(tmp_path):
    """Compared with an ordinary listing of the same size, not with a fixed time."""
    timings = []
    for i, body in enumerate(['{"packages": [' + ",".join(json.dumps({"name": f"p{n}", "versionInfo": f"1.0.{n}"})
                                                         for n in range(40_000)) + "]}",
                              '{"x": ["' + '", "'.join(["q1"] * 150_000) + '"]}']):
        root = tmp_path / f"exts{i}"
        make_folder(root, files={"out/extension.js": "1", "sbom.spdx.json": body})
        info = vscode.assess(root, None)
        start = time.perf_counter()
        vscode.attribute(info, [_finding("q1", f"9.0.{n}", pkg_type="node-pkg") for n in range(300)])
        timings.append(time.perf_counter() - start)
    assert timings[1] < 20 * max(timings[0], 0.02), timings


def test_an_extension_cannot_mark_itself_as_an_old_version(tmp_path):
    d = make_folder(tmp_path, files={"out/extension.js": "x" * vscode.BUNDLE_BYTES,
                                     ".obsolete": '{"example.ext-1.2.3": true}'})
    (e,) = vscode.assess(d, None)["extensions"]
    assert e["in_use"]
    _, other = vscode.warnings({"extensions": [{**e, "removed": None, "malicious": False}],
                                "removed_list": {"status": "checked", "detail": "", "source": "", "entries": 1}})
    assert any("bundles" in w for w in other)


def test_one_extension_owns_every_finding(tmp_path):
    """A .vsix or a single folder: Trivy's paths start at the unpacked folder, so they do not name the extension."""
    vsix = make_vsix(tmp_path / "x.vsix")
    stage = tmp_path / "stage"
    vscode.unpack(vsix, stage / "x")
    info = vscode.assess(stage, None, staged=True)
    vscode.attribute(info, [_finding("golang.org/x/net", "v0.1.0", pkg_type="gobinary", target="x/extension/bin/tool")])
    assert info["extensions"][0]["findings"]["total"] == 1 and info["unmatched"] == 0


def test_grype_paths_with_a_leading_slash_are_matched(tmp_path):
    root = tmp_path / "exts"
    make_folder(root, "example.a-1.0.0", manifest(name="a", version="1.0.0"))
    make_folder(root, "example.b-1.0.0", manifest(name="b", version="1.0.0"))
    info = vscode.assess(root, None)
    vscode.attribute(info, [_finding("tool", "1.0.0", pkg_type="go-module", target="/example.b-1.0.0/bin/tool")])
    assert [e["findings"]["total"] for e in info["extensions"]] == [0, 1]


def test_hidden_characters_in_a_dependency_are_reported(tmp_path):
    """A private package in node_modules is unknown to every database, so hidden code there is looked for too."""
    d = make_folder(tmp_path, files={"out/extension.js": "require('helper-x7');",
                                     "node_modules/helper-x7/package.json": '{"name": "helper-x7", "version": "1.0.0"}',
                                     "node_modules/helper-x7/index.js": f"const s = '{HIDDEN}'; eval(s);"})
    got = {i["id"]: i["seen"] for i in vscode.analyse(d)["indicators"]}
    assert set(got) == {"invisible"}
    assert got["invisible"][0]["file"] == "node_modules/helper-x7/index.js"
    assert got["invisible"][0]["detail"].endswith("in a dependency")


# ------------------------------------------------------------------------------------------ second review pass

def test_yarn_lock_reading_is_linear_on_crafted_text(tmp_path):
    """An entry line followed by space-only lines made the earlier multi-line pattern backtrack without end."""
    crafted = "a@x\n" + (" " * 20 + "\n") * 9
    ordinary = "".join(f'"p{n}@^1.0.0":\n  version "1.0.{n}"\n  resolved "x"\n\n' for n in range(20_000))
    timings = []
    for i, text in enumerate((ordinary, crafted * 20_000)):
        p = tmp_path / f"yarn{i}.lock"
        p.write_text(text, encoding="utf-8")
        start = time.perf_counter()
        vscode._listed(p, [vscode.READ_TOTAL_BYTES])
        timings.append(time.perf_counter() - start)
    assert timings[1] < 20 * max(timings[0], 0.02), timings
    p = tmp_path / "yarn.lock"
    p.write_text('# yarn lockfile v1\n\n"@scope/lib@^2.0.0", "@scope/lib@^2.1.0":\n  version "2.1.3"\n\n'
                 'left-pad@^1.0.0:\n  version "1.3.0"\n', encoding="utf-8")
    assert vscode._listed(p, [vscode.READ_TOTAL_BYTES]) == {("@scope/lib", "2.1.3"), ("left-pad", "1.3.0")}


def test_one_extensions_dependencies_cannot_leave_anothers_code_unread(tmp_path, monkeypatch):
    monkeypatch.setattr(vscode, "READ_TOTAL_BYTES", 400_000)
    root = tmp_path / "exts"
    make_folder(root, "aaa.big-1.0.0", manifest("aaa", "big", "1.0.0"),
                files={f"node_modules/dep{n}/index.js": "x" * 100_000 for n in range(10)} | {"out/extension.js": "1"})
    make_folder(root, "zzz.evil-1.0.0", manifest("zzz", "evil", "1.0.0"),
                files={"out/extension.js": "require('child_process').exec(x)"})
    evil = vscode.assess(root, None)["extensions"][1]
    assert [i["id"] for i in evil["indicators"]] == ["process"] and evil["not_read_total"] == 0


def test_in_a_folder_of_extensions_other_folders_are_not_credited(tmp_path):
    root = tmp_path / "exts"
    make_folder(root, "example.a-1.0.0", manifest(name="a", version="1.0.0"))
    (root / "junk-folder" / "bin").mkdir(parents=True)
    info = vscode.assess(root, None)
    vscode.attribute(info, [_finding("tool", "1.0.0", severity="CRITICAL", pkg_type="go-module",
                                     target="junk-folder/bin/tool")])
    assert info["extensions"][0]["findings"]["total"] == 0 and info["unmatched"] == 1
    single = vscode.assess(root / "example.a-1.0.0", None)
    vscode.attribute(single, [_finding("tool", "1.0.0", pkg_type="go-module", target="bin/tool")])
    assert single["extensions"][0]["findings"]["total"] == 1


@pytest.mark.parametrize("main", ["/out/extension.js", "C:/out/extension.js", "\\out\\extension.js",
                                  "./out/../out/extension"])
def test_absolute_main_is_read_inside_the_folder_as_vs_code_does(tmp_path, main):
    """Threat model open item: main was joined to the folder as given, so an absolute main pointed outside it,
    the real main file was not found and the bundled warning was avoided."""
    d = make_folder(tmp_path / "exts", pkg=manifest(main=main), files={"out/extension.js": "x" * vscode.BUNDLE_BYTES})
    assert vscode.analyse(d)["bundled"], main


@pytest.mark.parametrize("main", ["../out/extension.js", "./../../x", "/../x", ".."])
def test_main_leading_out_of_the_folder_is_an_indicator(tmp_path, main):
    """VS Code follows .. out of the folder (it only logs a warning), so that file is not read: it is reported."""
    d = make_folder(tmp_path / "exts", pkg=manifest(main=main))
    got = {i["id"]: i["seen"] for i in vscode.analyse(d)["indicators"]}
    assert "main-outside" in got and main in got["main-outside"][0]["detail"]


def test_main_inside_the_folder_still_found():
    assert vscode._inside("./out/extension.js") == ("out/extension.js", False)
    assert vscode._inside("out/../dist/main") == ("dist/main", False)
    assert vscode._inside("") == ("", False) and vscode._inside("/") == ("", False)
    assert vscode._inside("../x") == ("", True)


def test_a_main_name_too_long_for_the_system_does_not_stop_the_assessment(tmp_path):
    """Audit (7 Nov): is_file() raised ENAMETOOLONG for a 300-character main, and the whole folder's run stopped."""
    d = make_folder(tmp_path / "exts", pkg=manifest(main="a" * 300))
    assert "bundled" in vscode.analyse(d)


def test_compare_with_an_older_version_shows_what_the_update_adds(tmp_path, fixtures):
    """Backlog (done 8 Nov): most extension compromises arrive as an update to a trusted extension. With
    --compare-with, the report lists what the update adds: new indicators, native files, web addresses, packages,
    and a publisher or repository change."""
    old = make_vsix(tmp_path / "old.vsix", pkg=manifest(version="1.0.0", repository="https://github.com/a/b"),
                    files={"extension/out/extension.js": "fetch('https://api.example.com/x')"})
    new = make_vsix(tmp_path / "new.vsix", pkg=manifest(version="1.0.1", repository="https://github.com/c/d"),
                    files={"extension/out/extension.js": "require('child_process'); fetch('https://api.example.com/x');"
                                                         " fetch('https://drop.example.net/y')",
                           "extension/bin/helper.node": b"\x7fELF....",
                           "extension/node_modules/left-pad/package.json": '{"name":"left-pad","version":"1.3.0"}'})
    code, out = scan(tmp_path, fixtures, new, FakeHttp(), "--compare-with", str(old))
    assert code == cli.EXIT_OK
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    ch = a["extensions"]["changes"]
    assert (ch["from_version"], ch["to_version"], ch["same_extension"]) == ("1.0.0", "1.0.1", True)
    assert {i["id"] for i in ch["indicators_added"]} >= {"process", "native"}
    assert ch["native_added"] == ["bin/helper.node"] and ch["hosts_added"] == ["drop.example.net"]
    assert ch["packages_added"] == ["left-pad"] and ch["repository_changed"] and not ch["publisher_changed"]
    assert any("adds since 1.0.0" in w and "new web address" in w for w in a["warnings"])
    assert any("changes its repository since 1.0.0" in w for w in a["warnings"])
    md = (out / "summary.md").read_text(encoding="utf-8")
    assert "What the update from 1.0.0 to 1.0.1 changed" in md and "drop.example.net" in md
    assert "What the update from 1.0.0 to 1.0.1 changed" in (out / "report.html").read_text(encoding="utf-8")


def test_compare_with_needs_one_extension_on_each_side(tmp_path, fixtures, capsys):
    vsix = make_vsix(tmp_path / "x.vsix")
    root = tmp_path / "extensions"
    make_folder(root)
    code, _ = scan(tmp_path, fixtures, root, FakeHttp(), "--compare-with", str(vsix))
    assert code == cli.EXIT_USAGE and "--compare-with needs --path to one VS Code extension" in capsys.readouterr().err
    code, _ = scan(tmp_path, fixtures, vsix, FakeHttp(), "--compare-with", str(tmp_path / "nope"))
    assert code == cli.EXIT_USAGE and "not a VS Code extension" in capsys.readouterr().err
