"""Browser extensions (browserext.py): .crx files, unpacked and installed extensions, and browser profiles. Every
extension here is made up: the IDs are runs of one letter, the hosts are example ones."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

import pytest

from oss_intake import browserext, cli, gates, inputs, integrity, report, vscode

from .conftest import FakeHttp

AS_OF = "2026-11-23"
ID_A, ID_B = "a" * 32, "b" * 32

MV3 = {"manifest_version": 3, "name": "Example helper", "version": "1.0.0", "permissions": ["storage"]}


def crx(members: dict[str, bytes | str], header: bytes = b"\x12\x00", version: int = 3) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in members.items():
            z.writestr(name, data)
    return b"Cr24" + struct.pack("<II", version, len(header)) + header + buf.getvalue()


def write_ext(folder: Path, manifest: dict | str, **files: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "manifest.json").write_text(manifest if isinstance(manifest, str) else json.dumps(manifest, indent=2),
                                          encoding="utf-8")
    for name, text in files.items():
        p = folder / name.replace("__", "/")
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return folder


def profile(tmp_path: Path, exts: dict[str, dict]) -> Path:
    """A browser profile folder with each extension installed as Extensions/<id>/<version>_0."""
    prof = tmp_path / "Default"
    for ext_id, manifest in exts.items():
        write_ext(prof / "Extensions" / ext_id / f"{manifest['version']}_0", manifest)
    (prof / "Preferences").write_text("{}", encoding="utf-8")  # never read
    return prof


def signals(manifest: dict) -> dict[str, dict]:
    return {s["id"]: s for s in browserext.checks(manifest, json.dumps(manifest, indent=1))}


# ------------------------------------------------------------------------------------------- reading manifests

def test_comments_and_trailing_commas_are_read_but_not_inside_strings():
    text = ('// top\n{"name": "a // not a comment", /* block */ "version": "1,]", "list": [1, 2, ],\n'
            '"esc": "quote \\" // still a string", "manifest_version": 3, }')
    data = browserext.parse_manifest(text.encode())
    assert data == {"name": "a // not a comment", "version": "1,]", "list": [1, 2], "esc": 'quote " // still a string',
                    "manifest_version": 3}


@pytest.mark.parametrize("raw", [
    b'{"name": "x", "version": "1", "start_url": "/"}',  # a web app manifest: no manifest_version
    b'{"name": "x", "version": "1", "manifest_version": "3"}',  # not a whole number
    b'{"name": "x", "version": "1", "manifest_version": true}',
    b'{"version": "1", "manifest_version": 3}',
    b"[1, 2]", b"{", b"\xff\xfe\x00", b"/* never closed",
])
def test_other_files_are_not_extension_manifests(raw):
    assert browserext.parse_manifest(raw) is None


def test_a_deeply_nested_manifest_is_refused_not_a_crash():
    assert browserext.parse_manifest(b'{"name": "x", "version": "1", "manifest_version": 3, "a": '
                                     + b"[" * 100_000 + b"]" * 100_000 + b"}") is None


def test_the_name_comes_from_the_default_locale(tmp_path):
    folder = write_ext(tmp_path / "e", {**MV3, "name": "__MSG_AppName__", "default_locale": "en_GB"},
                       _locales__en_GB__messages__json="")
    (folder / "_locales/en_GB/messages.json").write_text('{"appname": {"message": "Localised name"}}',
                                                         encoding="utf-8")
    assert browserext.analyse(folder)["name"] == "Localised name"


def test_a_default_locale_that_leaves_the_folder_is_not_followed(tmp_path):
    (tmp_path / "messages.json").write_text('{"n": {"message": "outside"}}', encoding="utf-8")
    folder = write_ext(tmp_path / "e" / "f", {**MV3, "name": "__MSG_n__", "default_locale": "../../.."})
    assert browserext.analyse(folder)["name"] == "__MSG_n__"


def test_id_from_key_is_the_browsers_derivation():
    key = base64.b64encode(b"a public key").decode()
    want = "".join(chr(ord("a") + int(c, 16)) for c in hashlib.sha256(b"a public key").hexdigest()[:32])
    assert browserext.id_from_key(key) == want
    assert browserext.ID_RE.match(want)
    assert browserext.id_from_key("not base64!") is None and browserext.id_from_key(None) is None


# ------------------------------------------------------------------------------------------- permissions

@pytest.mark.parametrize("pattern", ["<all_urls>", "*://*/*", "https://*/*", "http://*/", "*://*", "file:///*"])
def test_patterns_for_every_site_are_graded_high(pattern):
    if pattern == "file:///*":  # file access is a local path, not every site
        assert not browserext.is_all_sites(pattern)
        return
    (p,) = browserext.permissions({"host_permissions": [pattern]})
    assert p["tier"] == "high" and p["kind"] == "site"


def test_permissions_are_graded_sorted_and_kept_when_unknown():
    perms = browserext.permissions({"permissions": ["storage", "debugger", "tabs", "https://example.com/*",
                                                    "brandNewThing", "storage"],
                                    "optional_permissions": ["cookies"]})
    assert [(p["name"], p["tier"], p["optional"]) for p in perms] == [
        ("debugger", "high", False), ("cookies", "high", True), ("tabs", "medium", False),
        ("https://example.com/*", "medium", False), ("storage", "low", False), ("brandNewThing", "not graded", False)]


def test_manifest_v2_sites_listed_among_permissions_are_site_access():
    (p,) = browserext.permissions({"permissions": ["<all_urls>"]})
    assert p["kind"] == "site" and p["tier"] == "high"


# ------------------------------------------------------------------------------------------- the manifest checks

def test_manifest_v2_is_flagged_with_the_browsers_timelines():
    s = signals({**MV3, "manifest_version": 2})["mv2"]
    assert "Chrome 138" in s["title"] and "Edge" in s["title"] and s["line"] == 2


def test_an_unsupported_manifest_version_is_flagged():
    assert "manifest-version" in signals({**MV3, "manifest_version": 4})


def test_content_scripts():
    found = signals({**MV3, "content_scripts": [
        {"matches": ["https://example.com/*"], "js": ["a.js"]},
        {"matches": ["<all_urls>"], "js": ["b.js"], "run_at": "document_start", "all_frames": True, "world": "MAIN"}]})
    assert set(found) == {"cs-all-sites", "cs-start", "cs-all-frames", "cs-main-world"}
    assert "content script 2" in found["cs-all-sites"]["detail"]


def test_a_content_script_on_some_sites_at_the_default_time_is_not_flagged():
    assert signals({**MV3, "content_scripts": [{"matches": ["https://example.com/*"], "run_at": "document_idle",
                                                "all_frames": False, "world": "ISOLATED"}]}) == {}


def test_externally_connectable_and_web_accessible_resources():
    found = signals({**MV3, "externally_connectable": {"ids": ["*"], "matches": ["https://example.com/*"]},
                     "web_accessible_resources": [{"resources": ["inject.js"], "matches": ["<all_urls>"]},
                                                  {"resources": ["x.png"], "matches": ["https://example.com/*"]}]})
    assert {"external-any", "external-pages", "web-accessible"} <= set(found)
    assert "inject.js" in found["web-accessible"]["detail"] and "x.png" not in found["web-accessible"]["detail"]
    assert "web-accessible" in signals({**MV3, "manifest_version": 2, "web_accessible_resources": ["a.js"]})


def test_wasm_unsafe_eval_and_local_sources_are_not_flagged():
    for policy in ("script-src 'self' 'wasm-unsafe-eval'; object-src 'self'",
                   "script-src 'self' http://localhost:8080 http://127.0.0.1",
                   "default-src 'self'; script-src 'self' 'sha256-abc='"):
        assert signals({**MV3, "content_security_policy": {"extension_pages": policy}}) == {}, policy


def test_csp_eval_and_remote_scripts_in_manifest_v2():
    found = signals({**MV3, "manifest_version": 2,
                     "content_security_policy": "script-src 'self' 'unsafe-eval' https://cdn.example.com; "
                                                "object-src 'self'"})
    assert found["csp-eval"]["tier"] == "high" and found["csp-remote"]["detail"] == "https://cdn.example.com"
    assert "Chrome does not load" not in found["csp-eval"]["detail"]


def test_csp_eval_in_manifest_v3_pages_says_chrome_refuses_it():
    found = signals({**MV3, "content_security_policy": {"extension_pages": "script-src 'self' 'unsafe-eval'"}})
    assert "Chrome does not load a Manifest V3 extension" in found["csp-eval"]["detail"]


def test_default_src_counts_when_there_is_no_script_src():
    assert "csp-remote" in signals({**MV3, "manifest_version": 2, "content_security_policy": "default-src *"})


def test_sandboxed_pages_are_their_own_signal():
    found = signals({**MV3, "content_security_policy": {
        "sandbox": "sandbox allow-scripts; script-src 'self' 'unsafe-eval' https://x.example"}})
    assert set(found) == {"csp-sandbox"} and found["csp-sandbox"]["tier"] == "medium"


@pytest.mark.parametrize("url, flagged", [
    ("https://clients2.google.com/service/update2/crx", False),
    ("https://edge.microsoft.com/extensionwebstorebase/v1/crx", False),
    ("https://clients2.google.com/service/update2/crx/", False),
    ("https://updates.example.net/crx", True),
    ("http://clients2.google.com/service/update2/crx", True),  # not the store's address: plain HTTP
])
def test_update_url(url, flagged):
    assert ("update-url" in signals({**MV3, "update_url": url})) is flagged


def test_no_update_url_is_not_flagged():
    assert "update-url" not in signals(MV3)


def test_settings_and_page_overrides():
    found = signals({**MV3, "chrome_settings_overrides": {"search_provider": {"name": "x"}, "homepage": "h"},
                     "chrome_url_overrides": {"newtab": "n.html"}})
    assert found["overrides-settings"]["detail"] == "search_provider, homepage"
    assert found["overrides-page"]["detail"] == "newtab"


def test_odd_types_in_a_manifest_are_not_a_crash():
    odd = {**MV3, "content_scripts": "x", "externally_connectable": [1], "web_accessible_resources": [1, None],
           "content_security_policy": 5, "sandbox": "x", "update_url": 3, "chrome_settings_overrides": [],
           "permissions": {"a": 1}, "author": {"email": 5}}
    assert browserext.checks(odd, json.dumps(odd)) == []
    assert browserext.permissions(odd) == []


# ------------------------------------------------------------------------------------------- finding extensions

def test_a_profile_and_its_layouts(tmp_path):
    prof = profile(tmp_path, {ID_A: MV3, ID_B: {**MV3, "version": "2.0"}})
    (prof / "Extensions" / "Temp").mkdir()  # not an ID: ignored
    (prof / "Extensions" / ("c" * 32)).mkdir()  # an ID with no version folder: ignored
    found = browserext.find(prof)
    assert [f.relative_to(prof).as_posix() for f in found] == [f"Extensions/{ID_A}/1.0.0_0", f"Extensions/{ID_B}/2.0_0"]
    assert browserext.find(prof / "Extensions") == found
    assert browserext.find(prof / "Extensions" / ID_A) == found[:1]
    assert browserext.find(found[0]) == found[:1]
    assert inputs.classify(prof) == "browser" and inputs.classify(found[0]) == "browser"
    assert not browserext.is_single(prof) and browserext.is_single(found[0])


def test_a_linked_extension_folder_is_not_followed(tmp_path):
    outside = write_ext(tmp_path / "outside" / "1.0.0_0", MV3)
    ext = tmp_path / "Default" / "Extensions" / ID_A
    ext.mkdir(parents=True)
    try:
        (ext / "1.0.0_0").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("this system cannot make links")
    assert browserext.find(tmp_path / "Default") == []


def test_too_many_extensions_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(browserext, "MAX_EXTENSIONS", 1)
    prof = profile(tmp_path, {ID_A: MV3, ID_B: MV3, "c" * 32: MV3})
    with pytest.raises(inputs.InputError, match="more than 1 extensions"):
        browserext.find(prof)


def test_a_web_app_folder_is_not_a_browser_extension(tmp_path):
    (tmp_path / "manifest.json").write_text('{"name": "app", "start_url": "/"}', encoding="utf-8")
    assert inputs.classify(tmp_path) == "dir"


@pytest.mark.parametrize("platform, rel", [
    ("darwin", "Library/Application Support/Google/Chrome/Default"),
    ("linux", ".config/google-chrome/Default"),
])
def test_default_profile_folders(platform, rel, tmp_path):
    assert browserext.profile_dir("chrome", platform, home=tmp_path) == tmp_path.joinpath(*rel.split("/"))


def test_default_profile_folders_on_windows(tmp_path):
    got = browserext.profile_dir("edge", "win32", environ={"LOCALAPPDATA": str(tmp_path)})
    assert got == tmp_path / "Microsoft" / "Edge" / "User Data" / "Default"
    assert browserext.profile_dir("brave", "win32", environ={"LOCALAPPDATA": "C"}).parts[-3:] == (
        "Brave-Browser", "User Data", "Default")
    with pytest.raises(inputs.InputError, match="LOCALAPPDATA"):
        browserext.profile_dir("chrome", "win32", environ={})


# ------------------------------------------------------------------------------------------- .crx files

def test_a_crx_is_unpacked_and_assessed(tmp_path):
    f = tmp_path / "ext.crx"
    f.write_bytes(crx({"manifest.json": json.dumps({**MV3, "permissions": ["debugger"]}), "bg.js": "x"}))
    assert inputs.classify(f) == "browser"
    target, tmp = inputs.stage(f, "browser")
    try:
        info = browserext.assess(target, staged=True)
    finally:
        __import__("shutil").rmtree(tmp)
    (e,) = info["extensions"]
    assert info["single"] and e["name"] == "Example helper" and e["tier"] == "high"
    assert e["permissions"][0]["name"] == "debugger"


@pytest.mark.parametrize("data, words", [
    (b"Cr24" + struct.pack("<II", 2, 4) + b"xxxx" + b"PK", "old CRX2"),
    (b"Cr24" + struct.pack("<II", 4, 4) + b"xxxx" + b"PK", "CRX version 4"),
    (b"Cr24" + struct.pack("<II", 3, 2_000_000) + b"x" * 10, "-byte header"),
    (b"Cr24" + struct.pack("<II", 3, 100) + b"x" * 10, "past the end"),
    (b"Cr24\x03", "no Cr24 header"),
])
def test_bad_crx_headers_are_refused(tmp_path, data, words):
    f = tmp_path / "bad.crx"
    f.write_bytes(data)
    with pytest.raises(inputs.InputError, match=words):
        browserext.unpack(f, tmp_path / "out")


def test_a_crx_with_no_extension_manifest_is_refused(tmp_path):
    f = tmp_path / "bad.crx"
    f.write_bytes(crx({"readme.txt": "hi"}))
    with pytest.raises(inputs.InputError, match="not a browser extension"):
        browserext.unpack(f, tmp_path / "out")


def test_a_damaged_zip_after_the_header_is_refused(tmp_path):
    f = tmp_path / "bad.crx"
    f.write_bytes(crx({"manifest.json": json.dumps(MV3)})[:-30])
    with pytest.raises(inputs.InputError, match="bad.crx could not be unpacked"):
        browserext.unpack(f, tmp_path / "out")


@pytest.mark.parametrize("name", ["../escape.js", "/abs.js", "C:/x.js", "a\\..\\b.js", "nul.txt"])
def test_member_names_that_could_leave_the_folder_are_refused_naming_the_crx(tmp_path, name):
    f = tmp_path / "evil.crx"
    f.write_bytes(crx({"manifest.json": json.dumps(MV3), name: "x"}))
    with pytest.raises(inputs.InputError, match=r"refused: evil\.crx has"):
        browserext.unpack(f, tmp_path / "out")
    assert not (tmp_path / "escape.js").exists()


def test_a_link_inside_a_crx_is_refused(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("manifest.json", json.dumps(MV3))
        info = zipfile.ZipInfo("link")
        info.external_attr = 0o120777 << 16
        z.writestr(info, "/etc/passwd")
    f = tmp_path / "link.crx"
    f.write_bytes(b"Cr24" + struct.pack("<II", 3, 0) + buf.getvalue())
    with pytest.raises(inputs.InputError, match="contains a link"):
        browserext.unpack(f, tmp_path / "out")


def test_zip_bombs_and_too_many_files_are_refused(tmp_path, monkeypatch):
    bomb = tmp_path / "bomb.crx"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("manifest.json", json.dumps(MV3))
        z.writestr("zeros.bin", b"\0" * 5_000_000)
    bomb.write_bytes(b"Cr24" + struct.pack("<II", 3, 0) + buf.getvalue())
    with pytest.raises(inputs.InputError, match="expands more than"):
        browserext.unpack(bomb, tmp_path / "a")
    many = tmp_path / "many.crx"
    many.write_bytes(crx({"manifest.json": json.dumps(MV3), **{f"f{i}.js": "x" for i in range(10)}}))
    monkeypatch.setattr(vscode, "MAX_FILES", 5)
    with pytest.raises(inputs.InputError, match="more than 5"):
        browserext.unpack(many, tmp_path / "b")


def test_a_crx_too_large_is_refused_before_it_is_read(tmp_path, monkeypatch):
    monkeypatch.setattr(browserext, "MAX_CRX_BYTES", 100)
    f = tmp_path / "big.crx"
    f.write_bytes(crx({"manifest.json": json.dumps(MV3), "pad.js": "x" * 500}))
    with pytest.raises(inputs.InputError, match="larger than 100 bytes"):
        browserext.unpack(f, tmp_path / "out")


def test_the_vsix_refusal_wording_is_unchanged():
    with pytest.raises(inputs.InputError, match=r"refused: the \.vsix has an unsafe file name"):
        vscode._member_path("/x")


# ------------------------------------------------------------------------------------------- identity and known-bad

def test_an_installed_folder_whose_key_gives_another_id_is_flagged(tmp_path):
    key = base64.b64encode(b"someone else's key").decode()
    prof = profile(tmp_path, {ID_A: {**MV3, "key": key}})
    (e,) = browserext.assess(prof)["extensions"]
    assert e["signals"][0]["id"] == "identity" and e["id_from_key"] in e["signals"][0]["detail"]
    _, other = browserext.warnings({"extensions": [e]})
    assert any("do not agree on what it is" in w for w in other)


def test_an_installed_folder_whose_version_differs_is_flagged(tmp_path):
    folder = write_ext(tmp_path / "Default" / "Extensions" / ID_A / "1.0.0_0", {**MV3, "version": "9.9.9"})
    (s,) = [x for x in browserext.analyse(folder)["signals"] if x["id"] == "identity"]
    assert "version 1.0.0" in s["detail"]


def test_an_unreadable_installed_manifest_is_reported_not_skipped(tmp_path):
    prof = profile(tmp_path, {ID_A: MV3})
    (prof / "Extensions" / ID_A / "1.0.0_0" / "manifest.json").write_text("{broken", encoding="utf-8")
    (e,) = browserext.assess(prof)["extensions"]
    assert e["unreadable"] and e["id"] == ID_A
    assert any("could not be read" in w for w in browserext.warnings({"extensions": [e]})[1])


@pytest.fixture
def listed(monkeypatch):
    """The bundled known-bad list with two made-up browser extension entries."""
    real = integrity._bundled_known_bad

    def with_entries():
        data = real()
        data["browser_extensions"] = [
            {"id": ID_A, "name": "Example helper", "versions": ["1.0.0"], "reference": "https://example.com/report",
             "note": "a compromised update"},
            {"id": ID_B, "name": "Other", "versions": ["*"], "reference": "https://example.com/r2",
             "note": "malicious in every version"}]
        return data
    monkeypatch.setattr(integrity, "_bundled_known_bad", with_entries)
    monkeypatch.setattr(integrity, "_published", None)


def test_known_bad_extensions_by_id_and_version(tmp_path, listed):
    prof = profile(tmp_path, {ID_A: MV3, ID_B: {**MV3, "version": "5.0"}, "c" * 32: MV3})
    info = browserext.assess(prof)
    hits = {e["id"]: e["known_bad"] for e in info["extensions"]}
    assert hits[ID_A]["note"] == "a compromised update" and hits[ID_B] and hits["c" * 32] is None
    assert info["known_bad_list"]["entries"] == 2
    alerts, _ = browserext.warnings(info)
    assert len(alerts) == 2 and alerts[0].startswith("BROWSER EXTENSION ON THE KNOWN-BAD LIST")
    assert gates.met(["malicious"], [], {}, None, None, 0, info) == ["malicious"]
    assert integrity.known_bad_extension(ID_A, "1.0.1") is None


def test_no_known_bad_extension_does_not_meet_the_gate(tmp_path):
    info = browserext.assess(profile(tmp_path, {ID_A: MV3}))
    assert gates.met(["malicious"], [], {}, None, None, 0, info) == []


@pytest.mark.parametrize("entry, ok", [
    ({"id": ID_A, "name": "n", "versions": ["1"], "reference": "r", "note": "x"}, True),
    ({"id": "A" * 32, "name": "n", "versions": ["1"], "reference": "r", "note": "x"}, False),
    ({"id": "q" * 32, "name": "n", "versions": ["1"], "reference": "r", "note": "x"}, False),
    ({"id": ID_A, "name": "n", "versions": [], "reference": "r", "note": "x"}, False),
    ({"id": ID_A, "name": "n", "versions": ["1"], "reference": "", "note": "x"}, False),
])
def test_a_published_list_with_a_bad_extension_entry_is_not_used(entry, ok):
    data = integrity._bundled_known_bad()
    data["browser_extensions"] = [entry]
    assert integrity._valid_known_bad(data) is ok
    del data["browser_extensions"]
    assert integrity._valid_known_bad(data)  # a list without the section, as older lists are, is still valid


def test_published_extension_entries_are_added_to_the_bundled_ones(monkeypatch):
    data = integrity._bundled_known_bad()
    data["browser_extensions"] = [{"id": ID_B, "name": "n", "versions": ["2"], "reference": "r", "note": "late"}]
    monkeypatch.setattr(integrity, "_published", data)
    assert integrity.known_bad_extension(ID_B, "2")["note"] == "late"


# ------------------------------------------------------------------------------------------- attribution and report

def test_findings_are_matched_by_folder(tmp_path):
    from oss_intake.models import Finding

    info = browserext.assess(profile(tmp_path, {ID_A: MV3, ID_B: MV3}))
    f = Finding(vuln_id="CVE-2099-0001", package="left-pad", installed="1.3.0", severity="HIGH",
                target=f"Extensions/{ID_B}/1.0.0_0/node_modules/left-pad/package.json")
    g = Finding(vuln_id="CVE-2099-0002", package="x", installed="1", severity="LOW", target="elsewhere")
    browserext.attribute(info, [f, g])
    by = {e["id"]: e["findings"] for e in info["extensions"]}
    assert by[ID_B]["high"] == 1 and by[ID_A]["total"] == 0 and info["unmatched"] == 1


def test_the_report_section_lists_grades_and_signals(tmp_path):
    info = browserext.assess(profile(tmp_path, {ID_A: {**MV3, "permissions": ["cookies", "brandNew"],
                                                        "update_url": "https://updates.example.net/crx"}}))
    browserext.attribute(info, [])
    title, blocks = report.browser_section({"browser_extensions": info})
    text = json.dumps(blocks)
    assert title == "Browser extensions (1)"
    assert "cookies" in text and "brandNew" in text and "not graded" in text and "not a store" in text
    assert "jquery.min.js" in text  # says what the scanners do not see


# ------------------------------------------------------------------------------------------- the CLI

def run(tmp_path, *args, http=None):
    fix = Path(__file__).parent / "fixtures"
    return cli.main(["--out", str(tmp_path / "out"), "--from-trivy-json", str(fix / "trivy.json"),
                     "--from-grype-json", str(fix / "grype.json"), "--as-of", AS_OF, "--formats", "json,md",
                     "--quiet", *args], http=http or FakeHttp())


def assessment(tmp_path) -> dict:
    return json.loads((tmp_path / "out" / "assessment.json").read_text(encoding="utf-8"))


def test_a_profile_end_to_end(tmp_path):
    prof = profile(tmp_path, {ID_A: {**MV3, "permissions": ["debugger"]}})
    assert run(tmp_path, "--path", str(prof)) == cli.EXIT_OK
    a = assessment(tmp_path)
    assert a["inputs"]["path_kind"] == "browser"
    assert a["browser_extensions"]["extensions"][0]["tier"] == "high"
    assert "## Browser extensions (1)" in (tmp_path / "out" / "summary.md").read_text(encoding="utf-8")


def test_fail_on_malicious_with_a_known_bad_extension(tmp_path, listed):
    prof = profile(tmp_path, {ID_A: MV3})
    assert run(tmp_path, "--path", str(prof), "--fail-on", "malicious") == cli.EXIT_THRESHOLD
    assert assessment(tmp_path)["warnings"][0].startswith("BROWSER EXTENSION ON THE KNOWN-BAD LIST")


def test_browser_option_reads_the_default_profile(tmp_path, monkeypatch):
    prof = profile(tmp_path, {ID_A: MV3, ID_B: MV3})
    monkeypatch.setattr(browserext, "profile_dir", lambda name: prof)
    assert run(tmp_path, "--browser", "chrome") == cli.EXIT_OK
    a = assessment(tmp_path)
    assert a["browser_extensions"]["browser"] == "Chrome" and len(a["browser_extensions"]["extensions"]) == 2
    assert run(tmp_path, "--browser", "chrome", "--browser-extension", ID_B) == cli.EXIT_OK
    (e,) = assessment(tmp_path)["browser_extensions"]["extensions"]
    assert e["id"] == ID_B and assessment(tmp_path)["browser_extensions"]["single"]


@pytest.mark.parametrize("args, words", [
    (["--browser-extension", ID_A], "needs --browser"),
    (["--browser", "chrome", "--browser-extension", "not-an-id"], "32 letters a to p"),
    (["--browser", "chrome", "--browser-extension", "c" * 32], "is not installed"),
    (["--browser", "chrome", "--path", "."], "on its own"),
    (["--browser", "chrome", "--image", "owner/app:1.0"], "on its own"),
])
def test_browser_option_misuse_is_a_usage_error(tmp_path, monkeypatch, capsys, args, words):
    prof = profile(tmp_path, {ID_A: MV3})
    monkeypatch.setattr(browserext, "profile_dir", lambda name: prof)
    assert run(tmp_path, *args) == cli.EXIT_USAGE
    assert words in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_browser_option_without_the_browser(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(browserext, "profile_dir", lambda name: tmp_path / "nowhere")
    assert run(tmp_path, "--browser", "edge") == cli.EXIT_USAGE
    assert "no Edge extensions folder" in capsys.readouterr().err


def test_browser_option_with_no_extensions_installed(tmp_path, monkeypatch, capsys):
    (tmp_path / "Default" / "Extensions").mkdir(parents=True)
    monkeypatch.setattr(browserext, "profile_dir", lambda name: tmp_path / "Default")
    assert run(tmp_path, "--browser", "brave") == cli.EXIT_USAGE
    assert "no extensions are installed" in capsys.readouterr().err


def test_a_bad_crx_is_a_usage_error_before_anything_is_written(tmp_path, capsys):
    f = tmp_path / "bad.crx"
    f.write_bytes(crx({"manifest.json": json.dumps(MV3), "../x": "y"}))
    assert run(tmp_path, "--path", str(f)) == cli.EXIT_USAGE
    assert "refused: bad.crx" in capsys.readouterr().err and not (tmp_path / "out").exists()


def test_the_profile_is_only_read(tmp_path):
    prof = profile(tmp_path, {ID_A: MV3})
    before = {p: p.stat().st_mtime_ns for p in prof.rglob("*")}
    assert run(tmp_path, "--path", str(prof)) == cli.EXIT_OK
    assert {p: p.stat().st_mtime_ns for p in prof.rglob("*")} == before


# ------------------------------------------------------------------------------------------- code signals (PR 2)

FILE_NAMES = {"bg__js": "bg.js", "page__html": "page.html", "inject__js": "inject.js", "packed__js": "packed.js",
              "obf__js": "obf.js", "entropy__js": "entropy.js", "blob__js": "blob.js", "popup__html": "popup.html",
              "bundle__js": "bundle.js", "big__js": "big.js", "bg__js__map": "bg.js.map", "c__js": "c.js",
              "a__js": "a.js", "_metadata__verified_contents__json": "_metadata/verified_contents.json"}


def files_in(folder: Path, manifest: dict, files: dict) -> Path:
    """An extension with these files, named by FILE_NAMES (keyword arguments cannot hold a dot)."""
    write_ext(folder, manifest)
    for key, text in files.items():
        p = folder / FILE_NAMES[key]
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return folder


def code(tmp_path: Path, **files: str) -> dict:
    folder = files_in(tmp_path / "code-ext", MV3, files)
    return {s["id"]: s for s in browserext.analyse(folder)["signals"] if s["id"].startswith("code-")}


def test_code_signals_each_with_file_and_line(tmp_path):
    found = code(tmp_path, bg__js="const a = 1;\neval(atob(x));\nnew Function('return 1')();\n"
                                  "setTimeout('alert(1)', 5);\nimportScripts('https://cdn.example.com/w.js');\n"
                                  "chrome.tabs.executeScript(id, {code: payload});\n",
                 page__html='<script src="https://cdn.example.com/lib.js"></script>',
                 inject__js="var s = document.createElement('script'); s.src = 'https://x.example/a.js';")
    assert set(found) == {"code-eval", "code-string-timer", "code-import-remote", "code-remote-script",
                          "code-execute-string"}
    assert found["code-eval"]["seen"][0] == {"file": "bg.js", "line": 2, "detail": "eval("}
    assert len(found["code-eval"]["seen"]) == 2 and found["code-remote-script"]["tier"] == "high"
    assert {x["file"] for x in found["code-remote-script"]["seen"]} == {"page.html", "inject.js"}


def test_ordinary_code_has_no_code_signals(tmp_path):
    found = code(tmp_path, bg__js="setTimeout(() => run(), 5);\nchrome.scripting.executeScript({target, func});\n"
                                  "importScripts('lib.js');\nconst logo = 'data:image/png;base64," + "A" * 3000
                                  + "';\nconst url = 'https://api.example.com/v1';\n")
    assert found == {}


def test_packed_obfuscated_high_entropy_and_blobs(tmp_path):
    noise = base64.b64encode(b"".join(hashlib.sha256(bytes([i])).digest() for i in range(10))).decode()
    names = " ".join(f"var _0x{i:04x}=1;" for i in range(25))
    found = code(tmp_path, packed__js="eval(function(p,a,c,k,e,d){return p}('x',1,1,'x'.split('|'),0,{}))",
                 obf__js=names, entropy__js=f"var k='{noise}';", blob__js="var b='" + "QUJD" * 600 + "';")
    assert {"code-packed", "code-obfuscated", "code-high-entropy", "code-blob"} <= set(found)
    assert found["code-obfuscated"]["seen"][0]["detail"] == "25 distinct _0x names"


def test_hidden_characters_are_a_high_signal(tmp_path):
    found = code(tmp_path, bg__js="const x = 1;‮// reversed\nconst y = '︀︁︂︃';")
    assert found["code-hidden"]["tier"] == "high" and len(found["code-hidden"]["seen"]) == 2


def test_hosts_are_listed_per_file_without_standards_namespaces(tmp_path):
    folder = files_in(tmp_path / "e", MV3, dict(bg__js="fetch('https://api.example.com/a'); const ns = "
                                                   "'http://www.w3.org/2000/svg';",
                                                popup__html='<a href="https://help.example.org/x">help</a>'))
    e = browserext.analyse(folder)
    assert e["hosts_by_file"] == {"bg.js": ["api.example.com"], "popup.html": ["help.example.org"]}
    assert not e["hosts_capped"]


def test_hosts_are_capped(tmp_path, monkeypatch):
    monkeypatch.setattr(browserext, "MAX_HOSTS", 2)
    folder = files_in(tmp_path / "e", MV3, dict(bg__js=" ".join(f"https://h{i}.example.com" for i in range(5))))
    e = browserext.analyse(folder)
    assert e["hosts_capped"] and len(e["hosts_all"]) == 2


def test_minified_files_are_a_fact_not_a_signal(tmp_path):
    folder = files_in(tmp_path / "e", MV3, dict(bundle__js="var a=1;" * 1000))
    e = browserext.analyse(folder)
    assert e["code_facts"]["minified_files"] == ["bundle.js"] and e["code_facts"]["longest_line"] == 8000
    assert not [s for s in e["signals"] if s["id"].startswith("code-")]


def test_what_is_not_read(tmp_path, monkeypatch):
    folder = files_in(tmp_path / "e", MV3, dict(bg__js="eval(1)", big__js="eval(2)" * 10,
                                                _metadata__verified_contents__json='"eval(3)"',
                                                bg__js__map='"eval(4)"'))
    (folder / "bin.dat").write_bytes(b"\0eval(5)")
    monkeypatch.setattr(browserext, "READ_FILE_BYTES", 30)
    e = browserext.analyse(folder)
    (s,) = [x for x in e["signals"] if x["id"] == "code-eval"]
    assert [x["file"] for x in s["seen"]] == ["bg.js"]
    assert e["code_facts"]["not_read"] == ["big.js"]


def test_the_reading_budget_is_shared_across_extensions(tmp_path, monkeypatch):
    monkeypatch.setattr(browserext, "READ_TOTAL_BYTES", 10)
    prof = profile(tmp_path, {ID_A: MV3, ID_B: MV3})
    for i in (ID_A, ID_B):
        (prof / "Extensions" / i / "1.0.0_0" / "a.js").write_text("eval(1); // padding", encoding="utf-8")
    info = browserext.assess(prof)
    assert sum(e["code_facts"]["not_read_total"] for e in info["extensions"]) >= 1


def test_a_linked_file_inside_an_extension_is_not_read(tmp_path):
    outside = tmp_path / "secret.js"
    outside.write_text("eval(1)", encoding="utf-8")
    folder = write_ext(tmp_path / "e", MV3)
    try:
        (folder / "link.js").symlink_to(outside)
    except OSError:
        pytest.skip("this system cannot make links")
    assert not [s for s in browserext.analyse(folder)["signals"] if s["id"] == "code-eval"]


# ------------------------------------------------------------------------------------------- comparing versions

def versions(tmp_path, old: dict, new: dict, old_files: dict | None = None, new_files: dict | None = None):
    o = browserext.analyse(files_in(tmp_path / "old", old, old_files or {}))
    n = browserext.analyse(files_in(tmp_path / "new", new, new_files or {}))
    return browserext.compare(o, n)


def test_an_update_that_asks_for_more_is_drift(tmp_path):
    diff = versions(tmp_path, {**MV3, "permissions": ["storage", "tabs"]},
                    {**MV3, "version": "1.1.0", "permissions": ["storage", "cookies"],
                     "optional_permissions": ["history"], "host_permissions": ["<all_urls>"],
                     "content_scripts": [{"matches": ["https://bank.example/*"], "js": ["c.js"]}]},
                    new_files={"c__js": "eval(x); fetch('https://collect.example.net')"})
    assert diff["drift"]
    assert diff["permissions_added"] == [{"name": "<all_urls>", "optional": False},
                                         {"name": "cookies", "optional": False}, {"name": "history", "optional": True}]
    assert diff["permissions_removed"] == [{"name": "tabs", "optional": False}]
    assert diff["content_sites_added"] == ["https://bank.example/*"]
    assert diff["hosts_added"] == ["collect.example.net"]
    assert [s["id"] for s in diff["signals_added"]] == ["code-eval"]
    warns = browserext.change_warnings(diff, "Example helper")
    assert len(warns) == 1 and "cookies" in warns[0] and "1.1.0 adds since 1.0.0" in warns[0]


def test_an_update_that_only_removes_is_not_drift(tmp_path):
    diff = versions(tmp_path, {**MV3, "permissions": ["storage", "tabs"]}, {**MV3, "version": "1.1.0"})
    assert not diff["drift"] and diff["permissions_removed"]
    assert browserext.change_warnings(diff, "x") == []


def test_a_new_update_address_is_drift_and_an_author_change_is_a_warning(tmp_path):
    diff = versions(tmp_path, {**MV3, "author": "Alice"},
                    {**MV3, "update_url": "https://updates.example.net/crx", "author": "Mallory"})
    assert diff["drift"] and set(diff["changed"]) == {"update_url", "author"}
    warns = browserext.change_warnings(diff, "x")
    assert any("update address" in w for w in warns) and any("author from Alice to Mallory" in w for w in warns)
    diff = versions(tmp_path / "2", {**MV3, "author": "Alice"}, {**MV3, "author": "Mallory"})
    assert not diff["drift"]


def test_a_signal_seen_more_often_is_reported(tmp_path):
    diff = versions(tmp_path, MV3, MV3, {"a__js": "eval(1)"}, {"a__js": "eval(1)\neval(2)\neval(3)"})
    assert diff["signals_grew"] == [{"id": "code-eval", "title": browserext.CODE_SIGNALS["code-eval"][1],
                                     "from": 1, "to": 3}]


def test_comparing_two_different_extensions_is_said(tmp_path):
    o = {**browserext.analyse(write_ext(tmp_path / "o", MV3)), "id": ID_A}
    n = {**browserext.analyse(write_ext(tmp_path / "n", MV3)), "id": ID_B}
    diff = browserext.compare(o, n)
    assert not diff["same_extension"] and "different extension" in browserext.change_warnings(diff, "x")[0]


def test_compare_and_the_drift_gate_end_to_end(tmp_path):
    old = tmp_path / "old.crx"
    old.write_bytes(crx({"manifest.json": json.dumps(MV3)}))
    new = write_ext(tmp_path / "new", {**MV3, "version": "1.1.0", "permissions": ["storage", "debugger"]})
    assert run(tmp_path, "--path", str(new), "--compare-with", str(old), "--fail-on", "permission-drift",
               "--scanners", "trivy,osv") == cli.EXIT_THRESHOLD
    a = assessment(tmp_path)
    assert a["browser_extensions"]["changes"]["permissions_added"] == [{"name": "debugger", "optional": False}]
    assert "hosts_all" not in a["browser_extensions"]["extensions"][0]
    md = (tmp_path / "out" / "summary.md").read_text(encoding="utf-8")
    assert "asks for more than the older version" in md
    same = write_ext(tmp_path / "same", {**MV3, "version": "1.1.0"})
    assert run(tmp_path, "--path", str(same), "--compare-with", str(old), "--fail-on",
               "permission-drift") == cli.EXIT_OK


@pytest.mark.parametrize("which, words", [
    ("profile", "not a profile or a folder of extensions"),
    ("old-not-ext", "not a browser extension"),
    ("no-compare", "--fail-on permission-drift needs --compare-with"),
])
def test_compare_misuse_is_a_usage_error(tmp_path, capsys, which, words):
    prof = profile(tmp_path, {ID_A: MV3})
    one = write_ext(tmp_path / "one", MV3)
    args = {"profile": ["--path", str(prof), "--compare-with", str(one)],
            "old-not-ext": ["--path", str(one), "--compare-with", str(tmp_path / "Default" / "Preferences")],
            "no-compare": ["--path", str(one), "--fail-on", "permission-drift"]}[which]
    assert run(tmp_path, *args) == cli.EXIT_USAGE
    assert words in capsys.readouterr().err


def test_the_drift_gate_is_not_evaluated_without_a_comparison():
    class Args:
        no_exploits = False
        browser_info = {"extensions": []}

    gaps = gates.not_evaluated(["permission-drift"], {"status": "ok"}, None, Args())
    assert gaps == [("permission-drift", "the two versions were not compared")]

