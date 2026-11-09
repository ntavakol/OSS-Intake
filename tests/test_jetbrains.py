"""JetBrains plugins (9 Nov): a plugin file, one installed plugin, or an IDE's plugins folder; Marketplace metadata;
--jetbrains-plugin downloads. The Marketplace answers follow those captured from the live service on 9 Nov 2026."""

import io
import json
import zipfile

import pytest

from oss_intake import cli, inputs, jetbrains

from .conftest import FakeHttp

AS_OF = "2026-11-09"
API = "https://plugins.jetbrains.com"


def plugin_xml(ident="mobi.hsz.idea.gitignore", name=".ignore", version="4.5.7", vendor="JetBrains"):
    return (f'<idea-plugin><id>{ident}</id><name>{name}</name><version>{version}</version>'
            f'<vendor url="https://www.jetbrains.com">{vendor}</vendor>'
            f'<idea-version since-build="252.0"/></idea-plugin>').encode()


def jar_bytes(xml: bytes | None, extra: dict | None = None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        if xml is not None:
            z.writestr("META-INF/plugin.xml", xml)
        z.writestr("com/example/Main.class", b"\xca\xfe\xba\xbe")
        for k, v in (extra or {}).items():
            z.writestr(k, v)
    return buf.getvalue()


def make_zip(path, folder="ignore", xml=None, libs=None):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"{folder}/lib/{folder}.jar", jar_bytes(xml if xml is not None else plugin_xml()))
        for name, data in (libs or {}).items():
            z.writestr(f"{folder}/lib/{name}", data)
    return path


def make_folder(root, folder="ignore", xml=None):
    lib = root / folder / "lib"
    lib.mkdir(parents=True)
    (lib / f"{folder}.jar").write_bytes(jar_bytes(xml if xml is not None else plugin_xml()))
    (lib / "dep-1.0.jar").write_bytes(jar_bytes(None))
    return root / folder


def marketplace(http, ident="mobi.hsz.idea.gitignore", pid=7495, version="4.5.7", **plugin):
    http.jetbrains[f"{API}/api/plugins/intellij/{ident}"] = {
        "id": pid, "name": ".ignore", "xmlId": ident, "downloads": 19963593, "pricingModel": "FREE",
        "isBlocked": False, "isHidden": False,
        "vendor": {"name": "JetBrains", "publicName": "JetBrains s.r.o.", "isVerified": True},
        "urls": {"sourceCodeUrl": "https://github.com/JetBrains/idea-gitignore"}, **plugin}
    http.jetbrains[f"{API}/api/plugins/{pid}/updates"] = [
        {"id": 936603, "version": version, "cdate": "1768825713000", "channel": "", "sinceUntil": "252.0+",
         "author": {"name": "Jakub Chrzanowski", "isJetBrains": True}}]


def scan(tmp_path, fixtures, target, http, *extra):
    out = tmp_path / "reports"
    argv = ["--path", str(target), "--out", str(out), "--from-trivy-json", str(fixtures / "trivy.json"),
            "--from-grype-json", str(fixtures / "grype.json"), "--as-of", AS_OF, *extra]
    return cli.main(argv, http=http), out


def test_a_plugin_zip_jar_folder_and_plugins_folder_are_jetbrains_inputs(tmp_path):
    z = make_zip(tmp_path / "ignore-4.5.7.zip")
    jar = tmp_path / "small.jar"
    jar.write_bytes(jar_bytes(plugin_xml("com.example.small", "Small", "1.0")))
    one = make_folder(tmp_path / "ide" / "plugins")
    make_folder(tmp_path / "ide" / "plugins", "other", plugin_xml("com.example.other", "Other", "2.0"))
    for p in (z, jar, one, tmp_path / "ide" / "plugins"):
        assert inputs.classify(p) == "jetbrains", p
    plain = tmp_path / "library.jar"
    plain.write_bytes(jar_bytes(None))
    assert inputs.classify(plain) == "artifact"  # a jar without plugin.xml is an ordinary artifact


def test_a_plugin_is_read_scanned_and_looked_up(tmp_path, fixtures):
    """Backlog (done 9 Nov): a JetBrains plugin's identity from its plugin.xml, its Marketplace entry (verified
    vendor, publication date), and its findings counted against it."""
    http = FakeHttp()
    marketplace(http)
    code, out = scan(tmp_path, fixtures, make_zip(tmp_path / "ignore-4.5.7.zip"), http)
    assert code == cli.EXIT_OK
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert a["inputs"]["path_kind"] == "jetbrains"
    (p,) = a["jetbrains"]["plugins"]
    assert (p["id"], p["version"], p["vendor"]) == ("mobi.hsz.idea.gitignore", "4.5.7", "JetBrains")
    m = p["marketplace"]
    assert m["vendor_verified"] and m["published"] == "2026-01-19" and not m["blocked"] and m["author"]
    assert p["findings"]["total"] == len(a["findings"]) > 0  # one plugin: everything scanned is its
    md = (out / "summary.md").read_text(encoding="utf-8")
    assert "JetBrains plugins (1)" in md and "mobi.hsz.idea.gitignore" in md and "2026-01-19" in md


def test_a_blocked_plugin_leads_the_report_and_an_unlisted_one_is_named(tmp_path, fixtures):
    http = FakeHttp()
    marketplace(http, isBlocked=True)
    root = tmp_path / "plugins"
    make_folder(root)
    make_folder(root, "private", plugin_xml("com.example.private", "Private", "1.0", "Example"))
    code, out = scan(tmp_path, fixtures, root, http)
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert a["warnings"][0].startswith("JETBRAINS MARKETPLACE HAS BLOCKED THIS PLUGIN: mobi.hsz.idea.gitignore")
    by = {p["id"]: p["marketplace"] for p in a["jetbrains"]["plugins"]}
    assert by["com.example.private"] == {"found": False}
    assert "not on the Marketplace" in (out / "summary.md").read_text(encoding="utf-8")


def test_a_failed_lookup_is_not_a_verdict(tmp_path):
    """Fail closed: a Marketplace error leaves the plugin unlooked-up, counted as an error, not "not listed"."""
    class Down(FakeHttp):
        def get_json(self, url, params=None):
            return (503, None) if url.startswith(API) else super().get_json(url, params)

    plugins = [{"id": "mobi.hsz.idea.gitignore", "version": "4.5.7"}]
    stats = jetbrains.lookup(Down(), plugins)
    assert stats["errors"] == 1 and "marketplace" not in plugins[0]


def test_a_plugin_is_downloaded_by_id_and_version(tmp_path, fixtures):
    http = FakeHttp()
    marketplace(http)
    url = f"{API}/plugin/download?pluginId=mobi.hsz.idea.gitignore&version=4.5.7"
    buf = io.BytesIO()
    make_zip(buf)
    http.files[url] = buf.getvalue()
    out = tmp_path / "reports"
    code = cli.main(["--jetbrains-plugin", "mobi.hsz.idea.gitignore@4.5.7", "--out", str(out), "--from-trivy-json",
                     str(fixtures / "trivy.json"), "--from-grype-json", str(fixtures / "grype.json"),
                     "--as-of", AS_OF], http=http)
    assert code == cli.EXIT_OK
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert a["jetbrains"]["download"]["source"] == url and "HTTPS only" in a["jetbrains"]["download"]["integrity"]
    assert any("downloaded from the JetBrains Marketplace over HTTPS" in w for w in a["warnings"])


@pytest.mark.parametrize("ident, extra, msg", [
    ("mobi.hsz.idea.gitignore", (), "an exact version"),
    ("mobi.hsz.idea.gitignore@4.5.7", ("--offline",), "needs the network"),
    ("mobi.hsz.idea.gitignore@4.5.7", ("--extension", "a.b@1.0.0"), "on its own"),
    ("mobi.hsz.idea.gitignore@9.9.9", (), "not found on the JetBrains Marketplace"),
])
def test_jetbrains_plugin_option_is_refused_when_it_cannot_work(tmp_path, fixtures, capsys, ident, extra, msg):
    code = cli.main(["--jetbrains-plugin", ident, "--out", str(tmp_path / "r"), "--from-trivy-json",
                     str(fixtures / "trivy.json"), "--from-grype-json", str(fixtures / "grype.json"), *extra],
                    http=FakeHttp())
    assert code == cli.EXIT_USAGE and msg in capsys.readouterr().err


def test_hostile_plugin_xml_and_files_are_refused_or_ignored(tmp_path):
    """An entity-expansion bomb, a plugin.xml that is not one, an oversized plugin.xml and a zip with a link are
    never read as a plugin; a zip bomb is refused by the .vsix limits."""
    bomb = (b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;">'
            b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;">]><idea-plugin><id>&c;</id></idea-plugin>')
    got = jetbrains.read_identity(bomb)  # small, so expat expands it; a large one is refused by expat
    assert got is None or len(got["id"]) <= 200
    assert jetbrains.read_identity(b"<project><id>x</id></project>") is None
    assert jetbrains.read_identity(b"not xml") is None
    big = jar_bytes(b"<idea-plugin><id>x</id>" + b" " * (jetbrains.MAX_PLUGIN_XML + 10) + b"</idea-plugin>")
    assert jetbrains._plugin_xml(big) is None
    no_xml = make_zip(tmp_path / "notaplugin.zip", xml=b"<project/>")
    with pytest.raises(inputs.InputError, match="not a JetBrains plugin"):
        jetbrains.unpack(no_xml, tmp_path / "staged")


# --- Review (9 Nov) ---------------------------------------------------------------------------------------------

def test_ordinary_zips_and_jars_stay_artifacts(tmp_path):
    """Review: any zip with <top>/lib/*.jar (a Maven or Tomcat distribution) and any jar with a META-INF/plugin.xml
    were taken as plugins and then refused (exit 2), losing the registry checksum check."""
    maven = tmp_path / "apache-maven-3.9.6-bin.zip"
    with zipfile.ZipFile(maven, "w") as z:
        z.writestr("apache-maven-3.9.6/lib/maven-core-3.9.6.jar", jar_bytes(None))
    other = tmp_path / "other-lib-1.0.jar"
    other.write_bytes(jar_bytes(b"<plugin><id>x</id></plugin>"))
    assert inputs.classify(maven) == "artifact" and inputs.classify(other) == "artifact"


def test_a_damaged_plugin_zip_is_a_bad_input_not_a_bug(tmp_path, fixtures, capsys):
    """Review: a plugin zip with a corrupt member exited 1 with "This is a bug in oss-intake"."""
    z = make_zip(tmp_path / "plugin.zip", libs={"big.bin": b"x" * 5000})
    raw = bytearray(z.read_bytes())
    i = raw.find(b"x" * 100)
    raw[i:i + 4] = b"yyyy"  # the stored member no longer matches its CRC
    z.write_bytes(bytes(raw))
    code, _ = scan(tmp_path, fixtures, z, FakeHttp())
    err = capsys.readouterr().err
    assert code == cli.EXIT_USAGE and "could not be unpacked" in err and "bug" not in err


def test_a_failed_version_lookup_is_an_error_not_version_not_found(tmp_path):
    """Review: an /updates failure read as "version not found" with no error counted."""
    class UpdatesDown(FakeHttp):
        def get_json(self, url, params=None):
            return (500, None) if url.endswith("/updates") else super().get_json(url, params)

    http = UpdatesDown()
    marketplace(http)
    plugins = [{"id": "mobi.hsz.idea.gitignore", "version": "4.5.7"}]
    stats = jetbrains.lookup(http, plugins)
    assert stats["errors"] == 1 and plugins[0]["marketplace"]["version_lookup"] == "failed (HTTP 500)"
    http = FakeHttp()
    marketplace(http, version="9.0.0")
    http.jetbrains[f"{API}/api/plugins/7495/updates"] *= 100  # a full page without this version
    plugins = [{"id": "mobi.hsz.idea.gitignore", "version": "4.5.7"}]
    jetbrains.lookup(http, plugins)
    assert plugins[0]["marketplace"]["version_lookup"] == "not among the 100 latest versions"


def test_a_one_jar_plugin_in_the_plugins_folder_is_a_plugin(tmp_path, fixtures):
    """Review: the IDE keeps a one-jar plugin directly in its plugins folder; it was missed, so a blocked one gave no
    alert and its findings went to another plugin."""
    http = FakeHttp()
    marketplace(http, ident="com.example.evil", pid=99, isBlocked=True)
    root = tmp_path / "plugins"
    make_folder(root)
    (root / "evil.jar").write_bytes(jar_bytes(plugin_xml("com.example.evil", "Evil", "4.5.7")))
    code, out = scan(tmp_path, fixtures, root, http)
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert {p["id"] for p in a["jetbrains"]["plugins"]} == {"mobi.hsz.idea.gitignore", "com.example.evil"}
    assert not a["jetbrains"]["single"]
    assert a["warnings"][0].startswith("JETBRAINS MARKETPLACE HAS BLOCKED THIS PLUGIN: com.example.evil")


def test_plugins_over_the_lookup_limit_are_warned_about(tmp_path, monkeypatch):
    monkeypatch.setattr(jetbrains, "MAX_LOOKUPS", 1)
    info = {"plugins": [{"id": "a", "version": "1"}, {"id": "b", "version": "1"}]}
    info["marketplace"] = {"status": "checked", **jetbrains.lookup(FakeHttp(), info["plugins"])}
    _, other = jetbrains.warnings(info)
    assert any("1 plugin(s) over the lookup limit" in w for w in other)


def test_a_download_that_is_not_the_plugin_asked_for_is_refused(tmp_path, fixtures, capsys):
    """Review: with HTTPS the only protection, a file of another plugin or version was assessed under its own
    name."""
    http = FakeHttp()
    url = f"{API}/plugin/download?pluginId=mobi.hsz.idea.gitignore&version=4.5.7"
    buf = io.BytesIO()
    make_zip(buf, xml=plugin_xml(version="4.5.6"))
    http.files[url] = buf.getvalue()
    code = cli.main(["--jetbrains-plugin", "mobi.hsz.idea.gitignore@4.5.7", "--out", str(tmp_path / "r"),
                     "--from-trivy-json", str(fixtures / "trivy.json"), "--from-grype-json",
                     str(fixtures / "grype.json")], http=http)
    assert code == cli.EXIT_USAGE and "not the plugin and version asked for" in capsys.readouterr().err
