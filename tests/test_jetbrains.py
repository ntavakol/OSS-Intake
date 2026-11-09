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
