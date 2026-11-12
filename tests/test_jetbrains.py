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


def test_a_plugin_is_downloaded_by_id_and_version(tmp_path, fixtures, signer):
    # Changed with Ned's OK (12 Nov): the Marketplace signs every file, so the fake download is signed (by the test
    # certificates standing in for JetBrains'); an unsigned one is now refused.
    http = FakeHttp()
    marketplace(http)
    url = f"{API}/plugin/download?pluginId=mobi.hsz.idea.gitignore&version=4.5.7"
    buf = io.BytesIO()
    make_zip(buf)
    http.files[url] = signer(buf.getvalue())
    out = tmp_path / "reports"
    code = cli.main(["--jetbrains-plugin", "mobi.hsz.idea.gitignore@4.5.7", "--out", str(out), "--from-trivy-json",
                     str(fixtures / "trivy.json"), "--from-grype-json", str(fixtures / "grype.json"),
                     "--as-of", AS_OF], http=http)
    assert code == cli.EXIT_OK
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert a["jetbrains"]["download"]["source"] == url
    assert a["jetbrains"]["download"]["integrity"] == "its JetBrains Marketplace signature verifies"
    assert not any("downloaded from the JetBrains Marketplace over HTTPS" in w for w in a["warnings"])


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


# --- Pre-release review, 0.20.0 (10 Nov) -------------------------------------------------------------------------

def test_a_source_folder_with_a_plugin_jar_keeps_its_lockfile_scan(tmp_path, monkeypatch):
    """A folder holding a plugin jar (a plugin's source checkout with its build output, say) is taken as JetBrains;
    it must still be scanned in both Trivy modes, so its lockfiles are read, and its findings are not all given to
    the plugin."""
    import stat

    folder = tmp_path / "repo"
    make_folder(folder.parent, "repo")
    (folder / "package-lock.json").write_text("{}", encoding="utf-8")
    fake = tmp_path / "trivy"
    fake.write_bytes(b"stand-in trivy binary")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    modes = []

    def run(cmd, timeout):
        if "--version" in cmd:
            return json.dumps({"Version": "0.76.1"}).encode()
        modes.append(cmd[1])
        return json.dumps({"SchemaVersion": 2, "ArtifactName": "repo", "Results": []}).encode()

    monkeypatch.setattr(cli.trivy_mod, "run", run)
    out = tmp_path / "o"
    assert cli.main(["--path", str(folder), "--out", str(out), "--offline", "--scanners", "trivy",
                     "--trivy-path", str(fake), "--formats", "json"]) == 0
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert a["inputs"]["path_kind"] == "jetbrains" and sorted(modes) == ["fs", "rootfs"]


def test_one_plugin_inside_a_bigger_folder_is_not_given_every_finding(tmp_path):
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "helper.jar").write_bytes(jar_bytes(plugin_xml("com.example.helper", "Helper", "1.0")))
    info = jetbrains.assess(root, None)
    assert len(info["plugins"]) == 1 and not info["single"]
    plugin_dir = make_folder(tmp_path / "p")
    assert jetbrains.assess(plugin_dir, None)["single"]


def test_a_single_plugin_with_repo_takes_its_version_as_the_scanned_release(tmp_path, fixtures):
    """A plugin file used to be an artifact, whose version came from its name for --repo's release lag; it now comes
    from its plugin.xml."""
    http = FakeHttp()
    marketplace(http)
    code, out = scan(tmp_path, fixtures, make_zip(tmp_path / "ignore.zip"), http, "--repo", "example/webapp")
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    # The fixture repository has no 4.5.7 release: that it looked for one shows the version was taken.
    assert any("No GitHub release matches '4.5.7'" in w for w in a["health"]["warnings"])


# ------------------------------------------------------------------------------------------- signatures (12 Nov)

@pytest.fixture
def signer(monkeypatch):
    """A test PKI whose root stands in for JetBrains' certificate, and the signer from tests/zipsigner.py."""
    pytest.importorskip("cryptography")
    from . import zipsigner

    pki = zipsigner.make_pki()
    if hasattr(jetbrains, "zipsign"):
        monkeypatch.setattr(jetbrains.zipsign, "jetbrains_ca", lambda: pki["root"])

    def sign(data: bytes, by: str = "marketplace") -> bytes:
        if by == "author":
            return zipsigner.sign(data, pki["author"], pki["author_key"])
        return zipsigner.sign(data, pki["chain"], pki["leaf_key"])
    return sign


def plugin_zip_bytes(**kw) -> bytes:
    buf = io.BytesIO()
    make_zip(buf, **kw)
    return buf.getvalue()


def changed(data: bytes) -> bytes:
    """data with its first entry's modification time changed: still the same plugin to every reader, but not the
    file that was signed."""
    out = bytearray(data)
    out[10] ^= 1
    return bytes(out)


def download_run(tmp_path, fixtures, body):
    http = FakeHttp()
    marketplace(http)
    http.files[f"{API}/plugin/download?pluginId=mobi.hsz.idea.gitignore&version=4.5.7"] = body
    out = tmp_path / "reports"
    code = cli.main(["--jetbrains-plugin", "mobi.hsz.idea.gitignore@4.5.7", "--out", str(out), "--from-trivy-json",
                     str(fixtures / "trivy.json"), "--from-grype-json", str(fixtures / "grype.json"),
                     "--as-of", AS_OF], http=http)
    return code, out


def test_a_signed_download_is_verified(tmp_path, fixtures, signer):
    """Backlog (agreed 9 Nov, done 12 Nov): the Marketplace's signature on a downloaded plugin is checked; a verified
    one is no longer "HTTPS only"."""
    code, out = download_run(tmp_path, fixtures, signer(plugin_zip_bytes()))
    assert code == cli.EXIT_OK
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    dl = a["jetbrains"]["download"]
    assert dl["signature"]["status"] == "verified" and "HTTPS only" not in dl["integrity"]
    assert a["jetbrains"]["plugins"][0]["signature"]["status"] == "verified"
    assert not any("over HTTPS" in w for w in a["warnings"])
    assert "verified (JetBrains Marketplace)" in (out / "summary.md").read_text(encoding="utf-8")


def test_a_download_that_does_not_match_its_signature_is_refused(tmp_path, fixtures, signer, capsys):
    """Fail closed: a download changed after the Marketplace signed it is not assessed at all."""
    code, out = download_run(tmp_path, fixtures, changed(signer(plugin_zip_bytes())))
    assert code == cli.EXIT_USAGE
    assert "does not match its JetBrains Marketplace signature" in capsys.readouterr().err
    assert not (out / "assessment.json").exists()


def test_a_download_signed_only_by_its_author_is_refused(tmp_path, fixtures, signer, capsys):
    """Ned's rule (12 Nov): the Marketplace signs every file it serves (old versions too), so a download signed by
    someone else is not the file it signed."""
    code, out = download_run(tmp_path, fixtures, signer(plugin_zip_bytes(), by="author"))
    assert code == cli.EXIT_USAGE
    assert "signed by CN=Plugin Author, not by the JetBrains Marketplace" in capsys.readouterr().err
    assert not (out / "assessment.json").exists()


def test_an_unsigned_download_is_refused_even_without_the_extra(tmp_path, fixtures, signer, capsys, monkeypatch):
    """No signing block at all needs no cryptography to see."""
    monkeypatch.setattr("oss_intake.zipsign._crypto", lambda: None)
    code, _ = download_run(tmp_path, fixtures, plugin_zip_bytes())
    assert code == cli.EXIT_USAGE
    assert "not signed by the JetBrains Marketplace" in capsys.readouterr().err


def test_without_the_extra_a_signed_download_is_https_only(tmp_path, fixtures, signer, monkeypatch):
    """Without cryptography, who signed it cannot be checked: assessed, with HTTPS named as its only protection."""
    monkeypatch.setattr("oss_intake.zipsign._crypto", lambda: None)
    code, out = download_run(tmp_path, fixtures, signer(plugin_zip_bytes()))
    assert code == cli.EXIT_OK
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert "HTTPS only" in a["jetbrains"]["download"]["integrity"]
    assert any("over HTTPS" in w and "signatures extra" in w for w in a["warnings"])


def test_a_plugin_file_that_does_not_match_its_signature_leads_the_report(tmp_path, fixtures, signer):
    f = tmp_path / "ignore-4.5.7.zip"
    f.write_bytes(changed(signer(plugin_zip_bytes())))
    http = FakeHttp()
    marketplace(http)
    code, out = scan(tmp_path, fixtures, f, http)
    assert code == cli.EXIT_OK
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert a["jetbrains"]["plugins"][0]["signature"]["status"] == "failed"
    assert a["warnings"][0].startswith("JETBRAINS SIGNATURE DOES NOT MATCH: mobi.hsz.idea.gitignore 4.5.7")


def test_a_signed_plugin_file_is_verified_offline(tmp_path, fixtures, signer):
    """The check needs no network: the signature and JetBrains' certificate are in hand."""
    f = tmp_path / "ignore-4.5.7.zip"
    f.write_bytes(signer(plugin_zip_bytes()))
    code, out = scan(tmp_path, fixtures, f, FakeHttp(), "--offline")
    assert code == cli.EXIT_OK
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert a["jetbrains"]["plugins"][0]["signature"]["status"] == "verified"


def test_an_unsigned_plugin_file_is_warned_about(tmp_path, fixtures, signer):
    code, out = scan(tmp_path, fixtures, make_zip(tmp_path / "ignore-4.5.7.zip"), FakeHttp(), "--offline")
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert a["jetbrains"]["plugins"][0]["signature"]["status"] == "unsigned"
    assert any("carries no JetBrains Marketplace signature" in w for w in a["warnings"])


def test_a_plugins_folder_checks_single_jars_and_marks_unpacked_ones(tmp_path, fixtures, signer):
    """An installed one-jar plugin keeps the file the Marketplace served; an unpacked one has lost its signature,
    which is said once in the report, not warned about per plugin."""
    plugins = tmp_path / "plugins"
    make_folder(plugins)
    (plugins / "small.jar").write_bytes(signer(jar_bytes(plugin_xml("com.example.small", "Small", "1.0"))))
    code, out = scan(tmp_path, fixtures, plugins, FakeHttp(), "--offline")
    assert code == cli.EXIT_OK
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    by = {p["id"]: p["signature"]["status"] for p in a["jetbrains"]["plugins"]}
    assert by == {"mobi.hsz.idea.gitignore": "unpacked", "com.example.small": "verified"}
    assert not any("signature" in w.lower() for w in a["warnings"])
    assert "lost their signature" in (out / "summary.md").read_text(encoding="utf-8")


def test_without_the_signatures_extra_the_check_is_named_once(tmp_path, fixtures, signer, monkeypatch):
    monkeypatch.setattr("oss_intake.zipsign._crypto", lambda: None)
    plugins = tmp_path / "plugins"
    plugins.mkdir()
    for n in ("a", "b"):
        (plugins / f"{n}.jar").write_bytes(signer(jar_bytes(plugin_xml(f"com.example.{n}", n, "1.0"))))
    code, out = scan(tmp_path, fixtures, plugins, FakeHttp(), "--offline")
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    hits = [w for w in a["warnings"] if "signatures extra" in w]
    assert len(hits) == 1 and "2 plugin file(s)" in hits[0] and "oss-intake[signatures]" in hits[0]


def test_a_plugin_file_holding_two_plugins_is_still_checked(tmp_path, fixtures, signer):
    """Review finding: a .zip with two plugin folders gave both "unpacked", so a second folder hid a mismatch."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("ignore/lib/ignore.jar", jar_bytes(plugin_xml()))
        z.writestr("other/lib/other.jar", jar_bytes(plugin_xml("com.example.other", "Other", "2.0")))
    f = tmp_path / "two.zip"
    f.write_bytes(changed(signer(buf.getvalue())))
    code, out = scan(tmp_path, fixtures, f, FakeHttp(), "--offline")
    assert code == cli.EXIT_OK
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert {p["signature"]["status"] for p in a["jetbrains"]["plugins"]} == {"failed"}
    assert sum(w.startswith("JETBRAINS SIGNATURE DOES NOT MATCH") for w in a["warnings"]) == 2
