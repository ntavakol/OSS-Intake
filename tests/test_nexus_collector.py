"""examples/nexus/nexus_sbom.py against a fake Nexus: paging, formats, the new-since-last-run state, credentials."""

import base64
import importlib.util
import io
import json
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest

from oss_intake import sbom

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("nexus_sbom", ROOT / "examples" / "nexus" / "nexus_sbom.py")
col = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(col)

REPOS = [{"name": "npm-proxy", "format": "npm", "type": "proxy"},
         {"name": "pypi-proxy", "format": "pypi", "type": "proxy"},
         {"name": "maven-central", "format": "maven2", "type": "proxy"},
         {"name": "maven-public", "format": "maven2", "type": "group"},
         {"name": "internal-npm", "format": "npm", "type": "hosted"},
         {"name": "docker-hub", "format": "docker", "type": "proxy"}]


def _asset(created):
    return [{"path": "x", "blobCreated": created, "uploaderIp": "172.17.0.1", "checksum": {"sha1": "0" * 40}}]


class FakeNexus:
    def __init__(self, items, page_size=2, auth=None):
        self.items, self.page_size, self.auth, self.seen = items, page_size, auth, []

    def __call__(self, req):
        u = urlparse(req.full_url)
        self.seen.append((req.full_url, req.get_header("Authorization")))
        if self.auth and req.get_header("Authorization") != self.auth:
            import urllib.error
            raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)
        if u.path == "/service/rest/v1/repositories":
            body = REPOS
        else:
            q = parse_qs(u.query)
            items = self.items.get(q["repository"][0], [])
            start = int(q.get("continuationToken", ["0"])[0])
            chunk = items[start:start + self.page_size]
            nxt = start + self.page_size
            body = {"items": chunk, "continuationToken": str(nxt) if nxt < len(items) else None}
        return io.BytesIO(json.dumps(body).encode())


ITEMS = {
    "npm-proxy": [
        {"repository": "npm-proxy", "format": "npm", "group": None, "name": "lodash", "version": "4.17.15",
         "assets": _asset("2026-10-30T01:00:00.000+00:00")},
        {"repository": "npm-proxy", "format": "npm", "group": "babel", "name": "traverse", "version": "7.22.0",
         "assets": _asset("2026-10-30T01:00:01.000+00:00")},
        {"repository": "npm-proxy", "format": "npm", "group": None, "name": "minimist", "version": "1.2.0",
         "assets": _asset("2026-10-30T01:00:02.000+00:00")}],
    "pypi-proxy": [{"repository": "pypi-proxy", "format": "pypi", "group": None, "name": "Django", "version": "2.2",
                    "assets": _asset("2026-10-30T01:00:03.000+00:00")}],
    "maven-central": [{"repository": "maven-central", "format": "maven2", "group": "org.apache.logging.log4j",
                       "name": "log4j-core", "version": "2.14.1", "assets": _asset("2026-10-30T01:00:04.000+00:00")}],
}


def test_reads_proxies_pages_and_formats(tmp_path, capsys):
    fake = FakeNexus(ITEMS)
    out = tmp_path / "s"
    assert col.main(["--url", "http://localhost:8081", "--out", str(out)], opener=fake) == 0
    entries, _, info = sbom.read(out / "all")
    purls = sorted(e["purl"] for e in entries)
    assert purls == ["pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "pkg:npm/%40babel/traverse@7.22.0",
                     "pkg:npm/lodash@4.17.15", "pkg:npm/minimist@1.2.0", "pkg:pypi/django@2.2"]
    labels = {e["purl"]: e["labels"] for e in entries}
    assert labels["pkg:npm/lodash@4.17.15"] == {"cached": "2026-10-30", "system": "nexus:npm-proxy"}
    printed = capsys.readouterr().out
    for skipped in ("maven-public: a group", "internal-npm: hosted", "docker-hub: docker repositories"):
        assert skipped in printed
    assert not any("internal-npm" in u for u, _ in fake.seen)
    assert "172.17.0.1" not in "".join(p.read_text(encoding="utf-8") for p in (out / "all").iterdir())


def test_new_until_accepted(tmp_path, capsys):
    """A run never accepts anything. What failed the gate, or a gate that did not run, shows up again."""
    out, state = tmp_path / "s", tmp_path / "state.json"
    args = ["--url", "http://localhost:8081", "--out", str(out), "--state", str(state), "--repository", "npm-proxy"]

    def new():
        return sorted(e["purl"] for e in sbom.read(out / "new")[0]) if any((out / "new").iterdir()) else []

    assert col.main(args, opener=FakeNexus(ITEMS)) == 0
    assert len(new()) == 3  # the first run: everything is new
    assert col.main(args, opener=FakeNexus(ITEMS)) == 0
    assert len(new()) == 3  # not accepted (the gate failed or did not run): still new
    assert col.main(["--state", str(state), "--accept"]) == 0
    assert col.main(args, opener=FakeNexus(ITEMS)) == 0
    assert new() == [] and "nothing new to check" in capsys.readouterr().out
    more = {"npm-proxy": ITEMS["npm-proxy"] + [{"repository": "npm-proxy", "format": "npm", "name": "axios",
                                                "version": "0.21.0", "assets": _asset("2026-10-30T02:00:00Z")}]}
    assert col.main(args, opener=FakeNexus(more)) == 0
    assert new() == ["pkg:npm/axios@0.21.0"]
    # removed from the cache, then cached again: new again
    gone = {"npm-proxy": [i for i in ITEMS["npm-proxy"] if i["name"] != "lodash"]}
    assert col.main(args, opener=FakeNexus(gone)) == 0
    assert col.main(["--state", str(state), "--accept"]) == 0
    assert col.main(args, opener=FakeNexus(ITEMS)) == 0
    assert new() == ["pkg:npm/lodash@4.17.15"]


def test_first_version_state_file_still_read(tmp_path):
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"seen": ["npm-proxy||lodash|4.17.15"]}), encoding="utf-8")
    out = tmp_path / "s"
    assert col.main(["--url", "http://localhost:8081", "--out", str(out), "--state", str(state),
                     "--repository", "npm-proxy"], opener=FakeNexus(ITEMS)) == 0
    assert "lodash" not in "".join(p.read_text(encoding="utf-8") for p in (out / "new").iterdir())


def test_failure_midway_writes_nothing_and_keeps_state(tmp_path):
    out, state = tmp_path / "s", tmp_path / "state.json"
    state.write_text(json.dumps({"seen": ["npm-proxy||lodash|4.17.15"]}), encoding="utf-8")

    class Broken(FakeNexus):
        def __call__(self, req):
            if "pypi-proxy" in req.full_url:
                import urllib.error
                raise urllib.error.URLError("connection reset")
            return super().__call__(req)

    assert col.main(["--url", "http://localhost:8081", "--out", str(out), "--state", str(state)],
                    opener=Broken(ITEMS)) == 2
    assert not out.exists()
    assert json.loads(state.read_text(encoding="utf-8")) == {"seen": ["npm-proxy||lodash|4.17.15"]}


def test_redirect_refused_so_credentials_stay_put(tmp_path, monkeypatch, capsys):
    """urllib copies Authorization onto a redirect, even to another host. Run real servers on localhost: the
    'Nexus' answers 302 to another port; that one must receive nothing."""
    import http.server
    import threading

    got = []

    class Other(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            got.append(self.headers.get("Authorization"))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"[]")

        def log_message(self, *a):
            pass

    other = http.server.HTTPServer(("127.0.0.1", 0), Other)

    class Nexus(Other):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{other.server_port}/login")
            self.end_headers()

    nexus = http.server.HTTPServer(("127.0.0.1", 0), Nexus)
    for srv in (other, nexus):
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    monkeypatch.setenv("NEXUS_USERNAME", "admin")
    monkeypatch.setenv("NEXUS_PASSWORD", "s3cret")
    try:
        assert col.main(["--url", f"http://127.0.0.1:{nexus.server_port}", "--out", str(tmp_path / "s")]) == 2
    finally:
        nexus.shutdown()
        other.shutdown()
    assert got == [] and "redirect" in capsys.readouterr().err


@pytest.mark.parametrize("env, message", [
    ({"NEXUS_TOKEN": "x"}, "name code and pass code"), ({"NEXUS_USERNAME": "admin"}, "set both"),
    ({"NEXUS_PASSWORD": "x"}, "set both")])
def test_credential_settings_that_would_mislead(tmp_path, monkeypatch, capsys, env, message):
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert col.main(["--url", "http://localhost:8081", "--out", str(tmp_path / "s")], opener=FakeNexus(ITEMS)) == 2
    assert message in capsys.readouterr().err


def test_anonymous_run_says_so(tmp_path, capsys):
    assert col.main(["--url", "http://localhost:8081", "--out", str(tmp_path / "s"), "--repository", "npm-proxy"],
                    opener=FakeNexus(ITEMS)) == 0
    assert "read anonymously" in capsys.readouterr().out


def test_repeating_continuation_token_stops(tmp_path, capsys):
    class Loop(FakeNexus):
        def __call__(self, req):
            if "components" in req.full_url:
                self.seen.append(req.full_url)
                return io.BytesIO(json.dumps({"items": [], "continuationToken": "same"}).encode())
            return super().__call__(req)

    loop = Loop(ITEMS)
    assert col.main(["--url", "http://localhost:8081", "--out", str(tmp_path / "s"), "--repository", "npm-proxy"],
                    opener=loop) == 2
    assert len(loop.seen) <= 3 and "same continuation token" in capsys.readouterr().err


def test_all_holds_only_this_run(tmp_path):
    out = tmp_path / "s"
    assert col.main(["--url", "http://localhost:8081", "--out", str(out)], opener=FakeNexus(ITEMS)) == 0
    assert col.main(["--url", "http://localhost:8081", "--out", str(out), "--repository", "npm-proxy"],
                    opener=FakeNexus(ITEMS)) == 0
    assert [p.name for p in (out / "all").iterdir()] == ["npm-proxy.cdx.json"]


def test_group_named_explicitly_refused(tmp_path, capsys):
    assert col.main(["--url", "http://localhost:8081", "--out", str(tmp_path / "s"), "--repository",
                     "maven-public"], opener=FakeNexus(ITEMS)) == 2
    assert "name its members" in capsys.readouterr().err


def test_lock_refuses_a_second_run(tmp_path, capsys):
    state = tmp_path / "state.json"
    (tmp_path / "state.json.lock").write_text("", encoding="utf-8")
    assert col.main(["--url", "http://localhost:8081", "--out", str(tmp_path / "s"), "--state", str(state)],
                    opener=FakeNexus(ITEMS)) == 2
    assert "another run" in capsys.readouterr().err


def test_checksums_only_from_the_one_package_file():
    jar = {"path": "/g/a/1/a-1.jar", "fileSize": 10, "maven2": {"extension": "jar"}, "checksum": {"sha1": "a" * 40}}
    javadoc = {"path": "/g/a/1/a-1-javadoc.jar", "fileSize": 99, "maven2": {"extension": "jar",
                                                                            "classifier": "javadoc"},
               "checksum": {"sha1": "b" * 40}}
    assert col.hashes("maven2", {"assets": [javadoc, jar]}) == [{"alg": "SHA-1", "content": "a" * 40}]
    wheels = [{"path": f"/packages/x/1/x-1-{p}.whl", "checksum": {"sha256": p * 8}} for p in ("cp311", "cp312")]
    assert col.hashes("pypi", {"assets": wheels}) == []  # no single file stands for the version


def test_repository_file_names_never_collide():
    used = set()
    names = [col._file_name(n, used) for n in ("npm.", "npm_", "npm", "NPM")]
    assert len({n.casefold() for n in names}) == 4


def test_credentials_sent_only_as_header_and_never_over_plain_http(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("NEXUS_USERNAME", "admin")
    monkeypatch.setenv("NEXUS_PASSWORD", "s3cret-value")
    auth = "Basic " + base64.b64encode(b"admin:s3cret-value").decode()
    fake = FakeNexus(ITEMS, auth=auth)
    assert col.main(["--url", "http://localhost:8081", "--out", str(tmp_path / "s"),
                     "--repository", "npm-proxy"], opener=fake) == 0
    assert all(a == auth for _, a in fake.seen) and not any("s3cret" in u for u, _ in fake.seen)
    assert col.main(["--url", "http://nexus.example.org", "--out", str(tmp_path / "t")], opener=fake) == 2
    err = capsys.readouterr()
    assert "plain http" in err.err and "s3cret" not in err.out + err.err


def test_wrong_password_says_so(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("NEXUS_USERNAME", "admin")
    monkeypatch.setenv("NEXUS_PASSWORD", "wrong")
    assert col.main(["--url", "http://localhost:8081", "--out", str(tmp_path / "s")],
                    opener=FakeNexus(ITEMS, auth="Basic other")) == 2
    assert "HTTP 401" in capsys.readouterr().err


def test_unknown_repository_and_page_cap(tmp_path, capsys):
    assert col.main(["--url", "http://localhost:8081", "--out", str(tmp_path / "s"), "--repository", "nope"],
                    opener=FakeNexus(ITEMS)) == 2
    assert "no such repository: nope" in capsys.readouterr().err
    assert col.main(["--url", "http://localhost:8081", "--out", str(tmp_path / "s"), "--repository", "npm-proxy",
                     "--max-pages", "1"], opener=FakeNexus(ITEMS)) == 2
    assert "more than 1 pages" in capsys.readouterr().err


@pytest.mark.parametrize("fmt, item, expected", [
    ("npm", {"group": "@types", "name": "node", "version": "20.1.0"}, "pkg:npm/%40types/node@20.1.0"),
    ("npm", {"group": None, "name": "@ctrl/tinycolor", "version": "4.1.1"}, "pkg:npm/%40ctrl/tinycolor@4.1.1"),
    ("pypi", {"name": "PyYAML", "version": "5.3"}, "pkg:pypi/pyyaml@5.3"),
    ("maven2", {"group": None, "name": "x", "version": "1"}, None),
    ("go", {"name": "golang.org/x/net", "version": "v0.17.0"}, "pkg:golang/golang.org/x/net@v0.17.0"),
    ("nuget", {"name": "Newtonsoft.Json", "version": "12.0.1"}, "pkg:nuget/Newtonsoft.Json@12.0.1"),
    ("go", {"name": "github.com/!burnt!sushi/toml", "version": "v1.3.2"},
     "pkg:golang/github.com/BurntSushi/toml@v1.3.2"),
    ("rubygems", {"name": "nokogiri", "version": "1.13.10-x86_64-linux"},
     "pkg:gem/nokogiri@1.13.10?platform=x86_64-linux")])
def test_purls(fmt, item, expected):
    assert col.purl(fmt, item) == expected


# --- a real Nexus (3.x Community Edition in Docker, 30 Oct 2026), recorded by try-nexus.sh -----------------------

REC = json.loads((ROOT / "tests" / "fixtures" / "nexus" / "recorded.json").read_text(encoding="utf-8"))


class RecordedNexus:
    def __call__(self, req):
        u = urlparse(req.full_url)
        if u.path == "/service/rest/v1/repositories":
            return io.BytesIO(json.dumps(REC["repositories"]).encode())
        repo = parse_qs(u.query)["repository"][0]
        pages = REC["components"].get(repo, [{"items": [], "continuationToken": None}])
        return io.BytesIO(json.dumps(pages[0]).encode())


def test_recorded_real_nexus(tmp_path, capsys):
    out = tmp_path / "s"
    assert col.main(["--url", "http://localhost:18081", "--out", str(out)], opener=RecordedNexus()) == 0
    entries, _, info = sbom.read(out / "all")
    assert sorted(e["purl"] for e in entries) == [
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", "pkg:npm/%40babel/traverse@7.22.0",
        "pkg:npm/lodash@4.17.15", "pkg:npm/minimist@1.2.0", "pkg:pypi/django@2.2", "pkg:pypi/urllib3@1.24.1"]
    assert info["not_checked"] == []
    doc = json.loads((out / "all" / "pypi-proxy.cdx.json").read_text(encoding="utf-8"))
    django = next(c for c in doc["components"] if c["name"] == "django")
    # the wheel's checksums, not those of the .metadata file Nexus also caches
    assert {"alg": "SHA-256", "content": "a2814bffd1f007805b19194eb0b9a331933b82bd5da1c3ba3d7b7ba16e06dc4b"} \
        in django["hashes"]
    written = "".join(p.read_text(encoding="utf-8") for p in (out / "all").iterdir())
    assert '"admin"' not in written  # who pulled each package through the proxy stays in Nexus
    printed = capsys.readouterr().out
    assert "nuget-hosted: hosted" in printed and "maven-public: a group" in printed
