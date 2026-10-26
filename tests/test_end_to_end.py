import csv
import json
import sys

import pytest

from oss_intake import cli
from oss_intake.health import releases, scorecard
from oss_intake.models import parse_datetime

from .conftest import FakeHttp

AS_OF = "2026-10-22"


def run(tmp_path, fixtures, http, *extra):
    out = tmp_path / "reports"
    argv = ["--image", "example/webapp:2.0.0", "--repo", "example/webapp", "--out", str(out),
            "--from-trivy-json", str(fixtures / "trivy.json"), "--from-grype-json", str(fixtures / "grype.json"),
            "--scanners", "trivy,grype,osv", "--as-of", AS_OF, *extra]
    return cli.main(argv, http=http), out


def test_full_assessment(tmp_path, fixtures, fake_http, capsys):
    code, out = run(tmp_path, fixtures, fake_http, "--likelihood")
    assert code == 0
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    lag = a["lag"]
    assert lag["total"] == 7
    assert lag["with_fix"] == 6
    assert lag["fix_date_known"] == 6 and lag["fix_date_unknown"] == 0  # libc6 dated from its USN advisory
    assert lag["fix_available_at_release"] == 4
    assert lag["fix_available_at_release_by_severity"]["CRITICAL"] == 1
    assert lag["fix_after_release"] == 2
    assert lag["oldest_available_fix"]["id"] == "CVE-2099-0001"
    assert lag["oldest_available_fix"]["days"] == 290
    assert lag["kev_with_fix"] == 1
    assert a["health"]["scanned_release"] == {"tag": "v2.0.0", "date": "2026-04-30T15:01:38+00:00", "matched": True}
    assert a["health"]["days_since_latest_release"] == 175
    assert a["health"]["releases_last_365d"] == 4
    assert a["scorecard"]["low_checks"] == ["Branch-Protection"]
    assert a["likelihood"]["level"] == 5 and a["likelihood"]["heuristic"] is True
    assert a["agreement"]["by_source"] == {"trivy": 5, "grype": 3, "osv": 2}

    rows = list(csv.DictReader((out / "findings.csv").open(encoding="utf-8", newline="")))
    by_id = {r["id"]: r for r in rows}
    assert by_id["CVE-2099-0001"]["sources"] == "grype;osv;trivy"
    assert by_id["CVE-2099-0001"]["fix_version_used"] == "6.1.12"
    assert by_id["CVE-2099-0001"]["fix_available_at_release"] == "yes"
    assert by_id["CVE-2099-0006"]["severity"] == "CRITICAL" and by_id["CVE-2099-0006"]["sources"] == "osv"
    assert by_id["CVE-2099-0003"]["kev"] == "yes"
    assert by_id["CVE-2099-0003"]["epss"] == "0.6123" and by_id["CVE-2099-0001"]["epss_percentile"] == "0.800"
    assert a["epss"]["scored"] == 2 and a["epss"]["model_date"] == "2026-10-21"
    assert a["lag"]["max_epss_with_fix"] == pytest.approx(0.6123)
    assert by_id["CVE-2099-1000"]["fix_published"] == "2026-02-10"
    assert by_id["CVE-2099-1000"]["fix_date_source"] == "advisory USN-9999-1"
    assert by_id["CVE-2099-0001"]["fix_date_source"] == "deps.dev"
    assert by_id["CVE-2099-0004"]["title"].startswith("'=")  # formula injection neutralised
    assert "triage_reachable" in rows[0]
    assert by_id["CVE-2099-0002"]["exploit_level"] == "weaponised"
    assert by_id["CVE-2099-0003"]["exploit_level"] == "kev"
    assert a["exploits"]["sources"] == {"metasploit": 1, "nuclei": 1, "exploit-db": 1}
    assert a["lag"]["exploits_checked"] is True
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "weaponised" in html
    assert by_id["CVE-2099-0003"]["suggested_group"] == "Act now"
    assert a["triage"]["groups"]["act"]["total"] == 3
    assert "## Suggested triage" in (out / "summary.md").read_text(encoding="utf-8")

    md = (out / "summary.md").read_text(encoding="utf-8")
    assert "version matching, not proof of exploitability" in md
    assert "## Fix date coverage" in md
    cov = {c["ecosystem"]: c for c in a["coverage"]}
    assert cov["maven"]["percent"] == 100 and cov["ubuntu"]["dated"] == 1
    assert "heuristic" in md
    assert "\u2014" not in md  # house style: no em dashes
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "<script" not in html and "&#x27;=HYPERLINK" not in html  # escaped, top table does not show titles
    assert "findings=7 critical=2 high=4" in capsys.readouterr().out


def test_offline_and_min_severity(tmp_path, fixtures):
    out = tmp_path / "r"
    code = cli.main(["--image", "example/webapp:2.0.0", "--out", str(out), "--offline",
                     "--from-trivy-json", str(fixtures / "trivy.json"), "--scanners", "trivy",
                     "--min-severity", "high", "--formats", "json", "--release-date", "2026-04-30",
                     "--as-of", AS_OF])
    assert code == 0
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert a["lag"]["total"] == 4 and a["lag"]["fix_date_known"] == 0
    assert (out / "findings.csv").exists()  # always written: the reports point to it


def test_fail_on_likelihood(tmp_path, fixtures, fake_http):
    code, _ = run(tmp_path, fixtures, fake_http, "--fail-on-likelihood", "4")
    assert code == cli.EXIT_THRESHOLD


def test_enrichment_failures_are_warnings(tmp_path, fixtures):
    http = FakeHttp(fail_hosts=("api.osv.dev", "api.deps.dev", "cisa.gov"))
    code, out = run(tmp_path, fixtures, http)
    assert code == 0
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert any("OSV lookup failed" in w for w in a["warnings"])
    assert a["lag"]["fix_date_known"] == 0


@pytest.mark.parametrize("argv,msg", [
    (["--image=-rm/x:1", "--out", "o"], "not a valid image"),
    (["--image", "Example/Web App:1", "--out", "o"], "not a valid image"),
    (["--image", "example/webapp", "--out", "o"], "explicit tag"),
    (["--repo", "not a repo", "--out", "o"], "owner/name"),
    (["--repo", "a/b", "--out", "o", "--formats", "pdf"], "unknown value"),
    (["--repo", "a/b", "--out", "o", "--as-of", "22/10/2026"], "YYYY-MM-DD"),
    (["--image", "a/b:1", "--out", "o", "--offline", "--scanners", "trivy,osv"], "--offline"),
    (["--image", "a/b:1", "--out", "o", "--scanners", "osv"], "needs the package list"),
    (["--out", "o"], "give --image"),
])
def test_validation_errors(argv, msg, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert cli.main(argv) == cli.EXIT_USAGE
    assert msg in capsys.readouterr().err


def test_repo_url_normalised():
    assert cli.validate_repo("https://github.com/example/webapp.git") == "example/webapp"
    assert cli.image_tag("ghcr.io/o/n:1.2.3") == "1.2.3"
    assert cli.image_tag("localhost:5000/o/n@sha256:" + "a" * 64) is None


def test_scorecard_404_is_not_scored():
    sc = scorecard.fetch(FakeHttp(scorecard_status=404), "example/webapp")
    assert sc["status"] == "not_scored" and "not a negative signal" in sc["note"]


def test_release_tag_not_found_warns():
    h = releases.fetch(FakeHttp(), "example/webapp", parse_datetime(AS_OF), image_tag="3.0.0")
    assert h["scanned_release"] is None and h["scanned_is_latest"] is None  # no silent fallback
    assert any("No GitHub release matches" in w for w in h["warnings"])


@pytest.mark.parametrize("tag", ["2.0.0-alpine", "v2.0.0", "2.0.0-jdk21"])
def test_release_tag_variant_suffix(tag):
    h = releases.fetch(FakeHttp(), "example/webapp", parse_datetime(AS_OF), image_tag=tag)
    assert h["scanned_release"]["tag"] == "v2.0.0"


def test_release_candidates():
    c = releases._candidates("2.528-jdk21", "jenkins")
    assert "jenkins-2.528" in c and c[0] == "2.528-jdk21"
    assert "release-1.29.2" in releases._candidates("1.29.2-alpine", "nginx")


def test_github_token_only_sent_to_github(monkeypatch):
    from oss_intake.http import RequestsHttp

    h = RequestsHttp(github_token="secret-value")
    assert h._headers("https://api.github.com/repos/a/b")["Authorization"] == "Bearer secret-value"
    for url in ("https://api.osv.dev/v1/querybatch", "https://api.github.com.evil.example/x",
                "https://api.deps.dev/v3/systems"):
        assert "Authorization" not in h._headers(url)


class _TagHttp(FakeHttp):
    def get_json(self, url, params=None):
        if url == "https://api.github.com/repos/example/webapp/releases/tags/v1.0.0":
            return 200, {"tag_name": "v1.0.0", "published_at": "2024-01-01T00:00:00Z", "prerelease": False}
        return super().get_json(url, params)


def test_release_found_beyond_first_page():
    h = releases.fetch(_TagHttp(), "example/webapp", parse_datetime(AS_OF), image_tag="1.0.0")
    assert h["scanned_release"]["tag"] == "v1.0.0" and h["scanned_is_latest"] is False
    assert "v2.0.0" in h["newer_stable_releases"]


def test_outdated_release_note(tmp_path, fixtures):
    class OldTag(FakeHttp):
        pass

    out = tmp_path / "old"
    code = cli.main(["--image", "example/webapp:1.9.0", "--repo", "example/webapp", "--out", str(out),
                     "--from-trivy-json", str(fixtures / "trivy.json"), "--scanners", "trivy",
                     "--as-of", AS_OF, "--likelihood", "--formats", "md"], http=OldTag())
    assert code == 0
    md = (out / "summary.md").read_text(encoding="utf-8")
    assert "not the project's latest (newer: v2.0.0" in md


@pytest.mark.parametrize("extra,source", [([], "image build date"), (["--no-image-date"], None),
                                          (["--release-date", "2026-01-01"], "--release-date")])
def test_image_build_date_fallback(tmp_path, fixtures, extra, source):
    report = json.loads((fixtures / "trivy.json").read_text(encoding="utf-8"))
    report["Metadata"]["ImageConfig"] = {"created": "2026-04-20T08:00:00Z"}
    src = tmp_path / "trivy.json"
    src.write_text(json.dumps(report), encoding="utf-8")
    out = tmp_path / "r"
    code = cli.main(["--image", "example/webapp:2.0.0", "--out", str(out), "--offline", "--scanners", "trivy",
                     "--from-trivy-json", str(src), "--formats", "json,md", "--as-of", AS_OF, *extra])
    assert code == 0
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert a["lag"]["release_date_source"] == source
    if source == "image build date":
        assert a["lag"]["release_date"].startswith("2026-04-20")
        assert a["lag"]["unshipped"] is None  # needs a matched release
        assert any("image build date" in w for w in a["warnings"])
        assert "no matching release; image build date 2026-04-20 used" in (out / "summary.md").read_text(
            encoding="utf-8")
    elif source is None:
        assert a["lag"]["release_date"] is None


@pytest.mark.parametrize("tag,expected", [("4.5.1", "R4.5.1"), ("31.0.9", "server-31.0.9")])
def test_release_tag_prefix_by_version_core(tag, expected):
    class Prefixed(FakeHttp):
        def get_json(self, url, params=None):
            if url == "https://api.github.com/repos/example/webapp/releases":
                return 200, [{"tag_name": expected, "published_at": "2026-05-01T00:00:00Z", "prerelease": False},
                             {"tag_name": "R4.4.3", "published_at": "2025-03-01T00:00:00Z", "prerelease": False}]
            return super().get_json(url, params)

    h = releases.fetch(Prefixed(), "example/webapp", parse_datetime(AS_OF), image_tag=tag)
    assert h["scanned_release"]["tag"] == expected


def test_release_tag_core_ambiguous_is_not_guessed():
    class Ambiguous(FakeHttp):
        def get_json(self, url, params=None):
            if url == "https://api.github.com/repos/example/webapp/releases":
                return 200, [{"tag_name": "api-1.2.0", "published_at": "2026-05-01T00:00:00Z"},
                             {"tag_name": "ui-1.2.0", "published_at": "2026-05-02T00:00:00Z"}]
            return super().get_json(url, params)

    h = releases.fetch(Ambiguous(), "example/webapp", parse_datetime(AS_OF), image_tag="1.2.0")
    assert h["scanned_release"] is None


def test_path_input_labels_report(tmp_path, fixtures, capsys):
    jar = tmp_path / "webapp-2.0.0.jar"
    jar.write_bytes(b"PK")
    out = tmp_path / "reports"
    code = cli.main(["--path", str(jar), "--out", str(out), "--from-trivy-json", str(fixtures / "trivy.json"),
                     "--from-grype-json", str(fixtures / "grype.json"), "--scanners", "trivy,grype", "--offline",
                     "--as-of", AS_OF, "--release-date", "2026-04-30"])
    assert code == 0
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    assert a["inputs"]["path_kind"] == "artifact" and a["lag"]["total"] > 0
    md = (out / "summary.md").read_text(encoding="utf-8")
    assert md.startswith("# OSS intake assessment: webapp-2.0.0.jar") and "| Artifact |" in md
    plan = [line for line in capsys.readouterr().err.splitlines() if "plan:" in line]
    assert plan and "platform=" not in plan[0] and "image-src=" not in plan[0]  # image-only settings


def test_path_input_validation(tmp_path):
    with _raises_usage():
        cli.cmd_scan(cli.build_parser().parse_args(["scan", "--path", str(tmp_path / "missing.jar"),
                                                    "--out", str(tmp_path / "o")]))
    lock = tmp_path / "renv.lock"
    lock.write_text('{"Packages": {}}', encoding="utf-8")
    with _raises_usage():
        cli.cmd_scan(cli.build_parser().parse_args(["scan", "--path", str(lock), "--offline",
                                                    "--out", str(tmp_path / "o")]))
    with _raises_usage():
        cli.cmd_scan(cli.build_parser().parse_args(["scan", "--path", str(lock), "--image", "a/b:1",
                                                    "--out", str(tmp_path / "o")]))


def _raises_usage():
    return pytest.raises(cli.UsageError)


def test_malicious_package_marks_every_finding_on_it(tmp_path):
    import json as _json

    trivy = {"SchemaVersion": 2, "ArtifactName": "x", "Results": [{"Target": "package-lock.json", "Class": "lang-pkgs",
             "Type": "npm", "Vulnerabilities": [
                 {"VulnerabilityID": "MAL-2099-1", "PkgName": "evil", "InstalledVersion": "0.1.1",
                  "PkgIdentifier": {"PURL": "pkg:npm/evil@0.1.1"}},
                 {"VulnerabilityID": "GHSA-aaaa-bbbb-cccc", "PkgName": "evil", "InstalledVersion": "0.1.1",
                  "Severity": "LOW", "PkgIdentifier": {"PURL": "pkg:npm/evil@0.1.1"}}]}]}
    tj = tmp_path / "t.json"
    tj.write_text(_json.dumps(trivy), encoding="utf-8")
    lock = tmp_path / "package-lock.json"
    lock.write_text("{}", encoding="utf-8")
    out = tmp_path / "o"
    code = cli.main(["--path", str(lock), "--out", str(out), "--from-trivy-json", str(tj), "--scanners", "trivy",
                     "--offline", "--min-severity", "HIGH", "--likelihood"])
    assert code == 0
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    groups = {f["id"]: f["suggested_group"] for f in a["findings"]}
    assert groups == {"MAL-2099-1": "Act now", "GHSA-aaaa-bbbb-cccc": "Act now"}  # LOW kept despite the filter
    assert a["likelihood"]["level"] == 5 and a["warnings"][0].startswith("MALICIOUS PACKAGE")


def test_cwe_506_advisory_is_malicious(tmp_path):
    """A compromised release with a CWE-506 advisory but no MAL- entry goes to Act now, not Routine."""
    import json as _json

    trivy = {"SchemaVersion": 2, "ArtifactName": "x", "Results": [{"Target": "package-lock.json", "Class": "lang-pkgs",
             "Type": "npm", "Vulnerabilities": [
                 {"VulnerabilityID": "CVE-2021-4229", "PkgName": "ua-parser-js", "InstalledVersion": "0.7.29",
                  "Severity": "HIGH", "CweIDs": ["CWE-506", "CWE-912"], "FixedVersion": "0.7.30",
                  "Title": "Embedded malware in ua-parser-js",
                  "PkgIdentifier": {"PURL": "pkg:npm/ua-parser-js@0.7.29"}}]}]}
    tj = tmp_path / "t.json"
    tj.write_text(_json.dumps(trivy), encoding="utf-8")
    lock = tmp_path / "package-lock.json"
    lock.write_text("{}", encoding="utf-8")
    out = tmp_path / "o"
    assert cli.main(["--path", str(lock), "--out", str(out), "--from-trivy-json", str(tj), "--scanners", "trivy",
                     "--offline"]) == 0
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    (f,) = a["findings"]
    assert f["suggested_group"] == "Act now" and f["cwes"] == "CWE-506;CWE-912"
    assert "ua-parser-js@0.7.29" in a["warnings"][0]
    assert a["lag"]["malicious_packages"] == ["ua-parser-js@0.7.29"]
    html = (out / "report.html").read_text(encoding="utf-8")
    assert '<header class="c">' in html and "Malicious packages" in html
    assert html.index("MALICIOUS PACKAGE") < html.index("Findings by severity")  # warnings before the detail


@pytest.mark.skipif(sys.platform == "win32", reason="the stand-in govulncheck is a #! script, which Windows "
                                                   "cannot run by path; the parsing is covered by unit tests")
def test_reachability_on_path_dir(tmp_path, fixtures):
    import json as _json
    import stat

    app = tmp_path / "app"
    (app / "bin").mkdir(parents=True)
    (app / "bin" / "server").write_bytes(b"\x7fELF")
    vuln = {"PkgName": "stdlib", "InstalledVersion": "v1.21.0", "FixedVersion": "1.21.5", "Severity": "HIGH",
            "PkgIdentifier": {"PURL": "pkg:golang/stdlib@v1.21.0"}}
    trivy = {"SchemaVersion": 2, "Results": [{"Target": "bin/server", "Class": "lang-pkgs", "Type": "gobinary",
             "Vulnerabilities": [{**vuln, "VulnerabilityID": "CVE-2099-7777"},
                                 {**vuln, "VulnerabilityID": "CVE-2099-7778"}]}]}
    tj = tmp_path / "t.json"
    tj.write_text(_json.dumps(trivy), encoding="utf-8")
    fake = tmp_path / "govulncheck"
    fake.write_text(f"#!{sys.executable}\n" + (fixtures / "fake_govulncheck.py").read_text(encoding="utf-8"),
                    encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IEXEC)
    out = tmp_path / "o"
    code = cli.main(["--path", str(app), "--out", str(out), "--from-trivy-json", str(tj), "--scanners", "trivy",
                     "--offline", "--reachability", "--govulncheck-path", str(fake)])
    assert code == 0
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    by = {f["id"]: f for f in a["findings"]}
    assert by["CVE-2099-7777"]["reachability"] == "reachable"
    assert by["CVE-2099-7778"]["reachability"] == "not reachable"
    assert by["CVE-2099-7778"]["suggested_group"] == "Set aside"
    assert a["scanners"]["govulncheck"]["version"] == "1.1.4"


def test_no_repo_no_release_date(tmp_path, fixtures, capsys):
    """Without --repo or a release date the report says so instead of showing empty or reassuring numbers."""
    out = tmp_path / "r"
    code = cli.main(["--image", "example/webapp:2.0.0", "--out", str(out), "--offline",
                     "--from-trivy-json", str(fixtures / "trivy.json"), "--scanners", "trivy",
                     "--formats", "html,md", "--as-of", AS_OF])
    assert code == 0
    assert (out / "findings.csv").exists()
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "no release date: pass --repo or --release-date" in html
    assert "not shipped in the scanned release" not in html
    assert "No repository given" in html and "Days since last push" not in html
    md = (out / "summary.md").read_text(encoding="utf-8")
    assert "No repository given" in md and "Days since last push" not in md


def _osv_vuln(vid, purl, fixed=None, severity="HIGH", aliases=()):
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    return {"id": vid, "aliases": list(aliases), "summary": f"synthetic advisory {vid}",
            "database_specific": {"severity": severity},
            "affected": [{"package": {"purl": purl}, "ranges": [{"type": "SEMVER", "events": events}]}]}


def test_inventory_csv(tmp_path):
    """A package inventory is validated, checked against OSV only, and reported per package with its labels."""
    from .conftest import FakeHttp

    vulns = {
        "pkg:npm/acme-widget@1.0.0": [_osv_vuln("GHSA-test-inv1-aaaa", "pkg:npm/acme-widget", "1.2.0", "CRITICAL"),
                                      _osv_vuln("GHSA-test-inv2-bbbb", "pkg:npm/acme-widget", "1.1.0")],
        "pkg:npm/%40acme/scoped@2.0.0": [_osv_vuln("MAL-2099-0001", "pkg:npm/%40acme/scoped", severity="")],
        "pkg:pypi/acme-lib@3.0.0": [_osv_vuln("GHSA-test-inv3-cccc", "pkg:pypi/acme-lib", None, "MODERATE")],
    }
    by_id = {v["id"]: v for vs in vulns.values() for v in vs}

    class InventoryHttp(FakeHttp):
        def post_json(self, url, body):
            self._check(url)
            assert url == "https://api.osv.dev/v1/querybatch"
            return 200, {"results": [{"vulns": [{"id": v["id"]} for v in vulns.get(q["package"]["purl"], [])]}
                                     for q in body["queries"]]}

        def get_json(self, url, params=None):
            if url.startswith("https://api.osv.dev/v1/vulns/"):
                self._check(url)
                return 200, by_id[url.rsplit("/", 1)[1]]
            return super().get_json(url, params)

    inv = tmp_path / "packages.csv"
    inv.write_text("﻿Ecosystem,Name,Version,Owner,System\n"
                   "npm,acme-widget,1.0.0,Team A,Web\n"
                   "npm,@acme/scoped,2.0.0,Team B,Web\n"
                   "Python,Acme_Lib,3.0.0,Team C,Payroll\n"
                   "npm,clean-pkg,1.0.0,Team A,Web\n"
                   "npm,acme-widget,1.0.0,Team D,Web\n", encoding="utf-8")
    out = tmp_path / "o"
    http = InventoryHttp()
    assert cli.main(["--path", str(inv), "--out", str(out), "--no-scorecard", "--no-workflows"], http=http) == 0
    assert not any("trivy" in c or "grype" in c for c in http.calls)
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    inv_a = a["inventory"]
    assert (inv_a["packages"], inv_a["with_findings"], inv_a["malicious"]) == (4, 3, 1)
    rows = {r["package"]: r for r in inv_a["rows"]}
    assert rows["@acme/scoped"]["group"] == "Act now" and rows["@acme/scoped"]["upgrade_to"].startswith("remove")
    assert rows["acme-widget"]["upgrade_to"] == "1.2.0" and rows["acme-widget"]["findings"] == 2
    assert rows["acme-widget"]["labels"] == {"owner": "Team A; Team D", "system": "Web"}
    assert rows["acme-lib"]["no_fix"] == 1 and rows["clean-pkg"]["findings"] == 0
    assert inv_a["rows"][0]["package"] == "@acme/scoped"  # worst first
    pk = list(csv.DictReader((out / "packages.csv").open(encoding="utf-8", newline="")))
    assert [r["package"] for r in pk][-1] == "clean-pkg" and pk[0]["owner"] == "Team B" and pk[0]["malicious"] == "yes"
    findings = list(csv.DictReader((out / "findings.csv").open(encoding="utf-8", newline="")))
    assert all("owner=" in f["labels"] for f in findings)
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "<h2>Packages</h2>" in html and "4 packages checked" in html and "Team B" in html
    assert "Packages checked" in html and "Fix existed before release</div>" not in html
    assert not any("release date" in w for w in a["warnings"])
    assert "## Packages" in (out / "summary.md").read_text(encoding="utf-8")


def test_inventory_invalid_rows_stop_before_lookup(tmp_path, capsys):
    from .conftest import FakeHttp

    inv = tmp_path / "packages.csv"
    inv.write_text("ecosystem,name,version\nnpm,acme-widget,^1.0.0\ncobol,thing,1\nmaven,no-group,2.0\n",
                   encoding="utf-8")
    http = FakeHttp()
    assert cli.main(["--path", str(inv), "--out", str(tmp_path / "o")], http=http) == 2
    err = capsys.readouterr().err
    assert "3 invalid row(s)" in err and "row 2:" in err and "row 3:" in err and "row 4:" in err
    assert http.calls == []
