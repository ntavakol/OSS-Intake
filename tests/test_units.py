from datetime import datetime, timezone

import pytest

from oss_intake import cvss, integrity, likelihood, merge, versions
from oss_intake.models import canonical_id, normalise_purl, parse_datetime, purl_without_version
from oss_intake.scanners import grype, trivy

from .conftest import load

# ------------------------------------------------------------- parsing helpers

@pytest.mark.parametrize("value,expected", [
    ("2026-01-10T06:15:11.94Z", datetime(2026, 1, 10, 6, 15, 11, 940000, tzinfo=timezone.utc)),
    ("2026-04-30T15:01:38Z", datetime(2026, 4, 30, 15, 1, 38, tzinfo=timezone.utc)),
    ("2026-03-01T12:00:00+10:00", datetime(2026, 3, 1, 2, 0, tzinfo=timezone.utc)),
    ("2026-10-22", datetime(2026, 10, 22, tzinfo=timezone.utc)),
    ("not a date", None), ("", None), (None, None),
])
def test_parse_datetime(value, expected):
    assert parse_datetime(value) == expected


def test_purl_normalisation():
    a = "pkg:maven/org.springframework/spring-web@6.1.10?package-id=abc"
    b = "pkg:MAVEN/org.springframework/spring-web@6.1.10"
    assert normalise_purl(a) == normalise_purl(b)
    assert purl_without_version(a) == "pkg:maven/org.springframework/spring-web"
    assert normalise_purl("not-a-purl") is None


def test_canonical_id_prefers_cve():
    assert canonical_id("GHSA-x", {"CVE-2099-1"}) == "CVE-2099-1"
    assert canonical_id("cve-2099-2") == "CVE-2099-2"
    assert canonical_id("GHSA-y", set()) == "GHSA-y"


@pytest.mark.parametrize("a,b,expected", [
    ("6.1.12", "6.1.10", 1), ("4.1.108.Final", "4.1.100.Final", 1), ("1.0", "1.0.0", 0),
    ("1.0-rc1", "1.0", -1), ("2.10", "2.9", 1), ("v1.2.3", "1.2.3", 0), ("1:2.0", "1.9", 1),
])
def test_version_compare(a, b, expected):
    assert versions.compare(a, b) == expected


def test_nearest_fix_picks_same_line():
    assert versions.nearest_fix("6.1.10", ["6.1.12", "5.3.39", "6.2.1"]) == "6.1.12"
    assert versions.nearest_fix("12.2.0", ["1.9.2-0.20260616075434-82ef13993059"]) is None
    assert versions.split_fixed("6.1.12, 5.3.39") == ["6.1.12", "5.3.39"]


@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:2.0/AV:N", None), ("garbage", None),
])
def test_cvss(vector, score):
    assert cvss.base_score(vector) == score


# ------------------------------------------------------------- scanners and merge

def test_trivy_parse():
    findings, info = trivy.parse(load("trivy.json"))
    assert len(findings) == 5
    f = next(x for x in findings if x.vuln_id == "CVE-2099-0001")
    assert f.fixed_versions == ["6.1.12", "5.3.39"] and f.cvss == 9.8 and f.severity == "CRITICAL"
    assert f.target == "opt/webapp/webapp.jar"
    assert info["os"] == "ubuntu 24.04"
    assert not next(x for x in findings if x.vuln_id == "CVE-2099-0004").has_fix


def test_grype_parse():
    findings, _ = grype.parse(load("grype.json"))
    assert {f.vuln_id for f in findings} == {"GHSA-test-0001-aaaa", "GHSA-test-0005-bbbb", "CVE-2099-1000"}
    f = findings[0]
    assert f.aliases == {"CVE-2099-0001"} and f.severity == "CRITICAL" and f.fixed_versions == ["6.1.12"]


def test_grype_source_prefix():
    assert grype.source_for("a/b:1", "remote") == "registry:a/b:1"
    assert grype.source_for("a/b:1", None) == "a/b:1"


def test_merge_trivy_and_grype():
    t, _ = trivy.parse(load("trivy.json"))
    g, _ = grype.parse(load("grype.json"))
    merged = merge.merge(t, g)
    ids = [f.vuln_id for f in merged]
    assert len(merged) == 6
    assert ids[0] == "CVE-2099-0001"  # sorted by severity first
    spring = merged[0]
    assert spring.sources == {"trivy", "grype"} and "GHSA-test-0001-aaaa" in spring.aliases
    libc = next(f for f in merged if f.vuln_id == "CVE-2099-1000")
    assert libc.sources == {"trivy", "grype"}
    agreement = merge.source_agreement(merged, ["trivy", "grype"])
    assert agreement["only"] == {"trivy": 3, "grype": 1} and agreement["all_enabled"] == 2


# ------------------------------------------------------------- integrity

def test_parse_checksums_bytes_crlf_bom_star():
    h1, h2 = "a" * 64, "B" * 64
    data = ("﻿" + f"{h1}  trivy_0.76.1_Linux-64bit.tar.gz\r\n{h2} *trivy_0.76.1_windows-64bit.zip\r\n\r\n"
            ).encode("utf-8")
    table = integrity.parse_checksums(data)
    assert table == {"trivy_0.76.1_Linux-64bit.tar.gz": h1, "trivy_0.76.1_windows-64bit.zip": h2.lower()}


def test_parse_checksums_rejects_text():
    with pytest.raises(TypeError):
        integrity.parse_checksums("abc")


def test_verify_against_checksums(tmp_path):
    f = tmp_path / "tool.tar.gz"
    f.write_bytes(b"hello\n")
    digest = integrity.sha256_file(f)
    (tmp_path / "sums.txt").write_bytes(f"{digest}  tool.tar.gz\n".encode())
    assert integrity.verify_against_checksums(f, tmp_path / "sums.txt") == digest
    (tmp_path / "bad.txt").write_bytes(f"{'0' * 64}  tool.tar.gz\n".encode())
    with pytest.raises(integrity.IntegrityError, match="mismatch"):
        integrity.verify_against_checksums(f, tmp_path / "bad.txt")
    with pytest.raises(integrity.IntegrityError, match="not listed"):
        integrity.verify_against_checksums(f, tmp_path / "bad.txt", name="other")
    assert integrity.verify_sha256(f, "SHA256:" + digest.upper()) == digest


@pytest.mark.parametrize("version", ["0.69.4", "v0.69.5", "0.69.6"])
def test_known_bad_trivy(version, tmp_path):
    assert integrity.known_bad_entry("trivy", version)
    exe = tmp_path / "trivy"
    exe.write_bytes(b"x")
    with pytest.raises(integrity.IntegrityError, match="known-bad"):
        integrity.check_binary("trivy", str(exe), version, None, None, None, None)


def test_check_binary_policy(tmp_path):
    exe = tmp_path / "trivy"
    exe.write_bytes(b"binary")
    good = integrity.sha256_file(exe)
    ok = integrity.check_binary("trivy", str(exe), "0.76.1", "0.76.1", good, None, None)
    assert ok.hash_verified and not ok.notes
    loose = integrity.check_binary("trivy", str(exe), "0.76.1", None, None, None, None)
    assert not loose.hash_verified and len(loose.notes) == 2
    with pytest.raises(integrity.IntegrityError, match="pinned"):
        integrity.check_binary("trivy", str(exe), "0.76.0", "0.76.1", None, None, None)
    with pytest.raises(integrity.IntegrityError, match="mismatch"):
        integrity.check_binary("trivy", str(exe), "0.76.1", None, "f" * 64, None, None)
    assert not integrity.known_bad_entry("trivy", "0.69.3")


# ------------------------------------------------------------- likelihood

def test_likelihood_default_rules():
    cfg = likelihood.DEFAULT_CONFIG
    base = {"critical_fix_at_release": 0, "high_fix_at_release": 0, "critical_with_fix": 0, "high_with_fix": 0,
            "kev_with_fix": 0, "days_since_latest_release": 30, "archived": 0, "scorecard_score": 7}
    assert likelihood.evaluate(cfg, base)["level"] == 1
    assert likelihood.evaluate(cfg, {**base, "high_with_fix": 1})["level"] == 2
    assert likelihood.evaluate(cfg, {**base, "critical_fix_at_release": 1})["level"] == 3
    assert likelihood.evaluate(cfg, {**base, "critical_fix_at_release": 1, "scorecard_score": 3})["level"] == 4
    assert likelihood.evaluate(cfg, {**base, "kev_with_fix": 1})["level"] == 5
    # Unknown signals never trigger a rule.
    assert likelihood.evaluate(cfg, {**base, "critical_fix_at_release": 1, "scorecard_score": None,
                                     "days_since_latest_release": None})["level"] == 3


def test_likelihood_config_validation(tmp_path):
    p = tmp_path / "rules.json"
    p.write_text('{"rules": [{"level": 9, "all": []}]}', encoding="utf-8")
    with pytest.raises(likelihood.ConfigError):
        likelihood.load_config(str(p))
    p.write_text('{"rules": [{"level": 2, "all": [{"metric": "high_with_fix", "op": "~", "value": 1}]}]}')
    with pytest.raises(likelihood.ConfigError):
        likelihood.load_config(str(p))


# ------------------------------------------------------------- build labels, grace, unshipped

def test_build_labels_are_neutral():
    assert versions.compare("12.10.2.jre11", "12.10.2") == 0
    assert versions.compare("33.0.0-android", "33.0.0-jre") == 0
    assert versions.compare("12.10.2.jre11", "12.8.2.jre11") == 1
    fixed = ["10.2.4.jre11", "12.8.2.jre11", "12.10.2.jre11", "13.2.1.jre11"]
    assert versions.nearest_fix("12.8.1", fixed) == "12.8.2.jre11"
    assert versions.label_only_match("12.10.2", fixed) == "12.10.2.jre11"
    assert versions.label_only_match("12.10.1", fixed) is None
    assert versions.label_only_match("1.0", ["1.0"]) is None


def _f(**kw):
    from oss_intake.models import Finding

    base = {"vuln_id": "CVE-2099-1", "package": "p", "installed": "1.0", "severity": "CRITICAL",
            "fixed_versions": ["1.1"], "purl": "pkg:maven/g/p@1.0"}
    return Finding(**{**base, **kw})


def test_label_match_excluded_from_lag():
    from oss_intake import lag

    f = _f(installed="12.10.2", fixed_versions=["12.10.2.jre11", "13.2.1.jre11"])
    assert lag.flag_label_matches([f]) == 1 and f.likely_fixed and "build label" in f.note
    m = lag.compute([f], parse_datetime("2026-04-30"), parse_datetime("2026-10-22"))
    assert m["with_fix"] == 0 and m["likely_fixed_label_match"] == 1


def test_grace_and_unshipped():
    from oss_intake import lag

    rel, as_of = parse_datetime("2026-04-30"), parse_datetime("2026-10-22")
    early = _f(vuln_id="CVE-2099-1", fix_published=parse_datetime("2026-01-01"))
    grace = _f(vuln_id="CVE-2099-2", fix_published=parse_datetime("2026-04-28"))
    later = _f(vuln_id="CVE-2099-3", fix_published=parse_datetime("2026-06-01"))
    recent = _f(vuln_id="CVE-2099-4", fix_published=parse_datetime("2026-10-01"), severity="HIGH")
    m = lag.compute([early, grace, later, recent], rel, as_of, scanned_is_latest=True)
    assert m["fix_available_at_release"] == 1 and m["fix_within_grace"] == 1
    assert m["unshipped"] == 3 and m["unshipped_by_severity"]["CRITICAL"] == 3
    m0 = lag.compute([early], rel, as_of, grace_days=0, scanned_is_latest=False)
    assert m0["unshipped"] is None  # not the latest release: n/a, not 0
    assert lag.compute([early], rel, as_of)["unshipped"] is None  # unknown without health data


def test_unshipped_likelihood_rule():
    cfg = likelihood.DEFAULT_CONFIG
    base = {"critical_fix_at_release": 0, "high_fix_at_release": 3, "critical_with_fix": 7, "high_with_fix": 40,
            "kev_with_fix": 0, "days_since_latest_release": 175, "archived": 0, "scorecard_score": 6,
            "critical_fix_unshipped": 0, "high_fix_unshipped": 4}
    assert likelihood.evaluate(cfg, base)["level"] == 2
    assert likelihood.evaluate(cfg, {**base, "critical_fix_unshipped": 2})["level"] == 3
    assert likelihood.evaluate(cfg, {**base, "high_fix_unshipped": 10})["level"] == 3
    assert likelihood.evaluate(cfg, {**base, "critical_fix_unshipped": 1, "days_since_latest_release": 200})[
        "level"] == 4


def test_go_fix_version_gets_v_prefix():
    from oss_intake.enrich import fixdates

    class H:
        urls = []

        def get_json(self, url, params=None):
            self.urls.append(url)
            return 200, {"publishedAt": "2026-01-01T00:00:00Z"}

    h = H()
    go = _f(package="golang.org/x/net", installed="0.30.0", fixed_versions=["0.38.0"],
            purl="pkg:golang/golang.org/x/net@v0.30.0")
    std = _f(package="stdlib", installed="1.24.1", fixed_versions=["1.24.4"], purl="pkg:golang/stdlib@v1.24.1")
    stats = fixdates.enrich(h, [go, std])
    assert h.urls == ["https://api.deps.dev/v3/systems/go/packages/golang.org%2Fx%2Fnet/versions/v0.38.0"]
    assert go.fix_published and stats["unsupported"] == 1


def test_likelihood_confidence():
    m = {"with_fix": 100, "fix_date_unknown": 90, "release_date_known": 1, "critical_fix_unshipped": 0}
    assert likelihood.confidence(m)[0] == "low"
    m = {"with_fix": 100, "fix_date_unknown": 10, "release_date_known": 1, "critical_fix_unshipped": 0}
    assert likelihood.confidence(m) == ("normal", [])


def test_scanner_platform_flags():
    from oss_intake.scanners import grype as g
    from oss_intake.scanners import trivy as t

    captured = {}

    def fake_run(cmd, timeout):
        captured.setdefault("cmds", []).append(cmd)
        return b"{}"

    import oss_intake.scanners.grype as gm
    import oss_intake.scanners.trivy as tm
    orig_g, orig_t = gm.run, tm.run
    gm.run = tm.run = fake_run
    try:
        g.scan("grype", "a/b:1", "remote", [], 10, "linux/amd64")
        t.scan("trivy", "a/b:1", "remote", [], 10, "linux/amd64")
    finally:
        gm.run, tm.run = orig_g, orig_t
    gcmd, tcmd = captured["cmds"]
    assert gcmd[1] == "registry:a/b:1" and "--platform" in gcmd and "-q" not in gcmd
    assert tcmd[tcmd.index("--platform") + 1] == "linux/amd64"


def test_confidence_ignored_at_top_level():
    m = {"kev_with_fix": 1, "with_fix": 100, "fix_date_unknown": 90, "release_date_known": 0,
         "critical_fix_unshipped": None}
    r = likelihood.evaluate(likelihood.DEFAULT_CONFIG, m)
    assert r["level"] == 5 and r["confidence"] == "normal"
    r = likelihood.evaluate(likelihood.DEFAULT_CONFIG, {**m, "kev_with_fix": 0, "high_with_fix": 3})
    assert r["level"] == 2 and r["confidence"] == "low"


def test_go_incompatible_retry():
    from oss_intake.enrich import fixdates

    class H:
        urls = []

        def get_json(self, url, params=None):
            self.urls.append(url)
            if url.endswith("v12.2.2%2Bincompatible"):
                return 200, {"publishedAt": "2026-07-01T00:00:00Z"}
            return 404, None

    h = H()
    f = _f(package="github.com/grafana/grafana", installed="12.2.0", fixed_versions=["12.2.2"],
           purl="pkg:golang/github.com/grafana/grafana@v12.2.0")
    v2 = _f(package="github.com/x/y/v3", installed="3.0.0", fixed_versions=["3.1.0"],
            purl="pkg:golang/github.com/x/y/v3@v3.0.0")
    fixdates.enrich(h, [f, v2])
    assert f.fix_published == parse_datetime("2026-07-01")
    assert sum("incompatible" in u for u in h.urls) == 1  # /v3 module is not retried


def test_flag_no_newer_fix():
    from oss_intake import lag

    f = _f(installed="12.2.0", fixed_versions=["1.9.2-0.20260616075434-82ef13993059"])
    ok = _f(installed="1.0", fixed_versions=["1.1"])
    assert lag.flag_no_newer_fix([f, ok]) == 1 and "pseudo-versions" in f.note and not ok.note


def test_distro_advisory_dates():
    from oss_intake.enrich import advisories

    class H:
        def get_json(self, url, params=None):
            dates = {"DSA-5001-1": "2026-03-01T00:00:00Z", "DLA-4001-1": "2026-02-01T00:00:00Z"}
            vid = url.rsplit("/", 1)[1]
            return (200, {"id": vid, "published": dates[vid]}) if vid in dates else (404, None)

    deb = _f(vendor_ids=["DSA-5001-1", "DLA-4001-1"], purl="pkg:deb/debian/openssl@3.0.1")
    other = _f(vendor_ids=["RHSA-2026:1234", "USN-1-1"], purl="pkg:rpm/redhat/x@1")
    dated = _f(vendor_ids=["DSA-5001-1"], fix_published=parse_datetime("2026-01-01"))
    stats = advisories.enrich(H(), [deb, other, dated])
    assert deb.fix_published == parse_datetime("2026-02-01") and deb.fix_date_source == "advisory DLA-4001-1"
    assert other.fix_published is None  # RHSA not used; USN-1-1 not in OSV
    assert dated.fix_published == parse_datetime("2026-01-01")  # deps.dev date is not overwritten
    assert stats == {"candidates": 2, "found": 1, "errors": 0}


def test_go_github_release_fallback():
    from oss_intake.enrich import github_releases

    class H:
        urls = []

        def get_json(self, url, params=None):
            self.urls.append(url)
            if url.endswith("/grafana/grafana/releases/tags/v12.2.2"):
                return 200, {"tag_name": "v12.2.2", "published_at": "2026-06-10T00:00:00Z"}
            return 404, None

    h = H()
    g = _f(package="github.com/grafana/grafana", installed="12.2.0", fixed_versions=["12.2.2"],
           purl="pkg:golang/github.com/grafana/grafana@v12.2.0")
    std = _f(package="stdlib", installed="1.24.1", fixed_versions=["1.24.4"], purl="pkg:golang/stdlib@v1.24.1")
    npm = _f(package="x", purl="pkg:npm/x@1.0")
    stats = github_releases.enrich(h, [g, std, npm])
    assert g.fix_published == parse_datetime("2026-06-10")
    assert g.fix_date_source == "GitHub release grafana/grafana@v12.2.2"
    assert len(h.urls) == 1 and stats["found"] == 1


@pytest.mark.parametrize("a,b,expected", [
    ("10.42-1+deb12u1", "10.42-1", 1), ("1.6.39-2+deb12u4", "1.6.39-2+deb12u3", 1),
    ("1.6.39-2+deb12u10", "1.6.39-2+deb12u9", 1), ("2.39-0ubuntu8.5", "2.39-0ubuntu8.4", 1),
    ("1.0.0", "1.0", 0), ("1.0-beta", "1.0", -1), ("1.0-SNAPSHOT", "1.0", -1), ("1.0.1", "1.0", 1),
])
def test_version_suffix_ordering(a, b, expected):
    assert versions.compare(a, b) == expected
    assert versions.compare(b, a) == -expected


def test_debian_tracker_dates(fixtures):
    from oss_intake.enrich import debian_tracker

    from .conftest import FakeHttp

    parsed = debian_tracker.parse((fixtures / "debian_DLA_list.txt").read_text(encoding="utf-8"))
    assert parsed == {"DLA-9001-1": parse_datetime("2026-10-21"), "DLA-9000-1": parse_datetime("2026-02-03")}
    a = _f(vendor_ids=["DLA-9001-1", "DLA-9000-1"], purl="pkg:deb/debian/libsynthetic@1.0-1")
    b = _f(vendor_ids=["DSA-9500-1"], purl="pkg:deb/debian/othersynthetic@2.0-1")
    c = _f(vendor_ids=["DLA-1-1"], purl="pkg:deb/debian/x@1")
    stats = debian_tracker.enrich(FakeHttp(), [a, b, c])
    assert a.fix_published == parse_datetime("2026-02-03") and "DLA-9000-1" in a.fix_date_source
    assert b.fix_published == parse_datetime("2026-01-15")
    assert c.fix_published is None and stats["found"] == 2
    assert sorted(stats["lists_loaded"]) == ["DLA:2", "DSA:1"]


def test_coverage_by_ecosystem():
    from oss_intake import coverage

    rows = [
        _f(purl="pkg:maven/g/a@1.0", fix_published=parse_datetime("2026-01-01"), fix_date_source="deps.dev"),
        _f(purl="pkg:maven/g/b@1.0"),
        _f(purl="pkg:deb/ubuntu/libc6@2.39?distro=ubuntu-24.04"),
        _f(purl="pkg:deb/debian/libpng16-16@1.6.39-2", fix_published=parse_datetime("2026-02-01"),
           fix_date_source="advisory DLA-1-1 (Debian tracker)"),
        _f(package="stdlib", purl="pkg:golang/stdlib@v1.24.1"),
        _f(purl="pkg:apk/alpine/musl@1.2.5"),
        _f(purl=None, pkg_type="binary"),
        _f(purl="pkg:maven/g/c@1.0", likely_fixed=True),  # excluded
        _f(purl="pkg:maven/g/d@1.0", fixed_versions=[]),  # no fix, excluded
    ]
    cov = {c["ecosystem"]: c for c in coverage.compute(rows)}
    assert cov["maven"] == {"ecosystem": "maven", "with_fix": 2, "dated": 1, "percent": 50,
                            "sources": {"deps.dev": 1}, "gap": ""}
    assert cov["debian"]["sources"] == {"advisory": 1} and cov["debian"]["percent"] == 100
    assert cov["ubuntu"]["gap"].startswith("no Ubuntu Security Notice")
    assert set(cov) == {"maven", "debian", "ubuntu", "go-stdlib", "alpine", "binary"}


def test_ubuntu_ecosystem_names():
    from oss_intake.enrich import ubuntu

    assert ubuntu.osv_ecosystem("ubuntu 24.04") == "Ubuntu:24.04:LTS"
    assert ubuntu.osv_ecosystem("ubuntu 22.04.5") == "Ubuntu:22.04:LTS"
    assert ubuntu.osv_ecosystem("ubuntu 24.10") == "Ubuntu:24.10"
    assert ubuntu.osv_ecosystem("ubuntu 23.04") == "Ubuntu:23.04"
    assert ubuntu.osv_ecosystem("debian 12.7") is None


def test_ubuntu_usn_matching():
    from oss_intake.enrich import ubuntu

    usn = {"id": "USN-9001-1", "published": "2026-03-05T10:00:00Z", "upstream": ["CVE-2099-3000"],
           "affected": [
               {"package": {"ecosystem": "Ubuntu:22.04:LTS", "name": "gnupg2"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.2.27-3ubuntu2.9"}]}]},
               {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "gnupg2"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.4.4-2ubuntu17.4"}]}]}]}
    other = {"id": "USN-9002-1", "published": "2026-01-01T00:00:00Z", "upstream": ["CVE-2099-3000"],
             "affected": [{"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "gnupg2"},
                           "ranges": [{"events": [{"fixed": "2.4.4-2ubuntu17.1"}]}]}]}

    class H:
        posted = []

        def post_json(self, url, body):
            self.posted.append(body)
            return 200, {"results": [{"vulns": [{"id": "UBUNTU-CVE-2099-3000"}, {"id": "USN-9001-1"},
                                                 {"id": "USN-9002-1"}]}]}

        def get_json(self, url, params=None):
            vid = url.rsplit("/", 1)[1]
            return 200, {"USN-9001-1": usn, "USN-9002-1": other}[vid]

    def ub(**kw):
        return _f(purl="pkg:deb/ubuntu/gpgv@2.4.4-2ubuntu17.3", installed="2.4.4-2ubuntu17.3",
                  src_name="gnupg2", src_version="2.4.4-2ubuntu17.3", os_release="ubuntu 24.04", **kw)

    hit = ub(vuln_id="CVE-2099-3000", fixed_versions=["2.4.4-2ubuntu17.4"])
    wrong_fix = ub(vuln_id="CVE-2099-3000", fixed_versions=["2.4.4-2ubuntu17.9"])
    wrong_cve = ub(vuln_id="CVE-2099-3999", fixed_versions=["2.4.4-2ubuntu17.4"])
    h = H()
    stats = ubuntu.enrich(h, [hit, wrong_fix, wrong_cve])
    assert hit.fix_published == parse_datetime("2026-03-05T10:00:00Z") and hit.fix_date_source == "advisory USN-9001-1"
    assert wrong_fix.fix_published is None and wrong_cve.fix_published is None  # strict matching
    assert stats["found"] == 1 and stats["notices_fetched"] == 2 and stats["packages_queried"] == 1
    q = h.posted[0]["queries"][0]
    assert q == {"package": {"ecosystem": "Ubuntu:24.04:LTS", "name": "gnupg2"}, "version": "2.4.4-2ubuntu17.3"}


def test_trivy_source_package_fields():
    report = {"Metadata": {"OS": {"Family": "ubuntu", "Name": "24.04"}}, "Results": [{
        "Class": "os-pkgs", "Type": "ubuntu",
        "Packages": [{"ID": "gpgv@2.4.4-2ubuntu17.3", "Name": "gpgv", "SrcName": "gnupg2",
                      "SrcVersion": "2.4.4", "SrcRelease": "2ubuntu17.3"}],
        "Vulnerabilities": [{"VulnerabilityID": "CVE-2099-3000", "PkgID": "gpgv@2.4.4-2ubuntu17.3",
                             "PkgName": "gpgv", "InstalledVersion": "2.4.4-2ubuntu17.3",
                             "FixedVersion": "2.4.4-2ubuntu17.4", "Severity": "HIGH"}]}]}
    from oss_intake.scanners import trivy as tv

    f = tv.parse(report)[0][0]
    assert (f.src_name, f.src_version, f.os_release) == ("gnupg2", "2.4.4-2ubuntu17.3", "ubuntu 24.04")


def test_epss_rules_and_batching():
    from oss_intake.enrich import epss as ep

    class H:
        calls = []

        def get_json(self, url, params=None):
            self.calls.append(params["cve"].split(","))
            return 200, {"data": [{"cve": c, "epss": "0.5", "percentile": "0.99", "date": "2026-10-21"}
                                  for c in params["cve"].split(",")]}

    fs = [_f(vuln_id=f"CVE-2099-{i:04d}") for i in range(150)] + [_f(vuln_id="GHSA-x", aliases={"CVE-2099-9999"})]
    h = H()
    stats = ep.enrich(h, fs)
    assert [len(c) for c in h.calls] == [100, 51] and stats["scored"] == 151
    assert fs[-1].epss == 0.5
    cfg = likelihood.DEFAULT_CONFIG
    base = {"kev_with_fix": 0, "with_fix": 10, "fix_date_unknown": 0, "release_date_known": 1,
            "critical_fix_unshipped": 0}
    assert likelihood.evaluate(cfg, {**base, "max_epss_with_fix": 0.6})["level"] == 4
    assert likelihood.evaluate(cfg, {**base, "max_epss_with_fix": 0.12})["level"] == 3
    assert likelihood.evaluate(cfg, {**base, "max_epss_with_fix": 0.01, "high_with_fix": 1})["level"] == 2


WORKFLOW_GOOD = """name: ci
on: [push]
permissions:
  contents: read
jobs:
  t:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: ./local-action
      - uses: docker://alpine:3.20
"""
WORKFLOW_BAD = """on:
  pull_request_target:
permissions: write-all
jobs:
  scan:
    steps:
      - uses: actions/setup-python@v5
      - name: scan
        uses: aquasecurity/trivy-action@0.28.0
      - uses: "aquasecurity/setup-trivy@ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12" # v0.2.6
      - uses: aquasecurity/trivy-action/sub@ab12ab12ab12ab12ab12ab12ab12ab12ab12ab12
"""


def test_workflow_analysis():
    from oss_intake.health import workflows as wf

    kb = integrity.load_known_bad()["actions"]
    good = wf.analyse("ci.yml", WORKFLOW_GOOD, kb)
    assert good == {"file": "ci.yml", "uses": 1, "unpinned": [], "known_bad": [], "top_level_permissions": True,
                    "write_all": False, "pull_request_target": False}
    bad = wf.analyse("scan.yml", WORKFLOW_BAD, kb)
    assert bad["unpinned"] == ["actions/setup-python@v5", "aquasecurity/trivy-action@0.28.0"]
    assert [b["version"] for b in bad["known_bad"]] == ["0.28.0", "unknown"]  # setup-trivy v0.2.6 is fine
    assert bad["write_all"] and bad["pull_request_target"]


def test_workflow_fetch():
    import base64

    from oss_intake.health import workflows as wf

    class H:
        def get_json(self, url, params=None):
            if url.endswith("/contents/.github/workflows"):
                return 200, [{"type": "file", "name": "ci.yml", "path": ".github/workflows/ci.yml"},
                             {"type": "file", "name": "scan.yaml", "path": ".github/workflows/scan.yaml"},
                             {"type": "file", "name": "README.md", "path": ".github/workflows/README.md"}]
            text = WORKFLOW_GOOD if url.endswith("ci.yml") else WORKFLOW_BAD
            return 200, {"encoding": "base64", "content": base64.b64encode(text.encode()).decode()}

    r = wf.fetch(H(), "o/r")
    assert r["files"] == 2 and r["uses_total"] == 5 and r["unpinned"] == 2 and r["pinned_percent"] == 60
    assert r["no_top_level_permissions"] == [] and r["write_all"] == ["scan.yaml"]
    assert len(r["known_bad"]) == 2 and r["known_bad"][0]["file"] == "scan.yaml"

    class Missing:
        def get_json(self, url, params=None):
            return 404, None

    assert wf.fetch(Missing(), "o/r")["status"] == "none"


def test_redhat_csaf_dates():
    from oss_intake import coverage
    from oss_intake.enrich import redhat

    class H:
        calls = []

        def get_json(self, url, params=None):
            self.calls.append(url)
            if url.endswith("RHSA-2026:42736.json"):
                return 200, {"document": {"tracking": {"initial_release_date": "2026-07-21T16:04:00+00:00",
                                                       "current_release_date": "2026-08-01T00:00:00+00:00"}}}
            return 404, None

    h = H()
    a = _f(vendor_ids=["RHSA-2026:42736"], purl="pkg:rpm/redhat/acl@2.3.1-4.el9?distro=redhat-9.6")
    b = _f(vendor_ids=["RHSA-2026:42736"], purl="pkg:rpm/redhat/libacl@2.3.1-4.el9")
    c = _f(vendor_ids=["RHSA-2026:99999"], purl="pkg:rpm/redhat/x@1")
    d = _f(vendor_ids=["DSA-1-1"], purl="pkg:deb/debian/y@1")
    stats = redhat.enrich(h, [a, b, c, d])
    assert a.fix_published == parse_datetime("2026-07-21T16:04:00+00:00")
    assert a.fix_date_source == "advisory RHSA-2026:42736 (Red Hat)" and b.fix_published == a.fix_published
    assert c.fix_published is None and d.fix_published is None
    assert len(h.calls) == 2 and stats == {"candidates": 3, "advisories_fetched": 2, "found": 2, "errors": 0}
    assert coverage.ecosystem(a) == "redhat"
    assert coverage.ecosystem(_f(purl="pkg:rpm/amazon/glibc@2.34")) == "amazon"


def test_confidence_not_lowered_for_older_release():
    m = {"with_fix": 10, "fix_date_unknown": 0, "release_date_known": 1, "critical_fix_unshipped": None,
         "scanned_is_latest": False}
    assert likelihood.confidence(m) == ("normal", [])
    assert likelihood.confidence({**m, "scanned_is_latest": None})[0] == "low"


def test_packagist_dates():
    from oss_intake.enrich import packagist

    class H:
        calls = []

        def get_json(self, url, params=None):
            self.calls.append(url)
            if url.endswith("/p2/guzzlehttp/guzzle.json"):
                return 200, {"packages": {"guzzlehttp/guzzle": [
                    {"version": "7.9.3", "time": "2025-03-27T13:37:11+00:00"},
                    {"version": "v7.9.2", "time": "2024-07-24T11:22:20+00:00"}]}}
            return 404, None

    h = H()
    g = _f(purl="pkg:composer/guzzlehttp/guzzle@7.9.1", installed="7.9.1", fixed_versions=["7.9.2"])
    g2 = _f(vuln_id="CVE-2099-2", purl="pkg:composer/guzzlehttp/guzzle@7.9.1", installed="7.9.1",
            fixed_versions=["7.9.3"])
    missing = _f(purl="pkg:composer/acme/none@1.0", installed="1.0", fixed_versions=["1.1"])
    stats = packagist.enrich(h, [g, g2, missing])
    assert g.fix_published == parse_datetime("2024-07-24T11:22:20+00:00") and g.fix_date_source == "Packagist"
    assert g2.fix_published == parse_datetime("2025-03-27T13:37:11+00:00")
    assert missing.fix_published is None and len(h.calls) == 2 and stats["found"] == 2
