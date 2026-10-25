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
    assert sorted(stats["lists_loaded"]) == ["DLA:2", "DSA:2"]


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
    assert cov["ubuntu"]["gap"].startswith("fixed version not published")
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
                    "write_all": False, "pull_request_target": False, "pull_request_target_pr_code": False}
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


def test_likelihood_drivers_name_the_component():
    from oss_intake import lag, report

    chrome = _f(vuln_id="CVE-2099-7", package="chrome", pkg_type="binary", purl=None,
                fix_published=parse_datetime("2026-01-01"), kev=True, epss=0.9)
    chrome.sources = {"grype"}
    app = _f(vuln_id="CVE-2099-8", package="flask", epss=0.2, fix_published=parse_datetime("2026-01-01"))
    app.sources = {"trivy", "osv"}
    m = lag.compute([chrome, app], parse_datetime("2026-04-30"), parse_datetime("2026-10-22"))
    assert [e["id"] for e in m["kev_findings"]] == ["CVE-2099-7"]
    assert [e["id"] for e in m["top_epss_findings"]] == ["CVE-2099-7", "CVE-2099-8"]
    text = report._drivers(m)
    assert "CVE-2099-7 in chrome (CRITICAL, EPSS 0.90; found only by Grype from a binary)" in text
    assert "found by osv, trivy" in text


def test_grype_advisories_become_vendor_ids():
    report = {"matches": [{"vulnerability": {"id": "CVE-2099-9", "severity": "High",
                                             "fix": {"state": "fixed", "versions": ["9.0-1.el9_8"]},
                                             "advisories": [{"id": "RHSA-2026:1111", "link": "x"}]},
                           "artifact": {"name": "vim-minimal", "version": "9.0-1.el9", "type": "rpm",
                                        "purl": "pkg:rpm/redhat/vim-minimal@9.0-1.el9"}}]}
    f = grype.parse(report)[0][0]
    assert f.vendor_ids == ["RHSA-2026:1111"]


def test_kernel_headers_excluded_from_lag_and_likelihood():
    from oss_intake import lag

    kh = _f(vuln_id="CVE-2099-50", package="linux-libc-dev", purl="pkg:deb/ubuntu/linux-libc-dev@6.8.0-1",
            kev=True, epss=0.94, fix_published=parse_datetime("2026-01-01"))
    rh = _f(vuln_id="CVE-2099-51", package="kernel-headers", purl="pkg:rpm/redhat/kernel-headers@5.14.0")
    app = _f(vuln_id="CVE-2099-52", package="libssl3", purl="pkg:deb/ubuntu/libssl3@3.0", epss=0.56,
             fix_published=parse_datetime("2026-01-01"))
    npm_named = _f(vuln_id="CVE-2099-53", package="linux-headers", purl="pkg:npm/linux-headers@1.0")
    assert lag.flag_kernel_headers([kh, rh, app, npm_named]) == 2
    assert kh.excluded and rh.excluded and not app.excluded and not npm_named.excluded
    m = lag.compute([kh, rh, app, npm_named], parse_datetime("2026-04-30"), parse_datetime("2026-10-22"))
    assert m["kev_with_fix"] == 0 and m["max_epss_with_fix"] == 0.56 and m["excluded_kernel_headers"] == 2
    assert m["total"] == 4 and m["with_fix"] == 2


def test_alpine_aports_matching():
    from oss_intake.enrich import alpine

    commits = {
        "main/busybox/APKBUILD": [
            {"sha": "aaaa1111bbbb", "commit": {"message": "main/busybox: patch CVE-2099-60",
                                                "committer": {"date": "2025-11-21T10:00:00Z"}}},
            {"sha": "cccc2222dddd", "commit": {"message": "main/busybox: upgrade to 1.37.0",
                                                "committer": {"date": "2024-10-20T10:00:00Z"}}}],
        "main/openssl/APKBUILD": [
            {"sha": "eeee3333ffff", "commit": {"message": "main/openssl: security upgrade to 3.5.6",
                                                "committer": {"date": "2026-04-09T10:00:00Z"}}},
            {"sha": "9999aaaa0000", "commit": {"message": "main/openssl: upgrade to 3.5.60-beta",
                                                "committer": {"date": "2026-01-01T10:00:00Z"}}}],
        "main/curl/APKBUILD": [
            {"sha": "1234abcd5678", "commit": {"message": "main/curl: security upgrade to 8.14.1",
                                                "committer": {"date": "2025-06-04T10:00:00Z"}}}],
    }

    class H:
        calls = []

        def get_json(self, url, params=None):
            self.calls.append(params)
            assert url == alpine.API and params["sha"] == "3.22-stable"
            return (200, commits[params["path"]]) if params["path"] in commits else (404, None)

    def apk(**kw):
        return _f(os_release="alpine 3.22.2", purl=f"pkg:apk/alpine/{kw['package']}@{kw['installed']}", **kw)

    busy = apk(vuln_id="CVE-2099-60", package="busybox", installed="1.37.0-r19", fixed_versions=["1.37.0-r20"])
    ssl = apk(vuln_id="CVE-2099-61", package="libcrypto3", src_name="openssl", installed="3.5.4-r0",
              fixed_versions=["3.5.6-r0"])
    curl = apk(vuln_id="CVE-2099-62", package="curl", installed="8.14.1-r2", fixed_versions=["8.14.1-r4"])
    none = apk(vuln_id="CVE-2099-63", package="ghostpkg", installed="1.0-r0", fixed_versions=["1.1-r0"])
    h = H()
    stats = alpine.enrich(h, [busy, ssl, curl, none])
    assert busy.fix_published == parse_datetime("2025-11-21T10:00:00Z") and busy.fix_date_source.startswith(
        "aports commit aaaa1111")
    assert ssl.fix_published == parse_datetime("2026-04-09T10:00:00Z")  # 3.5.60-beta must not match 3.5.6
    assert curl.fix_published is None  # rebuild -r4: "upgrade to 8.14.1" describes the base version
    assert none.fix_published is None
    assert stats["found"] == 2 and stats["packages"] == 4
    assert [c["path"] for c in h.calls].count("community/ghostpkg/APKBUILD") == 1  # tries community after main
    assert alpine.branch_for("alpine 3.22.2") == "3.22-stable" and alpine.branch_for("debian 12") is None


def test_compare_package_revisions():
    from oss_intake.versions import compare, nearest_fix

    assert compare("2.41.6-r0", "2.41-r9") > 0  # Alpine: upstream version first, then -rN
    assert compare("10.0_p1-r10", "10.0_p1-r7") > 0
    assert compare("2.41.6-1", "2.41-9") > 0  # Debian revision
    assert compare("10.42-1+deb12u1", "10.42-1") > 0
    assert compare("2.41.6-1.el9", "2.41-9.el9_4") > 0  # RPM release
    assert compare("2.41-10.el9", "2.41-9.el9") > 0
    assert compare("1.2.3", "1.2.3-r0") == 0
    assert nearest_fix("2.41-r9", ["2.41.6-r0", "2.41.6-r1"]) == "2.41.6-r0"


def test_alpine_cve_match_needs_boundary():
    from oss_intake.enrich.alpine import _matches

    assert _matches("main/curl: patch CVE-2026-5545", {"CVE-2026-5545"}, "8.14.1", "3")
    assert not _matches("main/curl: patch CVE-2026-55450", {"CVE-2026-5545"}, "8.14.1", "3")


def test_grype_os_package_keeps_distro_and_source():
    from oss_intake.scanners import grype

    report = {"distro": {"name": "alpine", "version": "3.22.2"}, "matches": [{
        "vulnerability": {"id": "CVE-2099-1", "severity": "High", "fix": {"state": "fixed", "versions": ["1.68.1-r0"]}},
        "artifact": {"name": "nghttp2-libs", "version": "1.65.0-r0", "type": "apk",
                     "purl": "pkg:apk/alpine/nghttp2-libs@1.65.0-r0", "upstreams": [{"name": "nghttp2"}]}}]}
    (f,), _ = grype.parse(report)
    assert f.os_release == "alpine 3.22.2" and f.src_name == "nghttp2"


def test_local_image_export_error_suggests_remote(tmp_path):
    import sys

    import pytest

    from oss_intake.scanners import ScannerError, run

    script = tmp_path / "fake.py"
    script.write_text("import sys; sys.stderr.write('FATAL unable to export the image: content digest "
                      "sha256:8e5b: not found'); sys.exit(1)")
    with pytest.raises(ScannerError, match="--image-src remote"):
        run([sys.executable, str(script)], 30)


def test_debian_point_release_dates():
    from oss_intake.enrich import debian_releases

    from .conftest import FakeHttp

    def deb(**kw):
        return _f(os_release="debian 13.1", purl=f"pkg:deb/debian/{kw['package']}@{kw['installed']}", **kw)

    web = deb(vuln_id="CVE-2099-3001", package="synthweb-bin", src_name="synthweb", installed="2.4.65-2",
              fixed_versions=["2.4.68-1~deb13u1"])
    glib = deb(vuln_id="CVE-2099-3002", package="synthglib", installed="2.84.4-3~deb13u1",
               fixed_versions=["2.84.4-3~deb13u2"])
    pend = deb(vuln_id="CVE-2099-3003", package="synthpending", installed="3.0-1", fixed_versions=["3.0-1+deb13u1"])
    other = deb(vuln_id="CVE-2099-3004", package="nothere", installed="1.0-1", fixed_versions=["1.0-1+deb13u1"])
    hdr = deb(vuln_id="CVE-2099-3005", package="linux-libc-dev", installed="6.1-1", fixed_versions=["6.2-1"],
              excluded="kernel-headers")
    old = _f(os_release="debian 12.9", purl="pkg:deb/debian/x@1.0-1", package="x", installed="1.0-1",
             fixed_versions=["1.0-1+deb12u1"])
    stats = debian_releases.enrich(FakeHttp(), [web, glib, pend, other, hdr, old])
    assert web.fix_published == parse_datetime("2026-07-11") and web.fix_date_source == "point release Debian 13.6"
    assert glib.fix_published == parse_datetime("2026-01-10")
    assert pend.fix_published is None and "proposed-updates" in pend.note
    assert other.fix_published is None and hdr.fix_published is None and old.fix_published is None
    assert stats["found"] == 2 and stats["pending"] == 1 and stats["suites_loaded"] == ["trixie:3"]
    assert debian_releases.codename_for("debian 13.1") == "trixie"
    assert debian_releases.codename_for("ubuntu 24.04") is None


def test_debian_tracker_matches_fixed_version_without_cve():
    from oss_intake.enrich import debian_tracker

    from .conftest import FakeHttp

    f = _f(vuln_id="CVE-2099-3011", package="synthmagick-common", src_name="synthmagick", os_release="debian 13.1",
           purl="pkg:deb/debian/synthmagick-common@8:7.1.1.43+dfsg1-1+deb13u4",
           installed="8:7.1.1.43+dfsg1-1+deb13u4", fixed_versions=["8:7.1.1.43+dfsg1-1+deb13u5"])
    stats = debian_tracker.enrich(FakeHttp(), [f])
    assert f.fix_published == parse_datetime("2026-01-26")
    assert f.fix_date_source == "advisory DSA-9600-1 (Debian tracker, by fixed version)"
    assert stats["found_by_version"] == 1


def test_go_stdlib_dates_from_release_history():
    from oss_intake.enrich import golang_stdlib

    from .conftest import FakeHttp

    trivy = _f(vuln_id="CVE-2099-4001", package="stdlib", purl="pkg:golang/stdlib@v1.22.7", installed="v1.22.7",
               fixed_versions=["1.22.8", "1.23.2"])
    grype = _f(vuln_id="CVE-2099-4002", package="stdlib", purl="pkg:golang/stdlib@go1.22.7", installed="go1.22.7",
               fixed_versions=["1.23.0"])
    unknown = _f(vuln_id="CVE-2099-4003", package="stdlib", purl="pkg:golang/stdlib@v1.22.7", installed="v1.22.7",
                 fixed_versions=["1.22.99"])
    module = _f(vuln_id="CVE-2099-4004", package="golang.org/x/net", purl="pkg:golang/golang.org/x/net@v0.1.0",
                installed="v0.1.0", fixed_versions=["0.2.0"])
    stats = golang_stdlib.enrich(FakeHttp(), [trivy, grype, unknown, module])
    assert trivy.fix_published == parse_datetime("2024-10-01") and trivy.fix_date_source == "Go release go1.22.8"
    assert grype.fix_published == parse_datetime("2024-08-13")
    assert unknown.fix_published is None and module.fix_published is None
    assert stats["found"] == 2 and stats["releases_loaded"] == 5
    assert golang_stdlib.norm("go1.20") == "1.20.0" and golang_stdlib.norm("v1.22.7") == "1.22.7"


def test_grype_go_stdlib_version_merges_with_trivy():
    from oss_intake import merge
    from oss_intake.scanners import grype

    report = {"matches": [{
        "vulnerability": {"id": "CVE-2099-5001", "severity": "High", "fix": {"state": "fixed", "versions": ["1.18.3"]}},
        "artifact": {"name": "stdlib", "version": "go1.18.2", "type": "go-module",
                     "purl": "pkg:golang/stdlib@1.18.2"}}]}
    (g,), _ = grype.parse(report)
    assert g.installed == "v1.18.2"
    t = _f(vuln_id="CVE-2099-5001", package="stdlib", purl="pkg:golang/stdlib@v1.18.2", installed="v1.18.2",
           fixed_versions=["1.18.3"], sources={"trivy"})
    merged = merge.merge([t], [g])
    assert len(merged) == 1 and merged[0].sources == {"trivy", "grype"}


def test_release_used_wording():
    from oss_intake.report import release_used

    assert release_used({"release_date": "2024-10-03T00:00:00", "release_date_source": "image build date"},
                        {"scanned_release": {"tag": "(image build date)"}}) == \
        "no matching release; image build date 2024-10-03 used"
    assert release_used({"release_date": "2026-04-30T15:01:38", "release_date_source": "GitHub release"},
                        {"scanned_release": {"tag": "v3.2.4"}}) == "v3.2.4 (2026-04-30), from GitHub release"


def test_pull_request_target_with_pr_checkout():
    from oss_intake.health import workflows as wf

    label_only = "on:\n  pull_request_target:\npermissions:\n  pull-requests: write\njobs:\n  l:\n    steps:\n" \
                 "      - uses: eps1lon/actions-label-merge-conflict@0273be72a0bbd58fcd71d0d6c02c209b50d1e5e1\n"
    risky = label_only + "      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n" \
                         "        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
    plain_pr = "on: pull_request\njobs:\n  t:\n    steps:\n      - run: echo ${{ github.head_ref }}\n"
    assert wf.analyse("a.yml", label_only, [])["pull_request_target_pr_code"] is False
    assert wf.analyse("b.yml", risky, [])["pull_request_target_pr_code"] is True
    assert wf.analyse("c.yml", plain_pr, [])["pull_request_target_pr_code"] is False


def test_merge_keeps_every_location():
    from oss_intake import merge

    a = _f(vuln_id="CVE-2099-6001", package="stdlib", purl="pkg:golang/stdlib@v1.21.12", installed="v1.21.12",
           target="usr/bin/bsondump", sources={"trivy"})
    b = _f(vuln_id="CVE-2099-6001", package="stdlib", purl="pkg:golang/stdlib@v1.21.12", installed="v1.21.12",
           target="usr/bin/mongodump", sources={"trivy"})
    c = _f(vuln_id="CVE-2099-6001", package="stdlib", purl="pkg:golang/stdlib@v1.21.12", installed="v1.21.12",
           target="/usr/bin/bsondump", sources={"grype"})
    (m,) = merge.merge([a, b], [c])
    assert m.target == "usr/bin/bsondump;usr/bin/mongodump"


def test_ubuntu_launchpad_dates():
    from oss_intake.enrich import ubuntu_launchpad

    from .conftest import FakeHttp

    def ubu(**kw):
        return _f(os_release="ubuntu 22.04", purl=f"pkg:deb/ubuntu/{kw['package']}@{kw['installed']}", **kw)

    ssl = ubu(vuln_id="CVE-2099-7001", package="libssl3", src_name="openssl", installed="3.0.2-0ubuntu1.20",
              fixed_versions=["3.0.2-0ubuntu1.25"])
    perl = ubu(vuln_id="CVE-2099-7002", package="perl", installed="5.34.0-3ubuntu1.5",
               fixed_versions=["5.34.0-3ubuntu1.7"])
    esm = ubu(vuln_id="CVE-2099-7003", package="libfoo", installed="1.0-1", fixed_versions=["1.0-1ubuntu0.1~esm1"])
    other = _f(vuln_id="CVE-2099-7004", package="x", installed="1.0-1", fixed_versions=["1.0-2"],
               os_release="ubuntu 18.04", purl="pkg:deb/ubuntu/x@1.0-1")
    http = FakeHttp()
    stats = ubuntu_launchpad.enrich(http, [ssl, perl, esm, other])
    assert ssl.fix_published == parse_datetime("2026-06-09T18:01:02.123+00:00")  # Proposed (earlier) ignored
    assert ssl.fix_date_source == "Launchpad publication (Security)"
    assert perl.fix_date_source == "Launchpad publication (Updates)"
    assert esm.fix_published is None and other.fix_published is None
    assert stats["found"] == 2 and stats["lookups"] == 3


def test_cvss_provenance_and_v4_fallback():
    from oss_intake import merge
    from oss_intake.cvss import better
    from oss_intake.scanners import grype, trivy

    assert better((5.0, "3.1", "nvd"), (9.0, "4.0", "ghsa"))  # any v3 beats v4
    assert not better((9.0, "4.0", "ghsa"), (5.0, "3.1", "nvd"))
    assert better((7.5, "3.1", "nvd"), (5.3, "3.1", "redhat"))

    rep = {"Results": [{"Target": "x", "Class": "lang-pkgs", "Type": "jar", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2099-8001", "PkgName": "a", "InstalledVersion": "1", "Severity": "HIGH",
         "SeveritySource": "redhat", "CVSS": {"nvd": {"V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                                       "V3Score": 9.8},
                                               "redhat": {"V3Vector": "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
                                                          "V3Score": 3.7}}},
        {"VulnerabilityID": "CVE-2099-8002", "PkgName": "b", "InstalledVersion": "1", "Severity": "LOW",
         "CVSS": {"ghsa": {"V40Vector": "CVSS:4.0/AV:L/AC:L/AT:P/PR:N/UI:A/VC:N/VI:L/VA:L/SC:N/SI:N/SA:N",
                           "V40Score": 1.8}}}]}]}
    a, b = trivy.parse(rep)[0]
    assert (a.cvss, a.cvss_version, a.cvss_source) == (9.8, "3.1", "nvd")  # highest v3 across sources
    assert (b.cvss, b.cvss_version, b.cvss_source) == (1.8, "4.0", "ghsa")

    g = {"matches": [{
        "vulnerability": {"id": "GHSA-xxxx", "namespace": "github:language:java", "severity": "Medium",
                          "fix": {"state": "fixed", "versions": ["2"]},
                          "cvss": [{"version": "4.0", "vector": "CVSS:4.0/AV:N", "metrics": {"baseScore": 6.9}}]},
        "relatedVulnerabilities": [{"id": "CVE-2099-8002", "namespace": "nvd:cpe",
                                    "cvss": [{"version": "3.1", "vector": "CVSS:3.1/AV:N",
                                              "metrics": {"baseScore": 5.3}}]}],
        "artifact": {"name": "b", "version": "1", "type": "java-archive", "purl": "pkg:maven/x/b@1"}}]}
    (gb,), _ = grype.parse(g)
    assert (gb.cvss, gb.cvss_version, gb.cvss_source) == (5.3, "3.1", "nvd")  # related v3 replaces v4

    b.purl = gb.purl = "pkg:maven/x/b@1"
    b.vuln_id = gb.vuln_id = "CVE-2099-8002"
    (m,) = merge.merge([b], [gb])
    assert (m.cvss, m.cvss_version, m.cvss_source) == (5.3, "3.1", "nvd")


def test_merge_prefers_nested_jar_path():
    from oss_intake import merge

    t = _f(vuln_id="CVE-2099-9001", package="org.x:lib", purl="pkg:maven/org.x/lib@1.0", installed="1.0",
           target="opt/app/app.jar/BOOT-INF/lib/lib-1.0.jar", sources={"trivy"})
    g = _f(vuln_id="CVE-2099-9001", package="org.x:lib", purl="pkg:maven/org.x/lib@1.0", installed="1.0",
           target="/opt/app/app.jar", sources={"grype"})
    (m,) = merge.merge([g], [t])  # outer first, nested second: nested replaces it
    assert m.target == "opt/app/app.jar/BOOT-INF/lib/lib-1.0.jar"
    (m2,) = merge.merge([t], [g])  # nested first: outer is not added
    assert m2.target == "opt/app/app.jar/BOOT-INF/lib/lib-1.0.jar"
    assert not merge._inside("/opt/app/app.jar", "opt/app/app.jar2")


def test_exploit_levels():
    from oss_intake.enrich import exploits

    from .conftest import FakeHttp

    def f(cve, **kw):
        return _f(vuln_id=cve, purl=f"pkg:maven/x/{cve.lower()}@1", **kw)

    kev = f("CVE-2099-0003", kev=True)
    msf = f("CVE-2099-0002")
    nuc = _f(vuln_id="GHSA-aaaa", aliases={"CVE-2099-0005"}, purl="pkg:maven/x/n@1")  # matched through alias
    edb = f("CVE-2099-0006")
    poc = f("CVE-2099-0004")  # only a payload references it in Metasploit, so it falls through to PoCs
    none = f("CVE-2099-0007")
    ghsa_only = _f(vuln_id="GHSA-bbbb", purl="pkg:maven/x/g@1")
    info = exploits.enrich(FakeHttp(), [kev, msf, nuc, edb, poc, none, ghsa_only])
    assert [x.exploit_level for x in (kev, msf, nuc, edb, poc, none, ghsa_only)] == \
        ["kev", "weaponised", "weaponised", "public", "poc", "none", "nocve"]
    assert msf.exploit_refs == ["metasploit:exploit/multi/http/synthetic_rce"]
    assert edb.exploit_refs == ["exploit-db:90001 (verified)"]
    assert poc.exploit_refs == ["github:someone/CVE-2099-0004 (5 stars)",
                                "github:other/CVE-2099-0004 (0 stars)"]  # the fork is not listed
    assert info["failed"] == [] and info["sources"] == {"metasploit": 1, "nuclei": 1, "exploit-db": 1}

    failing = FakeHttp(fail_hosts=("gitlab.com",))
    other = f("CVE-2099-0007")
    info = exploits.enrich(failing, [other])
    assert info["failed"] == ["exploit-db"] and other.exploit_level == ""  # not "none" when a source failed


def test_conditions_extract():
    from oss_intake.conditions import extract

    spring = ("Use of XsltView in a Spring MVC application can result in SSRF and RCE attack if:\n\n"
              "* the application uses XsltView\n* has a \"/**\" mapping that results in view rendering\n"
              "* does not explicitly specify the view name\n\nAffected Spring Products and Versions: 7.0.0 - 7.0.8.")
    assert extract(spring) == ("Use of XsltView in a Spring MVC application can result in SSRF and RCE attack if: "
                               "- the application uses XsltView - has a \"/**\" mapping that results in view "
                               "rendering - does not explicitly specify the view name")
    assert extract("A heap overflow in parse_foo allows remote attackers to cause a denial of service.") == ""
    saml = "Applications are vulnerable when using the REDIRECT binding for SAML 2.0 Login. Upgrade to 6.5.11."
    assert extract(saml) == "Applications are vulnerable when using the REDIRECT binding for SAML 2.0 Login."


def test_triage_groups():
    from oss_intake import triage

    cases = [
        (_f(excluded="kernel-headers", kev=True), "aside"),  # evidence wins over everything
        (_f(likely_fixed=True), "aside"),
        (_f(kev=True, conditions="only if X"), "act"),
        (_f(exploit_level="weaponised", exploit_refs=["metasploit:exploit/x"]), "act"),
        (_f(exploit_level="public"), "review"),
        (_f(epss=0.2, severity="LOW"), "review"),
        (_f(conditions="vulnerable when using X", severity="CRITICAL"), "conditions"),
        (_f(severity="CRITICAL", exploit_level="none"), "review"),
        (_f(severity="HIGH", exploit_level="poc", epss=0.01), "routine"),
    ]
    for f, want in cases:
        assert triage.classify(f)[0] == want, (want, f)
    info = triage.apply([c[0] for c in cases])
    assert info["groups"]["act"]["total"] == 2 and info["groups"]["aside"]["total"] == 2
    ranked = sorted([c[0] for c in cases], key=triage.rank_key)
    assert [f.triage_group for f in ranked][:2] == ["act", "act"] and ranked[-1].triage_group == "aside"
