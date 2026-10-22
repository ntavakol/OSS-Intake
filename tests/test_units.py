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
    assert m0["unshipped"] == 0
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
