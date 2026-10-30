"""Regression tests on trimmed real scan output from public images (tests/fixtures/real).

Each test pins a bug found while validating against real images. Fixtures are produced with
scripts/extract_regression_fixture.py; a test skips if its fixture has not been generated yet.
"""

import json
from pathlib import Path

import pytest

from oss_intake import coverage, lag, merge
from oss_intake.scanners import grype, trivy
from oss_intake.versions import nearest_fix

REAL = Path(__file__).parent / "fixtures" / "real"


def _load(name):
    p = REAL / name
    if not p.exists():
        pytest.skip(f"{name} not generated; see scripts/extract_regression_fixture.py")
    return json.loads(p.read_text(encoding="utf-8"))


def test_spring_app_mssql_label_false_positive():
    t, _ = trivy.parse(_load("spring-app-1.0.0-trivy.json"))
    g, _ = grype.parse(_load("spring-app-1.0.0-grype.json"))
    findings = merge.merge(t, g)
    assert lag.flag_label_matches(findings) >= 1
    mssql = [f for f in findings if "mssql-jdbc" in f.package]
    assert mssql and all(f.likely_fixed for f in mssql)
    assert all("grype" not in f.sources for f in mssql)  # Grype reads the jar version correctly
    others = [f for f in findings if "mssql-jdbc" not in f.package]
    assert others and not any(f.likely_fixed for f in others)


def test_jenkins_debian_security_suffix_and_advisories():
    t, _ = trivy.parse(_load("jenkins-2.528-jdk21-trivy.json"))
    deb = [f for f in t if "+deb" in "".join(f.fixed_versions)]
    assert deb
    assert lag.flag_no_newer_fix(deb) == 0  # 10.42-1+deb12u1 must sort above 10.42-1
    assert any(v.startswith(("DLA-", "DSA-")) for f in deb for v in f.vendor_ids)
    assert {coverage.ecosystem(f) for f in deb} == {"debian"}


def test_grafana_go_pseudo_versions_and_incompatible():
    t, _ = trivy.parse(_load("grafana-12.2.0-trivy.json"))
    gf = [f for f in t if f.package == "github.com/grafana/grafana"]
    assert any(nearest_fix(f.installed, f.fixed_versions) is None for f in gf)  # pseudo-version "fix"
    assert any(nearest_fix(f.installed, f.fixed_versions) for f in gf)  # a real v12 fix exists
    tempo = [f for f in t if f.package == "github.com/grafana/tempo"]
    assert tempo and all(nearest_fix(f.installed, f.fixed_versions) for f in tempo)
    assert any(coverage.ecosystem(f) == "go-stdlib" for f in t)


@pytest.mark.parametrize("name,eco", [("nginx-1.29.2-alpine-trivy.json", "alpine"),
                                      ("ubuntu-r-4.5.1-trivy.json", "ubuntu")])
def test_os_ecosystem_detection(name, eco):
    t, _ = trivy.parse(_load(name))
    assert t and {coverage.ecosystem(f) for f in t} == {eco}


def test_ubuntu_source_package_fields():
    t, _ = trivy.parse(_load("ubuntu-r-4.5.1-trivy.json"))
    assert t and all(f.src_name and "ubuntu" in f.src_version and f.os_release == "ubuntu 24.04" for f in t)


def test_ubi_redhat_advisories():
    t, _ = trivy.parse(_load("ubi9-9.6-trivy.json"))
    assert t and {coverage.ecosystem(f) for f in t} == {"redhat"}
    assert all(any(v.startswith("RHSA-") for v in f.vendor_ids) for f in t)
    assert lag.flag_no_newer_fix(t) == 0  # el9 -> el9_8 release ordering
