"""Amazon Linux fix dates from the ALAS advisories in the repository metadata (enrich/amazon.py).

The fixtures in tests/fixtures/amazon are cut from the live updateinfo.xml files of 12 Nov 2026 (descriptions
trimmed, packages limited to the ones tested): AL2023's ALAS2023-2023-001 (rsyslog), ALAS2023-2023-051 and -054
(openssl: CVE-2022-2097 fixed at two versions), ALAS2023-2023-160 and ALAS2023-2025-1054 (kernel-libbpf-static:
CVE-2023-1583 listed again, at the same version, two years later), and AL2's ALAS2-2022-1803 (rsyslog).
"""

from __future__ import annotations

import gzip
import hashlib
import json
from datetime import datetime, timezone

import pytest

from oss_intake import cli
from oss_intake.enrich import amazon
from oss_intake.models import Finding

from .conftest import FIX, FakeHttp

AL2023_BASE = "https://cdn.amazonlinux.com/al2023/core/guids/b1757122e91c63dc/x86_64"
AL2_BASE = "https://cdn.amazonlinux.com/2/core/2.0/x86_64/11f6487079809e63"


def repomd(gz: bytes, href: str = "repodata/updateinfo.xml.gz", digest: str | None = None) -> bytes:
    return f"""<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <revision>1793753800</revision>
  <data type="primary"><checksum type="sha256">{"0" * 64}</checksum><location href="repodata/primary.xml.gz" />
    <size>8458975</size></data>
  <data type="updateinfo">
    <checksum type="sha256">{digest or hashlib.sha256(gz).hexdigest()}</checksum>
    <location href="{href}" />
    <size>{len(gz)}</size>
  </data>
</repomd>""".encode()


def serve(http: FakeHttp, release: str = "2023", xml: bytes | None = None, *, base: str | None = None,
          gz: bytes | None = None, digest: str | None = None, mirror: str | None = None) -> None:
    """Answers for one release, as the CDN gives them: mirror.list (with a trailing slash), repomd.xml, updateinfo."""
    base = base or (AL2023_BASE if release == "2023" else AL2_BASE)
    name = "al2023" if release == "2023" else "al2"
    xml = xml if xml is not None else (FIX / "amazon" / f"{name}-updateinfo.xml").read_bytes()
    gz = gz if gz is not None else gzip.compress(xml)
    http.files[amazon.MIRROR_LISTS[release]] = (mirror if mirror is not None else base + "/\n").encode()
    http.files[f"{base}/repodata/repomd.xml"] = repomd(gz, digest=digest)
    http.files[f"{base}/repodata/updateinfo.xml.gz"] = gz


def finding(package: str, fixed: str, cve: str, release: str = "amazon 2023.6.20241031 (amazon linux)", **kw):
    ns = "amazon"
    return Finding(vuln_id=cve, package=package, installed="0-0", fixed_versions=[fixed], severity="HIGH",
                   purl=f"pkg:rpm/{ns}/{package}@0-0?arch=x86_64&distro=amazon-{release.split()[1][:4].rstrip('.')}",
                   os_release=release, **kw)


def dt(*a):
    return datetime(*a, tzinfo=timezone.utc)


# ------------------------------------------------------------------------------------------- which release


@pytest.mark.parametrize("os_release, purl, want", [
    ("amazon 2023.6.20241031 (amazon linux)", "pkg:rpm/amazon/curl@8.5.0-1.amzn2023", "2023"),
    ("amazon 2023 (amazon linux)", "", "2023"),
    ("amazon 2 (karoo)", "pkg:rpm/amazon/curl@7.88.1-1.amzn2", "2"),
    ("amazonlinux 2023", "pkg:rpm/amzn/curl@8.5.0-1.amzn2023?distro=amzn-2023", "2023"),  # Grype
    ("", "pkg:rpm/amzn/curl@7.88.1-1.amzn2?distro=amzn-2", "2"),
    ("amazon 2018.03", "pkg:rpm/amazon/curl@7.61.1-12.95.amzn1", None),  # the original AMI: not covered
    ("ubuntu 24.04", "pkg:deb/ubuntu/curl@8.5.0", None),
])
def test_release_of(os_release, purl, want):
    f = Finding(vuln_id="CVE-1", package="curl", installed="1", purl=purl, os_release=os_release)
    assert amazon.release_of(f) == want


# ------------------------------------------------------------------------------------------- dating


def test_a_fix_is_dated_by_its_advisory():
    http = FakeHttp()
    serve(http)
    f = finding("rsyslog", "8.2204.0-3.amzn2023.0.2", "CVE-2022-24903")
    stats = amazon.enrich(http, [f])
    assert f.fix_published == dt(2023, 2, 17, 20, 41)
    assert f.fix_date_source == "advisory ALAS2023-2023-001 (Amazon Linux)"
    assert f.fix_version_used == "8.2204.0-3.amzn2023.0.2"
    assert stats == {"candidates": 1, "found": 1, "releases": ["Amazon Linux 2023"], "errors": 0}


def test_amazon_linux_2():
    http = FakeHttp()
    serve(http, "2")
    f = finding("rsyslog", "8.24.0-57.amzn2.2.0.1", "CVE-2022-24903", release="amazon 2 (karoo)")
    amazon.enrich(http, [f])
    assert f.fix_date_source == "advisory ALAS2-2022-1803 (Amazon Linux)"
    assert f.fix_published == dt(2022, 5, 31, 23, 50)


@pytest.mark.parametrize("fixed, adv", [("3.0.8-1.amzn2023.0.1", "ALAS2023-2023-054"),
                                        ("3.0.5-1.amzn2023.0.4", "ALAS2023-2023-051")])
def test_a_cve_fixed_at_two_versions_takes_the_advisory_for_the_fixed_version(fixed, adv):
    http = FakeHttp()
    serve(http)
    f = finding("openssl", fixed, "CVE-2022-2097")
    amazon.enrich(http, [f])
    assert f.fix_date_source == f"advisory {adv} (Amazon Linux)"


def test_a_cve_listed_again_later_keeps_the_first_date():
    """AWS added CVE-2023-1583 to a 2025 advisory for the same kernel version it shipped in 2023: the fix was in
    the repository from 2023."""
    http = FakeHttp()
    serve(http)
    f = finding("kernel-libbpf-static", "6.1.23-36.46.amzn2023", "CVE-2023-1583")
    amazon.enrich(http, [f])
    assert f.fix_published.date().isoformat() == "2023-04-13"
    assert f.fix_date_source == "advisory ALAS2023-2023-160 (Amazon Linux)"


def test_an_epoch_in_the_fixed_version_is_ignored():
    http = FakeHttp()
    serve(http)
    f = finding("openssl", "1:3.0.8-1.amzn2023.0.1", "CVE-2022-2097")
    amazon.enrich(http, [f])
    assert f.fix_date_source == "advisory ALAS2023-2023-054 (Amazon Linux)"


def test_a_binary_package_not_listed_is_matched_by_its_source_package():
    http = FakeHttp()
    serve(http)
    f = finding("rsyslog-gnutls", "8.2204.0-3.amzn2023.0.2", "CVE-2022-24903", src_name="rsyslog")
    amazon.enrich(http, [f])
    assert f.fix_date_source == "advisory ALAS2023-2023-001 (Amazon Linux)"


@pytest.mark.parametrize("fixed, cve", [("8.2204.0-3.amzn2023.0.3", "CVE-2022-24903"),  # another version
                                        ("8.2204.0-3.amzn2023.0.2", "CVE-2099-0001")])  # a CVE it does not list
def test_no_exact_match_stays_undated(fixed, cve):
    http = FakeHttp()
    serve(http)
    f = finding("rsyslog", fixed, cve)
    stats = amazon.enrich(http, [f])
    assert f.fix_published is None and stats["found"] == 0 and stats["candidates"] == 1


def test_each_release_is_loaded_once_and_others_are_not_asked():
    http = FakeHttp()
    serve(http)
    fs = [finding("rsyslog", "8.2204.0-3.amzn2023.0.2", "CVE-2022-24903"),
          finding("openssl", "3.0.8-1.amzn2023.0.1", "CVE-2022-2097"),
          Finding(vuln_id="CVE-1", package="curl", installed="1", fixed_versions=["2"], os_release="ubuntu 24.04",
                  purl="pkg:deb/ubuntu/curl@1")]
    stats = amazon.enrich(http, fs)
    assert stats["found"] == 2
    assert sum(u.endswith("updateinfo.xml.gz") for u in http.calls) == 1
    assert not any("/2/core/" in u for u in http.calls)


# ------------------------------------------------------------------------------------------- fail closed


def _broken(kind: str, http: FakeHttp) -> None:
    xml = (FIX / "amazon" / "al2023-updateinfo.xml").read_bytes()
    if kind == "checksum":
        serve(http, digest="0" * 64)
    elif kind == "elsewhere":
        serve(http, mirror="https://example.com/al2023/x86_64/\n")
    elif kind == "plain_http":
        serve(http, mirror="http://cdn.amazonlinux.com/al2023/x86_64/\n")
    elif kind == "doctype":
        serve(http, xml=b'<?xml version="1.0"?><!DOCTYPE u [<!ENTITY a "x">]>' + xml.split(b"?>", 1)[1])
    elif kind == "truncated":
        gz = gzip.compress(xml)[:200]
        serve(http, gz=gz)
    elif kind == "not_xml":
        serve(http, xml=b"<updates><update><id>ALAS")
    elif kind == "corrupt":
        gz = bytearray(gzip.compress(xml, mtime=0))
        gz[10] ^= 0xFF  # the deflate stream's first byte: zlib.error ("invalid distance"), not OSError
        serve(http, gz=bytes(gz))
    else:
        raise AssertionError(kind)


@pytest.mark.parametrize("kind", ["checksum", "elsewhere", "plain_http", "doctype", "truncated", "not_xml",
                                  "corrupt"])
def test_metadata_that_is_not_right_dates_nothing(kind):
    """Fail closed: the run goes on, but no date comes from metadata that dnf would not accept either."""
    http = FakeHttp()
    _broken(kind, http)
    f = finding("rsyslog", "8.2204.0-3.amzn2023.0.2", "CVE-2022-24903")
    stats = amazon.enrich(http, [f])
    assert f.fix_published is None
    assert stats["errors"] == 1 and stats["error"].startswith("Amazon Linux 2023: ")


def test_a_network_failure_dates_nothing():
    http = FakeHttp(fail_hosts=("cdn.amazonlinux.com",))
    f = finding("rsyslog", "8.2204.0-3.amzn2023.0.2", "CVE-2022-24903")
    stats = amazon.enrich(http, [f])
    assert f.fix_published is None and stats["errors"] == 1


def test_an_oversized_updateinfo_is_refused(monkeypatch):
    monkeypatch.setattr(amazon, "MAX_XML", 1000)
    http = FakeHttp()
    serve(http)
    stats = amazon.enrich(http, [finding("rsyslog", "8.2204.0-3.amzn2023.0.2", "CVE-2022-24903")])
    assert stats["errors"] == 1 and "over" in stats["error"]


# ------------------------------------------------------------------------------------------- a whole run


def trivy_report(tmp_path):
    report = {
        "SchemaVersion": 2, "CreatedAt": "2026-11-12T06:00:00Z", "ArtifactName": "amazonlinux:2023",
        "ArtifactType": "container_image", "Metadata": {"OS": {"Family": "amazon", "Name": "2023.6.20241031"}},
        "Results": [{"Target": "amazonlinux:2023 (amazon 2023.6.20241031)", "Class": "os-pkgs", "Type": "amazon",
                     "Packages": [{"Name": "rsyslog", "Version": "8.2204.0-3.amzn2023.0.1"}],
                     "Vulnerabilities": [{
                         "VulnerabilityID": "CVE-2022-24903", "PkgName": "rsyslog", "SrcName": "rsyslog",
                         "PkgIdentifier": {"PURL": "pkg:rpm/amazon/rsyslog@8.2204.0-3.amzn2023.0.1?arch=x86_64"
                                                   "&distro=amazon-2023.6.20241031"},
                         "InstalledVersion": "8.2204.0-3.amzn2023.0.1", "FixedVersion": "8.2204.0-3.amzn2023.0.2",
                         "Severity": "HIGH", "Title": "rsyslog heap overflow",
                         "PublishedDate": "2022-05-08T18:15:00Z"}]}]}
    p = tmp_path / "trivy.json"
    p.write_text(json.dumps(report), encoding="utf-8")
    return p


def test_a_whole_run_dates_an_amazon_linux_finding(tmp_path, fixtures):
    http = FakeHttp()
    serve(http)
    out = tmp_path / "out"
    code = cli.main(["--image", "amazonlinux:2023", "--out", str(out), "--from-trivy-json", str(trivy_report(tmp_path)),
                     "--from-grype-json", str(fixtures / "grype.json"), "--release-date", "2026-11-01",
                     "--no-scorecard", "--as-of", "2026-11-12"], http=http)
    assert code == cli.EXIT_OK
    a = json.loads((out / "assessment.json").read_text(encoding="utf-8"))
    f = next(x for x in a["findings"] if x["package"] == "rsyslog")
    assert f["fix_date_source"] == "advisory ALAS2023-2023-001 (Amazon Linux)"
    assert f["fix_published"].startswith("2023-02-17")
    assert a["fix_dates"]["amazon"]["found"] == 1
