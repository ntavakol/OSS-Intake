"""examples/osquery/osquery_sbom.py: osquery results to CycloneDX, read back by oss-intake's SBOM reader."""

import importlib.util
import json
from pathlib import Path

import pytest

from oss_intake import sbom
from oss_intake.inputs import InputError

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures" / "osquery"
_spec = importlib.util.spec_from_file_location("osquery_sbom", ROOT / "examples" / "osquery" / "osquery_sbom.py")
col = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(col)


def _run(tmp_path, *args):
    out = tmp_path / "sboms"
    assert col.main([*args, "--out", str(out)]) == 0
    return out


def test_macos_sample_as_received(tmp_path):
    """Ned's Mac (osquery 5.24.0, macOS 26.5.1): only the Python rows can be checked; Homebrew and the OS are
    listed with the reason, never dropped."""
    out = _run(tmp_path, "--json", str(FIX / "macos-sample.json"), "--host", "mac-test")
    entries, os_queries, info = sbom.read(out)
    assert sorted(e["purl"] for e in entries) == [
        "pkg:pypi/altgraph@0.17.2", "pkg:pypi/future@0.18.2", "pkg:pypi/macholib@1.15.2", "pkg:pypi/pip@21.2.4",
        "pkg:pypi/pip@26.2.2", "pkg:pypi/setuptools@58.0.4", "pkg:pypi/six@1.15.0", "pkg:pypi/wheel@0.37.0"]
    assert os_queries == {}
    reasons = [n["reason"] for n in info["not_checked"]]
    assert len(reasons) == 16
    assert sum("Homebrew" in r for r in reasons) == 15 and sum("operating system" in r for r in reasons) == 1
    assert {e["labels"]["system"] for e in entries} == {"mac-test"}


def test_ubuntu_sample_source_packages_and_epochs(tmp_path):
    out = _run(tmp_path, "--json", str(FIX / "ubuntu-sample.json"))
    doc = json.loads((out / "ubuntu-sample.cdx.json").read_text())
    purls = {c["name"]: c.get("purl") for c in doc["components"]}
    # 'util-linux (2.39.3-9ubuntu6.6)': source name and source version; the binary's epoch kept as a qualifier
    assert purls["bsdutils"] == ("pkg:deb/ubuntu/bsdutils@2.39.3-9ubuntu6.6?arch=amd64&epoch=1&distro=ubuntu-24.04"
                                 "&upstream=util-linux%402.39.3-9ubuntu6.6")
    entries, os_queries, info = sbom.read(out)
    q = os_queries["pkg:deb/ubuntu/bsdutils@2.39.3-9ubuntu6.6?distro=ubuntu-24.04"]
    assert (q["ecosystem"], q["name"], q["version"]) == ("Ubuntu:24.04:LTS", "util-linux", "2.39.3-9ubuntu6.6")
    q = os_queries["pkg:deb/ubuntu/automake@1.16.5-1.3ubuntu1?distro=ubuntu-24.04"]
    assert (q["name"], q["version"]) == ("automake-1.16", "1:1.16.5-1.3ubuntu1")
    # Python packages the distro installed are left to the deb packages; home folders are shortened
    locations = {e["labels"].get("location") for e in entries if e["purl"].startswith("pkg:pypi/")}
    assert not any(str(x).startswith("/usr/lib/python3/") for x in locations)
    assert all(not str(x).startswith(("/root", "/home/")) for x in locations)
    assert any("~/.local/lib/python3.13" in str(x).split("; ") for x in locations)


def test_fleet_snapshot_log_one_sbom_per_host_latest_snapshot(tmp_path):
    out = _run(tmp_path, "--results", str(FIX / "fleet-results.log"))
    assert sorted(p.name for p in out.iterdir()) == ["web-01.cdx.json", "web-02.cdx.json"]
    entries, _, _ = sbom.read(out)
    assert not any("django" in e["purl"] for e in entries)  # the older web-01 snapshot is superseded
    # both hosts ran the same snapshot: one package entry each, naming both hosts
    assert {e["labels"]["system"] for e in entries} == {"web-01; web-02"}


def test_differential_results_refused(tmp_path):
    log = tmp_path / "diff.log"
    log.write_text(json.dumps({"name": "pack/x/deb_packages", "hostIdentifier": "h", "action": "added",
                               "columns": {"name": "curl", "version": "1"}}) + "\n")
    assert col.main(["--results", str(log), "--out", str(tmp_path / "o")]) == 2


@pytest.mark.parametrize("name, table", [
    ("deb_packages", "deb_packages"), ("pack/oss-intake/oss_intake_python_packages", "python_packages"),
    ("pack/Global/python_packages_app", "python_packages"), ("python", "python_packages"),
    ("pack/x/uptime", None), ("pack/x/python_packages2", None)])
def test_table_of(name, table):
    assert col.table_of(name) == table


def test_derivative_distro_not_guessed(tmp_path):
    raw = {"os_version": [{"name": "Linux Mint", "platform": "linuxmint", "major": "22", "minor": "1"}],
           "deb_packages": [{"name": "curl", "version": "8.5.0-2ubuntu10.6", "source": "", "arch": "amd64",
                             "status": "install ok installed"}]}
    f = tmp_path / "mint.json"
    f.write_text(json.dumps(raw))
    out = _run(tmp_path, "--json", str(f), "--host", "mint")
    entries, _, info = sbom.read(out)
    assert entries == [] and any("derivative" in n["reason"] for n in info["not_checked"])


def test_dir_quoting_and_validation(tmp_path):
    assert col._sql_string("/x/it's") == "'/x/it''s'"
    assert col.main(["--dir", str(tmp_path / "missing"), "--out", str(tmp_path / "o")]) == 2


def test_sbom_label_property_must_not_shadow_columns(tmp_path):
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        {"name": "x", "version": "1", "purl": "pkg:pypi/x@1",
         "properties": [{"name": "oss-intake:label:findings", "value": "low"}]}]}
    f = tmp_path / "s.cdx.json"
    f.write_text(json.dumps(doc))
    with pytest.raises(InputError, match="not a usable label"):
        sbom.read(f)
