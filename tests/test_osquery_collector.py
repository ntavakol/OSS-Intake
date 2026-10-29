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


# --- review fixes (29 Oct) -----------------------------------------------------------------------------------

def test_real_osqueryd_log_default_pack_delimiter(tmp_path):
    """Written by osqueryd 5.24.0 with oss-intake-pack.conf loaded as pack 'oss-intake' and the default
    --pack_delimiter '_': names are pack_oss-intake_oss_intake_deb_packages."""
    out = _run(tmp_path, "--results", str(FIX / "osqueryd.snapshots.log"))
    entries, os_queries, _ = sbom.read(out)
    assert {p.name for p in out.iterdir()} == {"srv-01.cdx.json"}
    assert sum(e["purl"].startswith("pkg:deb/") for e in entries) == 15 and os_queries
    assert any(e["purl"].startswith("pkg:npm/") for e in entries)


@pytest.mark.parametrize("name, table", [
    ("pack_oss-intake_oss_intake_deb_packages", "deb_packages"),
    ("pack_Global_python_packages_app", "python_packages"), ("pack_x_uptime", None)])
def test_table_of_underscore_delimiter(name, table):
    assert col.table_of(name) == table


def test_snapshot_event_format(tmp_path):
    """--logger_snapshot_event_type: one line per row, action 'snapshot', no 'snapshot' key."""
    rows = [{"name": "curl", "version": "8.5.0-2ubuntu10.6", "source": "", "arch": "amd64",
             "status": "install ok installed"}, {"name": "bash", "version": "5.2.21-2ubuntu4", "source": "",
                                                 "arch": "amd64", "status": "install ok installed"}]
    os_row = {"name": "Ubuntu", "major": "24", "minor": "4", "platform": "ubuntu"}
    lines = [{"name": "pack_p_os_version", "hostIdentifier": "h1", "unixTime": 10, "action": "snapshot",
              "columns": os_row}]
    lines += [{"name": "pack_p_deb_packages", "hostIdentifier": "h1", "unixTime": 5, "action": "snapshot",
               "columns": {"name": "old", "version": "1", "status": "install ok installed"}}]
    lines += [{"name": "pack_p_deb_packages", "hostIdentifier": "h1", "unixTime": 10, "action": "snapshot",
               "columns": r} for r in rows]
    log = tmp_path / "events.log"
    log.write_text("".join(json.dumps(x) + "\n" for x in lines))
    entries, _, _ = sbom.read(_run(tmp_path, "--results", str(log)))
    assert sorted(e["purl"].split("@")[0] for e in entries) == ["pkg:deb/ubuntu/bash", "pkg:deb/ubuntu/curl"]


def _host(tmp_path, raw, host="h"):
    f = tmp_path / f"{host}.json"
    f.write_text(json.dumps(raw))
    out = tmp_path / f"out-{host}"
    assert col.main(["--json", str(f), "--host", host, "--out", str(out)]) == 0
    return sbom.read(out)


def test_distro_python_kept_where_os_packages_cannot_be_checked(tmp_path):
    py = [{"name": "requests", "version": "2.25.1", "directory": "/usr/lib/python3.9/site-packages/"}]
    rpm = [{"name": "python3-requests", "version": "2.25.1", "release": "6.el9", "arch": "noarch",
            "source": "python-requests-2.25.1-6.el9.src.rpm"}]
    rhel = {"os_version": [{"name": "Red Hat", "platform": "rhel", "major": "9", "minor": "4"}],
            "rpm_packages": rpm, "python_packages": py}
    entries, _, _ = _host(tmp_path, rhel, "rhel")
    assert "pkg:pypi/requests@2.25.1" in {e["purl"] for e in entries}
    rocky = dict(rhel, os_version=[{"name": "Rocky", "platform": "rocky", "major": "9", "minor": "4"}])
    entries, _, _ = _host(tmp_path, rocky, "rocky")
    assert "pkg:pypi/requests@2.25.1" not in {e["purl"] for e in entries}


def test_debian_testing_has_no_release(tmp_path):
    raw = {"os_version": [{"name": "Debian GNU/Linux", "platform": "debian", "major": "", "minor": ""}],
           "deb_packages": [{"name": "curl", "version": "8.11.1-1", "source": "", "arch": "amd64",
                             "status": "install ok installed"}]}
    entries, _, info = _host(tmp_path, raw, "sid")
    assert entries == [] and any("testing or unstable" in n["reason"] for n in info["not_checked"])


def test_half_configured_deb_kept_config_files_dropped(tmp_path):
    base = {"source": "", "arch": "amd64"}
    raw = {"os_version": [{"name": "Ubuntu", "platform": "ubuntu", "major": "24", "minor": "4"}],
           "deb_packages": [dict(base, name="libssl3t64", version="3.0.13-0ubuntu3.4",
                                 status="install ok half-configured"),
                            dict(base, name="gone", version="1.0-1", status="deinstall ok config-files")]}
    entries, _, _ = _host(tmp_path, raw, "half")
    assert [e["purl"].split("@")[0] for e in entries] == ["pkg:deb/ubuntu/libssl3t64"]


def test_host_file_names_never_collide(tmp_path):
    lines = [{"name": "python_packages", "hostIdentifier": h, "unixTime": 1,
              "snapshot": [{"name": f"pkg{i}", "version": "1.0", "directory": "/opt/x/"}]}
             for i, h in enumerate(["web 01", "web_01", "Web_01"])]
    log = tmp_path / "hosts.log"
    log.write_text("".join(json.dumps(x) + "\n" for x in lines))
    out = _run(tmp_path, "--results", str(log))
    assert len(list(out.iterdir())) == 3
    assert len({p.name.casefold() for p in out.iterdir()}) == 3


@pytest.mark.parametrize("path, masked", [
    ("/var/home/ned/app", "~/app"), ("/export/home/ned", "~"), ("c:\\users\\ned\\x", "~\\x"),
    ("C:/Users/ned/x", "~/x"), ("\\\\?\\C:\\Users\\ned\\x", "~\\x"), ("/root/.local", "~/.local"),
    ("/rootfs/x", "/rootfs/x"), ("/usr/lib/python3", "/usr/lib/python3")])
def test_mask_home(path, masked):
    assert col.mask_home(path) == masked


def test_dir_project_root_finds_its_venv(tmp_path):
    site = tmp_path / "app" / ".venv" / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    assert col._site_packages(tmp_path / "app") == str(site.resolve())
