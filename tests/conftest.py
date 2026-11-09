import json
from pathlib import Path
from urllib.parse import unquote

import pytest

from oss_intake.http import Http, HttpError

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def _unexpected_errors_raise(monkeypatch):
    """cli.main turns an unexpected exception into exit 1 for users; in tests it must surface, so a test that
    expects exit 1 cannot pass because something broke (test_units checks the user-facing behaviour)."""
    monkeypatch.setenv("OSS_INTAKE_DEBUG", "1")


def load(name: str):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


class FakeHttp(Http):
    """Routes requests to fixtures. Unknown URLs raise, so no test can reach the network."""

    def __init__(self, scorecard_status: int = 200, fail_hosts: tuple[str, ...] = ()):
        self.calls: list[str] = []
        self.scorecard_status = scorecard_status
        self.fail_hosts = fail_hosts
        self.depsdev = load("depsdev.json")
        # Open VSX answers (URL to JSON) and downloads (URL to bytes or text) a test sets up; others are 404.
        self.openvsx: dict[str, dict] = {}
        self.crandb: dict[str, dict] = {}  # crandb answers (URL to JSON) a test sets up; others are 404
        self.jetbrains: dict[str, object] = {}  # JetBrains Marketplace answers a test sets up; others are 404
        self.files: dict[str, bytes] = {}

    def _check(self, url: str):
        self.calls.append(url)
        for h in self.fail_hosts:
            if h in url:
                raise HttpError(f"simulated failure for {h}")

    def get_json(self, url, params=None):
        self._check(url)
        if url.startswith("https://api.osv.dev/v1/vulns/"):
            vid = url.rsplit("/", 1)[1]
            p = FIX / f"osv_{vid}.json"
            return (200, load(p.name)) if p.exists() else (404, None)
        if url.startswith("https://api.deps.dev/v3/systems/"):
            rest = unquote(url[len("https://api.deps.dev/v3/systems/"):])
            system, _, tail = rest.partition("/packages/")
            name, _, version = tail.partition("/versions/")
            key = f"{system}/{name}/{version}"
            return (200, {"publishedAt": self.depsdev[key]}) if key in self.depsdev else (404, None)
        if url == "https://api.github.com/repos/example/webapp":
            return 200, load("github_repo.json")
        if url == "https://api.github.com/repos/example/webapp/releases":
            return 200, load("github_releases.json")
        if url.startswith("https://api.github.com/repos/"):
            return 404, {"message": "Not Found"}
        if url == "https://api.launchpad.net/1.0/ubuntu/series":
            return 200, {"entries": [{"version": "22.04", "name": "jammy",
                                      "self_link": "https://api.launchpad.net/1.0/ubuntu/jammy"},
                                     {"version": "24.04", "name": "noble",
                                      "self_link": "https://api.launchpad.net/1.0/ubuntu/noble"}]}
        if url == "https://api.launchpad.net/1.0/ubuntu/+archive/primary":
            key = f"{(params or {}).get('source_name')}/{(params or {}).get('version')}"
            data = load("launchpad.json")
            return 200, {"entries": data.get(key, [])}
        if url.startswith("https://api.securityscorecards.dev/"):
            return (200, load("scorecard.json")) if self.scorecard_status == 200 else (self.scorecard_status, None)
        if url == "https://api.first.org/data/v1/epss":
            wanted = set((params or {}).get("cve", "").split(","))
            data = load("epss.json")
            return 200, {**data, "data": [r for r in data["data"] if r["cve"] in wanted]}
        if "known_exploited_vulnerabilities" in url:
            return 200, load("kev.json")
        if url.endswith("/db/modules_metadata_base.json"):
            return 200, load("metasploit.json")
        if url.startswith("https://plugins.jetbrains.com/"):
            return (200, self.jetbrains[url]) if url in self.jetbrains else (404, {"msg": "not found"})
        if url.startswith("https://crandb.r-pkg.org/"):
            return (200, self.crandb[url]) if url in self.crandb else (404, {"error": "not_found"})
        if url.startswith("https://open-vsx.org/api/"):
            return (200, self.openvsx[url]) if url in self.openvsx else (404, {"error": "not found"})
        if url.startswith("https://raw.githubusercontent.com/nomi-sec/PoC-in-GitHub/"):
            p = FIX / "poc" / url.rsplit("/", 1)[1]
            return (200, json.loads(p.read_text(encoding="utf-8"))) if p.exists() else (404, None)
        raise AssertionError(f"unexpected GET {url}")

    def get_text(self, url):
        self._check(url)
        if url.endswith("/DSA/list"):
            return 200, (FIX / "debian_DSA_list.txt").read_text(encoding="utf-8")
        if url.endswith("/DLA/list"):
            return 200, (FIX / "debian_DLA_list.txt").read_text(encoding="utf-8")
        if url.endswith("/nuclei-templates/main/cves.json"):
            return 200, (FIX / "nuclei_cves.json").read_text(encoding="utf-8")
        if url.endswith("/files_exploits.csv"):
            return 200, (FIX / "exploitdb.csv").read_text(encoding="utf-8")
        if url == "https://raw.githubusercontent.com/microsoft/vsmarketplace/main/RemovedPackages.md":
            return 200, (FIX / "vscode_removed.md").read_text(encoding="utf-8")
        if url in self.files:
            return 200, self.files[url].decode("utf-8")
        if url == "https://go.dev/doc/devel/release":
            return 200, (FIX / "go_release.html").read_text(encoding="utf-8")
        if url.startswith("https://deb.debian.org/debian/dists/") and url.endswith("/ChangeLog"):
            p = FIX / f"debian_{url.split('/')[-2]}_ChangeLog.txt"
            return (200, p.read_text(encoding="utf-8")) if p.exists() else (404, "")
        raise AssertionError(f"unexpected GET (text) {url}")

    def get_bytes(self, url, limit):
        self._check(url)
        if url in self.files:
            if len(self.files[url]) > limit:
                raise HttpError(f"GET {url}: the answer is over the limit")
            return 200, self.files[url]
        if url.startswith("https://ntavakol.github.io/OSS-Intake/known-bad/"):
            return 404, b""  # the published known-bad list, unless a test sets it in files
        if url.startswith("https://plugins.jetbrains.com/"):
            return 404, b""  # a JetBrains download a test did not set up
        raise AssertionError(f"unexpected download {url}")

    def post_json(self, url, body):
        self._check(url)
        if url == "https://api.osv.dev/v1/querybatch":
            # One result per query, as OSV answers: the recorded results in order, then none. (The file holds
            # three, for the image fixture's packages; other runs ask for fewer or more.)
            recorded = load("osv_querybatch.json")["results"]
            n = len(body["queries"])
            return 200, {"results": (recorded + [{}] * n)[:n]}
        raise AssertionError(f"unexpected POST {url}")


@pytest.fixture
def fake_http():
    return FakeHttp()


@pytest.fixture
def fixtures():
    return FIX
