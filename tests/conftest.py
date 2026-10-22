import json
from pathlib import Path
from urllib.parse import unquote

import pytest

from oss_intake.http import Http, HttpError

FIX = Path(__file__).parent / "fixtures"


def load(name: str):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


class FakeHttp(Http):
    """Routes requests to fixtures. Unknown URLs raise, so no test can reach the network."""

    def __init__(self, scorecard_status: int = 200, fail_hosts: tuple[str, ...] = ()):
        self.calls: list[str] = []
        self.scorecard_status = scorecard_status
        self.fail_hosts = fail_hosts
        self.depsdev = load("depsdev.json")

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
        if url.startswith("https://api.securityscorecards.dev/"):
            return (200, load("scorecard.json")) if self.scorecard_status == 200 else (self.scorecard_status, None)
        if url == "https://api.first.org/data/v1/epss":
            wanted = set((params or {}).get("cve", "").split(","))
            data = load("epss.json")
            return 200, {**data, "data": [r for r in data["data"] if r["cve"] in wanted]}
        if "known_exploited_vulnerabilities" in url:
            return 200, load("kev.json")
        raise AssertionError(f"unexpected GET {url}")

    def get_text(self, url):
        self._check(url)
        if url.endswith("/DSA/list"):
            return 200, (FIX / "debian_DSA_list.txt").read_text(encoding="utf-8")
        if url.endswith("/DLA/list"):
            return 200, (FIX / "debian_DLA_list.txt").read_text(encoding="utf-8")
        raise AssertionError(f"unexpected GET (text) {url}")

    def post_json(self, url, body):
        self._check(url)
        if url == "https://api.osv.dev/v1/querybatch":
            return 200, load("osv_querybatch.json")
        raise AssertionError(f"unexpected POST {url}")


@pytest.fixture
def fake_http():
    return FakeHttp()


@pytest.fixture
def fixtures():
    return FIX
