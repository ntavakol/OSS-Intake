"""0.10.0 scale: parallel prefetch, the response cache, systems per package, and a 100,000-row inventory."""

import csv
import json
import threading
import time
import tracemalloc

import pytest

from oss_intake import cli, inventory_report, release_age
from oss_intake.http import CACHE_RULES, HttpError, RequestsHttp, ResponseCache
from oss_intake.scanners import osv

from .conftest import FakeHttp

AS_OF = "2026-10-01"


# --- ResponseCache ---------------------------------------------------------------------------------------------

def test_cache_rules_cover_slow_lookups_only():
    age = ResponseCache.max_age
    assert age("https://api.osv.dev/v1/vulns/GHSA-xxxx-yyyy-zzzz") == 86400
    assert age("https://api.deps.dev/v3/systems/npm/packages/chalk/versions/5.6.1") == 30 * 86400
    assert age("https://api.deps.dev/v3/systems/npm/packages/chalk") == 86400
    for fresh in ("https://api.osv.dev/v1/querybatch", "https://api.github.com/repos/a/b",
                  "https://api.first.org/data/v1/epss", "https://www.cisa.gov/kev.json",
                  "https://api.osv.dev/v1/vulns/X?x=1"):
        assert age(fresh) is None
    assert CACHE_RULES


def test_cache_round_trip_expiry_and_refusals(tmp_path):
    now = [1_000_000.0]
    c = ResponseCache(tmp_path, now=lambda: now[0])
    url = "https://api.osv.dev/v1/vulns/CVE-2099-1"
    assert c.get(url) is None
    c.put(url, 200, {"id": "CVE-2099-1"})
    c.put("https://api.osv.dev/v1/vulns/CVE-2099-2", 500, {"e": 1})  # an error is never kept
    c.put("https://api.osv.dev/v1/querybatch", 200, {})  # not a cached URL
    assert c.get(url) == (200, {"id": "CVE-2099-1"})
    assert c.get("https://api.osv.dev/v1/vulns/CVE-2099-2") is None
    assert c.writes == 1
    now[0] += 86401
    assert c.get(url) is None  # older than a day
    # a corrupt or foreign file is a miss, not a crash
    f = c._file(url)
    f.write_text("{not json", encoding="utf-8")
    assert c.get(url) is None


# --- RequestsHttp.prefetch (no network: the session is replaced) -------------------------------------------------

class _Resp:
    def __init__(self, status, data):
        self.status_code, self._data = status, data
        self.content = json.dumps(data).encode() if data is not None else b""

    def json(self):
        return self._data


class _Session:
    def __init__(self, log, lock, delay):
        self.headers, self.log, self.lock, self.delay = {}, log, lock, delay

    def request(self, method, url, **kw):
        with self.lock:
            self.log.append((threading.get_ident(), url))
        time.sleep(self.delay)
        if url.endswith("/boom"):
            import requests
            raise requests.ConnectionError("no route")
        return _Resp(200, {"url": url})


def _client(monkeypatch, tmp_path, delay=0.05, cache=True):
    import requests

    log, lock = [], threading.Lock()
    monkeypatch.setattr(requests, "Session", lambda: _Session(log, lock, delay))
    http = RequestsHttp(cache=ResponseCache(tmp_path / "c") if cache else None, workers=8, github_token="")
    return http, log


def test_prefetch_runs_in_parallel_and_serves_each_result_once(monkeypatch, tmp_path):
    """Parallel is measured against a sequential run in the same test, with no cache, so a slow runner (Windows
    CI, where every new file is scanned) cannot fail it: only "no faster than one at a time" does."""
    urls = [f"https://api.osv.dev/v1/vulns/CVE-2099-{i}" for i in range(40)]
    timings = {}
    for workers in (1, 8):
        http, log = _client(monkeypatch, tmp_path, cache=False)
        http._workers = workers
        t = time.monotonic()
        http.prefetch(urls + urls[:5])  # duplicates are fetched once
        timings[workers] = time.monotonic() - t
        assert len(log) == 40
    assert timings[8] < timings[1] / 2, timings
    assert len({tid for tid, _ in log}) > 1
    assert http.get_json(urls[3]) == (200, {"url": urls[3]})
    assert len(log) == 40  # answered from the prefetch


def test_second_run_answered_from_cache(monkeypatch, tmp_path):
    urls = [f"https://api.osv.dev/v1/vulns/CVE-2099-{i}" for i in range(40)]
    http, log = _client(monkeypatch, tmp_path, delay=0)
    http.prefetch(urls)
    assert len(log) == 40 and http.cache.writes == 40
    http2, log2 = _client(monkeypatch, tmp_path, delay=0)
    http2.prefetch(urls)
    assert log2 == [] and http2.cache.hits == 40


def test_prefetch_errors_surface_at_get_json(monkeypatch, tmp_path):
    http, _ = _client(monkeypatch, tmp_path, delay=0)
    http.prefetch(["https://api.osv.dev/v1/vulns/boom"])
    with pytest.raises(HttpError):
        http.get_json("https://api.osv.dev/v1/vulns/boom")


def test_no_cache_keeps_nothing(monkeypatch, tmp_path):
    http, log = _client(monkeypatch, tmp_path, delay=0, cache=False)
    http.get_json("https://api.osv.dev/v1/vulns/CVE-2099-1")
    http.get_json("https://api.osv.dev/v1/vulns/CVE-2099-1")
    assert len(log) == 2 and not (tmp_path / "c").exists()


def test_osv_scan_prefetches_every_advisory_before_reading():
    class H(FakeHttp):
        def __init__(self):
            super().__init__()
            self.prefetched = []

        def prefetch(self, urls):
            self.prefetched.append(list(urls))

        def post_json(self, url, body):
            return 200, {"results": [{"vulns": [{"id": "CVE-2099-1"}, {"id": "CVE-2099-2"}]} for _ in body["queries"]]}

    h = H()
    osv.scan(h, ["pkg:npm/a@1.0.0", "pkg:npm/b@1.0.0"])
    assert sorted(set(h.prefetched[0])) == ["https://api.osv.dev/v1/vulns/CVE-2099-1",
                                            "https://api.osv.dev/v1/vulns/CVE-2099-2"]


def test_release_age_limit_after_dedup():
    class H(FakeHttp):
        def get_json(self, url, params=None):
            self.calls.append(url)
            return 404, None

    h = H()
    purls = ["pkg:npm/a@1.0.0"] * 50 + [f"pkg:npm/p{i}@1.0.0" for i in range(10)]
    info = release_age.check(h, purls, __import__("datetime").datetime(2026, 10, 1), 7, limit=5)
    assert len(h.calls) == 5 and info["skipped_limit"] == 6 and info["status"] == "partial"


def test_cli_cache_options_validated(tmp_path):
    inv = tmp_path / "p.csv"
    inv.write_text("ecosystem,name,version\nnpm,a,1.0.0\n", encoding="utf-8")
    base = ["--path", str(inv), "--out", str(tmp_path / "o")]
    assert cli.main(base + ["--no-cache", "--cache-dir", str(tmp_path)], http=FakeHttp()) == cli.EXIT_USAGE
    assert cli.main(base + ["--release-age-max", "0"], http=FakeHttp()) == cli.EXIT_USAGE


# --- systems per package ------------------------------------------------------------------------------------------

def test_systems_count_and_abbreviation():
    assert inventory_report.systems({"system": "a; b; a"}) == 2
    assert inventory_report.systems({"host": "web-01"}) == 1
    assert inventory_report.systems({"owner": "x"}) is None
    long = "; ".join(f"h{i}" for i in range(30))
    assert inventory_report.abbreviate(long) == "h0; h1; h2; h3; h4; and 25 more"


# --- 100,000 rows -------------------------------------------------------------------------------------------------

class ScaleHttp(FakeHttp):
    """OSV with one vulnerable package; deps.dev knows nothing. Counts what is asked."""

    def __init__(self):
        super().__init__()
        self.queried = 0

    def post_json(self, url, body):
        self.queried += len(body["queries"])
        return 200, {"results": [{"vulns": [{"id": "GHSA-scal-e000-0001"}]}
                                 if q.get("package", {}).get("purl") == "pkg:npm/pkg-7@1.0.7" else {}
                                 for q in body["queries"]]}

    def get_json(self, url, params=None):
        if url.endswith("/vulns/GHSA-scal-e000-0001"):
            return 200, {"id": "GHSA-scal-e000-0001", "summary": "test", "affected": [
                {"package": {"ecosystem": "npm", "name": "pkg-7"},
                 "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.0.8"}]}]}],
                "database_specific": {"severity": "HIGH"}}
        if url.startswith("https://api.deps.dev/"):
            return 404, None
        return super().get_json(url, params)


def test_100k_row_inventory(tmp_path):
    """5,000 package versions on 20 hosts each: every version is asked once, packages.csv has 5,000 rows with
    the host count, package-systems.csv answers which hosts run the vulnerable one, and the run stays fast."""
    inv = tmp_path / "fleet.csv"
    with open(inv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["ecosystem", "name", "version", "system"])
        for h in range(20):
            for p in range(5000):
                w.writerow(["npm", f"pkg-{p}", f"1.0.{p % 10}", f"host-{h:02d}"])
    out = tmp_path / "o"
    http = ScaleHttp()
    tracemalloc.start()
    t = time.monotonic()
    code = cli.main(["--path", str(inv), "--out", str(out), "--no-latest", "--release-age-days", "0",
                     "--no-cache", "--as-of", AS_OF, "--no-epss", "--no-kev", "--no-exploits"], http=http)
    elapsed = time.monotonic() - t
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert code == cli.EXIT_OK
    assert http.queried == 5000
    rows = list(csv.DictReader((out / "packages.csv").open(encoding="utf-8", newline="")))
    assert len(rows) == 5000
    top = rows[0]
    assert (top["package"], top["version"], top["systems"]) == ("pkg-7", "1.0.7", "20")
    assert "and 0 more" not in top["system"] and top["system"].count(";") <= 20
    systems = [r for r in csv.DictReader((out / "package-systems.csv").open(encoding="utf-8", newline=""))
               if r["package"] == "pkg-7"]
    assert len(systems) == 20 and systems[0]["findings"] == "1"
    assert elapsed < 120, f"100k rows took {elapsed:.0f} s"
    assert peak < 1024 * 1024 * 1024, f"peak memory {peak / 1e6:.0f} MB"


# --- review fixes (29 Oct) -----------------------------------------------------------------------------------

def test_not_found_is_never_cached(tmp_path):
    """A version deps.dev has not indexed yet answers 404 today and a date tomorrow: keeping the 404 would let a
    brand-new release pass --fail-on recent for as long as the entry lived."""
    c = ResponseCache(tmp_path)
    url = "https://api.deps.dev/v3/systems/npm/packages/chalk/versions/9.9.9"
    c.put(url, 404, None)
    assert c.get(url) is None and c.writes == 0


@pytest.mark.parametrize("record", [
    [], "x", {"url": "U", "fetched": 1e12, "status": 200, "data": {}},  # not an entry; from the future
    {"url": "U", "fetched": 1_000_000.0, "status": 404, "data": None}])  # an old-format 404
def test_cache_ignores_untrustworthy_entries(tmp_path, record):
    url = "https://api.osv.dev/v1/vulns/CVE-2099-9"
    c = ResponseCache(tmp_path, now=lambda: 1_000_100.0)
    f = c._file(url)
    f.parent.mkdir(parents=True)
    if isinstance(record, dict):
        record = {**record, "url": url}
    f.write_text(json.dumps(record), encoding="utf-8")
    assert c.get(url) is None


@pytest.mark.skipif(__import__("os").name == "nt", reason="POSIX permissions")
def test_cache_folder_others_can_write_is_not_used(tmp_path, capsys):
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    assert "other users" in ResponseCache(shared).unsafe_reason()
    own = tmp_path / "own"
    assert ResponseCache(own).unsafe_reason() is None


def test_prefetch_stops_after_repeated_failures(monkeypatch, tmp_path):
    http, log = _client(monkeypatch, tmp_path, delay=0, cache=False)
    http._workers = 1  # deterministic order
    urls = [f"https://api.osv.dev/v1/vulns/boom?{i}" for i in range(40)]
    monkeypatch.setattr(http, "_get_cached", lambda u: (_ for _ in ()).throw(HttpError("down")) if log.append(u)
                        is None else None)
    http.prefetch(urls)
    assert len(log) == 3
    with pytest.raises(HttpError, match="repeated failures"):
        http.get_json(urls[-1])


def test_text_downloads_are_counted(monkeypatch, tmp_path):
    http, log = _client(monkeypatch, tmp_path, delay=0, cache=False)

    class R:
        status_code, content = 200, b"x"

    monkeypatch.setattr(http._session, "get", lambda *a, **k: R(), raising=False)
    http.get_text("https://example.invalid/list")
    assert http.requests_made == 1


def test_host_column_preferred_over_system(tmp_path):
    inv = tmp_path / "p.csv"
    lines = ["ecosystem,name,version,system,host"] + [f"npm,a,1.0.0,CRM,h{i}" for i in range(25)]
    inv.write_text("\n".join(lines) + "\n", encoding="utf-8")
    out = tmp_path / "o"
    assert cli.main(["--path", str(inv), "--out", str(out), "--no-latest", "--release-age-days", "0", "--no-cache",
                     "--no-epss", "--no-kev", "--no-exploits"], http=ScaleHttp()) == cli.EXIT_OK
    row = next(csv.DictReader((out / "packages.csv").open(encoding="utf-8", newline="")))
    assert row["systems"] == "25" and row["system"] == "CRM" and "and 5 more" in row["host"]
    pairs = list(csv.DictReader((out / "package-systems.csv").open(encoding="utf-8", newline="")))
    assert len(pairs) == 25


def test_inventory_column_named_like_a_report_column_refused(tmp_path, capsys):
    inv = tmp_path / "p.csv"
    inv.write_text("purl,systems\npkg:npm/a@1.0.0,CRM\n", encoding="utf-8")
    assert cli.main(["--path", str(inv), "--out", str(tmp_path / "o")], http=ScaleHttp()) == cli.EXIT_USAGE
    assert "systems" in capsys.readouterr().err


def test_every_prefetched_url_is_then_asked_for(tmp_path):
    """Prefetch lists are written apart from the loops that use them: a drift would waste requests or pass a
    cap (proof-of-concept lookups). Run with every enrichment on and check prefetched <= requested."""

    class Checking(ScaleHttp):
        def __init__(self):
            super().__init__()
            self.prefetched, self.asked = set(), set()

        def prefetch(self, urls):
            self.prefetched |= set(urls)

        def get_json(self, url, params=None):
            self.asked.add(url)
            if url.startswith("https://api.osv.dev/v1/vulns/GHSA-scal"):
                v = super().get_json(url, params)[1]
                return 200, {**v, "aliases": ["CVE-2021-44228"]}
            return super().get_json(url, params)

    inv = tmp_path / "p.csv"
    rows = "".join(f"npm,pkg-{p},1.0.{p % 10}\n" for p in range(30))
    inv.write_text("ecosystem,name,version\n" + rows, encoding="utf-8")
    h = Checking()
    cli.main(["--path", str(inv), "--out", str(tmp_path / "o"), "--no-cache", "--as-of", AS_OF], http=h)
    assert h.prefetched and h.prefetched <= h.asked
