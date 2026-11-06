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


def test_release_age_version_encoded_once():
    """pkg:golang/x@v2.0.0%2Bincompatible was sent as v2.0.0%252Bincompatible, which deps.dev answers 404."""

    class H(FakeHttp):
        def get_json(self, url, params=None):
            self.calls.append(url)
            return 404, None

    h = H()
    release_age.check(h, ["pkg:golang/github.com/x/y@v2.0.0%2Bincompatible"],
                      __import__("datetime").datetime(2026, 10, 1), 7)
    assert h.calls == ["https://api.deps.dev/v3/systems/go/packages/github.com%2Fx%2Fy/versions/v2.0.0%2Bincompatible"]


# --- --fail-on unknown-age (30 Oct) ----------------------------------------------------------------------------

class AgeHttp(ScaleHttp):
    """deps.dev knows one npm version (published long ago); everything else is 404, or fails if asked to."""

    def __init__(self, fail=False):
        super().__init__()
        self.fail = fail

    def get_json(self, url, params=None):
        if url.startswith("https://api.deps.dev/"):
            if self.fail:
                from oss_intake.http import HttpError as E
                raise E("down")
            if url.endswith("/npm/packages/known/versions/1.0.0"):
                return 200, {"publishedAt": "2020-01-01T00:00:00Z"}
            return 404, None
        return super().get_json(url, params)


def _age_run(tmp_path, rows, http, extra=()):
    inv = tmp_path / "p.csv"
    inv.write_text("ecosystem,name,version\n" + "".join(f"{r}\n" for r in rows), encoding="utf-8")
    return cli.main(["--path", str(inv), "--out", str(tmp_path / "o"), "--no-latest", "--no-cache", "--no-epss",
                     "--no-kev", "--no-exploits", "--as-of", AS_OF, "--fail-on", "unknown-age", *extra], http=http)


def test_unknown_age_fails_on_versions_without_a_date(tmp_path, capsys):
    """A version deps.dev has not indexed (likely when it is hours old) and a gem deps.dev does not cover."""
    assert _age_run(tmp_path, ["npm,known,1.0.0", "npm,brand-new,9.9.9", "gem,rails,7.1.0"], AgeHttp()) \
        == cli.EXIT_THRESHOLD
    err = capsys.readouterr().err
    assert "--fail-on unknown-age" in err and "pkg:npm/brand-new@9.9.9" in err and "pkg:gem/rails@7.1.0" in err


def test_unknown_age_passes_when_every_date_is_known(tmp_path):
    assert _age_run(tmp_path, ["npm,known,1.0.0"], AgeHttp()) == cli.EXIT_OK


def test_unknown_age_ignores_distro_packages(tmp_path):
    """A deb or rpm is not a registry release that can be hours old: never counted."""
    from oss_intake import release_age as ra

    info = ra.check(AgeHttp(), ["pkg:deb/ubuntu/curl@8.5.0-2ubuntu10.6?distro=ubuntu-24.04",
                                "pkg:npm/known@1.0.0"],
                    __import__("datetime").datetime(2026, 10, 1, tzinfo=__import__("datetime").timezone.utc), 7)
    assert info["unsupported"] == 1 and info["unsupported_purls"] == [] and info["unknown_purls"] == []


def test_unknown_age_that_could_not_run_fails_with_exit_1(tmp_path, capsys):
    assert _age_run(tmp_path, ["npm,known,1.0.0"], AgeHttp(fail=True)) == cli.EXIT_ERROR
    assert "could not be evaluated" in capsys.readouterr().err


def test_unknown_age_refused_without_the_date_check(tmp_path, capsys):
    assert _age_run(tmp_path, ["npm,known,1.0.0"], AgeHttp(), ["--release-age-days", "0"]) == cli.EXIT_USAGE
    assert "--fail-on unknown-age needs the release date check" in capsys.readouterr().err


def test_unknown_age_names_versions_never_looked_up_even_when_it_trips(tmp_path, capsys):
    """A gem trips the gate; a deps.dev error on another version must still be named, or accepting the gem
    after a look would accept a version nobody checked."""

    class Mixed(AgeHttp):
        def get_json(self, url, params=None):
            if "brand-new" in url:
                return 503, None
            return super().get_json(url, params)

    assert _age_run(tmp_path, ["npm,brand-new,1.0.0", "gem,rails,7.1.0"], Mixed(), ["--quiet"]) == cli.EXIT_THRESHOLD
    err = capsys.readouterr().err
    assert "pkg:gem/rails@7.1.0" in err and "not looked up" in err and "pkg:npm/brand-new@1.0.0" in err


def test_stdlib_skipped_only_for_go(tmp_path, capsys):
    assert _age_run(tmp_path, ["npm,stdlib,0.0.96"], AgeHttp()) == cli.EXIT_THRESHOLD  # 404: no date
    assert "pkg:npm/stdlib@0.0.96" in capsys.readouterr().err


def test_distro_only_image_passes_the_age_gates(tmp_path, fixtures):
    """A scan that found only distro packages has nothing a registry release date applies to: not 'not checked'."""
    report = json.loads((fixtures / "trivy.json").read_text(encoding="utf-8"))
    report["Results"] = [r for r in report["Results"] if r.get("Class") == "os-pkgs"]
    trivy = tmp_path / "trivy.json"
    trivy.write_text(json.dumps(report), encoding="utf-8")
    code = cli.main(["--image", "example/webapp:2.0.0", "--out", str(tmp_path / "o"), "--from-trivy-json",
                     str(trivy), "--scanners", "trivy", "--no-scorecard", "--no-workflows", "--no-cache",
                     "--as-of", AS_OF, "--fail-on", "unknown-age,recent"], http=AgeHttp())
    assert code == cli.EXIT_OK


def test_dateless_version_answer_not_cached(tmp_path):
    c = ResponseCache(tmp_path)
    url = "https://api.deps.dev/v3/systems/npm/packages/x/versions/1.0.0"
    c.put(url, 200, {"versionKey": {}})  # known, but no publishedAt yet
    assert c.writes == 0
    c.put(url, 200, {"publishedAt": "2026-10-01T00:00:00Z"})
    assert c.writes == 1


# --- Size limits and a total deadline (threat model open item, 6 Nov) -----------------------------------------

class _Streamed:
    """An answer sent in chunks, as requests gives with stream=True; content is the whole body, as the old
    non-streaming read took it."""
    def __init__(self, chunks, delay=0.0):
        self.status_code, self._chunks, self._delay, self.closed = 200, chunks, delay, False

    @property
    def content(self):
        return b"".join(self._chunks)

    def json(self):
        return json.loads(self.content)

    def iter_content(self, size):
        for c in self._chunks:
            time.sleep(self._delay)
            yield c

    def close(self):
        self.closed = True


def _streamed_client(monkeypatch, resp):
    import requests

    class S:
        headers: dict = {}

        def request(self, method, url, **kw):
            return resp

        def get(self, url, **kw):
            return resp

    monkeypatch.setattr(requests, "Session", lambda: S())
    return RequestsHttp(github_token="")


def test_service_answer_over_the_size_limit_is_a_failed_request(monkeypatch):
    from oss_intake import http as http_mod

    monkeypatch.setattr(http_mod, "MAX_RESPONSE_BYTES", 1000)
    resp = _Streamed([b'{"a": "' + b"x" * 600, b"x" * 600 + b'"}'])
    h = _streamed_client(monkeypatch, resp)
    with pytest.raises(HttpError, match="over 0 MB"):
        h.get_json("https://api.osv.dev/v1/vulns/GHSA-x")
    assert resp.closed
    with pytest.raises(HttpError, match="over 0 MB"):
        h.get_text("https://example.invalid/list")


def test_service_answer_past_the_deadline_is_a_failed_request(monkeypatch):
    """Each read was bounded by the timeout but the whole answer was not: a byte at a time held the run."""
    from oss_intake import http as http_mod

    monkeypatch.setattr(http_mod, "DEADLINE_SECONDS", 0.05)
    h = _streamed_client(monkeypatch, _Streamed([b"{", b'"a"', b":", b"1", b"}"], delay=0.03))
    h._timeout = 0  # so the deadline is DEADLINE_SECONDS, not twice the timeout
    with pytest.raises(HttpError, match="longer than the deadline"):
        h.get_json("https://api.osv.dev/v1/vulns/GHSA-x")


def test_service_answer_within_the_limits_is_read(monkeypatch):
    h = _streamed_client(monkeypatch, _Streamed([b'{"a"', b": 1}"]))
    assert h.get_json("https://api.osv.dev/v1/vulns/GHSA-x") == (200, {"a": 1})


@pytest.mark.parametrize("kind", ["inventory", "decisions-csv", "decisions-openvex", "renv"])
def test_input_file_over_the_size_limit_is_refused(tmp_path, monkeypatch, kind):
    from oss_intake import decisions, inputs

    monkeypatch.setattr(inputs, "MAX_INPUT_BYTES", 100)
    monkeypatch.setattr(decisions, "MAX_INPUT_BYTES", 100)
    if kind == "inventory":
        p = tmp_path / "p.csv"
        p.write_text("ecosystem,name,version\n" + "npm,a,1.0.0\n" * 20, encoding="utf-8")
        call = lambda: inputs.inventory(p)  # noqa: E731
    elif kind == "decisions-csv":
        p = tmp_path / "d.csv"
        p.write_text("vuln_id,package,decision\n" + "CVE-2099-1,a,fixed\n" * 20, encoding="utf-8")
        call = lambda: decisions.load(p)  # noqa: E731
    elif kind == "decisions-openvex":
        p = tmp_path / "d.json"
        p.write_text(json.dumps({"@context": "https://openvex.dev/ns/v0.2.0", "statements": [{}] * 50}),
                     encoding="utf-8")
        call = lambda: decisions.load(p)  # noqa: E731
    else:
        p = tmp_path / "renv.lock"
        p.write_text(json.dumps({"Packages": {f"p{i}": {"Package": f"p{i}"} for i in range(20)}}), encoding="utf-8")
        call = lambda: inputs.renv_purls(p)  # noqa: E731
    with pytest.raises(inputs.InputError, match="larger than 0 MB"):
        call()


def test_imported_report_over_the_size_limit_is_refused(tmp_path, fixtures, monkeypatch, capsys):
    from oss_intake import inputs

    monkeypatch.setattr(inputs, "MAX_REPORT_BYTES", 100)
    code = cli.main(["--image", "example/webapp:2.0.0", "--out", str(tmp_path / "o"), "--offline", "--scanners",
                     "trivy", "--from-trivy-json", str(fixtures / "trivy.json"), "--no-cache"])
    assert code == cli.EXIT_USAGE and "--from-trivy-json trivy.json is larger than" in capsys.readouterr().err


def test_sbom_over_the_size_limit_is_refused_not_scanned(tmp_path, monkeypatch):
    """It was classified as a plain file and given to the scanners, which found nothing in it."""
    from oss_intake import inputs, sbom

    p = tmp_path / "big.cdx.json"
    p.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
        {"type": "library", "name": f"p{i}", "purl": f"pkg:npm/p{i}@1.0.0"} for i in range(50)]}), encoding="utf-8")
    monkeypatch.setattr(sbom, "MAX_FILE_BYTES", 100)
    assert inputs.classify(p) == "sbom"
    with pytest.raises(inputs.InputError, match="larger than"):
        sbom.read(p)


# --- The cache's subfolders, entries and parents (threat model open item, 6 Nov) -------------------------------

_POSIX = pytest.mark.skipif(not hasattr(__import__("os"), "getuid"), reason="POSIX permissions")
_CACHE_URL = "https://api.osv.dev/v1/vulns/GHSA-test"


@_POSIX
def test_cache_entry_others_can_write_is_not_used(tmp_path):
    c = ResponseCache(tmp_path / "c")
    c.put(_CACHE_URL, 200, {"id": "GHSA-test"})
    assert c.get(_CACHE_URL) == (200, {"id": "GHSA-test"})
    f = c._file(_CACHE_URL)
    f.chmod(0o666)
    assert c.get(_CACHE_URL) is None
    f.chmod(0o600)
    f.parent.chmod(0o777)  # a subfolder others can write to: they could replace the entry
    assert c.get(_CACHE_URL) is None


@_POSIX
def test_cache_entry_that_is_a_link_is_not_used(tmp_path):
    c = ResponseCache(tmp_path / "c")
    c.put(_CACHE_URL, 200, {"id": "GHSA-test"})
    f = c._file(_CACHE_URL)
    planted = tmp_path / "planted.json"
    planted.write_text(f.read_text(encoding="utf-8"), encoding="utf-8")
    planted.chmod(0o600)
    f.unlink()
    f.symlink_to(planted)
    assert c.get(_CACHE_URL) is None


@_POSIX
def test_cache_entries_are_written_for_this_user_only_whatever_the_umask(tmp_path):
    import os

    old = os.umask(0o002)
    try:
        c = ResponseCache(tmp_path / "c")
        c.put(_CACHE_URL, 200, {"id": "GHSA-test"})
    finally:
        os.umask(old)
    assert c._file(_CACHE_URL).stat().st_mode & 0o777 == 0o600
    assert c.get(_CACHE_URL) == (200, {"id": "GHSA-test"})


@_POSIX
def test_cache_under_a_folder_others_can_write_is_not_used(tmp_path):
    """Only the nearest existing folder was checked: whoever can write to a parent can swap the cache folder."""
    shared = tmp_path / "shared"
    (shared / "c").mkdir(parents=True)
    shared.chmod(0o777)  # writable by others, not sticky
    (shared / "c").chmod(0o700)
    try:
        assert "can be written by other users" in (ResponseCache(shared / "c").unsafe_reason() or "")
        shared.chmod(0o1777)  # sticky, as /tmp is: others cannot rename the folder away
        assert ResponseCache(shared / "c").unsafe_reason() is None
    finally:
        shared.chmod(0o700)


def test_cache_outside_the_user_profile_on_windows_is_not_used(tmp_path, monkeypatch):
    """The folder was not checked at all on Windows. Its permissions are not read there, so only a folder in the
    user's own profile is trusted."""
    monkeypatch.setattr(__import__("pathlib").Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    (tmp_path / "home").mkdir()
    assert ResponseCache(tmp_path / "home" / "cache").unsafe_reason(windows=True) is None
    why = ResponseCache(tmp_path / "shared" / "cache").unsafe_reason(windows=True)
    assert why and "outside your user profile" in why


@_POSIX
def test_cache_made_under_umask_002_is_still_trusted_on_the_next_run(tmp_path):
    """Review (6 Nov): with umask 002 the first run made ~/.cache group-writable, and every later run then refused
    the cache. Folders it makes are 0700 whatever the umask."""
    import os

    folder = tmp_path / "home" / ".cache" / "oss-intake"
    old = os.umask(0o002)
    try:
        ResponseCache(folder).put(_CACHE_URL, 200, {"id": "GHSA-test"})
    finally:
        os.umask(old)
    assert (tmp_path / "home" / ".cache").stat().st_mode & 0o777 == 0o700
    assert ResponseCache(folder).unsafe_reason() is None
    assert ResponseCache(folder).get(_CACHE_URL) == (200, {"id": "GHSA-test"})


def test_group_write_by_the_users_private_group_is_not_others(monkeypatch):
    import stat

    from oss_intake import http

    monkeypatch.setattr(http, "_private_group", lambda gid: gid == 1000)
    assert not http._others_can_write(0o775 | stat.S_IFDIR, 1000)
    assert http._others_can_write(0o775 | stat.S_IFDIR, 50)
    assert http._others_can_write(0o757 | stat.S_IFDIR, 1000)


def test_deadline_holds_against_a_real_server_sending_a_byte_at_a_time(monkeypatch):
    """Review (6 Nov): with a Content-Length answer, iter_content waited to fill each 64 KiB chunk, and each
    socket read needed only a byte within the timeout, so the deadline was not checked until the server closed."""
    import socket

    from oss_intake import http as http_mod

    for var in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setattr(http_mod, "DEADLINE_SECONDS", 1)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    stop = threading.Event()

    def serve():
        c, _ = srv.accept()
        c.recv(65536)
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n")
        try:
            for _ in range(60):  # 6 s, then the connection closes, so code without the deadline fails, not hangs
                if stop.is_set():
                    break
                c.sendall(b" ")
                time.sleep(0.1)
        except OSError:
            pass
        finally:
            c.close()

    threading.Thread(target=serve, daemon=True).start()
    h = RequestsHttp(timeout=0)
    h._timeout = 0.5  # each read gets a byte well inside this; only the deadline (1 s) can stop the answer
    t = time.monotonic()
    try:
        with pytest.raises(HttpError, match="longer than the deadline"):
            h.get_json(f"http://127.0.0.1:{srv.getsockname()[1]}/x")
    finally:
        stop.set()
        srv.close()
    assert time.monotonic() - t < 4


def test_operator_can_vouch_for_a_windows_cache_outside_the_profile(tmp_path, monkeypatch):
    """Ned (7 Nov): a --cache-dir outside the profile on Windows (a CI workspace on D:) is used when the operator
    says only they can write to it; the refusal says how."""
    monkeypatch.setattr(__import__("pathlib").Path, "home", classmethod(lambda cls: tmp_path / "home"))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    (tmp_path / "home").mkdir()
    c = ResponseCache(tmp_path / "ci" / "cache")
    assert "--trust-cache-dir" in (c.unsafe_reason(windows=True) or "")
    assert c.unsafe_reason(windows=True, operator_trusted=True) is None


@_POSIX
def test_operator_cannot_vouch_over_permissions_that_are_read(tmp_path):
    c = ResponseCache(tmp_path / "c")
    (tmp_path / "c").mkdir(mode=0o700)
    (tmp_path / "c").chmod(0o777)
    try:
        assert "can be written by other users" in (c.unsafe_reason(windows=False, operator_trusted=True) or "")
    finally:
        (tmp_path / "c").chmod(0o700)


def test_trust_cache_dir_needs_cache_dir(tmp_path, capsys):
    code = cli.main(["--image", "example/webapp:2.0.0", "--out", str(tmp_path / "o"), "--trust-cache-dir"])
    assert code == cli.EXIT_USAGE and "--trust-cache-dir needs --cache-dir" in capsys.readouterr().err


# --- SBOM subjects and size (audit, 7 Nov) ------------------------------------------------------------------

def _sbom_file(tmp_path, doc, name="s.cdx.json"):
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def test_sbom_subject_package_is_checked_too(tmp_path):
    """The subject of a vendor SBOM for a library is the library: it, and components nested under it, were
    dropped silently, so the SBOM read as clean for that library."""
    from oss_intake import sbom

    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6",
           "metadata": {"component": {"type": "library", "name": "lodash", "version": "4.17.20",
                                      "purl": "pkg:npm/lodash@4.17.20",
                                      "components": [{"type": "library", "name": "minimist", "version": "1.2.0",
                                                      "purl": "pkg:npm/minimist@1.2.0"}]}},
           "components": [{"type": "library", "name": "x", "version": "1.0.0", "purl": "pkg:npm/x@1.0.0"}]}
    entries, _, _ = sbom.read(_sbom_file(tmp_path, cdx))
    assert {e["purl"] for e in entries} == {"pkg:npm/lodash@4.17.20", "pkg:npm/minimist@1.2.0", "pkg:npm/x@1.0.0"}
    spdx = {"spdxVersion": "SPDX-2.3", "name": "doc", "documentDescribes": ["SPDXRef-a"], "packages": [
        {"SPDXID": "SPDXRef-a", "name": "lodash", "versionInfo": "4.17.20", "externalRefs": [
            {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
             "referenceLocator": "pkg:npm/lodash@4.17.20"}]},
        {"SPDXID": "SPDXRef-b", "name": "minimist", "versionInfo": "1.2.0", "externalRefs": [
            {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
             "referenceLocator": "pkg:npm/minimist@1.2.0"}]}]}
    entries, _, _ = sbom.read(_sbom_file(tmp_path, spdx, "s.spdx.json"))
    assert {e["purl"] for e in entries} == {"pkg:npm/lodash@4.17.20", "pkg:npm/minimist@1.2.0"}


def test_image_subject_is_not_a_package(tmp_path):
    from oss_intake import sbom

    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6",
           "metadata": {"component": {"type": "container", "name": "app", "purl": "pkg:oci/app@sha256:aa"}},
           "components": [{"type": "library", "name": "x", "version": "1.0.0", "purl": "pkg:npm/x@1.0.0"}]}
    entries, _, info = sbom.read(_sbom_file(tmp_path, cdx))
    assert [e["purl"] for e in entries] == ["pkg:npm/x@1.0.0"] and info["not_checked"] == []


def test_huge_component_list_is_refused_quickly(tmp_path, monkeypatch):
    """The walk took list.pop(0), quadratic: a million empty components hung the run before the limit applied."""
    from oss_intake import inputs, sbom

    monkeypatch.setattr(sbom, "MAX_COMPONENTS", 100_000)
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{}] * 300_000}
    p = _sbom_file(tmp_path, cdx)
    t = time.monotonic()
    with pytest.raises(inputs.InputError, match="more than 100000 components"):
        sbom.read(p)
    assert time.monotonic() - t < 3  # the quadratic walk took about 10 s here
