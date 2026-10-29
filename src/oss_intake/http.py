"""Thin HTTP wrapper so network access is explicit, testable and never leaks tokens.

Two things make large inventories practical:
  prefetch(urls)  fetches a known list of GET URLs a few at a time in parallel; the get_json calls that follow
                  are answered from memory, so the code that uses the results stays sequential and simple.
  ResponseCache   keeps responses that change slowly (advisory details, release dates) on disk for a limited
                  time, so a weekly re-run does not repeat every lookup. What affects a version (OSV querybatch),
                  KEV, EPSS and the exploit indexes are always fetched fresh.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse

from . import __version__

USER_AGENT = f"oss-intake/{__version__}"
DEFAULT_TIMEOUT = 30
GITHUB_API_HOST = "api.github.com"


DEFAULT_WORKERS = 8
DAY = 86400
# (URL pattern, how long a response stays usable). GitHub API responses are never cached: they are personal to
# the token and rate limited per user, and the cache folder is not the place for them.
CACHE_RULES: list[tuple[re.Pattern, int]] = [
    (re.compile(r"^https://api\.osv\.dev/v1/vulns/[^/?]+$"), DAY),
    # A version's publication date never changes.
    (re.compile(r"^https://api\.deps\.dev/v3/systems/[^/]+/packages/[^/]+/versions/[^/?]+$"), 30 * DAY),
    (re.compile(r"^https://api\.deps\.dev/v3/systems/[^/]+/packages/[^/?]+$"), DAY),
    (re.compile(r"^https://raw\.githubusercontent\.com/nomi-sec/PoC-in-GitHub/master/\d{4}/CVE-[\d-]+\.json$"),
     7 * DAY),
]


class HttpError(Exception):
    """Network or protocol failure. Messages never include request headers."""


def default_cache_dir() -> Path:
    if os.name == "nt":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "oss-intake" / "cache"
    if os.uname().sysname == "Darwin":
        return Path.home() / "Library" / "Caches" / "oss-intake"
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "oss-intake"


class ResponseCache:
    """Successful (200) and not-found (404) JSON responses for the URLs in CACHE_RULES, one file per URL."""

    def __init__(self, folder: Path, now=time.time) -> None:
        self.folder = folder
        self._now = now
        self.hits = self.misses = self.writes = 0
        self._lock = threading.Lock()

    @staticmethod
    def max_age(url: str) -> int | None:
        return next((age for pattern, age in CACHE_RULES if pattern.match(url)), None)

    def _file(self, url: str) -> Path:
        h = hashlib.sha256(url.encode()).hexdigest()
        return self.folder / h[:2] / f"{h}.json"

    def get(self, url: str) -> tuple[int, Any] | None:
        age = self.max_age(url)
        if age is None:
            return None
        try:
            rec = json.loads(self._file(url).read_text(encoding="utf-8"))
            if rec.get("url") == url and self._now() - float(rec["fetched"]) <= age and rec["status"] in (200, 404):
                with self._lock:
                    self.hits += 1
                return int(rec["status"]), rec.get("data")
        except (OSError, ValueError, KeyError, TypeError):
            pass
        with self._lock:
            self.misses += 1
        return None

    def put(self, url: str, status: int, data: Any) -> None:
        if status not in (200, 404) or self.max_age(url) is None:
            return
        f = self._file(url)
        try:
            f.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = f.with_suffix(f".{threading.get_ident()}.tmp")
            tmp.write_text(json.dumps({"url": url, "fetched": self._now(), "status": status, "data": data}),
                           encoding="utf-8")
            os.replace(tmp, f)
            with self._lock:
                self.writes += 1
        except OSError:
            pass  # a cache that cannot be written is only slower

    def stats(self) -> dict:
        return {"folder": str(self.folder), "hits": self.hits, "misses": self.misses, "written": self.writes}


class Http:
    """Interface used by all network-facing modules. Tests substitute a fake."""

    def get_json(self, url: str, params: dict | None = None) -> tuple[int, Any]:
        raise NotImplementedError

    def post_json(self, url: str, body: Any) -> tuple[int, Any]:
        raise NotImplementedError

    def get_text(self, url: str) -> tuple[int, str]:
        raise NotImplementedError

    def prefetch(self, urls) -> None:
        """Fetch these GET URLs ahead of the get_json calls that will ask for them. Optional: the default does
        nothing, and every get_json still works without it."""


class RequestsHttp(Http):
    def __init__(self, timeout: int = DEFAULT_TIMEOUT, github_token: str | None = None,
                 cache: ResponseCache | None = None, workers: int = DEFAULT_WORKERS) -> None:
        import requests

        self._requests = requests
        self._local = threading.local()
        self._timeout = timeout
        # Read once, held privately, attached only to api.github.com requests, never logged.
        self._github_token = github_token if github_token is not None else os.environ.get("GITHUB_TOKEN")
        self.cache = cache
        self._workers = max(1, workers)
        self._ready: dict[str, tuple[int, Any] | HttpError] = {}
        self.requests_made = 0
        self._count_lock = threading.Lock()

    @property
    def _session(self):
        # requests.Session is not documented as thread-safe: one per thread.
        s = getattr(self._local, "session", None)
        if s is None:
            s = self._local.session = self._requests.Session()
            s.headers["User-Agent"] = USER_AGENT
        return s

    def _headers(self, url: str) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if urlparse(url).hostname == GITHUB_API_HOST:
            headers["Accept"] = "application/vnd.github+json"
            headers["X-GitHub-Api-Version"] = "2022-11-28"
            if self._github_token:
                headers["Authorization"] = f"Bearer {self._github_token}"
        return headers

    def _do(self, method: str, url: str, **kw: Any) -> tuple[int, Any]:
        with self._count_lock:
            self.requests_made += 1
        try:
            r = self._session.request(method, url, headers=self._headers(url), timeout=self._timeout, **kw)
        except self._requests.RequestException as exc:
            # str(exc) can include the URL but not headers; the token is never in the URL.
            raise HttpError(f"{method} {urlparse(url).netloc}{urlparse(url).path}: {type(exc).__name__}") from None
        if r.status_code == 204 or not r.content:
            return r.status_code, None
        try:
            return r.status_code, r.json()
        except ValueError:
            return r.status_code, None

    def _get_cached(self, url: str) -> tuple[int, Any]:
        hit = self.cache.get(url) if self.cache else None
        if hit is not None:
            return hit
        status, data = self._do("GET", url)
        if self.cache:
            self.cache.put(url, status, data)
        return status, data

    def get_json(self, url: str, params: dict | None = None) -> tuple[int, Any]:
        if params:
            # Cache and prefetch key on the full URL, so a query string is folded in rather than passed apart.
            url = f"{url}{'&' if '?' in url else '?'}{urlencode(params)}"
            return self._do("GET", url)
        ready = self._ready.pop(url, None)
        if isinstance(ready, HttpError):
            raise ready
        if ready is not None:
            return ready
        return self._get_cached(url)

    def prefetch(self, urls) -> None:
        todo = [u for u in dict.fromkeys(urls) if u not in self._ready]
        if not todo:
            return

        def one(u: str):
            try:
                return u, self._get_cached(u)
            except HttpError as exc:
                return u, exc

        if len(todo) == 1 or self._workers == 1:
            results = map(one, todo)
        else:
            pool = ThreadPoolExecutor(max_workers=min(self._workers, len(todo)), thread_name_prefix="oss-intake")
            results = list(pool.map(one, todo))
            pool.shutdown()
        for u, r in results:
            self._ready[u] = r

    def get_text(self, url: str) -> tuple[int, str]:
        try:
            r = self._session.get(url, headers={"Accept": "text/plain"}, timeout=max(self._timeout, 120))
        except self._requests.RequestException as exc:
            raise HttpError(f"GET {urlparse(url).netloc}{urlparse(url).path}: {type(exc).__name__}") from None
        # Decode explicitly; servers often send text/plain without a charset.
        return r.status_code, r.content.decode("utf-8", errors="replace")

    def post_json(self, url: str, body: Any) -> tuple[int, Any]:
        return self._do("POST", url, json=body)

    @property
    def has_github_token(self) -> bool:
        return bool(self._github_token)


def prefetch(http, urls) -> None:
    """http.prefetch(urls) where the client has it (test doubles may not)."""
    fn = getattr(http, "prefetch", None)
    if fn is not None:
        fn(urls)
