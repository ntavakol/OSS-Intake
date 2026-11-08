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
import sys
import threading
import time
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urljoin, urlparse

from . import __version__, jsonsafe

USER_AGENT = f"oss-intake/{__version__}"
DEFAULT_TIMEOUT = 30
# The timeout bounds each connect and each read, not the whole answer: a service sending a byte at a time, or
# without end, would hold the run. Every answer is read in chunks within a size limit and a total deadline (the
# largest, the exploit-db index, is tens of MB).
MAX_RESPONSE_BYTES = 256 * 1024 * 1024  # the ceiling for any answer
# Per source, below the ceiling: API answers are kilobytes; the bulk indexes read from repositories (Metasploit's
# module metadata, the Exploit-DB and Nuclei lists) run to tens of MB.
MAX_API_BYTES = 32 * 1024 * 1024
MAX_INDEX_BYTES = 128 * 1024 * 1024
INDEX_HOSTS = ("raw.githubusercontent.com", "gitlab.com")
DEADLINE_SECONDS = 300
# Redirects are followed by hand: a request with a body (the OSV batch query carries the package list) is never
# redirected, as a 307 or 308 would send the body on to wherever it points; a GET follows at most MAX_REDIRECTS,
# and only to https.
MAX_REDIRECTS = 5
REDIRECT_CODES = (301, 302, 303, 307, 308)


def answer_limit(url: str) -> int:
    host = (urlparse(url).hostname or "").lower()
    return min(MAX_RESPONSE_BYTES, MAX_INDEX_BYTES if host in INDEX_HOSTS else MAX_API_BYTES)
GITHUB_API_HOST = "api.github.com"


DEFAULT_WORKERS = 8
MAX_PREFETCH_FAILURES = 3
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
    # When an Ubuntu source version was first published never changes once it has been (an answer with no
    # publication is not kept: see put).
    (re.compile(r"^https://api\.launchpad\.net/1\.0/ubuntu/\+archive/primary\?ws\.op=getPublishedSources&"
                r"source_name=[^&]+&version=[^&]+&exact_match=true&distro_series=[^&]+&ws\.size=\d+$"), 30 * DAY),
    # An APKBUILD's commit history only grows; a day matches the OSV advisories the fix dates are read for.
    (re.compile(r"^https://api\.github\.com/repos/alpinelinux/aports/commits\?path=[^&]+&sha=[^&]+&per_page=\d+$"),
     DAY),
    # Not cached: GitHub releases (a new release must be seen for the release-age check) and EPSS (meant fresh).
]


class HttpError(Exception):
    """Network or protocol failure. Messages never include request headers."""


def _private_group(gid: int) -> bool:
    """The user's own private group (named as the user, no other members), as Fedora, RHEL, Debian and Ubuntu
    give each user with umask 002: group write there lets no one else in."""
    if sys.platform == "win32":
        return False
    try:
        import grp
        import pwd

        g, u = grp.getgrgid(gid), pwd.getpwuid(os.getuid())
    except (ImportError, KeyError, OSError):
        return False
    return gid == u.pw_gid and g.gr_name == u.pw_name and all(m == u.pw_name for m in g.gr_mem)


def _others_can_write(mode: int, gid: int) -> bool:
    import stat

    return bool(mode & stat.S_IWOTH or (mode & stat.S_IWGRP and not _private_group(gid)))


def _trusted(p: Path) -> bool:
    """A cache entry or subfolder only this user (or root) could have written: not a link, not another user's,
    not writable by others. A missing file reads as a miss either way. Always true on Windows (unsafe_reason
    checks the folder there)."""
    if sys.platform == "win32" or not hasattr(os, "getuid"):
        return True
    import stat

    try:
        st = os.lstat(p)
    except OSError:
        return True  # missing: the read that follows is a miss
    return (not stat.S_ISLNK(st.st_mode) and st.st_uid in (os.getuid(), 0)
            and not _others_can_write(st.st_mode, st.st_gid))


def default_cache_dir() -> Path:
    """Per-user cache directory: LOCALAPPDATA/oss-intake/cache on Windows, ~/Library/Caches/oss-intake on macOS,
    otherwise XDG_CACHE_HOME/oss-intake (default ~/.cache/oss-intake)."""
    # sys.platform rather than os.name / os.uname(): the same test, and type checkers understand it on every OS.
    if sys.platform == "win32":
        return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "oss-intake" / "cache"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Caches" / "oss-intake"
    return Path(os.environ.get("XDG_CACHE_HOME") or Path.home() / ".cache") / "oss-intake"


def folder_write_reason(folder: Path, windows: bool | None = None) -> str | None:
    """Who other than this user can write to the folder, or replace it through a folder above it, or None. On
    Windows it is read from the security descriptors, and None also when they cannot be read."""
    if windows if windows is not None else sys.platform == "win32":
        return _windows_acl_reason(folder)
    import stat

    for p in [folder, *folder.parents]:
        try:
            st = p.stat()
        except FileNotFoundError:
            continue  # not made yet: the folder above it decides
        except OSError as exc:
            return f"{p} cannot be checked ({exc.strerror or exc})"
        # A shared folder such as /tmp (sticky: only the owner can rename or delete) is fine above the folder.
        if _others_can_write(st.st_mode, st.st_gid) and (p == folder or not st.st_mode & stat.S_ISVTX):
            return f"{p} can be written by other users"
        if hasattr(os, "getuid") and st.st_uid not in (os.getuid(), 0):
            return f"{p} belongs to another user"
    return None


def _windows_acl_reason(folder: Path) -> str | None:
    """Another account that can write to the folder or replace it (winacl), or None, also when the
    descriptors cannot be read (not Windows, or the API failed): the cache's profile rule still applies then. A
    descriptor that was read but not understood is a reason."""
    from . import winacl

    try:
        me = winacl.user_sid()
    except OSError:
        return None
    nearest = True
    for p in [folder, *folder.parents]:
        if not p.exists():
            continue  # not made yet: whoever can add to the folder above could make it first
        try:
            sddl = winacl.read_sddl(str(p))
        except OSError:
            return None
        try:
            why = winacl.write_reason(sddl, me, winacl.FOLDER_WRITE if nearest else winacl.PARENT_WRITE,
                                      inherited=nearest, resolve=winacl.resolve_alias)
        except winacl.SddlError as exc:  # read, but not understood: refused rather than trusted
            return f"{p} has permissions this check cannot read ({exc})"
        if why:
            return f"{p} {why}"
        nearest = False
    return None


class ResponseCache:
    """Successful (200) JSON responses for the URLs in CACHE_RULES, one file per URL.

    "Not found" is never kept: a release deps.dev has not indexed yet, or a proof of concept not yet listed,
    answers 404 today and something else tomorrow, and keeping the 404 would hide exactly the new release the
    release-age check exists for. Entries are trusted only as far as they must be: a file that is not an
    entry for this URL, or that claims to come from the future, is ignored."""

    def __init__(self, folder: Path, now=time.time) -> None:
        self.folder = folder
        self.operator_trusted = False  # used on the operator's word (--trust-cache-dir), permissions not read
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
            f = self._file(url)
            if not (_trusted(f.parent) and _trusted(f)):
                raise ValueError("an entry or subfolder another user could have written")
            rec = jsonsafe.loads(f.read_text(encoding="utf-8"))
            if not isinstance(rec, dict):
                raise ValueError("not an entry")
            elapsed = self._now() - float(rec["fetched"])
            if rec.get("url") == url and 0 <= elapsed <= age and rec.get("status") == 200:
                with self._lock:
                    self.hits += 1
                return int(rec["status"]), rec.get("data")
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RecursionError):
            pass
        with self._lock:
            self.misses += 1
        return None

    def put(self, url: str, status: int, data: Any) -> None:
        if status != 200 or self.max_age(url) is None:
            return
        if "/versions/" in url and url.startswith("https://api.deps.dev/") and not (
                isinstance(data, dict) and data.get("publishedAt")):
            return  # a version deps.dev knows but has no date for yet: ask again next time
        if url.startswith("https://api.launchpad.net/") and not (isinstance(data, dict) and data.get("entries")):
            return  # not published yet: it may be by the next run
        f = self._file(url)
        try:
            # Folders it makes, parents included (~/.cache on a first run), are the user's only whatever the
            # umask: mkdir(parents=True) would give the parents the umask's mode, and unsafe_reason checks them.
            for d in [*reversed(f.parent.parents), f.parent]:
                if not d.exists():
                    try:
                        d.mkdir(mode=0o700)
                    except FileExistsError:  # another thread made it first
                        continue
                    os.chmod(d, 0o700)
            tmp = f.with_suffix(f".{os.getpid()}.{threading.get_ident()}.tmp")  # unique across runs sharing it
            # Readable and writable by this user only, whatever the umask: get() ignores an entry others could
            # write to.
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"url": url, "fetched": self._now(), "status": status, "data": data}))
            os.chmod(tmp, 0o600)  # O_CREAT's mode does not apply to a file left from an earlier attempt
            os.replace(tmp, f)
            with self._lock:
                self.writes += 1
        except OSError:
            pass  # a cache that cannot be written is only slower

    def unsafe_reason(self, windows: bool | None = None, operator_trusted: bool = False) -> str | None:
        """Why this folder should not be trusted, or None. Anyone who can write to it could plant answers (an
        old release date for a malicious new version), so a folder others can write to is not used. The folder
        and every folder above it are checked: whoever can write to a parent can swap the folder. (Entries and
        their subfolders are checked as they are read: _trusted.)"""
        if windows if windows is not None else sys.platform == "win32":
            # Who can write is read from each folder's security descriptor where it can be, and what it shows is
            # not overridden. On top of that, only a folder inside the user's profile is used unless the operator
            # vouches for it (--trust-cache-dir), as a descriptor judged here may still miss a way in.
            if why := self._windows_acl_reason():
                return why
            return None if operator_trusted else self._windows_reason()
        return folder_write_reason(self.folder, windows=False)

    def _windows_acl_reason(self) -> str | None:
        return _windows_acl_reason(self.folder)

    def _windows_reason(self) -> str | None:
        """The folders' descriptors (_windows_acl_reason) can miss a way in: an entry or subfolder given other
        rights, a junction, an account with the backup or restore privilege. So only a folder inside the user's
        own profile (where other users cannot write unless someone changed its permissions) is trusted unless
        the operator vouches for it."""
        def inside(p: Path, root: Path) -> bool:
            try:
                p.resolve().relative_to(root.resolve())
                return True
            except (ValueError, OSError, RuntimeError):
                return False

        roots = [Path.home()] + ([Path(os.environ["LOCALAPPDATA"])] if os.environ.get("LOCALAPPDATA") else [])
        if any(inside(self.folder, r) for r in roots):
            return None
        return (f"{self.folder} is outside your user profile, and its Windows permissions are not checked, so "
                "other users may be able to write to it (if only you can, say so with --trust-cache-dir)")

    def stats(self) -> dict:
        return {"folder": str(self.folder), "hits": self.hits, "misses": self.misses, "written": self.writes,
                **({"operator_trusted": True} if self.operator_trusted else {})}


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


def with_params(url: str, params: dict) -> str:
    """The URL get_json(url, params) asks for, as cache and prefetch key it."""
    return f"{url}{'&' if '?' in url else '?'}{urlencode(params)}"


class RequestsHttp(Http):
    """Http over requests: one session per thread, an optional ResponseCache and parallel prefetch for GETs
    (with parameters too, folded into the URL: with_params). A GitHub token (argument or GITHUB_TOKEN) is sent only to
    api.github.com. Connection failures raise HttpError; requests_made counts requests sent."""
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
        deadline = time.monotonic() + max(DEADLINE_SECONDS, 2 * self._timeout)
        r, url = self._send(method, url, None, self._timeout, **kw)
        body = self._body(r, method, url, deadline)
        if r.status_code == 204 or not body:
            return r.status_code, None
        try:
            return r.status_code, jsonsafe.loads(body)
        except (ValueError, RecursionError):  # not JSON, or nested too deeply to read: the caller sees no data
            return r.status_code, None

    def _send(self, method: str, url: str, accept: str | None, timeout: float, **kw: Any) -> tuple[Any, str]:
        """One request, following redirects by hand (see MAX_REDIRECTS): the answer, and the URL it came from."""
        for _ in range(MAX_REDIRECTS + 1):
            where = f"{method} {urlparse(url).netloc}{urlparse(url).path}"
            headers = self._headers(url) if accept is None else {"Accept": accept}  # the token: api.github.com only
            try:
                r = self._session.request(method, url, headers=headers, timeout=timeout, stream=True,
                                          allow_redirects=False, **kw)
            except self._requests.RequestException as exc:
                # str(exc) can include the URL but not headers; the token is never in the URL.
                raise HttpError(f"{where}: {type(exc).__name__}") from None
            location = (getattr(r, "headers", None) or {}).get("Location")
            if r.status_code not in REDIRECT_CODES or not location:
                return r, url
            close = getattr(r, "close", None)
            if close is not None:
                close()
            if method != "GET":
                raise HttpError(f"{where}: redirected ({r.status_code}); a request with a body is never redirected, "
                                "as that would send it on")
            url = urljoin(url, location)
            if urlparse(url).scheme != "https":
                raise HttpError(f"{where}: redirected to a non-https address, which is refused")
        raise HttpError(f"{method} {urlparse(url).netloc}: more than {MAX_REDIRECTS} redirects")

    def _body(self, r: Any, method: str, url: str, deadline: float) -> bytes:
        """The answer's bytes, read in chunks: over MAX_RESPONSE_BYTES or past the deadline is a failed request."""
        where = f"{method} {urlparse(url).netloc}{urlparse(url).path}"
        chunks = getattr(r, "iter_content", None)
        if chunks is None:  # an answer already read whole (as test doubles give)
            body = r.content or b""
            if len(body) > answer_limit(url):
                raise HttpError(f"{where}: the answer is over {answer_limit(url) // (1024 * 1024)} MB")
            return body
        import urllib3

        # read1 returns what has arrived (up to 64 KiB) rather than waiting to fill a chunk, so the deadline is
        # checked at least once per read timeout even against a byte at a time (urllib3 2; with urllib3 1.26
        # iter_content fills each chunk first).
        raw = getattr(r, "raw", None)
        if hasattr(raw, "read1"):
            def pieces():
                while True:
                    piece = raw.read1(1 << 16, decode_content=True)
                    if not piece:
                        return
                    yield piece
            source = pieces()
        else:
            source = chunks(1 << 16)
        buf = bytearray()
        limit = answer_limit(url)
        try:
            for chunk in source:
                buf += chunk
                if len(buf) > limit:
                    raise HttpError(f"{where}: the answer is over {limit // (1024 * 1024)} MB")
                if time.monotonic() > deadline:
                    raise HttpError(f"{where}: the answer took longer than the deadline to arrive")
        except (self._requests.RequestException, urllib3.exceptions.HTTPError, OSError) as exc:
            raise HttpError(f"{where}: {type(exc).__name__}") from None
        finally:
            close = getattr(r, "close", None)
            if close is not None:
                close()
        return bytes(buf)

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
            # Cache and prefetch key on the full URL, so a query string is folded in rather than passed apart,
            # and a GET with parameters is cached or prefetched like any other (CACHE_RULES decides).
            url = with_params(url, params)
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

        failures = [0]
        lock = threading.Lock()

        def one(u: str) -> tuple[str, tuple[int, Any] | HttpError]:
            # After a few failures the service is down or unreachable: answer the rest at once instead of
            # waiting out a timeout for each, as the sequential code did by stopping at the first error.
            with lock:
                if failures[0] >= MAX_PREFETCH_FAILURES:
                    return u, HttpError(f"GET {urlparse(u).netloc}: skipped after repeated failures")
            try:
                return u, self._get_cached(u)
            except HttpError as exc:
                with lock:
                    failures[0] += 1
                return u, exc

        results: Iterable[tuple[str, tuple[int, Any] | HttpError]]
        if len(todo) == 1 or self._workers == 1:
            results = map(one, todo)
        else:
            pool = ThreadPoolExecutor(max_workers=min(self._workers, len(todo)), thread_name_prefix="oss-intake")
            results = list(pool.map(one, todo))
            pool.shutdown()
        for u, r in results:
            self._ready[u] = r

    def get_text(self, url: str) -> tuple[int, str]:
        with self._count_lock:
            self.requests_made += 1
        timeout = max(self._timeout, 120)
        deadline = time.monotonic() + max(DEADLINE_SECONDS, 2 * timeout)
        r, url = self._send("GET", url, "text/plain", timeout)
        # Decode explicitly; servers often send text/plain without a charset.
        return r.status_code, self._body(r, "GET", url, deadline).decode("utf-8", errors="replace")

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
