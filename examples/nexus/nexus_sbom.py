#!/usr/bin/env python3
"""List what a Nexus Repository proxy has cached, as one CycloneDX SBOM per repository, for oss-intake.

  python3 nexus_sbom.py --url https://nexus.example.org --out nexus-sboms
  oss-intake --path nexus-sboms/all --out report

  # the gate: check what is new; accept it only once the check has passed (see README.md)
  python3 nexus_sbom.py --url https://nexus.example.org --out nexus-sboms --state nexus-state.json || exit 1
  if [ -n "$(ls nexus-sboms/new)" ]; then
      oss-intake --path nexus-sboms/new --out gate --fail-on malicious,recent,kev || exit $?
  fi
  python3 nexus_sbom.py --state nexus-state.json --accept

Every proxy repository of a format oss-intake checks is read (npm, PyPI, Maven, NuGet, RubyGems, Go, Cargo,
CRAN), through the components REST API (/service/rest/v1/components), or only the ones named with --repository.
Hosted repositories hold your own packages, which no public advisory database knows; add them with
--include-hosted if you want them listed anyway. Repositories of other formats (Docker, apt, yum, raw...) are
named in the output as not checked.

Credentials come from NEXUS_USERNAME and NEXUS_PASSWORD (for a user token, its name code and pass code), are
sent only to --url (redirects are refused, so they cannot follow one to a login page or another host), never
over plain http except to localhost, and are never printed. Without them the collector reads as the anonymous
user, which sees only what anonymous access allows. Each component's repository becomes its `system` label and
the date Nexus first cached it a `cached` label.

With --state, every component not yet accepted goes to <out>/new/ (everything is in <out>/all/). A run never
accepts anything: `--accept` does, once the gate has passed, so a package that failed the gate, or a gate that
could not run, shows up again next time. A component that leaves the cache and comes back is new again.

Standard library only; Python 3.10 or later. Nexus pages the components API (often 10 per page), so a large
proxy takes many requests; --max-pages stops a run that would never end.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote, urlencode, urlparse

TOOL_VERSION = "1"
# Nexus format -> purl type oss-intake checks
FORMATS = {"npm": "npm", "pypi": "pypi", "maven2": "maven", "nuget": "nuget", "rubygems": "gem", "go": "golang",
           "cargo": "cargo", "r": "cran"}
DEFAULT_MAX_PAGES = 20_000
# The file a version's checksums are taken from, per format. More than one candidate (wheels for several
# platforms) means no single file stands for the version, so no checksum is given rather than a guess.
PACKAGE_FILES = {"npm": (".tgz",), "pypi": (".whl", ".tar.gz", ".zip", ".tar.bz2", ".egg"),
                 "nuget": (".nupkg",), "rubygems": (".gem",), "cargo": (".crate",), "go": (".zip",),
                 "r": (".tar.gz", ".tgz")}
MAVEN_PACKAGING = {"jar", "war", "ear", "aar", "rar", "zip", "hpi", "jpi"}


class CollectorError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """urllib copies the Authorization header onto a redirect, even to another host or from https to http. The
    REST API does not redirect; one that does is a login page or a proxy in the way, so it is refused."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CollectorError(f"Nexus answered {code} with a redirect to {urlparse(newurl).netloc or newurl}; "
                             "refused, so credentials are not sent there. Is --url the Nexus address itself?")


class Client:
    def __init__(self, base: str, ca_file: str | None = None, timeout: int = 60, opener=None) -> None:
        u = urlparse(base)
        if u.scheme not in ("https", "http") or not u.hostname:
            raise CollectorError(f"--url {base}: give the Nexus address, e.g. https://nexus.example.org")
        self.base = base.rstrip("/")
        self.host = u.hostname
        self.timeout = timeout
        self.requests = 0
        if os.environ.get("NEXUS_TOKEN"):
            raise CollectorError("NEXUS_TOKEN is not used: give a user token's name code and pass code as "
                                 "NEXUS_USERNAME and NEXUS_PASSWORD")
        user, pw = os.environ.get("NEXUS_USERNAME"), os.environ.get("NEXUS_PASSWORD")
        if bool(user) != bool(pw):
            raise CollectorError("set both NEXUS_USERNAME and NEXUS_PASSWORD, or neither to read anonymously")
        self._auth = "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode() if user else None
        self.anonymous = self._auth is None
        local = u.hostname in ("localhost", "127.0.0.1", "::1")
        if self._auth and u.scheme == "http" and not local:
            raise CollectorError("refusing to send Nexus credentials over plain http; use https")
        handlers: list = [_NoRedirect()]
        if u.scheme == "https":
            handlers.append(urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=ca_file)))
        built = urllib.request.build_opener(*handlers)
        self._open = opener or (lambda req: built.open(req, timeout=timeout))

    def get(self, path: str, params: dict | None = None):
        url = f"{self.base}{path}" + (f"?{urlencode(params)}" if params else "")
        if urlparse(url).hostname != self.host:
            raise CollectorError("refusing a request to another host")
        req = urllib.request.Request(url, headers={"Accept": "application/json"})  # noqa: S310 - checked above
        if self._auth:
            req.add_header("Authorization", self._auth)
        self.requests += 1
        try:
            with self._open(req) as r:
                return json.loads(r.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            hint = " (check NEXUS_USERNAME / NEXUS_PASSWORD)" if exc.code in (401, 403) else ""
            raise CollectorError(f"GET {path}: HTTP {exc.code}{hint}") from None
        except urllib.error.URLError as exc:
            raise CollectorError(f"GET {path}: {exc.reason}") from None
        except ValueError:
            raise CollectorError(f"GET {path}: the answer is not JSON (is --url the Nexus address?)") from None


def repositories(client: Client, names: list[str], include_hosted: bool) -> tuple[list[dict], list[dict]]:
    """(repositories to read, repositories skipped with the reason)."""
    listed = client.get("/service/rest/v1/repositories")
    if not isinstance(listed, list):
        raise CollectorError("unexpected answer from /service/rest/v1/repositories")
    by_name = {str(r.get("name")): r for r in listed if isinstance(r, dict)}
    unknown = [n for n in names if n not in by_name]
    if unknown:
        raise CollectorError(f"no such repository: {', '.join(unknown)} (found: {', '.join(sorted(by_name))})")
    read, skipped = [], []
    for name in names or sorted(by_name):
        r = by_name[name]
        fmt, kind = str(r.get("format", "")), str(r.get("type", ""))
        if kind == "group" and names:
            raise CollectorError(f"{name} is a group repository, which only points at others; name its members")
        if fmt not in FORMATS:
            skipped.append({"repository": name, "reason": f"{fmt} repositories are not checked"})
        elif kind == "group":
            skipped.append({"repository": name, "reason": "a group repository; its members are read instead"})
        elif kind == "hosted" and not include_hosted and not names:
            skipped.append({"repository": name, "reason": "hosted (your own packages); add --include-hosted"})
        else:
            read.append({"name": name, "format": fmt, "type": kind})
    return read, skipped


def components(client: Client, repo: str, max_pages: int):
    token, tokens = None, set()
    for _ in range(max_pages):
        page = client.get("/service/rest/v1/components",
                          {"repository": repo, **({"continuationToken": token} if token else {})})
        if not isinstance(page, dict):
            raise CollectorError(f"unexpected answer listing {repo}")
        yield from (i for i in page.get("items") or [] if isinstance(i, dict))
        token = page.get("continuationToken")
        if not token:
            return
        if token in tokens:
            raise CollectorError(f"{repo}: Nexus returned the same continuation token twice; stopped, since the "
                                 "listing would never end")
        tokens.add(token)
    raise CollectorError(f"{repo}: more than {max_pages} pages; raise --max-pages")


def _q(v: str) -> str:
    return quote(str(v), safe="")


def purl(fmt: str, item: dict) -> str | None:
    group, name, version = str(item.get("group") or ""), str(item.get("name") or ""), str(item.get("version") or "")
    if not name or not version:
        return None
    ptype = FORMATS[fmt]
    if ptype == "npm":
        scope = group or (name.split("/", 1)[0] if name.startswith("@") and "/" in name else "")
        if scope:
            base = name.split("/", 1)[1] if name.startswith("@") and "/" in name else name
            return f"pkg:npm/{_q('@' + scope.lstrip('@'))}/{_q(base)}@{_q(version)}"
        return f"pkg:npm/{_q(name)}@{_q(version)}"
    if ptype == "maven":
        return f"pkg:maven/{_q(group)}/{_q(name)}@{_q(version)}" if group else None
    if ptype == "pypi":
        return f"pkg:pypi/{_q(re.sub(r'[-_.]+', '-', name).lower())}@{_q(version)}"
    if ptype == "golang":
        # Module paths may arrive case-encoded as the Go proxy stores them (!burnt!sushi = BurntSushi).
        name = re.sub(r"!([a-z])", lambda m: m.group(1).upper(), name)
        return f"pkg:golang/{'/'.join(_q(p) for p in name.split('/'))}@{_q(version)}"
    if ptype == "gem" and "-" in version:
        # 1.13.10-x86_64-linux: a platform build of 1.13.10 (gem versions have no '-')
        version, _, platform = version.partition("-")
        return f"pkg:gem/{_q(name)}@{_q(version)}?platform={_q(platform)}"
    return f"pkg:{ptype}/{_q(name)}@{_q(version)}"


def cached_date(item: dict) -> str:
    dates = sorted(str(a.get("blobCreated") or a.get("lastModified") or "")[:10]
                   for a in item.get("assets") or [] if isinstance(a, dict))
    return next((d for d in dates if d), "")


_HASHES = (("sha512", "SHA-512"), ("sha256", "SHA-256"), ("sha1", "SHA-1"))


def hashes(fmt: str, item: dict) -> list[dict]:
    """Checksums of the one package file that stands for this version (not PyPI's .metadata, a Maven .pom,
    -sources or -javadoc), or none when there is no such single file. Nexus also records who first pulled each
    file (`uploader`): never copied."""
    assets = [a for a in item.get("assets") or [] if isinstance(a, dict)]
    if fmt == "maven2":
        files = [a for a in assets if isinstance(a.get("maven2"), dict) and not a["maven2"].get("classifier")
                 and a["maven2"].get("extension") in MAVEN_PACKAGING]
    else:
        files = [a for a in assets if str(a.get("path", "")).endswith(PACKAGE_FILES.get(fmt, ()))]
    if len(files) != 1:
        return []
    sums = files[0].get("checksum") or {}
    return [{"alg": alg, "content": str(sums[k])} for k, alg in _HASHES if sums.get(k)]


def sbom(repo: dict, comps: list[dict], base_url: str) -> dict:
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
            "tools": {"components": [{"type": "application", "name": "oss-intake nexus collector",
                                      "version": TOOL_VERSION}]},
            "component": {"type": "application", "name": f"nexus:{repo['name']}",
                          "description": f"{repo['format']} {repo['type']} repository on "
                                         f"{urlparse(base_url).hostname}"},
        },
        "components": comps,
    }


def _component(fmt: str, item: dict) -> dict:
    p = purl(fmt, item)
    c: dict = {"type": "library", "name": str(item.get("name") or ""), "version": str(item.get("version") or "")}
    if item.get("group"):
        c["group"] = str(item["group"])
    props = [{"name": "oss-intake:label:cached", "value": cached_date(item)}] if cached_date(item) else []
    if p:
        c["purl"] = p
        if h := hashes(fmt, item):
            c["hashes"] = h
    else:
        props.append({"name": "oss-intake:not-checked", "value": "Nexus gave no group, name or version to build a "
                                                                 "package URL from"})
    if props:
        c["properties"] = props
    return c


def _key(repo: str, item: dict) -> str:
    return f"{repo}|{item.get('group') or ''}|{item.get('name') or ''}|{item.get('version') or ''}"


def _file_name(name: str, used: set[str]) -> str:
    """A file name per repository, unique even ignoring case: 'npm.' and 'npm_' must not overwrite each other."""
    import hashlib

    base = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "repository"
    if base.casefold() in used:
        base = f"{base}-{hashlib.sha256(name.encode()).hexdigest()[:8]}"
    used.add(base.casefold())
    return base


def _load_state(path: Path) -> dict:
    if not path.exists():
        return {"accepted": [], "pending": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise CollectorError(f"{path}: not a state file written by this collector")
    accepted = data.get("accepted", data.get("seen", []))  # "seen" was the first version's name
    pending = data.get("pending", [])
    if not isinstance(accepted, list) or not isinstance(pending, list):
        raise CollectorError(f"{path}: not a state file written by this collector")
    return {"accepted": [str(k) for k in accepted], "pending": [str(k) for k in pending]}


def _save_state(path: Path, state: dict) -> None:
    tmp = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps({**state, "updated": datetime.now(timezone.utc).isoformat()}) + "\n",
                   encoding="utf-8")
    os.replace(tmp, path)


class _Lock:
    """One run at a time per state file: two at once would each empty new/ under the other's gate."""

    def __init__(self, state: Path) -> None:
        self.path = state.with_name(state.name + ".lock")

    def __enter__(self):
        try:
            os.close(os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY))
        except FileExistsError:
            raise CollectorError(f"{self.path} exists: another run is using this state file (delete the lock "
                                 "file if none is)") from None
        return self

    def __exit__(self, *exc):
        self.path.unlink(missing_ok=True)


def _run(a, opener) -> None:
    client = Client(a.url, a.ca_file, opener=opener)
    state = _load_state(a.state) if a.state else None
    read, skipped = repositories(client, a.repository, a.include_hosted)
    if not read:
        raise CollectorError("no repository to read: " + "; ".join(f"{s['repository']}: {s['reason']}"
                                                                    for s in skipped))
    accepted = set(state["accepted"]) if state else set()
    results, present = [], set()
    for repo in read:
        comps, new, new_keys = [], [], []
        for item in components(client, repo["name"], a.max_pages):
            c = _component(repo["format"], item)
            comps.append(c)
            key = _key(repo["name"], item)
            present.add(key)
            if state is not None and key not in accepted:
                new.append(c)
                new_keys.append(key)
        results.append((repo, comps, new, new_keys))
    # Nothing is written until every repository was read: a half-read proxy must not look like a full one.
    for sub in ("all", "new") if state is not None else ("all",):
        (a.out / sub).mkdir(parents=True, exist_ok=True)
        for old in (a.out / sub).glob("*.cdx.json"):
            old.unlink()  # this run's view only: no repository from an earlier run, read or not
    used: set[str] = set()
    for repo, comps, new, _ in results:
        name = f"{_file_name(repo['name'], used)}.cdx.json"
        (a.out / "all" / name).write_text(json.dumps(sbom(repo, comps, a.url), indent=1) + "\n", encoding="utf-8")
        line = f"{a.out / 'all' / name}: {len(comps)} components"
        if state is not None:
            if new:
                (a.out / "new" / name).write_text(json.dumps(sbom(repo, new, a.url), indent=1) + "\n",
                                                  encoding="utf-8")
            line += f", {len(new)} not yet accepted"
        print(line)
    for s in skipped:
        print(f"  not read: {s['repository']}: {s['reason']}")
    if client.anonymous:
        print("  read anonymously: repositories and components anonymous access cannot see are not listed")
    if state is not None:
        read_names = {r["name"] for r in read}
        # A component no longer cached is forgotten, so it is new again if it comes back.
        kept = {k for k in accepted if k.split("|", 1)[0] not in read_names or k in present}
        pending = sorted(k for *_, keys in results for k in keys)
        _save_state(a.state, {"accepted": sorted(kept), "pending": pending})
        print(f"  {len(pending)} not yet accepted; after the gate passes: --state {a.state} --accept"
              if pending else "  nothing new to check")
    print(f"  {client.requests} requests to {client.host}")


def _accept(state_path: Path) -> None:
    state = _load_state(state_path)
    if not state_path.exists():
        raise CollectorError(f"{state_path}: no state yet; run the collector first")
    n = len(state["pending"])
    _save_state(state_path, {"accepted": sorted(set(state["accepted"]) | set(state["pending"])), "pending": []})
    print(f"accepted {n} component(s); they are no longer listed as new")


def main(argv: list[str] | None = None, opener=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    ap.add_argument("--url", help="Nexus address, e.g. https://nexus.example.org")
    ap.add_argument("--out", type=Path, help="folder for the SBOM files (OUT/all, and OUT/new with --state)")
    ap.add_argument("--repository", action="append", default=[], help="read only this repository (repeatable)")
    ap.add_argument("--include-hosted", action="store_true", help="also list hosted repositories")
    ap.add_argument("--state", type=Path, help="state file: components not yet accepted go to OUT/new")
    ap.add_argument("--accept", action="store_true",
                    help="with --state only: accept what the last run listed as new, once the gate has passed")
    ap.add_argument("--ca-file", help="CA bundle for a Nexus with an internal certificate")
    ap.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES, help="per repository (default 20000)")
    a = ap.parse_args(argv)
    try:
        if a.accept:
            if not a.state or a.url or a.out:
                raise CollectorError("--accept takes --state only")
            with _Lock(a.state):
                _accept(a.state)
            return 0
        if not a.url or not a.out:
            raise CollectorError("--url and --out are needed")
        if a.max_pages < 1:
            raise CollectorError("--max-pages must be 1 or more")
        if a.state:
            with _Lock(a.state):
                _run(a, opener)
        else:
            _run(a, opener)
    except (CollectorError, OSError, ValueError) as exc:
        print(f"nexus_sbom: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
