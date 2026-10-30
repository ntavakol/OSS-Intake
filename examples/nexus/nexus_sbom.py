#!/usr/bin/env python3
"""List what a Nexus Repository proxy has cached, as one CycloneDX SBOM per repository, for oss-intake.

  python3 nexus_sbom.py --url https://nexus.example.org --out nexus-sboms
  oss-intake --path nexus-sboms/all --out report

  # the gate: only what was cached since the last run, failing on malicious or days-old releases
  python3 nexus_sbom.py --url https://nexus.example.org --out nexus-sboms --state nexus-state.json
  [ -n "$(ls nexus-sboms/new)" ] && oss-intake --path nexus-sboms/new --out gate --fail-on malicious,recent

Every proxy repository of a format oss-intake checks is read (npm, PyPI, Maven, NuGet, RubyGems, Go, Cargo,
CRAN), through the components REST API (/service/rest/v1/components), or only the ones named with --repository.
Hosted repositories hold your own packages, which no public advisory database knows; add them with
--include-hosted if you want them listed anyway. Repositories of other formats (Docker, apt, yum, raw...) are
named in the output as not checked.

Credentials come from NEXUS_USERNAME and NEXUS_PASSWORD (or NEXUS_TOKEN, sent as a bearer token), are sent only
to --url, never over plain http except to localhost, and are never printed. Each component's repository becomes
its `system` label and the date Nexus first cached it a `cached` label. With --state, components not seen in an
earlier run are also written to <out>/new/ (everything is in <out>/all/), and the state file is updated only
after everything was read.

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


class CollectorError(Exception):
    pass


class Client:
    def __init__(self, base: str, ca_file: str | None = None, timeout: int = 60, opener=None) -> None:
        u = urlparse(base)
        if u.scheme not in ("https", "http") or not u.hostname:
            raise CollectorError(f"--url {base}: give the Nexus address, e.g. https://nexus.example.org")
        self.base = base.rstrip("/")
        self.host = u.hostname
        self.timeout = timeout
        self.requests = 0
        user, pw, token = (os.environ.get(k) for k in ("NEXUS_USERNAME", "NEXUS_PASSWORD", "NEXUS_TOKEN"))
        self._auth = (f"Bearer {token}" if token else
                      "Basic " + base64.b64encode(f"{user}:{pw}".encode()).decode() if user and pw else None)
        local = u.hostname in ("localhost", "127.0.0.1", "::1")
        if self._auth and u.scheme == "http" and not local:
            raise CollectorError("refusing to send Nexus credentials over plain http; use https")
        ctx = ssl.create_default_context(cafile=ca_file) if u.scheme == "https" else None
        self._open = opener or (lambda req: urllib.request.urlopen(req, timeout=timeout, context=ctx))  # noqa: S310

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
    token = None
    for _ in range(max_pages):
        page = client.get("/service/rest/v1/components",
                          {"repository": repo, **({"continuationToken": token} if token else {})})
        if not isinstance(page, dict):
            raise CollectorError(f"unexpected answer listing {repo}")
        yield from (i for i in page.get("items") or [] if isinstance(i, dict))
        token = page.get("continuationToken")
        if not token:
            return
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
        return f"pkg:golang/{'/'.join(_q(p) for p in name.split('/'))}@{_q(version)}"
    return f"pkg:{ptype}/{_q(name)}@{_q(version)}"


def cached_date(item: dict) -> str:
    dates = sorted(str(a.get("blobCreated") or a.get("lastModified") or "")[:10]
                   for a in item.get("assets") or [] if isinstance(a, dict))
    return next((d for d in dates if d), "")


_HASHES = (("sha512", "SHA-512"), ("sha256", "SHA-256"), ("sha1", "SHA-1"))


def hashes(item: dict) -> list[dict]:
    """Checksums of the package file itself (not PyPI's .metadata or a Maven .pom), so the SBOM can be checked
    against the registry later. Nexus records who first pulled each file (`uploader`): never copied."""
    files = [a for a in item.get("assets") or [] if isinstance(a, dict)
             and not str(a.get("path", "")).endswith((".metadata", ".pom", ".sha1", ".md5", ".asc"))]
    if not files:
        return []
    main = max(files, key=lambda a: int(a.get("fileSize") or 0))
    sums = main.get("checksum") or {}
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
        if h := hashes(item):
            c["hashes"] = h
    else:
        props.append({"name": "oss-intake:not-checked", "value": "Nexus gave no group, name or version to build a "
                                                                 "package URL from"})
    if props:
        c["properties"] = props
    return c


def _key(repo: str, item: dict) -> str:
    return f"{repo}|{item.get('group') or ''}|{item.get('name') or ''}|{item.get('version') or ''}"


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._") or "repository"


def main(argv: list[str] | None = None, opener=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0], allow_abbrev=False)
    ap.add_argument("--url", required=True, help="Nexus address, e.g. https://nexus.example.org")
    ap.add_argument("--out", type=Path, required=True, help="folder for the SBOM files")
    ap.add_argument("--repository", action="append", default=[], help="read only this repository (repeatable)")
    ap.add_argument("--include-hosted", action="store_true", help="also list hosted repositories")
    ap.add_argument("--state", type=Path, help="remember what was seen; write components new since then to OUT/new")
    ap.add_argument("--ca-file", help="CA bundle for a Nexus with an internal certificate")
    ap.add_argument("--max-pages", type=int, default=DEFAULT_MAX_PAGES, help="per repository (default 20000)")
    a = ap.parse_args(argv)
    try:
        if a.max_pages < 1:
            raise CollectorError("--max-pages must be 1 or more")
        seen: set[str] = set()
        if a.state and a.state.exists():
            data = json.loads(a.state.read_text(encoding="utf-8"))
            if not isinstance(data, dict) or not isinstance(data.get("seen"), list):
                raise CollectorError(f"{a.state}: not a state file written by this collector")
            seen = {str(k) for k in data["seen"]}
        client = Client(a.url, a.ca_file, opener=opener)
        read, skipped = repositories(client, a.repository, a.include_hosted)
        if not read:
            raise CollectorError("no repository to read: " + "; ".join(f"{s['repository']}: {s['reason']}"
                                                                        for s in skipped))
        results = []
        now_seen: set[str] = set()
        for repo in read:
            comps, new = [], []
            for item in components(client, repo["name"], a.max_pages):
                c = _component(repo["format"], item)
                comps.append(c)
                key = _key(repo["name"], item)
                now_seen.add(key)
                if a.state and key not in seen:
                    new.append(c)
            results.append((repo, comps, new))
        # Nothing is written until every repository was read: a half-read proxy must not look like a full one.
        (a.out / "all").mkdir(parents=True, exist_ok=True)
        if a.state:
            (a.out / "new").mkdir(exist_ok=True)
            for old in (a.out / "new").glob("*.cdx.json"):
                old.unlink()  # new means new since the last run, not since some run
        for repo, comps, new in results:
            f = a.out / "all" / f"{_safe(repo['name'])}.cdx.json"
            f.write_text(json.dumps(sbom(repo, comps, a.url), indent=1) + "\n", encoding="utf-8")
            line = f"{f}: {len(comps)} components"
            if a.state:
                if new:
                    (a.out / "new" / f.name).write_text(json.dumps(sbom(repo, new, a.url), indent=1) + "\n",
                                                        encoding="utf-8")
                line += f", {len(new)} new since the last run"
            print(line)
        for s in skipped:
            print(f"  not read: {s['repository']}: {s['reason']}")
        if a.state:
            tmp = a.state.with_suffix(".tmp")
            tmp.write_text(json.dumps({"seen": sorted(seen | now_seen),
                                       "updated": datetime.now(timezone.utc).isoformat()}) + "\n", encoding="utf-8")
            os.replace(tmp, a.state)
            if not any(n for _, _, n in results):
                print("  nothing new since the last run")
        print(f"  {client.requests} requests to {client.host}")
    except (CollectorError, OSError, ValueError) as exc:
        print(f"nexus_sbom: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
