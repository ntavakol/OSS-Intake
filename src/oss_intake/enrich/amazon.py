"""Amazon Linux fix dates from the advisories in the package repository's metadata (updateinfo.xml).

Trivy finds Amazon Linux's vulnerable packages but reports no ALAS advisory IDs. AWS publishes every advisory in
the repository metadata dnf reads, as well as on alas.aws.amazon.com: each <update> has its ID (ALAS2023-...,
ALAS2-...), an issued date, its CVEs, and the fixed packages by name, version and release. The path is the one
dnf follows: mirror.list names the repository, its repodata/repomd.xml gives updateinfo.xml.gz with its SHA-256,
which is checked. It is always the "latest" repository: AL2023's versioned repositories are frozen at release and
miss later advisories.

A finding is matched to the advisories that list its CVE for its package at exactly the fixed version Trivy reports
(many CVEs appear in several advisories, a later one fixing the same CVE again, so the CVE alone is not enough).
It is dated by the "Advisory Released Date" on the advisory's alas.aws.amazon.com page, which AWS defines as when
the update was first publicly available in the repository. The metadata's issued date is earlier, by 3 to 4 days at
the median (ALAS2023-2023-375: issued 27 Sep 2023, released 3 Oct 2023), and its updated date can be a year later,
so neither is used when the page can be read; when it cannot, the issued date is used and the source says so.
Covered: Amazon Linux 2023 and Amazon Linux 2's core repository. Not covered: AL2 Extras (kernel-5.10, docker and
others, whose advisories are in their own repositories) and the original Amazon Linux AMI (end of life). The
format was checked against the live files of 12 Nov 2026 (AL2023: 2,409 advisories from Feb 2023; AL2: 2,539
from Jan 2018; every one dated, all type "security").
"""

from __future__ import annotations

import gzip
import hashlib
import io
import re
import xml.etree.ElementTree as ET  # noqa: S405 - DOCTYPE refused before parsing; sizes capped
import zlib
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from ..http import Http, HttpError
from ..models import Finding
from ..versions import nearest_fix

CDN = "https://cdn.amazonlinux.com"
MIRROR_LISTS = {"2023": f"{CDN}/al2023/core/mirrors/latest/x86_64/mirror.list",
                "2": f"{CDN}/2/core/latest/x86_64/mirror.list"}
NAMES = {"2023": "Amazon Linux 2023", "2": "Amazon Linux 2"}
ALAS = "https://alas.aws.amazon.com"
MAX_PAGES = 300  # advisory pages read per run; the rest are dated by their issued date
PAGE_WORKERS = 8
MAX_PAGE_FAILURES = 3  # then the site is taken as down, and the rest are dated by their issued date
_RELEASED = re.compile(r"Advisory\s+Released\s+Date:\s*(\d{4}-\d{2}-\d{2})")
MAX_GZ = 64 * 1024 * 1024  # the files were 2.0 and 1.6 MB compressed
MAX_XML = 256 * 1024 * 1024  # and 19 and 16 MB unpacked
_REPO_NS = "{http://linux.duke.edu/metadata/repo}"
_EPOCH = re.compile(r"^\d+:")
_RELEASE = re.compile(r"(?:amazon\s*linux|amazonlinux|amazon|amzn)(?:\s+release)?[\s:-]*(\d{4}|\d)(?![\d])")
# A repository on the CDN, as requests will fetch it: no userinfo, port, backslash, percent-encoding or "..",
# which urlparse and requests read differently (https://evil.example\@cdn.amazonlinux.com/ is evil.example).
_REPOSITORY = re.compile(r"https://cdn\.amazonlinux\.com(?:/[A-Za-z0-9_.-]+)+")
_XML_DECL = re.compile(rb'\A<\?xml[^>]*?encoding\s*=\s*["\']([^"\']+)["\']')


class _Bad(Exception):
    """The repository metadata is not what dnf would accept: the run goes on without these dates."""


def release_of(f: Finding) -> str | None:
    """The Amazon Linux release of an OS package finding, "2023" or "2", or None (not Amazon Linux, or the
    original Amazon Linux AMI). From Trivy's os_release ("amazon 2 (karoo)", "amazon 2023.6.20241031 (...)"),
    Grype's ("amazonlinux 2023"), or the purl's distro qualifier."""
    purl = (f.purl or "").lower()
    os_release = (f.os_release or "").lower()
    if not (purl.startswith(("pkg:rpm/amazon/", "pkg:rpm/amzn/")) or "amazon" in os_release or "amzn" in os_release):
        return None
    for text in (f.os_release or "", purl.split("distro=", 1)[1].split("&", 1)[0] if "distro=" in purl else ""):
        m = _RELEASE.search(text.lower())
        if m and m.group(1) in MIRROR_LISTS:
            return m.group(1)
    return None


def _vr(version: str) -> str:
    """version-release without an epoch, as both sides are compared."""
    return _EPOCH.sub("", version.strip())


def _date(value: str | None) -> datetime | None:
    try:
        return datetime.strptime((value or "").strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _repository(http: Http, release: str) -> str:
    """The repository base dnf would use, from mirror.list: an https URL on cdn.amazonlinux.com, nothing else."""
    status, text = http.get_text(MIRROR_LISTS[release])
    if status != 200:
        raise _Bad(f"mirror.list answered HTTP {status}")
    base = next((line.strip() for line in text.splitlines() if line.strip()), "").rstrip("/")
    if not _REPOSITORY.fullmatch(base) or "/../" in base + "/" or "/./" in base + "/":
        raise _Bad("mirror.list does not name a repository on cdn.amazonlinux.com")
    return base


def _updateinfo_location(repomd: str) -> tuple[str, str, int]:
    """(path, sha256, size) of updateinfo.xml.gz, from repomd.xml."""
    if "<!DOCTYPE" in repomd or "<!ENTITY" in repomd:
        raise _Bad("repomd.xml declares a DOCTYPE")
    try:
        root = ET.fromstring(repomd)  # noqa: S314 - a few KB, DOCTYPE refused above
    except (ET.ParseError, ValueError) as exc:  # ValueError: an encoding expat does not support
        raise _Bad(f"repomd.xml cannot be read ({exc})") from None
    for data in root.findall(f"{_REPO_NS}data"):
        if data.get("type") != "updateinfo":
            continue
        loc = data.find(f"{_REPO_NS}location")
        csum = data.find(f"{_REPO_NS}checksum")
        href = loc.get("href", "") if loc is not None else ""
        digest = (csum.text or "").strip().lower() if csum is not None and csum.get("type") == "sha256" else ""
        try:
            size = int((data.findtext(f"{_REPO_NS}size") or "0").strip())
        except ValueError:
            size = 0
        if not re.fullmatch(r"repodata/[\w.-]+\.xml\.gz", href) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise _Bad("repomd.xml gives no usable updateinfo location and SHA-256")
        return href, digest, size
    raise _Bad("repomd.xml lists no updateinfo")


def parse(xml: bytes) -> dict[tuple[str, str], list[tuple[str, datetime, str]]]:
    """Map (CVE, binary package name) to [(version-release, issued date, advisory ID)] from updateinfo.xml."""
    xml = xml.removeprefix(b"\xef\xbb\xbf")
    decl = _XML_DECL.match(xml)
    if not xml.lstrip().startswith(b"<") or (decl and decl.group(1).lower() not in (b"utf-8", b"us-ascii")):
        raise _Bad("updateinfo.xml is not UTF-8 XML")  # also keeps a UTF-16 DOCTYPE from hiding from the check
    if b"<!DOCTYPE" in xml or b"<!ENTITY" in xml:
        raise _Bad("updateinfo.xml declares a DOCTYPE")
    out: dict[tuple[str, str], list[tuple[str, datetime, str]]] = {}
    try:
        for _, el in ET.iterparse(io.BytesIO(xml)):  # noqa: S314 - DOCTYPE refused above
            if el.tag != "update":
                continue
            adv = (el.findtext("id") or "").strip()
            issued = el.find("issued")
            when = _date(issued.get("date") if issued is not None else None)
            cves = {r.get("id", "").strip().upper() for r in el.findall("references/reference")
                    if r.get("type") == "cve" and (r.get("id") or "").upper().startswith("CVE-")}
            if adv and when and cves:
                for p in el.findall("pkglist/collection/package"):
                    name, ver, rel = p.get("name"), p.get("version"), p.get("release")
                    if name and ver and rel:
                        for c in cves:
                            entry = (f"{ver}-{rel}", when, adv)
                            got = out.setdefault((c, name), [])
                            if entry not in got:
                                got.append(entry)
            el.clear()
    except (ET.ParseError, ValueError) as exc:  # ValueError: an encoding expat does not support
        raise _Bad(f"updateinfo.xml cannot be read ({exc})") from None
    return out


def load(http: Http, release: str) -> dict[tuple[str, str], list[tuple[str, datetime, str]]]:
    """The advisories of one release, fetched and checked as dnf would (HTTPS, then the SHA-256 in repomd.xml)."""
    base = _repository(http, release)
    status, repomd = http.get_text(f"{base}/repodata/repomd.xml")
    if status != 200:
        raise _Bad(f"repomd.xml answered HTTP {status}")
    href, digest, size = _updateinfo_location(repomd)
    if size > MAX_GZ:
        raise _Bad(f"updateinfo is {size} bytes, over the {MAX_GZ // (1024 * 1024)} MB limit")
    status, body = http.get_bytes(f"{base}/{href}", MAX_GZ)
    if status != 200:
        raise _Bad(f"updateinfo answered HTTP {status}")
    if hashlib.sha256(body).hexdigest() != digest:
        raise _Bad("updateinfo does not match the SHA-256 in repomd.xml")
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
            xml = gz.read(MAX_XML + 1)
    except (OSError, EOFError, zlib.error) as exc:
        raise _Bad(f"updateinfo cannot be unpacked ({exc})") from None
    if len(xml) > MAX_XML:
        raise _Bad(f"updateinfo unpacks to over {MAX_XML // (1024 * 1024)} MB")
    return parse(xml)


def page_url(adv: str) -> str | None:
    """The advisory's page, by its ID (/AL2023/ALAS2023-2023-001.html, /AL2/ALAS2-2022-1803.html: no redirect, as
    checked on 12 Nov 2026; /AL2/ALAS-2022-1803.html redirects there)."""
    if re.fullmatch(r"ALAS2023-\d{4}-\d+", adv):
        return f"{ALAS}/AL2023/{adv}.html"
    return f"{ALAS}/AL2/{adv}.html" if re.fullmatch(r"ALAS2-\d{4}-\d+", adv) else None


def released(html: str) -> datetime | None:
    """The "Advisory Released Date" on an advisory page (markup removed first)."""
    m = _RELEASED.search(re.sub(r"<[^>]{0,500}>", " ", html[:2_000_000]))
    return _date(f"{m.group(1)} 00:00:00") if m else None


def _released_dates(http: Http, advs: list[str], stats: dict) -> dict[str, datetime]:
    """Each advisory's released date from its page, read in parallel, at most MAX_PAGES."""
    todo = [a for a in dict.fromkeys(advs) if page_url(a)][:MAX_PAGES]
    stats["skipped_limit"] = max(0, len(dict.fromkeys(advs)) - len(todo))
    failures = [0]

    def one(adv: str) -> tuple[str, datetime | None]:
        if failures[0] >= MAX_PAGE_FAILURES:
            return adv, None
        try:
            status, html = http.get_text(page_url(adv) or "")
        except (HttpError, ValueError):
            failures[0] += 1
            return adv, None
        if status != 200:  # a block or rate limit (403, 429, 5xx) counts too, so a refusing site is not asked 300 times
            failures[0] += 1
            return adv, None
        return adv, released(html)

    with ThreadPoolExecutor(max_workers=PAGE_WORKERS, thread_name_prefix="oss-intake-alas") as pool:
        got = dict(pool.map(one, todo))
    stats["pages"] = sum(1 for v in got.values() if v is not None)
    stats["pages_unread"] = sum(1 for v in got.values() if v is None) + stats["skipped_limit"]
    return {a: d for a, d in got.items() if d}


def enrich(http: Http, findings: list[Finding]) -> dict:
    """Set fix_published on Amazon Linux 2023 and Amazon Linux 2 findings to the issued date of the ALAS advisory
    that lists the finding's CVE for its package at exactly the fixed version (cdn.amazonlinux.com). Mutates
    findings in place; returns stats: candidates, found, releases (loaded), errors (releases that could not be
    loaded), error (the reasons), pages (advisory pages whose date was read), pages_unread (dated by their issued
    date instead), skipped_limit (over MAX_PAGES)."""
    stats: dict = {"candidates": 0, "found": 0, "releases": [], "errors": 0, "pages": 0, "pages_unread": 0,
                   "skipped_limit": 0}
    index: dict[str, dict | None] = {}
    matched: list[tuple[Finding, str, list[tuple[datetime, str]]]] = []
    for f in findings:
        if f.fix_published or f.likely_fixed or f.excluded or not f.fixed_versions:
            continue
        release = release_of(f)
        fix = nearest_fix(f.vs_fix, f.fixed_versions)
        if not release or not fix:
            continue
        stats["candidates"] += 1
        if release not in index:
            try:
                index[release] = load(http, release)
                stats["releases"].append(NAMES[release])
            except (_Bad, HttpError, ValueError) as exc:
                index[release] = None
                stats["errors"] += 1
                stats["error"] = "; ".join(filter(None, [stats.get("error"), f"{NAMES[release]}: {exc}"]))
        advisories = index[release]
        if not advisories:
            continue
        cves = {i.upper() for i in {f.vuln_id, *f.aliases} if i and i.upper().startswith("CVE-")}
        want = _vr(fix)
        hits = [(when, adv) for c in cves for name in dict.fromkeys(n for n in (f.package, f.src_name) if n)
                for vr, when, adv in advisories.get((c, name), []) if vr == want]
        if hits:
            matched.append((f, fix, hits))
    pages = _released_dates(http, [adv for _, _, hits in matched for _, adv in sorted(hits)], stats) if matched else {}
    for f, fix, hits in matched:
        # The earliest release among the advisories that list it (by page date, else issued date).
        when, adv = min((pages.get(adv, issued), adv) for issued, adv in hits)
        f.fix_published = when
        f.fix_version_used = fix
        f.fix_date_source = (f"advisory {adv} (Amazon Linux)" if adv in pages
                             else f"advisory {adv} (Amazon Linux, issued date: its page could not be read)")
        stats["found"] += 1
    return stats
