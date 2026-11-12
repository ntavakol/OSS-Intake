"""Amazon Linux fix dates from the advisories in the package repository's metadata (updateinfo.xml).

Trivy finds Amazon Linux's vulnerable packages but reports no ALAS advisory IDs. AWS publishes every advisory in
the repository metadata dnf reads, as well as on alas.aws.amazon.com: each <update> has its ID (ALAS2023-...,
ALAS2-...), an issued date (AWS's "Advisory Released Date": when the fix was first available in the repository),
its CVEs, and the fixed packages by name, version and release. The path is the one dnf follows: mirror.list names
the repository, its repodata/repomd.xml gives updateinfo.xml.gz with its SHA-256, which is checked. It is always
the "latest" repository: AL2023's versioned repositories are frozen at release and miss later advisories.

A finding is dated by the advisory that lists its CVE for its package at exactly the fixed version Trivy reports
(many CVEs appear in several advisories, a later one fixing the same CVE again, so the CVE alone is not enough).
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
from datetime import datetime, timezone
from urllib.parse import urlparse

from ..http import Http, HttpError
from ..models import Finding
from ..versions import nearest_fix

CDN = "https://cdn.amazonlinux.com"
MIRROR_LISTS = {"2023": f"{CDN}/al2023/core/mirrors/latest/x86_64/mirror.list",
                "2": f"{CDN}/2/core/latest/x86_64/mirror.list"}
NAMES = {"2023": "Amazon Linux 2023", "2": "Amazon Linux 2"}
MAX_GZ = 64 * 1024 * 1024  # the files were 2.0 and 1.6 MB compressed
MAX_XML = 256 * 1024 * 1024  # and 19 and 16 MB unpacked
_REPO_NS = "{http://linux.duke.edu/metadata/repo}"
_EPOCH = re.compile(r"^\d+:")
_RELEASE = re.compile(r"(?:amazon\s*linux|amazonlinux|amazon|amzn)[\s:-]*(\d{4}|\d)(?![\d])")


class _Bad(Exception):
    """The repository metadata is not what dnf would accept: the run goes on without these dates."""


def release_of(f: Finding) -> str | None:
    """The Amazon Linux release of an OS package finding, "2023" or "2", or None (not Amazon Linux, or the
    original Amazon Linux AMI). From Trivy's os_release ("amazon 2 (karoo)", "amazon 2023.6.20241031 (...)"),
    Grype's ("amazonlinux 2023"), or the purl's distro qualifier."""
    purl = (f.purl or "").lower()
    if not (purl.startswith(("pkg:rpm/amazon/", "pkg:rpm/amzn/")) or "amazon" in (f.os_release or "").lower()):
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
    u = urlparse(base)
    if u.scheme != "https" or u.hostname != "cdn.amazonlinux.com" or u.query or u.fragment or ".." in u.path:
        raise _Bad("mirror.list does not name a repository on cdn.amazonlinux.com")
    return base


def _updateinfo_location(repomd: str) -> tuple[str, str, int]:
    """(path, sha256, size) of updateinfo.xml.gz, from repomd.xml."""
    if "<!DOCTYPE" in repomd or "<!ENTITY" in repomd:
        raise _Bad("repomd.xml declares a DOCTYPE")
    try:
        root = ET.fromstring(repomd)  # noqa: S314 - a few KB, DOCTYPE refused above
    except ET.ParseError as exc:
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
    if b"<!DOCTYPE" in xml[:4096] or b"<!ENTITY" in xml:
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
    except ET.ParseError as exc:
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


def enrich(http: Http, findings: list[Finding]) -> dict:
    """Set fix_published on Amazon Linux 2023 and Amazon Linux 2 findings to the issued date of the ALAS advisory
    that lists the finding's CVE for its package at exactly the fixed version (cdn.amazonlinux.com). Mutates
    findings in place; returns stats: candidates, found, releases (loaded), errors (releases that could not be
    loaded), error (the last reason)."""
    stats: dict = {"candidates": 0, "found": 0, "releases": [], "errors": 0}
    index: dict[str, dict | None] = {}
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
            except (_Bad, HttpError) as exc:
                index[release] = None
                stats["errors"] += 1
                stats["error"] = f"{NAMES[release]}: {exc}"
        advisories = index[release]
        if not advisories:
            continue
        cves = {i.upper() for i in {f.vuln_id, *f.aliases} if i and i.upper().startswith("CVE-")}
        want = _vr(fix)
        hits = [(when, adv) for c in cves for name in dict.fromkeys(n for n in (f.package, f.src_name) if n)
                for vr, when, adv in advisories.get((c, name), []) if vr == want]
        if hits:
            when, adv = min(hits)
            f.fix_published = when
            f.fix_version_used = fix
            f.fix_date_source = f"advisory {adv} (Amazon Linux)"
            stats["found"] += 1
    return stats
