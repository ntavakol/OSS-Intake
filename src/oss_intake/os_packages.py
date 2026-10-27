"""OS packages (deb, rpm, apk) from an SBOM, checked in OSV by distro ecosystem.

OSV keys distro advisories on the distro's own ecosystem and release ("Ubuntu:24.04:LTS", "Debian:12",
"Alpine:v3.19", "Rocky Linux:9") and on the SOURCE package name: libssl3t64 is built from openssl, and the
advisory names openssl. Purl queries do not carry that, so each OS package is turned into a name, ecosystem and
version query here. Where the distro, its release or the source package cannot be told, the package is reported
as not checked rather than queried under a guess.

Where the source package comes from, in order: the purl's `upstream` qualifier (Syft: `upstream=openssl`, or an
rpm source file name such as `openssl-3.0.7-25.el9_3.src.rpm`), then the component's
`aquasecurity:trivy:SrcName` property (Trivy). Without either, the binary name is used, which is right for most
packages (curl, bash) and wrong only where the names differ.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, unquote

OS_TYPES = {"deb", "dpkg", "rpm", "apk"}
_UBUNTU_REL = re.compile(r"^(\d{2})\.(\d{2})")
_SRPM = re.compile(r"^(?P<name>.+)-[^-]+-[^-]+\.src\.rpm$")

# Families OSV has no data for: listed with the reason instead of being queried.
NO_OSV_DATA = {"amzn": "Amazon Linux", "amazon": "Amazon Linux", "rhel": "Red Hat Enterprise Linux",
               "redhat": "Red Hat Enterprise Linux", "centos": "CentOS", "fedora": "Fedora",
               "ol": "Oracle Linux", "oracle": "Oracle Linux", "photon": "Photon OS", "mariner": "CBL-Mariner"}
# Red Hat is in OSV, but under CPE-style ecosystems per product stream (Red Hat:enterprise_linux:9::appstream)
# that a package's purl does not state, so a query would be a guess.
NO_OSV_REASON = {"Red Hat Enterprise Linux": "OSV files Red Hat advisories per product stream, which the SBOM "
                                             "does not state; Trivy and Grype cover Red Hat images"}


def is_os_purl(purl: str) -> bool:
    return purl.startswith("pkg:") and purl[4:].split("/", 1)[0].lower() in OS_TYPES


def _parts(purl: str) -> tuple[str, str, str, str, dict]:
    """(type, namespace, name, version, qualifiers) of an OS purl."""
    body, _, query = purl[4:].split("#", 1)[0].partition("?")
    ptype, _, rest = body.partition("/")
    path, _, version = rest.rpartition("@")
    namespace, _, name = path.rpartition("/")
    quals = {k.lower(): v[0] for k, v in parse_qs(query).items() if v}
    return ptype.lower(), unquote(namespace).lower(), unquote(name), unquote(version), quals


# Code names some tools write instead of a release number.
CODENAMES = {"focal": "20.04", "jammy": "22.04", "noble": "24.04", "oracular": "24.10", "plucky": "25.04",
             "questing": "25.10", "buster": "10", "bullseye": "11", "bookworm": "12", "trixie": "13"}


def _distro(namespace: str, quals: dict) -> tuple[str, str]:
    """(family, release) from the distro qualifier ('ubuntu-24.04', 'alpine-3.19.1', '3.19.1' as Trivy writes it
    for Alpine, 'debian-bookworm') and the purl namespace."""
    d = quals.get("distro", "").strip().lower()
    family, release = namespace, ""
    m = re.match(r"^([a-z][a-z-]*?)-(\d[\w.]*)$", d) or re.match(r"^([a-z]+)-([a-z]+)$", d)
    if m:
        family, release = m.group(1), m.group(2)
    elif re.match(r"^\d[\w.]*$", d):
        release = d
    elif d in CODENAMES:
        release = d
    elif d:
        family = d
    return family, CODENAMES.get(release, release)


def ecosystem(family: str, release: str) -> tuple[str | None, str]:
    """OSV ecosystem for a distro family and release, or (None, why not)."""
    if family in NO_OSV_DATA:
        name = NO_OSV_DATA[family]
        return None, NO_OSV_REASON.get(name, f"OSV has no {name} advisories")
    if family in ("wolfi", "chainguard"):
        return family.capitalize(), ""
    if not release:
        return None, f"the SBOM does not say which {family or 'distro'} release"
    if not release[:1].isdigit():
        return None, f"the SBOM does not say which {family} release (it gives '{release}')"
    if family == "ubuntu":
        m = _UBUNTU_REL.match(release)
        if not m:
            return None, f"Ubuntu release '{release}' not recognised"
        yy, mm = m.groups()
        return f"Ubuntu:{yy}.{mm}" + (":LTS" if mm == "04" and int(yy) % 2 == 0 else ""), ""
    major = release.split(".")[0]
    if family == "debian":
        return f"Debian:{major}", ""
    if family == "alpine":
        minor = ".".join(release.split(".")[:2])
        return f"Alpine:v{minor}", ""
    if family in ("rocky", "rocky-linux", "rockylinux"):
        return f"Rocky Linux:{major}", ""
    if family in ("almalinux", "alma"):
        return f"AlmaLinux:{major}", ""
    return None, f"OSV has no {family or 'distro'} advisories that oss-intake can query"


def source_name(ptype: str, name: str, quals: dict, props: dict) -> tuple[str, str]:
    """(source package name, source version or '') for the advisory lookup."""
    up = quals.get("upstream", "").strip()
    if up:
        if ptype == "rpm":
            m = _SRPM.match(up)
            return (m.group("name"), "") if m else (up, "")
        src, _, ver = up.partition("@")  # Syft may write 'upstream=name@version' when they differ
        return src, ver
    src = props.get("aquasecurity:trivy:SrcName", "")
    if src:
        ver = props.get("aquasecurity:trivy:SrcVersion", "")
        rel = props.get("aquasecurity:trivy:SrcRelease", "")
        epoch = props.get("aquasecurity:trivy:SrcEpoch", "")
        if ver and rel:
            ver = f"{ver}-{rel}"
        if ver and epoch and epoch != "0":
            ver = f"{epoch}:{ver}"
        return src, ver
    return name, ""


def osv_query(purl: str, props: dict | None = None) -> tuple[dict | None, str]:
    """({"ecosystem", "name", "version", "os_release"}, '') for an OS package purl, or (None, why not checked)."""
    ptype, namespace, name, version, quals = _parts(purl)
    if not name or not version:
        return None, "no name or version in the purl"
    family, release = _distro(namespace, quals)
    eco, why = ecosystem(family, release)
    if not eco:
        return None, why
    src, src_version = source_name(ptype, name, quals, props or {})
    epoch = quals.get("epoch", "")
    if not src_version:
        src_version = f"{epoch}:{version}" if epoch and epoch != "0" and ":" not in version else version
    return {"ecosystem": eco, "name": src, "version": src_version,
            "os_release": f"{family} {release}".strip()}, ""
