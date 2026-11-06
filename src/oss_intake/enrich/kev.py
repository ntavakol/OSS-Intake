"""Flag findings listed in the CISA Known Exploited Vulnerabilities catalogue."""

from __future__ import annotations

from ..http import Http
from ..models import Finding

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load(http: Http) -> tuple[set[str], str | None]:
    """Fetch the CISA KEV catalogue (www.cisa.gov) and return (CVE IDs, catalogue version or release date); an empty
    set and None for a non-200 response, or one that is not an object with a list of vulnerabilities each naming its
    cveID. HttpError propagates."""
    status, data = http.get_json(KEV_URL)
    if status != 200 or not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
        return set(), None
    entries = data["vulnerabilities"]
    if not all(isinstance(v, dict) and isinstance(v.get("cveID"), str) and v["cveID"] for v in entries):
        return set(), None  # a catalogue with entries that cannot be read is not trusted in part
    ids = {v["cveID"].upper() for v in entries}
    return ids, data.get("catalogVersion") or data.get("dateReleased")


def apply(findings: list[Finding], kev_ids: set[str]) -> int:
    """Set kev on findings whose ID or any alias is in kev_ids, in place; returns how many were marked."""
    n = 0
    for f in findings:
        ids = {f.vuln_id.upper()} | {a.upper() for a in f.aliases}
        if ids & kev_ids:
            f.kev = True
            n += 1
    return n
