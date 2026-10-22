"""Flag findings listed in the CISA Known Exploited Vulnerabilities catalogue."""

from __future__ import annotations

from ..http import Http
from ..models import Finding

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def load(http: Http) -> tuple[set[str], str | None]:
    status, data = http.get_json(KEV_URL)
    if status != 200 or not isinstance(data, dict):
        return set(), None
    ids = {str(v.get("cveID", "")).upper() for v in data.get("vulnerabilities") or [] if v.get("cveID")}
    return ids, data.get("catalogVersion") or data.get("dateReleased")


def apply(findings: list[Finding], kev_ids: set[str]) -> int:
    n = 0
    for f in findings:
        ids = {f.vuln_id.upper()} | {a.upper() for a in f.aliases}
        if ids & kev_ids:
            f.kev = True
            n += 1
    return n
