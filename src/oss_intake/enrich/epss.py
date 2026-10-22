"""EPSS (Exploit Prediction Scoring System) scores from FIRST.

EPSS estimates the probability that a CVE is exploited in the wild in the next 30 days. It is a
signal for the likelihood heuristic, alongside CISA KEV (known exploitation).
"""

from __future__ import annotations

from ..http import Http, HttpError
from ..models import Finding

API = "https://api.first.org/data/v1/epss"
BATCH = 100  # keeps the comma-separated query string well under URL length limits


def _cve(f: Finding) -> str | None:
    for i in [f.vuln_id, *sorted(f.aliases)]:
        if i.upper().startswith("CVE-"):
            return i.upper()
    return None


def enrich(http: Http, findings: list[Finding]) -> dict:
    cves = sorted({c for f in findings if (c := _cve(f))})
    scores: dict[str, tuple[float, float]] = {}
    stats = {"cves": len(cves), "scored": 0, "errors": 0, "model_date": None}
    for i in range(0, len(cves), BATCH):
        chunk = cves[i:i + BATCH]
        try:
            status, data = http.get_json(API, params={"cve": ",".join(chunk)})
        except HttpError:
            stats["errors"] += 1
            continue
        if status != 200 or not isinstance(data, dict):
            stats["errors"] += 1
            continue
        for row in data.get("data") or []:
            try:
                scores[str(row["cve"]).upper()] = (float(row["epss"]), float(row["percentile"]))
            except (KeyError, TypeError, ValueError):
                continue
            stats["model_date"] = stats["model_date"] or row.get("date")
    for f in findings:
        c = _cve(f)
        if c and c in scores:
            f.epss, f.epss_percentile = scores[c]
            stats["scored"] += 1
    return stats
