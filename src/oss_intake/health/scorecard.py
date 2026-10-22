"""OpenSSF Scorecard via the public API.

The API only serves repositories in Scorecard's scheduled scan set, so a 404 means
"not scored", not "bad". Running the scorecard binary yourself is the alternative.
"""

from __future__ import annotations

from ..http import Http

API = "https://api.securityscorecards.dev/projects/github.com"


def fetch(http: Http, repo: str) -> dict:
    status, data = http.get_json(f"{API}/{repo}")
    if status == 404:
        return {"status": "not_scored",
                "note": "Repository is not in the OpenSSF Scorecard public dataset. This is not a negative signal."}
    if status != 200 or not isinstance(data, dict):
        return {"status": "error", "note": f"Scorecard API returned HTTP {status}"}
    checks = []
    for c in data.get("checks") or []:
        checks.append({"name": c.get("name"), "score": c.get("score"), "reason": c.get("reason")})
    low = [c["name"] for c in checks if isinstance(c["score"], (int, float)) and 0 <= c["score"] <= 3]
    return {
        "status": "ok",
        "score": data.get("score"),
        "date": data.get("date"),
        "checks": checks,
        "low_checks": low,
    }
