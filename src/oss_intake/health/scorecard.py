"""OpenSSF Scorecard via the public API.

The API only serves repositories in Scorecard's scheduled scan set, so a 404 means
"not scored", not "bad". Running the scorecard binary yourself is the alternative.
"""

from __future__ import annotations

from ..http import Http

API = "https://api.securityscorecards.dev/projects/github.com"
API_ROOT = "https://api.securityscorecards.dev/projects"


def fetch(http: Http, repo: str) -> dict:
    """OpenSSF Scorecard result for owner/name (GitHub) or gitlab.com/group/name from api.securityscorecards.dev:
    status ok with score, date, checks and low_checks (scored 0 to 3), not_scored (404, or a forge Scorecard does
    not cover) or error. HttpError propagates."""
    if repo.startswith("codeberg.org/"):
        return {"status": "not_scored", "note": "OpenSSF Scorecard does not cover Codeberg. This is not a negative "
                                                "signal."}
    url = f"{API_ROOT}/{repo}" if repo.startswith("gitlab.com/") else f"{API}/{repo}"
    status, data = http.get_json(url)
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
