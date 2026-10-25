"""Optional likelihood suggestion for a 5x5 risk matrix.

THIS IS A HEURISTIC. It turns observable signals (unshipped fixes, project activity,
KEV membership) into a starting point for a human assessor. It does not know whether
vulnerable code is reachable, exposed or mitigated in your deployment.

Rules are evaluated top to bottom; the first rule whose conditions all match wins.
A rule may have "all" (every condition must match) and/or "any" (at least one must match).
Supply your own rules with --likelihood-config FILE (same JSON shape as DEFAULT_RULES).
"""

from __future__ import annotations

import json
import operator
from pathlib import Path

OPS = {">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le, "==": operator.eq,
       "!=": operator.ne}

DEFAULT_CONFIG = {
    "scale": {"1": "Rare", "2": "Unlikely", "3": "Possible", "4": "Likely", "5": "Almost certain"},
    "rules": [
        {"level": 5, "reason": "A known-exploited (CISA KEV) vulnerability has a fix the project has not shipped",
         "all": [{"metric": "kev_with_fix", "op": ">=", "value": 1}]},
        {"level": 4, "reason": "A finding with an upstream fix has a ready-to-use public exploit "
                               "(Metasploit module or Nuclei template)",
         "all": [{"metric": "weaponised_with_fix", "op": ">=", "value": 1}]},
        {"level": 4, "reason": "A finding with an upstream fix has a high predicted exploitation probability "
                               "(EPSS 0.5 or more)",
         "all": [{"metric": "max_epss_with_fix", "op": ">=", "value": 0.5}]},
        {"level": 4, "reason": "Critical fixes were available before release and the project shows weak upkeep",
         "all": [{"metric": "critical_fix_at_release", "op": ">=", "value": 1}],
         "any": [{"metric": "days_since_latest_release", "op": ">", "value": 180},
                 {"metric": "archived", "op": "==", "value": 1},
                 {"metric": "scorecard_score", "op": "<", "value": 4}]},
        {"level": 4, "reason": "Critical fixes have been available for a long time and the project has not "
                               "released since",
         "all": [{"metric": "critical_fix_unshipped", "op": ">=", "value": 1},
                 {"metric": "days_since_latest_release", "op": ">", "value": 180}]},
        {"level": 3, "reason": "A finding with an upstream fix has a notable predicted exploitation probability "
                               "(EPSS 0.1 or more)",
         "all": [{"metric": "max_epss_with_fix", "op": ">=", "value": 0.1}]},
        {"level": 3, "reason": "A finding with an upstream fix has a published exploit (Exploit-DB)",
         "all": [{"metric": "public_exploit_with_fix", "op": ">=", "value": 1}]},
        {"level": 3, "reason": "Critical, or several high, fixes were available before release and not shipped",
         "any": [{"metric": "critical_fix_at_release", "op": ">=", "value": 1},
                 {"metric": "high_fix_at_release", "op": ">=", "value": 5}]},
        {"level": 3, "reason": "Critical, or many high, fixes have been available upstream for a long time with "
                               "no newer release",
         "any": [{"metric": "critical_fix_unshipped", "op": ">=", "value": 1},
                 {"metric": "high_fix_unshipped", "op": ">=", "value": 10}]},
        {"level": 2, "reason": "High or critical findings exist with upstream fixes",
         "any": [{"metric": "critical_with_fix", "op": ">=", "value": 1},
                 {"metric": "high_with_fix", "op": ">=", "value": 1}]},
        {"level": 1, "reason": "No high or critical findings with available fixes", "all": []},
    ],
}


class ConfigError(Exception):
    pass


def load_config(path: str | None) -> dict:
    if not path:
        return DEFAULT_CONFIG
    try:
        cfg = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read likelihood config: {exc}") from None
    validate(cfg)
    return cfg


def validate(cfg: dict) -> None:
    if not isinstance(cfg.get("rules"), list) or not cfg["rules"]:
        raise ConfigError("likelihood config needs a non-empty 'rules' list")
    for i, r in enumerate(cfg["rules"]):
        if not isinstance(r.get("level"), int) or not 1 <= r["level"] <= 5:
            raise ConfigError(f"rule {i}: 'level' must be an integer 1 to 5")
        for kind in ("all", "any"):
            for c in r.get(kind, []):
                if c.get("op") not in OPS or "metric" not in c or "value" not in c:
                    raise ConfigError(f"rule {i}: each condition needs metric, op ({', '.join(OPS)}) and value")


def metrics(lag: dict, health: dict, scorecard: dict) -> dict:
    sev_at = lag.get("fix_available_at_release_by_severity", {})
    sev_fix = lag.get("with_fix_by_severity", {})
    sev_un = lag.get("unshipped_by_severity")
    return {
        "critical_fix_at_release": sev_at.get("CRITICAL", 0),
        "high_fix_at_release": sev_at.get("HIGH", 0),
        "critical_with_fix": sev_fix.get("CRITICAL", 0),
        "high_with_fix": sev_fix.get("HIGH", 0),
        "kev_with_fix": lag.get("kev_with_fix", 0),
        "weaponised_with_fix": lag.get("weaponised_with_fix") if lag.get("exploits_checked") else None,
        "public_exploit_with_fix": lag.get("public_exploit_with_fix") if lag.get("exploits_checked") else None,
        "max_epss_with_fix": lag.get("max_epss_with_fix"),
        "critical_fix_unshipped": sev_un.get("CRITICAL", 0) if sev_un is not None else None,
        "high_fix_unshipped": sev_un.get("HIGH", 0) if sev_un is not None else None,
        "max_days_fix_available": lag.get("max_days_fix_available"),
        "days_since_latest_release": health.get("days_since_latest_release"),
        "archived": 1 if health.get("archived") else 0,
        "scorecard_score": scorecard.get("score") if scorecard.get("status") == "ok" else None,
        "fix_date_unknown": lag.get("fix_date_unknown", 0),
        "with_fix": lag.get("with_fix", 0),
        "release_date_known": 1 if lag.get("release_date") else 0,
        "scanned_is_latest": lag.get("scanned_is_latest"),
    }


def _match(cond: dict, m: dict) -> bool:
    val = m.get(cond["metric"])
    if val is None:
        return False  # unknown signals never trigger a rule
    return OPS[cond["op"]](val, cond["value"])


def confidence(m: dict) -> tuple[str, list[str]]:
    """How much of the evidence the date-based rules need was actually available."""
    reasons = []
    with_fix = m.get("with_fix") or 0
    unknown = m.get("fix_date_unknown") or 0
    if with_fix and unknown / with_fix > 0.5:
        reasons.append(f"fix dates unknown for {unknown} of {with_fix} findings with fixes (often OS packages "
                       "or binaries), so lag-based rules see only part of the picture")
    if not m.get("release_date_known"):
        reasons.append("no release date, so lag-based rules cannot fire")
    if m.get("critical_fix_unshipped") is None and m.get("scanned_is_latest") is not False:
        # Not applicable to an older release (not missing evidence), so only a missing match counts.
        reasons.append("unshipped metric unavailable (no matched GitHub release)")
    return ("low" if reasons else "normal"), reasons


def evaluate(cfg: dict, m: dict) -> dict:
    conf, conf_reasons = confidence(m)
    top = max(r["level"] for r in cfg["rules"])
    for r in cfg["rules"]:
        all_ok = all(_match(c, m) for c in r.get("all", []))
        any_list = r.get("any", [])
        any_ok = any(_match(c, m) for c in any_list) if any_list else True
        if all_ok and any_ok:
            if r["level"] == top:
                # Missing evidence can only hide a higher level; at the top of the scale it changes nothing.
                conf, conf_reasons = "normal", []
            return {
                "level": r["level"],
                "label": cfg.get("scale", {}).get(str(r["level"]), str(r["level"])),
                "reason": r.get("reason", ""),
                "metrics": m,
                "heuristic": True,
                "custom_config": cfg is not DEFAULT_CONFIG,
                "confidence": conf,
                "confidence_reasons": conf_reasons,
            }
    return {"level": None, "label": "No rule matched", "reason": "", "metrics": m, "heuristic": True,
            "custom_config": cfg is not DEFAULT_CONFIG, "confidence": conf, "confidence_reasons": conf_reasons}
