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

from . import jsonsafe

OPS = {">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le, "==": operator.eq,
       "!=": operator.ne}

DEFAULT_CONFIG = {
    "scale": {"1": "Rare", "2": "Unlikely", "3": "Possible", "4": "Likely", "5": "Almost certain"},
    "rules": [
        {"level": 5,
         "reason": "A package listed as malicious (OpenSSF malicious packages, or a CWE-506 advisory) is present",
         "all": [{"metric": "malicious", "op": ">=", "value": 1}]},
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
    """Raised when a likelihood config file cannot be read, parsed or validated."""
    pass


def load_config(path: str | None) -> dict:
    """DEFAULT_CONFIG when path is empty, else the JSON config at path after validate(). Raises ConfigError for a
    file that cannot be read or is not UTF-8, invalid JSON, JSON that is not an object, or a config that fails
    validation."""
    if not path:
        return DEFAULT_CONFIG
    try:
        cfg = jsonsafe.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ConfigError(f"cannot read likelihood config: {exc or 'nested too deeply'}") from None
    if not isinstance(cfg, dict):
        raise ConfigError("likelihood config must be a JSON object with a 'rules' list")
    validate(cfg)
    return cfg


def validate(cfg: dict) -> None:
    if not isinstance(cfg.get("rules"), list) or not cfg["rules"]:
        raise ConfigError("likelihood config needs a non-empty 'rules' list")
    scale = cfg.get("scale", {})
    if not isinstance(scale, dict) or not all(isinstance(v, str) for v in scale.values()):
        raise ConfigError("likelihood config 'scale' must map levels to names")
    for i, r in enumerate(cfg["rules"]):
        if not isinstance(r, dict):
            raise ConfigError(f"rule {i}: must be an object")
        if not isinstance(r.get("level"), int) or isinstance(r["level"], bool) or not 1 <= r["level"] <= 5:
            raise ConfigError(f"rule {i}: 'level' must be an integer 1 to 5")
        for kind in ("all", "any"):
            conds = r.get(kind, [])
            if not isinstance(conds, list):
                raise ConfigError(f"rule {i}: '{kind}' must be a list of conditions")
            for c in conds:
                if (not isinstance(c, dict) or not isinstance(c.get("op"), str) or c["op"] not in OPS
                        or "metric" not in c or "value" not in c):
                    raise ConfigError(f"rule {i}: each condition needs metric, op ({', '.join(OPS)}) and value")
                if not isinstance(c["metric"], str):
                    raise ConfigError(f"rule {i}: a condition's metric must be a name")
                if not isinstance(c["value"], (int, float)):  # bool is an int: archived == true
                    raise ConfigError(f"rule {i}: a condition's value must be a number or true/false")


def _number(value):
    """A number from a service answer, or None (unknown) for anything else, such as a score sent as text."""
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _bound(value, checked: bool):
    return value if checked or value else None


def _evidence(lag: dict, key: str, source: str):
    """A fix-related signal from a source: 0 when there is no finding with a fix (nothing it could count), what
    the source found when it ran, and unknown (None) when it failed and found nothing. lag without the
    <source>_ok key (older callers) reads as before."""
    if not lag.get("with_fix"):
        return 0
    value = lag.get(key)
    ok_key = f"{source}_ok"
    if ok_key not in lag:  # as before: the exploit counts are known only when the indexes were checked
        return (value if lag.get("exploits_checked") else None) if source == "exploits" else value or 0
    return _bound(value or 0, lag[ok_key])


def metrics(lag: dict, health: dict, scorecard: dict) -> dict:
    """Flatten the lag, health and Scorecard results into the metrics the likelihood rules match on (fixes by
    severity, KEV, exploits, EPSS, ages, archived, Scorecard score). Values that were not checked are None."""
    sev_at = lag.get("fix_available_at_release_by_severity", {})
    sev_fix = lag.get("with_fix_by_severity", {})
    sev_un = lag.get("unshipped_by_severity")
    return {
        "critical_fix_at_release": sev_at.get("CRITICAL", 0),
        "high_fix_at_release": sev_at.get("HIGH", 0),
        "critical_with_fix": sev_fix.get("CRITICAL", 0),
        "high_with_fix": sev_fix.get("HIGH", 0),
        # A count from a source that did not fully load is a lower bound: what it found counts, but a 0 from it
        # is unknown, so a rule on it must not read as not met.
        "kev_with_fix": _evidence(lag, "kev_with_fix", "kev"),
        "malicious": _bound(lag.get("malicious", 0), lag.get("malicious_ok", True)),
        "weaponised_with_fix": _evidence(lag, "weaponised_with_fix", "exploits"),
        "public_exploit_with_fix": _evidence(lag, "public_exploit_with_fix", "exploits"),
        "max_epss_with_fix": _evidence(lag, "max_epss_with_fix", "epss"),
        "critical_fix_unshipped": sev_un.get("CRITICAL", 0) if sev_un is not None else None,
        "high_fix_unshipped": sev_un.get("HIGH", 0) if sev_un is not None else None,
        "max_days_fix_available": lag.get("max_days_fix_available"),
        "days_since_latest_release": health.get("days_since_latest_release"),
        "archived": 1 if health.get("archived") else 0,
        "scorecard_score": _number(scorecard.get("score")) if scorecard.get("status") == "ok" else None,
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


# Evidence from sources that can fail on a given run (CISA KEV, malicious packages, EPSS, exploit indexes). When
# one failed, its metric is unknown and a rule on it is undecided, so --fail-on-likelihood cannot pass on a lower
# result. Other metrics that can be missing (release health without --repo, a release date) are a standing
# condition of the run, reported as low confidence: a rule on them reads as not met, as before.
EVIDENCE = {"kev_with_fix", "malicious", "max_epss_with_fix", "weaponised_with_fix", "public_exploit_with_fix"}


def _known(cond: dict, m: dict) -> bool | None:
    """A condition as True, False, or None when it rests on evidence that did not load."""
    if m.get(cond["metric"]) is not None:
        return _match(cond, m)
    return None if cond["metric"] in EVIDENCE else False


def _rule(r: dict, m: dict) -> bool | None:
    """A rule as True, False, or None when unchecked metrics decide it (it might have matched)."""
    alls = [_known(c, m) for c in r.get("all", [])]
    anys = [_known(c, m) for c in r.get("any", [])]
    all_ok = False if False in alls else None if None in alls else True
    any_ok = True if not anys or True in anys else None if None in anys else False
    return False if False in (all_ok, any_ok) else True if all_ok and any_ok else None


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
    """The first rule in cfg whose "all" and "any" conditions match the metrics, as a dict with level, label, reason,
    metrics, confidence and confidence_reasons (confidence is "normal" at the top level). With no match, level is
    None."""
    conf, conf_reasons = confidence(m)
    top = max(r["level"] for r in cfg["rules"])
    # Rules ahead of the one that matches whose metrics were not checked: had they been, one might have matched
    # instead, so --fail-on-likelihood at their level cannot pass on this result.
    undecided = [r for r in cfg["rules"][:next((i for i, r in enumerate(cfg["rules"]) if _rule(r, m)),
                                               len(cfg["rules"]))] if _rule(r, m) is None]
    could_be = max((r["level"] for r in undecided), default=None)
    unchecked = sorted({c["metric"] for r in undecided for c in r.get("all", []) + r.get("any", [])
                        if m.get(c["metric"]) is None})
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
                "could_be": could_be if could_be and could_be > r["level"] else None,
                "unchecked": unchecked if could_be and could_be > r["level"] else [],
            }
    return {"level": None, "label": "No rule matched", "reason": "", "metrics": m, "heuristic": True,
            "custom_config": cfg is not DEFAULT_CONFIG, "confidence": conf, "confidence_reasons": conf_reasons,
            "could_be": could_be, "unchecked": unchecked}
