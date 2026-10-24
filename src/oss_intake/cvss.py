"""CVSS v3.0/v3.1 base score from a vector string (FIRST specification, section 7)."""

from __future__ import annotations

import math

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def base_score(vector: str) -> float | None:
    if not vector or not vector.startswith("CVSS:3."):
        return None
    try:
        parts = dict(p.split(":", 1) for p in vector.split("/")[1:])
        scope_changed = parts["S"] == "C"
        iss = 1 - (1 - _CIA[parts["C"]]) * (1 - _CIA[parts["I"]]) * (1 - _CIA[parts["A"]])
        if scope_changed:
            impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        else:
            impact = 6.42 * iss
        pr = (_PR_C if scope_changed else _PR_U)[parts["PR"]]
        exploitability = 8.22 * _AV[parts["AV"]] * _AC[parts["AC"]] * pr * _UI[parts["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    if scope_changed:
        return _roundup(min(1.08 * (impact + exploitability), 10))
    return _roundup(min(impact + exploitability, 10))


def version_of(vector: str | None, fallback: str = "") -> str:
    """'CVSS:3.1/AV:N/...' -> '3.1'."""
    if vector and vector.startswith("CVSS:"):
        return vector[5:].split("/", 1)[0]
    return fallback


def better(candidate: tuple[float, str, str] | None, current: tuple[float, str, str] | None) -> bool:
    """(score, version, source): any v3 score beats a v4 score (the two scales are not comparable, and v3
    is what most tooling and policy still use); within the same major version the higher score wins."""
    if candidate is None or candidate[0] is None:
        return False
    if current is None or current[0] is None:
        return True
    rank_c, rank_cur = candidate[1].startswith("3"), current[1].startswith("3")
    if rank_c != rank_cur:
        return rank_c
    return candidate[0] > current[0]


def severity_from_score(score: float | None) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "UNKNOWN"
