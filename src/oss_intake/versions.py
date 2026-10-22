"""Loose, ecosystem-agnostic version comparison.

This is intentionally simple: numeric segments compare numerically, text segments
lexically, and pre-release markers (alpha, beta, rc, milestone, snapshot) sort before
the release. It is used only to pick the nearest fixed version above the installed one,
so an occasional mis-ordering affects a date estimate, never which findings are reported.
"""

from __future__ import annotations

import re

_PRE = {"dev": -5, "snapshot": -5, "alpha": -4, "a": -4, "beta": -3, "b": -3, "m": -2, "milestone": -2,
        "rc": -1, "cr": -1, "pre": -1}
_RELEASE = {"final": 0, "ga": 0, "release": 0, "r": 0}
_TOKEN = re.compile(r"\d+|[A-Za-z]+")
# Build labels that identify a variant of the same release, not a different version
# (e.g. mssql-jdbc 12.10.2.jre11, guava 33.0.0-jre / -android). Ignored when comparing.
_LABEL = re.compile(r"[.\-_+](?:jre|jdk|java)\d*$|[.\-_+]android$", re.IGNORECASE)


def strip_label(v: str) -> str:
    return _LABEL.sub("", v.strip())


def _key(v: str) -> list[tuple[int, int, str]]:
    v = v.strip().lstrip("vV")
    # Debian-style epoch "1:2.3" -> drop epoch only for ordering within one package.
    if ":" in v and v.split(":", 1)[0].isdigit():
        v = v.split(":", 1)[1]
    v = strip_label(v)
    out: list[tuple[int, int, str]] = []
    for tok in _TOKEN.findall(v):
        if tok.isdigit():
            out.append((1, int(tok), ""))
        else:
            t = tok.lower()
            if t in _RELEASE:
                continue
            out.append((0, _PRE.get(t, 0), t))
    return out


def compare(a: str, b: str) -> int:
    ka, kb = _key(a), _key(b)
    n = max(len(ka), len(kb))
    for i in range(n):
        x = ka[i] if i < len(ka) else (1, 0, "")  # missing segment == 0 release segment
        y = kb[i] if i < len(kb) else (1, 0, "")
        if x != y:
            return -1 if x < y else 1
    return 0


def split_fixed(value: str | list[str] | None) -> list[str]:
    """Trivy emits '6.1.14, 6.2.1'; Grype emits a list. Normalise to a de-duplicated list."""
    if not value:
        return []
    items = value if isinstance(value, list) else re.split(r"[,\s]+", value)
    seen: list[str] = []
    for i in items:
        i = i.strip()
        if i and i not in seen:
            seen.append(i)
    return seen


def nearest_fix(installed: str, fixed: list[str]) -> str | None:
    """Smallest fixed version strictly greater than installed (the shortest upgrade path)."""
    candidates = [f for f in fixed if compare(f, installed) > 0]
    if not candidates:
        return fixed[0] if fixed else None
    best = candidates[0]
    for c in candidates[1:]:
        if compare(c, best) < 0:
            best = c
    return best


def label_only_match(installed: str, fixed: list[str]) -> str | None:
    """Return a fixed version equal to the installed one apart from a build label, if any.

    Scanners sometimes read a JAR's version without its label (12.10.2 for 12.10.2.jre11)
    and then report the installed build as older than the fix. Such findings are likely
    already fixed and are flagged for review rather than counted as release lag.
    """
    for f in fixed:
        if f.strip() != installed.strip() and compare(f, installed) == 0 and strip_label(f) != f:
            return f
    return None
