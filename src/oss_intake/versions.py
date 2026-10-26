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
# OpenSSL-style patch letters after a three-part version: 1.1.1m > 1.1.1l > 1.1.1, and past z: 0.9.8z < 0.9.8za
# < 0.9.8zh. Read as a base-27 number. Only one or two letters after x.y.z, and never a, b, c or rc, which PEP 440
# uses for pre-releases (1.2.3a is 1.2.3a0, before 1.2.3); 1.0a1, 1.0rc1 and 2.0.0-M2 stay pre-releases.
_PATCH_LETTER = re.compile(r"^(\d+\.\d+\.\d+)([A-Za-z]{1,2})(?=$|[-+~_.])")
_NOT_PATCH = {"a", "b", "c", "rc"}


def _patch_letter(m: re.Match) -> str:
    letters = m.group(2).lower()
    if letters in _NOT_PATCH:
        return m.group(0)
    n = 0
    for ch in letters:
        n = n * 27 + (ord(ch) - 96)
    return f"{m.group(1)}.{n}"
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
    v = _PATCH_LETTER.sub(_patch_letter, v)
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


def _tail_sign(rest: list[tuple[int, int, str]]) -> int:
    """How extra trailing segments change a version: +1 newer, -1 older, 0 no change.

    Zero segments change nothing (1.0 == 1.0.0). A pre-release marker makes it older
    (1.0-rc1 < 1.0). Anything else makes it newer: numbers (1.0.1) and unrecognised suffixes,
    which is how Debian security updates (10.42-1+deb12u1 > 10.42-1) and Maven qualifiers sort.
    """
    for kind, rank, _ in rest:
        if kind == 1 and rank == 0:
            continue
        return -1 if kind == 0 and rank < 0 else 1
    return 0


# Package revision after the last hyphen: Alpine 2.41-r9, Debian 10.42-1+deb12u1, RPM 2.41-9.el9_4.
# Compared after the upstream version, otherwise 2.41-r9 would read as 2.41.9 and sort above 2.41.6.
_REVISION = re.compile(r"^(.+)-(r?\d+(?:[.+~_][0-9A-Za-z.+~_]*)?)$")


def _split_revision(v: str) -> tuple[str, str]:
    v = v.strip()
    m = _REVISION.match(v)
    return (m.group(1), m.group(2)) if m else (v, "")


def compare(a: str, b: str) -> int:
    (base_a, rev_a), (base_b, rev_b) = _split_revision(a), _split_revision(b)
    if rev_a or rev_b:
        c = _compare(base_a, base_b)
        if c:
            return c
        return _compare(rev_a.lstrip("r") or "0", rev_b.lstrip("r") or "0")
    return _compare(a, b)


def _compare(a: str, b: str) -> int:
    ka, kb = _key(a), _key(b)
    for x, y in zip(ka, kb, strict=False):
        if x != y:
            return -1 if x < y else 1
    if len(ka) == len(kb):
        return 0
    if len(ka) > len(kb):
        return _tail_sign(ka[len(kb):])
    return -_tail_sign(kb[len(ka):])


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
    """Smallest fixed version strictly greater than installed (the shortest upgrade path).

    Returns None when no listed fix is newer than the installed version. That is a scanner data
    anomaly (often Go pseudo-versions) and must not be papered over by picking an older "fix".
    """
    candidates = [f for f in fixed if compare(f, installed) > 0]
    if not candidates:
        return None
    best = candidates[0]
    for c in candidates[1:]:
        if compare(c, best) < 0:
            best = c
    return best


def _branch(v: str) -> tuple[int, ...]:
    """Major and minor number: the release line a fix belongs to (1.2.9 and 1.3.2 are different lines)."""
    nums = [rank for kind, rank, _ in _key(v) if kind == 1]
    return tuple(nums[:2])


def covers(candidate: str, fixed: list[str], installed: str = "") -> bool:
    """Is candidate fixed for this vulnerability, given its listed fixes?

    With fixes [1.2.9, 1.3.2], 1.2.9 and 1.3.2 are fixed, but 1.3.0 is not: the 1.3 line was fixed in 1.3.2.
    On a line with its own listed fix, the candidate must be at or above it. On a line with no listed fix, the
    candidate must be at or above the nearest fix for the installed version: the installed version itself shows
    that being above a lower line's fix is not enough (3.0.1 is affected although above 2.4.1).
    """
    line = _branch(candidate)
    on_line = [f for f in fixed if _branch(f) == line]
    if on_line:
        return not any(compare(f, candidate) > 0 for f in on_line)
    floor = nearest_fix(installed, fixed) if installed else None
    if floor is None:
        floor = max(fixed, key=_sort_key) if fixed else None
    return floor is not None and compare(candidate, floor) >= 0


def minimum_upgrade(installed: str, fixed_sets: list[list[str]]) -> str | None:
    """Lowest listed fix above installed that is fixed for every vulnerability (each a list of fixed versions),
    taking release lines into account. None when there is none."""
    sets = [s for s in fixed_sets if s]
    candidates = {f for s in sets for f in s if compare(f, installed) > 0}
    for c in sorted(candidates, key=_sort_key):
        if all(covers(c, s, installed) for s in sets):
            return c
    return None


def _sort_key(v: str):
    from functools import cmp_to_key

    return cmp_to_key(compare)(v)


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
