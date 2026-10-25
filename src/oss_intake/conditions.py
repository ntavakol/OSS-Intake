"""The advisory's own statement of when a finding applies, quoted verbatim.

Many advisories say an application is affected only under conditions, for example Spring's
"...can result in SSRF and RCE attack if: the application uses XsltView; has a "/**" mapping ...".
This module picks those sentences (and the list that follows a sentence ending in ':') out of the
advisory text, without interpreting them. Whether the conditions hold is the assessor's call.
"""

from __future__ import annotations

import re

MAX_LEN = 600
_COND = re.compile(
    r"\b(?:only (?:if|when)|vulnerable (?:if|when)|affected (?:if|when)|exploitable (?:if|when|only)"
    r"|all of the following|following (?:conditions )?(?:are|is) true|if (?:an|the) application"
    r"|applications? (?:that|which) (?:use|uses|have|has|enable|configure)|when (?:using|configured|the application)"
    r"|non-default configuration|is (?:enabled|configured|used)|are (?:enabled|configured|used)"
    r"|(?:attack|exploit\w*|vulnerable|affected) (?:if|when)\s*:)", re.IGNORECASE)
_BULLET = re.compile(r"^\s*(?:[-*•]|\d+[.)])\s+")


def _units(text: str) -> list[str]:
    """Sentences, with list items as their own units."""
    out: list[str] = []
    for line in text.replace("\r", "").split("\n"):
        line = line.strip()
        if not line:
            continue
        if _BULLET.match(line):
            out.append(line)
            continue
        out += [s.strip() for s in re.split(r"(?<=[.!?])\s+(?=[A-Z])", line) if s.strip()]
    return out


def extract(text: str) -> str:
    if not text:
        return ""
    units = _units(text)
    picked: list[str] = []
    i = 0
    while i < len(units):
        u = units[i]
        if _COND.search(u):
            picked.append(u)
            if u.rstrip().endswith(":"):  # the conditions follow as a list
                j = i + 1
                while j < len(units) and _BULLET.match(units[j]):
                    picked.append(_BULLET.sub("- ", units[j]))
                    j += 1
                i = j
                continue
        i += 1
    joined = " ".join(dict.fromkeys(picked))
    return joined if len(joined) <= MAX_LEN else joined[: MAX_LEN - 3].rsplit(" ", 1)[0] + "..."
