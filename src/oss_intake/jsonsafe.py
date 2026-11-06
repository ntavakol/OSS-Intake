"""json.loads with an explicit nesting limit.

Python up to 3.14 refused deeply nested JSON with RecursionError, and the parsers here treat that as input that
cannot be read. Python 3.15 measures the C stack instead, so 50,000 levels parse, and code that walks the
result (or a later json.dumps) is what fails. The limit is checked here, before parsing, on every Python."""

from __future__ import annotations

import json
import re
from itertools import accumulate
from typing import Any

MAX_DEPTH = 512  # far deeper than any real report, SBOM or answer; below where the walkers here would recurse out

_STRING = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"')
_NOT_BRACKET = re.compile(r"[^\[\]{}]+")
_STEP = {"[": 1, "{": 1, "]": -1, "}": -1}


def depth(text: str) -> int:
    """The deepest nesting of arrays and objects in text, ignoring brackets inside strings. Linear time, mostly in
    the regex engine."""
    brackets = _NOT_BRACKET.sub("", _STRING.sub("", text))
    return max(accumulate(map(_STEP.__getitem__, brackets)), default=0)


def loads(data: str | bytes | bytearray, max_depth: int = MAX_DEPTH) -> Any:
    """json.loads, but JSON nested deeper than max_depth raises RecursionError, as older Pythons did, so every
    caller's existing handling of it (input error, source failed) applies unchanged."""
    text = data.decode(json.detect_encoding(data), "surrogatepass") if isinstance(data, (bytes, bytearray)) else data
    if depth(text) > max_depth:
        raise RecursionError(f"nested more than {max_depth} levels deep")
    return json.loads(text)
