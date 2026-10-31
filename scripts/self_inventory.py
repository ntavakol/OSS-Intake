#!/usr/bin/env python3
"""Turn `pip list --format=json` into an oss-intake inventory CSV, so CI can check oss-intake's own dependencies.

    python -m pip list --format=json | python scripts/self_inventory.py > self-inventory.csv

Every installed distribution becomes one `pkg:pypi/<name>@<version>` row, except oss-intake itself (installed
from the checkout, at a version that may not be on PyPI yet) and anything installed from a local path.
"""

from __future__ import annotations

import json
import re
import sys

SKIP = {"oss-intake"}


def rows(listing: object) -> list[str]:
    if not isinstance(listing, list):
        raise ValueError("expected the JSON list that `pip list --format=json` prints")
    out = []
    for item in listing:
        if not isinstance(item, dict) or not item.get("name") or not item.get("version"):
            raise ValueError(f"unexpected entry: {item!r}")
        name = re.sub(r"[-_.]+", "-", str(item["name"])).lower()  # PEP 503
        if name in SKIP or item.get("editable_project_location"):
            continue
        out.append(f"pkg:pypi/{name}@{item['version']}")
    return sorted(set(out))


def main() -> int:
    try:
        purls = rows(json.load(sys.stdin))
    except ValueError as exc:
        print(f"self_inventory: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write("purl\n" + "".join(f"{p}\n" for p in purls))
    return 0


if __name__ == "__main__":
    sys.exit(main())
