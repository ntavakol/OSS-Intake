"""Take the README screenshots of a report, light and dark.

    python -m pip install playwright && python -m playwright install chromium
    python scripts/screenshots.py site/samples/compromised-npm/report.html docs/images

Only the top of the page is captured: header, tiles, warnings and the severity summary.
"""

from __future__ import annotations

import sys
from pathlib import Path

from playwright.sync_api import sync_playwright


def main(report: str, out_dir: str) -> None:
    src = Path(report).resolve().as_uri()
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as p:
        browser = p.chromium.launch()
        for scheme in ("light", "dark"):
            page = browser.new_page(viewport={"width": 1200, "height": 960}, color_scheme=scheme,
                                    device_scale_factor=2)
            page.goto(src)
            page.screenshot(path=str(out / f"report-{scheme}.png"))
            print(out / f"report-{scheme}.png")
        browser.close()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
