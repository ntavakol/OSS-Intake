"""Draw the README's architecture picture, light and dark.

    python -m pip install playwright && python -m playwright install chromium
    python scripts/architecture.py docs/images

Writes architecture-light.svg and architecture-dark.svg (the source, readable on their own) and a PNG of each,
which the README shows. Edit the lists below and run it again; the layout follows the text.
"""

from __future__ import annotations

import sys
from html import escape
from pathlib import Path

INPUTS = [
    ("Container images", "Docker, containerd, Podman, registries"),
    ("Source repos", "GitHub, GitLab, Codeberg (--repo)"),
    ("Folders and artifacts", "lockfiles, JARs, wheels, npm packages"),
    ("SBOMs and inventories", "CycloneDX, SPDX, CSV, Excel"),
    ("IDE extensions", "VS Code via Open VSX, JetBrains plugins"),
    ("Collectors", "osquery fleet, Nexus proxy cache"),
]
STEPS = [
    ("1  Verify scanners", ["checksums, Sigstore,", "signed known-bad list"]),
    ("2  Scan", ["Trivy, Grype,", "govulncheck, OSV"]),
    ("3  Merge", ["one finding per", "CVE and package"]),
    ("4  Enrich", ["fix dates, KEV, EPSS,", "exploits, project health"]),
    ("5  Judge", ["release lag, likelihood,", "your decisions"]),
    ("6  Gate", ["--fail-on rules set", "the exit code"]),
]
SERVICES = [
    ("Vulnerabilities", ["OSV, deps.dev,", "CISA KEV, FIRST EPSS"]),
    ("Exploit indexes", ["PoC-in-GitHub, Nuclei,", "Exploit-DB, Metasploit"]),
    ("Project health", ["GitHub, GitLab,", "Codeberg, OpenSSF", "Scorecard"]),
    ("Fix dates", ["Debian, Ubuntu, Red Hat,", "Amazon Linux, Alpine,", "CRAN, Go"]),
    ("Registries", ["PyPI, npm, Maven", "Central, Packagist"]),
    ("Extension stores", ["Open VSX, JetBrains", "Marketplace, VS Code", "removal list"]),
]
OUTPUTS = [
    ("Reports", "HTML, PDF, Markdown, CSV, JSON"),
    ("SARIF", "GitHub code scanning and other CI"),
    ("Exit codes", "0 clear, 3 gate failed, 1 or 2 error"),
    ("Executive summary", "act now, malicious, likelihood"),
    ("SBOM", "CycloneDX of what was scanned"),
    ("Scheduled re-scans", "GitHub Actions example workflow"),
]

PALETTES = {
    "light": {"bg": "#ffffff", "panel": "#f6f8fa", "panel_line": "#d0d7de", "text": "#1f2328", "sub": "#57606a",
              "arrow": "#57606a", "in": ("#ddf4ff", "#54aeff"), "core": ("#dafbe1", "#4ac26b"),
              "svc": ("#fff8c5", "#d4a72c"), "out": ("#fbefff", "#c297ff")},
    "dark": {"bg": "#0d1117", "panel": "#161b22", "panel_line": "#30363d", "text": "#e6edf3", "sub": "#9198a1",
             "arrow": "#9198a1", "in": ("#0c2d6b", "#1f6feb"), "core": ("#0f3d1e", "#2ea043"),
             "svc": ("#3b2e05", "#9e6a03"), "out": ("#2e1a52", "#8957e5")},
}

FONT = "Inter, 'Segoe UI', Helvetica, Arial, sans-serif"
PAD, TITLE_H, GAP = 24, 56, 14
COL_W, BLOCK_W, BLOCK_H = 420, 372, 74
STEP_W, STEP_H, STEP_GAP = 224, 104, 56
MARGIN = 20
SVC_H = 112
CORE_X = COL_W + 72
CORE_W = PAD * 2 + STEP_W * 3 + STEP_GAP * 2
OUT_X = CORE_X + CORE_W + 72
WIDTH = OUT_X + COL_W + MARGIN * 2
SIDE_H = TITLE_H + len(INPUTS) * (BLOCK_H + GAP) - GAP + PAD
CORE_H = TITLE_H + STEP_H * 2 + 60 + PAD
SVC_Y = CORE_H + 110
SVC_PANEL_H = TITLE_H + SVC_H * 2 + GAP + PAD
HEIGHT = max(SIDE_H, SVC_Y + SVC_PANEL_H) + MARGIN * 2


def svg(p: dict) -> str:
    out: list[str] = []
    add = out.append

    def text(x, y, s, size=17, weight=400, color=None, anchor="start"):
        add(f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{color or p["text"]}" '
            f'text-anchor="{anchor}">{escape(s)}</text>')

    def panel(x, y, w, h, title):
        add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="{p["panel"]}" stroke="{p["panel_line"]}"/>')
        text(x + PAD, y + 36, title, 21, 700)

    def block(x, y, w, h, colors, title, lines):
        add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="10" fill="{colors[0]}" stroke="{colors[1]}" '
            'stroke-width="1.5"/>')
        text(x + 14, y + 28, title, 18, 700)
        for i, line in enumerate(lines):
            text(x + 14, y + 52 + i * 21, line, 16, 400, p["sub"])

    def arrow(points, label=None, lx=0, ly=0):
        d = " ".join(f"{'M' if i == 0 else 'L'}{x},{y}" for i, (x, y) in enumerate(points))
        add(f'<path d="{d}" fill="none" stroke="{p["arrow"]}" stroke-width="2" marker-end="url(#head)"/>')
        if label:
            for i, line in enumerate(label):
                text(lx, ly + i * 21, line, 16, 400, p["sub"])

    add(f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}" '
        f'font-family="{FONT}">')
    add(f'<defs><marker id="head" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" '
        f'orient="auto-start-reverse"><path d="M0,0 L10,5 L0,10 z" fill="{p["arrow"]}"/></marker></defs>')
    add(f'<rect width="{WIDTH}" height="{HEIGHT}" fill="{p["bg"]}"/>')
    add(f'<g transform="translate({MARGIN},{MARGIN})">')

    panel(0, 0, COL_W, SIDE_H, "What it reads")
    for i, (t, s) in enumerate(INPUTS):
        block(PAD, TITLE_H + i * (BLOCK_H + GAP), BLOCK_W, BLOCK_H, p["in"], t, [s])

    panel(CORE_X, 0, CORE_W, CORE_H, "oss-intake, on your machine or in CI")
    pos = []
    for i, (t, lines) in enumerate(STEPS):
        x = CORE_X + PAD + (i % 3) * (STEP_W + STEP_GAP)
        y = TITLE_H + (0 if i < 3 else STEP_H + 60)
        pos.append((x, y))
        block(x, y, STEP_W, STEP_H, p["core"], t, lines)
    for a, b in ((0, 1), (1, 2), (3, 4), (4, 5)):
        y = pos[a][1] + STEP_H / 2
        arrow([(pos[a][0] + STEP_W, y), (pos[b][0] - 2, y)])
    mid = pos[2][1] + STEP_H + 30
    arrow([(pos[2][0] + STEP_W / 2, pos[2][1] + STEP_H), (pos[2][0] + STEP_W / 2, mid),
           (pos[3][0] + STEP_W / 2, mid), (pos[3][0] + STEP_W / 2, pos[3][1] - 2)])

    panel(CORE_X, SVC_Y, CORE_W, SVC_PANEL_H, "Public services it asks, over HTTPS")
    for i, (t, lines) in enumerate(SERVICES):
        x = CORE_X + PAD + (i % 3) * (STEP_W + STEP_GAP)
        y = SVC_Y + TITLE_H + (0 if i < 3 else SVC_H + GAP)
        block(x, y, STEP_W, SVC_H, p["svc"], t, lines)
    cx = CORE_X + CORE_W / 2
    arrow([(cx, CORE_H), (cx, SVC_Y - 2)], ["package names and versions, never files;", "none with --offline"],
          cx + 16, CORE_H + 46)

    panel(OUT_X, 0, COL_W, SIDE_H, "What it produces")
    for i, (t, s) in enumerate(OUTPUTS):
        block(OUT_X + PAD, TITLE_H + i * (BLOCK_H + GAP), BLOCK_W, BLOCK_H, p["out"], t, [s])

    arrow([(COL_W, CORE_H / 2), (CORE_X - 2, CORE_H / 2)])
    arrow([(CORE_X + CORE_W, CORE_H / 2), (OUT_X - 2, CORE_H / 2)])
    add("</g></svg>")
    return "\n".join(out) + "\n"


def main(out_dir: str) -> None:
    from playwright.sync_api import sync_playwright

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        for scheme, palette in PALETTES.items():
            source = out / f"architecture-{scheme}.svg"
            source.write_text(svg(palette), encoding="utf-8")
            page = browser.new_page(viewport={"width": WIDTH, "height": HEIGHT}, device_scale_factor=2)
            page.goto(source.resolve().as_uri())
            page.screenshot(path=str(out / f"architecture-{scheme}.png"), omit_background=False)
            print(source, out / f"architecture-{scheme}.png")
        browser.close()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "docs/images")
