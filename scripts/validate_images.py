"""Run oss-intake over a list of public images and write one summary table.

Each non-comment line of the list is:  IMAGE [GITHUB_REPO|-] [extra oss-intake args...]
Results go to OUT/<image>/ and OUT/summary.md, which is the file to share.

Usage:
  python scripts/validate_images.py images.txt --out reports-validate [--trivy-sha256 HEX] [--grype-sha256 HEX]
"""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
import time
from pathlib import Path


def run_one(image: str, repo: str | None, extra: list[str], out: Path, common: list[str]) -> dict:
    cmd = [sys.executable, "-m", "oss_intake", "--image", image, "--out", str(out), "--formats", "md,json,csv"]
    if repo:
        cmd += ["--repo", repo]
    cmd += common + extra
    start = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    row = {"image": image, "repo": repo or "-", "exit": proc.returncode, "seconds": round(time.time() - start)}
    errors = [ln for ln in proc.stderr.splitlines() if "error:" in ln]
    row["error"] = errors[-1].split("error:", 1)[1].strip()[:140] if errors else ""
    a_path = out / "assessment.json"
    if proc.returncode in (0, 3) and a_path.exists():
        a = json.loads(a_path.read_text(encoding="utf-8"))
        lag, lk = a["lag"], a.get("likelihood") or {}
        row.update({
            "findings": lag["total"], "crit": lag["by_severity"]["CRITICAL"], "high": lag["by_severity"]["HIGH"],
            "with_fix": lag["with_fix"], "dated": lag["fix_date_known"],
            "release": f"{(lag.get('release_date') or '')[:10]} ({lag.get('release_date_source') or 'none'})",
            "before_rel": lag["fix_available_at_release"],
            "unshipped": "n/a" if lag.get("unshipped") is None else lag["unshipped"],
            "coverage": ", ".join(f"{c['ecosystem']} {c['dated']}/{c['with_fix']}" for c in a.get("coverage") or []),
            "likelihood": f"{lk.get('level')} {lk.get('confidence', '')}".strip() if lk else "-",
            "sources": ",".join(s for s, v in a["scanners"].items() if v.get("enabled")),
            "warnings": len(a.get("warnings") or []),
        })
    return row


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("image_list", type=Path)
    ap.add_argument("--out", type=Path, default=Path("reports-validate"))
    ap.add_argument("--trivy-sha256")
    ap.add_argument("--grype-sha256")
    args = ap.parse_args()
    if not args.image_list.is_file():
        raise SystemExit(f"error: {args.image_list} not found")
    common = ["--image-src", "remote", "--min-severity", "HIGH", "--likelihood", "--quiet"]
    if args.trivy_sha256:
        common += ["--trivy-sha256", args.trivy_sha256]
    if args.grype_sha256:
        common += ["--grype-sha256", args.grype_sha256]
    rows = []
    for line in args.image_list.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = shlex.split(line)
        image, repo = parts[0], (parts[1] if len(parts) > 1 and parts[1] != "-" else None)
        out = args.out / image.replace("/", "_").replace(":", "_")
        print(f"=== {image}", flush=True)
        row = run_one(image, repo, parts[2:], out, common)
        print(f"    exit={row['exit']} {row.get('findings', '-')} findings, {row['seconds']}s {row['error']}",
              flush=True)
        rows.append(row)
    cols = ["image", "exit", "findings", "crit", "high", "with_fix", "dated", "coverage", "release", "before_rel",
            "unshipped", "likelihood", "sources", "warnings", "error"]
    lines = ["| " + " | ".join(cols) + " |", "|" + "|".join("---" for _ in cols) + "|"]
    for r in rows:
        lines.append("| " + " | ".join(str(r.get(c, "")).replace("|", "/") for c in cols) + " |")
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote {args.out / 'summary.md'}")


if __name__ == "__main__":
    main()
