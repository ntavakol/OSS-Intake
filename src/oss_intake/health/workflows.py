"""Supply-chain hygiene of the target project's GitHub Actions workflows.

Reads .github/workflows through the GitHub contents API and checks, without a YAML dependency:
  * third-party actions not pinned to a full 40-character commit SHA (tags can be force-pushed)
  * known-bad action versions (from data/known_bad.json, e.g. trivy-action below 0.35.0)
  * no top-level permissions block, or write-all (the token may default to write access)
  * pull_request_target triggers (run with the base repository's secrets), and whether the same file checks
    out the pull request's own code, which is the combination that lets an outside contributor run code
    with those secrets. The trigger alone is the normal, safe way to label or comment on PRs.
This describes how exposed the project's releases are to tampering. It does not change the
likelihood rules, which are about exploitation of the vulnerabilities found in the artifact.
"""

from __future__ import annotations

import base64
import re
from urllib.parse import quote

from ..http import Http, HttpError
from ..integrity import load_known_bad
from ..versions import compare

API = "https://api.github.com/repos"
MAX_FILES = 20
_USES = re.compile(r"""^\s*(?:-\s*)?uses:\s*["']?([^"'\s#]+)""", re.MULTILINE)
_SHA = re.compile(r"^[0-9a-f]{40}$")
_TOP_PERMS = re.compile(r"^permissions:\s*(.*)$", re.MULTILINE)
_PRT = re.compile(r"\bpull_request_target\b")
# References to the PR's own code: checkout of the head SHA/ref, the PR merge ref, or gh pr checkout.
_PR_CODE = re.compile(r"github\.event\.pull_request\.head\.(?:sha|ref)|github\.head_ref\b|refs/pull/|"
                      r"\bgh\s+pr\s+checkout\b")


def _version_from_ref(ref: str, line_comment: str) -> str | None:
    """Version of an action reference. A SHA pin has no version of its own, so only the trailing
    comment (e.g. '# v0.35.0') can say which release it is; digits inside the hash must not count."""
    for cand in ([] if _SHA.match(ref) else [ref]) + [line_comment]:
        m = re.search(r"\bv?(\d+(?:\.\d+){0,3})\b", cand or "")
        if m:
            return m.group(1)
    return None


def analyse(name: str, text: str, known_bad: list[dict]) -> dict:
    uses, unpinned, bad = [], [], []
    for m in _USES.finditer(text):
        ref_full = m.group(1)
        if ref_full.startswith(("./", "docker://")) or "@" not in ref_full:
            continue
        action, ref = ref_full.rsplit("@", 1)
        line = text[m.start():text.find("\n", m.end()) if text.find("\n", m.end()) != -1 else len(text)]
        comment = line.split("#", 1)[1] if "#" in line else ""
        uses.append(ref_full)
        if not _SHA.match(ref):
            unpinned.append(ref_full)
        base = "/".join(action.split("/")[:2]).lower()
        for kb in known_bad:
            if base == kb["action"].lower():
                ver = _version_from_ref(ref, comment)
                if ver is None or compare(ver, kb["below"]) < 0:
                    bad.append({"uses": ref_full, "version": ver or "unknown", "reference": kb["reference"],
                                "note": kb["note"]})
    perms = _TOP_PERMS.search(text)
    return {
        "file": name, "uses": len(uses), "unpinned": unpinned, "known_bad": bad,
        "top_level_permissions": bool(perms),
        "write_all": bool(perms and "write-all" in perms.group(1)),
        "pull_request_target": bool(_PRT.search(text)),
        "pull_request_target_pr_code": bool(_PRT.search(text) and _PR_CODE.search(text)),
    }


def fetch(http: Http, repo: str) -> dict:
    owner, name = repo.split("/", 1)
    try:
        status, listing = http.get_json(f"{API}/{owner}/{name}/contents/.github/workflows")
    except HttpError as exc:
        return {"status": "error", "note": str(exc)}
    if status == 404:
        return {"status": "none", "note": "No .github/workflows directory; the project may build elsewhere."}
    if status != 200 or not isinstance(listing, list):
        return {"status": "error", "note": f"GitHub contents API returned HTTP {status}"}
    files = [e for e in listing if e.get("type") == "file" and e.get("name", "").endswith((".yml", ".yaml"))]
    known_bad = load_known_bad().get("actions", [])
    results, skipped = [], max(0, len(files) - MAX_FILES)
    for e in files[:MAX_FILES]:
        try:
            st, data = http.get_json(f"{API}/{owner}/{name}/contents/{quote(e['path'])}")
        except HttpError:
            continue
        if st != 200 or not isinstance(data, dict) or data.get("encoding") != "base64":
            continue
        text = base64.b64decode(data.get("content", "")).decode("utf-8", errors="replace")
        results.append(analyse(e["name"], text, known_bad))
    total = sum(r["uses"] for r in results)
    unpinned = sum(len(r["unpinned"]) for r in results)
    return {
        "status": "ok",
        "files": len(results),
        "files_skipped": skipped,
        "uses_total": total,
        "unpinned": unpinned,
        "pinned_percent": round(100 * (total - unpinned) / total) if total else None,
        "known_bad": [dict(b, file=r["file"]) for r in results for b in r["known_bad"]],
        "no_top_level_permissions": [r["file"] for r in results if not r["top_level_permissions"]],
        "write_all": [r["file"] for r in results if r["write_all"]],
        "pull_request_target": [r["file"] for r in results if r["pull_request_target"]],
        "pull_request_target_pr_code": [r["file"] for r in results if r["pull_request_target_pr_code"]],
        "details": results,
    }
