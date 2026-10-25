"""Apply govulncheck results to findings on Go binaries (opt-in, --reachability).

reachability values:
  reachable      govulncheck found a vulnerable function linked into the binary
  not reachable  govulncheck lists the vulnerability for the binary but none of its vulnerable functions are
                 in it (in every binary the finding was seen in)
  ""             no evidence: not a Go binary finding, or govulncheck does not mention this vulnerability
The finding stays in the counts either way: the vulnerable version is still shipped.
"""

from __future__ import annotations

from .models import Finding


def _norm(path: str) -> str:
    return path.lstrip("/")


def apply(findings: list[Finding], results: dict[str, dict[str, dict]]) -> dict:
    stats = {"binaries": len(results), "reachable": 0, "not_reachable": 0}
    by_path = {_norm(k): v for k, v in results.items()}
    for f in findings:
        targets = [_norm(t) for t in f.target.split(";") if t] if f.target else []
        hits = []
        for t in targets:
            res = by_path.get(t)
            if res is None:
                continue
            ids = {f.vuln_id.upper(), *(a.upper() for a in f.aliases)}
            levels = [res[i] for i in ids if i in res]
            if levels:
                best = max(levels, key=lambda x: x["level"])
                hits.append((t, best))
        if not hits:
            continue
        reach = [(t, h) for t, h in hits if h["level"] >= 3]
        if reach:
            t, h = reach[0]
            f.reachability = "reachable"
            f.reachability_note = f"govulncheck {h['go_id']}: vulnerable function present in {t}"
            stats["reachable"] += 1
        elif len(hits) == len(targets):
            f.reachability = "not reachable"
            f.reachability_note = ("govulncheck " + hits[0][1]["go_id"] + ": vulnerable functions not in "
                                   + ", ".join(t for t, _ in hits))
            stats["not_reachable"] += 1
    return stats
