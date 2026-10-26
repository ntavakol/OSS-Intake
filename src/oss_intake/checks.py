"""Which evidence sources actually ran, so a report never shows a skipped check as a clean result.

Each source gets a state:
  checked      the source was consulted (a zero means none found)
  partial      some of it was consulted; the reason says what is missing
  not checked  the source was not consulted; a zero would mean nothing, so reports show "not checked"

Sources: kev (CISA KEV), exploits (Metasploit, Nuclei, Exploit-DB), epss (FIRST EPSS), malicious (OpenSSF
malicious packages via OSV; without OSV only advisories classed CWE-506 by Trivy or Grype are seen).
"""

from __future__ import annotations

CHECKED, PARTIAL, NOT_CHECKED = "checked", "partial", "not checked"
LABEL = {"kev": "CISA KEV", "exploits": "exploit indexes", "epss": "EPSS", "malicious": "malicious package data"}


def state(value: str, reason: str = "") -> dict:
    return {"state": value, "reason": reason}


def compute(n_findings: int, kev: dict, epss: dict, exploits: dict, malicious: dict,
            skipped_by: dict[str, str]) -> dict:
    """kev, epss, exploits: the enrichment info dicts from the scan. malicious: a state dict worked out from the
    OSV step. skipped_by: why a source with status 'skipped' did not run, e.g. {"kev": "--no-kev"}."""
    out: dict = {}
    for name, info in (("kev", kev), ("exploits", exploits), ("epss", epss)):
        status = (info or {}).get("status", "skipped")
        if not n_findings:
            out[name] = state(CHECKED, "no findings to look up")
        elif status == "skipped":
            out[name] = state(NOT_CHECKED, skipped_by.get(name, "not run"))
        elif name == "exploits" and status in ("ok", "partial") and info.get("failed"):
            loaded = sorted(info.get("sources") or {})
            out[name] = (state(PARTIAL, "could not load " + ", ".join(info["failed"])) if loaded
                         else state(NOT_CHECKED, "no exploit index could be loaded"))
        elif status != "ok":
            out[name] = state(NOT_CHECKED, "could not be loaded" + (f": {info['note']}" if info.get("note") else ""))
        elif name == "epss" and info.get("errors"):
            out[name] = state(PARTIAL, f"{info['errors']} lookup batch(es) failed")
        else:
            out[name] = state(CHECKED)
    out["malicious"] = malicious
    return out


def state_of(checks: dict | None, name: str) -> str:
    return (checks or {}).get(name, {}).get("state", CHECKED)


def is_checked(checks: dict | None, name: str) -> bool:
    """True when the source ran at least in part. With no checks recorded (older callers), assume it ran."""
    if not checks or name not in checks:
        return True
    return checks[name]["state"] != NOT_CHECKED


def gaps(checks: dict | None) -> list[str]:
    """Sources that were not fully checked, in a stable order."""
    return [k for k in LABEL if checks and k in checks and checks[k]["state"] != CHECKED]


def describe(checks: dict, name: str) -> str:
    """'not checked (--offline)' / 'partial (could not load nuclei)'."""
    c = checks[name]
    return c["state"] + (f" ({c['reason']})" if c["reason"] else "")


def warning(checks: dict | None) -> str | None:
    missing = gaps(checks)
    if not missing:
        return None
    parts = [f"{LABEL[n]} {describe(checks, n)}" for n in missing]
    return ("Not every source was checked: " + "; ".join(parts)
            + ". A zero for these means not checked, not clean")


def exploits_note(chk: dict) -> str:
    return (f"Exploit indexes {describe(chk, 'exploits')}, so 'Act now' can only come from CISA KEV"
            + ("" if is_checked(chk, "kev") else " (also not checked)") + " and malicious packages.")
