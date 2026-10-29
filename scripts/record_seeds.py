"""Record live OSV answers for the seeds whose expected CVE oss-intake found, for tests/test_recorded_seeds.py.

Usage, with seeds.csv having ecosystem,name,version,expected_cve columns:
  oss-intake --path seeds.csv --out seeds-out --no-cache
  python3 scripts/record_seeds.py seeds.csv seeds-out/findings.csv tests/fixtures/recorded-seeds.json

Writes only public advisory data: for each confirmed seed, the advisory IDs OSV returns for that package version
(querybatch) and the full record of the advisory carrying the expected CVE. Standard library only.
"""

import csv
import json
import sys
import urllib.error
import urllib.request

API = "https://api.osv.dev/v1"


def _open(req):
    url = req.full_url if isinstance(req, urllib.request.Request) else req
    if not url.startswith(API + "/"):
        raise ValueError(f"refusing {url}: only {API} is used")
    return urllib.request.urlopen(req, timeout=60)  # noqa: S310 - https only, checked above


def post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(),  # noqa: S310 - checked in _open
                                 headers={"Content-Type": "application/json"})
    with _open(req) as r:
        return json.load(r)


def get(url):
    with _open(url) as r:
        return json.load(r)


def purl(eco, name, version):
    if eco == "pypi":
        name = name.lower().replace("_", "-").replace(".", "-")
    return f"pkg:{eco}/{name}@{version}"


seeds = list(csv.DictReader(open(sys.argv[1], encoding="utf-8-sig")))
found = {}
for r in csv.DictReader(open(sys.argv[2], encoding="utf-8-sig")):
    ids = {r["id"].upper(), *[a.upper() for a in r["aliases"].split(";") if a]}
    found.setdefault((r["package"].lower(), r["installed"]), []).append((r["id"], ids))

confirmed = []
for s in seeds:
    for _vid, ids in found.get((s["name"].lower(), s["version"]), []):
        if s["expected_cve"].upper() in ids:
            confirmed.append({**s, "purl": purl(s["ecosystem"], s["name"], s["version"]), "ids": ids})
            break
print(f"{len(confirmed)} confirmed seeds")

batch = post(f"{API}/querybatch", {"queries": [{"package": {"purl": c["purl"]}} for c in confirmed]})
out = {"source": "api.osv.dev, recorded by record_seeds.py", "seeds": [], "vulns": {}}
missing = []
for c, res in zip(confirmed, batch["results"], strict=True):
    osv_ids = [v["id"] for v in res.get("vulns", [])]
    # The advisory OSV returns for this version that carries the expected CVE: findings.csv names it by its
    # CVE, but OSV may file it as GHSA-... or PYSEC-..., and /vulns/CVE-... can be a 404.
    advisory = None
    for vid in [i for i in osv_ids if i.upper() in c["ids"]]:
        try:
            rec = out["vulns"].get(vid) or get(f"{API}/vulns/{vid}")
        except urllib.error.HTTPError:
            continue
        if c["expected_cve"].upper() in {rec["id"].upper(), *[a.upper() for a in rec.get("aliases") or []],
                                         *[u.upper() for u in rec.get("upstream") or []]}:
            out["vulns"][vid], advisory = rec, vid
            break
    if advisory is None:
        missing.append(c["purl"])
        continue
    out["seeds"].append({"purl": c["purl"], "expected_cve": c["expected_cve"], "advisory": advisory,
                         "osv_ids": osv_ids})
json.dump(out, open(sys.argv[3], "w", encoding="utf-8"), indent=1, sort_keys=True)
print(f"wrote {sys.argv[3]}: {len(out['seeds'])} seeds, {len(out['vulns'])} advisories"
      + (f"; no OSV advisory with the expected CVE now for: {missing}" if missing else ""))
