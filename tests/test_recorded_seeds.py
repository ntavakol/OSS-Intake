"""53 known-vulnerable package versions, replayed from real OSV answers recorded on 30 Oct 2026.

Each seed's expected CVE was found by a live run and confirmed against OSV. The test replays what OSV said
(which advisories affect the version, and the record of the one carrying the CVE) with no network, so a change
that stops oss-intake finding one of them (alias handling, package naming, purl encoding, the merge) fails here.
It cannot notice OSV changing its data; the scheduled re-scan is for that. To refresh the recording, run
scripts/record_seeds.py (see its docstring) and replace tests/fixtures/recorded-seeds.json.
"""

import csv
import json
from pathlib import Path

from oss_intake import cli
from oss_intake.http import Http

REC = json.loads((Path(__file__).parent / "fixtures" / "recorded-seeds.json").read_text(encoding="utf-8"))


class Replay(Http):
    def __init__(self):
        self.by_purl = {s["purl"]: s["osv_ids"] for s in REC["seeds"]}
        self.asked: set[str] = set()

    def post_json(self, url, body):
        assert url == "https://api.osv.dev/v1/querybatch"
        out = []
        for q in body["queries"]:
            p = q["package"]["purl"]
            self.asked.add(p)  # also the upgrade comparison's fix versions, which were not recorded
            out.append({"vulns": [{"id": i} for i in self.by_purl.get(p, [])]})
        return 200, {"results": out}

    def get_json(self, url, params=None):
        vid = url.rsplit("/", 1)[1]
        if url.startswith("https://api.osv.dev/v1/vulns/") and vid in REC["vulns"]:
            return 200, REC["vulns"][vid]
        return 404, None  # everything else: unknown, never invented

    def get_text(self, url):
        return 404, ""


def test_recorded_seeds_all_found(tmp_path):
    assert len(REC["seeds"]) == 53
    inv = tmp_path / "seeds.csv"
    with open(inv, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["purl"])
        for s in REC["seeds"]:
            w.writerow([s["purl"]])
    out = tmp_path / "o"
    http = Replay()
    code = cli.main(["--path", str(inv), "--out", str(out), "--no-latest", "--release-age-days", "0", "--no-cache",
                     "--no-epss", "--no-kev", "--no-exploits", "--no-fix-dates", "--as-of", "2026-10-30"], http=http)
    assert code == cli.EXIT_OK
    assert set(http.by_purl) <= http.asked  # each seed was asked about under the purl that was recorded
    found: dict[str, set[str]] = {}
    for f in json.loads((out / "assessment.json").read_text(encoding="utf-8"))["findings"]:
        key = f"{f['pkg_type']}/{f['package'].lower()}@{f['installed']}"
        found.setdefault(key, set()).update({f["id"].upper(), *[a.upper() for a in f.get("aliases") or []]})
    missed = []
    for s in REC["seeds"]:
        key = s["purl"][4:].lower()
        if s["expected_cve"].upper() not in found.get(key, set()):
            missed.append(f"{s['purl']} {s['expected_cve']}")
    assert missed == []
