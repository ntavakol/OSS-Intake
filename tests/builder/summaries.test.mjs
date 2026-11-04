// "What this command will do" for a fixed set of commands, against tests/fixtures/wizard_summaries.json.
// Every condition in wizard.json changes the summary of at least one of these commands, so any change to a
// condition or a sentence shows up here as a diff to review. After a deliberate change, regenerate with
//   UPDATE_SUMMARIES=1 node --test tests/builder/summaries.test.mjs
// and read the diff of the fixture before committing: each changed line must be true of what the CLI does.
import assert from "node:assert/strict";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import * as w from "../../site/builder/wizard.js";
import { ROOT, data, wizard } from "./helpers.mjs";

const KINDS = {
  lockfile: { path: "package-lock.json" },
  renv: { path: "renv.lock" },
  image: { image: "owner/app:1.0" },
  artifact: { path: "app.jar" },
  folder: { path: "build" },
  inventory: { path: "packages.csv" },
  sbom: { path: "sbom.cdx.json", __what: "inventory" },
  package: { package: ["npm:chalk@5.6.1"] },
  repo: { repo: "owner/name" },
};
const VARIANTS = {
  default: {},
  repo: { repo: "owner/name" },
  offline: { offline: true },
  "repo offline": { repo: "owner/name", offline: true },
  "scanners trivy": { scanners: "trivy" },
  "scanners grype": { scanners: "grype" },
  "scanners trivy,osv": { scanners: "trivy,osv" },
  "no lookups": { no_fix_dates: true, release_age_days: "0", no_latest: true },
  "no fix dates": { no_fix_dates: true },
  "no release age": { release_age_days: "0" },
  "no latest": { no_latest: true },
  "no exploitation": { no_kev: true, no_epss: true, no_exploits: true },
  "no kev": { no_kev: true },
  "repo, no scorecard or workflows": { repo: "owner/name", no_scorecard: true, no_workflows: true },
  "gates": { fail_on: "malicious,kev,high" },
  "gate mismatch": { fail_on: "mismatch" },
  "gate recent": { fail_on: "recent" },
  "likelihood": { fail_on_likelihood: "4" },
  reachability: { reachability: true },
  "reachability, grype": { reachability: true, scanners: "grype" },
  sbom: { sbom: true },
  "imported trivy": { from_trivy_json: "t.json" },
  "imported both": { from_trivy_json: "t.json", from_grype_json: "g.json" },
  "pinned trivy": { trivy_version: "0.76.1" },
  remote: { image_src: "remote" },
  docker: { image_src: "docker" },
  "no registry check": { no_registry_check: true },
  label: { label: ["owner=x"] },
  "min severity, quiet, formats": { min_severity: "HIGH", quiet: true, formats: "csv,html" },
  decisions: { decisions: "old.csv" },
  "scanners trivy,osv, no fix dates": { scanners: "trivy,osv", no_fix_dates: true },
  "scanners trivy, no fix dates": { scanners: "trivy", no_fix_dates: true },
  "scanners grype, no fix dates": { scanners: "grype", no_fix_dates: true },
  "no fix dates or release age": { no_fix_dates: true, release_age_days: "0" },
  "no kev or epss": { no_kev: true, no_epss: true },
  "no epss or exploits": { no_epss: true, no_exploits: true },
  "no kev or exploits": { no_kev: true, no_exploits: true },
  "likelihood flag": { likelihood: true },
  "likelihood config": { likelihood_config: "rules.json" },
  "gate malicious": { fail_on: "malicious" },
  "gate kev": { fail_on: "kev" },
  "gate act": { fail_on: "act" },
  "gate critical": { fail_on: "critical" },
  "reachability, trivy": { reachability: true, scanners: "trivy" },
  "sbom, trivy": { sbom: true, scanners: "trivy" },
  "imported grype": { from_grype_json: "g.json" },
};

function compute() {
  const out = {};
  for (const [kind, base] of Object.entries(KINDS)) {
    for (const [name, extra] of Object.entries(VARIANTS)) {
      const { __what, ...values } = { ...base, ...extra, out: "r" };
      const s = { command: "scan", what: __what, values };
      const groups = w.summary(data, wizard, s);
      out[`${kind} | ${name}`] = groups.flatMap((g) => g.items.map((i) => `${g.head}: ${i}`));
    }
  }
  return out;
}

test("the summaries match tests/fixtures/wizard_summaries.json", () => {
  const path = join(ROOT, "tests", "fixtures", "wizard_summaries.json");
  const got = compute();
  if (process.env.UPDATE_SUMMARIES) writeFileSync(path, `${JSON.stringify(got, null, 1)}\n`);
  const want = JSON.parse(readFileSync(path, "utf8"));
  for (const k of Object.keys(got)) assert.deepEqual(got[k], want[k], k);
  assert.deepEqual(Object.keys(got), Object.keys(want));
});
