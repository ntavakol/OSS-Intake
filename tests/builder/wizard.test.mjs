// The guided wizard: each golden answer set walks through every step and builds its command, and "What this
// command will do" says what the command does, and only that.
import assert from "node:assert/strict";
import { test } from "node:test";

import * as b from "../../site/builder/builder.js";
import * as w from "../../site/builder/wizard.js";
import { data, rules, wizard, wizardGolden } from "./helpers.mjs";

function answer(c) {
  let s = w.choose(wizard, { command: "scan", values: {} }, c.what);
  s = w.setOutcome(s, c.outcome);
  Object.assign(s.values, structuredClone(c.values));
  for (const g of c.gates ?? []) s = w.toggleGate(wizard, s, g, true);
  return s;
}

const text = (s) => w.summary(data, wizard, s).flatMap((g) => g.items.map((i) => `${g.head}: ${i}`)).join("\n");

test("each golden answer set passes every step and builds its command", () => {
  for (const c of wizardGolden) {
    const s = answer(c);
    for (const step of [0, 1, 2, 3]) assert.deepEqual(w.stepProblems(data, rules, wizard, s, step), [], `${c.name}, step ${step}`);
    assert.equal(b.buildCommand(data, s), c.bash, c.name);
    for (const d of Object.keys(s.values)) assert.ok(w.offered(wizard, c.what).includes(d), `${c.name}: ${d} not offered`);
  }
});

test("a step cannot be left while it is incomplete", () => {
  const s = w.choose(wizard, { command: "scan", values: {} }, "lockfile");
  assert.deepEqual(w.stepProblems(data, rules, wizard, { command: "scan", values: {} }, 0).length, 1);
  assert.equal(w.stepProblems(data, rules, wizard, s, 1)[0].dest, "path");
  s.values.path = "package-lock.json";
  s.values.repo = "not a repo";
  assert.equal(w.stepProblems(data, rules, wizard, s, 1)[0].dest, "repo");
  delete s.values.repo;
  const gate = w.setOutcome(s, "gate");
  assert.match(w.stepProblems(data, rules, wizard, gate, 2)[0].message, /at least one/);
  gate.values.out = "";
  assert.ok(w.stepProblems(data, rules, wizard, gate, 2).some((p) => p.dest === "out"));
});

test("gates keep wizard.json's order, and a report drops them", () => {
  let s = w.setOutcome(w.choose(wizard, { command: "scan", values: {} }, "lockfile"), "gate");
  for (const g of ["high", "malicious", "kev"]) s = w.toggleGate(wizard, s, g, true);
  assert.equal(s.values.fail_on, "malicious,kev,high");
  s = w.toggleGate(wizard, s, "kev", false);
  assert.equal(s.values.fail_on, "malicious,high");
  s.values.fail_on_likelihood = "4";
  const r = w.setOutcome(s, "report");
  assert.equal(r.values.fail_on, undefined);
  assert.equal(r.values.fail_on_likelihood, undefined);
});

test("a new first answer keeps what still applies and drops the rest", () => {
  const s = { command: "scan", values: { path: "a.jar", repo: "owner/x", out: "o", fail_on: "malicious,mismatch" } };
  const img = w.choose(wizard, s, "image");
  assert.deepEqual(img.values, { repo: "owner/x", out: "o", fail_on: "malicious" });
  const repo = w.choose(wizard, s, "repo");
  assert.deepEqual(repo.values, { repo: "owner/x", out: "o" });
});

test("the summary for the extension example says what it checks, contacts and leaves out", () => {
  const t = text(answer(wizardGolden[0]));
  assert.match(t, /Checks: the dependency list ~\/Downloads\/vscode-extension\/package-lock\.json/);
  assert.match(t, /Also checks: owner\/vscode-extension on GitHub/);
  assert.match(t, /Fails: with exit code 3 if the suggested likelihood is 4 or higher/);
  assert.match(t, /Contacts: OSV: sends package names and versions/);
  assert.match(t, /Contacts: GitHub: sends the repository name/);
  assert.match(t, /Doesn't check: the project's own code/);
  assert.doesNotMatch(t, /exit code 1/);  // only --fail-on gates fail on a check that could not run
});

test("offline contacts nothing itself, and says what that leaves out", () => {
  const s = { command: "scan", values: { image: "owner/app:1.2.3", offline: true, out: "r" } };
  const t = text(s);
  assert.doesNotMatch(t, /Contacts: (OSV|deps\.dev|GitHub|CISA|FIRST)/);
  assert.match(t, /Contacts: nothing itself/);
  assert.match(t, /with Trivy, plus Grype/);
  assert.match(t, /Doesn't check: anything that needs the network/);
});

test("turning a check off moves it from what is checked to what is not", () => {
  const base = { command: "scan", values: { path: "a.jar", repo: "o/n", out: "r" } };
  assert.match(text(base), /Contacts: OpenSSF Scorecard/);
  assert.match(text(base), /Contacts: Maven Central, PyPI or npm/);
  const off = { command: "scan", values: { ...base.values, no_scorecard: true, no_registry_check: true } };
  assert.doesNotMatch(text(off), /OpenSSF Scorecard: sends|Maven Central, PyPI or npm/);
  assert.match(text(off), /Doesn't check: the OpenSSF Scorecard \(turned off\)/);
});

test("a gate's summary names what fails, in plain words", () => {
  const s = answer(wizardGolden[5]);
  assert.match(text(s), /exit code 3 if it finds a package known to be malware or a package version published in the last 7 days/);
});

test("every summary and service condition uses known operators, for every first answer", () => {
  for (const t of wizard.targets) {
    const s = { command: "scan", what: t.id, values: {} };
    assert.doesNotThrow(() => w.summary(data, wizard, s), t.id);
  }
});

test("the form's command is summarised too, reading the first answer from its options", () => {
  assert.equal(w.whatOf(wizard, { command: "scan", values: { path: "x" } }), "path");
  assert.equal(w.whatOf(wizard, { command: "scan", values: { image: "a:1", repo: "o/n" } }), "image");
  assert.equal(w.whatOf(wizard, { command: "verify", values: {} }), null);
  assert.match(text({ command: "scan", values: { path: "x", out: "r" } }), /Checks: x: a lockfile, file or folder/);
});

test("a link carries the view and the first answer, and nothing else unknown", () => {
  const s = answer(wizardGolden[0]);
  const back = b.fromFragment(data, b.toFragment(data, s, "bash", { what: "lockfile" }));
  assert.equal(back.extra.what, "lockfile");
  assert.equal(b.buildCommand(data, back.state), wizardGolden[0].bash);
  assert.deepEqual(b.fromFragment(data, "view=form&what=<b>&cmd=scan").extra, { view: "form" });
});

test("the wizard's answer gives way when the form changes the options under it", () => {
  const s = { command: "scan", what: "lockfile", values: { path: "package-lock.json", out: "r" } };
  assert.equal(w.whatOf(wizard, s), "lockfile");
  assert.equal(w.whatOf(wizard, { ...s, values: { image: "a:1", out: "r" } }), "image");
  assert.equal(w.whatOf(wizard, { ...s, values: { out: "r" } }), "lockfile");  // not answered yet: still asking
  assert.equal(w.whatOf(wizard, { ...s, what: "package", values: { package: ["npm:a@1"] } }), "package");
});

// ---------------------------------------------------------------- after review

const OPS = new Set(["all", "any", "not", "set", "none", "has", "lt", "eq", "what"]);
const KINDS = new Set([...wizard.targets.map((t) => t.id), "path", "renv"]);
const DESTS = new Set(data.commands.scan.options.map((o) => o.dest));

function checkCond(cond, where) {
  const keys = Object.keys(cond);
  assert.equal(keys.length, 1, `${where}: one operator per condition`);
  const [op, arg] = [keys[0], cond[keys[0]]];
  assert.ok(OPS.has(op), `${where}: unknown operator ${op}`);
  if (op === "all" || op === "any") { assert.ok(Array.isArray(arg) && arg.length); arg.forEach((c) => checkCond(c, where)); }
  else if (op === "not") checkCond(arg, where);
  else if (op === "set") assert.ok(DESTS.has(arg), `${where}: ${arg}`);
  else if (op === "none") arg.forEach((d) => assert.ok(DESTS.has(d), `${where}: ${d}`));
  else if (op === "what") arg.forEach((k) => assert.ok(KINDS.has(k), `${where}: kind ${k}`));
  else { assert.ok(DESTS.has(arg[0]), `${where}: ${arg[0]}`); assert.equal(arg.length, 2); }
}

test("every condition in wizard.json is well formed, down to each leaf", () => {
  for (const [name, list] of [["summary", wizard.summary], ["services", wizard.services], ["scanner_notes", wizard.scanner_notes],
    ["privacy_notes", wizard.privacy_notes], ["kind_rules", wizard.kind_rules], ["kind_cautions", wizard.kind_cautions]]) {
    list.forEach((x, i) => checkCond(x.when, `${name}[${i}]`));
  }
  for (const line of wizard.summary) {
    for (const [, d] of line.text.matchAll(/\{([a-z_]+)\}/g)) assert.ok(DESTS.has(d) || d === "malware", `{${d}} in "${line.text}"`);
  }
});

test("the kind of input follows the file name where the CLI decides by name", () => {
  const k = (what, path) => w.kindOf(wizard, { command: "scan", what, values: { path } });
  assert.equal(k("lockfile", "x/renv.lock"), "renv");
  assert.equal(k("lockfile", "packages.CSV"), "inventory");
  assert.equal(k("lockfile", "app.jar"), "artifact");
  assert.equal(k("artifact", "go.sum"), "lockfile");
  assert.equal(k("inventory", "sbom.json"), "inventory");
  assert.equal(k(null, "~/x/package-lock.json"), "lockfile");
  assert.equal(k(null, "build"), "path");
  assert.match(text({ command: "scan", what: "lockfile", values: { path: "renv.lock", out: "r" } }), /CRAN packages/);
  assert.doesNotMatch(text({ command: "scan", what: "lockfile", values: { path: "renv.lock", out: "r" } }), /Trivy|raw/);
});

function argsState(args) {
  const names = { "{lockfile}": "package-lock.json", "{csv}": "packages.csv", "{renv}": "renv.lock", "{jar}": "app.jar", "{out}": "r" };
  return b.stateFromArgs(data, "scan", args.map((a) => names[a] ?? a));
}

test("each kind rule fires on its examples and stays quiet on the nearest accepted commands", () => {
  for (const r of [...wizard.kind_rules, ...wizard.kind_cautions]) {
    for (const args of [r.args, ...(r.more_args ?? [])]) {
      assert.ok(w.kindProblems(data, wizard, argsState(args)).some((p) => p.message === r.message), `${r.id}: ${args}`);
    }
    for (const args of [r.ok_args, ...(r.more_ok_args ?? [])].filter(Boolean)) {
      assert.ok(!w.kindProblems(data, wizard, argsState(args)).some((p) => p.message === r.message), `${r.id} ok: ${args}`);
    }
  }
});

test("passing over answers, or picking the same one again, changes nothing", () => {
  let s = w.choose(wizard, { command: "scan", values: {} }, "lockfile");
  s.values.path = "pkg/package-lock.json";
  s.values.repo = "o/n";
  for (const what of ["image", "artifact"]) s = w.choose(wizard, s, what);
  assert.equal(b.buildCommand(data, s), "oss-intake --path pkg/package-lock.json --repo o/n --out report");
  const formSet = { command: "scan", what: "image", values: { image: "a/b:1", no_kev: true, fail_on: "high", out: "r" } };
  assert.equal(w.choose(wizard, formSet, "image"), formSet);
  assert.equal(w.choose(wizard, formSet, "lockfile").values.no_kev, true);  // set in All options: kept
  const link = { command: "scan", values: { path: "x.jar", offline: true, scanners: "trivy", out: "r" } };
  assert.equal(b.buildCommand(data, w.choose(wizard, link, "artifact")), "oss-intake --path x.jar --out r --scanners trivy --offline");
});

test("a gate set anywhere makes the answer a pass or fail check", () => {
  assert.equal(w.outcomeOf({ outcome: "report", values: { fail_on: "high" } }), "gate");
  assert.equal(w.outcomeOf({ outcome: "gate", values: {} }), "gate");
  assert.equal(w.outcomeOf({ values: {} }), "report");
});

// What each command contacts and how it fails, exactly: a wrong condition in wizard.json changes one of these.
const services = (s) => wizard.services.filter((x) => b.holds(x.when, b.optionsFor(data, "scan"), s.values, { what: w.kindOf(wizard, s) })).map((x) => x.name.split(" ")[0]);
const fails = (s) => w.summary(data, wizard, s).find((g) => g.head === "Fails")?.items ?? [];
const S = (values, what) => ({ command: "scan", what, values: { out: "r", ...values } });

test("contacts, table-driven", () => {
  const cases = [
    [S({ path: "package-lock.json" }), ["OSV", "deps.dev", "CISA", "FIRST", "Exploit", "Fix-date"]],
    [S({ path: "package-lock.json", repo: "o/n" }), ["OSV", "deps.dev", "GitHub", "OpenSSF", "CISA", "FIRST", "Exploit", "Fix-date"]],
    [S({ path: "package-lock.json", offline: true }), []],
    [S({ path: "package-lock.json", no_kev: true, no_epss: true, no_exploits: true, no_fix_dates: true, release_age_days: "0" }), ["OSV"]],
    [S({ path: "package-lock.json", scanners: "trivy", no_fix_dates: true, release_age_days: "0" }), ["CISA", "FIRST", "Exploit"]],
    [S({ path: "app.jar" }, "artifact"), ["OSV", "deps.dev", "Maven", "CISA", "FIRST", "Exploit", "Fix-date"]],
    [S({ path: "app.jar", no_registry_check: true }, "artifact"), ["OSV", "deps.dev", "CISA", "FIRST", "Exploit", "Fix-date"]],
    [S({ package: ["npm:a@1"] }), ["OSV", "deps.dev", "CISA", "FIRST", "Exploit", "Fix-date"]],
    [S({ package: ["npm:a@1"], no_fix_dates: true, release_age_days: "0", no_latest: true }), ["OSV", "CISA", "FIRST", "Exploit"]],
    [S({ repo: "o/n" }, "repo"), ["GitHub", "OpenSSF"]],
    [S({ repo: "o/n", no_scorecard: true }, "repo"), ["GitHub"]],
  ];
  for (const [s, want] of cases) assert.deepEqual(services(s), want, JSON.stringify(s.values));
});

test("fails, table-driven", () => {
  const cases = [
    [S({ path: "package-lock.json" }), ["never on what it finds: it exits 0 when "]],
    [S({ path: "package-lock.json", fail_on: "high" }), ["with exit code 3 if it finds a high or cr", "with exit code 1, rather than passing, if"]],
    [S({ path: "a.jar", fail_on: "mismatch" }, "artifact"), ["with exit code 3 if it finds a file that ", "with exit code 1, rather than passing", "The checksum gate compares a JAR, wheel"]],
    [S({ path: "package-lock.json", fail_on_likelihood: "4" }), ["with exit code 3 if the suggested likeli"]],
  ];
  for (const [s, want] of cases) {
    const got = fails(s);
    assert.equal(got.length, want.length, JSON.stringify(got));
    want.forEach((start, i) => assert.ok(got[i].startsWith(start), `${got[i]} / ${start}`));
  }
});

test("sentences that depend on the input appear only for inputs they are true of", () => {
  assert.doesNotMatch(text(S({ path: "a.jar", sbom: true }, "artifact")), /CycloneDX SBOM from Trivy/);
  assert.match(text(S({ image: "a/b:1", sbom: true })), /CycloneDX SBOM from Trivy/);
  assert.doesNotMatch(text(S({ package: ["npm:a@1"], reachability: true })), /govulncheck/);
  assert.match(text(S({ package: ["npm:a@1"], reachability: true })), /whether the vulnerable code is reachable/);
  assert.match(text(S({ path: "package-lock.json", scanners: "trivy" })), /Malware is seen only in advisories/);
  assert.doesNotMatch(text(S({ path: "package-lock.json", scanners: "trivy" })), /vulnerabilities and malware/);
  assert.match(text(S({ image: "a/b:1" })), /pull the image from its registry/);
  assert.match(text(S({ repo: "o/n" }, "repo")), /GITHUB_TOKEN/);
});

test("set-aside gates come back as they were, and a report drops them", () => {
  let s = w.setOutcome(w.choose(wizard, { command: "scan", values: {} }, "artifact"), "gate");
  s.values.path = "a.jar";
  for (const g of ["high", "mismatch"]) s = w.toggleGate(wizard, s, g, true);
  s = w.choose(wizard, w.choose(wizard, s, "image"), "artifact");  // scenario A
  assert.equal(s.values.fail_on, "high,mismatch");
  s = w.toggleGate(wizard, s, "high", false);
  s = w.choose(wizard, w.choose(wizard, s, "image"), "artifact");  // scenario B
  assert.equal(s.values.fail_on, "mismatch");
  s = w.toggleGate(wizard, s, "high", true);
  s = w.setOutcome(w.choose(wizard, s, "lockfile"), "report");  // scenario C
  assert.equal(w.choose(wizard, s, "image").values.fail_on, undefined);
  assert.equal(w.outcomeOf(w.choose(wizard, s, "artifact")), "report");
});

test("renv.lock is not offered gates it can never check", () => {
  const s = { command: "scan", what: "lockfile", values: { path: "renv.lock", out: "r" } };
  assert.deepEqual(w.gatesFor(data, wizard, s), ["malicious", "kev", "act", "critical", "high"]);
  assert.equal(w.gatesFor(data, wizard, { ...s, values: { path: "package-lock.json" } }).length, 7);
});

// Each branch of each condition, both ways: [state, phrases that must appear, phrases that must not].
const F = (values, what) => ({ command: "scan", what, values: { out: "r", ...values } });
const LOCK = { path: "package-lock.json" };
const facts = [
  // OSV: used by scanners, by fix-date lookups, and always for package lists.
  [F({ ...LOCK, scanners: "trivy" }), ["OSV: sends"], []],
  [F({ ...LOCK, scanners: "trivy", no_fix_dates: true }), [], ["OSV: sends"]],
  [F({ package: ["npm:a@1"], no_fix_dates: true }), ["OSV: sends"], []],
  // deps.dev: fix dates, release ages (with a package list) and latest versions (package lists).
  [F({ ...LOCK, no_fix_dates: true }), ["deps.dev: sends"], []],
  [F({ ...LOCK, no_fix_dates: true, release_age_days: "0" }), [], ["deps.dev: sends"]],
  [F({ ...LOCK, scanners: "grype", no_fix_dates: true }), [], ["deps.dev: sends", "any language package version"]],
  [F({ package: ["npm:a@1"], no_fix_dates: true, release_age_days: "0" }), ["deps.dev: sends"], []],
  [F({ path: "renv.lock" }), ["R packages are not looked up"], ["deps.dev: sends", "Fix-date", "any language package version", "when each fix was published"]],
  // GitHub and the services that need the network.
  [F({ ...LOCK, repo: "o/n", offline: true }), ["o/n: offline skips GitHub"], ["GitHub: sends", "OpenSSF Scorecard: sends", "CISA"]],
  [F({ ...LOCK, repo: "o/n" }), ["GitHub: sends the repository name, and your GITHUB_TOKEN", "its release dates"], []],
  [F({ repo: "o/n" }, "repo"), ["its releases and how often"], ["its release dates", "OSV: sends"]],
  [F({ path: "a.jar", offline: true }, "artifact"), [], ["Maven Central", "A JAR, wheel, sdist or npm .tgz is also compared"]],
  // Fails.
  [F({ ...LOCK, fail_on: "unknown-age" }), ["with exit code 1, rather than passing"], []],
  [F({ path: "a.jar", fail_on: "mismatch" }, "artifact"), ["a failed lookup), the gate exits 1", "with exit code 1, rather than passing"], ["never fails here"]],
  [F({ image: "a/b:1", fail_on: "mismatch" }), ["never fails here"], ["with exit code 1, rather than passing", "The checksum gate compares"]],
  // Writes.
  [F({ image: "a/b:1", sbom: true, from_trivy_json: "t.json" }), [], ["CycloneDX SBOM"]],
  [F({ image: "a/b:1", sbom: true, scanners: "grype" }), [], ["CycloneDX SBOM"]],
  [F({ image: "a/b:1", from_trivy_json: "t.json", from_grype_json: "g.json" }), [], ["own output goes in", "download their vulnerability databases", "pull the image"]],
  [F({ image: "a/b:1", from_trivy_json: "t.json" }), ["own output goes in", "pull the image"], []],
  // Reachability needs a Trivy report and a binary.
  [F({ ...LOCK, reachability: true }), ["whether the vulnerable code is reachable"], ["govulncheck"]],
  [F({ image: "a/b:1", reachability: true, scanners: "grype" }), ["whether the vulnerable code is reachable"], ["govulncheck"]],
  [F({ image: "a/b:1", reachability: true }), ["Go binaries with govulncheck", "vuln.go.dev"], ["whether the vulnerable code is reachable"]],
  // Notes.
  [F({ image: "a/b:1" }), ["pull the image"], ["pom.xml"]],
  [F({ path: "build" }), ["pom.xml", "Apart from what the scanners fetch"], []],
  [F({ ...LOCK, scanners: "grype" }), [], ["pom.xml"]],
  [F({ path: "packages.csv" }, "inventory"), ["The file is read on your computer"], ["Apart from what the scanners fetch", "download their vulnerability databases"]],
  [F({ ...LOCK, offline: true }), ["Malware is seen only", "with Trivy, plus Grype"], ["OSV: sends", "vulnerabilities and malware"]],
  [F(LOCK), ["vulnerabilities and malware"], ["Malware is seen only"]],
];

test("each condition branch, both ways", () => {
  for (const [s, yes, no] of facts) {
    const t = text(s);
    for (const p of yes) assert.ok(t.includes(p), `${JSON.stringify(s.values)} should say "${p}"\n${t}`);
    for (const p of no) assert.ok(!t.includes(p), `${JSON.stringify(s.values)} should not say "${p}"\n${t}`);
  }
});

test("every first answer has an icon, and the Contacts group carries the services it lists", async () => {
  const { ICONS } = await import("../../site/builder/dom.js");
  for (const t of wizard.targets) assert.ok(ICONS[t.icon], `${t.id}: icon ${t.icon}`);
  const g = w.summary(data, wizard, { command: "scan", values: { path: "package-lock.json", repo: "o/n", out: "r" } })
    .find((x) => x.head === "Contacts");
  assert.deepEqual(g.services.map((s) => s.name), ["OSV", "deps.dev", "GitHub", "OpenSSF Scorecard", "CISA KEV", "FIRST EPSS",
    "Exploit indexes", "Fix-date records"]);
  for (const s of g.services) assert.ok(g.items.some((i) => i.includes(s.sends)), s.name);  // the text says the same
  assert.deepEqual(g.notes, g.items.slice(g.services.length));
});
