// oss-intake command builder: the wizard's logic and "What this command will do", with no DOM access, so Node
// can test it (tests/builder/wizard.test.mjs). The wizard's answers are ordinary builder state (option values),
// so builder.js makes and checks the command exactly as it does for the full form.
import * as b from "./builder.js";

export const STEPS = ["What are you checking?", "Details", "What do you want back?", "Review"];

const SCAN = "scan";
const ALWAYS = ["out"];  // offered whatever the first answer

export function target(wiz, what) {
  return wiz.targets.find((t) => t.id === what) ?? null;
}

/** The wizard's first answer for a state: as given when the wizard set it, otherwise read from the options (the
 * full form, or a link): "path" when a --path is given, since its kind depends on the file. */
export function whatOf(wiz, state) {
  if (state.command !== SCAN) return null;
  const inferred = inferWhat(state);
  const t = state.what ? target(wiz, state.what) : null;
  // The wizard's answer stands while the options still fit it: the full form may have changed them since.
  if (t && (inferred === null || inferred === t.id || (inferred === "path" && t.fields.includes("path")))) return t.id;
  return inferred;
}

function inferWhat(state) {
  const v = state.values ?? {};
  const given = (d) => (Array.isArray(v[d]) ? v[d].some((x) => String(x).trim()) : String(v[d] ?? "").trim() !== "");
  if (given("image")) return "image";
  if (given("path")) return "path";
  if (given("package")) return "package";
  if (given("repo")) return "repo";
  return null;
}

/** The kind of input oss-intake will see, for "What this command will do" and the checks that depend on it:
 * the first answer, corrected by the file name where the CLI decides by name (inputs.classify): renv.lock, a .csv
 * package list, or a lockfile name. An SBOM is told by its content, so the answer "SBOM or package list" stands. */
export function kindOf(wiz, state) {
  const what = whatOf(wiz, state);
  if (!["lockfile", "artifact", "inventory", "path"].includes(what)) return what;
  const name = String(state.values?.path ?? "").trim().split(/[\\/]/).pop();
  if (!name) return what;
  if (name === "renv.lock") return "renv";
  if (name.toLowerCase().endsWith(".csv")) return "inventory";
  if (new RegExp(wiz.lockfile_names).test(name)) return "lockfile";
  if (what === "inventory") return what;
  // Neither an SBOM nor a folder: a file the CLI scans as an artifact. Unasked, only a name that says so counts.
  if (what === "path" && !/\.(jar|war|ear|whl|tgz|zip|exe|dll|so|tar\.gz)$/i.test(name)) return what;
  return "artifact";
}

/** The options the wizard offers for a first answer, in the order it asks for them. */
export function offered(wiz, what) {
  const t = target(wiz, what);
  if (!t) return [];
  const out = [...t.fields];
  if (t.repo) out.push("repo");
  out.push(...ALWAYS);
  if (t.gates.length) out.push("fail_on");
  out.push("fail_on_likelihood");
  return out;
}

/** A new first answer. Options only the guided steps ask for (the input fields, the GitHub project, gates) that
 * the new answer does not offer are set aside, not lost: going back to an answer that offers them brings them
 * back, so passing over answers with the arrow keys changes nothing. Options set in All options are kept. */
export function choose(wiz, state, what) {
  if (what === state.what) return state;
  const t = target(wiz, what);
  const keep = new Set(offered(wiz, what));
  const guided = new Set(wiz.targets.flatMap((x) => offered(wiz, x.id)));
  const values = {};
  const aside = { ...(state.aside ?? {}) };
  // Gates: the ones ticked now plus the ones set aside, split into those this answer offers and the rest.
  const all = new Set([...gatesOf(state.values?.fail_on), ...gatesOf(aside.fail_on)]);
  const order = wiz.gates.map((g) => g.id).filter((g) => all.has(g));
  const here = order.filter((g) => t.gates.includes(g));
  const away = order.filter((g) => !t.gates.includes(g));
  if (here.length) values.fail_on = here.join(",");
  if (away.length) aside.fail_on = away.join(","); else delete aside.fail_on;
  for (const [d, v] of Object.entries(state.values ?? {})) {
    if (d === "fail_on") continue;
    if (keep.has(d) || !guided.has(d)) values[d] = v;
    else aside[d] = v;
  }
  for (const d of keep) {
    if (d !== "fail_on" && values[d] === undefined && aside[d] !== undefined) {
      values[d] = aside[d];
      delete aside[d];
    }
  }
  if (!values.out) values.out = "report";
  return { command: SCAN, what, outcome: state.outcome, values, aside };
}

export function gatesOf(value) {
  return String(value ?? "").split(",").map((x) => x.trim().toLowerCase()).filter(Boolean);
}

/** Tick or untick one gate, keeping wizard.json's order so the command does not depend on click order. */
export function toggleGate(wiz, state, id, on) {
  const now = new Set(gatesOf(state.values.fail_on));
  if (on) now.add(id); else now.delete(id);
  const value = wiz.gates.map((g) => g.id).filter((g) => now.has(g)).join(",");
  return { ...state, values: { ...state.values, fail_on: value } };
}

/** "A report" or "a pass or fail check": always the latter when a gate is set, whoever set it. */
export function outcomeOf(state) {
  const v = state.values ?? {};
  if (String(v.fail_on ?? "").trim() || String(v.fail_on_likelihood ?? "").trim()) return "gate";
  return state.outcome ?? "report";
}

export function setOutcome(state, outcome) {
  const values = { ...state.values };
  const aside = { ...(state.aside ?? {}) };
  if (outcome === "report") {  // a report has no gates, including any set aside by an earlier answer
    for (const d of ["fail_on", "fail_on_likelihood"]) { delete values[d]; delete aside[d]; }
  }
  return { ...state, outcome, values, aside };
}

/** Checks the CLI makes that depend on the kind of file (wizard.json "kind_rules"): rules.json leaves them out,
 * since the full form does not know the kind, but the wizard does. */
export function kindProblems(data, wiz, state) {
  const options = b.optionsFor(data, SCAN);
  const ctx = { what: kindOf(wiz, state) };
  // kind_rules: what the CLI refuses (exit 2). kind_cautions: gates that could only ever fail (exit 1), since
  // the check they need never runs for that kind; a CI gate like that is a mistake, so it is refused here too.
  return [...wiz.kind_rules, ...wiz.kind_cautions].filter((r) => b.holds(r.when, options, state.values ?? {}, ctx))
    .map((r) => ({ rule: r.id, dest: r.dest, message: r.message }));
}

/** The gates the wizard offers: the answer's, less those the kind of file can never check (kind_cautions). */
export function gatesFor(data, wiz, state) {
  const t = target(wiz, whatOf(wiz, state));
  if (!t) return [];
  const options = b.optionsFor(data, SCAN);
  const ctx = { what: kindOf(wiz, state) };
  return t.gates.filter((g) => !wiz.kind_cautions.some((r) =>
    b.holds(r.when, options, { ...state.values, fail_on: g }, ctx)));
}

/** Problems that stop the wizard leaving a step: the step's own fields, and on the last step everything. */
export function stepProblems(data, rules, wiz, state, step) {
  const what = whatOf(wiz, state);
  if (step === 0) return what ? [] : [{ message: "pick what you are checking" }];
  const all = [...b.problems(data, rules, state), ...kindProblems(data, wiz, state)];
  if (step === 3) return all;
  const t = target(wiz, what);
  const here = step === 1 ? [...t.fields, ...(t.repo ? ["repo"] : [])] : ["out", "fail_on", "fail_on_likelihood"];
  const out = all.filter((p) => here.includes(p.dest));
  const options = b.optionsFor(data, SCAN);
  const set = (d) => b.isSet(options.find((o) => o.dest === d), state.values?.[d]);
  if (step === 1 && !set(t.fields[0])) out.push({ dest: t.fields[0], message: `${wiz.fields[t.fields[0]].label} is needed` });
  if (step === 2 && outcomeOf(state) === "gate" && !set("fail_on") && !set("fail_on_likelihood")) {
    out.push({ dest: "fail_on", message: "pick at least one thing to fail on" });
  }
  return out;
}

// ---------------------------------------------------------------- What this command will do

function joinWords(xs) {
  return xs.length <= 1 ? (xs[0] ?? "") : `${xs.slice(0, -1).join(", ")} or ${xs.at(-1)}`;
}

function joinAnd(xs) {
  return xs.length <= 1 ? (xs[0] ?? "") : `${xs.slice(0, -1).join(", ")} and ${xs.at(-1)}`;
}

const SCANNER_NAMES = { trivy: "Trivy", grype: "Grype", osv: "OSV" };
const FILES = { md: "summary.md", json: "assessment.json", html: "report.html" };

function valueOrDefault(options, values, dest) {
  const o = options.find((x) => x.dest === dest);
  const v = values[dest];
  if (Array.isArray(v)) return v.map((x) => String(x).trim()).filter(Boolean);
  const text = String(v ?? "").trim();
  return text === "" ? (o?.default ?? "") : text;
}

/** Text for one {dest} in a summary sentence. */
function word(data, wiz, values, dest) {
  const options = b.optionsFor(data, SCAN);
  const v = valueOrDefault(options, values, dest);
  if (dest === "scanners") {
    const xs = b.isSet(options.find((o) => o.dest === "scanners"), values.scanners) ? gatesOf(v) : ["auto"];
    if (xs.includes("auto")) {
      return values.offline === true ? "Trivy, plus Grype if it is installed" : "Trivy and OSV, plus Grype if it is installed";
    }
    return joinAnd(xs.map((x) => SCANNER_NAMES[x] ?? x));
  }
  if (dest === "fail_on") {
    return joinWords(gatesOf(v).map((g) => fill(data, wiz, values,
      wiz.gates.find((x) => x.id === g)?.summary ?? g)));
  }
  if (dest === "malware") {  // used only in the sentences for scanner runs
    const xs = gatesOf(values.scanners);
    const osv = !b.isSet(options.find((o) => o.dest === "scanners"), values.scanners) || xs.includes("osv") || xs.includes("auto");
    return values.offline !== true && osv ? " and malware" : "";
  }
  if (dest === "formats") {
    const fs = gatesOf(v).filter((f) => f !== "csv").map((f) => FILES[f] ?? f);
    return joinAnd(["findings.csv", ...fs]);
  }
  return Array.isArray(v) ? joinAnd(v) : String(v);
}

function fill(data, wiz, values, text) {
  return text.replace(/\{([a-z_]+)\}/g, (_, d) => word(data, wiz, values, d));
}

/** "What this command will do": [{ head, items: [sentence] }], in wizard.json's order, then what it contacts.
 * Built from the options, so it describes the full form's command too. */
export function summary(data, wiz, state) {
  if (state.command !== SCAN) return [];
  const options = b.optionsFor(data, SCAN);
  const values = state.values ?? {};
  const what = kindOf(wiz, state);
  if (!what) return [];
  const ctx = { what };
  const heads = [];
  const byHead = new Map();
  const add = (head, text) => {
    if (!byHead.has(head)) { byHead.set(head, []); heads.push(head); }
    byHead.get(head).push(text);
  };
  for (const line of wiz.summary) {
    if (b.holds(line.when, options, values, ctx)) add(line.head, fill(data, wiz, values, line.text));
  }
  const used = wiz.services.filter((s) => b.holds(s.when, options, values, ctx));
  const contacts = used.map((s) => `${s.name}${s.if_found ? ", if it finds vulnerabilities" : ""}: sends ${s.sends}.`);
  const scannerNotes = wiz.scanner_notes.filter((n) => b.holds(n.when, options, values, ctx)).map((n) => n.text);
  if (!contacts.length) contacts.push(scannerNotes.length ? "nothing itself." : "nothing.");
  contacts.push(...scannerNotes);
  contacts.push(...wiz.privacy_notes.filter((n) => b.holds(n.when, options, values, ctx)).map((n) => n.text));
  const order = [...heads];
  const at = order.indexOf("Doesn't check");
  order.splice(at < 0 ? order.length : at, 0, "Contacts");
  byHead.set("Contacts", contacts);
  return order.map((head) => ({ head, items: byHead.get(head) }));
}

/** One line per argument of the command, for the review step: the flag and what it does (its --help text). */
export function explain(data, state) {
  const options = b.optionsFor(data, state.command);
  const values = state.values ?? {};
  return options.filter((o) => b.isSet(o, values[o.dest])).map((o) => ({ flag: o.flag, help: o.help }));
}
