// Each rules.json rule flags its own example (the example tests/test_builder.py runs through the CLI), and
// nothing else in rules.json is malformed.
import assert from "node:assert/strict";
import { test } from "node:test";

import * as b from "../../site/builder/builder.js";
import { data, groups, rules } from "./helpers.mjs";

const fill = (a) => a.replaceAll("{out}", "out").replaceAll("{file}", "report.json");

for (const r of rules.rules) {
  test(`rule ${r.id} flags its example`, () => {
    const state = b.stateFromArgs(data, r.command, r.args.map(fill));
    assert.ok(b.problems(data, rules, state).some((p) => p.rule === r.id), JSON.stringify(state));
  });
}

for (const f of rules.fields) {
  test(`field ${f.dest} (${f.message}) accepts its valid and refuses its invalid examples`, () => {
    const o = b.optionsFor(data, f.command).find((x) => x.dest === f.dest);
    const v = (x) => (o.kind === "repeatable" ? [x] : x);
    for (const x of f.valid) assert.deepEqual(b.fieldErrors(o, v(x), { fields: [f] }, f.command), [], x);
    for (const x of f.invalid) assert.notDeepEqual(b.fieldErrors(o, v(x), { fields: [f] }, f.command), [], x);
  });
}

test("an unknown condition in rules.json is an error, not a silent no-match", () => {
  assert.throws(() => b.holds({ sett: "image" }, [], {}), /unknown condition/);
});

test("presets produce commands with no problems", () => {
  for (const p of groups.presets) {
    const state = { command: p.command, values: p.values };
    assert.deepEqual(b.problems(data, rules, state), [], p.name);
  }
});
