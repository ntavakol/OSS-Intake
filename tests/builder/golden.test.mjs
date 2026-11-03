// builder.js must turn each golden state into exactly the commands in tests/fixtures/builder_golden.json.
// tests/test_builder.py checks the same commands are valid oss-intake input.
import assert from "node:assert/strict";
import { test } from "node:test";

import * as b from "../../site/builder/builder.js";
import { data, golden, rules } from "./helpers.mjs";

for (const c of golden.filter((x) => !x.invalid)) {
  test(`golden: ${c.name}`, () => {
    assert.deepEqual(b.problems(data, rules, c.state), []);
    assert.deepEqual(b.buildArgs(data, c.state), c.args);
    assert.equal(b.buildCommand(data, c.state, "bash"), c.bash);
    assert.equal(b.buildCommand(data, c.state, "powershell"), c.powershell);
  });
}

for (const c of golden.filter((x) => x.invalid)) {
  test(`golden, refused: ${c.name}`, () => {
    const got = [...new Set(b.problems(data, rules, c.state).map((p) => p.rule ?? p.dest))].sort();
    assert.deepEqual(got, c.problems);
  });
}

test("args round-trip through stateFromArgs", () => {
  for (const c of golden.filter((x) => !x.invalid)) {
    const args = c.state.command === "scan" ? c.args : c.args.slice(1);
    const back = b.stateFromArgs(data, c.state.command, args);
    assert.deepEqual(b.buildArgs(data, back), c.args, c.name);
  }
});
