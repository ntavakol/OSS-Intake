// The URL fragment: a round trip keeps the state, and a hostile link is reduced to known options as text.
import assert from "node:assert/strict";
import { test } from "node:test";

import * as b from "../../site/builder/builder.js";
import { data, golden } from "./helpers.mjs";

test("each golden state survives a round trip through the fragment, in both shells", () => {
  for (const c of golden.filter((x) => !x.invalid)) {
    for (const shell of ["bash", "powershell"]) {
      const back = b.fromFragment(data, b.toFragment(data, c.state, shell));
      assert.equal(back.shell, shell);
      assert.equal(b.buildCommand(data, back.state, shell), c[shell], c.name);
    }
  }
});

test("unknown commands, unknown options and odd flag values are dropped", () => {
  const got = b.fromFragment(data, "#cmd=rm&__proto__=x&constructor=y&evil=1&quiet=yes&out=o&package=a&package=b");
  assert.equal(got.state.command, "scan");
  assert.deepEqual(got.state.values, { out: "o", package: ["a", "b"] });
  assert.equal(got.shell, "bash");
  assert.equal(Object.getPrototypeOf(got.state.values), Object.prototype);
});

test("values from a link are length-limited text", () => {
  const got = b.fromFragment(data, `cmd=scan&out=${"x".repeat(5000)}`);
  assert.equal(got.state.values.out.length, 2000);
});
