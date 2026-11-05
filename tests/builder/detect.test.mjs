// The paste box: each input in tests/fixtures/detect_cases.json gives exactly the expected result, every result
// that is ready builds a command the builder accepts, and anything else says why rather than guessing.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import * as b from "../../site/builder/builder.js";
import { detect, slug } from "../../site/builder/detect.js";
import * as w from "../../site/builder/wizard.js";
import { ROOT, data, rules, wizard } from "./helpers.mjs";

const cases = JSON.parse(readFileSync(join(ROOT, "tests", "fixtures", "detect_cases.json"), "utf8")).cases;
const ctx = { wiz: wizard, rules };

function ready(r) {
  let s = w.choose(wizard, { command: "scan", values: {} }, r.what);
  s = { ...s, values: { ...s.values, ...r.values } };
  return s;
}

test("each pasted input gives the expected result", () => {
  assert.ok(cases.length >= 40);
  for (const c of cases) {
    const r = detect(c.input, ctx);
    assert.equal(r.status, c.status, JSON.stringify(c.input));
    if (c.status === "ok") {
      assert.equal(r.what, c.what, c.input);
      assert.deepEqual(r.values, c.values, c.input);
    }
    if (c.status === "ask") {
      assert.deepEqual(r.choices.map((x) => x.label), c.choices.map((x) => x.label), c.input);
      r.choices.forEach((x, i) => {
        assert.equal(x.status, c.choices[i].status, `${c.input}: ${x.label}`);
        if (x.status === "ok") assert.deepEqual(x.values, c.choices[i].values, `${c.input}: ${x.label}`);
      });
    }
    if (c.status !== "ok" && c.input.trim()) assert.ok(r.says, `${c.input}: says why`);
    if (c.says) assert.ok(r.says.includes(c.says), `${c.input}: says "${c.says}", not "${r.says}"`);
  }
});

test("every ready result builds a command the builder accepts, with nothing left to ask", () => {
  const all = cases.flatMap((c) => {
    const r = detect(c.input, ctx);
    return r.status === "ok" ? [[c.input, r]] : (r.choices ?? []).filter((x) => x.status === "ok").map((x) => [`${c.input} (${x.label})`, x]);
  });
  assert.ok(all.length >= 30);
  for (const [input, r] of all) {
    const s = ready(r);
    assert.ok(w.target(wizard, r.what), input);
    assert.deepEqual([...b.problems(data, rules, s), ...w.kindProblems(data, wizard, s)], [], input);
    for (const step of [1, 2, 3]) assert.deepEqual(w.stepProblems(data, rules, wizard, s, step), [], `${input}, step ${step}`);
    assert.match(r.values.out, /^report-[a-z0-9.-]+$/, input);
  }
});

test("nothing pasted is turned into a guess", () => {
  for (const text of ["hello world", "https://example.com/x", "nginx", "npm install chalk", "pip install 'django>=4'",
    "https://www.npmjs.com/package/chalk", "docker pull nginx", "a\nb", "<script>alert(1)</script>",
    "npm install chalk@^5.0.0", "pkg:docker/nginx@1.27", "https://github.com/orgs/owner", "package.json", "npm ci",
    "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", "maven:log4j-core@2.14.1", "https://www.npmjs.com/package/chalk/v/latest"]) {
    assert.notEqual(detect(text, ctx).status, "ok", text);
  }
});

test("docker never reads past the image into the container's command", () => {
  for (const [text, image] of [['docker run -it --rm alpine:3.20 sh -c "echo a:b"', "alpine:3.20"],
    ["docker run --link db:db --restart always nginx:1.27", "nginx:1.27"],
    ['docker run -p 8080:80 -e A=b:c nginx:1.27 nginx -g "daemon off;"', "nginx:1.27"]]) {
    assert.equal(detect(text, ctx).values?.image, image, text);
  }
  assert.equal(detect("docker run --rm nginx echo a:b", ctx).status, "no");
});

test("a ready package always names one version number, never a tag such as next or latest", () => {
  for (const c of cases) {
    for (const r of [detect(c.input, ctx), ...(detect(c.input, ctx).choices ?? [])]) {
      for (const p of r.status === "ok" ? r.values.package ?? [] : []) {
        assert.match(decodeURIComponent(p.slice(p.lastIndexOf("@") + 1)), /^v?\d/, `${c.input}: ${p}`);
      }
    }
  }
});

test("folder names are short and safe", () => {
  assert.equal(slug({ package: ["npm:@ctrl/tinycolor@4.1.1"] }), "ctrl-tinycolor-4.1.1");
  assert.equal(slug({ image: "ghcr.io/owner/app@sha256:" + "a".repeat(64) }), "owner-app");
  assert.equal(slug({ path: "~/projects/web/package-lock.json" }), "web");
  assert.equal(slug({ path: "../../etc/passwd.jar" }), "passwd");
  assert.equal(slug({ repo: "x".repeat(200) + "/y" }).length, 60);
});
