// docs/admin-guide.md: every builder link opens a command the builder accepts, and the command shown under it is
// exactly what the builder makes from that link. A change to the builder that would make the guide wrong fails here.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import * as b from "../../site/builder/builder.js";
import * as w from "../../site/builder/wizard.js";
import { ROOT, data, rules, wizard } from "./helpers.mjs";

const guide = readFileSync(join(ROOT, "docs", "admin-guide.md"), "utf8");
const LINK = /\]\(https:\/\/ntavakol\.github\.io\/OSS-Intake\/builder\/#([^)]+)\)\s*\n\s*```bash\n(oss-intake [^\n]+)\n```/g;

test("each example link opens the command shown under it, with nothing the builder would refuse", () => {
  const examples = [...guide.matchAll(LINK)];
  assert.ok(examples.length >= 8, `found ${examples.length} examples`);
  for (const [, fragment, shown] of examples) {
    const { state, extra } = b.fromFragment(data, fragment);
    if (extra.what) state.what = extra.what;
    assert.equal(b.buildCommand(data, state), shown, fragment);
    assert.deepEqual([...b.problems(data, rules, state), ...w.kindProblems(data, wizard, state)], [], shown);
    if (extra.what) assert.ok(w.target(wizard, extra.what), `${extra.what} is a wizard answer`);
  }
});

test("the labels the guide tells you to pick are the builder's own", () => {
  const labels = [...guide.matchAll(/\*\*([^*]+)\*\*/g)].map((m) => m[1].replace(/\s+/g, " ").replace(/:$/, ""));
  const known = new Set([
    ...wizard.targets.map((t) => t.label), ...wizard.outcomes.map((o) => o.label), ...wizard.gates.map((g) => g.label),
    ...Object.values(wizard.fields).flatMap((f) => [f.label, f.default_label].filter(Boolean)), ...w.STEPS,
    ...w.STEPS.map((s, i) => `${i + 1}. ${s}`),
  ]);
  for (const l of ["A container image", "A project's dependency list", "A file or folder you downloaded or built",
    "An SBOM or a package list", "Specific packages", "Just a GitHub project's health", "A report to read",
    "A pass or fail check, for CI", "Which image?", "Where is it?", "Where is the source on GitHub?",
    "Which packages?", "Labels (optional)", "Folder for the report", "Let the scanners choose",
    "Also fail if the suggested likelihood is at least", "A package is known malware",
    "The file doesn't match the checksum its registry publishes", "4. Review"]) {
    assert.ok(labels.includes(l), `the guide no longer names "${l}"`);
  }
  for (const l of labels.filter((x) => /^[A-Z1-4]/.test(x) && known.size)) {
    const isUi = known.has(l) || [...known].some((k) => k.startsWith(l));
    const prose = ["When", "You need", "Read the result", "Make it stronger", "Exit codes", "Guided", "Command",
      "bash / zsh", "PowerShell", "Next", "Copy", "All options", "Scanners and image", "Evidence sources",
      "What this command will do", "Doesn't check", "Fix existed before release", "Act now", "Review",
      "Check conditions", "Routine", "Warnings", "Malicious packages", "Suggested triage", "Top findings",
      "Project health", "recommended", "Add another --package", "remote", "1. What are you checking?",
      "2. Details", "3. What do you want back?"];
    assert.ok(isUi || prose.includes(l), `"${l}" in the guide is not a label the builder shows`);
  }
});
