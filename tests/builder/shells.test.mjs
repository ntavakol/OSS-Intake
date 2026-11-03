// The quoting, checked by real shells: each golden command is run with a stand-in oss-intake that prints the
// arguments it receives. bash always; zsh and PowerShell (pwsh) when installed (GitHub's Ubuntu runners have
// pwsh). A shell that is not installed is skipped, not passed.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { delimiter, join } from "node:path";
import { test } from "node:test";

import { golden } from "./helpers.mjs";

function which(name) {
  try {
    execFileSync(process.platform === "win32" ? "where" : "which", [name], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

const bin = mkdtempSync(join(tmpdir(), "oss-intake-stub-"));
const stub = join(bin, "oss-intake");
writeFileSync(stub, `#!${process.execPath}\nprocess.stdout.write(JSON.stringify(process.argv.slice(2)));\n`);
chmodSync(stub, 0o755);
const env = { ...process.env, PATH: `${bin}${delimiter}${process.env.PATH}`, HOME: "/home/tester" };
const home = (args) => args.map((a) => a.replace(/^~(?=[/\\])/, "/home/tester"));

const shells = [
  ["bash", "bash", (cmd) => ["-c", cmd], (c) => c.bash],
  ["zsh", "zsh", (cmd) => ["-f", "-c", cmd], (c) => c.bash],
  ["PowerShell", "pwsh", (cmd) => ["-NoProfile", "-NonInteractive", "-Command", cmd], (c) => c.powershell],
];

for (const [label, exe, argv, pick] of shells) {
  const skip = process.platform === "win32" ? "the stand-in is a #! script" : !which(exe) && `${exe} not installed`;
  test(`${label} passes each golden command's arguments unchanged`, { skip }, () => {
    for (const c of golden.filter((x) => !x.invalid)) {
      const out = execFileSync(exe, argv(pick(c)), { env, encoding: "utf8" });
      assert.deepEqual(JSON.parse(out), home(c.args), c.name);
    }
  });
}
