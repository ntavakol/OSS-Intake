import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const json = (...p) => JSON.parse(readFileSync(join(ROOT, ...p), "utf8"));
export const data = json("site", "builder", "options.json");
export const rules = json("site", "builder", "rules.json");
export const groups = json("site", "builder", "ui-groups.json");
export const golden = json("tests", "fixtures", "builder_golden.json").cases;
