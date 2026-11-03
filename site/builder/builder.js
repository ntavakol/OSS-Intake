// oss-intake command builder: the logic, with no DOM access, so Node can test it (tests/builder/).
//
// State: { command: "scan" | "verify" | "doctor", values: { <dest>: value } }, where a flag is true, a
// repeatable option is a list of strings, and anything else is a string. An option is part of the command only
// when it is set: a flag that is true, a non-empty list, or a non-empty value that differs from the default.

const SCAN = "scan";

/** The options of one subcommand, keyed by dest, in parser order. */
export function optionsFor(data, command) {
  const cmd = data.commands[command];
  if (!cmd) throw new Error(`unknown command ${command}`);
  return cmd.options;
}

function listOf(value) {
  return Array.isArray(value) ? value.filter((v) => String(v).trim() !== "") : [];
}

/** True when the option contributes to the command. */
export function isSet(option, value) {
  if (option.kind === "flag") return value === true;
  if (option.kind === "repeatable") return listOf(value).length > 0;
  if (value === undefined || value === null) return false;
  const text = String(value).trim();
  if (text === "") return false;
  return option.default === null || text !== String(option.default);
}

function setValue(options, values, dest) {
  const option = options.find((o) => o.dest === dest);
  return option ? isSet(option, values[dest]) : false;
}

function items(value) {
  return String(value ?? "").split(",").map((x) => x.trim().toLowerCase()).filter((x) => x !== "");
}

/** Does option dest hold value (a comma list or a repeatable option)? */
function has(values, dest, wanted) {
  const v = values[dest];
  const all = Array.isArray(v) ? v.map((x) => String(x).trim().toLowerCase()) : items(v);
  return all.includes(String(wanted).toLowerCase());
}

function intOf(options, values, dest) {
  const option = options.find((o) => o.dest === dest);
  const raw = values[dest];
  const text = raw === undefined || raw === null || String(raw).trim() === "" ? option?.default : raw;
  const n = Number.parseInt(String(text), 10);
  return Number.isNaN(n) ? null : n;
}

/** Evaluate a rules.json condition against the state. Only the listed operators exist; anything else throws,
 * so a typo in rules.json fails the tests instead of silently never matching. */
export function holds(cond, options, values) {
  const [op, arg] = Object.entries(cond)[0] ?? [];
  switch (op) {
    case "all": return arg.every((c) => holds(c, options, values));
    case "any": return arg.some((c) => holds(c, options, values));
    case "not": return !holds(arg, options, values);
    case "set": return setValue(options, values, arg);
    case "none": return arg.every((d) => !setValue(options, values, d));
    case "has": return has(values, arg[0], arg[1]);
    case "lt": { const n = intOf(options, values, arg[0]); return n !== null && n < arg[1]; }
    case "eq": { const n = intOf(options, values, arg[0]); return n !== null && n === arg[1]; }
    default: throw new Error(`rules.json: unknown condition ${JSON.stringify(cond)}`);
  }
}

function realDate(text) {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(text);
  if (!m) return false;
  const [y, mo, d] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const dt = new Date(Date.UTC(y, mo - 1, d));
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === mo - 1 && dt.getUTCDate() === d;
}

/** Problems with one field's value: argparse's own checks (int, choices) and rules.json "fields". */
export function fieldErrors(option, value, rules, command) {
  if (!isSet(option, value)) return [];
  const out = [];
  const values = option.kind === "repeatable" ? listOf(value) : [String(value).trim()];
  for (const v of values) {
    if (option.kind === "int" && !/^-?\d+$/.test(v)) out.push(`${option.flag}: a whole number`);
    if (option.kind === "choice") {
      const want = option.upper ? v.toUpperCase() : v;
      if (!option.choices.map(String).includes(want)) {
        out.push(`${option.flag}: one of ${option.choices.join(", ")}`);
      }
    }
    for (const f of rules.fields) {
      if (f.command !== command || f.dest !== option.dest) continue;
      let ok = true;
      if (f.pattern) ok = new RegExp(f.pattern).test(v);
      if (f.date) ok = realDate(v);
      if (f.list_of) {
        const xs = items(v);
        ok = xs.length > 0 && xs.every((x) => f.list_of.includes(x)) &&
          (!f.auto_alone || !xs.includes("auto") || xs.length === 1);
      }
      if (!ok) out.push(`${option.flag}: ${f.message}`);
    }
  }
  return [...new Set(out)];
}

/** Everything that stops the command from being copied: field errors, required options, the required
 * either-or groups, and the cross-option rules. Each entry: { dest | rule, message }. */
export function problems(data, rules, state) {
  const options = optionsFor(data, state.command);
  const values = state.values ?? {};
  const out = [];
  for (const o of options) {
    for (const message of fieldErrors(o, values[o.dest], rules, state.command)) out.push({ dest: o.dest, message });
    if (o.required && !isSet(o, values[o.dest])) out.push({ dest: o.dest, message: `${o.flag} is required` });
  }
  data.commands[state.command].exclusive_groups.forEach((g) => {
    const given = g.options.filter((d) => setValue(options, values, d));
    const flags = g.options.map((d) => options.find((o) => o.dest === d).flag);
    if (given.length > 1) out.push({ rule: "exclusive", message: `give only one of ${flags.join(", ")}` });
    if (g.required && given.length === 0) out.push({ rule: "exclusive", message: `give one of ${flags.join(", ")}` });
  });
  for (const r of rules.rules) {
    if (r.command === state.command && holds(r.when, options, values)) out.push({ rule: r.id, message: r.message });
  }
  return out;
}

/** Notes that apply (information, not errors). */
export function notes(data, rules, state) {
  const options = optionsFor(data, state.command);
  return rules.notes.filter((n) => n.command === state.command && holds(n.when, options, state.values ?? {}))
    .map((n) => n.message);
}

/** The command as an argument list, in parser order. A value that starts with "-" is joined to its flag
 * (--trivy-arg=--db-repository=x), because argparse would read it as an option otherwise. */
export function buildArgs(data, state) {
  const options = optionsFor(data, state.command);
  const values = state.values ?? {};
  const args = state.command === SCAN ? [] : [state.command];
  for (const o of options) {
    const v = values[o.dest];
    if (!isSet(o, v)) continue;
    if (o.kind === "flag") { args.push(o.flag); continue; }
    const vs = o.kind === "repeatable" ? listOf(v).map((x) => String(x).trim()) : [String(v).trim()];
    for (const x of vs) {
      if (x.startsWith("-")) args.push(`${o.flag}=${x}`);
      else args.push(o.flag, x);
    }
  }
  return args;
}

const BASH_SAFE = /^[A-Za-z0-9_@%+=:,./-]+$/;
const PS_SAFE = /^[A-Za-z0-9_%+=:./\\-]+$/;

/** One argument for bash or zsh: as is when it has no special characters, otherwise in single quotes. A leading
 * ~/ is left outside the quotes so the shell still expands it to the home folder. */
export function quoteBash(arg) {
  if (arg !== "" && BASH_SAFE.test(arg)) return arg;
  if (arg.startsWith("~/") && BASH_SAFE.test(arg.slice(2))) return arg;
  if (arg.startsWith("~/")) return `~/${quoteBash(arg.slice(2))}`;
  return `'${arg.replaceAll("'", "'\\''")}'`;
}

/** One argument for PowerShell: as is when safe, otherwise in single quotes with ' doubled. Commas, @, $,
 * backticks, braces, parentheses, semicolons, quotes and spaces all need quoting there. PowerShell does not
 * expand ~ for programs, so a leading ~/ becomes "$HOME/..." (double quotes, with ` " and $ escaped). */
export function quotePowerShell(arg) {
  if (/^--[a-z0-9-]+$/.test(arg)) return arg;
  if (/^~[/\\]/.test(arg)) return `"$HOME/${arg.slice(2).replace(/[`"$]/g, (m) => `\`${m}`)}"`;
  if (arg !== "" && PS_SAFE.test(arg) && !arg.startsWith("-")) return arg;
  return `'${arg.replaceAll("'", "''")}'`;
}

/** The full command line for "bash" (bash and zsh) or "powershell". */
export function buildCommand(data, state, shell = "bash") {
  const quote = shell === "powershell" ? quotePowerShell : quoteBash;
  return ["oss-intake", ...buildArgs(data, state).map(quote)].join(" ");
}

/** True when a value would not survive Windows PowerShell 5.1 (it mangles " inside arguments to programs). */
export function needsPowerShell7(data, state) {
  return buildArgs(data, state).some((a) => a.includes('"'));
}

// ---------------------------------------------------------------- URL fragment

/** The state as a URL fragment (without "#"): only options that are set, so a link stays short. */
export function toFragment(data, state, shell = "bash") {
  const p = new URLSearchParams();
  p.set("cmd", state.command);
  if (shell !== "bash") p.set("shell", shell);
  for (const o of optionsFor(data, state.command)) {
    const v = state.values?.[o.dest];
    if (!isSet(o, v)) continue;
    if (o.kind === "flag") p.set(o.dest, "1");
    else if (o.kind === "repeatable") for (const x of listOf(v)) p.append(o.dest, String(x));
    else p.set(o.dest, String(v));
  }
  return p.toString();
}

/** Read a fragment back. It comes from a link anyone can make, so only known commands and options are kept,
 * flags only as "1", and every value as plain text (checked by problems() like anything typed in). */
export function fromFragment(data, fragment) {
  const p = new URLSearchParams(String(fragment ?? "").replace(/^#/, ""));
  const command = Object.hasOwn(data.commands, p.get("cmd") ?? "") ? p.get("cmd") : SCAN;
  const shell = p.get("shell") === "powershell" ? "powershell" : "bash";
  const values = {};
  for (const o of optionsFor(data, command)) {
    if (!p.has(o.dest)) continue;
    if (o.kind === "flag") { if (p.get(o.dest) === "1") values[o.dest] = true; }
    else if (o.kind === "repeatable") values[o.dest] = p.getAll(o.dest).slice(0, 1000).map((x) => x.slice(0, 2000));
    else values[o.dest] = (p.get(o.dest) ?? "").slice(0, 2000);
  }
  return { state: { command, values }, shell };
}

/** An argument list back into a state (for tests, and the reverse of buildArgs). Throws on an unknown option. */
export function stateFromArgs(data, command, args) {
  const options = optionsFor(data, command);
  const byFlag = new Map(options.map((o) => [o.flag, o]));
  const values = {};
  for (let i = 0; i < args.length; i += 1) {
    let flag = args[i];
    let value = null;
    const eq = flag.indexOf("=");
    if (flag.startsWith("--") && eq > 0) { value = flag.slice(eq + 1); flag = flag.slice(0, eq); }
    const o = byFlag.get(flag);
    if (!o) throw new Error(`unknown option ${flag}`);
    if (o.kind === "flag") { values[o.dest] = true; continue; }
    if (value === null) { i += 1; value = args[i]; }
    if (o.kind === "repeatable") (values[o.dest] ??= []).push(value);
    else values[o.dest] = value;
  }
  return { command, values };
}
