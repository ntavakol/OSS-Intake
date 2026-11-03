// oss-intake command builder: the page. Renders the form from options.json and ui-groups.json, and shows the
// command builder.js makes. The DOM is built with createElement and textContent only, never from HTML text, as the
// page's Content Security Policy expects.
import * as b from "./builder.js";

const $ = (id) => document.getElementById(id);
let data, rules, layout;
let state = { command: "scan", values: {} };
let shell = "bash";

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || (v === false && !k.startsWith("aria-"))) continue;
    if (k === "text") node.textContent = v;
    else if (k === "class") node.className = v;
    else if (k.startsWith("aria-")) node.setAttribute(k, String(v));  // aria-checked="true", not ""
    else node.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children) if (c) node.append(c);
  return node;
}

function option(dest) {
  return b.optionsFor(data, state.command).find((o) => o.dest === dest);
}

function set(dest, value) {
  state.values[dest] = value;
  refresh();
}

// ---------------------------------------------------------------- fields

function fieldId(dest) {
  return `f-${state.command}-${dest}`;
}

function about(o) {
  const bits = [o.help];
  if (o.default !== null && o.default !== "" && o.kind !== "flag") bits.push(`Default: ${o.default}.`);
  return bits.filter(Boolean).join(" ");
}

function textInput(o, value, onInput, extra = {}) {
  const input = el("input", {
    type: "text", id: extra.id, value: value ?? "", autocomplete: "off", spellcheck: "false",
    placeholder: o.default !== null && o.default !== "" ? String(o.default) : (o.metavar ?? ""),
    inputmode: o.kind === "int" ? "numeric" : null, "aria-describedby": extra.describedby,
    "aria-label": extra.label,
  });
  input.addEventListener("input", () => onInput(input.value));
  return input;
}

function renderField(o) {
  const id = fieldId(o.dest);
  const helpId = `${id}-help`;
  const errId = `${id}-err`;
  const value = state.values[o.dest];
  const describedby = `${helpId} ${errId}`;
  const flag = el("span", { class: "flag", text: o.flag });
  const help = el("span", { class: "about", id: helpId, text: about(o) });
  const err = el("span", { class: "error", id: errId, "data-error": o.dest });

  if (o.kind === "flag") {
    const box = el("input", { type: "checkbox", id, checked: value === true, "aria-describedby": describedby });
    box.addEventListener("change", () => set(o.dest, box.checked));
    return el("div", { class: "field check", "data-field": o.dest }, box,
      el("div", {}, el("label", { for: id }, flag), help, err));
  }

  const label = el("label", { for: id }, flag);
  if (o.kind === "choice") {
    const select = el("select", { id, "aria-describedby": describedby });
    select.append(el("option", { value: "", text: o.default !== null ? `(default: ${o.default})` : "(not set)" }));
    for (const c of o.choices) select.append(el("option", { value: String(c), text: String(c) }));
    select.value = value === undefined ? "" : String(value);
    select.addEventListener("change", () => set(o.dest, select.value));
    return el("div", { class: "field", "data-field": o.dest }, label, select, help, err);
  }

  if (o.kind === "repeatable") {
    const rows = Array.isArray(value) && value.length ? value : [""];
    const list = el("div", { class: "rows" });
    rows.forEach((v, i) => {
      const input = textInput(o, v, (text) => {
        const next = [...(state.values[o.dest] ?? [""])];
        next[i] = text;
        state.values[o.dest] = next;
        refresh();
      }, { id: i === 0 ? id : `${id}-${i}`, describedby, label: i === 0 ? null : `${o.flag} ${i + 1}` });
      const remove = el("button", { type: "button", class: "btn", "aria-label": `Remove ${o.flag} ${i + 1}`, text: "×" });
      remove.addEventListener("click", () => {
        const next = [...(state.values[o.dest] ?? [])];
        next.splice(i, 1);
        state.values[o.dest] = next;
        render();
      });
      list.append(el("div", { class: "row" }, input, rows.length > 1 || v ? remove : null));
    });
    const add = el("button", { type: "button", class: "btn add", text: `Add another ${o.flag}` });
    add.addEventListener("click", () => {
      state.values[o.dest] = [...(state.values[o.dest] ?? [""]), ""];
      render();
      const inputs = document.querySelectorAll(`[data-field="${o.dest}"] input`);
      inputs[inputs.length - 1]?.focus();
    });
    return el("div", { class: "field", "data-field": o.dest }, label, list, add, help, err);
  }

  return el("div", { class: "field", "data-field": o.dest }, label,
    textInput(o, value, (text) => set(o.dest, text), { id, describedby }), help, err);
}

function renderGroups() {
  const box = $("groups");
  box.replaceChildren();
  const groups = layout.commands[state.command].groups;
  const advanced = [];
  for (const g of groups) {
    const fields = el("div", { class: "fields" }, ...g.options.map((d) => renderField(option(d))));
    const given = g.options.filter((d) => b.isSet(option(d), state.values[d])).length;
    const summary = el("summary", {}, g.name, given ? el("span", { class: "count", text: `${given} set` }) : null);
    const details = el("details", { class: "group", open: g.basic || given > 0 }, summary, fields);
    if (g.basic) box.append(details);
    else advanced.push(details);
  }
  if (advanced.length) {
    box.append(el("h2", { class: "help", text: "Advanced" }));
    box.append(...advanced);
  }
}

// ---------------------------------------------------------------- command panel

function renderCommand() {
  const problems = b.problems(data, rules, state);
  // One span per argument, so lines wrap between arguments and never inside one (--fail-on stays whole).
  // Copy uses buildCommand itself, not this text.
  const parts = b.buildCommand(data, state, shell).split(" ");
  const quote = shell === "powershell" ? b.quotePowerShell : b.quoteBash;
  const words = ["oss-intake", ...b.buildArgs(data, state).map(quote)];
  const shown = words.join(" ") === parts.join(" ") ? words : parts;
  $("command").replaceChildren(...shown.flatMap((w, i) => [i ? " " : "", el("span", { class: w.length > 40 ? "arg long" : "arg", text: w })]));
  const list = $("problems");
  list.replaceChildren(...problems.map((p) => el("li", { text: p.message })));
  const notes = b.notes(data, rules, state);
  if (shell === "powershell" && b.needsPowerShell7(data, state)) {
    notes.push("A value contains a double quote: PowerShell 7.3 or later passes it correctly; Windows PowerShell 5.1 does not.");
  }
  $("notes").replaceChildren(...notes.map((n) => el("li", { text: n })));
  $("copy").disabled = problems.length > 0;
  $("copy").title = problems.length ? "Fix the problems listed below first" : "";
  for (const node of document.querySelectorAll("[data-error]")) {
    const msgs = problems.filter((p) => p.dest === node.dataset.error).map((p) => p.message);
    node.textContent = msgs.join(" ");
    node.closest(".field").classList.toggle("bad", msgs.length > 0);
    for (const input of node.closest(".field").querySelectorAll("input,select")) {
      input.setAttribute("aria-invalid", msgs.length ? "true" : "false");
    }
  }
  const fragment = b.toFragment(data, state, shell);
  history.replaceState(null, "", `#${fragment}`);
}

function refresh() {
  renderCommand();
  for (const g of document.querySelectorAll(".group")) {
    const dests = [...g.querySelectorAll("[data-field]")].map((f) => f.dataset.field);
    const n = dests.filter((d) => b.isSet(option(d), state.values[d])).length;
    const summary = g.querySelector("summary");
    summary.querySelector(".count")?.remove();
    if (n) summary.append(el("span", { class: "count", text: `${n} set` }));
  }
}

function radios(box, items, current, onPick) {
  box.replaceChildren(...items.map(([value, label]) => {
    const button = el("button", { type: "button", role: "radio", "aria-checked": value === current, text: label });
    button.addEventListener("click", () => onPick(value));
    return button;
  }));
}

function render() {
  radios($("commands"), Object.keys(layout.commands).map((c) => [c, layout.commands[c].label]), state.command,
    (c) => { state = { command: c, values: {} }; render(); });
  radios($("shells"), [["bash", "bash / zsh"], ["powershell", "PowerShell"]], shell,
    (s) => { shell = s; render(); });
  $("command-help").textContent = layout.commands[state.command].help;
  const preset = $("preset");
  preset.replaceChildren(el("option", { value: "", text: "(choose an example)" }),
    ...layout.presets.map((p, i) => el("option", { value: String(i), text: p.name })));
  renderGroups();
  renderCommand();
}

async function copy(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    $("status").textContent = `${what} copied`;
  } catch {
    $("status").textContent = `Could not copy: select the ${what.toLowerCase()} and copy it yourself`;
  }
  setTimeout(() => { $("status").textContent = ""; }, 4000);
}

async function load(name) {
  const r = await fetch(name, { cache: "no-cache" });
  if (!r.ok) throw new Error(`${name}: HTTP ${r.status}`);
  return r.json();
}

async function main() {
  [data, rules, layout] = await Promise.all([load("options.json"), load("rules.json"), load("ui-groups.json")]);
  const fromLink = b.fromFragment(data, location.hash);
  state = fromLink.state;
  shell = fromLink.shell;
  $("version").textContent = `For oss-intake ${data.version}. Check yours with oss-intake --version.`;
  $("preset").addEventListener("change", (e) => {
    const p = layout.presets[Number(e.target.value)];
    if (!p) return;
    state = { command: p.command, values: structuredClone(p.values) };
    render();
    e.target.value = "";
  });
  $("reset").addEventListener("click", () => { state = { command: state.command, values: {} }; render(); });
  $("copy").addEventListener("click", () => copy(b.buildCommand(data, state, shell), "Command"));
  $("link").addEventListener("click", () => copy(location.href, "Link"));
  render();
}

main().catch((err) => {
  $("version").textContent = `The builder could not load its option list (${err.message}).`;
});
