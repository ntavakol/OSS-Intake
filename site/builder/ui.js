// oss-intake command builder: the page. Two views of one state: the guided wizard (wizard-ui.js, the default)
// and the full form, rendered here from options.json and ui-groups.json. The command panel and "What this
// command will do" are shared. builder.js and wizard.js hold the logic; dom.js the DOM helpers.
import * as b from "./builder.js";
import * as w from "./wizard.js";
import { $, commandSpans, copy, el, focusKey, radios, restoreFocus, summaryNodes } from "./dom.js";
import { renderWizard, refreshWizard } from "./wizard-ui.js";

const app = { data: null, rules: null, layout: null, wiz: null, state: { command: "scan", values: {} },
  shell: "bash", view: "wizard", step: 0 };

function option(dest) {
  return b.optionsFor(app.data, app.state.command).find((o) => o.dest === dest);
}

function set(dest, value) {
  app.state.values[dest] = value;
  refresh();
}

// ---------------------------------------------------------------- the full form

function fieldId(dest) {
  return `f-${app.state.command}-${dest}`;
}

function about(o) {
  const bits = [o.help];
  if (o.default !== null && o.default !== "" && o.kind !== "flag") bits.push(`Default: ${o.default}.`);
  return bits.filter(Boolean).join(" ");
}

export function textInput(o, value, onInput, extra = {}) {
  const input = el("input", {
    type: "text", id: extra.id, value: value ?? "", autocomplete: "off", spellcheck: "false",
    placeholder: extra.placeholder ?? (o.default !== null && o.default !== "" ? String(o.default) : (o.metavar ?? "")),
    inputmode: o.kind === "int" ? "numeric" : null, "aria-describedby": extra.describedby,
    "aria-label": extra.label,
  });
  input.addEventListener("input", () => onInput(input.value));
  return input;
}

/** The rows of a repeatable option, with Remove and Add another. Shared with the wizard. */
export function repeatableRows(o, id, describedby, placeholder) {
  const value = app.state.values[o.dest];
  const rows = Array.isArray(value) && value.length ? value : [""];
  const list = el("div", { class: "rows" });
  rows.forEach((v, i) => {
    const rowId = i === 0 ? id : `${id}-${i}`;
    const input = textInput(o, v, (text) => {
      const next = [...(app.state.values[o.dest] ?? [""])];
      next[i] = text;
      app.state.values[o.dest] = next;
      refresh();
    }, { id: rowId, describedby, label: i === 0 ? null : `${o.flag} ${i + 1}`, placeholder });
    const remove = el("button", { type: "button", class: "btn", "aria-label": `Remove ${o.flag} ${i + 1}`, text: "×" });
    remove.addEventListener("click", () => {
      const next = [...(app.state.values[o.dest] ?? [])];
      next.splice(i, 1);
      app.state.values[o.dest] = next;
      const previous = i > 1 ? `${id}-${i - 1}` : id;
      render(`#${previous}`, id);
    });
    list.append(el("div", { class: "row" }, input, rows.length > 1 || v ? remove : null));
  });
  const add = el("button", { type: "button", class: "btn add", text: `Add another ${o.flag}` });
  add.addEventListener("click", () => {
    app.state.values[o.dest] = [...(app.state.values[o.dest] ?? [""]), ""];
    render(`#${id}-${rows.length}`);
  });
  return [list, add];
}

function renderField(o) {
  const id = fieldId(o.dest);
  const helpId = `${id}-help`;
  const errId = `${id}-err`;
  const value = app.state.values[o.dest];
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
    const select = choiceSelect(o, id, describedby, o.default !== null ? `(default: ${o.default})` : "(not set)");
    return el("div", { class: "field", "data-field": o.dest }, label, select, help, err);
  }
  if (o.kind === "repeatable") {
    return el("div", { class: "field", "data-field": o.dest }, label, ...repeatableRows(o, id, describedby), help, err);
  }
  return el("div", { class: "field", "data-field": o.dest }, label,
    textInput(o, value, (text) => set(o.dest, text), { id, describedby }), help, err);
}

/** A select for a choice option, showing a value from a link that is not allowed as "(not allowed)". */
export function choiceSelect(o, id, describedby, emptyLabel) {
  const value = app.state.values[o.dest];
  const select = el("select", { id, "aria-describedby": describedby });
  select.append(el("option", { value: "", text: emptyLabel }));
  for (const c of o.choices) select.append(el("option", { value: String(c), text: String(c) }));
  if (value !== undefined && value !== "" && !o.choices.map(String).includes(String(value))) {
    select.append(el("option", { value: String(value), text: `${value} (not allowed)` }));
  }
  select.value = value === undefined ? "" : String(value);
  select.addEventListener("change", () => set(o.dest, select.value));
  return select;
}

function renderGroups() {
  const box = $("groups");
  box.replaceChildren();
  const groups = app.layout.commands[app.state.command].groups;
  const advanced = [];
  for (const g of groups) {
    const fields = el("div", { class: "fields" }, ...g.options.map((d) => renderField(option(d))));
    const given = g.options.filter((d) => b.isSet(option(d), app.state.values[d])).length;
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

function renderForm() {
  radios($("commands"), Object.keys(app.layout.commands).map((c) => [c, app.layout.commands[c].label]),
    app.state.command, (c) => { app.state = { command: c, values: {} }; render(`commands:${c}`); });
  $("command-help").textContent = app.layout.commands[app.state.command].help;
  const preset = $("preset");
  preset.replaceChildren(el("option", { value: "", text: "(choose an example)" }),
    ...app.layout.presets.map((p, i) => el("option", { value: String(i), text: p.name })));
  renderGroups();
}

function refreshFormCounts() {
  for (const g of document.querySelectorAll(".group")) {
    const dests = [...g.querySelectorAll("[data-field]")].map((f) => f.dataset.field);
    const n = dests.filter((d) => b.isSet(option(d), app.state.values[d])).length;
    const summary = g.querySelector("summary");
    summary.querySelector(".count")?.remove();
    if (n) summary.append(el("span", { class: "count", text: `${n} set` }));
  }
}

// ---------------------------------------------------------------- the command panel, shared

function renderPanel() {
  const { data, rules, state, shell } = app;
  // The file-kind checks need the kind, which the file name tells the form as well (wizard.js kindOf).
  const problems = [...b.problems(data, rules, state), ...(state.command === "scan" ? w.kindProblems(data, app.wiz, state) : [])];
  const quote = shell === "powershell" ? b.quotePowerShell : b.quoteBash;
  $("command").replaceChildren(...commandSpans(["oss-intake", ...b.buildArgs(data, state).map(quote)]));
  // The wizard lists problems at the step they belong to; before its last step the command is not finished yet.
  const early = app.view === "wizard" && app.step < 3;
  $("problems").replaceChildren(...(early ? [] : problems.map((p) => el("li", { text: p.message }))));
  const notes = b.notes(data, rules, state);
  if (shell === "powershell" && b.needsPowerShell7(data, state)) {
    notes.push("A value contains a double quote: PowerShell 7.3 or later passes it correctly; Windows PowerShell 5.1 does not.");
  }
  if (early && problems.length) notes.unshift("Finish the steps to copy the command.");
  $("notes").replaceChildren(...notes.map((n) => el("li", { text: n })));
  $("copy").disabled = problems.length > 0;
  $("copy").title = problems.length ? "Fix the problems listed first" : "";
  for (const node of document.querySelectorAll("[data-error]")) {
    const msgs = problems.filter((p) => p.dest === node.dataset.error).map((p) => p.message);
    node.textContent = msgs.join(" ");
    const field = node.closest(".field");
    field.classList.toggle("bad", msgs.length > 0);
    for (const input of field.querySelectorAll("input,select")) input.setAttribute("aria-invalid", msgs.length ? "true" : "false");
  }
  const groups = w.summary(data, app.wiz, state);
  $("summary").replaceChildren(...(groups.length ? summaryNodes(groups)
    : [el("p", { class: "help", text: state.command === "scan" ? "Pick what you are checking to see this." : "" })]));
  // On the wizard's review step the summary is in the step itself, above the flag-by-flag list.
  $("summary-box").classList.toggle("hidden", (app.view === "wizard" && app.step === 3) || state.command !== "scan");
  history.replaceState(null, "", `#${fragment()}`);
}

function fragment() {
  return b.toFragment(app.data, app.state, app.shell,
    { view: app.view === "form" ? "form" : null, what: app.view === "wizard" ? app.state.what : null });
}

/** After a value changes: the panel, and what depends on it, without rebuilding the fields being typed in. */
export function refresh() {
  if (app.view === "form") refreshFormCounts();
  else refreshWizard(app, hooks);
  renderPanel();
}

export function render(focus = focusKey(document.activeElement), fallback = null) {
  radios($("views"), [["wizard", "Guided"], ["form", "All options"]], app.view, (v) => switchView(v));
  radios($("shells"), [["bash", "bash / zsh"], ["powershell", "PowerShell"]], app.shell,
    (s) => { app.shell = s; render(`shells:${s}`); });
  $("wizard").classList.toggle("hidden", app.view !== "wizard");
  $("form").classList.toggle("hidden", app.view !== "form");
  if (app.view === "form") renderForm();
  else renderWizard(app, hooks);
  renderPanel();
  restoreFocus(focus, fallback);
}

function switchView(view) {
  if (view === app.view) return;
  app.view = view;
  if (view === "wizard") {
    // The wizard covers scan. Values the form set are kept; the review step lists them all.
    if (app.state.command !== "scan") app.state = { command: "scan", values: {} };
    app.state.what = w.whatOf(app.wiz, app.state) === "path" ? null : w.whatOf(app.wiz, app.state);
    delete app.state.outcome;  // read again from the gates, which the form may have changed
    app.step = app.state.what ? 3 : 0;
  }
  render(`views:${view}`);
}

const hooks = { refresh, render, set, textInput, repeatableRows, choiceSelect };

// ---------------------------------------------------------------- start

function fromLink() {
  const got = b.fromFragment(app.data, location.hash);
  app.state = got.state;
  app.shell = got.shell;
  app.view = got.extra.view === "form" || app.state.command !== "scan" ? "form" : "wizard";  // the wizard: scan only
  if (app.view === "wizard") {
    // A link's first answer counts only while its options fit it (a link can say anything).
    const asked = w.target(app.wiz, got.extra.what) ? got.extra.what : null;
    const what = w.whatOf(app.wiz, { ...app.state, what: asked });
    app.state.what = what === "path" ? null : what;
    const given = Object.keys(app.state.values).some((d) => d !== "out");
    app.step = app.state.what && given ? 3 : 0;
    if (!app.state.values.out) app.state.values.out = "report";
  }
}

async function load(name) {
  const r = await fetch(name, { cache: "no-cache" });
  if (!r.ok) throw new Error(`${name}: HTTP ${r.status}`);
  return r.json();
}

async function main() {
  [app.data, app.rules, app.layout, app.wiz] = await Promise.all(
    ["options.json", "rules.json", "ui-groups.json", "wizard.json"].map(load));
  fromLink();
  $("version").textContent = `For oss-intake ${app.data.version}. Check yours with oss-intake --version.`;
  $("preset").addEventListener("change", (e) => {
    const p = app.layout.presets[Number(e.target.value)];
    if (!p) return;
    app.state = { command: p.command, values: structuredClone(p.values) };
    render("#preset");
    e.target.value = "";
  });
  $("reset").addEventListener("click", () => { app.state = { command: app.state.command, values: {} }; render("#reset"); });
  window.addEventListener("hashchange", () => {
    if (location.hash.slice(1) === fragment()) return;  // our own update
    fromLink();
    render();
  });
  $("copy").addEventListener("click", () => copy(b.buildCommand(app.data, app.state, app.shell), "Command"));
  $("link").addEventListener("click", () => copy(location.href, "Link"));
  $("back").addEventListener("click", () => { app.step = Math.max(0, app.step - 1); render(null); focusStep(); });
  $("next").addEventListener("click", () => {
    if (w.stepProblems(app.data, app.rules, app.wiz, app.state, app.step).length) return;
    app.step = Math.min(3, app.step + 1);
    render(null);
    focusStep();
  });
  render();
}

function focusStep() {
  $("step-title")?.focus();
}

main().catch((err) => {
  $("version").textContent = `The builder could not load its option list (${err.message}).`;
});
