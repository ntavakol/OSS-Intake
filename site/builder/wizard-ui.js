// oss-intake command builder: the guided wizard. Four steps over the same state as the full form; wizard.js
// decides what each step offers and when it is complete, and the command panel shows the command throughout.
import * as b from "./builder.js";
import * as w from "./wizard.js";
import { $, badge, copy, el, icon, radios, summaryNodes } from "./dom.js";
import { detect } from "./detect.js";

function option(app, dest) {
  return b.optionsFor(app.data, "scan").find((o) => o.dest === dest);
}

function progress(app, hooks) {
  $("progress").replaceChildren(...w.STEPS.map((name, i) => {
    const mark = el("span", { class: "dot", "aria-hidden": "true" }, i < app.step ? icon("check") : document.createTextNode(String(i + 1)));
    const label = el("span", { class: "step-name", text: name });
    const state = i < app.step ? "done" : i === app.step ? "current" : "";
    if (i < app.step) {
      const go = el("button", { type: "button", class: "step-link", "data-focus": `progress:${i}`,
        "aria-label": `Step ${i + 1}, ${name}, done: go back to it` }, mark, label);
      go.addEventListener("click", () => { app.step = i; hooks.render(null); $("step-title").focus(); });
      return el("li", { class: state }, go);
    }
    return el("li", { class: state, "aria-current": i === app.step ? "step" : null },
      el("span", { class: "step-link" }, mark, el("span", { class: "visually-hidden", text: `Step ${i + 1}, ` }), label));
  }));
}

/** One question: the wizard's label, the flag it sets, a hint, the input, and the field's problems. */
function question(app, hooks, dest, input, id) {
  const f = app.wiz.fields[dest];
  const o = option(app, dest);
  return el("div", { class: "field q", "data-field": dest },
    el("label", { for: id }, el("span", { class: "q-label", text: f.label }), " ", el("span", { class: "flag", text: o.flag })),
    input,
    el("span", { class: "about", id: `${id}-help`, text: f.hint }),
    el("span", { class: "error", id: `${id}-err`, "data-error": dest }));
}

function field(app, hooks, dest) {
  const o = option(app, dest);
  const f = app.wiz.fields[dest];
  const id = `w-${dest}`;
  const describedby = `${id}-help ${id}-err`;
  const placeholder = typeof f.placeholder === "object" ? f.placeholder[app.state.what] : f.placeholder;
  if (o.kind === "repeatable") {
    return question(app, hooks, dest, el("div", {}, ...hooks.repeatableRows(o, id, describedby, placeholder)), id);
  }
  if (o.kind === "choice") return question(app, hooks, dest, hooks.choiceSelect(o, id, describedby, f.default_label), id);
  return question(app, hooks, dest, hooks.textInput(o, app.state.values[dest], (text) => hooks.set(dest, text),
    { id, describedby, placeholder }), id);
}

function title(text) {
  return el("h2", { id: "step-title", tabindex: "-1", text });
}

const EXAMPLES = ["npm install chalk@5.6.1", "docker pull nginx:1.27", "https://github.com/owner/name", "package-lock.json"];

/** Use a result from the paste box: a fresh check of that kind, with its values, then on to the next question. */
function usePasted(app, hooks, result) {
  const fresh = w.choose(app.wiz, { command: "scan", values: {} }, result.what);
  app.state = { ...fresh, values: { ...fresh.values, ...result.values } };
  const complete = w.stepProblems(app.data, app.rules, app.wiz, app.state, 1).length === 0;
  app.step = complete ? 2 : 1;
  app.pasted = { says: result.says };
  hooks.render(null);
  $("step-title")?.focus();
}

function pasteResult(app, hooks, result, box, input) {
  const nodes = [];
  if (result.status === "ok") {
    nodes.push(el("p", { class: "found" }, el("strong", { text: "Recognised: " }),
      document.createTextNode(`${result.says}. Press Set it up to continue.`)));
  } else if (result.status === "ask") {
    nodes.push(el("p", { class: "found", text: result.says }));
    const row = el("div", { class: "pick", role: "group", "aria-label": result.says });
    for (const c of result.choices) {
      const btn = el("button", { type: "button", class: "btn", text: c.label });
      btn.addEventListener("click", () => {
        if (c.status === "ok") { usePasted(app, hooks, c); return; }
        // The button that had focus is gone: give it back to the box, with the reason read out.
        pasteResult(app, hooks, c, box, input);
        input.focus();
      });
      row.append(btn);
    }
    nodes.push(row);
  } else if (result.says) {
    nodes.push(el("p", { class: result.status === "no" ? "cannot" : "found", text: result.says }));
  }
  box.replaceChildren(...nodes);
}

function pasteBox(app, hooks) {
  const input = el("input", { type: "text", id: "w-paste", autocomplete: "off", spellcheck: "false",
    placeholder: "a link, an install command, a package, an image or a file name", "aria-describedby": "w-paste-help" });
  const result = el("div", { id: "w-paste-result", role: "status" });
  const go = el("button", { type: "button", class: "btn primary", id: "w-paste-go", text: "Set it up" });
  let timer = null;
  const run = (apply) => {
    clearTimeout(timer);
    const r = detect(input.value, { wiz: app.wiz, rules: app.rules });
    if (apply && r.status === "ok") usePasted(app, hooks, r);
    else pasteResult(app, hooks, r, result, input);
  };
  // While typing, wait for a pause, so a screen reader is not told about every letter.
  input.addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(() => run(false), 400); });
  input.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); run(true); } });
  go.addEventListener("click", () => run(true));
  const tries = EXAMPLES.map((x) => {
    const t = el("button", { type: "button", class: "chip-btn", text: x });
    t.addEventListener("click", () => { input.value = x; run(false); input.focus(); });
    return t;
  });
  return el("section", { class: "paste", "aria-labelledby": "w-paste-label" },
    el("label", { for: "w-paste", id: "w-paste-label", class: "paste-label", text: "Paste what you were given" }),
    el("p", { class: "help", id: "w-paste-help", text: "A GitHub, npm, PyPI, Maven or Docker Hub link; a command such as "
      + "npm install, pip install or docker pull; a package such as npm:chalk@5.6.1; an image such as nginx:1.27; or a "
      + "file name such as package-lock.json. Nothing you paste leaves this page." }),
    el("div", { class: "paste-row" }, input, go),
    el("div", { class: "tries" }, el("span", { text: "Try:" }), ...tries),
    result);
}

function stepWhat(app, hooks) {
  const box = el("div", { class: "choices", role: "radiogroup", "aria-labelledby": "choose-title", id: "targets" });
  radios(box, app.wiz.targets.map((t, i) => [t.id, t.label, t.hint, badge(t.icon, (i % 5) + 1)]), app.state.what ?? null, (id) => {
    app.state = w.choose(app.wiz, app.state, id);
    app.pasted = null;
    hooks.render(`targets:${id}`);
  });
  return [title("What are you checking?"), pasteBox(app, hooks),
    el("h3", { class: "or", id: "choose-title", text: "Or choose what you are checking" }), box];
}

/** After the paste box set things up: what it recognised, shown once on the next step. */
function pastedNote(app) {
  if (!app.pasted) return null;
  const note = el("p", { class: "pasted" }, el("strong", { text: "Set up from what you pasted: " }),
    document.createTextNode(`${app.pasted.says}. Check the details, then Next.`));
  return note;
}

function stepDetails(app, hooks) {
  const t = w.target(app.wiz, app.state.what);
  const dests = [...t.fields, ...(t.repo ? ["repo"] : [])];
  return [title(t.label), pastedNote(app), el("p", { class: "help", text: t.hint }),
    el("div", { class: "questions" }, ...dests.map((d) => field(app, hooks, d)))];
}

function stepOutcome(app, hooks) {
  const t = w.target(app.wiz, app.state.what);
  const outcome = w.outcomeOf(app.state);
  const outcomes = el("div", { class: "choices two", role: "radiogroup", "aria-label": "What do you want back?", id: "outcomes" });
  const items = app.wiz.outcomes.map((x) => [x.id, x.label, x.hint]);
  radios(outcomes, items, outcome, (id) => {
    app.state = w.setOutcome(app.state, id);
    hooks.render(`outcomes:${id}`);
  });
  const parts = [title("What do you want back?"), pastedNote(app), outcomes];
  if (outcome === "gate") {
    const chosen = new Set(w.gatesOf(app.state.values.fail_on));
    const boxes = [];
    for (const id of w.gatesFor(app.data, app.wiz, app.state)) {
      const g = app.wiz.gates.find((x) => x.id === id);
      const cid = `w-gate-${id}`;
      const box = el("input", { type: "checkbox", id: cid, checked: chosen.has(id), "aria-describedby": "w-fail_on-err" });
      box.addEventListener("change", () => { app.state = w.toggleGate(app.wiz, app.state, id, box.checked); hooks.refresh(); });
      boxes.push(el("div", { class: "field check" }, box, el("label", { for: cid }, g.label,
        g.recommended ? el("span", { class: "tag", text: "recommended" }) : null)));
    }
    if (boxes.length) {
      parts.push(el("fieldset", { class: "gates field", "data-field": "fail_on" },
        el("legend", {}, "Fail if ", el("span", { class: "flag", text: "--fail-on" })), ...boxes,
        el("span", { class: "error", id: "w-fail_on-err", "data-error": "fail_on" })));
    }
    parts.push(el("div", { class: "questions" }, field(app, hooks, "fail_on_likelihood")));
  }
  parts.push(el("div", { class: "questions" }, field(app, hooks, "out")));
  return parts;
}

function checkItem(item) {
  const li = el("li", {}, el("span", { text: item.text }));
  for (const c of item.code ?? []) {
    const btn = el("button", { type: "button", class: "btn small", text: "Copy", "aria-label": `Copy ${c}` });
    btn.addEventListener("click", () => copy(c, "Command"));
    li.append(el("div", { class: "code-row" }, el("code", { text: c }), btn));
  }
  if (item.link) li.append(" ", el("a", { href: item.link.href, text: item.link.text }));
  return li;
}

function checklistNodes(app) {
  const { before, after } = w.checklist(app.data, app.wiz, app.state, app.shell);
  return [
    el("h3", { class: "sum-title", text: "Before you run it" }), el("ul", { class: "checklist" }, ...before.map(checkItem)),
    el("h3", { class: "sum-title", text: "After it runs" }), el("ul", { class: "checklist" }, ...after.map(checkItem)),
  ];
}

function stepReview(app, hooks) {
  const groups = w.summary(app.data, app.wiz, app.state);
  const lines = w.explain(app.data, app.state);
  const extra = Object.keys(app.state.values).filter((d) => b.isSet(option(app, d), app.state.values[d])
    && !w.offered(app.wiz, app.state.what).includes(d));
  const toForm = el("button", { type: "button", class: "btn", text: "Change any option in All options", "data-focus": "to-form" });
  toForm.addEventListener("click", () => $("views").querySelector('[data-focus="views:form"]').click());
  return [
    title("Review"),
    el("p", { class: "help", text: "Copy the command from the Command panel. Here is what you need, what to do after, "
      + "and exactly what the command will do." }),
    ...checklistNodes(app),
    el("section", { class: "summary inline", "aria-label": "What this command will do" },
      el("h3", { class: "sum-title", text: "What this command will do" }), ...summaryNodes(groups)),
    el("h3", { class: "sum-title", text: "Each option in the command" }),
    el("dl", { class: "explain" }, ...lines.flatMap((l) => [el("dt", { class: "flag", text: l.flag }), el("dd", { text: l.help })])),
    extra.length ? el("p", { class: "help", text: "Includes options set in All options." }) : null,
    toForm,
  ];
}

export function renderWizard(app, hooks) {
  progress(app, hooks);
  const step = [stepWhat, stepDetails, stepOutcome, stepReview][app.step];
  $("step").replaceChildren(...step(app, hooks).filter(Boolean));
  refreshWizard(app, hooks);
}

/** What changes as the person types: whether Next is allowed, and why not. */
export function refreshWizard(app) {
  const why = w.stepProblems(app.data, app.rules, app.wiz, app.state, app.step);
  $("back").classList.toggle("hidden", app.step === 0);
  $("next").classList.toggle("hidden", app.step === 3);
  $("next").setAttribute("aria-disabled", why.length ? "true" : "false");
  $("next").setAttribute("aria-describedby", "next-why");
  $("next-why").textContent = app.step < 3 && why.length ? why[0].message : "";
}
