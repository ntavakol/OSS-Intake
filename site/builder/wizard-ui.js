// oss-intake command builder: the guided wizard. Four steps over the same state as the full form; wizard.js
// decides what each step offers and when it is complete, and the command panel shows the command throughout.
import * as b from "./builder.js";
import * as w from "./wizard.js";
import { $, badge, el, icon, radios, summaryNodes } from "./dom.js";

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

function stepWhat(app, hooks) {
  const box = el("div", { class: "choices", role: "radiogroup", "aria-labelledby": "step-title", id: "targets" });
  radios(box, app.wiz.targets.map((t, i) => [t.id, t.label, t.hint, badge(t.icon, (i % 5) + 1)]), app.state.what ?? null, (id) => {
    app.state = w.choose(app.wiz, app.state, id);
    hooks.render(`targets:${id}`);
  });
  return [title("What are you checking?"), box];
}

function stepDetails(app, hooks) {
  const t = w.target(app.wiz, app.state.what);
  const dests = [...t.fields, ...(t.repo ? ["repo"] : [])];
  return [title(t.label), el("p", { class: "help", text: t.hint }),
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
  const parts = [title("What do you want back?"), outcomes];
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

function stepReview(app, hooks) {
  const groups = w.summary(app.data, app.wiz, app.state);
  const lines = w.explain(app.data, app.state);
  const extra = Object.keys(app.state.values).filter((d) => b.isSet(option(app, d), app.state.values[d])
    && !w.offered(app.wiz, app.state.what).includes(d));
  const toForm = el("button", { type: "button", class: "btn", text: "Change any option in All options", "data-focus": "to-form" });
  toForm.addEventListener("click", () => $("views").querySelector('[data-focus="views:form"]').click());
  return [
    title("Review"),
    el("p", { class: "help", text: "Check what the command will do, then copy it from the Command panel." }),
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
