// oss-intake command builder: small DOM helpers shared by the wizard and the full form. Elements are built with
// createElement and textContent only, never from HTML text, as the page's Content Security Policy expects.

export const $ = (id) => document.getElementById(id);

export function el(tag, attrs = {}, ...children) {
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

/** A radio group as buttons: one tab stop (the checked one), arrow keys move and pick, as WAI-ARIA describes.
 * items: [value, label], or [value, label, hint, art] where art is an optional element shown first. */
export function radios(box, items, current, onPick) {
  const buttons = items.map(([value, label, hint, art]) => {
    const on = value === current;
    const text = hint ? el("span", { class: "choice-text" }, el("span", { class: "choice-label", text: label }),
      el("span", { class: "choice-hint", text: hint })) : document.createTextNode(label);
    const button = el("button", { type: "button", role: "radio", "aria-checked": on,
      tabindex: on || (current === null && value === items[0][0]) ? "0" : "-1", "data-focus": `${box.id}:${value}` },
    art ?? null, text);
    button.addEventListener("click", () => onPick(value));
    return button;
  });
  box.onkeydown = (e) => {
    const step = { ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1 }[e.key];
    if (!step) return;
    e.preventDefault();
    const at = items.findIndex(([v]) => v === current);
    const i = at < 0 ? (step > 0 ? -1 : 0) : at;  // nothing picked yet: Down picks the first, Up the last
    onPick(items[(i + step + items.length) % items.length][0]);
  };
  box.replaceChildren(...buttons);
}

// Rebuilding part of the page loses the keyboard focus, so it is put back where it was (or on a fallback).
export function focusKey(node) {
  return node?.dataset?.focus ?? (node?.id ? `#${node.id}` : null);
}

export function restoreFocus(key, fallback) {
  if (!key) return;
  const node = key.startsWith("#") ? document.getElementById(key.slice(1))
    : document.querySelector(`[data-focus="${CSS.escape(key)}"]`);
  (node ?? (fallback && document.getElementById(fallback)))?.focus();
}

export async function copy(text, what) {
  try {
    await navigator.clipboard.writeText(text);
    $("status").textContent = `${what} copied`;
  } catch {
    $("status").textContent = `Could not copy: select the ${what.toLowerCase()} and copy it yourself`;
  }
  setTimeout(() => { $("status").textContent = ""; }, 4000);
}

/** A command as one span per argument, so lines wrap between arguments and never inside one. Flags are marked,
 * so they can be shown in their own colour. */
export function commandSpans(words) {
  return words.flatMap((w, i) => [i ? " " : "", el("span", {
    class: [w.length > 40 ? "arg long" : "arg", /^--[a-z]/.test(w) ? "opt" : ""].join(" ").trim(), text: w })]);
}

// ---------------------------------------------------------------- icons

// Line icons, 24 by 24, drawn with the page's own code (no icon library): each is a list of SVG elements.
export const ICONS = {
  doc: [["path", "M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"], ["path", "M14 3v6h6M8 13h8M8 17h6"]],
  cube: [["path", "M21 8 12 3 3 8v8l9 5 9-5z"], ["path", "M3 8l9 5 9-5M12 13v8"]],
  archive: [["path", "M3 7h18v13H3zM3 7l2-4h14l2 4M9 11h6"]],
  code: [["path", "M8 7l-5 5 5 5M16 7l5 5-5 5M14 4l-4 16"]],
  list: [["path", "M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01"]],
  tag: [["path", "M20.6 13.4 13.4 20.6a2 2 0 0 1-2.8 0L3 13V3h10l7.6 7.6a2 2 0 0 1 0 2.8z"], ["path", "M7.5 7.5h.01"]],
  branch: [["circle", "6,6,2"], ["circle", "6,18,2"], ["circle", "18,8,2"], ["path", "M6 8v8M18 10c0 4-6 3-10 6"]],
  check: [["path", "M20 6 9 17l-5-5"]],
  search: [["circle", "11,11,6"], ["path", "M20 20l-4.3-4.3M11 8v6M8 11h6"]],
  flag: [["path", "M5 21V4M5 4s1.5-1 4-1 4.5 2 7 2 3-1 3-1v10s-.5 1-3 1-4.5-2-7-2-4 1-4 1"]],
  alert: [["path", "M12 3 2 20h20z"], ["path", "M12 10v4M12 17h.01"]],
  file: [["path", "M14 3H6a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9z"], ["path", "M14 3v6h6M12 12v6M9 15l3 3 3-3"]],
  send: [["path", "M3 12h13M12 6l6 6-6 6M21 4v16"]],
  noeye: [["path", "M3 3l18 18M10.6 6.1A9.8 9.8 0 0 1 12 6c5 0 9 6 9 6a17 17 0 0 1-2.6 3.2M6.6 6.6C4.3 8.1 3 12 3 12s4 6 9 6c1.6 0 3-.4 4.3-1"], ["path", "M9.9 9.9a3 3 0 0 0 4.2 4.2"]],
  laptop: [["rect", "4,5,16,11,2"], ["path", "M2 20h20"]],
};
const NS = "http://www.w3.org/2000/svg";

/** An icon as an SVG element, hidden from screen readers (the text beside it says the same). */
export function icon(name) {
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", "0 0 24 24");
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  for (const [tag, spec] of ICONS[name] ?? []) {
    const node = document.createElementNS(NS, tag);
    if (tag === "path") node.setAttribute("d", spec);
    if (tag === "circle") { const [cx, cy, r] = spec.split(","); Object.entries({ cx, cy, r }).forEach(([k, v]) => node.setAttribute(k, v)); }
    if (tag === "rect") {
      const [x, y, width, height, rx] = spec.split(",");
      Object.entries({ x, y, width, height, rx }).forEach(([k, v]) => node.setAttribute(k, v));
    }
    svg.append(node);
  }
  return svg;
}

/** An icon in a round badge; tone picks its colour (1 to 5). */
export function badge(name, tone = 1, small = false) {
  return el("span", { class: `badge t${tone}${small ? " sm" : ""}` }, icon(name));
}

const HEADS = { Checks: ["check", 1], "Also checks": ["search", 2], Flags: ["flag", 3], Fails: ["alert", 2],
  Writes: ["file", 4], Contacts: ["send", 4], "Doesn't check": ["noeye", 5] };

/** What leaves the computer, as a picture: this computer, then one chip per service with what it is sent. A
 * dashed chip is a service used only if vulnerabilities are found. The sentences below it say the same. */
function flow(group) {
  const chips = group.services.map((s) => el("li", { class: s.if_found ? "chip maybe" : "chip" },
    el("strong", { text: s.name }), el("span", { text: s.sends })));
  return el("div", { class: "flow" },
    el("div", { class: "from" }, badge("laptop", 1, true), el("strong", { text: "Your computer" }),
      el("span", { class: "arrow", "aria-hidden": "true" }), el("span", { text: chips.length ? "sends to" : "" })),
    chips.length ? el("ul", { class: "chips", "aria-label": "Services it contacts" }, ...chips)
      : el("p", { class: "none", text: "Nothing is sent by oss-intake itself." }),
    group.services.some((s) => s.if_found)
      ? el("p", { class: "legend", text: "Dashed: only if it finds vulnerabilities." }) : null);
}

/** "What this command will do" as headed groups, each with its icon; Contacts as the picture plus its notes. */
export function summaryNodes(groups) {
  return groups.map((g) => {
    const [name, tone] = HEADS[g.head] ?? ["check", 1];
    const head = el("h3", {}, badge(name, tone, true), el("span", { text: g.head === "Contacts" ? "What leaves your computer" : g.head }));
    if (g.head === "Contacts" && g.services) {
      return el("div", { class: "sum" }, head, flow(g), g.notes.length ? el("ul", {}, ...g.notes.map((t) => el("li", { text: t }))) : null);
    }
    return el("div", { class: "sum" }, head, el("ul", {}, ...g.items.map((t) => el("li", { text: t }))));
  });
}
