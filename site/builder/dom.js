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
 * items: [value, label] or [value, label, hint]. */
export function radios(box, items, current, onPick) {
  const buttons = items.map(([value, label, hint]) => {
    const on = value === current;
    const button = el("button", { type: "button", role: "radio", "aria-checked": on,
      tabindex: on || (current === null && value === items[0][0]) ? "0" : "-1", "data-focus": `${box.id}:${value}` },
    hint ? el("span", { class: "choice-label", text: label }) : document.createTextNode(label),
    hint ? el("span", { class: "choice-hint", text: hint }) : null);
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

/** A command as one span per argument, so lines wrap between arguments and never inside one. */
export function commandSpans(words) {
  return words.flatMap((w, i) => [i ? " " : "", el("span", { class: w.length > 40 ? "arg long" : "arg", text: w })]);
}

/** "What this command will do" as a list of headed groups. */
export function summaryNodes(groups) {
  return groups.map((g) => el("div", { class: "sum" }, el("h3", { text: g.head }),
    el("ul", {}, ...g.items.map((t) => el("li", { text: t })))));
}
