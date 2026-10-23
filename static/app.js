"use strict";

// Everything coming back from lookups is attacker-influenced (DNS TXT records, HTTP headers,
// profile bios...), so the UI only ever inserts it with textContent - never innerHTML.

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const $ = (sel) => document.querySelector(sel);

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value == null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : value);
  }
  for (const child of children.flat()) {
    if (child == null || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

// ---------------------------------------------------------------------------
// theme + recent searches (per-browser conveniences only)
// ---------------------------------------------------------------------------

const store = {
  get(key, fallback) {
    try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch { return fallback; }
  },
  set(key, value) {
    try { localStorage.setItem(key, JSON.stringify(value)); } catch { /* private mode etc. */ }
  },
};

function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}
applyTheme(store.get("theme", null));
$("#theme").addEventListener("click", () => {
  const dark = document.documentElement.dataset.theme
    ? document.documentElement.dataset.theme === "dark"
    : matchMedia("(prefers-color-scheme: dark)").matches;
  const next = dark ? "light" : "dark";
  applyTheme(next);
  store.set("theme", next);
});

function renderRecent() {
  const recent = store.get("recent", []);
  const row = $("#recent");
  row.replaceChildren();
  if (!recent.length) { row.hidden = true; return; }
  row.hidden = false;
  row.append(el("span", { class: "muted", text: "Recent:" }));
  for (const item of recent) {
    row.append(el("button", { type: "button", class: "chip", text: item.q, onclick: () => start(item.q, item.type) }));
  }
}

function remember(q, type) {
  const recent = store.get("recent", []).filter((r) => r.q !== q);
  recent.unshift({ q, type });
  store.set("recent", recent.slice(0, 8));
  renderRecent();
}

// ---------------------------------------------------------------------------
// generic data rendering
// ---------------------------------------------------------------------------

const ACRONYMS = { ip: "IP", asn: "ASN", dns: "DNS", mx: "MX", spf: "SPF", dmarc: "DMARC", dkim: "DKIM", url: "URL",
  ptr: "PTR", cidr: "CIDR", tls: "TLS", http: "HTTP", https: "HTTPS", rdap: "RDAP", dnssec: "DNSSEC", rua: "RUA" };

function prettyKey(key) {
  if (/^[A-Z0-9]+$/.test(key) || /[-.@]/.test(key)) return key; // DNS record types, header names, hostnames
  const words = key.replace(/([a-z])([A-Z])/g, "$1 $2").split(/[_\s]+/);
  return words.map((w, i) => ACRONYMS[w.toLowerCase()] || (i === 0 ? w[0].toUpperCase() + w.slice(1) : w)).join(" ");
}

const isUrl = (s) => typeof s === "string" && /^https?:\/\/[^\s]+$/i.test(s);
const isPlain = (v) => v === null || ["string", "number", "boolean"].includes(typeof v);

function link(href, text) {
  return el("a", { href, target: "_blank", rel: "noopener noreferrer", text: text || href });
}

function renderScalar(v) {
  if (v === null || v === undefined || v === "") return el("span", { class: "no", text: "—" });
  if (v === true) return el("span", { class: "yes", text: "yes" });
  if (v === false) return el("span", { class: "no", text: "no" });
  if (isUrl(v)) return link(v);
  return document.createTextNode(String(v));
}

function renderTags(items, limit = 24) {
  const box = el("div", { class: "tags" });
  const shown = items.slice(0, limit);
  const make = (item) => (isUrl(item) ? el("span", { class: "tag" }, link(item)) : el("span", { class: "tag", text: String(item) }));
  box.append(...shown.map(make));
  if (items.length > limit) {
    const more = el("button", { type: "button", class: "more ghost", text: `+${items.length - limit} more` });
    more.addEventListener("click", () => { more.replaceWith(...items.slice(limit).map(make)); });
    box.append(more);
  }
  return box;
}

function renderRows(items) {
  // array of flat objects -> table with the union of keys as columns
  const cols = [...new Set(items.flatMap((o) => Object.keys(o)))];
  const table = el("table", { class: "rows" },
    el("thead", {}, el("tr", {}, cols.map((c) => el("th", { text: prettyKey(c) })))),
    el("tbody", {}, items.map((o) => el("tr", {}, cols.map((c) => el("td", {}, renderValue(o[c])))))));
  return el("div", { class: "table-scroll" }, table);
}

function renderValue(v) {
  if (isPlain(v) || v === undefined) return renderScalar(v);
  if (Array.isArray(v)) {
    if (!v.length) return renderScalar(null);
    if (v.every(isPlain)) return renderTags(v);
    if (v.every((o) => o && typeof o === "object" && !Array.isArray(o) && Object.values(o).every(isPlain))) {
      return renderRows(v);
    }
    return el("div", {}, v.map((item) => renderValue(item)));
  }
  return renderKV(v);
}

function renderKV(obj) {
  const entries = Object.entries(obj);
  if (!entries.length) return renderScalar(null);
  return el("table", { class: "kv" },
    el("tbody", {}, entries.map(([k, v]) => el("tr", {}, el("th", { text: prettyKey(k) }), el("td", {}, renderValue(v))))));
}

// ---------------------------------------------------------------------------
// results rendering
// ---------------------------------------------------------------------------

const state = { target: null, planned: [], reports: new Map(), startedAt: 0, controller: null, duration: null };

function sevBadge(sev) {
  return el("span", { class: `sev-badge sev-${sev}`, text: sev });
}

function allFindings() {
  const out = [];
  for (const r of state.reports.values()) for (const f of r.findings) out.push({ ...f, moduleTitle: r.title });
  return out.sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity));
}

function renderSummary() {
  const findings = allFindings();
  $("#tiles").replaceChildren(...SEVERITIES.map((s) => {
    const n = findings.filter((f) => f.severity === s).length;
    return el("div", { class: `tile sev-${s}${n ? "" : " zero"}` }, el("b", { text: n }), el("span", { text: s }));
  }));

  const list = $("#findings");
  if (!findings.length) {
    const done = state.reports.size === state.planned.length;
    list.replaceChildren(el("li", { class: "empty", text: done ? "No issues found by the modules that ran." : "Waiting for results…" }));
  } else {
    list.replaceChildren(...findings.map((f) => el("li", { class: `sev-${f.severity}` },
      sevBadge(f.severity),
      el("div", { class: "finding-title", text: f.title }),
      f.detail ? el("div", { class: "finding-detail", text: f.detail }) : null,
      el("div", { class: "finding-module", text: f.moduleTitle }))));
  }

  const total = state.planned.length || 1;
  $("#progress-bar").style.width = `${Math.round((state.reports.size / total) * 100)}%`;
  const done = state.reports.size === state.planned.length;
  $("#t-status").textContent = done
    ? `${state.planned.length} module${state.planned.length === 1 ? "" : "s"} finished in ${((state.duration ?? 0) / 1000).toFixed(1)} s`
    : `${state.reports.size} of ${state.planned.length} modules finished…`;
  $("#export").disabled = !done;
}

function moduleCard(mod) {
  return el("article", { class: "card loading", id: `m-${mod.id}` },
    el("div", { class: "card-head" }, el("h4", { text: mod.title }), el("span", { class: "card-meta" }, el("span", { class: "spinner" }), "running")),
    el("p", { class: "card-summary", text: "Looking up…" }));
}

function fillCard(r) {
  const meta = [`${r.duration_ms} ms`];
  if (r.cached) meta.push("cached");
  const card = el("article", { class: `card is-${r.status}`, id: `m-${r.id}` },
    el("div", { class: "card-head" },
      el("h4", { text: r.title }),
      el("span", { class: "card-meta" }, el("span", { class: `status status-${r.status}`, text: r.status }), ` · ${meta.join(" · ")}`)),
    el("p", { class: "card-summary", text: r.summary }));

  if (r.findings.length) {
    card.append(el("ul", { class: "card-findings" },
      r.findings.map((f) => el("li", { class: `sev-${f.severity}` }, sevBadge(f.severity), el("span", { text: f.title })))));
  }
  if (r.data && Object.keys(r.data).length) card.append(renderKV(r.data));
  const links = Object.entries(r.links || {});
  if (links.length) card.append(el("div", { class: "links" }, links.map(([label, href]) => link(href, `Open in ${label} ↗`))));

  const old = document.getElementById(`m-${r.id}`);
  if (old) old.replaceWith(card); else $("#modules").append(card);
}

// ---------------------------------------------------------------------------
// streaming lookup (fetch + a tiny Server-Sent Events parser, so HTTP errors are readable)
// ---------------------------------------------------------------------------

function showError(message) {
  const box = $("#error");
  box.textContent = message;
  box.hidden = !message;
}

async function start(q, type = "auto") {
  q = q.trim();
  if (!q) return;
  $("#q").value = q;
  $("#kind").value = type;
  state.controller?.abort();
  const controller = new AbortController();
  state.controller = controller;

  showError("");
  document.body.classList.add("compact");
  $("#go").disabled = true;
  const params = new URLSearchParams({ q });
  if (type && type !== "auto") params.set("type", type);
  history.replaceState(null, "", `?${params}`);

  try {
    const resp = await fetch(`/api/stream?${params}`, { signal: controller.signal });
    if (!resp.ok) {
      const body = await resp.json().catch(() => ({}));
      throw new Error(body.error || `Request failed (HTTP ${resp.status})`);
    }
    const reader = resp.body.pipeThrough(new TextDecoderStream()).getReader();
    let buffer = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += value;
      let cut;
      while ((cut = buffer.indexOf("\n\n")) >= 0) {
        const chunk = buffer.slice(0, cut);
        buffer = buffer.slice(cut + 2);
        const event = /^event: (.*)$/m.exec(chunk)?.[1];
        const data = chunk.split("\n").filter((l) => l.startsWith("data: ")).map((l) => l.slice(6)).join("\n");
        if (event && data) handle(event, JSON.parse(data));
      }
    }
    remember(q, type);
  } catch (err) {
    if (err.name !== "AbortError") {
      showError(err.message || String(err));
      if (!state.reports.size) $("#results").hidden = true;
    }
  } finally {
    if (state.controller === controller) $("#go").disabled = false;
  }
}

function handle(event, data) {
  if (event === "start") {
    state.target = data.target;
    state.planned = data.modules;
    state.reports = new Map();
    state.duration = null;
    $("#results").hidden = false;
    $("#t-kind").textContent = data.target.kind;
    $("#t-value").textContent = data.target.value;
    $("#modules").replaceChildren(...data.modules.map(moduleCard));
    renderSummary();
  } else if (event === "module") {
    state.reports.set(data.id, data);
    fillCard(data);
    renderSummary();
  } else if (event === "done") {
    state.duration = data.duration_ms;
    renderSummary();
  }
}

// ---------------------------------------------------------------------------
// actions
// ---------------------------------------------------------------------------

$("#search").addEventListener("submit", (e) => {
  e.preventDefault();
  start($("#q").value, $("#kind").value);
});

$("#examples").addEventListener("click", (e) => {
  const q = e.target.closest("[data-q]")?.dataset.q;
  if (q) start(q, "auto");
});

$("#copy-link").addEventListener("click", async (e) => {
  const button = e.currentTarget;
  try {
    await navigator.clipboard.writeText(location.href);
    button.textContent = "Copied";
  } catch {
    button.textContent = "Copy failed";
  }
  setTimeout(() => { button.textContent = "Copy link"; }, 1500);
});

$("#export").addEventListener("click", () => {
  const order = state.planned.map((m) => m.id);
  const report = {
    target: state.target,
    generated_at: new Date().toISOString(),
    findings: allFindings().map(({ moduleTitle, ...f }) => f),
    modules: [...state.reports.values()].sort((a, b) => order.indexOf(a.id) - order.indexOf(b.id)),
  };
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const safe = state.target.value.replace(/[^a-z0-9._-]+/gi, "_");
  el("a", { href: url, download: `osint-${safe}.json` }).click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});

renderRecent();
const initial = new URLSearchParams(location.search);
if (initial.get("q")) start(initial.get("q"), initial.get("type") || "auto");
