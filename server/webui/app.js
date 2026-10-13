/* GAIDE-Trace console — vanilla JS, no dependencies.
   Talks to the API with the bearer key kept in localStorage; every view is
   rendered into <main> via hash routing. */

"use strict";

const $ = (sel, el) => (el || document).querySelector(sel);
const main = $("#main");
const tooltip = $("#tooltip");

const state = {
  me: null,
  token: localStorage.getItem("gt_session") || "",
  filters: { project: "", range: "30" },   // shared by overview + sessions
  sessionsPage: 0,
  sessionsModel: "",
};

// ---------------------------------------------------------------- helpers

function esc(s) {
  return String(s == null ? "" : s)
    .replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function fmt(n) {
  if (n == null) return "–";
  n = Number(n);
  if (Math.abs(n) >= 1e9) return (n / 1e9).toFixed(1) + "B";
  if (Math.abs(n) >= 1e6) return (n / 1e6).toFixed(1) + "M";
  if (Math.abs(n) >= 1e4) return (n / 1e3).toFixed(1) + "K";
  return n.toLocaleString("en-US");
}

function fmtTime(iso) {
  if (!iso) return "–";
  const d = new Date(iso);
  if (isNaN(d)) return iso;
  return d.toLocaleString(undefined, {
    day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit",
  });
}

function timeAgo(iso) {
  if (!iso) return "";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 90) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

function rangeFrom(range) {
  if (range === "all") return "";
  const d = new Date(Date.now() - Number(range) * 86400e3);
  return d.toISOString().slice(0, 10);
}

function qs(params) {
  const p = Object.entries(params).filter(([, v]) => v !== "" && v != null);
  return p.length ? "?" + p.map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join("&") : "";
}

async function api(path, opts) {
  // keepSession: on a 401, throw without signing out, for a caller that must
  // first show what it did (the price import's per-row results).
  const { keepSession, ...fetchOpts } = opts || {};
  const res = await fetch(path, {
    ...fetchOpts,
    headers: {
      Authorization: "Bearer " + state.token,
      ...(fetchOpts.body ? { "Content-Type": "application/json" } : {}),
      ...fetchOpts.headers,
    },
  });
  if (res.status === 401) { if (!keepSession) logout(); throw new Error("unauthorized"); }
  if (!res.ok) {
    let msg = res.statusText;
    try { msg = (await res.json()).error || msg; } catch (e) { /* keep statusText */ }
    throw new Error(msg);
  }
  return res;
}

const apiJSON = (path, opts) => api(path, opts).then((r) => r.json());

async function download(path) {
  const res = await api(path);
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") || "";
  const name = (cd.match(/filename="([^"]+)"/) || [])[1] || "export.jsonl";
  const url = URL.createObjectURL(blob);
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------- tooltip

function showTooltip(html, x, y) {
  tooltip.innerHTML = html;
  tooltip.classList.remove("hidden");
  const r = tooltip.getBoundingClientRect();
  const px = Math.min(x + 14, window.innerWidth - r.width - 10);
  const py = Math.max(y - r.height - 12, 8);
  tooltip.style.left = px + "px";
  tooltip.style.top = py + "px";
}
const hideTooltip = () => tooltip.classList.add("hidden");

// ---------------------------------------------------------------- charts
// Marks follow the dataviz spec: bars ≤24px with 4px rounded data-end and a
// square baseline, 2px surface gaps, solid hairline grid, text in ink tokens.

// Carbon ramp steps (purple 60, teal 50), CVD-validated on the tile surface.
const SERIES = [
  { key: "prompts", label: "Prompts", color: "var(--series-1)", hex: "#8a3ffc" },
  { key: "tool_calls", label: "Tool calls", color: "var(--series-2)", hex: "#009d9a" },
];

function niceMax(v) {
  if (v <= 5) return 5;
  const pow = Math.pow(10, Math.floor(Math.log10(v)));
  for (const m of [1, 2, 2.5, 5, 10]) if (v <= m * pow) return m * pow;
  return 10 * pow;
}

function barRect(x, y, w, h, fill) {
  // Carbon chart bars: flat, square-cornered
  if (h <= 0 && w <= 0) return "";
  return `<rect x="${x}" y="${y}" width="${Math.max(w, 0)}" height="${Math.max(h, 0)}"
    fill="${fill}"></rect>`;
}

/* Fill calendar gaps so the time axis is honest (a day with no events is a
   zero, not a missing slot). */
function fillDays(days) {
  if (days.length < 2) return days;
  const calendar = calendarDays(days[0].day, days[days.length - 1].day);
  if (!calendar) return days;
  const byDay = Object.fromEntries(days.map((d) => [d.day, d]));
  return calendar.map((day) => byDay[day] || { day, prompts: 0, tool_calls: 0 });
}

// Timestamps are client-supplied; one event dated year 1 would otherwise ask
// for ~740,000 calendar slots. Past this span the axis shows only days with data.
const MAX_FILLED_DAYS = 1100;

/* Every UTC day from first to last inclusive, or null when the span is too
   long to draw day by day. */
function calendarDays(first, last) {
  const start = new Date(first + "T00:00:00Z").getTime();
  const end = new Date(last + "T00:00:00Z").getTime();
  if (!(end >= start) || (end - start) / 86400e3 > MAX_FILLED_DAYS) return null;
  const out = [];
  for (let t = start; t <= end; t += 86400e3) out.push(new Date(t).toISOString().slice(0, 10));
  return out;
}

// Math.max(...arr) passes every element as an argument and overflows the call
// stack on long arrays.
const maxOf = (items, f) => items.reduce((m, x) => Math.max(m, f(x)), 1);

/* Grouped columns per day, two series, hover band + tooltip, table twin. */
function activityChart(container, days) {
  days = fillDays(days);
  const W = 640, H = 240, padL = 46, padR = 10, padT = 10, padB = 26;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const max = niceMax(maxOf(days, (d) => Math.max(d.prompts || 0, d.tool_calls || 0)));
  const ticks = [0, max / 2, max].map((t) => Math.round(t));
  const n = Math.max(days.length, 1);
  const band = plotW / n;
  const gap = 2;                                   // surface gap between bars
  const barW = Math.min(24, Math.max(2, (band - gap * 3) / 2));
  const groupW = barW * 2 + gap;
  const y = (v) => padT + plotH * (1 - v / max);

  let bars = "", bands = "";
  days.forEach((d, i) => {
    const gx = padL + band * i + (band - groupW) / 2;
    SERIES.forEach((s, si) => {
      const v = d[s.key] || 0;
      const by = y(v);
      bars += barRect(gx + si * (barW + gap), by, barW, padT + plotH - by, s.hex);
    });
    bands += `<rect class="hover-band" data-i="${i}" x="${padL + band * i}" y="${padT}"
               width="${band}" height="${plotH}" fill="transparent"></rect>`;
  });

  const grid = ticks.map((t) =>
    `<line x1="${padL}" x2="${W - padR}" y1="${y(t)}" y2="${y(t)}"
       stroke="${t === 0 ? "var(--baseline)" : "var(--grid)"}" stroke-width="1"></line>
     <text x="${padL - 8}" y="${y(t) + 4}" text-anchor="end" fill="var(--ink-3)"
       font-size="10" style="font-variant-numeric:tabular-nums">${fmt(t)}</text>`).join("");

  const labelEvery = Math.ceil(n / 8);
  const xlabels = days.map((d, i) => i % labelEvery ? "" :
    `<text x="${padL + band * i + band / 2}" y="${H - 8}" text-anchor="middle"
       fill="var(--ink-3)" font-size="10">${esc(d.day.slice(5))}</text>`).join("");

  container.innerHTML = `
    <div class="legend">${SERIES.map((s) =>
      `<span class="key"><span class="swatch" style="background:${s.color}"></span>${s.label}</span>`).join("")}
    </div>
    <div class="chart-wrap"><svg viewBox="0 0 ${W} ${H}" role="img"
      aria-label="Prompts and tool calls per day">${grid}${bars}${xlabels}${bands}</svg></div>`;

  container.querySelectorAll(".hover-band").forEach((band_) => {
    band_.addEventListener("mousemove", (e) => {
      const d = days[Number(band_.dataset.i)];
      showTooltip(`<div class="tt-title">${esc(d.day)}</div>` +
        SERIES.map((s) => `<div class="tt-row"><span class="swatch" style="background:${s.color}"></span>
          ${s.label}<b>${fmt(d[s.key] || 0)}</b></div>`).join(""), e.clientX, e.clientY);
    });
    band_.addEventListener("mouseleave", hideTooltip);
  });
}

function activityTable(container, days) {
  container.innerHTML = `<div class="table-scroll"><table>
    <thead><tr><th>Day</th><th class="num">Prompts</th><th class="num">Tool calls</th></tr></thead>
    <tbody>${days.map((d) => `<tr><td>${esc(d.day)}</td>
      <td class="num">${fmt(d.prompts || 0)}</td><td class="num">${fmt(d.tool_calls || 0)}</td></tr>`).join("")}
    </tbody></table></div>`;
}

/* Horizontal bars, single series (slot 1), value at the tip. */
function toolsChart(container, rows) {
  const max = Math.max(1, ...rows.map((r) => r.n));
  const rowH = 26, barH = 12, labelW = 120, valW = 52;
  const W = 420, H = rows.length * rowH + 6;
  let svg = "";
  rows.forEach((r, i) => {
    const y0 = i * rowH + (rowH - barH) / 2;
    const w = Math.max(2, (W - labelW - valW) * (r.n / max));
    svg += `
      <text x="${labelW - 10}" y="${y0 + barH - 2}" text-anchor="end"
        fill="var(--ink-2)" font-size="11">${esc(r.tool.length > 15 ? r.tool.slice(0, 14) + "…" : r.tool)}</text>
      ${barRect(labelW, y0, w, barH, "#8a3ffc")}
      <text x="${labelW + w + 8}" y="${y0 + barH - 2}" fill="var(--ink-3)" font-size="10"
        style="font-variant-numeric:tabular-nums">${fmt(r.n)}</text>
      <rect class="hover-band" data-i="${i}" x="0" y="${i * rowH}" width="${W}" height="${rowH}"
        fill="transparent"></rect>`;
  });
  container.innerHTML = `<div class="chart-wrap"><svg viewBox="0 0 ${W} ${H}" role="img"
    aria-label="Tool calls by tool">${svg}</svg></div>`;
  container.querySelectorAll(".hover-band").forEach((b) => {
    b.addEventListener("mousemove", (e) => {
      const r = rows[Number(b.dataset.i)];
      showTooltip(`<div class="tt-title">${esc(r.tool)}</div>
        <div class="tt-row">calls<b>${fmt(r.n)}</b></div>`, e.clientX, e.clientY);
    });
    b.addEventListener("mouseleave", hideTooltip);
  });
}

function toolsTable(container, rows) {
  container.innerHTML = `<div class="table-scroll"><table>
    <thead><tr><th>Tool</th><th class="num">Calls</th></tr></thead>
    <tbody>${rows.map((r) => `<tr><td>${esc(r.tool)}</td><td class="num">${fmt(r.n)}</td></tr>`).join("")}
    </tbody></table></div>`;
}

// ---------------------------------------------------------------- models

// Series slots are the current view's top models, as the server ranks them;
// everything else is "other" grey. Order matches the validated --series-1..4
// tokens.
const MODEL_COLORS = ["#8a3ffc", "#009d9a", "#0072c3", "#d02670"];
// Model names are arbitrary ingested strings ("day", "__proto__", "null"), so
// per-model counts live in Maps and "other" is a sentinel no string can equal.
const OTHER = Symbol("other models");
// Same set as the server's PLACEHOLDER_MODELS: raw event records keep what was
// captured, but the console never presents these as a model.
const PLACEHOLDER_MODELS = new Set(["<synthetic>"]);
const MODELS_TABLE_LIMIT = 50;
const OTHER_COLOR = "#8d8d8d";
const modelColor = (model, series) => {
  const i = (series || []).indexOf(model);
  return i >= 0 ? MODEL_COLORS[i] : OTHER_COLOR;
};

function fmtUSD(v) {
  if (v == null) return "—";
  if (v > 0 && v < 0.01) return "<$0.01";
  if (v >= 1e4) return "$" + fmt(v);
  return "$" + v.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
}

const fmtOrDash = (v) => (v == null ? "—" : fmt(v));

function shortName(name, max = 32) {
  return name.length > max ? name.slice(0, max - 1) + "…" : name;
}

function modelCell(model, series) {
  const swatch = series ? `<span class="swatch" style="background:${modelColor(model, series)}"></span>` : "";
  return `<span class="model-cell">${swatch}<span class="model-name" title="${esc(model)}">${esc(shortName(model, 48))}</span></span>`;
}

function cacheWrite(r) {
  return r.cache_write_5m_tokens == null && r.cache_write_1h_tokens == null
    ? null : (r.cache_write_5m_tokens || 0) + (r.cache_write_1h_tokens || 0);
}

function costCell(r) {
  if (r.cost_status === "unpriced") return `<span title="no price set for this model">—</span>`;
  if (r.cost_status === "no_tokens") return `<span title="this source records no token usage">—</span>`;
  const partial = r.turns_without_tokens ? " (partial: some turns have no token data)" : "";
  return `<span title="${esc(r.cost + " USD" + partial)}">${fmtUSD(r.cost)}${partial ? "*" : ""}</span>`;
}

/* Every caveat that bounds an estimate is stated, never implied (spec AC16–AC20). */
function modelNotes(t) {
  const plural = (n, word) => `${fmt(n)} ${word}${n === 1 ? "" : "s"}`;
  const notes = ["Estimated cost in USD at the current price table — an estimate, not billing data."];
  if (t.unpriced_models) {
    notes.push(`${plural(t.unpriced_models, "model")} without a price ${t.unpriced_models === 1 ? "is" : "are"} excluded from the cost total` +
      (state.me.role === "admin" ? ` — <a href="#/prices">set prices</a>` : " — an admin can set prices"));
  }
  if (t.no_token_models) {
    notes.push(`${plural(t.no_token_models, "model")} record${t.no_token_models === 1 ? "s" : ""} no token usage (e.g. Antigravity): tokens and cost are unknown, and token totals cover only models with token data`);
  }
  if (t.premium_priced_turns) {
    notes.push(`${plural(t.premium_priced_turns, "turn")} ran at a premium speed and ${t.premium_priced_turns === 1 ? "is" : "are"} priced at standard rates, so the estimate is a lower bound`);
  }
  if (t.cache_write_5m_tokens || t.cache_write_1h_tokens) {
    notes.push("Cache writes without a 5-minute / 1-hour breakdown are priced at the 5-minute rate.");
  }
  return `<ul class="notes">${notes.map((n) => `<li>${n}</li>`).join("")}</ul>`;
}

/* One row per model; `opts.series` adds colour swatches, `opts.overview` the
   sessions + share columns, `opts.total` a closing total row. */
function modelTable(rows, opts = {}) {
  const hidden = opts.limit ? Math.max(0, rows.length - opts.limit) : 0;
  const shown = hidden ? rows.slice(0, opts.limit) : rows;
  const tokenCols = (r) => `
    <td class="num">${fmtOrDash(r.input_tokens)}</td>
    <td class="num">${fmtOrDash(r.output_tokens)}</td>
    <td class="num">${fmtOrDash(r.cache_read_tokens)}</td>
    <td class="num" title="5m ${fmtOrDash(r.cache_write_5m_tokens)} · 1h ${fmtOrDash(r.cache_write_1h_tokens)}">${fmtOrDash(cacheWrite(r))}</td>`;
  const t = opts.total;
  return `<div class="table-scroll"><table>
    <thead><tr><th>Model</th>${opts.overview ? '<th class="num">Sessions</th>' : "<th>Source</th>"}
      <th class="num">Turns</th>${opts.overview ? '<th class="num">Share</th>' : ""}
      <th class="num">Input</th><th class="num">Output</th><th class="num">Cache read</th>
      <th class="num">Cache write</th><th class="num">Est. cost</th></tr></thead>
    <tbody>${shown.map((r) => `<tr>
      <td>${modelCell(r.model, opts.series)}</td>
      ${opts.overview ? `<td class="num">${fmt(r.sessions)}</td>` : `<td>${esc(r.source || "—")}</td>`}
      <td class="num">${fmt(r.turns)}</td>
      ${opts.overview ? `<td class="num">${(r.share * 100).toFixed(1)}%</td>` : ""}
      ${tokenCols(r)}
      <td class="num">${costCell(r)}</td></tr>`).join("")}
    ${t && rows.length > 1 ? `<tr class="total"><td>Total</td><td></td>
      <td class="num">${fmt(t.turns)}</td>${opts.overview ? "<td></td>" : ""}${tokenCols(t)}
      <td class="num">${fmtUSD(t.cost_total)}</td></tr>` : ""}
    </tbody></table></div>
    ${hidden ? `<div class="pager"><span>showing ${fmt(shown.length)} of ${fmt(rows.length)} models — the total covers all of them</span>
      <button class="btn btn-ghost show-all-models">show all</button></div>` : ""}
    ${opts.omitted ? `<p class="helper-text" style="margin-top:8px">${fmt(opts.omitted)} less-used model${opts.omitted === 1 ? " is" : "s are"} not listed (the server returns the ${fmt(rows.length)} most used); totals include them.</p>` : ""}`;
}

/* Stacked columns per day: one segment per series model, then "other". */
function modelDayRows(perDay, series) {
  const byDay = new Map();
  perDay.forEach((d) => {
    if (!byDay.has(d.day)) byDay.set(d.day, new Map());
    byDay.get(d.day).set(d.model === null ? OTHER : d.model, d.turns);
  });
  let days = [...byDay.keys()].sort();
  if (days.length > 1) days = calendarDays(days[0], days[days.length - 1]) || days;
  const keys = perDay.some((d) => d.model === null) ? [...series, OTHER] : [...series];
  return {
    keys,
    days: days.map((day) => {
      const counts = new Map(keys.map((k) => [k, (byDay.get(day) || new Map()).get(k) || 0]));
      return { day, counts, total: [...counts.values()].reduce((a, v) => a + v, 0) };
    }),
  };
}

const seriesLabel = (k) => (k === OTHER ? "other models" : k);
// Chart-made labels ("other models", "total") are set in italics: a model can
// be *named* "Other models" or "total", but ingested names are always escaped
// text, so they can never look like these.
const bucketLabel = (text) => `<em class="bucket">${esc(text)}</em>`;
const seriesLabelHtml = (k, max = 32) => (k === OTHER ? bucketLabel("other models") : esc(shortName(k, max)));

function modelDayChart(container, perDay, series) {
  const { keys, days } = modelDayRows(perDay, series);
  const W = 640, H = 240, padL = 46, padR = 10, padT = 10, padB = 26;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const max = niceMax(maxOf(days, (d) => d.total));
  const ticks = [0, max / 2, max].map((t) => Math.round(t));
  const n = Math.max(days.length, 1);
  const band = plotW / n;
  const gap = 2;
  const barW = Math.min(24, Math.max(2, band - gap * 2));
  const y = (v) => padT + plotH * (1 - v / max);

  let bars = "", bands = "";
  days.forEach((d, i) => {
    const x = padL + band * i + (band - barW) / 2;
    let cum = 0;
    keys.forEach((k) => {
      const v = d.counts.get(k);
      if (!v) return;
      const top = y(cum + v), bottom = y(cum);
      // 2px surface gap between stacked segments, taken from the upper one
      const h = bottom - top - (cum > 0 ? gap : 0);
      if (h > 0) bars += barRect(x, top, barW, h, modelColor(k, series));
      cum += v;
    });
    bands += `<rect class="hover-band" data-i="${i}" x="${padL + band * i}" y="${padT}"
               width="${band}" height="${plotH}" fill="transparent"></rect>`;
  });

  const grid = ticks.map((t) =>
    `<line x1="${padL}" x2="${W - padR}" y1="${y(t)}" y2="${y(t)}"
       stroke="${t === 0 ? "var(--baseline)" : "var(--grid)"}" stroke-width="1"></line>
     <text x="${padL - 8}" y="${y(t) + 4}" text-anchor="end" fill="var(--ink-3)"
       font-size="10" style="font-variant-numeric:tabular-nums">${fmt(t)}</text>`).join("");
  const labelEvery = Math.ceil(n / 8);
  const xlabels = days.map((d, i) => i % labelEvery ? "" :
    `<text x="${padL + band * i + band / 2}" y="${H - 8}" text-anchor="middle"
       fill="var(--ink-3)" font-size="10">${esc(d.day.slice(5))}</text>`).join("");

  container.innerHTML = `
    <div class="legend">${keys.map((k) =>
      `<span class="key" title="${esc(seriesLabel(k))}"><span class="swatch" style="background:${modelColor(k, series)}"></span>${seriesLabelHtml(k)}</span>`).join("")}
    </div>
    <div class="chart-wrap"><svg viewBox="0 0 ${W} ${H}" role="img"
      aria-label="Model turns per day, stacked by model">${grid}${bars}${xlabels}${bands}</svg></div>`;

  container.querySelectorAll(".hover-band").forEach((b) => {
    b.addEventListener("mousemove", (e) => {
      const d = days[Number(b.dataset.i)];
      showTooltip(`<div class="tt-title">${esc(d.day)}</div>` +
        keys.filter((k) => d.counts.get(k)).map((k) => `<div class="tt-row">
          <span class="swatch" style="background:${modelColor(k, series)}"></span>
          ${seriesLabelHtml(k)}<b>${fmt(d.counts.get(k))}</b></div>`).join("") +
        `<div class="tt-row tt-total">${bucketLabel("total")}<b>${fmt(d.total)}</b></div>`, e.clientX, e.clientY);
    });
    b.addEventListener("mouseleave", hideTooltip);
  });
}

function modelDayTable(container, perDay, series) {
  const { keys, days } = modelDayRows(perDay, series);
  container.innerHTML = `<div class="table-scroll"><table>
    <thead><tr><th>Day</th>${keys.map((k) => `<th class="num" title="${esc(seriesLabel(k))}">${seriesLabelHtml(k, 24)}</th>`).join("")}
      <th class="num">${bucketLabel("total")}</th></tr></thead>
    <tbody>${days.map((d) => `<tr><td>${esc(d.day)}</td>
      ${keys.map((k) => `<td class="num">${fmt(d.counts.get(k))}</td>`).join("")}
      <td class="num">${fmt(d.total)}</td></tr>`).join("")}</tbody></table></div>`;
}

/* Share of turns: the chart's series plus one "other" segment, same colours. */
function modelShareCard(m) {
  const card = document.createElement("div");
  card.className = "card";
  const inSeries = m.rows.filter((r) => m.series.includes(r.model));
  // "Other" is derived from the window totals, not from the listed rows: the
  // server caps the listing, and the omitted models belong in this bucket.
  const otherCount = m.rows.length - inSeries.length + (m.models_omitted || 0);
  const otherTurns = m.turns - inSeries.reduce((a, r) => a + r.turns, 0);
  const segments = inSeries.map((r) => ({
    label: r.model, html: esc(shortName(r.model, 40)), key: r.model, turns: r.turns, share: r.share,
  }));
  if (otherCount > 0) {
    const label = `other models (${fmt(otherCount)})`;
    segments.push({ label, html: bucketLabel(label), key: OTHER,
                    turns: otherTurns, share: otherTurns / m.turns });
  }
  card.innerHTML = `<div class="card-head"><span class="card-title">Model share — turns</span></div>
    <div class="share-bar" role="img" aria-label="Share of model turns">${segments.map((s, i) =>
      `<span data-i="${i}" style="flex:${s.share} 1 0;background:${modelColor(s.key, m.series)}"></span>`).join("")}</div>
    <div class="table-scroll"><table>
      <thead><tr><th>Model</th><th class="num">Turns</th><th class="num">Share</th></tr></thead>
      <tbody>${segments.map((s) => `<tr>
        <td><span class="model-cell"><span class="swatch" style="background:${modelColor(s.key, m.series)}"></span>
          <span class="model-name" title="${esc(s.label)}">${s.html}</span></span></td>
        <td class="num">${fmt(s.turns)}</td>
        <td class="num">${(s.share * 100).toFixed(1)}%</td></tr>`).join("")}</tbody></table></div>`;
  card.querySelectorAll(".share-bar span").forEach((el) => {
    el.addEventListener("mousemove", (e) => {
      const s = segments[Number(el.dataset.i)];
      showTooltip(`<div class="tt-title">${s.key === OTHER ? s.html : esc(s.label)}</div>
        <div class="tt-row">turns<b>${fmt(s.turns)}</b></div>
        <div class="tt-row">share<b>${(s.share * 100).toFixed(1)}%</b></div>`, e.clientX, e.clientY);
    });
    el.addEventListener("mouseleave", hideTooltip);
  });
  return card;
}

/* Wire a chart card's chart/table toggle. */
function chartCard(title, renderChart, renderTable) {
  const card = document.createElement("div");
  card.className = "card";
  card.innerHTML = `
    <div class="card-head"><span class="card-title">${esc(title)}</span>
      <div class="card-tools"><button class="toggle-table" type="button">table</button></div>
    </div><div class="card-body"></div>`;
  const body = $(".card-body", card);
  const btn = $(".toggle-table", card);
  let showingTable = false;
  const render = () => (showingTable ? renderTable(body) : renderChart(body));
  btn.addEventListener("click", () => {
    showingTable = !showingTable;
    btn.classList.toggle("active", showingTable);
    btn.textContent = showingTable ? "chart" : "table";
    render();
  });
  render();
  return card;
}

// ---------------------------------------------------------------- filters row

async function filtersRow(onChange, extra) {
  const wrap = document.createElement("div");
  wrap.className = "filters";
  const projects = await apiJSON("/api/v1/projects").catch(() => []);
  wrap.innerHTML = `
    <div class="field"><label class="microlabel">Project</label>
      <select id="f-project"><option value="">${Array.isArray(state.me.scope)
        ? "all my projects" : "all projects"}</option>
        ${projects.map((p) => `<option ${p === state.filters.project ? "selected" : ""}
          value="${esc(p)}">${esc(p)}</option>`).join("")}
      </select></div>
    <div class="field"><label class="microlabel">Window</label>
      <div class="range-presets">
        ${["7", "30", "90", "all"].map((r) => `<button type="button" data-r="${r}"
          class="${state.filters.range === r ? "active" : ""}">${r === "all" ? "all time" : r + "d"}</button>`).join("")}
      </div></div>
    ${extra || ""}`;
  $("#f-project", wrap).addEventListener("change", (e) => {
    state.filters.project = e.target.value;
    onChange();
  });
  wrap.querySelectorAll(".range-presets button").forEach((b) =>
    b.addEventListener("click", () => {
      state.filters.range = b.dataset.r;
      wrap.querySelectorAll(".range-presets button").forEach((x) =>
        x.classList.toggle("active", x === b));
      onChange();
    }));
  return wrap;
}

// ---------------------------------------------------------------- views

async function viewOverview() {
  main.innerHTML = "";
  main.appendChild(await filtersRow(viewOverview));

  const params = { project: state.filters.project, from: rangeFrom(state.filters.range) };
  const o = await apiJSON("/api/v1/overview" + qs(params));
  const t = o.totals;

  const failNote = t.tool_calls
    ? `${((t.failures / (t.tool_calls + t.failures)) * 100).toFixed(1)}% of tool calls`
    : "";
  const kpis = [
    ["Sessions", t.sessions, `${t.projects || 0} project${t.projects === 1 ? "" : "s"} · ${t.origins || 0} member${t.origins === 1 ? "" : "s"}`],
    ["Prompts", t.prompts, ""],
    ["Tool calls", t.tool_calls, ""],
    ["Tool failures", t.failures, failNote, t.failures > 0],
    // Token and cost tiles use the Models card's turn-time totals, so the two
    // never disagree about the same window.
    ["Output tokens", o.models.output_tokens, tokenKpiNote(o.models), false, fmtOrDash],
    ["Est. cost", o.models.cost_total, costKpiNote(o.models), false, fmtUSD],
  ];
  const kpiRow = document.createElement("div");
  kpiRow.className = "kpi-row";
  kpiRow.innerHTML = kpis.map(([label, v, note, bad, format]) => `
    <div class="card kpi"><span class="microlabel">${label}</span>
      <div class="kpi-value">${format ? format(v) : fmt(v || 0)}</div>
      <div class="kpi-note${bad ? " bad" : ""}">${esc(note || "")}</div></div>`).join("");
  main.appendChild(kpiRow);

  const grid = document.createElement("div");
  grid.className = "grid-2";
  if (o.per_day.length) {
    grid.appendChild(chartCard("Activity — per day",
      (el) => activityChart(el, o.per_day), (el) => activityTable(el, o.per_day)));
  }
  if (o.top_tools.length) {
    grid.appendChild(chartCard("Tool usage",
      (el) => toolsChart(el, o.top_tools), (el) => toolsTable(el, o.top_tools)));
  }
  main.appendChild(grid);

  if (!o.per_day.length) {
    main.insertAdjacentHTML("beforeend", `<div class="card"><div class="empty">
      <span class="glyph">◉</span>no events in this window —
      connect a project with <code>install.sh --server</code> and start a session</div></div>`);
  }

  const m = o.models;
  if (m.rows.length) {
    const modelGrid = document.createElement("div");
    modelGrid.className = "grid-2";
    modelGrid.appendChild(chartCard("Model turns — per day",
      (el) => modelDayChart(el, m.per_day, m.series), (el) => modelDayTable(el, m.per_day, m.series)));
    modelGrid.appendChild(modelShareCard(m));
    main.appendChild(modelGrid);
  }
  const modelsCard = document.createElement("div");
  modelsCard.className = "card";
  const renderModels = (limit) => {
    modelsCard.innerHTML = `<div class="card-head"><span class="card-title">Models — tokens and estimated cost</span></div>` +
      (m.rows.length
        ? modelTable(m.rows, { series: m.series, overview: true, total: m, limit,
                               omitted: m.models_omitted }) + modelNotes(m)
        : `<div class="empty"><span class="glyph">∴</span>no model turns in this window</div>`);
    const more = $(".show-all-models", modelsCard);
    if (more) more.addEventListener("click", () => renderModels(0));
  };
  renderModels(MODELS_TABLE_LIMIT);
  main.appendChild(modelsCard);

  const twoCol = document.createElement("div");
  twoCol.className = "grid-2";
  twoCol.appendChild(breakdownCard("Projects", o.projects, "project"));
  twoCol.appendChild(breakdownCard("People", o.origins, "origin"));
  main.appendChild(twoCol);

  const last = o.projects.map((p) => p.last_ts).sort().pop();
  $("#last-signal").textContent = last ? "last event " + timeAgo(last) : "";
}

function tokenKpiNote(m) {
  if (m.output_tokens == null) return m.rows.length ? "no token data in this window" : "";
  const input = fmt(m.input_tokens) + " input";
  return m.no_token_models ? `${input} · models with token data only` : input;
}

function costKpiNote(m) {
  const parts = [];
  if (m.unpriced_models) parts.push(`${m.unpriced_models} unpriced`);
  if (m.no_token_models) parts.push(`${m.no_token_models} without token data`);
  return parts.length ? `excludes models: ${parts.join(", ")}` : "USD at current prices";
}

function breakdownCard(title, rows, keyField) {
  const card = document.createElement("div");
  card.className = "card";
  card.innerHTML = `<div class="card-head"><span class="card-title">${title}</span></div>
    <div class="table-scroll"><table>
      <thead><tr><th>${keyField}</th><th class="num">Sessions</th>
        <th class="num">Prompts</th><th class="num">Tool calls</th><th>Last active</th></tr></thead>
      <tbody>${rows.map((r) => `<tr>
        <td>${esc(r[keyField] || "—")}</td>
        <td class="num">${fmt(r.sessions)}</td>
        <td class="num">${fmt(r.prompts || 0)}</td>
        <td class="num">${fmt(r.tool_calls || 0)}</td>
        <td>${timeAgo(r.last_ts)}</td></tr>`).join("") ||
        `<tr><td colspan="5" class="empty">no data yet</td></tr>`}
      </tbody></table></div>`;
  return card;
}

async function viewSessions() {
  main.innerHTML = "";
  let models = [], modelsError = "";
  try {
    models = (await apiJSON("/api/v1/models")).models.filter((m) => m.turns > 0);
  } catch (err) {
    if (err.message === "unauthorized") throw err;
    modelsError = err.message;
  }
  // A remembered filter for a model no longer listed would filter rows while
  // the select claims "all models".
  if (!models.some((m) => m.model === state.sessionsModel)) state.sessionsModel = "";
  const extra = `
    <div class="field"><label class="microlabel">Model${modelsError
      ? ` <span class="row-error" title="${esc(modelsError)}">· list unavailable</span>` : ""}</label>
      <select id="f-model"><option value="">all models</option>
        ${models.map((m, i) => `<option value="${i}" ${m.model === state.sessionsModel ? "selected" : ""}
          title="${esc(m.model)}">${esc(shortName(m.model, 64))}</option>`).join("")}
      </select></div>
    <div class="field"><label class="microlabel">Session id</label>
      <input id="f-q" placeholder="search…" value=""></div>`;
  main.appendChild(await filtersRow(() => { state.sessionsPage = 0; loadSessions(); }, extra));
  $("#f-model").addEventListener("change", (e) => {
    state.sessionsModel = e.target.value === "" ? "" : models[Number(e.target.value)].model;
    state.sessionsPage = 0;
    loadSessions();
  });
  const holder = document.createElement("div");
  holder.className = "card";
  main.appendChild(holder);
  let qTimer;
  $("#f-q").addEventListener("input", () => {
    clearTimeout(qTimer);
    qTimer = setTimeout(() => { state.sessionsPage = 0; loadSessions(); }, 250);
  });

  async function loadSessions() {
    const limit = 50;
    const params = {
      project: state.filters.project,
      from: rangeFrom(state.filters.range),
      q: ($("#f-q") || {}).value || "",
      model: state.sessionsModel,
      limit, offset: state.sessionsPage * limit,
    };
    const data = await apiJSON("/api/v1/sessions" + qs(params));
    if (!data.sessions.length) {
      holder.innerHTML = `<div class="empty"><span class="glyph">◉</span>no sessions match</div>`;
      return;
    }
    holder.innerHTML = `<div class="table-scroll"><table>
      <thead><tr><th>Session</th><th>Project</th><th>Member</th><th>Model</th><th>Last active</th>
        <th class="num">Prompts</th><th class="num">Tools</th><th class="num">Fail</th>
        <th class="num">Out tokens</th><th>Transcript</th></tr></thead>
      <tbody>${data.sessions.map((s) => `<tr class="click" data-sid="${esc(s.session_id)}">
        <td><span class="mono-id">${esc(s.session_id.slice(0, 8))}…</span></td>
        <td>${esc(s.project || "—")}</td>
        <td>${esc(s.origin || "—")}</td>
        <td>${s.dominant_model
          ? `<span class="model-name" title="${esc(s.dominant_model)}">${esc(shortName(s.dominant_model))}</span>` +
            (s.model_count > 1 ? `<span class="badge plus-n" title="${s.model_count - 1} other model${s.model_count === 2 ? "" : "s"} in this session">+${s.model_count - 1}</span>` : "")
          : "—"}</td>
        <td>${fmtTime(s.last_ts)}</td>
        <td class="num">${fmt(s.prompts)}</td>
        <td class="num">${fmt(s.tool_calls)}</td>
        <td class="num">${s.failures ? `<span style="color:var(--serious)">${fmt(s.failures)}</span>` : "0"}</td>
        <td class="num">${fmt(s.output_tokens)}</td>
        <td>${s.transcript_bytes ? '<span class="badge ok">✓ stored</span>' : '<span class="badge">events only</span>'}</td>
      </tr>`).join("")}</tbody></table></div>
      <div class="pager">
        <span>${data.total} session${data.total === 1 ? "" : "s"}</span>
        <button class="btn btn-ghost" id="pg-prev" ${state.sessionsPage ? "" : "disabled"}>‹ prev</button>
        <button class="btn btn-ghost" id="pg-next"
          ${(state.sessionsPage + 1) * limit < data.total ? "" : "disabled"}>next ›</button>
      </div>`;
    holder.querySelectorAll("tr.click").forEach((tr) =>
      tr.addEventListener("click", () => { location.hash = "#/session/" + tr.dataset.sid; }));
    $("#pg-prev", holder).addEventListener("click", () => { state.sessionsPage--; loadSessions(); });
    $("#pg-next", holder).addEventListener("click", () => { state.sessionsPage++; loadSessions(); });
  }
  await loadSessions();
}

// Canonical, tool-agnostic vocabulary. Indexes built before v0.3 may still
// hold the legacy Claude-shaped names — normalize when rendering.
const LEGACY_EVENTS = {
  SessionStart: "session.start", UserPromptSubmit: "prompt.submit",
  PostToolUse: "tool.call", PostToolUseFailure: "tool.fail",
  Stop: "turn.end", SubagentStart: "agent.start", SubagentStop: "agent.end",
  PreCompact: "context.compact", SessionEnd: "session.end",
};
const canonEvent = (ev) => LEGACY_EVENTS[ev] || ev;
const shownModel = (model) => model && !PLACEHOLDER_MODELS.has(model);

const EVENT_GLYPHS = {
  "session.start": ["▶", "", "session start"],
  "prompt.submit": ["❯", "prompt", "prompt"],
  "tool.call": ["⚙", "", ""],
  "tool.fail": ["✕", "fail", "tool failure"],
  "model.turn": ["∴", "", "model turn"],
  "turn.end": ["◀", "stop", "turn end"],
  "agent.start": ["◌", "agent", "subagent start"],
  "agent.end": ["◌", "agent", "subagent stop"],
  "context.compact": ["≋", "", "context management"],
  "session.end": ["■", "", "session end"],
  "note": ["·", "", "note"],
};

async function viewSession(sid) {
  main.innerHTML = `<div class="card"><div class="empty">loading session…</div></div>`;
  const data = await apiJSON("/api/v1/sessions/" + encodeURIComponent(sid));
  const s = data.session;
  main.innerHTML = "";

  const head = document.createElement("div");
  head.className = "card session-head";
  head.innerHTML = `
    <div>
      <span class="microlabel">Session</span>
      <div class="mono-strong">${esc(s.session_id)}</div>
      <div class="session-meta">
        <div><span class="microlabel">Project</span><span class="val">${esc(s.project || "—")}</span></div>
        <div><span class="microlabel">Member</span><span class="val">${esc(s.origin || "—")}</span></div>
        <div><span class="microlabel">Started</span><span class="val">${fmtTime(s.first_ts)}</span></div>
        <div><span class="microlabel">Last event</span><span class="val">${fmtTime(s.last_ts)}</span></div>
        <div><span class="microlabel">Prompts</span><span class="val">${fmt(s.prompts)}</span></div>
        <div><span class="microlabel">Tool calls</span><span class="val">${fmt(s.tool_calls)}</span></div>
        <div><span class="microlabel">Failures</span><span class="val">${fmt(s.failures)}</span></div>
        <div><span class="microlabel">Tokens in / out</span>
          <span class="val">${fmt(s.input_tokens)} / ${fmt(s.output_tokens)}</span></div>
        ${s.dominant_model ? `<div><span class="microlabel">Model</span><span class="val" title="${esc(s.dominant_model)}">${esc(shortName(s.dominant_model, 48))}${s.model_count > 1 ? ` <span class="badge plus-n">+${s.model_count - 1}</span>` : ""}</span></div>` : ""}
      </div>
    </div>
    <div class="form-actions">
      ${data.has_transcript ? `<button class="btn" id="dl-transcript">↓ transcript.jsonl</button>` : ""}
      <button class="btn" id="dl-events">↓ events.jsonl</button>
      <button class="btn" id="dl-events-csv">↓ events.csv</button>
    </div>`;
  main.appendChild(head);
  if (data.has_transcript) {
    $("#dl-transcript").addEventListener("click", () =>
      download(`/api/v1/sessions/${encodeURIComponent(sid)}/transcript`));
  }
  $("#dl-events").addEventListener("click", () =>
    download(`/api/v1/export${qs({ session: sid, format: "jsonl" })}`));
  $("#dl-events-csv").addEventListener("click", () =>
    download(`/api/v1/export${qs({ session: sid, format: "csv" })}`));

  if (data.models.length) {
    const usage = document.createElement("div");
    usage.className = "card";
    usage.innerHTML = `<div class="card-head"><span class="card-title">Model usage</span></div>` +
      modelTable(data.models, { total: data.models_total, omitted: data.models_omitted }) +
      modelNotes(data.models_total);
    main.appendChild(usage);
  }

  const tl = document.createElement("div");
  tl.className = "timeline";
  tl.innerHTML = data.events.map((e, i) => {
    const ev = canonEvent(e.event);
    const [glyph, cls, tag] = EVENT_GLYPHS[ev] || ["·", "", ev];
    let body = "";
    if (ev === "prompt.submit") {
      body = `<div class="tl-card prompt"><div class="tl-tag">prompt${e.agent_type ? " · " + esc(e.agent_type) : ""}</div>
        <div class="tl-text">${esc(e.prompt || "")}</div></div>`;
    } else if (ev === "tool.call" || ev === "tool.fail") {
      const fail = ev === "tool.fail";
      body = `<div class="tl-card${fail ? " fail" : ""}">
        <div class="tl-tool" data-i="${i}">
          <span class="chev">›</span>
          <span class="tool-name">${esc(e.tool_name || "tool")}</span>
          ${fail ? '<span class="badge warn">✕ failed</span>' : ""}
          ${e.agent_type ? `<span class="badge">${esc(e.agent_type)}</span>` : ""}
        </div>
        <div class="tl-io">
          ${e.tool_input ? `<span class="microlabel">input</span><pre>${esc(e.tool_input)}</pre>` : ""}
          ${e.tool_response ? `<span class="microlabel">response</span><pre>${esc(e.tool_response)}</pre>` : ""}
        </div></div>`;
    } else if (ev === "turn.end" || ev === "agent.end" || ev === "model.turn" || ev === "note") {
      const label = tag + (shownModel(e.model) ? ` · <span title="${esc(e.model)}">${esc(shortName(e.model, 64))}</span>` : "");
      body = e.last_assistant_message
        ? `<div class="tl-card stop"><div class="tl-tag">${label}${e.agent_type ? " · " + esc(e.agent_type) : ""}</div>
           <div class="tl-text">${esc(e.last_assistant_message)}</div></div>`
        : `<div class="tl-tag" style="padding:8px 0">${label}${ev === "model.turn" && e.tool_name ? " · → " + esc(e.tool_name) : ""}</div>`;
    } else {
      body = `<div class="tl-tag" style="padding:8px 0">${esc(tag)}
        ${shownModel(e.model) ? `· <span title="${esc(e.model)}">${esc(shortName(e.model, 64))}</span>` : ""}</div>`;
    }
    return `<div class="tl-item">
      <div class="tl-time">${fmtTime(e.ts).split(", ")[1] || fmtTime(e.ts)}</div>
      <div class="tl-rail"><div class="tl-glyph ${cls}">${glyph}</div></div>
      <div class="tl-body">${body}</div></div>`;
  }).join("");
  main.appendChild(tl);
  tl.querySelectorAll(".tl-tool").forEach((el) =>
    el.addEventListener("click", () => el.classList.toggle("open")));
}

async function viewExport() {
  main.innerHTML = "";
  const card = document.createElement("div");
  card.className = "card";
  const projects = await apiJSON("/api/v1/projects").catch(() => []);
  card.innerHTML = `
    <div class="card-head"><span class="card-title">Export the ledger</span></div>
    <p style="margin-bottom:16px;color:var(--ink-3)">Filtered slices of the event
      layer, ready for pandas / spreadsheets. Raw transcripts are downloaded per
      session from its detail page.</p>
    <div class="form-grid">
      <div class="field"><label class="microlabel">Project</label>
        <select id="x-project"><option value="">all</option>
          ${projects.map((p) => `<option value="${esc(p)}">${esc(p)}</option>`).join("")}</select></div>
      <div class="field"><label class="microlabel">Event type</label>
        <select id="x-event"><option value="">all</option>
          ${Object.keys(EVENT_GLYPHS).map((e) => `<option>${e}</option>`).join("")}</select></div>
      <div class="field"><label class="microlabel">From (UTC date)</label>
        <input id="x-from" type="date"></div>
      <div class="field"><label class="microlabel">To (UTC date)</label>
        <input id="x-to" type="date"></div>
      <div class="field"><label class="microlabel">Session id (optional)</label>
        <input id="x-session" placeholder="full id"></div>
      <div class="field"><label class="microlabel">Member (optional)</label>
        <input id="x-origin" placeholder="key name"></div>
    </div>
    <div class="form-actions">
      <button class="btn btn-accent" id="x-jsonl">↓ Export JSONL</button>
      <button class="btn" id="x-csv">↓ Export CSV</button>
    </div>`;
  main.appendChild(card);
  const params = (format) => qs({
    format,
    project: $("#x-project").value,
    event: $("#x-event").value,
    from: $("#x-from").value,
    to: $("#x-to").value ? $("#x-to").value + "T23:59:59" : "",
    session: $("#x-session").value.trim(),
    origin: $("#x-origin").value.trim(),
  });
  $("#x-jsonl").addEventListener("click", () => download("/api/v1/export" + params("jsonl")));
  $("#x-csv").addEventListener("click", () => download("/api/v1/export" + params("csv")));
}

async function viewKeys() {
  if (state.me.role !== "admin") { location.hash = "#/overview"; return; }
  main.innerHTML = "";
  const create = document.createElement("div");
  create.className = "card";
  create.innerHTML = `
    <div class="card-head"><span class="card-title">Issue a key</span></div>
    <p class="helper-text" style="margin-bottom:16px">Keys are not scoped to projects:
      a member or admin key reads every project, whoever holds it. Project access
      is set per account on the Users page.</p>
    <div class="form-grid">
      <div class="field"><label class="microlabel">Name (person or machine)</label>
        <input id="k-name" placeholder="alice"></div>
      <div class="field"><label class="microlabel">Role</label>
        <select id="k-role">
          <option value="agent">agent — ingest only (for hooks)</option>
          <option value="member" selected>member — ingest + console + export</option>
          <option value="admin">admin — everything</option>
        </select></div>
    </div>
    <div class="form-actions"><button class="btn btn-accent" id="k-create">Create key</button></div>
    <div id="k-reveal"></div>`;
  main.appendChild(create);

  const listCard = document.createElement("div");
  listCard.className = "card";
  main.appendChild(listCard);

  async function loadKeys() {
    const keys = await apiJSON("/api/v1/keys");
    listCard.innerHTML = `
      <div class="card-head"><span class="card-title">Issued keys</span></div>
      <div class="table-scroll"><table>
        <thead><tr><th>Name</th><th>Role</th><th>Created</th><th>Last seen</th>
          <th class="num">Sessions</th><th>Status</th><th></th></tr></thead>
        <tbody>${keys.map((k) => `<tr>
          <td style="color:var(--ink)">${esc(k.name)}</td>
          <td><span class="badge">${esc(k.role)}</span></td>
          <td>${fmtTime(k.created_at)}</td>
          <td>${k.last_seen_at ? timeAgo(k.last_seen_at) : "never"}</td>
          <td class="num">${fmt(k.sessions)}</td>
          <td>${k.revoked_at ? '<span class="badge warn">revoked</span>' : '<span class="badge ok">active</span>'}</td>
          <td>${k.revoked_at ? "" : `<button class="btn btn-ghost btn-danger" data-id="${k.id}">revoke</button>`}</td>
        </tr>`).join("")}</tbody></table></div>`;
    listCard.querySelectorAll("button[data-id]").forEach((b) =>
      b.addEventListener("click", async () => {
        if (!confirm(`Revoke this key? Hooks using it will stop shipping (local capture continues).`)) return;
        await api("/api/v1/keys/" + b.dataset.id, { method: "DELETE" });
        loadKeys();
      }));
  }
  await loadKeys();

  $("#k-create").addEventListener("click", async () => {
    const name = $("#k-name").value.trim();
    if (!name) return;
    const res = await apiJSON("/api/v1/keys", {
      method: "POST",
      body: JSON.stringify({ name, role: $("#k-role").value }),
    });
    $("#k-reveal").innerHTML = `<div class="token-reveal">
      <span class="microlabel">shown once</span><code>${esc(res.token)}</code>
      <button class="btn" id="k-copy">copy</button></div>`;
    $("#k-copy").addEventListener("click", () =>
      navigator.clipboard.writeText(res.token));
    $("#k-name").value = "";
    loadKeys();
  });
}

// ---------------------------------------------------------------- projects

function installPrompt(p) {
  const origin = location.origin;
  return `Conecte este projeto ao GAIDE-Trace (o coletor de traces de sessões de IA do time).

Execute no diretório raiz do projeto:

1. Baixe (ou atualize) o instalador:
   git clone https://github.com/jcarlos78/GAIDE-Trace ~/.gaide-trace-installer 2>/dev/null || git -C ~/.gaide-trace-installer pull

2. Conecte o projeto ao servidor do time:
   ~/.gaide-trace-installer/install.sh "$PWD" --server ${origin} --token ${p.agent_token} --name ${p.name}

3. Se já existir histórico local em .gaide-trace/, envie-o ao servidor:
   python3 ~/.gaide-trace-installer/tools/backfill.py "$PWD/.gaide-trace"

4. Confirme que .gaide-trace/config.json aponta para ${origin} e me informe o resultado.
   A captura é local-first: os dados ficam no projeto e são enviados ao servidor com retry automático.

Nota: os passos acima capturam sessões do Claude Code (hooks). Para sessões do
Antigravity IDE neste projeto, rode periodicamente (ou deixe em watch):
   python3 ~/.gaide-trace-installer/tools/import_antigravity.py --workspace "$PWD"`;
}

function promptReveal(p) {
  return `<div class="prompt-reveal" data-name="${esc(p.name)}">
    <div class="card-head"><span class="card-title">Install prompt — ${esc(p.name)}</span>
      <button class="btn copy-prompt" data-name="${esc(p.name)}">Copy prompt</button></div>
    <p class="helper-text">Paste this into your coding agent (Claude Code,
      Antigravity, Cursor, …) at the project root. The embedded key is
      ingest-only.</p>
    <textarea class="prompt-text" rows="14" readonly>${esc(installPrompt(p))}</textarea>
  </div>`;
}

async function viewProjects() {
  main.innerHTML = "";
  const create = document.createElement("div");
  create.className = "card";
  create.innerHTML = `
    <div class="card-head"><span class="card-title">Register a project</span></div>
    <p class="helper-text" style="margin-bottom:16px">Registering creates an
      ingest-only key for the project and generates a copy-paste install prompt
      for the team.</p>
    <div class="filters">
      <div class="field"><label class="microlabel">Project name</label>
        <input id="p-name" placeholder="my-app" spellcheck="false"></div>
      <button class="btn btn-accent" id="p-create">Register project</button>
    </div>
    <div id="p-new"></div>`;
  main.appendChild(create);

  const listCard = document.createElement("div");
  listCard.className = "card";
  main.appendChild(listCard);

  async function loadProjects() {
    const rows = await apiJSON("/api/v1/projects/manage");
    if (!rows.length) {
      listCard.innerHTML = `<div class="empty"><span class="glyph">◉</span>
        no projects registered yet</div>`;
      return;
    }
    listCard.innerHTML = `
      <div class="card-head"><span class="card-title">Registered projects</span></div>
      <div class="table-scroll"><table>
        <thead><tr><th>Project</th><th>Created</th><th>By</th>
          <th class="num">Sessions</th><th>Last active</th><th>Key</th><th></th></tr></thead>
        <tbody>${rows.map((p) => `<tr>
          <td style="color:var(--text-primary)">${esc(p.name)}</td>
          <td>${fmtTime(p.created_at)}</td>
          <td>${esc(p.created_by || "—")}</td>
          <td class="num">${fmt(p.sessions)}</td>
          <td>${p.last_ts ? timeAgo(p.last_ts) : "no data yet"}</td>
          <td>${p.key_revoked ? '<span class="badge warn">revoked</span>'
                              : '<span class="badge ok">active</span>'}</td>
          <td style="text-align:right">
            <button class="btn btn-ghost p-prompt" data-id="${p.id}">install prompt</button>
            <button class="btn btn-ghost p-rotate" data-id="${p.id}">rotate key</button>
            ${state.me.role === "admin"
              ? `<button class="btn btn-ghost btn-danger p-del" data-id="${p.id}">remove</button>` : ""}
          </td></tr>
          <tr class="prompt-row hidden" data-id="${p.id}"><td colspan="7"></td></tr>`).join("")}
        </tbody></table></div>`;
    const byId = Object.fromEntries(rows.map((p) => [String(p.id), p]));
    listCard.querySelectorAll(".p-prompt").forEach((b) =>
      b.addEventListener("click", () => {
        const row = listCard.querySelector(`.prompt-row[data-id="${b.dataset.id}"]`);
        row.classList.toggle("hidden");
        if (!row.classList.contains("hidden")) {
          row.firstElementChild.innerHTML = promptReveal(byId[b.dataset.id]);
          wireCopy(row);
        }
      }));
    listCard.querySelectorAll(".p-rotate").forEach((b) =>
      b.addEventListener("click", async () => {
        if (!confirm("Rotate this project's key? Machines using the old one stop " +
                     "shipping until they reinstall with the new prompt.")) return;
        await apiJSON(`/api/v1/projects/${b.dataset.id}/rotate`, { method: "POST" });
        loadProjects();
      }));
    listCard.querySelectorAll(".p-del").forEach((b) =>
      b.addEventListener("click", async () => {
        if (!confirm("Remove this project registration and revoke its key? " +
                     "Already-ingested trace data is kept.")) return;
        await api(`/api/v1/projects/${b.dataset.id}`, { method: "DELETE" });
        loadProjects();
      }));
  }

  function wireCopy(scope) {
    scope.querySelectorAll(".copy-prompt").forEach((b) =>
      b.addEventListener("click", () => {
        navigator.clipboard.writeText(scope.querySelector(".prompt-text").value);
        b.textContent = "Copied ✓";
        setTimeout(() => { b.textContent = "Copy prompt"; }, 1600);
      }));
  }

  $("#p-create").addEventListener("click", async () => {
    const name = $("#p-name").value.trim();
    if (!name) return;
    try {
      const p = await apiJSON("/api/v1/projects", {
        method: "POST", body: JSON.stringify({ name }),
      });
      $("#p-name").value = "";
      $("#p-new").innerHTML = promptReveal(p);
      wireCopy($("#p-new"));
      loadProjects();
    } catch (err) { alert(err.message); }
  });

  await loadProjects();
}

// ---------------------------------------------------------------- model prices

const PRICE_FIELDS = [
  ["input", "Input"], ["output", "Output"], ["cache_read", "Cache read"],
  ["cache_write_5m", "Cache write 5m"], ["cache_write_1h", "Cache write 1h"],
];

async function viewPrices() {
  if (state.me.role !== "admin") { location.hash = "#/overview"; return; }
  main.innerHTML = "";
  let pageModels = [];
  const importCard = priceImportCard(() => pageModels, () => load());
  main.appendChild(importCard);
  const card = document.createElement("div");
  card.className = "card";
  main.appendChild(card);

  const priceInputs = (price) => PRICE_FIELDS.map(([f, label]) =>
    `<td class="num"><input class="price-input" type="number" min="0" step="any"
       data-field="${f}" aria-label="${label} USD per million tokens"
       value="${price && price[f] != null ? price[f] : ""}"></td>`).join("");

  async function save(model, row) {
    const body = { model };
    row.querySelectorAll("input[data-field]").forEach((el) => {
      body[el.dataset.field] = el.value === "" ? null : Number(el.value);
    });
    try {
      await apiJSON("/api/v1/models/prices", { method: "PUT", body: JSON.stringify(body) });
      load();
    } catch (err) {
      const errEl = row.querySelector(".row-error") || card.querySelector(".add-error");
      errEl.textContent = err.message;
    }
  }

  async function load(notice = "") {
    const { models, omitted } = await apiJSON("/api/v1/models");
    pageModels = models;
    importCard.refresh();
    card.innerHTML = `
      <div class="card-head"><span class="card-title">Model prices</span></div>
      ${notice ? `<p class="row-error pr-notice" role="alert">${esc(notice)}</p>` : ""}
      ${omitted ? `<p class="helper-text">${fmt(omitted)} less-used model${omitted === 1 ? " is" : "s are"} not listed;
        use the row at the bottom to price one by name.</p>` : ""}
      <p class="helper-text" style="margin-bottom:16px">USD per million tokens, per
        token type. Used only for the cost estimates in this console. Set them by
        hand, or load input and output list prices from benchlm.ai above and
        review them before applying — keep them in step with your contract.
        Models without a price show no cost rather than a guess.</p>
      <div class="table-scroll"><table>
        <thead><tr><th>Model</th><th class="num">Turns</th><th>Last used</th>
          ${PRICE_FIELDS.map(([, label]) => `<th class="num">${label}</th>`).join("")}
          <th>Last changed</th><th></th></tr></thead>
        <tbody>
          ${models.map((m, i) => `<tr data-i="${i}">
            <td>${modelCell(m.model)}</td>
            <td class="num">${fmt(m.turns)}</td>
            <td>${m.last_ts ? timeAgo(m.last_ts) : "not seen yet"}</td>
            ${PRICE_FIELDS.map(([f]) => `<td class="num">${m.price ? "$" + m.price[f] : ""}</td>`).join("")}
            <td>${m.price ? `${timeAgo(m.price.updated_at)} · ${esc(m.price.updated_by || "—")}`
                          : '<span class="badge">unpriced</span>'}</td>
            <td><div class="actions">
              <button class="btn btn-ghost pr-edit">${m.price ? "edit" : "set price"}</button>
              ${m.price ? '<button class="btn btn-ghost btn-danger pr-clear">clear</button>' : ""}
            </div></td></tr>`).join("") ||
            `<tr><td colspan="10" class="empty">no models seen yet</td></tr>`}
          <tr class="pr-add">
            <td><input class="price-model-input" placeholder="model not seen yet" spellcheck="false"
                 maxlength="128" aria-label="Model name"></td>
            <td></td><td></td>${priceInputs(null)}<td></td>
            <td><div class="actions"><button class="btn btn-ghost pr-add-save">add price</button></div></td>
          </tr>
          <tr><td colspan="10" class="row-error add-error"></td></tr>
        </tbody></table></div>`;

    card.querySelectorAll("tr[data-i]").forEach((row) => {
      const m = models[Number(row.dataset.i)];
      row.querySelector(".pr-edit").addEventListener("click", () => {
        row.innerHTML = `<td>${modelCell(m.model)}</td><td class="num">${fmt(m.turns)}</td>
          <td>${m.last_ts ? timeAgo(m.last_ts) : "not seen yet"}</td>${priceInputs(m.price)}
          <td class="row-error"></td>
          <td><div class="actions"><button class="btn btn-accent pr-save">save</button>
            <button class="btn btn-ghost pr-cancel">cancel</button></div></td>`;
        row.querySelector("input").focus();
        row.querySelector(".pr-save").addEventListener("click", () => save(m.model, row));
        row.querySelector(".pr-cancel").addEventListener("click", () => load());
        row.querySelectorAll("input").forEach((el) => el.addEventListener("keydown", (e) => {
          if (e.key === "Enter") save(m.model, row);
          if (e.key === "Escape") load();
        }));
      });
      const clear = row.querySelector(".pr-clear");
      if (clear) {
        clear.addEventListener("click", async () => {
          if (!confirm("Clear this model's price? Its cost will show as unpriced.")) return;
          try {
            await api("/api/v1/models/prices" + qs({ model: m.model }), { method: "DELETE" });
            load();
          } catch (err) {
            if (err.message === "unauthorized") return;
            // The row is probably stale (changed elsewhere): refresh the list
            // and put the message where the admin is looking.
            await load(`Could not clear the price of ${m.model}: ${err.message}. The list has been refreshed.`);
            card.querySelector(".pr-notice").scrollIntoView({ block: "center" });
          }
        });
      }
    });
    const addRow = card.querySelector(".pr-add");
    card.querySelector(".pr-add-save").addEventListener("click", () =>
      save(addRow.querySelector(".price-model-input").value.trim(), addRow));
  }

  await load();
}

// ---------------------------------------------------------------- price import (specs/price-import)

// parseFeed, classifyModels, buildPriceBody and the PRICE_* constants are globals
// from price-import.js, which index.html loads first; it is a separate file so
// the unit tests can run it under Node (plan D-a).
const PRICE_FEED_TIMEOUT_MS = 15000;
const PRICE_LABELS = Object.fromEntries(PRICE_FIELDS);
const PRICE_IMPORT_STATUS = {
  "importable": ["importable", "ok", "the feed has a list price that differs from the current one"],
  "unchanged": ["unchanged", "", "the feed's input and output prices equal the current ones"],
  "no-match": ["no match", "", "no feed entry has this model's normalized name; price it by hand"],
  "ambiguous": ["ambiguous", "warn", "more than one feed entry has this model's normalized name; price it by hand"],
  "not-priced": ["not priced in feed", "", "the feed lists this model without a usable input and output price"],
};

const feedError = (message) => Object.assign(new Error(message), { feed: true });
const tooLarge = () => feedError("the feed is larger than 5 MB");

async function readFeedBody(res) {
  if (Number(res.headers.get("Content-Length")) > PRICE_FEED_MAX_BYTES) throw tooLarge();
  if (!res.body || !res.body.getReader) return res.text();
  // Streamed with a running count so an oversized body is dropped before it
  // is held in memory whole, whatever Content-Length claimed.
  const reader = res.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > PRICE_FEED_MAX_BYTES) { reader.cancel(); throw tooLarge(); }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const c of chunks) { bytes.set(c, offset); offset += c.byteLength; }
  return new TextDecoder().decode(bytes);
}

async function fetchPriceFeed() {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), PRICE_FEED_TIMEOUT_MS);
  const timedOut = () => feedError("benchlm.ai did not answer within 15 seconds");
  try {
    let res;
    try {
      // No credentials and no referrer. benchlm.ai still sees the admin's IP
      // address and, via Origin, the console's host (spec, Security considerations).
      res = await fetch(PRICE_FEED_URL, {
        credentials: "omit", referrerPolicy: "no-referrer", cache: "no-store", signal: ctrl.signal,
      });
    } catch (e) {
      if (ctrl.signal.aborted) throw timedOut();
      throw feedError("the request failed or was blocked — offline, a proxy, a content-security " +
                      "policy or CORS (the browser does not say which)");
    }
    if (!res.ok) throw feedError(`benchlm.ai answered HTTP ${res.status}`);
    let text;
    try {
      text = await readFeedBody(res);
    } catch (e) {
      if (ctrl.signal.aborted) throw timedOut();
      throw e.feed ? e : feedError("the download was interrupted");
    }
    const feed = parseFeed(text);
    if (!feed.ok) throw feedError(feed.error);
    return feed;
  } finally {
    clearTimeout(timer);
  }
}

function priceImportCard(getModels, reloadPrices) {
  const card = document.createElement("div");
  card.className = "card";
  // Selection, typed cache prices and results are keyed by model name, which
  // the price page lists once each, so they survive re-classification.
  const st = { phase: "idle", error: "", notice: "", feed: null, rows: [], ticked: new Set(),
               cache: new Map(), results: new Map(), applying: false, signedOut: false };

  const selected = () => st.rows.filter((r) => st.ticked.has(r.model));

  function resultHtml(res) {
    if (!res) return "";
    if (res.state === "saving") return '<span class="pi-result">saving…</span>';
    if (res.state === "ok") return '<span class="pi-result ok">✓ applied</span>';
    if (res.state === "fail") return `<span class="pi-result fail">✕ not applied: ${esc(res.message)}</span>`;
    return '<span class="pi-result">not applied</span>';
  }

  function cacheRowHtml(r, i) {
    const vals = st.cache.get(r.model) || {};
    return `<tr class="pi-cache-row"><td></td><td colspan="8"><div class="pi-cache">
      <span class="helper-text">No price is set for this model and the feed has no cache
        prices. Enter them, in USD per million tokens, to apply it.</span>
      ${PRICE_CACHE_FIELDS.map((f) => `<label class="pi-cache-field">
        <span class="microlabel">${PRICE_LABELS[f]}</span>
        <input class="price-input" type="number" min="0" max="10000" step="any"
          data-i="${i}" data-field="${f}" value="${esc(vals[f] || "")}"
          ${st.applying ? "disabled" : ""}></label>`).join("")}
    </div></td></tr>`;
  }

  function rowHtml(r, i) {
    const ticked = st.ticked.has(r.model);
    const [label, cls, why] = PRICE_IMPORT_STATUS[r.status];
    const now = (f) => (r.current ? "$" + esc(r.current[f]) : '<span class="pi-dim">unpriced</span>');
    const feedVal = (v, changed) => (v == null ? '<span class="pi-dim">—</span>'
      : `<span class="${changed ? "pi-changed" : "pi-dim"}">$${v}</span>`);
    return `<tr class="${ticked ? "pi-ticked" : ""}">
      <td>${r.tickable ? `<input type="checkbox" class="pi-tick" data-i="${i}"
        ${ticked ? "checked" : ""} ${st.applying ? "disabled" : ""}
        aria-label="Import the price for ${esc(r.model)}">` : ""}</td>
      <td>${modelCell(r.model)}</td>
      <td>${r.feedNames.length ? r.feedNames.map((n) => modelCell(n)).join("") : '<span class="pi-dim">—</span>'}</td>
      <td class="num">${now("input")}</td><td class="num">${feedVal(r.feedInput, r.changed.input)}</td>
      <td class="num">${now("output")}</td><td class="num">${feedVal(r.feedOutput, r.changed.output)}</td>
      <td><span class="badge ${cls}" title="${esc(why)}">${label}</span></td>
      <td>${resultHtml(st.results.get(r.model))}</td></tr>
      ${ticked && !r.current ? cacheRowHtml(r, i) : ""}`;
  }

  function previewHtml() {
    const f = st.feed;
    const importable = st.rows.filter((r) => r.tickable).length;
    return `
      <p class="helper-text pi-source">Source:
        <a href="https://benchlm.ai" target="_blank" rel="noopener noreferrer">benchlm.ai</a>
        · feed updated ${f.lastUpdated ? esc(f.lastUpdated) : "(no date given)"}
        · ${fmt(importable)} of ${fmt(st.rows.length)} models importable${f.skipped
          ? ` · ${fmt(f.skipped)} unreadable feed entr${f.skipped === 1 ? "y" : "ies"} skipped` : ""}.
        Input and output list prices only: the feed has no cache prices, so a model's
        current cache prices are kept, and a model with no price needs them typed in.</p>
      ${st.notice ? `<p class="row-error" role="alert">${esc(st.notice)}</p>` : ""}
      ${st.signedOut ? '<p><button class="btn btn-accent pi-signin">Sign in again</button></p>' : ""}
      <div class="table-scroll"><table>
        <thead><tr><th></th><th>Model</th><th>Feed entry</th>
          <th class="num">Input now</th><th class="num">Input feed</th>
          <th class="num">Output now</th><th class="num">Output feed</th>
          <th>Status</th><th>Result</th></tr></thead>
        <tbody>${st.rows.map(rowHtml).join("") ||
          '<tr><td colspan="9" class="empty">no models on this page yet</td></tr>'}</tbody>
      </table></div>
      <div class="pi-toolbar">
        <button class="btn btn-accent pi-apply" disabled>Apply</button>
        <button class="btn btn-ghost pi-all" ${st.applying || !importable ? "disabled" : ""}>select all importable</button>
        <button class="btn btn-ghost pi-none" ${st.applying ? "disabled" : ""}>clear selection</button>
        <span class="helper-text pi-blocked" aria-live="polite"></span>
      </div>`;
  }

  function updateApply() {
    const apply = card.querySelector(".pi-apply");
    if (!apply) return;
    const sel = selected();
    const blocked = [];
    sel.forEach((r) => {
      const built = buildPriceBody(r, st.cache.get(r.model));
      if (!built.ok) blocked.push(r.model);
      const i = st.rows.indexOf(r);
      card.querySelectorAll(`input[data-i="${i}"][data-field]`).forEach((el) => {
        // Flag only what was typed and is wrong; an untouched empty field is
        // simply still to do, and the line below the table says so.
        const bad = el.validity.badInput
          || (!built.ok && built.fields.includes(el.dataset.field) && el.value !== "");
        el.classList.toggle("invalid", bad);
        el.setAttribute("aria-invalid", String(bad));
      });
    });
    apply.disabled = st.applying || st.signedOut || !sel.length || blocked.length > 0;
    apply.textContent = st.applying ? "Applying…" : sel.length ? `Apply ${sel.length} selected` : "Apply";
    card.querySelector(".pi-blocked").textContent = blocked.length
      ? `Enter all three cache prices (0 to 10,000) for: ${blocked.join(", ")}` : "";
  }

  function render(focusSel) {
    const busy = st.phase === "loading" || st.applying;
    card.innerHTML = `
      <div class="card-head pi-head"><span class="card-title">Import from benchlm.ai</span>
        <div class="card-tools">
          ${st.phase === "preview" ? `<button class="btn btn-ghost pi-close" ${busy ? "disabled" : ""}>close preview</button>` : ""}
          <button class="btn pi-load" ${busy ? "disabled" : ""}>${st.phase === "loading" ? "Loading…" : "Load prices from benchlm.ai"}</button>
        </div></div>
      ${st.phase === "error" ? `<p class="row-error" role="alert">Could not load prices from benchlm.ai:
        ${esc(st.error)}. No price was changed.</p>` : ""}
      ${st.phase === "preview" ? previewHtml() : `<p class="helper-text">Fetches benchlm.ai's public list
        prices from this browser and shows what would change. Nothing is saved until you tick
        models and apply them.</p>`}`;

    card.querySelector(".pi-load").addEventListener("click", loadFeed);
    const close = card.querySelector(".pi-close");
    if (close) close.addEventListener("click", () => { st.phase = "idle"; st.notice = ""; render(); });
    if (st.phase !== "preview") return;

    card.querySelectorAll(".pi-tick").forEach((el) => el.addEventListener("change", () => {
      const r = st.rows[Number(el.dataset.i)];
      if (el.checked) st.ticked.add(r.model); else st.ticked.delete(r.model);
      render(`.pi-tick[data-i="${el.dataset.i}"]`);
    }));
    card.querySelectorAll("input[data-field]").forEach((el) => el.addEventListener("input", () => {
      const r = st.rows[Number(el.dataset.i)];
      st.cache.set(r.model, { ...st.cache.get(r.model), [el.dataset.field]: el.value });
      updateApply();
    }));
    card.querySelector(".pi-all").addEventListener("click", () => {
      st.rows.forEach((r) => { if (r.tickable) st.ticked.add(r.model); });
      render();
    });
    card.querySelector(".pi-none").addEventListener("click", () => { st.ticked.clear(); render(); });
    card.querySelector(".pi-apply").addEventListener("click", apply);
    const signIn = card.querySelector(".pi-signin");
    if (signIn) signIn.addEventListener("click", logout);
    updateApply();
    if (focusSel) { const el = card.querySelector(focusSel); if (el) el.focus(); }
  }

  async function loadFeed() {
    st.phase = "loading";
    render();
    try {
      st.feed = await fetchPriceFeed();
      st.rows = classifyModels(getModels(), st.feed.entries);
      st.ticked.clear(); st.cache.clear(); st.results.clear(); st.notice = ""; st.signedOut = false;
      st.phase = "preview";
    } catch (e) {
      st.phase = "error";
      st.error = e.feed ? e.message : `unexpected error (${e.message})`;
    }
    render();
  }

  async function apply() {
    const work = selected().map((r) => [r, buildPriceBody(r, st.cache.get(r.model))]);
    if (!work.length || work.some(([, built]) => !built.ok)) return;
    st.applying = true;
    st.notice = "";
    // Only this run's rows lose their old result; earlier ones stay visible.
    work.forEach(([r]) => st.results.delete(r.model));
    render();
    // One at a time so each row gets its own answer, and a failure touches
    // only its row (spec AC10, plan D-d).
    for (const [r, built] of work) {
      if (st.signedOut) { st.results.set(r.model, { state: "skipped" }); continue; }
      st.results.set(r.model, { state: "saving" });
      render();
      try {
        await api("/api/v1/models/prices",
                  { method: "PUT", body: JSON.stringify(built.body), keepSession: true });
        st.results.set(r.model, { state: "ok" });
      } catch (e) {
        // Every later row would fail the same way, so stop. The session is
        // kept until the admin has seen which rows saved (spec use case 6).
        st.signedOut = e.message === "unauthorized";
        st.results.set(r.model, { state: "fail",
                                  message: st.signedOut ? "your session expired" : e.message });
      }
    }
    st.applying = false;
    if (st.signedOut) {
      st.notice = "Your session expired. Rows marked ✓ applied were saved; the others were not. " +
                  "Sign in again to apply them.";
      render();
      return;
    }
    // load() calls refresh(), which re-classifies: applied rows become
    // "unchanged" and drop out of the selection; failed rows stay ticked.
    try {
      await reloadPrices();
    } catch (e) {
      st.notice = `The prices could not be reloaded (${e.message}); refresh the page to see them.`;
      render();
    }
  }

  // Called after every load of the price table, so the preview never offers
  // (or re-sends) prices that a hand edit on this page has since replaced.
  card.refresh = () => {
    if (st.phase !== "preview" || st.applying) return;
    st.rows = classifyModels(getModels(), st.feed.entries);
    st.ticked = new Set(st.rows.filter((r) => r.tickable && st.ticked.has(r.model)).map((r) => r.model));
    render();
  };

  render();
  return card;
}

// ---------------------------------------------------------------- users

// ---- project scope editor (specs/project-access AC3, AC22) ----

const PROJECT_NAME = /^[A-Za-z0-9._-]{1,64}$/;

/* Registered projects, projects seen in the data, and whatever the account
   already holds — so access can be granted before the first session arrives. */
async function offeredProjects(extra = []) {
  // A failed fetch surfaces as an error, not as a half-empty checklist.
  const [seen, registered] = await Promise.all([
    apiJSON("/api/v1/projects"), apiJSON("/api/v1/projects/manage"),
  ]);
  return [...new Set([...seen, ...registered.map((p) => p.name), ...extra])].sort();
}

function scopeCell(u) {
  if (u.role === "admin" || u.all_projects) return '<span class="badge ok">all projects</span>';
  if (!u.projects.length) return '<span class="badge warn">no projects yet</span>';
  return `<span class="scope-names">${u.projects.map((p) =>
    `<span class="badge">${esc(p)}</span>`).join("")}</span>`;
}

function projectCheck(name, checked, disabled) {
  return `<label class="check"><input type="checkbox" class="sc-p" value="${esc(name)}"
    ${checked ? "checked" : ""} ${disabled ? "disabled" : ""}> ${esc(name)}</label>`;
}

function scopeEditorHtml(offered, current) {
  const all = !!current.all_projects;
  return `<div class="scope-editor">
    <label class="check"><input type="checkbox" class="sc-all" ${all ? "checked" : ""}>
      all projects — including sessions that carry no project name</label>
    <div class="scope-list ${all ? "muted" : ""}">${offered.length
      ? offered.map((p) => projectCheck(p, current.projects.includes(p), all)).join("")
      : '<span class="helper-text sc-none">no projects known yet — add a name below</span>'}</div>
    <div class="scope-add">
      <input class="sc-new" placeholder="another project name" spellcheck="false" ${all ? "disabled" : ""}>
      <button type="button" class="btn btn-ghost sc-add-btn" ${all ? "disabled" : ""}>add</button>
    </div></div>`;
}

function wireScopeEditor(editor) {
  const allBox = $(".sc-all", editor);
  allBox.addEventListener("change", () => {
    editor.querySelectorAll(".sc-p, .sc-new, .sc-add-btn").forEach((el) => {
      el.disabled = allBox.checked;
    });
    $(".scope-list", editor).classList.toggle("muted", allBox.checked);
  });
  const add = () => {
    const name = $(".sc-new", editor).value.trim();
    if (!PROJECT_NAME.test(name)) { alert("project name: letters, digits, . _ - (max 64)"); return; }
    const existing = [...editor.querySelectorAll(".sc-p")].find((c) => c.value === name);
    if (existing) existing.checked = true;
    else {
      const list = $(".scope-list", editor);
      list.querySelector(".sc-none")?.remove();
      list.insertAdjacentHTML("beforeend", projectCheck(name, true, false));
    }
    $(".sc-new", editor).value = "";
  };
  $(".sc-add-btn", editor).addEventListener("click", add);
  $(".sc-new", editor).addEventListener("keydown", (e) => { if (e.key === "Enter") add(); });
}

/* The request body the server expects: {all: true} or {projects: [...]}. */
function readScope(editor) {
  if ($(".sc-all", editor).checked) return { all: true };
  return { projects: [...editor.querySelectorAll(".sc-p:checked")].map((c) => c.value) };
}

async function viewUsers() {
  if (state.me.role !== "admin") { location.hash = "#/overview"; return; }
  main.innerHTML = "";
  const offered = await offeredProjects();
  const create = document.createElement("div");
  create.className = "card";
  create.innerHTML = `
    <div class="card-head"><span class="card-title">Add a team member</span></div>
    <div class="filters">
      <div class="field"><label class="microlabel">Username</label>
        <input id="u-name" placeholder="alice" spellcheck="false"></div>
      <div class="field"><label class="microlabel">Role</label>
        <select id="u-role">
          <option value="member" selected>member — console + export</option>
          <option value="admin">admin — everything</option>
        </select></div>
      <button class="btn btn-accent" id="u-create">Create account</button>
    </div>
    <div id="u-scope" style="margin-top:16px">
      <label class="microlabel">Projects this member may see</label>
      ${scopeEditorHtml(offered, { all_projects: false, projects: [] })}
    </div>
    <p class="helper-text" style="margin-top:12px">A new member sees nothing until
      granted here. API keys are not scoped: a member or admin key reads every project.</p>
    <div id="u-reveal"></div>`;
  main.appendChild(create);
  wireScopeEditor($("#u-scope .scope-editor"));
  $("#u-role").addEventListener("change", (e) =>
    $("#u-scope").classList.toggle("hidden", e.target.value === "admin"));

  const listCard = document.createElement("div");
  listCard.className = "card";
  main.appendChild(listCard);

  function tempPwReveal(res) {
    return `<div class="token-reveal">
      <span class="microlabel">temporary password for ${esc(res.username)} (shown once)</span>
      <code>${esc(res.temp_password)}</code>
      <span class="helper-text">they set their own on first login</span></div>`;
  }

  async function loadUsers() {
    const users = await apiJSON("/api/v1/users");
    listCard.innerHTML = `
      <div class="card-head"><span class="card-title">Accounts</span></div>
      <div class="table-scroll"><table>
        <thead><tr><th>Username</th><th>Role</th><th>Projects</th><th>Status</th>
          <th>Last login</th><th>Created</th><th></th></tr></thead>
        <tbody>${users.map((u) => `<tr>
          <td style="color:var(--text-primary)">${esc(u.username)}</td>
          <td><span class="badge">${esc(u.role)}</span></td>
          <td>${scopeCell(u)}</td>
          <td>${u.disabled_at ? '<span class="badge warn">disabled</span>'
              : u.must_change_password ? '<span class="badge">must change pw</span>'
              : '<span class="badge ok">active</span>'}</td>
          <td>${u.last_login_at ? timeAgo(u.last_login_at) : "never"}</td>
          <td>${fmtTime(u.created_at)}</td>
          <td style="text-align:right">
            ${u.role === "admin" ? "" :
              `<button class="btn btn-ghost u-scope" data-id="${u.id}">access</button>`}
            <button class="btn btn-ghost u-reset" data-id="${u.id}">reset password</button>
            ${u.disabled_at ? "" :
              `<button class="btn btn-ghost btn-danger u-del" data-id="${u.id}">disable</button>`}
          </td></tr>
          <tr class="scope-row hidden" data-id="${u.id}"><td colspan="7"></td></tr>`).join("")}
        </tbody></table></div>`;
    const byId = Object.fromEntries(users.map((u) => [String(u.id), u]));
    listCard.querySelectorAll(".u-scope").forEach((b) =>
      b.addEventListener("click", async () => {
        const row = listCard.querySelector(`.scope-row[data-id="${b.dataset.id}"]`);
        if (!row.classList.contains("hidden")) { row.classList.add("hidden"); return; }
        const u = byId[b.dataset.id];
        const cell = row.firstElementChild;
        let offered;
        try { offered = await offeredProjects(u.projects); } catch (err) { alert(err.message); return; }
        cell.innerHTML = `<label class="microlabel">Projects ${esc(u.username)} may see</label>
          ${scopeEditorHtml(offered, u)}
          <div class="scope-actions">
            <button class="btn btn-accent sc-save">Save access</button>
            <button class="btn btn-ghost sc-cancel">cancel</button>
          </div>`;
        wireScopeEditor($(".scope-editor", cell));
        $(".sc-cancel", cell).addEventListener("click", () => row.classList.add("hidden"));
        $(".sc-save", cell).addEventListener("click", async () => {
          try {
            await apiJSON(`/api/v1/users/${u.id}/scope`, {
              method: "PUT", body: JSON.stringify(readScope($(".scope-editor", cell))),
            });
            loadUsers();
          } catch (err) { alert(err.message); }
        });
        row.classList.remove("hidden");
      }));
    listCard.querySelectorAll(".u-reset").forEach((b) =>
      b.addEventListener("click", async () => {
        const res = await apiJSON(`/api/v1/users/${b.dataset.id}/reset`, { method: "POST" });
        $("#u-reveal").innerHTML = tempPwReveal(res);
        loadUsers();
      }));
    listCard.querySelectorAll(".u-del").forEach((b) =>
      b.addEventListener("click", async () => {
        if (!confirm("Disable this account? They can be re-enabled with a password reset.")) return;
        try {
          await api(`/api/v1/users/${b.dataset.id}`, { method: "DELETE" });
        } catch (err) { alert(err.message); }
        loadUsers();
      }));
  }

  $("#u-create").addEventListener("click", async () => {
    const username = $("#u-name").value.trim();
    if (!username) return;
    try {
      const role = $("#u-role").value;
      const res = await apiJSON("/api/v1/users", {
        method: "POST",
        body: JSON.stringify({ username, role,
          ...(role === "admin" ? {} : readScope($("#u-scope .scope-editor"))) }),
      });
      $("#u-name").value = "";
      $("#u-reveal").innerHTML = tempPwReveal(res);
      loadUsers();
    } catch (err) { alert(err.message); }
  });

  await loadUsers();
}

// ---------------------------------------------------------------- router / auth

const VIEWS = { overview: viewOverview, sessions: viewSessions, projects: viewProjects,
                export: viewExport, users: viewUsers, keys: viewKeys, prices: viewPrices };

async function route() {
  if (!state.me) return;
  const hash = location.hash || "#/overview";
  const m = hash.match(/^#\/session\/(.+)$/);
  hideTooltip();
  document.querySelectorAll("#nav a").forEach((a) =>
    a.classList.toggle("active", hash.startsWith(a.getAttribute("href")) ||
      (m && a.dataset.view === "sessions")));
  const view = hash.slice(2);
  const dataView = m || ["overview", "sessions", "projects", "export"].includes(view)
    || !VIEWS[view];
  try {
    if (Array.isArray(state.me.scope) && !state.me.scope.length && dataView) {
      main.innerHTML = `<div class="card"><div class="empty"><span class="glyph">◌</span>
        an admin has not granted you any project yet — ask an admin to grant you
        one</div></div>`;
    } else if (m) await viewSession(decodeURIComponent(m[1]));
    else await (VIEWS[view] || viewOverview)();
  } catch (err) {
    if (err.message !== "unauthorized") {
      main.innerHTML = `<div class="card"><div class="empty">
        <span class="glyph">✕</span>${esc(err.message)}</div></div>`;
    }
  }
}

function showLogin(step) {
  $("#shell").classList.add("hidden");
  $("#login").classList.remove("hidden");
  $("#login-step-cred").classList.toggle("hidden", step === "pw");
  $("#login-step-pw").classList.toggle("hidden", step !== "pw");
  (step === "pw" ? $("#pw-current") : $("#login-user")).focus();
}

function logout() {
  if (state.token) {
    fetch("/api/v1/auth/logout", {
      method: "POST",
      headers: { Authorization: "Bearer " + state.token },
    }).catch(() => {});
  }
  localStorage.removeItem("gt_session");
  state.token = "";
  state.me = null;
  showLogin("cred");
}

function enterShell(me) {
  state.me = me;
  $("#login").classList.add("hidden");
  $("#login-error").textContent = "";
  $("#shell").classList.remove("hidden");
  $("#who").innerHTML = `${esc(me.name)} <span class="role">· ${esc(me.role)}</span>`;
  const note = $("#scope-note");
  if (Array.isArray(me.scope)) {
    note.textContent = me.scope.length
      ? `${me.scope.length} of the team's projects` : "no project granted yet";
    note.title = me.scope.join(", ");
  }
  note.classList.toggle("hidden", !Array.isArray(me.scope));
  $("#server-version").textContent = "v" + me.version;
  $("#nav-keys").classList.toggle("hidden", me.role !== "admin");
  $("#nav-users").classList.toggle("hidden", me.role !== "admin");
  $("#nav-prices").classList.toggle("hidden", me.role !== "admin");
  route();
}

async function doLogin() {
  const username = $("#login-user").value.trim();
  const password = $("#login-pass").value;
  if (!username || !password) return;
  $("#login-error").textContent = "";
  try {
    const res = await fetch("/api/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    state.token = data.token;
    localStorage.setItem("gt_session", data.token);
    if (data.must_change_password) {
      $("#pw-current").value = password;   // they just proved they know it
      showLogin("pw");
    } else {
      enterShell(data);
    }
  } catch (err) {
    $("#login-error").textContent = err.message;
  } finally {
    $("#login-pass").value = "";
  }
}

async function doChangePassword() {
  const current = $("#pw-current").value;
  const pw = $("#pw-new").value;
  if (pw.length < 8) { $("#login-error").textContent = "new password needs at least 8 characters"; return; }
  if (pw !== $("#pw-confirm").value) { $("#login-error").textContent = "passwords do not match"; return; }
  $("#login-error").textContent = "";
  try {
    const res = await apiJSON("/api/v1/auth/password", {
      method: "POST",
      body: JSON.stringify({ current_password: current, new_password: pw }),
    });
    state.token = res.token;               // password change re-issues the session
    localStorage.setItem("gt_session", res.token);
    ["#pw-current", "#pw-new", "#pw-confirm"].forEach((s) => { $(s).value = ""; });
    enterShell(await apiJSON("/api/v1/me"));
  } catch (err) {
    if (err.message !== "unauthorized") $("#login-error").textContent = err.message;
  }
}

async function restoreSession() {
  if (!state.token) return showLogin("cred");
  try {
    const me = await apiJSON("/api/v1/me");
    if (me.must_change_password) {
      $("#pw-current").value = "";
      showLogin("pw");
    } else {
      enterShell(me);
    }
  } catch (err) { /* apiJSON already logged out on 401 */ }
}

window.addEventListener("hashchange", route);
$("#logout").addEventListener("click", logout);
$("#login-btn").addEventListener("click", doLogin);
$("#pw-btn").addEventListener("click", doChangePassword);
["#login-user", "#login-pass"].forEach((s) =>
  $(s).addEventListener("keydown", (e) => { if (e.key === "Enter") doLogin(); }));
["#pw-current", "#pw-new", "#pw-confirm"].forEach((s) =>
  $(s).addEventListener("keydown", (e) => { if (e.key === "Enter") doChangePassword(); }));

restoreSession();
