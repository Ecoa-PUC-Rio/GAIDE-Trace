/* GAIDE-Trace console — Security page (specs/security-scan).

   Two halves, as the spec frames them: exposure (what potentially
   confidential material the ledger holds, as masked pointers) and activity
   (what security work actually happened, and which code-touching sessions
   show none). The analysis itself is server-side (ADR 0003); this file only
   renders it.

   Chart decisions, because they are not free choices here:

   - Findings per day is ONE series in the critical status colour, with the
     severity split in the tooltip and in the table twin. Stacking
     high/medium/low would encode an ordinal scale as three touching status
     hues whose adjacent-pair separation for colour-vision deficiency cannot
     be validated here (`node` is not available to run the validator), so the
     breakdown goes where it is unambiguous: the tiles, the tooltip, the
     tables.
   - Activity per day stacks the API's own leading categories with the
     console's validated categorical tokens in fixed order, folding the rest
     into "other" — the same contract the Overview model chart already has.

   Both carry a legend when they have more than one series, a hover tooltip
   and a table twin, so no colour ever carries meaning alone.

   Loaded before app.js, so nothing here may touch app.js's bindings at the
   top level — only inside functions, which run after it. */

"use strict";

const SEVERITY_STEPS = [
  { key: "high", label: "High", color: "var(--critical)" },
  { key: "medium", label: "Medium", color: "var(--serious)" },
  { key: "low", label: "Low", color: "var(--ink-3)" },
];

// The same validated steps the model chart uses, read from the stylesheet
// rather than copied as hex: style.css is the one place the palette lives.
const CATEGORY_FILLS = ["var(--series-1)", "var(--series-2)",
                        "var(--series-3)", "var(--series-4)"];
const CATEGORY_OTHER_FILL = "var(--series-other)";

/* What the page can and cannot see. Shown on every render, including the
   empty one: "no findings" must never read as a clean bill of health (AC30). */
const SECURITY_LIMITS = [
  `Event text was already redacted at capture, so most credentials never reach
   the ledger in the first place — the markers below count what redaction
   caught. Transcript snapshots are raw by design, which is where an
   unredacted value does show up.`,
  `Only what an agent session ran is in the ledger. A scanner that runs in CI,
   in a pre-commit hook or by hand outside a session is invisible here, so
   "no activity" means "none recorded", not "none happened".`,
  `Detection is pattern-based: it has false positives and false negatives.
   Every finding is a pointer to look at, never a verdict.`,
];

const severityBadge = (severity) =>
  `<span class="badge sev-${esc(severity)}">${esc(severity)}</span>`;

const sessionLink = (id) =>
  `<a class="mono-id" href="#/session/${encodeURIComponent(id)}">${esc(id)}</a>`;

const emptyCard = (glyph, text) =>
  `<div class="empty"><span class="glyph">${glyph}</span>${text}</div>`;

const cardHead = (title, tools) =>
  `<div class="card-head"><span class="card-title">${esc(title)}</span>
     ${tools ? `<div class="card-tools">${tools}</div>` : ""}</div>`;

function card(title, inner, tools) {
  const el = document.createElement("div");
  el.className = "card";
  el.innerHTML = cardHead(title, tools) + inner;
  return el;
}

function omittedNote(n, what) {
  return n ? `<p class="hint">${fmt(n)} more ${esc(what)} not shown (the totals
    above cover all of them).</p>` : "";
}

/* A day with no findings is a zero, not a missing slot. */
function fillSecurityDays(days, zero) {
  if (days.length < 2) return days;
  const calendar = calendarDays(days[0].day, days[days.length - 1].day);
  if (!calendar) return days;
  const byDay = Object.fromEntries(days.map((d) => [d.day, d]));
  return calendar.map((day) => byDay[day] || Object.assign({ day }, zero));
}

// ---------------------------------------------------------------- tiles

function securityTiles(s) {
  const e = s.exposure.totals;
  const a = s.activity.totals;
  const c = s.activity.coverage;
  const pct = c.code_sessions
    ? Math.round((c.with_any / c.code_sessions) * 100) + "%" : "—";
  const tiles = [
    ["High findings", fmt(e.high), e.high ? "credentials or sensitive paths" : "none in this window", e.high > 0],
    ["Medium", fmt(e.medium), "personal data, tokens, terms", false],
    ["Low", fmt(e.low), "e-mail, phone, redaction markers", false],
    ["Sessions affected", fmt(e.sessions),
     `${fmt(e.distinct_values)} distinct value${e.distinct_values === 1 ? "" : "s"}`, false],
    ["Security actions", fmt(a.actions),
     a.suppressions ? `${fmt(a.suppressions)} suppression${a.suppressions === 1 ? "" : "s"} recorded` : "no suppressions",
     a.suppressions > 0],
    ["Scan coverage", pct,
     `${fmt(c.with_any)} of ${fmt(c.code_sessions)} sessions that changed code`,
     c.code_sessions > 0 && c.with_any < c.code_sessions],
  ];
  const row = document.createElement("div");
  row.className = "kpi-row";
  row.innerHTML = tiles.map(([label, value, note, bad]) => `
    <div class="card kpi"><span class="microlabel">${label}</span>
      <div class="kpi-value">${value}</div>
      <div class="kpi-note${bad ? " bad" : ""}">${esc(note)}</div></div>`).join("");
  return row;
}

// ---------------------------------------------------------------- limits

function securityLimitsCard(s, reload) {
  const scan = s.scan;
  const badges = [];
  if (scan.stale) {
    badges.push(`<span class="badge warn">terms changed since the last full scan</span>`);
  }
  if (scan.truncated_sessions) {
    badges.push(`<span class="badge warn">${fmt(scan.truncated_sessions)} session(s)
      hit the scan caps</span>`);
  }
  const isAdmin = state.me.role === "admin";
  const el = card("What this page can and cannot see",
    `<p class="hint">${badges.join(" ")}</p>
     <ul class="limits">${SECURITY_LIMITS.map((t) => `<li>${esc(t)}</li>`).join("")}</ul>
     <p class="hint">${scan.scanned_at
       ? `Stored data last scanned in full: ${esc(fmtTime(scan.scanned_at))}.`
       : `Everything here was scanned as it arrived; no full pass over stored
          data has run yet, which is what a rule or term change needs.`}</p>
     ${isAdmin ? `<div class="form-actions">
        <button class="btn" id="sec-rescan">Rescan stored data</button>
        <span class="hint" id="sec-rescan-state"></span></div>` : ""}`);
  if (isAdmin) wireRescan(el, s, reload);
  return el;
}

/* The rescan is a background job: start it, then poll while it runs. The
   timer is parked on window so a navigation away can cancel it. */
function wireRescan(el, s, reload) {
  const button = $("#sec-rescan", el);
  const label = $("#sec-rescan-state", el);

  const show = (job) => {
    if (!job || job.state === "idle") {
      label.textContent = "";
      label.classList.remove("bad");
      return;
    }
    const where = job.project ? ` (${job.project})` : "";
    if (job.state === "running") {
      const done = job.total ? ` ${job.done}/${job.total} sessions` : "";
      label.textContent = `rescanning${where}…${done}`;
    } else if (job.state === "failed") {
      label.textContent = `last rescan failed: ${job.error || "unknown error"}`;
    } else {
      label.textContent = `last rescan${where}: ${fmt(job.sessions || 0)} sessions` +
        (job.failed && job.failed.length ? `, ${job.failed.length} skipped` : "");
    }
    label.classList.toggle("bad", job.state === "failed" ||
      Boolean(job.failed && job.failed.length));
  };

  const poll = () => {
    clearInterval(window.__secRescanTimer);
    window.__secRescanTimer = setInterval(async () => {
      const job = await apiJSON("/api/v1/security/rescan").catch(() => null);
      show(job);
      if (!job || job.state !== "running") {
        clearInterval(window.__secRescanTimer);
        button.disabled = false;
        reload();
      }
    }, 1000);
  };

  show(s.scan.rescan);
  if (s.scan.rescan && s.scan.rescan.state === "running") {
    button.disabled = true;
    poll();
  }
  button.addEventListener("click", async () => {
    button.disabled = true;
    const body = state.filters.project ? { project: state.filters.project } : {};
    const res = await api("/api/v1/security/rescan",
                          { method: "POST", body: JSON.stringify(body) })
      .catch((err) => err);
    if (res instanceof Error) {
      label.textContent = res.message;
      label.classList.add("bad");
      button.disabled = false;
      return;
    }
    show(await res.json());
    poll();
  });
}

// ---------------------------------------------------------------- charts

function findingsDayChart(container, perDay) {
  const zero = { high: 0, medium: 0, low: 0 };
  const days = fillSecurityDays(perDay, zero);
  const total = (d) => (d.high || 0) + (d.medium || 0) + (d.low || 0);
  const W = 640, H = 240, padL = 46, padR = 10, padT = 10, padB = 26;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const max = niceMax(maxOf(days, total));
  const ticks = [0, max / 2, max].map((t) => Math.round(t));
  const n = Math.max(days.length, 1);
  const band = plotW / n;
  const barW = Math.min(24, Math.max(2, band - 4));
  const y = (v) => padT + plotH * (1 - v / max);

  let bars = "", bands = "";
  days.forEach((d, i) => {
    const top = y(total(d));
    bars += barRect(padL + band * i + (band - barW) / 2, top, barW,
                    padT + plotH - top, "var(--critical)");
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

  container.innerHTML = `<div class="chart-wrap"><svg viewBox="0 0 ${W} ${H}" role="img"
    aria-label="Exposure findings per day">${grid}${bars}${xlabels}${bands}</svg></div>`;
  container.querySelectorAll(".hover-band").forEach((b) => {
    b.addEventListener("mousemove", (e) => {
      const d = days[Number(b.dataset.i)];
      showTooltip(`<div class="tt-title">${esc(d.day)}</div>` +
        SEVERITY_STEPS.map((s) => `<div class="tt-row">
          <span class="swatch" style="background:${s.color}"></span>${s.label}
          <b>${fmt(d[s.key] || 0)}</b></div>`).join(""), e.clientX, e.clientY);
    });
    b.addEventListener("mouseleave", hideTooltip);
  });
}

function findingsDayTable(container, perDay) {
  container.innerHTML = `<div class="table-scroll"><table>
    <thead><tr><th>Day</th><th class="num">High</th><th class="num">Medium</th>
      <th class="num">Low</th></tr></thead>
    <tbody>${perDay.map((d) => `<tr><td>${esc(d.day)}</td>
      <td class="num">${fmt(d.high || 0)}</td><td class="num">${fmt(d.medium || 0)}</td>
      <td class="num">${fmt(d.low || 0)}</td></tr>`).join("")}</tbody></table></div>`;
}

/* Stacked columns per day over the view's leading categories, rest in
   "other" — the same series contract as the model chart. */
function activityDayRows(activity) {
  const keys = activity.series.slice();
  const hasOther = activity.per_day.some((d) => !keys.includes(d.category));
  const byDay = new Map();
  activity.per_day.forEach((d) => {
    if (!byDay.has(d.day)) byDay.set(d.day, new Map());
    const key = keys.includes(d.category) ? d.category : null;
    const row = byDay.get(d.day);
    row.set(key, (row.get(key) || 0) + d.runs);
  });
  let days = [...byDay.keys()].sort();
  if (days.length > 1) days = calendarDays(days[0], days[days.length - 1]) || days;
  const all = hasOther ? [...keys, null] : keys;
  return {
    keys: all,
    days: days.map((day) => {
      const counts = new Map(all.map((k) => [k, (byDay.get(day) || new Map()).get(k) || 0]));
      return { day, counts, total: [...counts.values()].reduce((x, v) => x + v, 0) };
    }),
  };
}

const categoryFill = (key, keys) =>
  key === null ? CATEGORY_OTHER_FILL : CATEGORY_FILLS[keys.indexOf(key) % CATEGORY_FILLS.length];
const categoryLabel = (key) => (key === null ? "other" : key);

function activityDayChart(container, activity) {
  const { keys, days } = activityDayRows(activity);
  const W = 640, H = 240, padL = 46, padR = 10, padT = 10, padB = 26;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const max = niceMax(maxOf(days, (d) => d.total));
  const ticks = [0, max / 2, max].map((t) => Math.round(t));
  const n = Math.max(days.length, 1);
  const band = plotW / n;
  const barW = Math.min(24, Math.max(2, band - 4));
  const y = (v) => padT + plotH * (1 - v / max);

  let bars = "", bands = "";
  days.forEach((d, i) => {
    const x = padL + band * i + (band - barW) / 2;
    let acc = 0;
    keys.forEach((key) => {
      const v = d.counts.get(key) || 0;
      if (!v) return;
      const top = y(acc + v);
      // 2px surface gap between stacked segments (dataviz spec).
      const h = Math.max(1, padT + plotH - top - y(0) + y(acc) - 2);
      bars += barRect(x, top, barW, h, categoryFill(key, keys));
      acc += v;
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
    <div class="legend">${keys.map((k) => `<span class="key">
      <span class="swatch" style="background:${categoryFill(k, keys)}"></span>
      ${k === null ? bucketLabel("other") : esc(k)}</span>`).join("")}</div>
    <div class="chart-wrap"><svg viewBox="0 0 ${W} ${H}" role="img"
      aria-label="Security actions per day by category">${grid}${bars}${xlabels}${bands}</svg></div>`;
  container.querySelectorAll(".hover-band").forEach((b) => {
    b.addEventListener("mousemove", (e) => {
      const d = days[Number(b.dataset.i)];
      showTooltip(`<div class="tt-title">${esc(d.day)}</div>` +
        keys.map((k) => `<div class="tt-row">
          <span class="swatch" style="background:${categoryFill(k, keys)}"></span>
          ${k === null ? "other" : esc(k)}<b>${fmt(d.counts.get(k) || 0)}</b></div>`).join("") +
        `<div class="tt-row">${bucketLabel("total")}<b>${fmt(d.total)}</b></div>`,
        e.clientX, e.clientY);
    });
    b.addEventListener("mouseleave", hideTooltip);
  });
}

function activityDayTable(container, activity) {
  const { keys, days } = activityDayRows(activity);
  container.innerHTML = `<div class="table-scroll"><table>
    <thead><tr><th>Day</th>${keys.map((k) =>
      `<th class="num">${k === null ? "other" : esc(k)}</th>`).join("")}
      <th class="num">Total</th></tr></thead>
    <tbody>${days.map((d) => `<tr><td>${esc(d.day)}</td>
      ${keys.map((k) => `<td class="num">${fmt(d.counts.get(k) || 0)}</td>`).join("")}
      <td class="num">${fmt(d.total)}</td></tr>`).join("")}</tbody></table></div>`;
}

// ---------------------------------------------------------------- tables

function exposureRulesCard(exposure) {
  const rows = exposure.rules;
  if (!rows.length) {
    return card("Exposure by rule",
      emptyCard("◌", "no findings in this window — see the limits above before reading that as clean"));
  }
  return card("Exposure by rule",
    `<div class="table-scroll"><table>
      <thead><tr><th>Severity</th><th>Rule</th><th>Category</th>
        <th class="num">Findings</th><th class="num">Occurrences</th>
        <th class="num">Sessions</th><th class="num">Distinct values</th>
        <th>Last seen</th></tr></thead>
      <tbody>${rows.map((r) => `<tr>
        <td>${severityBadge(r.severity)}</td>
        <td><span class="model-name">${esc(r.rule)}</span></td>
        <td>${esc(r.category)}</td>
        <td class="num">${fmt(r.findings)}</td>
        <td class="num">${fmt(r.occurrences)}</td>
        <td class="num">${fmt(r.sessions)}</td>
        <td class="num">${fmt(r.distinct_values)}</td>
        <td>${r.last_ts ? esc(fmtTime(r.last_ts)) : "—"}</td></tr>`).join("")}
      </tbody></table></div>${omittedNote(exposure.rows_omitted.rules, "rules")}`);
}

function recurringCard(exposure) {
  const rows = exposure.recurring;
  const inner = rows.length
    ? `<p class="hint">One value seen in more than one session, grouped by its
         fingerprint. The value itself is never stored — rotate it once and it
         disappears from every session below.</p>
       <div class="table-scroll"><table>
        <thead><tr><th>Rule</th><th>Evidence</th><th class="num">Sessions</th>
          <th class="num">Findings</th><th>First</th></tr></thead>
        <tbody>${rows.map((r) => `<tr>
          <td>${severityBadge(r.severity)} ${esc(r.rule)}</td>
          <td><span class="mono-id">${esc(r.evidence)}</span></td>
          <td class="num">${fmt(r.sessions)}</td>
          <td class="num">${fmt(r.findings)}</td>
          <td>${r.first_ts ? esc(fmtTime(r.first_ts)) : "—"}</td></tr>`).join("")}
        </tbody></table></div>${omittedNote(exposure.rows_omitted.recurring, "values")}`
    : emptyCard("∴", "no value appears in more than one session");
  return card("Recurring values", inner);
}

function affectedSessionsCard(exposure) {
  const rows = exposure.sessions;
  const inner = rows.length
    ? `<div class="table-scroll"><table>
        <thead><tr><th>Session</th><th>Project</th><th>Member</th>
          <th class="num">High</th><th class="num">Med</th><th class="num">Low</th>
          <th>Last</th></tr></thead>
        <tbody>${rows.map((r) => `<tr>
          <td>${sessionLink(r.session_id)}</td>
          <td>${esc(r.project || "—")}</td><td>${esc(r.origin || "—")}</td>
          <td class="num">${fmt(r.high)}</td><td class="num">${fmt(r.medium)}</td>
          <td class="num">${fmt(r.low)}</td>
          <td>${r.last_ts ? esc(timeAgo(r.last_ts)) : "—"}</td></tr>`).join("")}
        </tbody></table></div>${omittedNote(exposure.rows_omitted.sessions, "sessions")}`
    : emptyCard("◌", "no session carries a finding in this window");
  return card("Most affected sessions", inner);
}

function securityToolsCard(activity) {
  const rows = activity.tools;
  const inner = rows.length
    ? `<div class="table-scroll"><table>
        <thead><tr><th>Category</th><th>Tool</th><th class="num">Runs</th>
          <th class="num">Sessions</th><th class="num">Clean</th>
          <th class="num">Findings</th><th class="num">Errors</th>
          <th class="num">Unknown</th><th>Last run</th></tr></thead>
        <tbody>${rows.map((r) => `<tr>
          <td>${esc(r.category)}</td>
          <td><span class="model-name">${esc(r.tool)}</span></td>
          <td class="num">${fmt(r.runs)}</td><td class="num">${fmt(r.sessions)}</td>
          <td class="num">${fmt(r.clean)}</td><td class="num">${fmt(r.findings)}</td>
          <td class="num">${fmt(r.errors)}</td><td class="num">${fmt(r.unknown)}</td>
          <td>${r.last_ts ? esc(fmtTime(r.last_ts)) : "—"}</td></tr>`).join("")}
        </tbody></table></div>
       <p class="hint">An outcome is only reported when the tool said so plainly;
         anything else stays <em>unknown</em> rather than guessed.</p>
       ${omittedNote(activity.rows_omitted.tools, "tools")}`
    : emptyCard("∴", `no security tool ran <em>in a session</em> in this window —
        a scanner in CI, in a pre-commit hook or run by hand is not in the ledger`);
  return card("Security tools that ran", inner);
}

function coverageCard(activity) {
  const c = activity.coverage;
  const rows = [
    ["Sessions that changed code", c.code_sessions, null],
    ["…with any security action", c.with_any, c.code_sessions],
    ["…with SAST", c.with_sast, c.code_sessions],
    ["…with a dependency scan", c.with_sca, c.code_sessions],
    ["…with a secret scan", c.with_secrets, c.code_sessions],
  ];
  return card("Coverage",
    `<div class="table-scroll"><table>
      <thead><tr><th>Sessions</th><th class="num">Count</th><th class="num">Share</th></tr></thead>
      <tbody>${rows.map(([label, value, base]) => `<tr>
        <td>${label}</td><td class="num">${fmt(value)}</td>
        <td class="num">${base ? Math.round((value / base) * 100) + "%" : "—"}</td>
      </tr>`).join("")}</tbody></table></div>
     <p class="hint">A session counts as changing code when it wrote a file or
       committed. Suppressions are never counted as a security action.</p>`);
}

function gapsCard(activity) {
  const rows = activity.gaps;
  const inner = rows.length
    ? `<div class="table-scroll"><table>
        <thead><tr><th>Session</th><th>Project</th><th>Member</th>
          <th class="num">Code edits</th><th>Last</th></tr></thead>
        <tbody>${rows.map((r) => `<tr>
          <td>${sessionLink(r.session_id)}</td>
          <td>${esc(r.project || "—")}</td><td>${esc(r.origin || "—")}</td>
          <td class="num">${fmt(r.code_edits)}</td>
          <td>${r.last_ts ? esc(timeAgo(r.last_ts)) : "—"}</td></tr>`).join("")}
        </tbody></table></div>${omittedNote(activity.rows_omitted.gaps, "sessions")}`
    : emptyCard("◉", "every session that changed code ran at least one check");
  return card("Changed code, ran nothing", inner);
}

function suppressionsCard(activity) {
  const rows = activity.suppressions;
  const inner = rows.length
    ? `<p class="hint">Silencing a check instead of running one. Recorded
         separately and never counted as security activity.</p>
       <div class="table-scroll"><table>
        <thead><tr><th>When</th><th>Session</th><th>Member</th><th>Signal</th></tr></thead>
        <tbody>${rows.map((r) => `<tr>
          <td>${r.ts ? esc(fmtTime(r.ts)) : "—"}</td>
          <td>${sessionLink(r.session_id)}</td>
          <td>${esc(r.origin || "—")}</td>
          <td>${esc(r.detail || r.tool)}</td></tr>`).join("")}
        </tbody></table></div>${omittedNote(activity.rows_omitted.suppressions, "signals")}`
    : emptyCard("◉", "no check was suppressed in this window");
  return card("Suppressions", inner);
}

// ---------------------------------------------------------------- admin: terms

async function securityTermsCard(reload) {
  const data = await apiJSON("/api/v1/security/terms").catch(() => ({ terms: [] }));
  const projects = await apiJSON("/api/v1/projects").catch(() => []);
  let terms = data.terms.map((t) => ({ project: t.project, term: t.term }));
  const el = card("Internal terms (admin)", "");
  const render = () => {
    el.innerHTML = cardHead("Internal terms (admin)") + `
      <p class="hint">Literal keywords that mark internal or proprietary
        content — a client name, an internal domain, a codename. Matched
        case-insensitively and never as a pattern. Do not paste a live secret
        here: terms are stored as written. At most 100 per project, and a term
        that applies to all projects spends every project's budget.</p>
      <div class="table-scroll"><table>
        <thead><tr><th>Project</th><th>Term</th><th></th></tr></thead>
        <tbody>${terms.length ? terms.map((t, i) => `<tr>
          <td>${t.project ? esc(t.project) : bucketLabel("all projects")}</td>
          <td>${esc(t.term)}</td>
          <td><div class="actions"><button class="btn btn-ghost" data-drop="${i}">remove</button></div></td>
        </tr>`).join("") : `<tr><td colspan="3" class="hint">no terms yet</td></tr>`}
        </tbody></table></div>
      <div class="form-grid">
        <div class="field"><label class="microlabel">Project</label>
          <select id="term-project"><option value="">all projects</option>
            ${projects.map((p) => `<option value="${esc(p)}">${esc(p)}</option>`).join("")}
          </select></div>
        <div class="field"><label class="microlabel">Term (4–64 characters)</label>
          <input id="term-text" placeholder="acme-holdings" spellcheck="false"></div>
      </div>
      <div class="form-actions">
        <button class="btn" id="term-add">Add term</button>
        <button class="btn btn-accent" id="term-save">Save terms</button>
        <span class="hint" id="term-note"></span>
      </div>`;
    el.querySelectorAll("[data-drop]").forEach((b) =>
      b.addEventListener("click", () => {
        terms.splice(Number(b.dataset.drop), 1);
        render();
      }));
    $("#term-add", el).addEventListener("click", () => {
      const term = $("#term-text", el).value.trim();
      const project = $("#term-project", el).value;
      if (term.length < 4 || term.length > 64) {
        $("#term-note", el).textContent = "a term is 4–64 characters";
        return;
      }
      if (terms.some((t) => t.project === project && t.term.toLowerCase() === term.toLowerCase())) {
        $("#term-note", el).textContent = "already in the list";
        return;
      }
      terms.push({ project, term });
      render();
    });
    $("#term-save", el).addEventListener("click", async () => {
      const note = $("#term-note", el);
      note.textContent = "saving…";
      try {
        await api("/api/v1/security/terms",
                  { method: "PUT", body: JSON.stringify({ terms }) });
        note.textContent = "saved — stored data is now stale until a rescan";
        reload();
      } catch (err) {
        note.textContent = err.message;
      }
    });
  };
  render();
  return el;
}

function securityExportCard() {
  const el = card("Export the analysis",
    `<p class="hint">The rows behind this page. Evidence is masked and no column
       carries a matched value.</p>
     <div class="form-actions">
       <button class="btn" data-x="findings&format=jsonl">↓ Findings JSONL</button>
       <button class="btn" data-x="findings&format=csv">↓ Findings CSV</button>
       <button class="btn" data-x="actions&format=jsonl">↓ Actions JSONL</button>
       <button class="btn" data-x="actions&format=csv">↓ Actions CSV</button>
     </div>`);
  el.querySelectorAll("[data-x]").forEach((b) =>
    b.addEventListener("click", () => download(
      `/api/v1/security/export?kind=${b.dataset.x}` +
      qs({ project: state.filters.project, from: rangeFrom(state.filters.range) })
        .replace("?", "&"))));
  return el;
}

// ---------------------------------------------------------------- the view

async function viewSecurity() {
  clearInterval(window.__secRescanTimer);
  main.innerHTML = "";
  main.appendChild(await filtersRow(viewSecurity));

  const params = { project: state.filters.project, from: rangeFrom(state.filters.range) };
  const s = await apiJSON("/api/v1/security" + qs(params));

  main.appendChild(securityTiles(s));
  main.appendChild(securityLimitsCard(s, viewSecurity));

  const charts = document.createElement("div");
  charts.className = "grid-2";
  charts.appendChild(chartCard("Exposure findings — per day",
    (el) => findingsDayChart(el, s.exposure.per_day),
    (el) => findingsDayTable(el, s.exposure.per_day)));
  charts.appendChild(chartCard("Security actions — per day",
    (el) => activityDayChart(el, s.activity),
    (el) => activityDayTable(el, s.activity)));
  if (s.exposure.per_day.length || s.activity.per_day.length) main.appendChild(charts);

  main.appendChild(exposureRulesCard(s.exposure));

  const pair = document.createElement("div");
  pair.className = "grid-2";
  pair.appendChild(affectedSessionsCard(s.exposure));
  pair.appendChild(recurringCard(s.exposure));
  main.appendChild(pair);

  main.appendChild(securityToolsCard(s.activity));

  const pair2 = document.createElement("div");
  pair2.className = "grid-2";
  pair2.appendChild(gapsCard(s.activity));
  pair2.appendChild(coverageCard(s.activity));
  main.appendChild(pair2);

  main.appendChild(suppressionsCard(s.activity));
  if (state.me.role === "admin") main.appendChild(await securityTermsCard(viewSecurity));
  main.appendChild(securityExportCard());
}
