# Plan: Security scan — exposure findings and security activity in the ledger

> **Prerequisite:** `spec.md` approved (2026-10-14).

## Architectural decisions

- **The analysis is derived index data, computed when data arrives or is
  re-derived — never at query time, and never by running real scanners.**
  Findings and actions land in three new tables, rebuildable from the JSONL
  archive and the snapshots. — **ADR required (ADR 0003)**
- **A finding stores a pointer, not a value:** masked evidence (≤4 leading
  characters + length) plus an HMAC fingerprint over a per-store random salt.
  — part of **ADR 0003**
- **The rule and activity catalogues live in code; only custom terms are
  data.** Extending detection is a reviewed code change; admins configure
  vocabulary, not patterns. — part of **ADR 0003**
- **The server becomes a directory, not a single file:** the scanner lands in
  `server/security_scan.py` and `gaide_trace_server.py` imports it, so the
  classifier can later be reused by a local command without a second
  definition of "finding". Every deployment already copies `server/`
  (Dockerfile `COPY server/`, systemd and the AWS bootstrap run from
  `/opt/gaide-trace/server/`), so only the by-path loaders need a `sys.path`
  entry. — part of **ADR 0003** (accepted cost)
- **One rescan at a time, in a background thread, admin-only.** Minor decision:
  it mirrors `rederive_if_stale` but cannot run before binding, since it is
  triggered from the console.
- **Scanning on the ingest path is provisional.** It is what makes live data
  appear immediately, and it is the one place where this feature could cost a
  client a slow request. Task 20 measures it; the documented fallback (scan
  only on derivation/rescan) is a configuration-free code change, not a
  redesign.

## Affected components

- `server/security_scan.py` — **new.** Rule catalogue with severities and
  validators, activity and suppression catalogues, `scan_text`,
  `scan_event_row`, `scan_transcript`, `classify_tool_call`, `is_code_edit`,
  masking, fingerprinting, caps. Stdlib only (`re`, `hashlib`, `hmac`).
- `server/gaide_trace_server.py` — schema (`security_findings`,
  `security_actions`, `security_terms`, the salt in `meta`, `sessions.code_edits`);
  hooks in `ingest_events` and `index_transcript`; `DERIVED_VERSION` 3 → 4 and
  the scan inside `_rederive_all` / `rebuild_index`; the rescan job; six API
  routes; the `security` block on session detail; CLI `scan-security`.
- `server/webui/security.js` — **new.** The Security view (tiles, two per-day
  charts, rule/tool/gap/suppression tables, terms editor, rescan control),
  following the `price-import.js` precedent of a second script file.
- `server/webui/app.js` — nav + router entry, the session page's security
  section, reuse of `filtersRow`, `chartCard` and the model-chart helpers.
- `server/webui/index.html`, `style.css` — nav link; severity pills and the
  terms editor's styles.
- `tests/test_security_scan.py` — **new.** Scanner and classifier units.
- `tests/test_security_api.py` — **new.** HTTP-level: shape, scope, roles,
  rescan, export.
- `tests/fixtures.py` — synthesized, assembled-at-runtime fake secrets (see
  risks: a literal key-shaped string in the repo would trip gitleaks in CI,
  and suppressing that would violate Principle 10).
- `docs/SERVER.md` — endpoints, both catalogues with severities, the limits of
  the analysis, term rules, rescan, upgrade note.
- `README.md` — the console feature list and the privacy section.
- `docs/adr/0003-derive-security-analysis-in-the-index.md` — **new.**
- `PROGRESS.md` — session entries.

## Implementation sequence

**Sprint 1 — exposure scan (Tasks 1–8)**
ADR; tests from the spec (red); the scanner module with its catalogue and
validators; fingerprint and salt; the three tables; wiring into ingest and
into transcript indexing.

**Sprint 2 — security activity and coverage (Tasks 9–12)**
Activity and suppression catalogues; code-touching detection and the
`code_edits` counter; `DERIVED_VERSION` 4, the scan inside re-derivation and
`rebuild-index`, and the `scan-security` CLI command.

**Sprint 3 — API (Tasks 13–17)**
The aggregate endpoint; the session block; the export; the term endpoints; the
rescan endpoints. Scope and role tests land with each endpoint, not after.

**Sprint 4 — console and documentation (Tasks 18–21)**
The Security page; the session page's section, the admin-only controls and the
limits note; docs, the ingest-cost measurement and the review passes.

Each sprint ends green (`pytest -q`) and leaves the console usable; nothing is
committed before the maintainer's approval (Principle 3).

## Testing strategy

- **Unit (`tests/test_security_scan.py`)**
  - One case per rule: a positive and a near-miss negative (an invalid CPF, a
    card failing Luhn, a `.envrc` that is not `.env`, `semgrep` named inside a
    prompt rather than run).
  - Masking: for a battery of synthesized values, the stored finding and the
    API row contain at most the first 4 characters — asserted by searching the
    whole serialized row for the remainder of the value.
  - Fingerprints: stable within a store, different across stores for the same
    value, absent salt never served.
  - Caps: a 50 MB synthetic line is scanned over at most
    `MAX_SCAN_CHARS_PER_LINE` characters (asserted on an instrumented counter,
    not on wall-clock), findings per record and per session are capped, and the
    truncation is reported.
  - Idempotency: indexing the same transcript twice, and `rebuild-index`,
    produce byte-identical snapshots and an identical finding set.
  - Classification: positives per category, `tool.fail` → `error`, ambiguous
    responses → `unknown`, suppressions never counted as actions, and the
    GAIDE-independence check (catalogue minus GAIDE entries ⇒ identical
    behaviour for a non-GAIDE project).
- **Integration (`tests/test_security_api.py`)** — the aggregate shape; a
  scoped member sees only granted projects and cannot distinguish "no data"
  from "not yours"; `member` and `member`-key callers get 403 on terms and
  rescan; rescan answers 202 then 409; export honours filters and scope; the
  session block is additive.
- **Manual / `verifier`** — the console page against a locally seeded server:
  both halves, empty states, the stale and truncated badges, the admin-only
  controls, chart/table parity. `playwright` is not available in this
  environment, so the pass is a documented browser walk plus `curl`, as in the
  previous sprint.
- **Harness** — `scripts/check-file.sh`, `check-security.sh`,
  `check-stdlib-only.sh` on every edited file; `check-clean-state.sh` before
  the session ends.

## Implementation risks

- **Fake secrets in fixtures trip the repo's own scanners.** A literal
  `AKIA…`-shaped string in `tests/` is exactly what gitleaks and semgrep
  exist to catch, and an allowlist entry to quiet them would violate
  Principle 10. | Mitigation: fixtures assemble every secret-shaped value at
  runtime from fragments, so no complete pattern exists as a literal in the
  repository; the test asserts the assembled value, never a stored one.
- **Ingest latency.** ~40 compiled patterns over four fields of every record,
  on the request path. | Mitigation: patterns compiled at import, caps per
  field, and a measured budget in Task 20. *Resolved 2026-10-14:* measured at
  18.7 ms per maximal record (3.7 s for a 200-record batch against the hook's
  5 s timeout), which was too slow. A single combined alternation was tried and
  was worse (35 ms); a literal gate per rule brought it to 1.2 ms for ordinary
  code and 8.2 ms for the worst realistic mix, so the documented fallback
  (scanning only on derivation) was not needed.
- **Rescan contends with live ingest for the single SQLite writer.** |
  Mitigation: the job commits per session rather than in one transaction, the
  existing `timeout=30` covers brief contention, and the job is admin-only and
  single-flight.
- **Transcript re-scan cost on every upload.** A snapshot is re-uploaded whole
  on each `turn.end`, so its findings are recomputed each time. |
  Mitigation: the scan rides the parse `index_transcript` already does (one
  pass, not two), and findings for the session are replaced wholesale, which
  keeps it idempotent; if cost shows up, the size-based short-circuit the
  client already uses for uploads is the next lever.
- **False positives make the page untrustworthy.** | Mitigation: severities
  per rule, and the rule table surfaces noise by count. *Resolved 2026-10-14:*
  Task 20 was to run the scanner over this repository's own store first, but no
  trace store exists on this machine. The maintainer decided not to source real
  text from elsewhere just to calibrate: the rule table **is** the profile, so
  the catalogue is tightened from it on the first real store, in its own
  commit. The risk is therefore accepted and visible rather than measured in
  advance.
- **Scope bugs leak across projects.** The same risk class ADR 0002 addressed.
  | Mitigation: every new read goes through the existing `scope_sql` helper and
  gets its own negative test; the mandatory `security-reviewer` pass audits
  exactly this.

## Sprint contract

> The operational meaning of "done" for this feature. Verified item by item by
> the reviewer; a failure comes back as feedback, not as a renegotiation.

- [ ] A store seeded with synthesized events and transcripts carrying fake
  credentials, PII and sensitive-path access reports them on the Security page
  with the right rules and severities — verify by: seed script +
  `http://127.0.0.1:<port>/#/security`
- [ ] No matched value, and no text surrounding a match, appears in the
  database or in any API response — verify by:
  `sqlite3 data/trace.db "SELECT * FROM security_findings"` and
  `curl -s .../api/v1/security | grep -F "<the fake secret>"` (no match)
- [ ] The same fake key ingested in three sessions is grouped as one recurring
  value with three sessions — verify by: the recurring table on the page
- [ ] A session that ran `semgrep`, `osv-scanner` and `gitleaks` shows three
  actions in three categories with outcomes; a session that only mentioned
  them in a prompt shows none — verify by: the tool table and the session page
- [ ] Coverage and gaps are correct for a seeded mix of code-touching sessions
  with and without scanners — verify by: the coverage tile and the gap list
- [ ] A `# nosemgrep` write and a `git commit --no-verify` appear as
  suppressions and are absent from the action counts — verify by: the
  suppression list and the action tiles
- [ ] A member scoped to one project sees that project only across every
  security endpoint, and gets 403 on terms and rescan — verify by:
  `curl` with a scoped member's session token
- [ ] Adding a term marks the scan stale; a rescan clears it and the new
  findings appear; a second concurrent rescan is refused — verify by: the
  Security page's admin controls and `curl -X POST .../api/v1/security/rescan`
- [ ] A copy of a v0.6.0 store upgrades in place: the server scans it once at
  start, with progress, and the page covers the full history — verify by:
  `cp -r` a real store, start the new server, read the console
- [ ] `rebuild-index` on that store reproduces identical security tables and
  leaves every snapshot byte-identical — verify by: row counts + `sha256sum`
  before/after
- [ ] The page states its two limits (redaction at capture, no CI visibility)
  on both halves, including when there is nothing to report — verify by: the
  empty-state view
- [ ] `pytest -q` green, `scripts/check-stdlib-only.sh` clean, no scanner
  suppression anywhere in the diff — verify by: `./init.sh` and
  `git diff | grep -nE "nosemgrep|nosec|noqa|gitleaks:allow"` (no match)

## Definition of Done

- [ ] All tests derived from the spec pass (`pytest -q`, no new skips)
- [ ] Code review approved (`code-reviewer` skill + human review)
- [ ] **Security review approved (`security-reviewer` skill)** — mandatory:
  this touches redaction, data sensitivity and read authorization
- [ ] Independent `verifier` pass over the spec's criteria and this contract
- [ ] ADR 0003 accepted
- [ ] `docs/SERVER.md` and `README.md` updated; both catalogues documented
- [ ] No secrets in the diff and no scanner suppression in it
- [ ] Constitution respected; `PROGRESS.md` updated
