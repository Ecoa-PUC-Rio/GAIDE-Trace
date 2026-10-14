# Tasks: Security scan — exposure findings and security activity in the ledger

> **Prerequisite:** `plan.md` approved.
>
> **Status lifecycle:** `pending → in-progress → done → verified`.
> `done` = implemented and its own tests pass. `verified` = checked against the
> spec's acceptance criteria by someone (or some agent) other than whoever
> implemented it. Status only moves forward when the work actually happened
> (Constitution Principle 9).

---

## Sprint 1 — exposure scan

## Task 1 — Record ADR 0003

**Status:** done

**Files:** `docs/adr/0003-derive-security-analysis-in-the-index.md`

**Description:** The decision to derive the analysis in the index (not at query
time, not by running real scanners), to store a masked pointer plus a salted
fingerprint instead of the matched value, to keep catalogues in code and only
terms as data, and to let the server become a directory.

**Done when:**
- [x] ADR follows the Nygard format used by 0001/0002, with alternatives and
  honest costs
- [x] Status `accepted` only after the maintainer approves

**Estimate:** ~30 min · **Depends on:** —

---

## Task 2 — Tests from the spec: exposure rules (red)

**Status:** done

**Files:** `tests/test_security_scan.py`, `tests/fixtures.py`

**Description:** One positive and one near-miss negative per rule of AC2, plus
the masking, fingerprint and cap assertions. Fake secrets are assembled at
runtime from fragments — never written as complete literals, which gitleaks
and semgrep would (correctly) flag in CI.

**Done when:**
- [x] Tests exist for every rule in AC2 and fail for the right reason
- [x] `gitleaks detect` and `scripts/check-security.sh` on the new test file
  report nothing
- [x] A helper builds a store with seeded exposure for later HTTP tests

**Estimate:** ~60 min · **Depends on:** —

---

## Task 3 — Scanner module: catalogue, scan_text, masking, caps

**Status:** verified

**Files:** `server/security_scan.py`, `tests/test_security_scan.py`

**Description:** The rule catalogue (category, rule, severity, compiled
pattern), `scan_text` collapsing repeats into a count, `mask`, and the caps
(`MAX_SCAN_CHARS_PER_LINE`, per-record and per-session limits) with truncation
reported rather than silent. Every pattern linear — no nested quantifiers.

**Done when:**
- [x] Rule tests from Task 2 pass except the validator-dependent ones
- [x] Masking tests pass: no stored form contains more than the first 4
  characters of a match, and no surrounding text
- [x] The cap test passes on an instrumented character counter
- [x] `scripts/check-stdlib-only.sh server/security_scan.py` clean

**Estimate:** ~60 min · **Depends on:** Task 2

---

## Task 4 — Validators: CPF, CNPJ check digits and Luhn

**Status:** verified

**Files:** `server/security_scan.py`, `tests/test_security_scan.py`

**Description:** Attach validators to the PII rules so a digit sequence that
cannot be a CPF, CNPJ or card number is not reported as one (AC7).

**Done when:**
- [x] Valid synthesized values are found; invalid ones are not
- [x] Separators and plain-digit forms both work; repeated-digit CPFs
  (`111.111.111-11`) are rejected

**Estimate:** ~30 min · **Depends on:** Task 3

---

## Task 5 — Fingerprints and the per-store salt

**Status:** verified

**Files:** `server/security_scan.py`, `server/gaide_trace_server.py`,
`tests/test_security_scan.py`

**Description:** `fingerprint(value, salt)` as truncated HMAC-SHA256, and a
random salt generated once per store in `meta`, never served by any endpoint.

**Done when:**
- [x] The same value fingerprints identically within a store and differently
  across two stores
- [x] No endpoint response contains the salt (asserted against `/api/v1/me`,
  the security endpoints and the export)
- [x] The salt survives `rebuild-index` (fingerprints stay comparable)

**Estimate:** ~30 min · **Depends on:** Task 3

---

## Task 6 — Schema: findings, actions, terms, code_edits

**Status:** verified

**Files:** `server/gaide_trace_server.py`, `tests/test_security_api.py`

**Description:** `security_findings`, `security_actions`, `security_terms`,
their indexes, the uniqueness that makes inserts idempotent, and
`sessions.code_edits` added by the same guarded-`ALTER` pattern used for the
v0.5→v0.6 migration.

**Done when:**
- [x] A fresh store and a copied v0.6.0 store both open without error
- [x] Re-opening an upgraded store does not re-run the migration
- [x] `test_server_startup.py` still passes

**Estimate:** ~30 min · **Depends on:** Task 3

---

## Task 7 — Scan events on ingest

**Status:** done

**Files:** `server/gaide_trace_server.py`, `tests/test_security_api.py`

**Description:** Scan the four text fields of each accepted record, insert
findings idempotently keyed by (`trace_id`, rule, location), and log-and-
continue when the scan of one record raises — the record is still stored
(AC27, Principle 8).

**Done when:**
- [x] Ingesting a seeded batch produces the expected findings, and re-ingesting
  it produces no duplicates
- [x] A record crafted to raise inside the scanner is still stored, with the
  failure on stderr

**Estimate:** ~45 min · **Depends on:** Tasks 3, 6

---

## Task 8 — Scan transcripts on indexing

**Status:** verified

**Files:** `server/gaide_trace_server.py`, `server/security_scan.py`,
`tests/test_security_scan.py`

**Description:** Scan snapshot lines inside the single pass `index_transcript`
already makes, recording line numbers as the location, and replace the
session's transcript findings wholesale so re-indexing is idempotent.

**Done when:**
- [x] Findings carry the right line numbers
- [x] Indexing the same snapshot twice yields an identical finding set and a
  byte-identical file on disk (AC6)
- [x] A 50 MB single-line snapshot is scanned within the cap and does not stall

**Estimate:** ~45 min · **Depends on:** Tasks 3, 6

---

## Sprint 2 — security activity and coverage

## Task 9 — Activity catalogue and classification

**Status:** verified

**Files:** `server/security_scan.py`, `tests/test_security_scan.py`

**Description:** `classify_tool_call`: extract the invoked command from the
tool call (shell command, tool name, skill/slash-command argument), match the
catalogue for `sast`, `sca`, `secrets`, `iac`, `container`, `dast`,
`supply-chain`, `review`, and infer the outcome (`clean`, `findings`, `error`,
`unknown` — never guessed). Classification reads only `tool.call`/`tool.fail`.

**Done when:**
- [x] Positive cases across all categories classify with the right tool
- [x] A scanner merely named in a prompt or an assistant message yields nothing
  (AC9)
- [x] `tool.fail` → `error`; an ambiguous response → `unknown` (AC10)
- [x] Removing the GAIDE entries leaves non-GAIDE behaviour unchanged (AC14)

**Estimate:** ~60 min · **Depends on:** Task 3

---

## Task 10 — Suppression signals

**Status:** verified

**Files:** `server/security_scan.py`, `server/gaide_trace_server.py`,
`tests/test_security_scan.py`

**Description:** Detect inline suppression comments written into files, entries
added to scanner ignore files, `--no-verify` and `SKIP=` on pre-commit; store
them in the `suppression` category.

**Done when:**
- [x] Each signal is detected with its session, time and what was suppressed
- [x] Suppressions never appear in action counts or coverage (AC11)

**Estimate:** ~45 min · **Depends on:** Task 9

---

## Task 11 — Code-touching sessions

**Status:** verified

**Files:** `server/gaide_trace_server.py`, `server/security_scan.py`,
`tests/test_security_api.py`

**Description:** `is_code_edit` (file-writing tool names plus commit/patch
commands), the `sessions.code_edits` counter bumped in `_bump_session`, and the
SQL that recomputes it during re-derivation.

**Done when:**
- [x] A seeded session's `code_edits` is correct through ingest and through
  re-derivation
- [x] Sessions with no code edit are excluded from coverage and gaps (AC12)

**Estimate:** ~45 min · **Depends on:** Tasks 6, 9

---

## Task 12 — Derivation, rebuild and the `scan-security` command

**Status:** verified

**Files:** `server/gaide_trace_server.py`, `tests/test_security_api.py`

**Description:** `DERIVED_VERSION` 3 → 4; scan stored events and snapshots
inside `_rederive_all` with the existing progress reporting; make
`rebuild_index` reproduce the security tables; add the `scan-security
[--project]` CLI command for ops.

**Done when:**
- [x] A copied v0.6.0 store is scanned once at the first start, before binding,
  with progress (AC33)
- [x] `rebuild-index` produces identical security tables and leaves snapshots
  byte-identical
- [x] A second start does not re-scan
- [x] One unparsable session is skipped and logged, not fatal

**Estimate:** ~60 min · **Depends on:** Tasks 7, 8, 11

---

## Sprint 3 — API

## Task 13 — `GET /api/v1/security`

**Status:** verified

**Files:** `server/gaide_trace_server.py`, `tests/test_security_api.py`

**Description:** Both halves in one response: totals and per-severity counts,
per-category and per-rule rows, per-day series, recurring fingerprints, top
affected sessions; action totals, per-category and per-tool rows, per-day
series, coverage, gaps, suppressions; plus `as_of`, staleness and truncation.
Reuses `_filters` and `scope_sql`.

**Done when:**
- [x] The shape matches AC15 and the numbers match a seeded store
- [x] A scoped member sees only granted projects, with no project name, rule
  name, count or session id from outside (AC23)
- [x] A non-granted `?project=` answers exactly as a project with no data
- [x] Row listings are capped the way the models endpoint is, with the omitted
  count reported

**Estimate:** ~90 min · **Depends on:** Task 12

---

## Task 14 — Session detail gains a `security` block

**Status:** verified

**Files:** `server/gaide_trace_server.py`, `tests/test_security_api.py`

**Description:** That session's findings (rule, severity, location, masked
evidence) and actions, additive to the existing response.

**Done when:**
- [x] The block is present and correct for a seeded session
- [x] Existing session-detail tests pass unchanged (AC16)
- [x] A session outside the caller's scope still answers 404

**Estimate:** ~30 min · **Depends on:** Task 13

---

## Task 15 — `GET /api/v1/security/export`

**Status:** verified

**Files:** `server/gaide_trace_server.py`, `tests/test_security_api.py`

**Description:** `kind=findings|actions`, `format=jsonl|csv`, inside the
caller's scope and the same filters as the page.

**Done when:**
- [x] Both kinds in both formats export the rows behind the page
- [x] A scoped member's export carries nothing from outside the scope
- [x] No exported field contains a matched value (AC21)

**Estimate:** ~45 min · **Depends on:** Task 13

---

## Task 16 — Custom term endpoints

**Status:** verified

**Files:** `server/gaide_trace_server.py`, `tests/test_security_api.py`

**Description:** `GET`/`PUT /api/v1/security/terms`, admin-only; literal terms,
case-insensitive, 4–64 characters, ≤100 per project; a change marks the scan
stale for the affected projects.

**Done when:**
- [x] Valid lists are stored and served; invalid ones are rejected with 400 and
  no change (AC18)
- [x] A member token and a `member` key get 403 (AC24)
- [x] Terms are matched literally, never compiled (AC25)
- [x] New data is scanned against new terms immediately; stored data is
  reported stale

**Estimate:** ~60 min · **Depends on:** Task 13

---

## Task 17 — Rescan endpoints

**Status:** verified

**Files:** `server/gaide_trace_server.py`, `tests/test_security_api.py`

**Description:** `POST /api/v1/security/rescan` (admin, optional project) in a
single-flight background thread, committing per session; `GET` reports state,
start, progress and last result, including a failure (Principle 8).

**Done when:**
- [x] A rescan refreshes findings for the chosen project and clears staleness
- [x] A second concurrent request answers 409 (AC19)
- [x] A member gets 403
- [x] A rescan running while events are ingested neither loses data nor errors

**Estimate:** ~60 min · **Depends on:** Task 16

---

## Sprint 4 — console and documentation

## Task 18 — Console: the Security page

**Status:** verified

**Files:** `server/webui/security.js`, `server/webui/app.js`,
`server/webui/index.html`, `server/webui/style.css`

**Description:** Nav entry and route; severity tiles; findings-per-day and
actions-per-day charts (≤4 series + "other", CVD-safe palette, table fallback);
rule, recurring-value, affected-session, tool, gap and suppression tables; the
shared project/date filter.

**Done when:**
- [x] Both halves render against a seeded server and match the API
- [x] Charts follow the console's conventions, each with its table (AC32)
- [x] Empty states read sensibly (AC12 of the spec's use case 12)

**Estimate:** ~90 min · **Depends on:** Task 13

---

## Task 19 — Console: session section, admin controls, honest limits

**Status:** verified

**Files:** `server/webui/app.js`, `server/webui/security.js`,
`server/webui/style.css`

**Description:** The session page's findings/actions section; the terms editor
and the rescan control for admins only; the permanent limits note (redaction at
capture, no CI visibility) plus stale and truncated badges. No per-person
ranking anywhere.

**Done when:**
- [x] The session section shows findings and actions (AC29)
- [x] A member sees no terms editor and no rescan control (AC31)
- [x] The limits note is present on both halves, including when empty (AC30)

**Estimate:** ~60 min · **Depends on:** Tasks 17, 18

---

## Task 20 — Measure cost and noise on real data

**Status:** done (2026-10-14) — cost measured; the noise half closed by an
explicit decision, see "Done when" below

**Files:** `specs/security-scan/plan.md` (results), `PROGRESS.md`

**Description:** Measure the ingest cost of scanning (a 200-record batch,
before/after) against the stated budget, and run the scanner over this
repository's own store to see the real false-positive profile before the page
is called done. If the budget is missed, apply the documented fallback (scan
only on derivation/rescan).

**Done when:**
- [x] The ingest cost recorded in `PROGRESS.md` with its conclusion: 18.7 ms
  per maximal record was too slow for a full shipping batch, so every rule got
  a literal gate (1.2 ms for ordinary code, 8.2 ms for the worst realistic
  mix), and the scan stayed on the ingest path.
- [~] **The false-positive profile was not measured, by decision of the
  maintainer on 2026-10-14.** This machine holds no trace store — the
  repository has no `.gaide-trace/` and no server `data/` — so the only ways to
  get real text were to read a store from another project or to pull the
  production server's data. Neither is worth doing to calibrate a catalogue,
  because **the feature produces this measurement itself**: the "Exposure by
  rule" table is exactly a per-rule false-positive profile, per project,
  continuously. The calibration therefore happens on the first real store, with
  real eyes on that table, in its own commit.
- [ ] *(superseded by the decision above)* The rule catalogue tightened if a
  rule is dominated by noise — to be done from the console's own rule table on
  first real use. Known suspects to look at first: `email` firing inside a
  connection string, `private-key-file` on a `.key` path that is configuration
  rather than access, and the widened `secret-assignment`.

**Estimate:** ~45 min · **Depends on:** Task 12

---

## Task 21 — Documentation and reviews

**Status:** done

**Files:** `docs/SERVER.md`, `README.md`, `docs/adr/0003-*.md`, `PROGRESS.md`

**Description:** Document the endpoints, both catalogues with severities, what
the analysis cannot see, term rules, the rescan and the upgrade behaviour;
update the console feature list and the privacy section. Then the review
passes: `code-reviewer`, the mandatory `security-reviewer`, and an independent
`verifier` pass over the acceptance criteria and the sprint contract.

**Done when:**
- [x] `docs/SERVER.md` and `README.md` updated (AC34)
- [x] ADR 0003 accepted
- [x] Code review and security review closed: 4 blockers + 14 suggestions fixed, no suppression
- [x] Independent `verifier` pass: 32/34 observed on a running server; the one failure fixed and re-verified; AC27 is not reachable from a client and says so
- [x] `./init.sh` green; `PROGRESS.md` entry appended

**Estimate:** ~90 min · **Depends on:** Tasks 18, 19, 20

---

## Traceability

| Spec criterion | Task(s) | Status |
| --- | --- | --- |
| AC1 (everything scanned) | 3, 7, 8, 12 | verified |
| AC2 (rule catalogue) | 2, 3, 4 | verified |
| AC3 (finding fields) | 3, 5, 6 | verified |
| AC4 (severities) | 3, 21 | verified |
| AC5 (repeats collapse) | 3 | verified |
| AC6 (idempotent, snapshots intact) | 8, 12 | verified |
| AC7 (check digits / Luhn) | 4 | verified |
| AC8 (activity categories) | 9, 21 | verified |
| AC9 (only invoked commands) | 9 | verified |
| AC10 (outcome never guessed) | 9 | verified |
| AC11 (suppressions separate) | 10 | verified |
| AC12 (coverage) | 11, 13 | verified |
| AC13 (gap list) | 11, 13 | verified |
| AC14 (no GAIDE dependency) | 9 | verified |
| AC15 (aggregate endpoint) | 13 | verified |
| AC16 (session block) | 14 | verified |
| AC17 (export) | 15 | verified |
| AC18 (term endpoints) | 16 | verified |
| AC19 (rescan) | 17 | verified |
| AC20 (scope on every read) | 13, 14, 15 | verified |
| AC21 (no value stored or served) | 3, 15 | verified |
| AC22 (salted fingerprints) | 5 | verified |
| AC23 (no cross-project oracle) | 13, 15 | verified |
| AC24 (admin-only endpoints) | 16, 17 | verified |
| AC25 (terms are literal) | 16 | verified |
| AC26 (bounded scanning) | 3, 8, 13 | verified |
| AC27 (ingest survives a scan failure) | 7 | done (unit, fault-injected) — not reachable from a client, so not observable |
| AC28 (Security page) | 18 | verified |
| AC29 (session page) | 19 | verified |
| AC30 (stated limits) | 19 | verified |
| AC31 (admin-only controls, no ranking) | 19 | verified |
| AC32 (chart conventions) | 18 | verified |
| AC33 (upgrade scan) | 12 | verified |
| AC34 (documentation) | 21 | verified |

> A criterion reaches `verified` only when exercised against the running
> application by someone other than its implementer, not by green unit tests.
