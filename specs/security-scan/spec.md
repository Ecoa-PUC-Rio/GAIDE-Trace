# Spec: Security scan — exposure findings and security activity in the ledger

> **Status:** approved (2026-10-14)
> **Author:** José Menezes (drafted with Claude Code)
> **Date:** 2026-10-14

## Context

The ledger already holds the material to answer two security questions that no
view answers today.

**1. Did potentially confidential information pass through a session?** Capture
redacts obvious secrets before anything reaches disk (D5), but the redaction is
a handful of patterns, and transcript snapshots are *raw by design* — the
highest-fidelity record is also the one that can hold an unredacted API key, a
customer's CPF, or a connection string with a password. Today nobody can tell
whether a store holds such data, in which session, or how often. An admin who
suspects a leak has to grep the archive by hand; a member cannot check their
own sessions at all.

**2. Was anything actually *done* about security while the work happened?**
SAST, SCA, secret scanning, IaC checks, a security review — in an
AI-assisted session these are tool calls like any other, so the ledger already
records them. Counting them (and, more importantly, their *absence* on sessions
that changed code) turns the ledger into evidence about security practice in
the SDLC, instead of self-report. This has to work for any project in the
ledger, GAIDE-governed or not: GAIDE's own checks (`scripts/check-security.sh`,
the `security-reviewer` skill) are entries in a catalogue of recognised
activity, never a precondition for the analysis.

For whom:

- **Admins** — is there exposure in this store? Which key must be rotated,
  which session cleaned up, which project is changing code with no scanning?
- **Members** — what did my own sessions expose, and what did they check?
- **The research programme** — security practice in AI-assisted development,
  measured from captured behaviour rather than from a questionnaire.

This is the first behavioural change to the server's analysis layer beyond
usage and cost, so this spec is the spec for *the server's security analysis*.
It does not back-fill specs for capture-time redaction (D5) or for the rest of
the console, which stay described in `docs/ARCHITECTURE.md` and `docs/SERVER.md`.

## Expected behavior

### Terms

- **Scanned data:** the indexed text of events (`prompt`, `tool_input`,
  `tool_response`, `last_assistant_message`) and the stored transcript
  snapshots, line by line. Nothing else is read, and nothing new is captured.
- **Exposure finding:** one record saying *a rule matched, in this location, in
  this session* — never the matched value. Each finding carries a **category**
  (`secret`, `sensitive-path`, `pii`, `internal`, `redaction`), a **rule**
  (e.g. `aws-access-key-id`, `cpf`, `private-key-block`), a **severity**
  (`high`, `medium`, `low`), a **location** (event field + `trace_id`, or
  transcript line number), masked **evidence** and a **fingerprint**.
- **Masked evidence:** a display form of the match that carries at most its
  first 4 characters plus its length (`AKIA…[20 chars]`). It never carries the
  rest of the value, and never the surrounding text.
- **Fingerprint:** `HMAC-SHA256(store salt, matched value)`, truncated to 12
  hex characters. It groups the same value across sessions ("this one key
  appears in 14 sessions") without storing the value, and the per-store salt
  (random, generated once, never served by the API) makes it unguessable even
  for a small value space such as a CPF.
- **Security action:** a tool call in the ledger recognised as a security
  activity, with a **category** (`sast`, `sca`, `secrets`, `iac`, `container`,
  `dast`, `supply-chain`, `review`), the **tool** that ran (`semgrep`,
  `osv-scanner`, `gitleaks`, …) and a best-effort **outcome** (`clean`,
  `findings`, `error`, `unknown`).
- **Suppression signal:** a tool call that silences a security check instead of
  running one — an inline `# nosemgrep` / `# nosec` / `# noqa: S…` written into
  a file, an entry added to `.semgrepignore` / `.gitleaksignore` /
  `.trivyignore` / `.snyk`, `git commit --no-verify`, `SKIP=` on a pre-commit
  run. Recorded as its own category (`suppression`) because Constitution
  Principle 10 makes it load-bearing.
- **Code-touching session:** a session with at least one tool call that writes
  code — a file-writing tool (`Write`, `Edit`, `MultiEdit`, `NotebookEdit` and
  the equivalents other adapters report) or a shell command that commits or
  applies a patch.
- **Coverage:** of the code-touching sessions in the current filter, how many
  carry at least one security action, and how many carry one per category
  (SAST / SCA / secrets).
- **Gap:** a code-touching session with no security action at all.
- **Custom term:** an admin-configured literal keyword (not a regex) that marks
  internal or proprietary content — a client name, an internal domain, a
  codename. Scoped to one project or to all projects.
- **Scan:** the derivation that produces findings and actions. It runs at
  ingest for new data, at transcript indexing for new snapshots, and over
  stored data on an upgrade or an explicit rescan. It is derived index data in
  the sense of D7: always rebuildable from the JSONL archive and the snapshots,
  never a source of truth.

### Use cases

1. **An admin looks for exposure in the store (main case)**
   - Given: a store with sessions from several projects
   - When: the admin opens the Security page
   - Then: the page shows, for the current project/date filter, how many
     findings exist by severity, how many sessions are affected, the rules that
     matched (with counts and how many sessions each touches), the findings per
     day, the values that recur across sessions, and the sessions with the most
     findings. No raw secret, PII value or surrounding text appears anywhere on
     the page.

2. **An admin acts on one finding**
   - Given: a `high` finding with rule `aws-access-key-id` in session `S`
   - When: the admin opens `S`
   - Then: the session page lists that session's findings (rule, severity,
     where — which event field or transcript line — masked evidence) and its
     security actions, so the admin can rotate that key and clean up the
     session.

3. **A member reviews their own practice**
   - Given: a member scoped to project `app`
   - When: they open the Security page
   - Then: everything shown comes from `app` only — findings, actions,
     coverage, gaps — with the same scope rules as every other read
     (`specs/project-access`).

4. **Reading security activity, GAIDE or no GAIDE**
   - Given: project `app` runs `semgrep` and `npm audit` in its sessions and
     project `legacy` runs nothing; neither has GAIDE installed
   - When: either project is filtered
   - Then: `app` shows SAST and SCA activity with the tools, runs, outcomes and
     dates; `legacy` shows no activity and its code-touching sessions are
     listed as gaps. Nothing in the analysis requires GAIDE; GAIDE's own
     checks (`scripts/check-security.sh`, the `security-reviewer` skill) simply
     appear as recognised entries where they ran.

5. **Coverage and gaps**
   - Given: 30 code-touching sessions in the window, 11 of which ran at least
     one scanner
   - When: the admin reads the activity half of the page
   - Then: coverage reads 11 of 30, broken down by category, and the 19 gap
     sessions are listed (session, project, member, when, how many code
     edits), each linking to its session page.

6. **A suppression is recorded**
   - Given: a session where a `# nosemgrep` was written into a file and a
     commit used `--no-verify`
   - When: the window covering it is filtered
   - Then: both appear in the suppression list with session, time, member and
     what was suppressed, separately from the action inventory — a suppression
     is never counted as a security action.

7. **An admin adds custom terms**
   - Given: an admin on the Security page
   - When: they add the terms `acme-holdings` and `internal.example.net` for
     project `app`
   - Then: the terms are saved, new data is scanned against them immediately,
     and the page says the stored data has not been rescanned yet and offers a
     rescan.

8. **A rescan**
   - Given: terms were changed, or an admin wants the stored data re-examined
   - When: the admin starts a rescan (optionally for one project)
   - Then: it runs in the background, the page reports its progress and, when
     it finishes, the findings reflect the current rules and terms. A second
     rescan requested while one is running is refused, not queued.

9. **An existing server upgrades to this version**
   - Given: a store with events and transcripts from earlier versions
   - When: the new server starts
   - Then: it scans the stored data once, before accepting requests, reporting
     progress the way the existing re-derivation does, and the Security page
     then covers the full history. Nothing in the archive or in any snapshot is
     modified.

10. **A member tries to read beyond their scope (abuse case)**
    - Given: a member scoped to `app`, and a finding in `research`
    - When: they request the security endpoints, with or without
      `?project=research`
    - Then: they see nothing from `research` — no counts, no rule names, no
      session ids, no project name — and the custom-term endpoints answer 403
      whatever they send.

11. **A hostile client floods the scanner (abuse case)**
    - Given: an `agent` key ingesting records crafted to maximise matches — a
      single 50 MB line, a field with 100 000 fake keys, a pathological string
      aimed at the scan patterns
    - When: the data is ingested
    - Then: ingest stays bounded in time and the index stays bounded in size:
      scanning is capped per line, per record and per session, the caps are
      reported rather than hidden, and no pattern takes superlinear time.

12. **Nothing to report**
    - Given: a filter whose data has no findings and no security actions
    - When: the page is opened
    - Then: each half says so plainly, and the page still states the two
      limits that always apply: event text was already redacted at capture
      (D5), and scanners that run in CI or outside an agent session are not in
      the ledger and therefore not counted.

## Acceptance criteria

Exposure scan:

- [ ] AC1 — Every indexed event field (`prompt`, `tool_input`,
  `tool_response`, `last_assistant_message`) and every line of every stored
  transcript snapshot is scanned against the rule catalogue, at ingest, at
  transcript indexing, and for stored data on upgrade or rescan.
- [ ] AC2 — The catalogue covers, at least: private key blocks, AWS access key
  ids, GitHub / Slack / Stripe / OpenAI-style / Google API keys, JWTs, URLs
  carrying credentials, database connection strings with a password,
  `KEY=value` assignments whose key names a secret; sensitive paths (`.env`,
  `*.pem`, `*.key`, `id_rsa*`, `~/.aws`, `~/.ssh`, `~/.kube/config`, `.netrc`,
  `.npmrc`, `.git-credentials`); PII (CPF and CNPJ with valid check digits,
  card numbers passing Luhn, e-mail addresses, Brazilian phone numbers);
  custom terms; and `[REDACTED]` markers left by capture.
- [ ] AC3 — Each finding records category, rule, severity, session, project,
  member, timestamp, location (event field + `trace_id`, or transcript line
  number), masked evidence and fingerprint.
- [ ] AC4 — Severity is fixed per rule and documented: credentials and
  sensitive-path access are `high`; CPF, CNPJ, card, connection strings, JWTs
  and custom terms are `medium`; e-mail, phone and `[REDACTED]` markers are
  `low`.
- [ ] AC5 — Repeated matches of the same rule in the same record collapse into
  one finding carrying a count, instead of one finding per occurrence.
- [ ] AC6 — Re-indexing a transcript or rebuilding the index produces exactly
  the same findings for the same data (idempotent), and leaves every stored
  snapshot byte-identical.
- [ ] AC7 — CPF, CNPJ and card rules validate check digits / Luhn, so a
  sequence of digits that cannot be one of those is not reported as one.

Security activity:

- [ ] AC8 — Tool calls are classified into `sast`, `sca`, `secrets`, `iac`,
  `container`, `dast`, `supply-chain` and `review` from the command or tool
  invoked, with the tool's name preserved; the initial catalogue is documented
  and extending it is a code change, not configuration.
- [ ] AC9 — Classification reads only `tool.call` / `tool.fail` events, and
  only the invoked command: a prompt, an assistant message or a file that
  merely *mentions* a scanner produces no action.
- [ ] AC10 — Outcome is `error` for `tool.fail`, `clean` or `findings` when the
  response states it unambiguously, and `unknown` otherwise — never guessed.
- [ ] AC11 — Suppression signals (inline suppression comments written to a
  file, entries added to scanner ignore files, `--no-verify`, `SKIP=` on
  pre-commit) are recorded in the `suppression` category and are never counted
  as security actions.
- [ ] AC12 — A session is marked code-touching when it has at least one
  file-writing tool call or a commit/patch command; coverage reports, for the
  current filter, how many code-touching sessions have at least one action, and
  how many have one per category (SAST, SCA, secrets).
- [ ] AC13 — Gap sessions (code-touching, no action) are listed with session,
  project, member, last activity and number of code edits.
- [ ] AC14 — No part of the analysis requires GAIDE: with the GAIDE entries
  removed from the catalogue the behaviour for a non-GAIDE project is
  unchanged, and a project that never ran a GAIDE check is reported on
  normally.

API:

- [ ] AC15 — `GET /api/v1/security?project=&from=&to=` returns both halves
  (exposure and activity) with totals, per-category rows, per-day series,
  recurring fingerprints, top affected sessions, coverage, gaps and
  suppressions, plus the scan's as-of timestamp and whether it is stale.
- [ ] AC16 — `GET /api/v1/sessions/<id>` gains a `security` block with that
  session's findings and actions; the response shape stays backward-compatible
  for existing console code.
- [ ] AC17 — `GET /api/v1/security/export?kind=findings|actions&format=jsonl|csv`
  exports the rows behind the page, inside the caller's scope and filters.
- [ ] AC18 — `GET`/`PUT /api/v1/security/terms` read and replace the custom
  term list (admin only); terms are literal, case-insensitive, 4–64
  characters, at most 100 per project, and are rejected with 400 otherwise.
- [ ] AC19 — `POST /api/v1/security/rescan` (admin, optional `project`) starts
  one background rescan and answers 202; a second request while one runs
  answers 409; `GET /api/v1/security/rescan` reports state, start time,
  progress and last result.
- [ ] AC20 — Every read endpoint applies the caller's project scope, exactly as
  the existing reads do.

Negative (abuse) criteria:

- [ ] AC21 — No stored row and no API response ever contains a matched secret,
  PII value or custom-term context: evidence carries at most the first 4
  characters plus a length, and no surrounding text is stored.
- [ ] AC22 — Fingerprints are HMAC values over a per-store random salt; the
  salt is never served by any endpoint, and the same value in two stores
  produces different fingerprints.
- [ ] AC23 — A scoped member learns nothing about a project outside their
  scope through the security endpoints: not a count, not a rule name, not a
  session id, not a project name, not an error that distinguishes "no data"
  from "not yours".
- [ ] AC24 — The term endpoints and the rescan endpoints require `admin`; a
  member token or a `member` key gets 403 and nothing changes.
- [ ] AC25 — Custom terms are literal strings, never compiled as patterns, so
  no term can alter the scan's behaviour or cost beyond a substring search.
- [ ] AC26 — Scanning is bounded: at most the first 50 000 characters of any
  line or field, at most 20 findings per record and 1 000 per session, with
  the truncation reported in the response rather than silently applied; every
  pattern in the catalogue runs in time linear in the input (no nested
  quantifiers), and a crafted 50 MB line cannot stall ingest or a rescan.
- [ ] AC27 — Ingest keeps working if the scan of one record fails: the record
  is still stored and the failure is logged, never swallowed (Principle 8).

Console:

- [ ] AC28 — A `Security` page, in the nav for members and admins, shows both
  halves: severity tiles, findings per day, the rule table, recurring values,
  affected sessions; action tiles, actions per day by category, the tool table,
  coverage, the gap list and the suppression list — all honouring the shared
  project/date filter.
- [ ] AC29 — The session page shows that session's findings and actions.
- [ ] AC30 — The page always states its two limits (event text is redacted at
  capture; scanners run outside an agent session are not in the ledger) and,
  when the scan is stale or truncated, says so.
- [ ] AC31 — The custom-term editor and the rescan control appear only for
  admins; the page never presents a per-person ranking of findings.
- [ ] AC32 — Charts follow the console's existing conventions (at most four
  categorical series plus an "other" bucket, CVD-safe palette, a table
  fallback for every chart).

Upgrade and documentation:

- [ ] AC33 — A store from v0.6.0 is scanned once on the first start of the new
  version, before the server binds, with progress on stderr/stdout, and needs
  no manual command; `rebuild-index` also reproduces the security tables.
- [ ] AC34 — `docs/SERVER.md` documents the endpoints, the rule catalogue with
  severities, the activity catalogue, what the analysis cannot see, the term
  rules and the rescan; `README.md` mentions the page in the console's feature
  list.

## Out of scope

- **Running real scanners.** The server does not execute semgrep, gitleaks,
  osv-scanner or anything else, and does not read the user's repository. It
  classifies what the ledger already recorded.
- **A local CLI** over `.gaide-trace/` stores. Server-only in this spec; the
  classifier stays a self-contained module so a local command can reuse it in
  a later spec without a second definition of "finding".
- **Changing capture.** No hook change, no new captured field, no change to
  capture-time redaction (D5). If the scan shows redaction is too narrow, that
  is a separate spec against the hook.
- **Entropy-based secret detection** (flagging high-entropy strings). Too noisy
  to ship as a first catalogue; revisit with real data from this feature.
- **Reconstructing file contents** from `Write`/`Edit` inputs to attribute a
  secret to a file in the repository.
- **Purging or redacting the offending data** from the archive or snapshots. A
  "clean up this session" action is a real need and a separate spec — it
  deletes research data, which is an ethics decision, not a button.
- **Policy baselines and scorecards** per project or per person ("SAST+SCA
  required every sprint", adherence grades).
- **Alerting**: no webhook, e-mail, Slack or CI gate. The page is read-only.
- **Per-finding workflow**: no acknowledge, assign, mute or false-positive
  state. A finding is a fact about the data, not a ticket.
- **Scanning anything the server does not already store** (repositories,
  CI logs, issue trackers).

## Security considerations

- **Data sensitivity:** the highest of any feature so far. The scan reads raw
  transcripts (prompts, file contents, third-party personal data) and produces
  a concentrated index of *where the sensitive material is* — the single most
  attractive table in the store. Two controls make that safe: the findings
  table stores no matched value (AC21), and every read is scope-filtered
  (AC20, AC23). A finding is a pointer, not a copy.
- **Authentication / authorization:** reads require `member` and the caller's
  project scope; custom terms and rescans require `admin` (AC24). The console
  hiding a control is not a control.
- **Abuse cases:**
  - *The findings table as a secret store* — if evidence carried the full
    match, this feature would duplicate every secret in the store into one
    queryable table. Masked evidence plus salted fingerprints (AC21, AC22).
  - *Fingerprint brute force* — a CPF has ~10¹¹ values and an unsalted hash
    would be trivially reversible; the per-store secret salt removes that
    (AC22).
  - *Cross-project leakage through the new endpoints* — the same oracle risk
    the project-access spec closed for every other read (AC23).
  - *Scanner flooding / ReDoS* — the scanned text is written by whoever holds
    an `agent` key. Linear patterns and hard caps keep ingest and rescan
    bounded (AC26), and capture itself must stay unaffected (D4 lives on the
    client; the server's cost never travels back to a session).
  - *Terms as a code-injection vector* — literal matching only, never a
    compiled pattern (AC25).
  - *Rescan as a denial of service* — one rescan at a time, admin only, in a
    background thread, never blocking reads (AC19).
  - *Surveillance drift* — findings name the member who ran the session
    because rotating a key requires knowing whose it was, but the page must
    not become a per-person scoreboard (AC31). Measuring practice is the
    research goal; ranking people is not.

## Effect on captured data, invariants and ethics

- **Captured data:** unchanged. No new event field, no schema change, no
  adapter change; `schema/event.schema.json` is untouched. Stores already in
  the field stay readable by older versions.
- **Invariants:** D4 is not touched (no capture-path change). D5 is *measured*,
  not changed — the scan exists partly to show how well capture-time redaction
  works, and the spec says plainly that transcripts stay raw. D6 is untouched
  (no client change). D7 holds: findings and actions are derived index data,
  rebuilt by `rebuild-index` and by the version-bump re-derivation, and the
  JSONL archive plus the snapshots remain the truth. Stdlib-only holds: `re`,
  `hashlib`, `hmac`, `secrets` — no scanner library, no network call.
- **Privacy and ethics:** the feature widens nothing that is captured and sends
  nothing anywhere new; it makes already-stored exposure visible so it can be
  remediated, which is a net reduction in risk for the research data. The
  ethical weight is in *who* can see the pointer index (scope, admin-only
  terms) and in not turning a research instrument into a per-person
  surveillance report (AC31). The README's privacy section is updated to say
  the server analyses stored data for exposure and that the analysis stores no
  secret values.

## Dependencies

- `specs/project-access` — scope enforcement is reused as-is for the new reads.
- `specs/model-usage` — the derived-data pattern (`DERIVED_VERSION`,
  re-derivation before binding) is reused; this spec bumps it.
- No new libraries. Python standard library only, on the server path.
- No MCP server. The `verifier` skill needs `playwright` for the console pass,
  as for any console work (it is currently unavailable in this environment —
  verification falls back to a manual browser pass plus `curl`).

## Constitution adherence

- **Principle 1 (Spec before code):** this spec precedes implementation ✓
- **Principle 2 (Tests track behavior):** every AC maps to tests in
  `tests/test_security_scan.py` (scanner rules, idempotency, caps, API shape,
  scope) via `test-generator`.
- **Principle 3 (Human approval):** nothing is implemented before the
  maintainer approves spec, plan and tasks.
- **Principle 5 (ADRs):** deriving the analysis in the index (rather than
  scanning at query time or shelling out to real scanners), and the
  masked-evidence + salted-fingerprint rule, are architectural — ADR 0003.
- **Principle 6 (No secrets in the repo):** test fixtures use synthesised,
  obviously-fake values, never harvested ones, and never a real key shape that
  a scanner would flag in CI.
- **Principle 8 (Fail visibly):** a scan failure on one record is logged and
  the record still stored (AC27); a failed rescan reports its error.
- **Principle 10 (Security findings are load-bearing):** this feature makes the
  principle measurable — suppression signals are recorded as such (AC11), and
  the spec forbids counting them as activity.

## Identified risks

- **False positives drown the signal** (e-mails in git metadata, example keys
  in documentation, fake tokens in test fixtures) | Mitigation: severity is
  per rule with e-mail/phone/marker rules at `low`; the rule table shows
  counts per rule so noise is visible and the catalogue can be tightened with
  real data before the page is trusted.
- **False negatives read as "clean"** | Mitigation: the page states its limits
  on every view (AC30) — redacted event text, no CI visibility, pattern-based
  detection. "No findings" never renders as a clean bill of health.
- **Rescan cost on a large store** (hundreds of MB of snapshots) | Mitigation:
  bounded per-line work, one job at a time, progress reported; the upgrade scan
  runs before binding, like the existing re-derivation, so it is never racing
  live ingest.
- **Ingest latency** from scanning every record | Mitigation: compiled
  patterns at module import, caps per field, and a measurement task in the plan
  — if per-batch cost grows beyond a set budget, scanning moves off the ingest
  path to the rescan/derivation path only.
- **Catalogue rot** (new scanners, renamed tools) | Mitigation: the catalogue
  is one documented table in one module; `docs/SERVER.md` lists it so a gap is
  visible, and unrecognised tools are simply not counted — never guessed.
