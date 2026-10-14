# ADR 0003 — Security analysis is derived index data, and a finding is a pointer, not a copy

- **Status:** accepted
- **Date:** 2026-10-14
- **Decision-makers:** José Menezes

## Context

Through v0.6.0 the server analyses the ledger for usage and cost. Two security
questions the stored data can already answer have no mechanism
([spec](../../specs/security-scan/spec.md)): whether potentially confidential
information passed through a session, and whether any security activity (SAST,
SCA, secret scanning, IaC checks, a security review) actually happened while
the work was done — the latter for any project in the ledger, GAIDE-governed
or not.

Both answers come from text the server already holds: the indexed event fields
and the transcript snapshots, which are raw by design
([D5](../ARCHITECTURE.md)). Three questions shaped the decision: *when* the
analysis is computed, *what* a finding is allowed to contain, and *who* may
change what is detected.

The constraints are the project's own: standard library only on the server
path, JSONL remains the truth ([D7](../ARCHITECTURE.md)), captured data
outlives every version of this code, and the server has no access to anyone's
repository — it sees the ledger, not the code.

## Decision

1. **The analysis is derived index data, computed when data arrives or is
   re-derived — never at query time.** Findings, actions and terms live in
   three new SQLite tables, filled at ingest, at transcript indexing, by the
   version-bump re-derivation (`DERIVED_VERSION` 3 → 4), by `rebuild-index`
   and by an explicit admin rescan. They are fully rebuildable from the JSONL
   archive and the snapshots, so D7 is unchanged: the tables are an index, not
   a record.
2. **The server never runs a real scanner.** No semgrep, gitleaks or
   osv-scanner process, no repository checkout, no network call. Detection is
   pattern matching over stored text, in the standard library. What the server
   reports about SAST and SCA is *that the team ran them*, read from the
   ledger — not its own opinion of the code.
3. **A finding stores a pointer, not a value.** Each finding carries category,
   rule, severity, session, project, member, timestamp and location (event
   field plus `trace_id`, or transcript line number), masked evidence of at
   most the first four characters plus a length, and a fingerprint —
   `HMAC-SHA256` over a per-store random salt, truncated. Never the matched
   value, never the text around it. The fingerprint groups one value across
   sessions; the salt makes it unguessable even where the value space is small
   (a CPF has ~10¹¹ possibilities, and an unsalted digest of one is reversible
   in seconds).
4. **Catalogues are code; only vocabulary is data.** The rule catalogue and
   the activity/suppression catalogue live in one module and change through a
   reviewed commit. Admins configure *custom terms* — literal, case-insensitive
   keywords naming internal or proprietary content — which are never compiled
   as patterns.
5. **The server becomes a directory, not a single file.** The classifier lands
   in `server/security_scan.py`, imported by `gaide_trace_server.py`, so a
   local command can later reuse it without a second definition of "finding".

## Alternatives considered

- **Scan at query time.** No new tables, always current, no staleness and no
  rescan machinery. Rejected: every page load would re-read every snapshot in
  the filter — hundreds of megabytes for a research-scale store — and the cost
  would land on the reader instead of once on the writer. Derived data is also
  the pattern the server already uses for model usage.
- **Shell out to real scanners (gitleaks, trufflehog) on the server.**
  Far better detection quality, maintained rule sets. Rejected on two grounds:
  it breaks the stdlib-only deployment story (the server is expected to run on
  a bare VPS with no package manager), and it would mean handing raw
  transcripts to a third-party binary. The catalogue's job is to be honest
  about being pattern-based, not to pretend to be a scanner.
- **Store the matched value (or surrounding context) with the finding.**
  Trivially more useful for triage: an admin would see exactly which key
  leaked. Rejected outright — it would turn the index into one queryable table
  holding every secret the store has ever seen, which is a worse exposure than
  the one the feature exists to report. Masked evidence plus the fingerprint
  covers the real need (identify and rotate; see the same value recur).
- **Unsalted hashes as fingerprints.** Comparable across stores, which would
  let a future deployment correlate leaks. Rejected: small value spaces (CPF,
  CNPJ, card, phone) make an unsalted digest equivalent to storing the value.
- **Make the rule catalogue configurable (admin-supplied regexes).** Flexible
  and tempting. Rejected: a user-supplied pattern is arbitrary execution cost
  (ReDoS) on the ingest path, and it would make two stores incomparable for
  research. Literal terms give the needed flexibility at no cost.
- **Policy baselines and per-project or per-person scorecards.** Deferred, and
  deliberately: the ledger is a research instrument. Findings name the member
  because rotating a key requires knowing whose session it was, but a ranking
  of people would change what the tool is for. The spec forbids it; a later
  ADR can revisit it if the research needs it.
- **Keep everything in `gaide_trace_server.py`.** Preserves the
  copy-one-file story. Rejected as a smaller cost than it looks: every
  deployment already copies `server/` (Dockerfile, systemd unit, AWS
  bootstrap), only by-path loaders need a `sys.path` entry, and the catalogue
  is exactly the kind of table that wants to be read on its own.

## Consequences

### Positive
- Both questions are answered without touching capture: no hook change, no new
  captured field, no schema change (`schema/event.schema.json` untouched), so
  stores in the field stay readable by older versions.
- The index stays rebuildable; nothing in the archive or in any snapshot is
  modified by the analysis.
- The most attractive table in the store holds no secret: the blast radius of
  a read-authorization bug on these endpoints is "where to look", not "what
  the value is".
- Security practice becomes measurable from behaviour instead of self-report,
  for GAIDE and non-GAIDE projects alike.

### Negative (accepted costs)
- **Detection is pattern-based, so it has false positives and false
  negatives.** The console must therefore state its limits on every view —
  event text was already redacted at capture, scanners that run in CI are not
  in the ledger — and "no findings" must never render as a clean bill of
  health.
- **Masked evidence makes triage harder.** An admin sees that an AWS key
  leaked in a session, not which one; identifying it means opening the session.
  Accepted: the alternative is a secret store.
- **Terms changes make stored findings stale** until a rescan runs, so the page
  carries a staleness state the reader has to understand.
- **Ingest does more work per record**, and a transcript's findings are
  recomputed on every upload of its snapshot. Measured against a budget before
  the feature is called done; the fallback is to scan only on derivation.
- **Upgrading a large store pays a one-time scan** before the server binds,
  as with the existing re-derivations.
- The server is no longer one file.

### Neutral
- Custom terms and the salt are server configuration, not captured data: they
  live in the index next to users and keys and are not part of what
  `rebuild-index` reproduces from the archive (the salt is preserved so
  fingerprints stay comparable).
- Reads reuse the scope helper from [ADR 0002](0002-project-scope-on-accounts.md)
  unchanged; the security endpoints add no new authorization concept.
- The classifier module is importable, which makes a local
  `.gaide-trace` command a later spec rather than a rewrite.

## Constitution adherence

- **Principle 1 (Spec before code):** behaviour specified in
  `specs/security-scan/spec.md`, approved before this record.
- **Principle 5 (ADRs):** this record precedes implementation.
- **Principle 6 (No secrets in the repository):** the decision not to store
  matched values extends the same reasoning to the ledger's own index; test
  fixtures assemble fake secrets at runtime so no complete pattern exists as a
  literal in the repository.
- **Principle 8 (Fail visibly):** a scan failure on one record is logged and
  the record is still stored; a failed rescan reports its error.
- **Principle 10 (Security findings are load-bearing):** suppression signals
  are recorded as their own category and are never counted as security
  activity, which makes the principle measurable instead of aspirational.
- **D5 / Privacy & ethics (README):** the analysis measures redaction rather
  than changing it, widens nothing that is captured, and sends nothing
  anywhere new.

## Future review

Revisit when any of these appears: the measured false-positive profile makes a
rule class untenable (entropy-based detection would be the replacement to
consider); the ingest budget is missed on a real team's volume; a local
`.gaide-trace` scan command is wanted (the module is ready, the CLI surface is
not specified); a need to purge or redact offending data from the archive
appears (a separate spec — it deletes research data); or the research programme
needs policy baselines, which would reopen the deliberate decision not to
score people.
