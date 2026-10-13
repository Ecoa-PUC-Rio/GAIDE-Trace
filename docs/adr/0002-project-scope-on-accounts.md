# ADR 0002 — Project scope attaches to console accounts and is enforced by the server

- **Status:** accepted
- **Date:** 2026-10-13
- **Decision-makers:** José Menezes

## Context

Through v0.5.0 the team server has one axis of authorization: the role
(`agent` ingests, `member` reads and exports, `admin` manages). Every
`member` sees every project the server holds — sessions, aggregates, raw
transcripts, exports, and the install prompts and ingest keys of every
registered project.

That model assumes one team on one codebase. The server is now expected to
serve several populations at once: more than one team, a client, a student
cohort, a research partner. Transcripts are raw by design
([D5](../ARCHITECTURE.md)) and carry prompts, file contents and third-party
personal data, so a session reaching someone who is not on that project is a
data-protection failure, not a cosmetic one. The maintainer needs to decide,
per account, which projects that account can see
([spec](../../specs/project-access/spec.md)).

Two questions shaped the decision: *what* carries the scope (accounts, API
keys, or both), and *where* it is enforced (server, console, or both).

## Decision

1. **Scope is a property of console accounts, not of API keys.** Every
   account has either the *all projects* scope or an explicit list of project
   names. Admin accounts always have *all projects*. `member` and `admin` API
   keys keep the *all projects* scope they have today; `agent` keys ingest
   only and are untouched. The console states this wherever keys are managed.
2. **The server enforces the scope on every read; the console only mirrors
   it.** Each read query applies the caller's scope through one shared helper,
   resolved once per request at authentication. The console reads the scope
   from `/api/v1/me` to render notices and empty states, nothing more.
3. **Outside the scope means non-existent.** A session the caller may not see
   answers exactly as an unknown session; a project the caller may not see
   filters exactly as a project with no data. Reads never answer "forbidden".
4. **Defaults protect existing installs and new accounts alike.** Accounts
   that exist before the upgrade keep *all projects* (nobody is locked out by
   upgrading); accounts created afterwards start with an empty list (access is
   opt-in).

## Alternatives considered

- **Scope on API keys as well.** Keys are issued only by admins, for scripts,
  and already carry a role the admin chose. A second axis on keys doubles the
  key UI and the test surface for a need nobody has stated. If scripted
  per-project access becomes a need, a scoped key extends this model (a key
  with a scope) without changing it.
- **Scope on the ingest side (an agent key may only ingest its own
  project).** Orthogonal: it governs what data arrives, not who reads it. Out
  of scope here and still possible later.
- **Groups or teams of users with per-project roles.** Richer, but it
  presupposes a membership model the project does not have. A flat list per
  account is the smallest thing that answers the stated need, and groups
  would be a layer on top of these grants, not a replacement.
- **Enforce in the console only (hide links and filters).** Not a control:
  every endpoint is reachable with the session token from `curl`. Rejected
  outright.
- **Answer 403 for sessions outside the scope.** Simpler to reason about,
  but it turns a session id pasted in chat into an oracle that confirms the
  session exists on that server. Rejected in favor of indistinguishability.

## Consequences

### Positive
- One server can host several populations without any of them seeing the
  others' raw data.
- The authorization model stays small: role plus scope, both resolved at
  authentication, both enforced by one helper every read query uses.
- Upgrading is safe: existing members keep what they had.

### Negative (accepted costs)
- A `member` API key is a full-read credential; an admin issuing one must
  know that. The console says so.
- Every read query carries one more fragment and the scoped `models` query
  joins `sessions`; the unscoped (admin, key) queries are unchanged.
- Scope changes are logged, not tabled; there is no history view.

### Neutral
- Grants are by project *name*, exactly matching the `project` field of the
  data. Renaming a project in the hooks' configuration means re-granting.
- Scope is account configuration and lives in the SQLite index next to users
  and keys; it is not captured data and is not part of `rebuild-index`
  ([D7](../ARCHITECTURE.md)).

## Constitution adherence

- **Principle 1 (Spec before code):** the behavior is specified in
  `specs/project-access/spec.md`, approved before this ADR was written.
- **Principle 5 (ADRs):** this record precedes implementation.
- **Principle 8 (Fail visibly):** a scope that cannot be resolved denies;
  every scope change is logged with actor and target.
- **D5 / Privacy & ethics (README):** this is the mechanism that keeps raw
  transcripts inside the project they belong to.

## Future review

Revisit when any of these appears: a need for scripted per-project access
(scoped keys), a need for per-project roles or groups, a need for ingest-side
ownership checks, or a second server population large enough that a flat
list per account becomes unwieldy to administer.
