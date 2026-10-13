# Spec: Project access — choose which projects each user can see

> **Status:** approved (2026-10-13)
> **Author:** José Menezes (drafted with Claude Code)
> **Date:** 2026-10-13

## Context

Today every console account with the `member` role sees everything the server
holds: every project's sessions, transcripts, aggregates and exports, and the
install prompts and ingest keys of every registered project. The only
distinction the server makes is `member` versus `admin`.

That is fine for a single team on a single codebase. It is not fine as soon as
the same server serves more than one team, a client, a student cohort or a
research partner: a transcript is raw by design (D5) and carries prompts, file
contents and third-party personal data, so showing a session to someone who is
not on that project is a data-protection problem, not a cosmetic one. The
maintainer needs to decide, per account, which projects that account can see.

For whom: admins who manage accounts (they grant access); members (they see
only what they were granted, and the console tells them so).

This is the first behavioral change to the server's authorization model, so
this spec is the spec for *read authorization* on the server. It does not
back-fill the rest of the auth model (login, password rules, key roles), which
stays described in `docs/SERVER.md`.

## Expected behavior

### Terms

- **Project:** the string carried by sessions and events as `project`. A
  project may be *registered* (it has a row on the Projects page and an ingest
  key) or merely *seen* (data arrived carrying that name, with a key that
  belongs to another registration or to a raw `agent` key). Access is granted
  by name, so both kinds can be granted.
- **Unassigned data:** sessions and events whose `project` is empty.
- **Scope** of an account: either **all projects** (everything, including
  unassigned data, exactly what a member sees today) or an explicit **project
  list** (zero or more project names).
- **Granted project:** a project inside an account's scope.
- **Admin:** an account with the `admin` role. Admins always have the *all
  projects* scope; it cannot be narrowed.
- **Visible data** for an account: with *all projects*, every session and
  event; with a project list, the sessions and events whose `project` is a
  granted project. Unassigned data is never visible to a project list.

### Use cases

1. **Admin restricts a member to some projects (main case)**
   - Given: an admin on the Users page, a member `mia`, and projects `app`,
     `api` and `research` holding data
   - When: the admin sets mia's scope to the list `app`, `api`
   - Then: the change takes effect on mia's next request, with no new login.
     mia's Overview, Sessions, session details, transcripts, Export, Projects
     page and project filter show only `app` and `api`. The Users page shows
     `app, api` next to mia.

2. **Member browses within scope**
   - Given: mia with scope `app`, `api`
   - When: she opens the console
   - Then: the project filter lists `app` and `api` only; Overview totals and
     the per-project and per-member breakdowns count only those projects'
     data; the Sessions list and the model filter's model list come only from
     those projects; the console says, somewhere persistent, that she sees a
     subset ("2 of your team's projects").

3. **Member reaches for data outside scope (abuse case)**
   - Given: mia with scope `app`, `api`, and a session `S` of `research`
   - When: she requests `S` directly by id (session detail or transcript
     download), or asks for `?project=research` on any read endpoint, or
     exports without a project filter
   - Then: `S` is reported as unknown (the same answer as for an id that does
     not exist); a `research` filter yields the same as a project with no
     data (empty, not an error that confirms it exists); the export contains
     only `app` and `api` events.

4. **Member with an empty list**
   - Given: a member whose scope is an empty project list
   - When: she signs in
   - Then: she can log in, change her password and see the console shell, but
     every view is empty and says that an admin has not granted her any
     project yet. Nothing errors.

5. **Admin widens a scope back to everything**
   - Given: mia with a project list
   - When: the admin picks *all projects* for her
   - Then: she sees everything again on her next request, including
     unassigned data.

6. **Registering projects while scoped**
   - Given: mia with scope `app`, `api`
   - When: she registers a new project `web`
   - Then: `web` is added to her list automatically (she created it, she must
     be able to hand out its install prompt), and the Users page reflects it.
     She can reveal the install prompt and rotate the key only of projects in
     her scope; the Projects page lists only those.

7. **Projects with no data yet**
   - Given: a registered project `new-thing` with no sessions
   - When: an admin edits any member's scope
   - Then: `new-thing` is offered for granting, alongside every project seen
     in the data, so access can be set up before the first session arrives.

8. **Existing server upgrades to this version**
   - Given: a server with members created before this feature
   - When: it starts on the new version
   - Then: every existing member keeps the *all projects* scope. Nobody loses
     access by upgrading; narrowing is always an explicit admin action.

9. **New members (default)**
   - Given: an admin creating a member
   - When: the account is created
   - Then: its scope is an empty project list unless the admin picks projects
     (or *all projects*) in the same form. Access is opt-in for accounts
     created from now on.

10. **A grant names a project that later disappears from the data**
    - Given: mia granted `old` and the registration of `old` removed
    - When: an admin views mia
    - Then: `old` still appears in her list (the grant is by name; data may
      still exist, or arrive again) and can be removed like any other.

11. **Non-admin tries to edit scopes (abuse case)**
    - Given: a member token or a `member` API key
    - When: it calls the scope-editing endpoint for any account
    - Then: the request is refused with the same answer as every other
      admin-only endpoint, and nothing changes.

### API keys

API keys with `member` or `admin` role are issued only by admins, for scripts.
They are **not** scoped by this spec: a `member` key keeps the *all projects*
scope it has today. `agent` keys ingest only and are untouched. The Users and
API keys pages say so.

### Audit

Every scope change is written to the server log (who changed whose scope, to
what). There is no audit table in this version.

## Acceptance criteria

Scope and management:

- [ ] AC1 — An admin can set a member's scope to *all projects* or to an
  explicit list of project names via the API and via the Users page.
- [ ] AC2 — `GET /api/v1/users` reports each account's scope; the Users page
  shows it ("all projects" or the names).
- [ ] AC3 — The set of projects offered for granting is the union of
  registered projects and projects seen in sessions, deduplicated.
- [ ] AC4 — Granting accepts any project name that matches the registration
  rule (letters, digits, `.`, `_`, `-`, max 64), including names with no data
  yet; anything else is rejected with 400 and no change.
- [ ] AC5 — Setting the scope of an admin to a list is rejected (400); admins
  always have *all projects*.
- [ ] AC6 — Existing members have *all projects* after upgrading a store that
  predates this feature; new members have an empty list unless the create
  form says otherwise.
- [ ] AC7 — A scope change takes effect on the account's next request without
  a new login.
- [ ] AC8 — `GET /api/v1/me` reports the caller's scope so the console can
  render the subset notice and the empty-list message.
- [ ] AC9 — A member who registers a project gets that project added to her
  list; a member with *all projects* is unchanged. A scoped member cannot
  register a name that already carries data, registered or not (409, the same
  answer as for a registered name), so registering never widens a scope to
  existing data.

Enforcement (server side, for a member with a project list):

- [ ] AC10 — `GET /api/v1/projects` returns only granted projects that have
  data; `GET /api/v1/projects/manage` only granted registrations.
- [ ] AC11 — `GET /api/v1/overview`: totals, per-day series, top tools, the
  per-project and per-member breakdowns and the model statistics count only
  visible data.
- [ ] AC12 — `GET /api/v1/sessions` lists only visible sessions; `?project=`
  naming a non-granted project returns an empty list with `total` 0, not an
  error.
- [ ] AC13 — `GET /api/v1/sessions/<id>` and `GET /api/v1/sessions/<id>/transcript`
  for a session that is not visible answer exactly as for an unknown session
  (404 with the same body).
- [ ] AC14 — `GET /api/v1/export` (jsonl and csv) contains only visible
  events, whatever the filters say; a non-granted `?project=` yields an
  empty export.
- [ ] AC15 — `GET /api/v1/models` lists models from visible data only (plus
  every priced model, as today, since prices are not per project).
- [ ] AC16 — `POST /api/v1/projects/<id>/rotate` on a registration outside
  the scope answers as for an unknown registration (404).
- [ ] AC17 — Unassigned data (empty `project`) is never visible to a project
  list; it is visible to *all projects*.
- [ ] AC18 — Admins and `member`/`admin` API keys see everything, unchanged
  from today.

Negative (abuse) criteria:

- [ ] AC19 — The scope-editing endpoint requires `admin`; a member token and a
  `member` key get 403 and nothing changes.
- [ ] AC20 — No read endpoint reveals, to a scoped member, the name of a
  project outside her scope: not in `projects`, not in overview breakdowns,
  not in the model list, not in error messages.
- [ ] AC21 — A scoped member cannot tell a non-granted project with data from
  a project with no data through any read endpoint (same status, same shape).

Console:

- [ ] AC22 — The Users page lets an admin edit a member's scope with an
  *all projects* switch and a checklist of offered projects (AC3), and shows
  the current scope per account; the create form carries the same control.
- [ ] AC23 — A scoped member sees a persistent notice naming how many projects
  she can see; with an empty list every view says an admin has not granted
  any project yet.
- [ ] AC24 — The Users and API keys pages state that API keys are not scoped.

Documentation:

- [ ] AC25 — `docs/SERVER.md` describes scopes, the default for new and
  upgraded accounts, the API-key exception, and the new endpoint.

## Out of scope

- Scoping `member`/`admin` API keys (see "API keys" above).
- Per-project roles (read-only versus manage), groups or teams of users, and
  project-level admins. One flat list per account.
- Write restrictions on ingest: an `agent` key still ingests whatever project
  name the hook sends. Project *ownership* of ingested data is not checked.
- Hiding member names (`origin`) across projects: within a granted project,
  every member who worked on it is visible, as today.
- An audit table or history of scope changes (log line only).
- Changing an account's role (no such endpoint exists today; not added here).
- Retroactively re-attributing unassigned data to a project.

## Security considerations

- **Data sensitivity:** this is the feature that stops raw transcripts (D5:
  prompts, file contents, third-party personal data) and per-member activity
  from reaching people outside the project. Getting it wrong leaks exactly the
  data the README's ethics section promises to protect.
- **Authentication / authorization:** only admins set scopes (AC19). The
  server enforces scope on every read endpoint (AC10–AC17); the console only
  reflects it. A console that hides a link is not a control.
- **Abuse cases:**
  - *IDOR on session ids:* ids are UUIDs but circulate in chat and logs; a
    scoped member pasting one must get an "unknown session" (AC13), not the
    data and not a "forbidden" that confirms it exists.
  - *Enumeration through filters:* `?project=`, `?origin=` and the model list
    must not act as oracles for projects outside the scope (AC12, AC15,
    AC20, AC21).
  - *Export without filters:* the one endpoint that returns bulk raw data must
    apply the scope even when the caller asks for everything (AC14).
  - *Privilege escalation via self-service:* a member must not be able to
    widen her own scope, including by registering a project name that
    already exists to gain its data (AC9 grants only on *successful*
    registration, which for a scoped member fails with 409 for any name that
    is registered *or* already seen in the data, including a name whose
    registration an admin removed). The 409 confirms that a name is taken;
    that is the one place a scoped member learns a name exists, and it was
    already true of registered names before this spec.
  - *Upgrade lock-out / silent widening:* existing members keep what they had
    (AC6); nobody gains access silently because new accounts start empty.
- **Bypass through other roles:** a `member` API key sees everything; the
  spec says so explicitly (AC18, AC24) so an admin issuing one knows what it
  is.

## Dependencies

- Other specs: `specs/model-usage` (the model statistics and `GET /api/v1/models`
  this spec narrows to visible data); `specs/price-import` (unaffected: prices
  are global).
- External systems: none.
- Libraries: none. Standard library only, as for everything on the server path.

## Constitution adherence

- **Principle 1 (Spec before code):** this spec was written before implementation ✓
- **Principle 2 (Tests track behavior):** AC1–AC21 map to HTTP-level tests in
  `tests/` on the in-process harness; AC22–AC24 are verified against the
  running console by the `verifier` skill.
- **Principle 3 (Human approval):** implementation waits for approval of this
  spec, the plan and the tasks.
- **Principle 5 (ADRs):** [ADR 0002](../../docs/adr/0002-project-scope-on-accounts.md) records the decision to scope accounts but not API keys, and
  to enforce in the server with the console as a mirror.
- **Principle 8 (Fail visibly):** scope changes are logged; a scope that
  cannot be resolved (for example a corrupt row) denies, never widens.
- **D7 (JSONL is the truth):** scopes are account configuration, not captured
  data; they live in the index like users and keys do and are not part of
  `rebuild-index`. The archive stays rebuildable as before.
- **Security review:** mandatory for this change (it touches server auth).

## Identified risks

- Risk: a read endpoint is missed and keeps serving everything | Mitigation:
  one shared scope filter applied by every read query, plus a test per
  endpoint (AC10–AC17) that asserts the scoped answer against a fixture with
  three projects and unassigned data.
- Risk: performance of per-request scope resolution | Mitigation: one small
  indexed lookup per request; grants are tiny tables.
- Risk: a project name granted differs in case from the name in the data |
  Mitigation: grants are exact-match, like filters are today; the Users page
  offers names from the data (AC3), so admins pick rather than type.
- Risk: upgrade default surprises an admin who expected restriction by
  default | Mitigation: AC6 is spelled out in `docs/SERVER.md` and in the
  release note; narrowing takes one click per account.
