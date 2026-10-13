# Plan: Project access — choose which projects each user can see

> **Prerequisite:** `spec.md` approved (2026-10-13).

## Architectural decisions

- **Scope lives on console accounts, not on API keys.** Keys are an admin's
  scripting tool and already carry a role chosen by the admin; adding a
  second axis to them doubles the key UI for no stated need. — **ADR required**
  (`docs/adr/0002-project-scope-on-accounts.md`), because it fixes the shape
  of the authorization model for everything that comes after (groups, per
  project roles would extend this, not replace it).
- **The server enforces, the console mirrors.** Every read query applies the
  caller's scope through one shared helper; the console only uses `/me` to
  render notices. — part of the same ADR.
- **Scope is resolved once per request, at authentication.** The identity
  dict gains `scope`: `None` for *all projects* (admins, API keys, accounts
  with the all-projects flag) or a list of names (possibly empty). Handlers
  never read the grants table themselves. — minor decision.
- **Storage: a flag plus a grants table.** `users.all_projects INTEGER`
  (migration sets it to 1 for every account that exists before the column,
  AC6) and `user_projects(user_id, project, granted_at, granted_by)` with a
  composite primary key. Grants are by name, so removing a registration or
  having no data does not touch them (use case 10). — minor decision.
- **Non-visible means non-existent.** For a scoped caller a session outside
  the scope is a 404 with the body `unknown session`, and a project outside
  the scope filters like a project with no data. No 403 on reads, so nothing
  confirms existence (AC13, AC21). — minor decision, written into the spec.
- **No new endpoint for the offered project list.** The Users page unions
  what an admin already gets from `GET /api/v1/projects` (seen) and
  `GET /api/v1/projects/manage` (registered) (AC3). — minor decision.
- **Scope changes are logged, not tabled.** One stderr line per change via
  the handler's own logger (Principle 8). — minor decision.

## Affected components

- `server/gaide_trace_server.py`
  - `Store._init_schema` — column `users.all_projects`, table `user_projects`,
    migration that flags pre-existing accounts.
  - `authenticate` — resolve `scope` for user tokens; keys get `None`.
  - new helper `scope_sql(ident, col)` → (`fragment`, `params`): empty for
    `None`, `col IN (...)` for a list, `0 = 1` for an empty list.
  - `_filters`, `api_overview`, `_overview_models`, `api_sessions`,
    `api_session_detail`, `api_get_transcript`, `api_export`, `api_models`,
    the `GET /api/v1/projects` route, `api_projects_manage`,
    `api_rotate_project` — apply the scope.
  - `api_create_project` — auto-grant to a scoped creator (AC9).
  - new `PUT /api/v1/users/<id>/scope`; `GET /api/v1/users` returns
    `all_projects` and `projects`; `api_create_user` accepts the same two
    fields; `/api/v1/me` and the login response carry `scope`.
  - module docstring: one line on scopes.
- `server/webui/app.js` — Users page scope editor (switch + checklist) in
  the create form and per row; shell notice from `/me.scope`; empty-list
  message in every view; "keys are not scoped" note on Users and API keys
  pages. `server/webui/style.css` only if the checklist needs it.
- `tests/server_harness.py` — `add_user(..., projects=None)` helper that
  writes the flag and grants directly, so tests do not depend on the
  endpoint under test.
- `tests/fixtures.py` — nothing new expected; reuse `event` and `transcript`.
- `tests/test_project_access.py` — new, HTTP-level, one fixture store with
  projects `app`, `api`, `research` and unassigned data.
- `docs/SERVER.md` — roles table, a "Who sees what" section, endpoint table.
- `docs/adr/0002-project-scope-on-accounts.md` — new.

## Implementation sequence

1. ADR 0002 (decision recorded before code, Principle 5).
2. Tests first (red): `tests/test_project_access.py` covering AC1–AC21 on
   the harness, plus the harness helper.
3. Schema, migration and scope resolution in `authenticate`; `/me` and login
   carry it (AC6, AC7, AC8).
4. Scope management endpoint, users listing, create form fields, validation,
   logging (AC1, AC2, AC4, AC5, AC19).
5. Shared `scope_sql` helper; sessions, session detail, transcript (AC12,
   AC13, AC17, AC21).
6. Overview and models (AC11, AC15, AC20).
7. Export (AC14).
8. Projects list, manage, rotate, auto-grant on register (AC9, AC10, AC16).
9. Suite green; `./init.sh` clean.
10. Console: Users page scope editor and key note (AC22, AC24).
11. Console: subset notice and empty state (AC23).
12. `docs/SERVER.md` (AC25), docstring, `PROGRESS.md`.
13. `verifier` against a local server; `security-reviewer`; `code-reviewer`.

Commits: one for the ADR; one for the server (steps 2–9, tests included);
one for the console (10–11); one for the docs (12). Four concerns, four
commits (Principle 7).

## Testing strategy

- Unit tests: `scope_sql` on its three shapes, and the migration on a store
  created with the previous schema (a temp DB whose `users` table lacks the
  column: after `Store()` every existing account has `all_projects = 1`).
- Integration tests (`tests/test_project_access.py`, in-process server):
  - one store, three projects plus unassigned data, members `all`, `two`
    (`app`, `api`) and `none` (empty list), one admin, one member key;
  - for each read endpoint, the three members and the key, asserting counts,
    names and the "unknown session" body (AC10–AC18, AC20, AC21);
  - scope endpoint: validation, admin-only, admin target rejected, effect
    without re-login (AC1, AC4, AC5, AC7, AC19);
  - register-while-scoped auto-grant and the 409 path that must not grant
    (AC9).
- Manual (verifier skill, running server + console): AC22–AC24 end to end as
  admin and as a scoped member; the Node-free suite covers nothing in
  `app.js`.

## Implementation risks

- Risk: the scope fragment is appended to a query that already has a `WHERE`
  with a different alias (`events`, `sessions`, `s.`, `mt`) and silently
  filters the wrong column | Mitigation: `scope_sql` takes the column
  expression; every call site is covered by an AC test that would fail with
  an unscoped answer.
- Risk: `api_models` ranks models across all data via `model_turns`, which
  has no project column | Mitigation: join `sessions` for the scoped case
  only; the unscoped query stays as it is, so the price page cost is
  unchanged.
- Risk: the transcript endpoint reads the file by session id without touching
  the index | Mitigation: look the session up in `sessions` first, under the
  scope, then read the file.
- Risk: the migration runs on every start | Mitigation: guarded by
  `PRAGMA table_info`, like the existing v0.2→v0.3 migration.

## Sprint contract

- [x] A member scoped to `app, api` sees only those two in the project filter
  and in the Overview breakdown — verify by: sign in as that member, open
  Overview, read the filter and the "projects" card.
- [x] The same member, given a `research` session id, gets "unknown session"
  on `/api/v1/sessions/<id>` and on `/transcript`, status 404 — verify by:
  `curl -i -H "Authorization: Bearer <member token>" http://127.0.0.1:8321/api/v1/sessions/<id>`.
- [x] Her `GET /api/v1/export?format=jsonl` contains no `research` line —
  verify by: `curl ... | grep -c research` → 0.
- [x] `PUT /api/v1/users/<id>/scope` with a member token returns 403 and
  the admin's listing is unchanged — verify by: curl as member, then
  `GET /api/v1/users` as admin.
- [x] An admin ticks `research` for her on the Users page; her next
  `GET /api/v1/projects` includes `research` without signing in again —
  verify by: console action, then the curl above with the same token.
- [x] A store from v0.5.0 with two members starts on the new version with
  both members on *all projects* — verify by: run the suite's migration test,
  and `GET /api/v1/users` on an upgraded data directory.
- [x] A member with an empty list signs in and sees the "no project granted
  yet" message on every view — verify by: console as that member.
- [x] `./init.sh` passes and the suite has a test per AC1–AC21 — verify by:
  `./init.sh`; `grep -c "AC" tests/test_project_access.py`.

Checked 2026-10-13 by the implementer against a seeded local server (three
projects, one unassigned session, members `mia` = `app, api`, `nobody` = empty
list, `ana` = all projects), in the browser and with curl; the upgrade item
against a store created by the v0.5.0 server. The independent `verifier` pass
is still owed.

## Definition of Done

- [x] All tests derived from the spec pass (147, `./init.sh` OK)
- [ ] Code review approved (`code-reviewer` skill + human review)
- [ ] Security review approved (`security-reviewer` skill; mandatory for auth)
- [x] ADR 0002 recorded
- [x] `docs/SERVER.md` updated
- [x] No secrets in the diff (`check-secrets.sh` clean)
- [ ] Constitution respected
