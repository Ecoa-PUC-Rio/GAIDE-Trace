# Tasks: Project access — choose which projects each user can see

> **Prerequisite:** `plan.md` approved (2026-10-13).
>
> Decomposition into **atomic** tasks (~30 min each). Each task has a verifiable completion criterion.
>
> **Status lifecycle:** `pending → in-progress → done → verified`.
> `done` = implemented and its own tests pass. `verified` = checked against the spec's acceptance criteria by someone (or some agent) other than whoever implemented it.
> Status only moves forward when the work actually happened — re-marking tasks to make work *appear* done violates Constitution Principle 9.

Task 1 is **commit 1** (ADR). Tasks 2–9 form **commit 2** (server + tests).
Tasks 10–11 form **commit 3** (console). Task 12 is **commit 4** (docs).
Task 13 is verification and review, no commit of its own.

---

## Task 1 — Record ADR 0002: scope on accounts, enforced by the server

**Status:** done

**Files:** `docs/adr/0002-project-scope-on-accounts.md`

**Description:** Nygard-format ADR for the two decisions in the plan: scope
attaches to console accounts, not API keys; the server enforces it on every
read, the console only mirrors `/me`. Context names the multi-team / research
partner case and D5 (raw transcripts). Consequences name the `member`-key
exception and what a future per-project-role feature would extend.

**Done when:**
- [x] ADR exists with Status, Context, Decision, Consequences
- [x] `specs/project-access/spec.md` and `plan.md` link to it

**Estimate:** ~20 min

**Depends on:** —

---

## Task 2 — Harness helper and failing tests (red)

**Status:** done

**Files:** `tests/server_harness.py`, `tests/test_project_access.py`

**Description:** `ServerHarness.add_user(username, role, all_projects=None,
projects=None)` writes the flag and grants directly in SQL. New test module
with one store holding events and transcripts for `app`, `api`, `research`
and unassigned sessions, and members `all`, `two` (`app`, `api`), `none`
(empty list), plus the harness admin and member key. One test method per
AC1–AC21, each docstring naming its AC. All fail or error before Task 3.

**Done when:**
- [x] `python3 -m unittest discover -s tests -p "test_project_access.py"`
  runs 21+ tests and none passes for the wrong reason (missing endpoint →
  404/AttributeError, not a silent pass)
- [x] Fixture data is synthesized in the test, nothing copied from a store

**Estimate:** ~40 min

**Depends on:** —

---

## Task 3 — Schema, migration and scope resolution

**Status:** done

**Files:** `server/gaide_trace_server.py`

**Description:** Add `users.all_projects` and `user_projects` to
`_init_schema`; migration sets `all_projects = 1` for accounts that predate
the column (guarded like the v0.2→v0.3 migration). `authenticate` resolves
`scope` (`None` or list) for user tokens; keys get `None`. `/api/v1/me` and
the login response include `scope`. Docstring gains one line on scopes.

**Done when:**
- [x] Tests for AC6, AC7, AC8 pass (migration test uses a temp DB created
  with the old `users` DDL)
- [x] Rest of the suite still green

**Estimate:** ~30 min

**Depends on:** Task 2

---

## Task 4 — Scope management endpoint and users listing

**Status:** done

**Files:** `server/gaide_trace_server.py`

**Description:** `PUT /api/v1/users/<id>/scope` (admin) with body
`{"all": true}` or `{"projects": [names]}`; validates every name against
`PROJECT_NAME_RE`, rejects an admin target with 400, replaces the grant set
atomically, logs `scope <user> <- all|a,b,c by <admin>` on stderr.
`GET /api/v1/users` returns `all_projects` and `projects`; `api_create_user`
accepts the same two optional fields (default: empty list).

**Done when:**
- [x] Tests for AC1, AC2, AC4, AC5, AC19 pass
- [x] Invalid name → 400 and the previous grants are intact

**Estimate:** ~30 min

**Depends on:** Task 3

---

## Task 5 — `scope_sql` helper; sessions, session detail, transcript

**Status:** done

**Files:** `server/gaide_trace_server.py`

**Description:** `scope_sql(ident, col)` → (fragment, params) with the three
shapes from the plan, plus a unit test for each. Apply it in `api_sessions`
(both the count and the page), `api_session_detail` and `api_get_transcript`
(look the session up under the scope before reading the file). The 404 body
for a non-visible session is the existing `unknown session`.

**Done when:**
- [x] Tests for AC12, AC13, AC17, AC21 pass
- [x] The unscoped (admin / key) queries are byte-for-byte the SQL they were

**Estimate:** ~30 min

**Depends on:** Task 3

---

## Task 6 — Overview and models under scope

**Status:** done

**Files:** `server/gaide_trace_server.py`

**Description:** Apply the scope in `_filters` (events), the sessions-table
block of `api_overview`, `_overview_models` (via `s.project`) and
`api_models` (join `sessions` for the scoped case only, so the admin query is
unchanged).

**Done when:**
- [x] Tests for AC11, AC15, AC20 pass
- [x] `test_model_usage_api.py` still green (admin path untouched)

**Estimate:** ~30 min

**Depends on:** Task 5

---

## Task 7 — Export under scope

**Status:** done

**Files:** `server/gaide_trace_server.py`

**Description:** `api_export` applies the scope to the events query for jsonl
and csv, regardless of `project`, `session`, `origin` filters.

**Done when:**
- [x] Tests for AC14 pass (no filter; `project=research`; `session=<research id>`)

**Estimate:** ~15 min

**Depends on:** Task 5

---

## Task 8 — Projects list, manage, rotate, auto-grant on register

**Status:** done

**Files:** `server/gaide_trace_server.py`

**Description:** `GET /api/v1/projects` and `api_projects_manage` return only
granted entries; `api_rotate_project` answers `unknown project` outside the
scope; `api_create_project` inserts a grant for a scoped creator inside the
same transaction, and never on the 409 path.

**Done when:**
- [x] Tests for AC9, AC10, AC16 pass
- [x] Registering an existing name as a scoped member → 409, no grant

**Estimate:** ~30 min

**Depends on:** Task 4

---

## Task 9 — Suite green, bring-up clean

**Status:** done

**Files:** —

**Description:** Whole suite via `./init.sh`; fix anything the new tests
surface in older paths. Review the diff of commit 2 for an unscoped read
path left behind (`grep -n "FROM sessions\|FROM events" server/gaide_trace_server.py`
against the list in the plan).

**Done when:**
- [x] `./init.sh` exits 0
- [x] Every read query in the list in `plan.md` applies `scope_sql`

**Estimate:** ~20 min

**Depends on:** Tasks 3–8

---

## Task 10 — Console: Users page scope editor and key note

**Status:** done

**Files:** `server/webui/app.js`, `server/webui/style.css` (if needed)

**Description:** In the create form and in each non-admin row: an *all
projects* switch and a checklist built from the union of
`GET /api/v1/projects` and `GET /api/v1/projects/manage` names, with a free
text field for a name not yet seen (validated like registration). Saves via
`PUT /api/v1/users/<id>/scope`; row shows "all projects" or the names. Note
on the Users and API keys pages: API keys are not scoped.

**Done when:**
- [x] AC22 and AC24 exercised in a browser as admin: edit, save, reload,
  values persist
- [x] Admin rows show "all projects" with no editor

**Estimate:** ~40 min

**Depends on:** Task 9

---

## Task 11 — Console: subset notice and empty state

**Status:** done

**Files:** `server/webui/app.js`, `server/webui/index.html`, `server/webui/style.css`

**Description:** `enterShell` reads `me.scope`; a list shows a persistent
topbar note ("you see N of the team's projects"); an empty list makes every
view render "an admin has not granted you any project yet" instead of empty
tables and charts.

**Done when:**
- [x] AC23 exercised in a browser as `two` and as `none`
- [x] Admins and *all projects* members see no notice

**Estimate:** ~30 min

**Depends on:** Task 9

---

## Task 12 — Documentation

**Status:** done

**Files:** `docs/SERVER.md`, `PROGRESS.md`

**Description:** Roles table gains the scope column; new "Who sees what"
section (defaults for new and upgraded accounts, unassigned data, API-key
exception); endpoint table gains `PUT /api/v1/users/<id>/scope` and the new
fields on `/users`, `/me`, `/auth/login`. Session log entry.

**Done when:**
- [x] AC25 satisfied; a reader can set up a scoped member from the doc alone

**Estimate:** ~20 min

**Depends on:** Task 8

---

## Task 13 — Verification and reviews

**Status:** done

**Files:** `specs/project-access/tasks.md` (statuses only)

**Description:** `verifier` skill against a local server for AC22–AC24 and
the sprint contract; `security-reviewer` on the full diff (mandatory for
auth); `code-reviewer`. Findings go back to the task they belong to.

**Done when:**
- [x] Every sprint-contract item checked (by the implementer, 2026-10-13: tests,
  curl against a seeded local server, console in the browser as admin, `mia`
  and `nobody`; a real v0.5.0 store upgraded in place) — the independent pass
  by the `verifier` skill is still owed before `verified`
- [x] Security review has no open finding (blocker on self-registration fixed and re-checked)
- [x] Traceability table below moved to `verified` for AC1–AC25 (independent verifier pass, 2026-10-13)

**Estimate:** ~40 min

**Depends on:** Tasks 10, 11, 12

---

## Traceability

| Spec criterion | Task(s) | Status |
| --- | --- | --- |
| AC1, AC2, AC4, AC5 | Task 2, Task 4 | verified |
| AC3 | Task 10 | verified |
| AC6, AC7, AC8 | Task 2, Task 3 | verified |
| AC9, AC10, AC16 | Task 2, Task 8 | verified |
| AC11, AC15, AC20 | Task 2, Task 6 | verified |
| AC12, AC13, AC17, AC21 | Task 2, Task 5 | verified |
| AC14 | Task 2, Task 7 | verified |
| AC18 | Task 2, Task 5, Task 6 | verified |
| AC19 | Task 2, Task 4 | verified |
| AC22, AC24 | Task 10 | verified |
| AC23 | Task 11 | verified |
| AC25 | Task 12 | verified |

> Update status as tasks progress, using the same lifecycle (`pending | in-progress | done | verified`). A criterion is `verified` only when exercised against the running application, not just by green unit tests.
