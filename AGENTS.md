# Project Briefing

> **How to use this file:** this is the canonical briefing for **any** coding agent working on this repository — Claude Code, Google Antigravity, Cursor, Codex, Zed, Copilot, Gemini CLI, or a human. Tools that read `AGENTS.md` load it natively; Claude Code loads it via `.claude/CLAUDE.md`; Antigravity via `.agents/rules/`.

---

## Overview

**Project name:** GAIDE-Trace

**One-line description:** a research-grade, LLM- and IDE-agnostic interaction ledger that records what actually happened in AI-assisted development sessions (prompts, tool calls, turns, transcripts), with an optional team server.

**Current status:** in development (v0.7.0) — capture adapters for Claude Code and the Antigravity IDE, optional team server with web console (per-model usage and cost estimates, list prices loadable from benchlm.ai, per-account project access, security analysis of the ledger).

**Relationship to [GAIDE](https://github.com/jcarlos78/GAIDE):** GAIDE governs *how* AI-assisted development happens; GAIDE-Trace records *what happened*. They are separate, independently adoptable projects — and this repository is itself developed under the GAIDE harness (see [ADR 0001](docs/adr/0001-adopt-gaide-harness.md)). Keep the distinction sharp when editing: GAIDE-Trace must never require GAIDE to be useful.

## Tech stack

- **Primary language:** Python 3.9+ — **standard library only** for everything on the capture and server path. A third-party import in `hooks/`, `tools/`, `server/` or `schema/` is a breaking change to the project's deployment story and needs an ADR.
- **Third-party dependencies:** `pandas`, and only in `analysis/` (the analysis toolkit is explicitly opt-in).
- **Framework:** none. The server is `http.server` + `sqlite3`; the web console is vanilla HTML/CSS/JS with no build step and no CDN.
- **Storage:** JSONL is the source of truth (local store and server archive); SQLite is a rebuildable index (`rebuild-index`), never the truth.
- **Deployment:** the server runs anywhere Python does — container image in `deploy/` (Docker Compose + Caddy for TLS), bare VPS with systemd + Caddy, or the Terraform reference deployment for AWS in `deploy/aws/`. See `docs/SERVER.md`.

## Relevant folder structure

```text
.
├── AGENTS.md               This file — canonical agent briefing
├── agents/                 Portable agent procedures (single source)
│   ├── skills/             Skills: spec writing, review, ADRs, tests, verification
│   └── reviewers/          Clean-context reviewer rubrics
├── scripts/                Portable enforcement checks (run in any tool, or by hand)
├── specs/                  SDD specs — source of truth for behavior
├── docs/adr/               Architecture Decision Records
├── PROGRESS.md             Session log — read at start, update at end
│
│   -- product code (this is what GAIDE-Trace ships) --
├── hooks/trace_hook.py     Claude Code capture adapter (real-time, via hooks)
├── tools/                  import_antigravity.py (Antigravity adapter), backfill.py
├── schema/event.schema.json  Canonical event vocabulary — the contract every adapter meets
├── server/                 Optional team server (stdlib HTTP + SQLite) + webui/ console
├── analysis/               pandas loaders for the captured store
├── install.sh / uninstall.sh  Connect (or disconnect) a target project
├── config/, deploy/        OTEL example env, container/systemd/Caddy deployment
│   └── aws/                Terraform reference deployment (EC2 + EBS + Caddy + S3)
└── docs/                   ARCHITECTURE.md (design decisions D1–D8), ADAPTERS.md, SERVER.md
```

**Do not confuse the two `hooks` layers.** `hooks/trace_hook.py` is *product code* — the Claude Code capture adapter this project ships. `.claude/hooks/` is *governance binding* — thin adapters that run the `scripts/` enforcement checks on this repository's own edits. Editing one never means editing the other.

Tool-specific bindings (generated from the portable sources by `scripts/sync-adapters.sh` — never edit them directly): `.claude/` for Claude Code, `.agents/` for Antigravity.

## Session protocol

- **At session start:** run `./init.sh` (syntax check, test suite, live server health check — a failure means inherited broken state), then read `PROGRESS.md` and the recent `git log` to understand where the last session left off. If the previous session left something broken, fix that before starting new work. `PROGRESS.md` is local and gitignored — if it doesn't exist yet, create it (title + dated entries with done / next / known issues, newest first).
- **At session end:** append an entry to `PROGRESS.md` (done / next / known issues).

## Mandatory operating principles

Before any code change, the agent MUST:

1. **Read the constitution** at `specs/constitution.md`.
2. **Check whether a spec exists** for the feature at `specs/<feature>/spec.md`.
3. **If no spec exists**, propose writing one using the `spec-writer` skill before coding.
4. **Follow the SDD flow**: spec → plan → tasks → implementation.
5. **Never edit tests or task lists to make work appear done** (Constitution Principle 9).

Pre-GAIDE code (everything committed before ADR 0001) has no spec. That is a known debt, not a licence: the first behavioral change to a component writes the spec for the behavior it touches.

## Project-specific invariants

These come from `docs/ARCHITECTURE.md` (design decisions D1–D8) and are load-bearing. Breaking one is an ADR-level decision, not an implementation detail:

- **D4 — capture never breaks the session.** `trace_hook.py` always exits 0, writes nothing to stdout (stdout from some hook events is injected into model context), and swallows every internal error. A logging bug may cost data; it may never cost a working session.
- **D5 — redact at capture, not at analysis.** Secrets are redacted before anything reaches disk in the event layer. Transcript snapshots are raw by design — say so, don't silently change it.
- **D6 — local-first shipping.** The local store is written *before* any network I/O, unconditionally. The server is an additional destination, never a dependency. Delivery is at-least-once via the file-per-record outbox; the server dedupes by `trace_id`, so retries must stay safe by construction.
- **D7 — JSONL is the truth.** The SQLite index must remain fully rebuildable from the JSONL archive.
- **Canonical vocabulary.** Every adapter emits the tool-neutral event names in `schema/event.schema.json` and preserves `source`, `native_event` and `model`. Adding a tool means adding an adapter, never widening the vocabulary for one tool's convenience (see `docs/ADAPTERS.md`).
- **Opt-in by default.** Installing writes to `.claude/settings.local.json` (personal); `--project` is the explicit shared choice. The store stays gitignored in the target repo.
- **Stdlib only on the capture and server path** (see Tech stack).

Changes to the event schema are backward-compatible or they come with a migration path for stores already in the field, and with an ADR either way — captured data outlives every version of this code.

## Enforcement checks

The checks in `scripts/` are the portable enforcement layer. In Claude Code they fire automatically as hooks; **in every other tool, run them yourself**:

- `scripts/check-file.sh <file>` — syntax check after editing a file
- `scripts/check-security.sh <file>` — SAST (semgrep) / dependency scan (osv-scanner) on an edited file
- `scripts/check-secrets.sh` — secret-pattern scan of content on stdin
- `scripts/check-clean-state.sh` — before ending a session with uncommitted changes: secrets (gitleaks) + test suite

Whatever the tool, the guaranteed floor is the same for everyone: pre-commit (`.pre-commit-config.yaml`) and CI (`.github/workflows/security.yml`).

## Ground rules (enforced as deny-permissions where the tool supports it)

- Never read `.env` files, private keys (`*.pem`, `*.key`, `id_rsa*`), or credential stores (`~/.ssh`, `~/.aws`, `~/.config/gcloud`).
- Never run `git push --force`, `git reset --hard`, or pipe downloads into a shell.
- Secrets never enter versioned files, even as examples (Constitution Principle 6).
- **Captured traces are research data, not test fixtures.** Never commit anything from a `.gaide-trace/` store, `data/`, or a server archive — real sessions carry prompts, file contents and third-party personal data. Fixtures are synthesized, never harvested.

## Code conventions

- Python: standard library idioms, `pathlib`, explicit `utf-8`; keep modules single-file and dependency-free so a hook can be copied into a target project as-is.
- Shell: `bash`, `set -euo pipefail`, POSIX-portable where practical (`install.sh` runs on contributors' machines).
- Comments explain *why*, not *what* (Principle 4). The existing modules document design rationale at the top of the file — keep that convention.
- Commit messages: imperative summary line describing the behavior change, body explaining the why.
- Docs (README, `docs/`, specs, ADRs) in English; conversation with the maintainer may be in Portuguese.

## Critical integrations

- **Claude Code hooks** — the real-time capture mechanism (`SessionStart`, `UserPromptSubmit`, `PostToolUse`, `Stop`, `SessionEnd`, …). Its payload shape is an external contract this project does not control; treat unknown fields defensively.
- **Antigravity IDE local databases** — read-only, incremental import (`tools/import_antigravity.py`). An undocumented, version-dependent format: parse defensively, never write.
- **GAIDE-Trace team server HTTP API** — `docs/SERVER.md`; hooks are `agent`-role clients of it.

MCP servers are declared in `.mcp.json` (canonical reference). See `docs/mcp-setup.md` for connecting them in each tool. Only `playwright` is relevant here — the `verifier` skill uses it to exercise the server's web console end-to-end.

## How the agent should work

- **Current autonomy mode:** HIC (every code change requires explicit human approval before commit).
- **Change size:** prefer small, atomic changes. No sweeping refactors without an ADR.
- **Comments:** only when the *why* is not obvious from the code.
- **Tests:** changing code that affects behavior without changing/adding tests is forbidden. The suite lives in `tests/` (stdlib `unittest` style, no third-party fixtures) and runs with `pytest -q` or `python3 -m unittest discover -s tests`; `./init.sh` uses whichever is available.
- **Verification:** for anything touching the web console or the ingest path, "tests pass" is not "it works" — use the `verifier` skill against a locally running server before a criterion reaches `verified`.
- **Logging:** the capture path never logs to stdout (D4). Server-side operational errors fail visibly (Principle 8) via the server's own logging.

## Available skills

Source of truth in `agents/skills/` (Claude Code exposes them as `/name` via `.claude/skills/`; Antigravity as `/name` workflows via `.agents/workflows/` — both generated):

- `spec-writer` — write SDD specs
- `code-reviewer` — review the current diff in a clean context (rubric in `agents/reviewers/code-reviewer.md`; never pass the reviewer the implementation conversation)
- `security-reviewer` — security review of the current diff (rubric in `agents/reviewers/security-reviewer.md`); mandatory for anything touching the server's auth, key management, ingest endpoints, or redaction
- `verifier` — exercise a feature end-to-end against the spec's criteria; the only path to `verified` status
- `adr-writer` — record architectural decisions
- `test-generator` — generate tests from a spec

## Contacts and governance

- **Maintainer:** José Menezes (<jcarlos78@gmail.com>) — sole maintainer; constitution changes need his approval.
- **Review channel:** GitHub pull requests on `jcarlos78/GAIDE-Trace`.
- **Human-response SLA:** best-effort — this is a research project, not a staffed product.
- **Research context:** developed to support a master's research program on AI-assisted software engineering. Data-handling changes carry ethics weight (see the Privacy & ethics section of the README).
