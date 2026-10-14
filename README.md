# GAIDE-Trace

**A research-grade interaction ledger for AI-assisted development.**

GAIDE-Trace captures a complete, analyzable history of every interaction
between a developer and an AI coding agent in a project: prompts, model
responses, tool calls, subagent activity, and full session transcripts —
stored as plain JSONL you can version, query and mine.

It is **LLM- and IDE-agnostic by design**: every record uses one canonical,
tool-neutral event vocabulary (with the source tool and model preserved per
record), so sessions from different agents land in the same store, the same
server, and the same analyses. Capture adapters exist for **Claude Code**
(real-time, via hooks) and the **Antigravity IDE** (incremental importer of
its local session databases); adding a tool means writing one adapter — see
[`docs/ADAPTERS.md`](docs/ADAPTERS.md).

For teams, an optional **zero-dependency server** centralizes every member's
traces into one durable ledger with a web console (dashboard, session
timelines, exports, key management) — see
[Team server](#team-server-optional).

It is a **standalone, opt-in companion** to [GAIDE](https://github.com/jcarlos78/GAIDE)
(Governed AI Development Environment). You can connect it to a GAIDE project,
to any other project, or not at all — the choice belongs to each user, per
project.

GAIDE-Trace is also **developed under GAIDE itself** — see
[How this project is developed](#how-this-project-is-developed).

## Why

Governance needs evidence. GAIDE enforces *how* AI-assisted development should
happen; GAIDE-Trace records *what actually happened*, so you can audit
sessions, study human–AI collaboration patterns, and support empirical
research (this project was born to support a master's research program on
AI-assisted software engineering).

## How it works

Each supported tool has a small, self-contained **adapter** that translates
that tool's native record of a session into the canonical event vocabulary
(`session.start`, `prompt.submit`, `tool.call`, `tool.fail`, `model.turn`,
`turn.end`, `agent.start/end`, `context.compact`, `session.end`) and appends
it to the project's local store:

```
your-project/
└── .gaide-trace/
    ├── events/       # one JSONL per session: prompts, tool calls, turn ends
    └── transcripts/  # full-fidelity transcript snapshots, where the tool
                      # provides one (messages, tool I/O, per-turn tokens)
```

| Tool | Adapter | Mechanism |
|---|---|---|
| Claude Code | `hooks/trace_hook.py` | native hooks — real-time, deterministic ("instructions degrade, mechanisms don't") |
| Antigravity IDE | `tools/import_antigravity.py` | incremental importer of Antigravity's local conversation databases (it has no hook system) |
| anything else | yours | one file; see [`docs/ADAPTERS.md`](docs/ADAPTERS.md) |

Every record carries `source` (which adapter), `native_event` (the tool's own
event name) and, when known, `model` — so cross-tool and cross-LLM comparisons
are a `groupby`, not a data-cleaning project.

Two layers, two purposes:

| Layer | Source | Best for |
|---|---|---|
| `events/` | adapters (this project) | timeline analysis, tool-usage patterns, prompt taxonomy |
| `transcripts/` | the tool's own transcript, snapshotted | full conversation reconstruction, token accounting per turn |

Optionally, enable Claude Code's native **OpenTelemetry** export for
quantitative metrics (cost, latency, tokens per request) — see
`config/otel.env.example`.

## Install (connect to a project)

**Claude Code** (registers the hooks):

```bash
git clone https://github.com/jcarlos78/GAIDE-Trace
cd GAIDE-Trace
./install.sh /path/to/your-project          # personal opt-in (settings.local.json)
./install.sh /path/to/your-project --project # shared: every contributor traces
```

**Antigravity IDE** (imports its local session databases into the same store):

```bash
python3 tools/import_antigravity.py --workspace /path/to/your-project
python3 tools/import_antigravity.py --watch 60   # or keep it running
```

By default the importer only touches projects that already have a
`.gaide-trace/` store (i.e. that opted in); `--create-store` widens that.
Import is incremental and idempotent — re-running never duplicates records.

Requirements: Python 3.9+ on PATH. No third-party dependencies for capture;
`pandas` only for the analysis toolkit.

Disconnect anytime (data is preserved):

```bash
./uninstall.sh /path/to/your-project
# or temporarily: export GAIDE_TRACE_DISABLE=1
```

## Team server (optional)

For a team, run the central ledger server — Python stdlib only, nothing to
install — and connect each project to it:

```bash
# on your server (VPS or container — see docs/SERVER.md for TLS & systemd):
python3 server/gaide_trace_server.py serve
# then sign in at http://<server>:8321/ with admin/admin
# (a new password is required on first login)
```

Everything else is visual: create team accounts on the **Users** page,
register a project on the **Projects** page, and click **install prompt** —
the console generates a copy-paste prompt that any team member gives to
Claude Code, which clones this repo and connects their project automatically.
The manual equivalent still works:

```bash
./install.sh /path/to/your-project --server https://trace.example.com --token gtr_...
python3 tools/backfill.py /path/to/your-project/.gaide-trace   # pre-existing history
```

Capture stays **local-first**: every event is written to the project's local
store before any network I/O, then shipped through an offline-safe outbox
(at-least-once, deduped server-side) — a down server can never lose data.
The server keeps a raw JSONL archive as the source of truth plus a SQLite
index, and serves a web console at `/` with a team dashboard, per-session
timelines, transcript downloads, filtered JSONL/CSV exports, a **Security**
page (what potentially confidential material the ledger holds, and which
security activity — SAST, SCA, secret scanning, IaC checks, reviews — actually
happened in the sessions that changed code), and API key management (roles:
`agent` = ingest-only for hooks, `member`, `admin`).

Deployment (container with automatic TLS, or bare VPS with systemd + Caddy),
backups and the HTTP API are documented in [`docs/SERVER.md`](docs/SERVER.md).

## Analyze

```bash
pip install pandas
python3 analysis/load_trace.py /path/to/your-project/.gaide-trace
```

Or in a notebook:

```python
from load_trace import load_events, load_transcripts
events = load_events("your-project/.gaide-trace")   # tidy DataFrame of events
turns  = load_transcripts("your-project/.gaide-trace")  # messages + token usage
```

The event schema is documented in `schema/event.schema.json`.

## Privacy & ethics

- Obvious secrets (API keys, tokens, private keys) are redacted at capture time.
- Oversized payloads are truncated in the event layer (`GAIDE_TRACE_MAX_FIELD`).
- The store is **local and gitignored by default**; publishing or versioning
  the data is an explicit decision by the researcher.
- If sessions may contain personal data of third parties, treat the store as
  research data: apply your institution's ethics/consent requirements before
  sharing.
- The team server analyses what it already stores for exposure (credentials,
  sensitive paths, personal data) so it can be found and remediated. The
  analysis records *pointers* — a rule, a location, masked evidence and a
  salted fingerprint — and never the matched value
  (see "Security analysis" in [docs/SERVER.md](docs/SERVER.md)).

## Design notes

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design:
data model, why hooks + transcript snapshots (and not a proxy), how to extend
capture to other AI tools via an LLM gateway, and the analysis roadmap.

## How this project is developed

GAIDE-Trace records governed AI-assisted development, so it is developed that
way itself: this repository runs the [GAIDE](https://github.com/jcarlos78/GAIDE)
harness ([ADR 0001](docs/adr/0001-adopt-gaide-harness.md)).

- [`AGENTS.md`](AGENTS.md) — canonical briefing for any coding agent, including
  the project invariants that are not up for negotiation (capture never breaks
  the session, redaction at capture time, local-first shipping, JSONL as the
  truth, standard library only on the capture and server path).
- [`specs/`](specs/) — constitution and spec-driven flow. Behavior is specified
  before it is coded; pre-v0.3 code carries that debt openly
  ([why nothing is back-filled](specs/README.md)).
- [`scripts/`](scripts/) — enforcement checks that run as Claude Code hooks, in
  pre-commit, and in CI: secret patterns, per-file syntax, SAST/dependency
  scans, and `check-stdlib-only.sh`, which mechanically rejects a third-party
  import on the capture or server path.
- [`./init.sh`](init.sh) — session bring-up: compile every module, check the
  invariants and the event schema, run the tests, and start a throwaway server
  to prove `/healthz` answers.

Contributing: run `./init.sh` first, read `AGENTS.md`, and keep the generated
tool bindings in sync with `scripts/sync-adapters.sh` (CI fails on drift).
Adopting the harness does **not** make GAIDE a dependency of GAIDE-Trace —
nothing shipped to a traced project references it.

## License

MIT — same as GAIDE.
