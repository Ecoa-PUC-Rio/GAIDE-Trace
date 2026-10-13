# GAIDE-Trace Server — team deployment guide

The server turns GAIDE-Trace from a per-machine store into a **team-central
interaction ledger**: every member's hooks keep writing locally first (nothing
is ever lost to a network problem), and additionally ship each record to one
central server that offers:

- **Durability** — events land in a raw JSONL archive *and* a SQLite index;
  the index is always rebuildable from the archive.
- **A web console** — dashboard, per-session timelines, transcript downloads,
  filtered exports (JSONL/CSV), API key management.
- **Team identity** — each record is tagged with the key that shipped it, so
  activity is attributable per member and per project.

Everything is Python standard library. There is **nothing to `pip install`**
on the server — if the machine has Python 3.9+, it can run the server.

```
developer machines                         your server
┌────────────────────────┐                ┌─────────────────────────────┐
│ Claude Code session    │                │ gaide_trace_server.py       │
│  └─ hooks/trace_hook   │   HTTPS        │  ├─ data/archive/  (JSONL)  │
│      1. local store ✓  │ ─────────────▶ │  ├─ data/transcripts/       │
│      2. outbox → ship  │  retry-safe    │  ├─ data/trace.db  (index)  │
│         (at-least-once)│                │  └─ web console  :8321      │
└────────────────────────┘                └─────────────────────────────┘
```

## 1. Quick start (any machine, 60 seconds)

```bash
git clone https://github.com/jcarlos78/GAIDE-Trace
cd GAIDE-Trace
python3 server/gaide_trace_server.py serve
```

Open `http://localhost:8321/` and sign in with the default account
**`admin` / `admin`** — the console forces you to set a new password before
anything else works. From there, everything is managed visually:

- **Users** — create accounts for the team (each gets a temporary password,
  shown once, that must be changed on first login), choose which projects each
  account may see (§1.1), reset passwords, disable.
- **Projects** — register a project; the server generates an ingest-only key
  and a ready-to-paste **install prompt** (see §2).
- **API keys** — advanced: raw bearer keys for scripts/CI.
- **Model prices** — per-model USD prices behind the console's cost estimates,
  set by hand or loaded from benchlm.ai after review (see §7).

Locked out? Reset any account from the server shell:

```bash
python3 server/gaide_trace_server.py user reset admin   # prints a temp password
python3 server/gaide_trace_server.py user list
```

Two kinds of credentials:

| Credential | Who uses it | Can | Sees |
|---|---|---|---|
| username + password | humans, in the console | member: browse + export + register projects · admin: + users, keys, removals | member: the projects granted to the account (§1.1) · admin: everything |
| `agent` API key | hooks / install prompts | ingest only — leaked, it can add data but never read | nothing |
| `member`/`admin` API key | scripts, CI | scripted API access (create via **API keys** or `key create`) | everything — keys are not scoped |

### 1.1 Who sees what — project access per account

Every console account has a **project scope**: either *all projects*, or an
explicit list of project names. Admins always see everything. A member with a
list sees only sessions, transcripts, aggregates, exports, registered
projects and install prompts of the projects on that list — the server
applies the scope to every read, so it holds for `curl` as much as for the
console. Data outside the scope is simply absent: a session id from another
project answers "unknown session", and a project the member may not see
filters like a project with no data.

- **Granting:** on **Users**, click *access* on a member row, tick projects
  (registered ones and any name seen in the data are offered; type a name to
  grant it before its first session arrives), or switch on *all projects*.
  Changes apply on the member's next request, with no new login.
- **Defaults:** accounts created before this feature keep *all projects*
  (upgrading never takes access away). Accounts created from now on start
  with **no projects** until an admin grants some — the create form has the
  same control, so you can set it up in one step.
- **Registering a project** adds it to the registering member's own list.
  A member with a list cannot register a name that already carries data
  (409), so registration never hands out access to existing sessions.
- **Sessions without a project name** are visible only to *all projects*
  accounts.
- **API keys are not scoped.** A `member` or `admin` key reads every project,
  whoever holds it — issue them knowingly. `agent` keys cannot read at all.
- Every scope change is written to the server log with who changed whose
  scope to what.

Decision record: [ADR 0002](adr/0002-project-scope-on-accounts.md).

## 2. Connect a project

The easy path: open **Projects** in the console, register the project, click
**install prompt** and send the text to whoever works on that repo. They paste
it into Claude Code at the project root and the agent does the rest — clones
this repo, runs `install.sh` with the right `--server`/`--token`/`--name`, and
backfills any pre-existing local history. The key embedded in the prompt is
ingest-only and can be rotated from the same page at any time.

Manual equivalent:

```bash
./install.sh /path/to/your-project \
  --server https://trace.example.com --token gtr_... [--name my-project]
```

This registers the hooks as before **and** writes the connection to
`<project>/.gaide-trace/config.json` (mode 600, inside the gitignored store —
the token never enters the code repo). Environment variables
`GAIDE_TRACE_SERVER` / `GAIDE_TRACE_TOKEN` / `GAIDE_TRACE_PROJECT` override it.

### No-data-loss model

1. Every event is appended to the **local store first**, unconditionally.
2. It is then queued in `.gaide-trace/outbox/` and shipped in batches.
3. If the server is down or you are offline, the outbox simply accumulates
   and is flushed by later hook fires — delivery is **at-least-once**, and the
   server dedupes by `trace_id`, so retries are always safe.
4. Transcript snapshots are uploaded (gzipped) at every `Stop`/`SessionEnd`;
   each upload supersedes the previous one, same as the local semantics.

### Backfill history

Adopted the server after weeks of local tracing? Push the whole store:

```bash
python3 tools/backfill.py /path/to/your-project/.gaide-trace
# (uses config.json; or pass --server/--token explicitly)
```

Idempotent — run it as often as you like.

## 3. Deploy on a VPS (systemd, no container)

Requirements: a Linux VPS with Python 3.9+ and a DNS record pointing at it.

```bash
# as root
useradd --system --create-home --home-dir /var/lib/gaide-trace gaide-trace
git clone https://github.com/jcarlos78/GAIDE-Trace /opt/gaide-trace
cp /opt/gaide-trace/deploy/gaide-trace-server.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now gaide-trace-server

# the one-time admin key is in the journal:
journalctl -u gaide-trace-server | grep gtr_
```

The unit binds to `127.0.0.1:8321` and is sandboxed (`ProtectSystem=strict`,
only its data dir writable). Put **Caddy** in front for automatic HTTPS:

```bash
apt install caddy                          # Debian/Ubuntu
cp /opt/gaide-trace/deploy/Caddyfile.example /etc/caddy/Caddyfile
# edit the domain, then:
systemctl reload caddy
```

Done: `https://trace.example.com` serves the console and the ingest API with
a Let's Encrypt certificate that renews itself. (nginx + certbot works the
same way — proxy to `127.0.0.1:8321`.)

Updating:

```bash
cd /opt/gaide-trace && git pull && systemctl restart gaide-trace-server
```

## 4. Deploy as a container

```bash
git clone https://github.com/jcarlos78/GAIDE-Trace && cd GAIDE-Trace

# plain, on localhost:8321 (LAN / behind your own proxy):
docker compose -f deploy/docker-compose.yml up -d

# or with automatic TLS via the bundled Caddy service:
TRACE_DOMAIN=trace.example.com \
  docker compose -f deploy/docker-compose.yml --profile tls up -d

docker compose -f deploy/docker-compose.yml logs server | grep gtr_   # admin key
```

Data lives in the `trace-data` named volume. The image is `python:3.12-slim`
plus the repo's `server/` directory — no dependencies to patch.

Kubernetes or any other orchestrator: run the same image with `/data` on a
persistent volume and one replica (SQLite is single-writer by design at this
scale).

## 5. Deploy on AWS (Terraform)

`deploy/aws/` provisions the §3 layout on AWS as code: one Graviton EC2
instance, the archive on a dedicated EBS volume that instance rebuilds never
touch, Caddy for TLS, and a nightly sync of the JSONL truth layer to a
versioned S3 bucket.

```bash
cd deploy/aws
cp terraform.tfvars.example terraform.tfvars   # set domain and region
terraform init && terraform apply
```

Point your A record at the `public_ip` output (or set `route53_zone_id` and let
Terraform own the record), then sign in at `https://<domain>/` as `admin` /
`admin` — and change that password immediately, because the console is public
the moment DNS resolves.

Shell access is through SSM Session Manager, so no port 22 is open by default.
Roughly US$ 20/month on-demand; see `deploy/aws/README.md` for the cost
breakdown, upgrades, restore procedure and teardown.

Serverless is deliberately not offered: the truth layer is an append-only
directory plus a single-writer SQLite index (D6/D7), which needs one process
with one persistent local disk.

## 6. Backups

The entire state is one directory (`data/`, or the `trace-data` volume):

- `archive/events/*.jsonl` — source of truth for the event layer
- `transcripts/*.jsonl` — full-fidelity transcript snapshots
- `trace.db` — derived index (rebuildable: `gaide_trace_server.py rebuild-index`)

Because the truth layer is append-only plain files, any file-level backup
works and stays consistent:

```bash
# example: nightly rsync
rsync -a /var/lib/gaide-trace/data/ backup-host:/backups/gaide-trace/
```

If `trace.db` is ever lost or corrupted, `rebuild-index` reconstructs it from
the JSONL archive.

**Upgrades re-derive the index on their own.** When a release changes how
index data is derived (from the stored transcripts and the indexed events),
the server re-derives existing data on its first start, before it accepts
connections, and logs one line (`derived-index schema N -> M: ...`, plus progress lines on long runs;
a 50 MB transcript takes well under a second). The archive
and transcript files are never modified; no manual `rebuild-index` is needed.
A session whose stored data cannot be derived is logged by id
(`re-deriving index: skipped session ...`) and skipped, followed by a
`WARNING: N sessions could not be re-derived` line — the server still starts.
Such a session re-derives on its next transcript upload or `rebuild-index`.

Ingest tolerates hostile or malformed input without losing the rest of a
batch: unparseable request bodies get a 400, transcript lines that cannot be
parsed are skipped, out-of-range timestamps are indexed without a time, and
non-text field values in an event are stored as JSON text.

**Token totals drop after upgrading past v0.3.1 — that is a correction.**
Claude Code writes each assistant message to its transcript as one line per
content block, repeating the same usage on every line. Up to v0.3.1 the server
summed every line, inflating session and overview token totals for Claude Code
sessions (by roughly 2–3× on real data). The server now counts each message
once (by its `message.id`) and ignores Claude Code's `<synthetic>` placeholder
messages. Token figures exported or quoted from earlier versions were
inflated.

## 7. API (for your own tooling)

**Upgrading from v0.2:** event names are now the canonical tool-agnostic
vocabulary (see `docs/ADAPTERS.md`); legacy Claude-shaped names are
normalized automatically at ingest, and one `python3
server/gaide_trace_server.py rebuild-index` after upgrading normalizes the
rows indexed before v0.3 (the JSONL archive itself is never rewritten).

All endpoints under `/api/v1/`, auth via `Authorization: Bearer <token>` —
either an API key (`gtr_...`) or a console session (`gts_...`, obtained from
the login endpoint).

| Method & path | Role | Purpose |
|---|---|---|
| `POST /api/v1/auth/login` | — | `{username, password}` → session token (+ `must_change_password`, `scope`) |
| `GET /api/v1/me` | agent | who am I: `name`, `role`, `kind`, `scope` (`null` = every project, else the granted names) |
| `POST /api/v1/auth/password` | member | change own password (required on first login) |
| `POST /api/v1/auth/logout` | member | revoke the session |
| `POST /api/v1/events` | agent | ingest a JSON array of event records (idempotent by `trace_id`; gzip body supported) |
| `PUT /api/v1/transcripts/<session_id>?project=` | agent | store/replace a transcript snapshot (gzip supported) |
| `GET /api/v1/overview?project&from&to` | member | within the caller's scope (§1.1), like every read below — aggregates: totals, per-day series, top tools, per-project/member, and `models` (see below) |
| `GET /api/v1/sessions?project&origin&model&from&to&q&limit&offset` | member | session list; each row carries `dominant_model` and `model_count`; `model` keeps sessions where that model has at least one turn |
| `GET /api/v1/sessions/<id>` | member | session meta + full event timeline + `models` (per-model rows) and `models_total` |
| `GET /api/v1/models` | member | `{models, omitted}`: the 500 most-used models seen (turns, sessions, last use) plus every priced model, each with its `price` or `null`; `omitted` counts seen models beyond the 500 |
| `PUT /api/v1/models/prices` | admin | set a price: `{model, input, output, cache_read, cache_write_5m, cache_write_1h}` in USD per million tokens, each 0–10000 |
| `DELETE /api/v1/models/prices?model=` | admin | clear a model's price |
| `GET /api/v1/sessions/<id>/transcript` | member | raw transcript download |
| `GET /api/v1/export?format=jsonl\|csv&project&session&origin&event&from&to` | member | filtered event export |
| `GET /api/v1/projects/manage`, `POST /api/v1/projects`, `POST .../<id>/rotate` | member | registered projects + install-prompt keys |
| `DELETE /api/v1/projects/<id>` | admin | remove registration (data kept) |
| `GET/POST /api/v1/users`, `POST .../<id>/reset`, `DELETE .../<id>` | admin | console accounts; each row carries `all_projects` and `projects`; create accepts `{"all": true}` or `{"projects": [...]}` (default: none) |
| `PUT /api/v1/users/<id>/scope` | admin | set a member's project scope: `{"all": true}` or `{"projects": ["app", "api"]}` (names: letters, digits, `.` `_` `-`, max 64, at most 200; duplicates collapse; `all` wins over `projects`); refused for admins |
| `GET/POST /api/v1/keys`, `DELETE /api/v1/keys/<id>` | admin | raw API-key management |
| `GET /healthz` | — | liveness |

The export format is the same schema as the local store
(`schema/event.schema.json`) plus `origin` (key name) and `received_at` —
`analysis/load_trace.py` loads server exports unchanged.

### Model usage and cost estimates

The server attributes every **model turn** to the model that produced it:

- **Claude Code** — one distinct assistant message in the transcript snapshot
  (by `message.id`). Hook events carry no model, so a Claude Code session has
  model data once its transcript has been uploaded.
- **Antigravity** (and any adapter emitting it) — one `model.turn` event with
  a `model`. These sources record no token usage: tokens and cost are
  reported as unknown (`null`), never as zero.

A session's turns come from its transcript when that yields any, otherwise
from its `model.turn` events — never both. Claude Code's `<synthetic>`
placeholder is never counted as a model. Model names are truncated to 128
characters.

Per-model rows (`models` on a session, `models.rows` on the overview) carry
`turns`, `turns_without_tokens`, `input_tokens`, `output_tokens`,
`cache_read_tokens`, `cache_write_5m_tokens`, `cache_write_1h_tokens`,
`premium_turns`, `cost` and `cost_status`; overview rows add `sessions` and
`share` of turns. Totals add `cost_total`, `unpriced_models`,
`no_token_models`, `premium_turns` and `premium_priced_turns`. The overview
window applies to each turn's own timestamp, so a session crossing the window
edge contributes only its turns inside it. `models.per_day` gives turns per
UTC day for the view's top four models (named in `models.series`), with every
other model folded into `model: null`.

Per-model listings are capped at the 500 most-used models — `models.rows` on
the overview, `models` on a session — with the rest counted in
`models_omitted`; totals, shares and cost always cover every model. The cap
keeps a flood of distinct model names from an ingest key out of members'
browsers. Token sums are computed in floating point, so they cannot overflow
however large the ingested counts; a single turn's count above 10¹² is treated
as invalid and counted as 0.

**Cost is an estimate, not billing data.** Admins maintain a price per model on
the console's **Model prices** page; the server never fetches prices from a
provider. Cost = Σ tokens of each type × that type's price ÷ 1,000,000, at the
prices current when you look (no price history), returned unrounded.

- `cost_status: "unpriced"` — no price entry: `cost` is `null` and the model is
  excluded from `cost_total`, never guessed.
- `cost_status: "no_tokens"` — the source records no usage (e.g. Antigravity).
- Turns whose usage reports a non-standard `speed` (fast mode) are priced at
  standard rates; `premium_priced_turns` > 0 means the total is a lower bound.
- Cache writes without a 5-minute / 1-hour breakdown are priced at the
  5-minute rate.

Prices are configuration, like users and keys: `rebuild-index` keeps them.

**Loading list prices from benchlm.ai.** On the Model prices page, **Load
prices from benchlm.ai** fetches benchlm.ai's public pricing feed
(`https://benchlm.ai/api/data/pricing`) *from the admin's browser* — the server
makes no outbound request, and the request carries no cookies, referrer or
GAIDE-Trace data. benchlm.ai does see the admin's IP address and, through the
`Origin` header every cross-origin request carries, the console's host name. Nothing changes until
the admin ticks models in the preview and applies them; each is then saved
through `PUT /api/v1/models/prices` like a hand edit, with the admin as author.

- Models are matched by normalized name (lowercase, punctuation runs → `-`,
  trailing `-YYYYMMDD` dropped), so `Claude Opus 5` matches `claude-opus-5`.
  Only exact, unique matches are importable; others show *no match*,
  *ambiguous* or *not priced in feed* and stay hand-priced.
- The feed has **input and output prices only**. Applying keeps a model's
  current cache prices; a model with no price yet needs its three cache prices
  typed in before it can be applied. Nothing fills them in.
- Open-weight models listed at `0` are treated as unpriced, not free.
- A blocked or failing fetch (offline, a proxy, a content-security policy,
  CORS, a 15-second timeout, a malformed or oversized feed) shows an error and
  changes nothing; hand pricing is unaffected.

## 8. Security notes

- **Always front with TLS** for anything beyond localhost — passwords and
  tokens travel as bearer credentials.
- Passwords are stored as PBKDF2-SHA256 (600k iterations); logins throttle
  after 5 straight failures. A password change revokes every open session of
  that account.
- API keys are stored only as SHA-256 hashes; a lost key is revoked, never
  recovered. Exception: a *registered project's* agent key is kept readable
  server-side so the install prompt can be re-copied and rotated from the
  console — an accepted tradeoff because those keys are ingest-only (they can
  add data, never read it).
- Give hooks `agent` keys where possible: an exfiltrated agent key can only
  *add* data, never read it.
- The event layer is redacted at capture (see `docs/ARCHITECTURE.md` D5);
  transcript snapshots are raw by design — treat the server's data directory
  with the same care as the code it describes, and apply your institution's
  ethics/consent requirements before sharing datasets.
