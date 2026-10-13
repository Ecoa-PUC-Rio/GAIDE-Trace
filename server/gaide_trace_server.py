#!/usr/bin/env python3
"""
GAIDE-Trace Server — team-central interaction ledger.

A single-process, zero-dependency (Python stdlib only) server that receives
trace events and transcript snapshots shipped by `hooks/trace_hook.py` from
every team member's machine, stores them durably, and serves a web console
for exploration, management and export.

Storage model (mirrors the local store's two-layer philosophy):
  data/
  ├── trace.db               SQLite index (WAL) — queries, aggregates, auth
  ├── archive/events/        raw JSONL append log, one file per session
  └── transcripts/           full-fidelity transcript snapshots (one per session)

JSONL stays the source of truth: the SQLite index can always be rebuilt from
the archive (`rebuild-index` command). Ingest is idempotent (deduped by
trace_id), so client retries are always safe.

Auth, two mechanisms:
  * People sign in to the web console with username + password. First run
    creates the default account admin/admin, which MUST change its password
    on first login. Users, projects and keys are then managed visually.
  * Machines (hooks, scripts) authenticate with bearer API keys:
      agent   ingest only (what hooks and install prompts carry)
      member  ingest + read + export (for scripted API access)
      admin   everything
    Each project registered in the console gets its own agent key, embedded
    in a copy-paste install prompt for the team.
  * Every console account has a project scope: all projects, or an explicit
    list of project names. The server applies it to every read; admins and
    member/admin keys always see everything (specs/project-access, ADR 0002).

Usage:
  python3 gaide_trace_server.py serve [--host 0.0.0.0] [--port 8321] [--data DIR]
  python3 gaide_trace_server.py key create --name alice --role member
  python3 gaide_trace_server.py key list
  python3 gaide_trace_server.py key revoke <id>
  python3 gaide_trace_server.py rebuild-index

Environment (overridden by CLI flags):
  GAIDE_TRACE_SERVER_DATA   data directory (default: ./data)
  GAIDE_TRACE_SERVER_HOST   bind host (default: 0.0.0.0)
  GAIDE_TRACE_SERVER_PORT   bind port (default: 8321)

On first start, if no admin key exists, one is generated and printed once.
Run behind a TLS reverse proxy (Caddy/nginx) for anything non-local — see
docs/SERVER.md.
"""

import argparse
import csv
import gzip
import hashlib
import hmac
import io
import json
import math
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

VERSION = "0.6.0"

# Bump whenever the rules that derive index data from stored transcripts
# change: `serve` re-derives existing data on start (see
# Store.rederive_if_stale), so an upgrade needs no manual rebuild-index.
#   1 — transcript usage counted once per message, placeholder models dropped
#   2 — session time ranges lost to a transcript-first arrival are restored
#   3 — per-turn model usage (model_turns) and each session's dominant model
DERIVED_VERSION = 3
PROGRESS_EVERY_SECONDS = 5

# Model names come from ingested data an agent key controls; cap what the
# index stores so a hostile client cannot bloat it through this field.
MAX_MODEL_NAME = 128
# Far above any real message (context windows are ~10^6) and within SQLite's
# 64-bit INTEGER for one value. It does not make sums safe — enough maximal
# turns still pass 2^63 — which is why aggregates use sum_tokens().
MAX_TOKENS_PER_TURN = 10 ** 12
# Per-model rows returned by the API: every real team fits, a flood of
# distinct names from a hostile client does not reach browsers.
MAX_MODEL_ROWS = 500

# USD per million tokens, per token type. The ceiling only has to be far above
# any real list price while still catching a unit slip (per-token vs per-MTok).
PRICE_FIELDS = ("input", "output", "cache_read", "cache_write_5m", "cache_write_1h")
PRICE_TOKEN_COLUMNS = dict(zip(PRICE_FIELDS, (
    "input_tokens", "output_tokens", "cache_read_tokens",
    "cache_write_5m_tokens", "cache_write_1h_tokens")))
MAX_PRICE_PER_MTOK = 10_000

# Models drawn as their own series in the Overview per-day chart; the rest are
# folded into one "other" bucket, which also bounds the response size. Four
# categorical slots are what passed CVD validation on the console's tile.
CHART_SERIES = 4

MAX_EVENTS_BODY = 32 * 1024 * 1024        # 32 MB per events batch
MAX_TRANSCRIPT_BODY = 256 * 1024 * 1024   # 256 MB per transcript snapshot

EVENT_COLUMNS = [
    "trace_id", "ts", "received_at", "event", "native_event", "source",
    "session_id", "prompt_id",
    "project", "origin", "cwd", "permission_mode", "model", "agent_id",
    "agent_type", "tool_name", "tool_use_id", "tool_input", "tool_response",
    "prompt", "last_assistant_message",
]

# v0.2 stores shipped Claude Code hook names as `event`. Normalize to the
# canonical tool-agnostic vocabulary at ingest/index time; the original name
# is preserved in native_event. Old archives never need rewriting.
LEGACY_EVENTS = {
    "SessionStart": "session.start",
    "UserPromptSubmit": "prompt.submit",
    "PostToolUse": "tool.call",
    "PostToolUseFailure": "tool.fail",
    "Stop": "turn.end",
    "SubagentStart": "agent.start",
    "SubagentStop": "agent.end",
    "PreCompact": "context.compact",
    "SessionEnd": "session.end",
}


def event_row(rec: dict) -> dict:
    """The indexable columns of an ingested record. Every column is text; a
    client sending a number, boolean or object gets it stored as JSON text
    rather than failing the whole batch (SQLite cannot bind a dict or an int
    past 64 bits, and an unhashable `event` would break the legacy lookup)."""
    row = {}
    for c in EVENT_COLUMNS:
        value = rec.get(c)
        if value is not None and not isinstance(value, str):
            value = json.dumps(value, ensure_ascii=False)
        row[c] = value
    return normalize_event(row)


def normalize_event(row: dict):
    """Map legacy (v0.2, Claude-shaped) event names to canonical ones."""
    canonical = LEGACY_EVENTS.get(row.get("event"))
    if canonical:
        row["native_event"] = row.get("native_event") or row["event"]
        row["source"] = row.get("source") or "claude-code"
        row["event"] = canonical
    return row

SESSION_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

# ---------------------------------------------------------------- storage


class Store:
    """All persistence: SQLite index + raw JSONL archive + transcript files."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.archive_dir = data_dir / "archive" / "events"
        self.transcripts_dir = data_dir / "transcripts"
        for d in (self.archive_dir, self.transcripts_dir):
            d.mkdir(parents=True, exist_ok=True)
        self.db_path = data_dir / "trace.db"
        self._archive_lock = threading.Lock()
        with self.connect() as db:
            self._init_schema(db)

    def connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.db_path, timeout=30)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=NORMAL")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @staticmethod
    def _init_schema(db):
        db.executescript("""
        CREATE TABLE IF NOT EXISTS keys (
          id INTEGER PRIMARY KEY,
          token_hash TEXT UNIQUE NOT NULL,
          name TEXT NOT NULL,
          role TEXT NOT NULL CHECK (role IN ('agent','member','admin')),
          created_at TEXT NOT NULL,
          last_seen_at TEXT,
          revoked_at TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
          trace_id TEXT PRIMARY KEY,
          ts TEXT NOT NULL,
          received_at TEXT NOT NULL,
          event TEXT NOT NULL,
          native_event TEXT,
          source TEXT,
          session_id TEXT NOT NULL,
          prompt_id TEXT,
          project TEXT,
          origin TEXT,
          cwd TEXT,
          permission_mode TEXT,
          model TEXT,
          agent_id TEXT,
          agent_type TEXT,
          tool_name TEXT,
          tool_use_id TEXT,
          tool_input TEXT,
          tool_response TEXT,
          prompt TEXT,
          last_assistant_message TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, ts);
        CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
        CREATE INDEX IF NOT EXISTS idx_events_project ON events(project, ts);
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          salt TEXT NOT NULL,
          role TEXT NOT NULL CHECK (role IN ('member','admin')),
          must_change_password INTEGER NOT NULL DEFAULT 0,
          created_at TEXT NOT NULL,
          last_login_at TEXT,
          disabled_at TEXT,
          all_projects INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS web_sessions (
          token_hash TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id),
          created_at TEXT NOT NULL,
          expires_at TEXT NOT NULL
        );
        -- Grants are by project *name*, so a registration can go and come back
        -- without touching who may see its data (specs/project-access).
        CREATE TABLE IF NOT EXISTS user_projects (
          user_id INTEGER NOT NULL REFERENCES users(id),
          project TEXT NOT NULL,
          granted_at TEXT NOT NULL,
          granted_by TEXT,
          PRIMARY KEY (user_id, project)
        );
        CREATE TABLE IF NOT EXISTS projects (
          id INTEGER PRIMARY KEY,
          name TEXT UNIQUE NOT NULL,
          created_at TEXT NOT NULL,
          created_by TEXT,
          key_id INTEGER REFERENCES keys(id),
          agent_token TEXT
        );
        CREATE TABLE IF NOT EXISTS sessions (
          session_id TEXT PRIMARY KEY,
          project TEXT,
          origin TEXT,
          first_ts TEXT,
          last_ts TEXT,
          events INTEGER NOT NULL DEFAULT 0,
          prompts INTEGER NOT NULL DEFAULT 0,
          tool_calls INTEGER NOT NULL DEFAULT 0,
          failures INTEGER NOT NULL DEFAULT 0,
          models TEXT,
          input_tokens INTEGER,
          output_tokens INTEGER,
          cache_read_tokens INTEGER,
          cache_creation_tokens INTEGER,
          transcript_bytes INTEGER,
          transcript_lines INTEGER,
          transcript_updated_at TEXT,
          dominant_model TEXT,
          model_count INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_last ON sessions(last_ts);
        CREATE TABLE IF NOT EXISTS model_turns (
          session_id TEXT NOT NULL,
          turn_key TEXT NOT NULL,
          model TEXT NOT NULL,
          source TEXT NOT NULL CHECK (source IN ('transcript','events')),
          ts TEXT,
          input_tokens INTEGER,
          output_tokens INTEGER,
          cache_read_tokens INTEGER,
          cache_write_5m_tokens INTEGER,
          cache_write_1h_tokens INTEGER,
          premium INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY (session_id, turn_key)
        );
        CREATE INDEX IF NOT EXISTS idx_model_turns_ts ON model_turns(ts);
        CREATE INDEX IF NOT EXISTS idx_model_turns_model ON model_turns(model, ts);
        -- Sessions "used model X" filter: without it the EXISTS probe scans
        -- every turn of X once per session row.
        CREATE INDEX IF NOT EXISTS idx_model_turns_session_model
          ON model_turns(session_id, model);
        CREATE TABLE IF NOT EXISTS model_prices (
          model TEXT PRIMARY KEY,
          input REAL NOT NULL,
          output REAL NOT NULL,
          cache_read REAL NOT NULL,
          cache_write_5m REAL NOT NULL,
          cache_write_1h REAL NOT NULL,
          updated_at TEXT NOT NULL,
          updated_by TEXT
        );
        CREATE TABLE IF NOT EXISTS meta (
          key TEXT PRIMARY KEY,
          value TEXT
        );
        """)
        # v0.2 -> v0.3 migration: add columns if the table predates them.
        cols = {r[1] for r in db.execute("PRAGMA table_info(events)")}
        for col in ("native_event", "source"):
            if col not in cols:
                db.execute(f"ALTER TABLE events ADD COLUMN {col} TEXT")
        cols = {r[1] for r in db.execute("PRAGMA table_info(sessions)")}
        if "dominant_model" not in cols:
            db.execute("ALTER TABLE sessions ADD COLUMN dominant_model TEXT")
        if "model_count" not in cols:
            db.execute("ALTER TABLE sessions ADD COLUMN model_count INTEGER NOT NULL DEFAULT 0")
        # v0.5 -> v0.6: accounts that predate project scopes keep seeing
        # everything; narrowing is an explicit admin action (AC6). Guarded by
        # the column so a later narrowing is never undone by a restart.
        cols = {r[1] for r in db.execute("PRAGMA table_info(users)")}
        if "all_projects" not in cols:
            db.execute("ALTER TABLE users ADD COLUMN all_projects INTEGER NOT NULL DEFAULT 0")
            db.execute("UPDATE users SET all_projects = 1")
        db.commit()

    # ---- events ingest ----

    def ingest_events(self, records, origin: str):
        """Insert a batch. Returns (inserted, duplicates). Idempotent by trace_id."""
        now = utcnow()
        inserted, duplicates = 0, 0
        accepted = []
        with self.connect() as db:
            for rec in records:
                if not isinstance(rec, dict):
                    continue
                row = event_row(rec)
                if not row["trace_id"] or not row["session_id"] or not row["event"]:
                    continue
                row["received_at"] = now
                row["origin"] = origin
                row["ts"] = row["ts"] or now
                if not SESSION_ID_RE.match(str(row["session_id"])):
                    continue
                cur = db.execute(
                    f"INSERT OR IGNORE INTO events ({','.join(EVENT_COLUMNS)}) "
                    f"VALUES ({','.join('?' for _ in EVENT_COLUMNS)})",
                    [row[c] for c in EVENT_COLUMNS],
                )
                if cur.rowcount:
                    inserted += 1
                    accepted.append(row)
                else:
                    duplicates += 1
            touched = set()
            for row in accepted:
                self._bump_session(db, row)
                if self._add_event_turn(db, row):
                    touched.add(row["session_id"])
            for sid in touched:
                self._summarize_session_models(db, sid)
            db.commit()
        # Raw archive: append accepted records to per-session JSONL. The
        # archive, not SQLite, is the source of truth (index is rebuildable).
        with self._archive_lock:
            by_session = {}
            for row in accepted:
                by_session.setdefault(row["session_id"], []).append(row)
            for sid, rows in by_session.items():
                f = self.archive_dir / f"{sid}.jsonl"
                with f.open("a", encoding="utf-8") as fh:
                    for row in rows:
                        fh.write(json.dumps(
                            {k: v for k, v in row.items() if v is not None},
                            ensure_ascii=False) + "\n")
        return inserted, duplicates

    @staticmethod
    def _bump_session(db, row):
        ev = row["event"]
        db.execute(
            """INSERT INTO sessions (session_id, project, origin, first_ts, last_ts, events)
               VALUES (?,?,?,?,?,1)
               ON CONFLICT(session_id) DO UPDATE SET
                 events = events + 1,
                 project = COALESCE(sessions.project, excluded.project),
                 origin = COALESCE(sessions.origin, excluded.origin),
                 -- scalar MIN/MAX return NULL if either side is NULL, and a
                 -- transcript upload creates the row with no times
                 first_ts = MIN(COALESCE(sessions.first_ts, excluded.first_ts), excluded.first_ts),
                 last_ts = MAX(COALESCE(sessions.last_ts, excluded.last_ts), excluded.last_ts)""",
            (row["session_id"], row["project"], row["origin"], row["ts"], row["ts"]),
        )
        if ev == "prompt.submit":
            db.execute("UPDATE sessions SET prompts = prompts + 1 WHERE session_id = ?",
                       (row["session_id"],))
        elif ev == "tool.call":
            db.execute("UPDATE sessions SET tool_calls = tool_calls + 1 WHERE session_id = ?",
                       (row["session_id"],))
        elif ev == "tool.fail":
            db.execute("UPDATE sessions SET failures = failures + 1 WHERE session_id = ?",
                       (row["session_id"],))

    # ---- model usage ----

    @staticmethod
    def _add_event_turn(db, row) -> bool:
        """Record a live model.turn event as a turn, unless the session's
        transcript already accounts for its turns — the two sources are never
        added together. Returns whether a turn was recorded."""
        model = model_name(row.get("model"))
        if row["event"] != "model.turn" or not model:
            return False
        if db.execute("SELECT 1 FROM model_turns WHERE session_id = ? AND source = 'transcript'"
                      " LIMIT 1", (row["session_id"],)).fetchone():
            return False
        cur = db.execute(
            """INSERT OR IGNORE INTO model_turns (session_id, turn_key, model, source, ts)
               VALUES (?,?,?,'events',?)""",
            (row["session_id"], row["trace_id"], model, utc_iso(row["ts"])))
        return bool(cur.rowcount)

    @staticmethod
    def _replace_session_models(db, session_id, turns):
        """The one place the source rule lives: a session's turns come from
        its transcript when that yields any, otherwise from its model.turn
        events."""
        db.execute("DELETE FROM model_turns WHERE session_id = ?", (session_id,))
        if turns:
            db.executemany(
                """INSERT OR IGNORE INTO model_turns
                     (session_id, turn_key, model, source, ts, input_tokens, output_tokens,
                      cache_read_tokens, cache_write_5m_tokens, cache_write_1h_tokens, premium)
                   VALUES (?,?,?,'transcript',?,?,?,?,?,?,?)""",
                [(session_id, t["key"], t["model"], t["ts"], t["input_tokens"],
                  t["output_tokens"], t["cache_read_tokens"], t["cache_write_5m_tokens"],
                  t["cache_write_1h_tokens"], int(t["premium"])) for t in turns])
        else:
            for ev in db.execute(
                    "SELECT trace_id, ts, model FROM events"
                    " WHERE session_id = ? AND event = 'model.turn'",
                    (session_id,)).fetchall():
                model = model_name(ev["model"])
                if model:
                    db.execute(
                        """INSERT OR IGNORE INTO model_turns
                             (session_id, turn_key, model, source, ts)
                           VALUES (?,?,?,'events',?)""",
                        (session_id, ev["trace_id"], model, utc_iso(ev["ts"])))
        Store._summarize_session_models(db, session_id)

    @staticmethod
    def _summarize_session_models(db, session_id):
        rows = db.execute(
            """SELECT model FROM model_turns WHERE session_id = ?
               GROUP BY model
               ORDER BY COUNT(*) DESC, TOTAL(output_tokens) DESC, model""",
            (session_id,)).fetchall()
        db.execute("UPDATE sessions SET dominant_model = ?, model_count = ? WHERE session_id = ?",
                   (rows[0]["model"] if rows else None, len(rows), session_id))

    def session_models(self, session_id):
        """Per-model usage of one session. Token sums are None for turns whose
        source has no token data."""
        with self.connect() as db:
            return model_usage_rows(db, " WHERE mt.session_id = ?", [session_id])

    # ---- transcripts ----

    def store_transcript(self, session_id: str, data: bytes, project, origin):
        """Overwrite the snapshot (each supersedes the last, same as local
        semantics) and refresh the session's token accounting from it."""
        dst = self.transcripts_dir / f"{session_id}.jsonl"
        tmp = dst.with_suffix(".tmp")
        tmp.write_bytes(data)
        tmp.replace(dst)
        return self.index_transcript(session_id, data, project, origin, utcnow())

    def index_transcript(self, session_id: str, source, project, origin, updated_at):
        """Derive the session's transcript accounting from `source` (the
        uploaded bytes, or the stored snapshot's Path) without touching any
        file — re-derivation must leave stored snapshots byte-identical."""
        if isinstance(source, Path):
            size = source.stat().st_size
            with source.open("rb") as fh:
                turns, lines = transcript_turns(fh)
        else:
            size = len(source)
            turns, lines = transcript_turns(source)
        stats = summarize_turns(turns, lines)
        with self.connect() as db:
            db.execute(
                """INSERT INTO sessions (session_id, project, origin) VALUES (?,?,?)
                   ON CONFLICT(session_id) DO UPDATE SET
                     project = COALESCE(sessions.project, excluded.project),
                     origin = COALESCE(sessions.origin, excluded.origin)""",
                (session_id, project, origin),
            )
            db.execute(
                """UPDATE sessions SET
                     transcript_bytes = ?, transcript_lines = ?, transcript_updated_at = ?,
                     input_tokens = ?, output_tokens = ?,
                     cache_read_tokens = ?, cache_creation_tokens = ?,
                     models = ?
                   WHERE session_id = ?""",
                (size, stats["lines"], updated_at,
                 stats["input_tokens"], stats["output_tokens"],
                 stats["cache_read_tokens"], stats["cache_creation_tokens"],
                 stats["models"], session_id),
            )
            self._replace_session_models(db, session_id, turns)
            db.commit()
        return {"bytes": size, "lines": stats["lines"]}

    def transcript_path(self, session_id: str):
        p = self.transcripts_dir / f"{session_id}.jsonl"
        return p if p.is_file() else None

    # ---- index rebuild (archive is the source of truth) ----

    def rebuild_index(self):
        with self.connect() as db:
            db.execute("DELETE FROM events")
            db.execute("DELETE FROM sessions")
            db.execute("DELETE FROM model_turns")
            db.commit()
            n = 0
            for f in sorted(self.archive_dir.glob("*.jsonl")):
                for line in f.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    try:
                        rec = json.loads(line)
                    except (ValueError, RecursionError):
                        continue
                    if not isinstance(rec, dict):
                        continue
                    row = event_row(rec)
                    if not row["trace_id"]:
                        continue
                    cur = db.execute(
                        f"INSERT OR IGNORE INTO events ({','.join(EVENT_COLUMNS)}) "
                        f"VALUES ({','.join('?' for _ in EVENT_COLUMNS)})",
                        [row[c] for c in EVENT_COLUMNS],
                    )
                    if cur.rowcount:
                        self._bump_session(db, row)
                        n += 1
            db.commit()
        self._rederive_all()
        self._set_derived_version(DERIVED_VERSION)
        return n

    # ---- derived-data versioning ----

    def _rederive_all(self, progress=None):
        """Re-derive transcript accounting and model usage for every session.
        Returns (transcripts re-indexed, session ids that failed).

        Stored data was written by clients an agent key controls. One session
        that cannot be derived is logged and skipped: aborting would keep the
        whole server from starting, or make rebuild-index unusable."""
        files = sorted(self.transcripts_dir.glob("*.jsonl"))
        failed = []

        def skipped(sid, exc):
            failed.append(sid)
            print(f"re-deriving index: skipped session {sid}: {exc!r}",
                  file=sys.stderr, flush=True)

        with_transcript = {f.stem for f in files}
        with self.connect() as db:
            sids = [r[0] for r in db.execute("SELECT session_id FROM sessions").fetchall()]
        for sid in sids:
            if sid in with_transcript:
                continue
            try:
                with self.connect() as db:
                    self._replace_session_models(db, sid, None)
                    db.commit()
            except Exception as exc:
                skipped(sid, exc)
        last_report = time.monotonic()
        for done, f in enumerate(files, 1):
            # The file's mtime is when its last upload landed; stamping "now"
            # would make every session look freshly uploaded after an upgrade.
            uploaded = datetime.fromtimestamp(f.stat().st_mtime, timezone.utc).isoformat()
            try:
                self.index_transcript(f.stem, f, None, None, uploaded)
            except Exception as exc:
                skipped(f.stem, exc)
            if progress and time.monotonic() - last_report >= PROGRESS_EVERY_SECONDS:
                progress(done, len(files))
                last_report = time.monotonic()
        return len(files) - sum(1 for sid in failed if sid in with_transcript), failed

    def derived_version(self) -> int:
        with self.connect() as db:
            row = db.execute(
                "SELECT value FROM meta WHERE key = 'derived_version'").fetchone()
        try:
            return int(row["value"]) if row else 0
        except ValueError:
            return 0

    def _set_derived_version(self, version: int):
        with self.connect() as db:
            db.execute(
                """INSERT INTO meta (key, value) VALUES ('derived_version', ?)
                   ON CONFLICT(key) DO UPDATE SET value = excluded.value""",
                (str(version),))
            db.commit()

    def _repair_session_times(self):
        with self.connect() as db:
            db.execute(
                """UPDATE sessions SET
                     first_ts = (SELECT MIN(ts) FROM events e WHERE e.session_id = sessions.session_id),
                     last_ts = (SELECT MAX(ts) FROM events e WHERE e.session_id = sessions.session_id)
                   WHERE first_ts IS NULL OR last_ts IS NULL""")
            db.commit()

    def rederive_if_stale(self, progress=None):
        """Bring derived index data up to the code's DERIVED_VERSION — session
        time ranges from indexed events, transcript accounting and model usage
        from stored transcripts and model.turn events — so upgrades never need
        a manual rebuild-index. Returns a summary dict, or None when already
        current (or when there is nothing to derive yet — a fresh install is
        not an upgrade)."""
        found = self.derived_version()
        if found >= DERIVED_VERSION:
            return None
        with self.connect() as db:
            has_sessions = db.execute("SELECT 1 FROM sessions LIMIT 1").fetchone()
        if not has_sessions and not any(self.transcripts_dir.glob("*.jsonl")):
            self._set_derived_version(DERIVED_VERSION)
            return None
        started = time.monotonic()
        self._repair_session_times()
        transcripts, failed = self._rederive_all(progress)
        # Recorded even with failures: they are logged per session, and a
        # session re-derives on its next transcript upload or rebuild-index
        # (events-only sessions have no upload, so only the latter).
        self._set_derived_version(DERIVED_VERSION)
        return {"from": found, "to": DERIVED_VERSION, "transcripts": transcripts,
                "failed": failed, "seconds": round(time.monotonic() - started, 2)}


# Model values that name no real model: Claude Code stamps "<synthetic>" on
# messages it fabricates locally (interruptions, API errors). They carry no
# billed usage and must never show up as a model.
PLACEHOLDER_MODELS = frozenset({"<synthetic>"})


def model_name(value):
    """A model value usable for attribution, or None for missing and
    placeholder values."""
    if not isinstance(value, str) or not value or value in PLACEHOLDER_MODELS:
        return None
    return value[:MAX_MODEL_NAME]


def utc_iso(value):
    """Normalize a timestamp to UTC ISO-8601 so day buckets and window
    comparisons line up across sources ("Z" suffixes, offsets, naive)."""
    if not isinstance(value, str) or not value:
        return None
    text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    try:
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        # Dates at the edge of the calendar parse, then overflow on conversion.
        return parsed.astimezone(timezone.utc).isoformat()
    except (ValueError, OverflowError):
        return None


def _token(value):
    """A usable token count, else 0. Counts past MAX_TOKENS_PER_TURN are
    garbage, and would overflow SQLite's 64-bit INTEGER on insert or SUM."""
    if isinstance(value, int) and not isinstance(value, bool) and 0 < value <= MAX_TOKENS_PER_TURN:
        return value
    return 0


def _turn_key(msg_id: str) -> str:
    """Bound the stored key without losing de-duplication: long ids (which
    no real transcript has) are replaced by their digest."""
    if len(msg_id) <= MAX_MODEL_NAME:
        return msg_id
    return "sha256:" + hashlib.sha256(msg_id.encode("utf-8", "surrogatepass")).hexdigest()


def transcript_turns(source):
    """Parse a Claude Code transcript (bytes, or a binary file object read
    line by line) into model turns. Returns (turns, lines).

    Claude Code writes one line per content block and repeats the message's
    id and identical usage on every line, so a turn is one distinct
    message.id — summing lines would multiply tokens by the block count.
    The first line of a message wins. Lines without an id cannot be matched
    and count individually."""
    if isinstance(source, (bytes, bytearray)):
        source = io.BytesIO(source)  # same line splitting as a stored file
    turns = []
    seen_ids = set()
    lines = 0
    for n, line in enumerate(source):
        if not line.strip():
            continue
        lines += 1
        try:
            e = json.loads(line)
        # ValueError also covers bad UTF-8 and over-long number literals;
        # RecursionError, absurdly nested lines. Skipping one line must never
        # fail the upload.
        except (ValueError, RecursionError):
            continue
        msg = e.get("message") if isinstance(e, dict) else None
        if not isinstance(msg, dict):
            continue
        model = model_name(msg.get("model"))
        if not model:
            continue
        msg_id = msg.get("id")
        if isinstance(msg_id, str) and msg_id:
            if msg_id in seen_ids:
                continue
            seen_ids.add(msg_id)
            key = _turn_key(msg_id)
        else:
            key = f"line:{n}"
        usage = msg.get("usage") if isinstance(msg.get("usage"), dict) else {}
        cache_write = _token(usage.get("cache_creation_input_tokens"))
        tiers = usage.get("cache_creation")
        if isinstance(tiers, dict):
            write_5m = _token(tiers.get("ephemeral_5m_input_tokens"))
            write_1h = _token(tiers.get("ephemeral_1h_input_tokens"))
        else:
            # No tier breakdown: price everything at the cheaper 5-minute rate
            # (spec AC18) rather than guess at a split.
            write_5m, write_1h = cache_write, 0
        speed = usage.get("speed")
        turns.append({
            "key": key,
            "model": model,
            "ts": utc_iso(e.get("timestamp")),
            "input_tokens": _token(usage.get("input_tokens")),
            "output_tokens": _token(usage.get("output_tokens")),
            "cache_read_tokens": _token(usage.get("cache_read_input_tokens")),
            "cache_creation_tokens": cache_write,
            "cache_write_5m_tokens": write_5m,
            "cache_write_1h_tokens": write_1h,
            "premium": isinstance(speed, str) and speed != "standard",
        })
    return turns, lines


def summarize_transcript(source):
    """Token usage + models of a transcript snapshot. Understands the Claude
    Code JSONL format; other sources contribute only a line count (their
    events carry the model per record). Usage on a message that names no
    model is not attributable to any model and is not counted."""
    return summarize_turns(*transcript_turns(source))


def summarize_turns(turns, lines):
    totals = {k: sum(t[k] for t in turns) for k in
              ("input_tokens", "output_tokens", "cache_read_tokens", "cache_creation_tokens")}
    models = sorted({t["model"] for t in turns})
    return {**totals, "lines": lines, "models": ",".join(models) or None}


def sum_tokens(column: str) -> str:
    """SQL for an overflow-safe token sum that stays NULL when every value is
    NULL (unknown, not zero). SQLite's SUM() raises "integer overflow" past
    2^63, and ingested counts are client-controlled: a few maximal uploads
    would take down every aggregate view. TOTAL() is floating point and
    never overflows; callers turn the result back into an int."""
    return f"CASE WHEN COUNT({column}) = 0 THEN NULL ELSE TOTAL({column}) END"


def int_or_none(value):
    return None if value is None else int(value)


def model_usage_rows(db, where: str, params):
    """Per-model aggregates over model_turns (alias mt, joined to sessions as
    s), most-used first. `where` is a trusted SQL fragment built by callers
    from fixed column names; values only ever travel in `params`."""
    token_cols = ("input_tokens", "output_tokens", "cache_read_tokens",
                  "cache_write_5m_tokens", "cache_write_1h_tokens")
    rows = db.execute(
        f"""SELECT mt.model AS model,
                   GROUP_CONCAT(DISTINCT mt.source) AS source,
                   COUNT(DISTINCT mt.session_id) AS sessions,
                   COUNT(*) AS turns,
                   COUNT(*) - COUNT(mt.output_tokens) AS turns_without_tokens,
                   {', '.join(f'{sum_tokens("mt." + c)} AS {c}' for c in token_cols)},
                   SUM(mt.premium) AS premium_turns,
                   MIN(mt.ts) AS first_ts, MAX(mt.ts) AS last_ts
            FROM model_turns mt JOIN sessions s ON s.session_id = mt.session_id
            {where}
            GROUP BY mt.model
            ORDER BY turns DESC, TOTAL(mt.output_tokens) DESC, mt.model""",
        params).fetchall()
    out = []
    for r in rows:
        row = dict(r)
        for c in token_cols:
            row[c] = int_or_none(row[c])
        out.append(row)
    return out


def load_prices(db):
    return {r["model"]: dict(r) for r in db.execute("SELECT * FROM model_prices")}


def price_rows(rows, prices):
    """Annotate per-model rows with an estimated cost and return totals.

    cost_status: `priced`, `unpriced` (no price entry — cost is never guessed)
    or `no_tokens` (the source recorded no usage, so there is nothing to
    price; counted apart from unpriced). Costs are left unrounded."""
    totals = {"turns": 0, "premium_turns": 0, "premium_priced_turns": 0, "cost_total": None,
              "unpriced_models": 0, "no_token_models": 0,
              **{col: None for col in PRICE_TOKEN_COLUMNS.values()}}
    for row in rows:
        totals["turns"] += row["turns"]
        totals["premium_turns"] += row["premium_turns"] or 0
        for col in PRICE_TOKEN_COLUMNS.values():
            if row[col] is not None:
                totals[col] = (totals[col] or 0) + row[col]
        price = prices.get(row["model"])
        if row["turns_without_tokens"] == row["turns"]:
            row["cost"], row["cost_status"] = None, "no_tokens"
            totals["no_token_models"] += 1
        elif price is None:
            row["cost"], row["cost_status"] = None, "unpriced"
            totals["unpriced_models"] += 1
        else:
            spend = 0
            for field, col in PRICE_TOKEN_COLUMNS.items():
                spend += (row[col] or 0) * price[field]
            row["cost"], row["cost_status"] = spend / 1_000_000, "priced"
            totals["cost_total"] = (totals["cost_total"] or 0) + row["cost"]
            # Only these make the total a lower bound: premium turns of an
            # unpriced model are not in the estimate at all.
            totals["premium_priced_turns"] += row["premium_turns"] or 0
    return rows, totals


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------- auth


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_token() -> str:
    return "gtr_" + secrets.token_urlsafe(32)


def create_key(store: Store, name: str, role: str) -> str:
    token = new_token()
    with store.connect() as db:
        db.execute(
            "INSERT INTO keys (token_hash, name, role, created_at) VALUES (?,?,?,?)",
            (hash_token(token), name, role, utcnow()),
        )
        db.commit()
    return token


# ---- console users (username + password, PBKDF2 at rest) ----

MIN_PASSWORD_LEN = 8
SESSION_TTL_SECONDS = 7 * 86400


def hash_password(password: str, salt_hex: str = None):
    salt_hex = salt_hex or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             bytes.fromhex(salt_hex), 600_000)
    return dk.hex(), salt_hex


def verify_password(password: str, password_hash: str, salt_hex: str) -> bool:
    candidate, _ = hash_password(password, salt_hex)
    return hmac.compare_digest(candidate, password_hash)


def create_user(store: Store, username: str, password: str, role: str,
                must_change: bool, all_projects: bool = False, projects=(),
                granted_by=None):
    """Admins always get every project; a member starts with the given scope
    (empty list by default: access is opt-in, specs/project-access AC6)."""
    pw_hash, salt = hash_password(password)
    all_projects = all_projects or role == "admin"
    with store.connect() as db:
        cur = db.execute(
            """INSERT INTO users (username, password_hash, salt, role,
                                  must_change_password, created_at, all_projects)
               VALUES (?,?,?,?,?,?,?)""",
            (username, pw_hash, salt, role, 1 if must_change else 0, utcnow(),
             1 if all_projects else 0),
        )
        if not all_projects:
            db.executemany(
                """INSERT INTO user_projects (user_id, project, granted_at, granted_by)
                   VALUES (?,?,?,?)""",
                [(cur.lastrowid, name, utcnow(), granted_by) for name in projects])
        db.commit()


def user_scope(db, user_id: int, role: str, all_projects) -> "list | None":
    """None means every project (admins, all-projects accounts); otherwise the
    sorted names the account may see, possibly none."""
    if role == "admin" or all_projects:
        return None
    return [r["project"] for r in db.execute(
        "SELECT project FROM user_projects WHERE user_id = ? ORDER BY project",
        (user_id,))]


PROJECT_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")


# Every scoped read expands the list into `IN (?, ...)`; keep it far below
# SQLite's host-parameter limit so an admin cannot brick an account by
# granting it too much.
MAX_SCOPE_NAMES = 200


def parse_scope(payload: dict, default=None):
    """(all_projects, names) from {"all": true} or {"projects": [...]}.
    `default` when the payload names neither; None when it is invalid."""
    if payload.get("all") is True:
        return True, []
    names = payload.get("projects")
    if names is None:
        return default
    if (not isinstance(names, list) or len(names) > MAX_SCOPE_NAMES or not all(
            isinstance(n, str) and PROJECT_NAME_RE.match(n) for n in names)):
        return None
    return False, sorted(set(names))


def scope_sql(ident, col: str):
    """WHERE fragment + params restricting `col` to the caller's scope: nothing
    for all projects, `col IN (...)` for a list, a false clause for an empty
    list. Every read query goes through here (ADR 0002)."""
    scope = ident.get("scope")
    if scope is None:
        return "", []
    if not scope:
        return "0 = 1", []
    return f"{col} IN ({','.join('?' for _ in scope)})", list(scope)


def set_password(store: Store, user_id: int, password: str, must_change: bool):
    pw_hash, salt = hash_password(password)
    with store.connect() as db:
        db.execute(
            """UPDATE users SET password_hash = ?, salt = ?,
                                must_change_password = ? WHERE id = ?""",
            (pw_hash, salt, 1 if must_change else 0, user_id),
        )
        # a password change invalidates every open session of that user
        db.execute("DELETE FROM web_sessions WHERE user_id = ?", (user_id,))
        db.commit()


# Brute-force throttle: after 5 straight failures a username locks for 60s.
_login_fails = {}
_login_lock = threading.Lock()


def login_throttled(username: str) -> bool:
    with _login_lock:
        fails, until = _login_fails.get(username, (0, 0))
        return fails >= 5 and time.monotonic() < until


def login_result(username: str, ok: bool):
    with _login_lock:
        if ok:
            _login_fails.pop(username, None)
        else:
            fails, _ = _login_fails.get(username, (0, 0))
            _login_fails[username] = (fails + 1, time.monotonic() + 60)


def open_web_session(store: Store, user_id: int) -> str:
    token = "gts_" + secrets.token_urlsafe(32)
    now = time.time()
    with store.connect() as db:
        db.execute(
            "INSERT INTO web_sessions (token_hash, user_id, created_at, expires_at) "
            "VALUES (?,?,?,?)",
            (hash_token(token), user_id, utcnow(),
             datetime.fromtimestamp(now + SESSION_TTL_SECONDS, timezone.utc).isoformat()),
        )
        db.execute("UPDATE users SET last_login_at = ? WHERE id = ?",
                   (utcnow(), user_id))
        db.commit()
    return token


def authenticate(store: Store, headers):
    """Resolve the bearer token to an identity.

    Returns {name, role, kind: 'key'|'user', ...}. Console sessions ('gts_')
    map to users; anything else is looked up as an API key."""
    auth = headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[len("Bearer "):].strip()
    if not token:
        return None
    if token.startswith("gts_"):
        with store.connect() as db:
            row = db.execute(
                """SELECT u.id, u.username, u.role, u.must_change_password,
                          u.all_projects
                   FROM web_sessions s JOIN users u ON u.id = s.user_id
                   WHERE s.token_hash = ? AND s.expires_at > ?
                     AND u.disabled_at IS NULL""",
                (hash_token(token), utcnow()),
            ).fetchone()
            if not row:
                return None
            scope = user_scope(db, row["id"], row["role"], row["all_projects"])
        return {"kind": "user", "user_id": row["id"], "name": row["username"],
                "role": row["role"], "scope": scope,
                "must_change_password": bool(row["must_change_password"])}
    with store.connect() as db:
        row = db.execute(
            "SELECT id, name, role FROM keys WHERE token_hash = ? AND revoked_at IS NULL",
            (hash_token(token),),
        ).fetchone()
        if row:
            db.execute("UPDATE keys SET last_seen_at = ? WHERE id = ?",
                       (utcnow(), row["id"]))
            db.commit()
    if not row:
        return None
    return {"kind": "key", "name": row["name"], "role": row["role"], "scope": None,
            "must_change_password": False}


ROLE_RANK = {"agent": 0, "member": 1, "admin": 2}


# ---------------------------------------------------------------- HTTP


class Handler(BaseHTTPRequestHandler):
    server_version = f"gaide-trace/{VERSION}"
    store: Store = None          # set by serve()
    webui_dir: Path = None

    # -- plumbing --

    def log_message(self, fmt, *args):  # quieter default log line
        sys.stderr.write("%s [%s] %s\n" % (
            self.address_string(), datetime.now().strftime("%H:%M:%S"), fmt % args))

    def send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status, message):
        self.send_json({"error": message}, status=status)

    def read_body(self, max_len: int):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > max_len:
            return None
        data = self.rfile.read(length)
        if self.headers.get("Content-Encoding", "").lower() == "gzip":
            try:
                data = gzip.decompress(data)
            except OSError:
                return None
            if len(data) > max_len:
                return None
        return data

    def require(self, min_role: str, allow_must_change=False):
        """Authenticate and enforce role. Returns identity dict or None (replied)."""
        ident = authenticate(self.store, self.headers)
        if not ident:
            self.send_error_json(401, "missing or invalid credentials")
            return None
        if ident["must_change_password"] and not allow_must_change:
            self.send_error_json(403, "password_change_required")
            return None
        if ROLE_RANK[ident["role"]] < ROLE_RANK[min_role]:
            self.send_error_json(403, f"requires role '{min_role}'")
            return None
        return ident

    # -- routing --

    def do_GET(self):
        try:
            self.route("GET")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        try:
            self.route("POST")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_PUT(self):
        try:
            self.route("PUT")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_DELETE(self):
        try:
            self.route("DELETE")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def route(self, method):
        url = urlparse(self.path)
        path = url.path
        q = {k: v[0] for k, v in parse_qs(url.query).items()}

        if path == "/healthz":
            return self.send_json({"ok": True, "version": VERSION})

        if path.startswith("/api/v1/"):
            return self.route_api(method, path, q)

        if method == "GET":
            return self.serve_static(path)
        self.send_error_json(404, "not found")

    def route_api(self, method, path, q):
        m = (method, path)

        if m == ("GET", "/api/v1/me"):
            ident = self.require("agent", allow_must_change=True)
            if ident:
                self.send_json({"name": ident["name"], "role": ident["role"],
                                "kind": ident["kind"], "scope": ident["scope"],
                                "must_change_password": ident["must_change_password"],
                                "version": VERSION})
            return

        if m == ("POST", "/api/v1/auth/login"):
            return self.api_login()

        if m == ("POST", "/api/v1/auth/password"):
            return self.api_change_password()

        if m == ("POST", "/api/v1/auth/logout"):
            token = (self.headers.get("Authorization", "")
                     .removeprefix("Bearer ").strip())
            if token.startswith("gts_"):
                with self.store.connect() as db:
                    db.execute("DELETE FROM web_sessions WHERE token_hash = ?",
                               (hash_token(token),))
                    db.commit()
            return self.send_json({"ok": True})

        if m == ("GET", "/api/v1/users"):
            if self.require("admin"):
                self.send_json(self.api_users())
            return

        if method == "PUT" and re.fullmatch(r"/api/v1/users/\d+/scope", path):
            return self.api_set_scope(int(path.split("/")[4]))

        if m == ("POST", "/api/v1/users"):
            return self.api_create_user()

        if method == "POST" and re.fullmatch(r"/api/v1/users/\d+/reset", path):
            return self.api_reset_user(int(path.split("/")[4]))

        if method == "DELETE" and re.fullmatch(r"/api/v1/users/\d+", path):
            return self.api_disable_user(int(path.rsplit("/", 1)[1]))

        if m == ("GET", "/api/v1/projects/manage"):
            ident = self.require("member")
            if ident:
                self.send_json(self.api_projects_manage(ident))
            return

        if m == ("POST", "/api/v1/projects"):
            return self.api_create_project()

        if method == "POST" and re.fullmatch(r"/api/v1/projects/\d+/rotate", path):
            return self.api_rotate_project(int(path.split("/")[4]))

        if method == "DELETE" and re.fullmatch(r"/api/v1/projects/\d+", path):
            return self.api_delete_project(int(path.rsplit("/", 1)[1]))

        if m == ("POST", "/api/v1/events"):
            return self.api_ingest_events()

        if method == "PUT" and path.startswith("/api/v1/transcripts/"):
            return self.api_put_transcript(path.split("/api/v1/transcripts/", 1)[1], q)

        if m == ("GET", "/api/v1/overview"):
            ident = self.require("member")
            if ident:
                self.send_json(self.api_overview(q, ident))
            return

        if m == ("GET", "/api/v1/projects"):
            ident = self.require("member")
            if ident:
                frag, params = scope_sql(ident, "project")
                with self.store.connect() as db:
                    rows = db.execute(
                        "SELECT DISTINCT project FROM sessions WHERE project IS NOT NULL"
                        + (f" AND {frag}" if frag else "") + " ORDER BY project",
                        params).fetchall()
                self.send_json([r["project"] for r in rows])
            return

        if m == ("GET", "/api/v1/sessions"):
            ident = self.require("member")
            if ident:
                self.send_json(self.api_sessions(q, ident))
            return

        if m == ("GET", "/api/v1/models"):
            ident = self.require("member")
            if ident:
                self.send_json(self.api_models(ident))
            return

        if m == ("PUT", "/api/v1/models/prices"):
            return self.api_set_price()

        if m == ("DELETE", "/api/v1/models/prices"):
            return self.api_clear_price(q)

        if method == "GET" and path.startswith("/api/v1/sessions/"):
            rest = path.split("/api/v1/sessions/", 1)[1]
            if rest.endswith("/transcript"):
                sid = rest[: -len("/transcript")]
                return self.api_get_transcript(sid)
            ident = self.require("member")
            if ident:
                return self.api_session_detail(rest, ident)
            return

        if m == ("GET", "/api/v1/export"):
            return self.api_export(q)

        if m == ("GET", "/api/v1/keys"):
            if self.require("admin"):
                with self.store.connect() as db:
                    rows = db.execute(
                        """SELECT k.id, k.name, k.role, k.created_at, k.last_seen_at,
                                  k.revoked_at,
                                  (SELECT COUNT(*) FROM sessions s WHERE s.origin = k.name)
                                  AS sessions
                           FROM keys k ORDER BY k.created_at DESC""").fetchall()
                self.send_json([dict(r) for r in rows])
            return

        if m == ("POST", "/api/v1/keys"):
            if not self.require("admin"):
                return
            body = self.read_body(64 * 1024)
            try:
                payload = json.loads(body or b"{}")
            except json.JSONDecodeError:
                return self.send_error_json(400, "invalid JSON")
            name = (payload.get("name") or "").strip()
            role = payload.get("role") or "member"
            if not name or role not in ROLE_RANK:
                return self.send_error_json(400, "need name and role in agent|member|admin")
            token = create_key(self.store, name, role)
            return self.send_json({"token": token, "name": name, "role": role}, 201)

        if method == "DELETE" and path.startswith("/api/v1/keys/"):
            if not self.require("admin"):
                return
            try:
                key_id = int(path.rsplit("/", 1)[1])
            except ValueError:
                return self.send_error_json(400, "bad key id")
            with self.store.connect() as db:
                db.execute("UPDATE keys SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
                           (utcnow(), key_id))
                db.commit()
            return self.send_json({"ok": True})

        self.send_error_json(404, "unknown API route")

    # -- API implementations --

    def api_ingest_events(self):
        ident = self.require("agent")
        if not ident:
            return
        body = self.read_body(MAX_EVENTS_BODY)
        if body is None:
            return self.send_error_json(413, "missing or oversized body")
        try:
            records = json.loads(body)
        except (ValueError, RecursionError):  # also over-long literals, deep nesting
            return self.send_error_json(400, "body must be a JSON array of event records")
        if isinstance(records, dict):
            records = [records]
        if not isinstance(records, list):
            return self.send_error_json(400, "body must be a JSON array of event records")
        inserted, duplicates = self.store.ingest_events(records, origin=ident["name"])
        self.send_json({"inserted": inserted, "duplicates": duplicates})

    def api_put_transcript(self, session_id, q):
        ident = self.require("agent")
        if not ident:
            return
        if not SESSION_ID_RE.match(session_id):
            return self.send_error_json(400, "bad session id")
        body = self.read_body(MAX_TRANSCRIPT_BODY)
        if body is None:
            return self.send_error_json(413, "missing or oversized body")
        result = self.store.store_transcript(
            session_id, body, project=q.get("project"), origin=ident["name"])
        self.send_json(result)

    def _json_body(self, max_len=64 * 1024):
        try:
            return json.loads(self.read_body(max_len) or b"{}")
        # ValueError covers JSONDecodeError and over-long integer literals;
        # RecursionError, deeply nested arrays. All are client errors.
        except (ValueError, RecursionError):
            return None

    # -- console auth & user management --

    def api_login(self):
        payload = self._json_body()
        if payload is None:
            return self.send_error_json(400, "invalid JSON")
        username = (payload.get("username") or "").strip()
        password = payload.get("password") or ""
        if not username or not password:
            return self.send_error_json(400, "need username and password")
        if login_throttled(username):
            return self.send_error_json(429, "too many attempts — wait a minute")
        with self.store.connect() as db:
            row = db.execute(
                "SELECT * FROM users WHERE username = ? AND disabled_at IS NULL",
                (username,)).fetchone()
        ok = bool(row) and verify_password(password, row["password_hash"], row["salt"])
        login_result(username, ok)
        if not ok:
            return self.send_error_json(401, "wrong username or password")
        token = open_web_session(self.store, row["id"])
        with self.store.connect() as db:
            scope = user_scope(db, row["id"], row["role"], row["all_projects"])
        self.send_json({"token": token, "name": row["username"], "role": row["role"],
                        "scope": scope,
                        "must_change_password": bool(row["must_change_password"]),
                        "version": VERSION})

    def api_change_password(self):
        ident = self.require("member", allow_must_change=True)
        if not ident:
            return
        if ident["kind"] != "user":
            return self.send_error_json(400, "API keys have no password")
        payload = self._json_body()
        if payload is None:
            return self.send_error_json(400, "invalid JSON")
        current = payload.get("current_password") or ""
        new = payload.get("new_password") or ""
        with self.store.connect() as db:
            row = db.execute("SELECT * FROM users WHERE id = ?",
                             (ident["user_id"],)).fetchone()
        if not verify_password(current, row["password_hash"], row["salt"]):
            return self.send_error_json(401, "current password is wrong")
        if len(new) < MIN_PASSWORD_LEN:
            return self.send_error_json(400, f"new password needs >= {MIN_PASSWORD_LEN} chars")
        if new == current:
            return self.send_error_json(400, "new password must differ from the current one")
        set_password(self.store, ident["user_id"], new, must_change=False)
        token = open_web_session(self.store, ident["user_id"])  # old sessions were revoked
        self.send_json({"ok": True, "token": token})

    def api_create_user(self):
        ident = self.require("admin")
        if not ident:
            return
        payload = self._json_body()
        if payload is None:
            return self.send_error_json(400, "invalid JSON")
        username = (payload.get("username") or "").strip().lower()
        role = payload.get("role") or "member"
        if not re.fullmatch(r"[a-z0-9._-]{2,40}", username) or role not in ("member", "admin"):
            return self.send_error_json(400, "need username [a-z0-9._-]{2,40} and role member|admin")
        scope = parse_scope(payload, default=(False, []))
        if scope is None:
            return self.send_error_json(400, self.SCOPE_HELP)
        all_projects, projects = scope
        temp_password = secrets.token_urlsafe(9)
        try:
            create_user(self.store, username, temp_password, role, must_change=True,
                        all_projects=all_projects, projects=projects,
                        granted_by=ident["name"])
        except sqlite3.IntegrityError:
            return self.send_error_json(409, "username already exists")
        self.send_json({"username": username, "role": role,
                        "temp_password": temp_password}, 201)

    def api_users(self):
        with self.store.connect() as db:
            rows = db.execute(
                """SELECT id, username, role, must_change_password,
                          created_at, last_login_at, disabled_at, all_projects
                   FROM users ORDER BY created_at""").fetchall()
            grants = {}
            for g in db.execute("SELECT user_id, project FROM user_projects ORDER BY project"):
                grants.setdefault(g["user_id"], []).append(g["project"])
        out = []
        for r in rows:
            d = dict(r)
            d["all_projects"] = r["role"] == "admin" or bool(r["all_projects"])
            d["projects"] = [] if d["all_projects"] else grants.get(r["id"], [])
            out.append(d)
        return out

    SCOPE_HELP = ('need {"all": true} or {"projects": [names]} '
                  f"(letters, digits, . _ - max 64 each, at most {MAX_SCOPE_NAMES})")

    def api_set_scope(self, user_id: int):
        ident = self.require("admin")
        if not ident:
            return
        payload = self._json_body()
        if not isinstance(payload, dict):
            return self.send_error_json(400, "invalid JSON")
        scope = parse_scope(payload)
        if scope is None:
            return self.send_error_json(400, self.SCOPE_HELP)
        all_projects, projects = scope
        with self.store.connect() as db:
            row = db.execute("SELECT id, username, role FROM users WHERE id = ?",
                             (user_id,)).fetchone()
            if not row:
                return self.send_error_json(404, "unknown user")
            if row["role"] == "admin":
                return self.send_error_json(400, "admins always see every project")
            db.execute("UPDATE users SET all_projects = ? WHERE id = ?",
                       (1 if all_projects else 0, user_id))
            db.execute("DELETE FROM user_projects WHERE user_id = ?", (user_id,))
            db.executemany(
                """INSERT INTO user_projects (user_id, project, granted_at, granted_by)
                   VALUES (?,?,?,?)""",
                [(user_id, name, utcnow(), ident["name"]) for name in projects])
            db.commit()
        # The audit trail for grants is the server log (Principle 8).
        self.log_message("scope %s <- %s by %s", row["username"],
                         "all projects" if all_projects else (",".join(projects) or "(none)"),
                         ident["name"])
        self.send_json({"username": row["username"], "all_projects": all_projects,
                        "projects": projects})

    def api_reset_user(self, user_id: int):
        if not self.require("admin"):
            return
        with self.store.connect() as db:
            row = db.execute("SELECT id, username FROM users WHERE id = ?",
                             (user_id,)).fetchone()
        if not row:
            return self.send_error_json(404, "unknown user")
        temp_password = secrets.token_urlsafe(9)
        set_password(self.store, user_id, temp_password, must_change=True)
        with self.store.connect() as db:
            db.execute("UPDATE users SET disabled_at = NULL WHERE id = ?", (user_id,))
            db.commit()
        self.send_json({"username": row["username"], "temp_password": temp_password})

    def api_disable_user(self, user_id: int):
        ident = self.require("admin")
        if not ident:
            return
        if ident.get("user_id") == user_id:
            return self.send_error_json(400, "you cannot disable your own account")
        with self.store.connect() as db:
            active_admins = db.execute(
                "SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled_at IS NULL"
            ).fetchone()["n"]
            row = db.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
            if not row:
                return self.send_error_json(404, "unknown user")
            if row["role"] == "admin" and active_admins <= 1:
                return self.send_error_json(400, "cannot disable the last admin")
            db.execute("UPDATE users SET disabled_at = ? WHERE id = ?",
                       (utcnow(), user_id))
            db.execute("DELETE FROM web_sessions WHERE user_id = ?", (user_id,))
            db.commit()
        self.send_json({"ok": True})

    # -- registered projects (visual onboarding) --

    def api_projects_manage(self, ident):
        frag, params = scope_sql(ident, "p.name")
        with self.store.connect() as db:
            rows = db.execute(
                f"""SELECT p.id, p.name, p.created_at, p.created_by, p.agent_token,
                          k.revoked_at AS key_revoked,
                          (SELECT COUNT(*) FROM sessions s WHERE s.project = p.name) AS sessions,
                          (SELECT MAX(last_ts) FROM sessions s WHERE s.project = p.name) AS last_ts
                   FROM projects p LEFT JOIN keys k ON k.id = p.key_id
                   {('WHERE ' + frag) if frag else ''}
                   ORDER BY p.created_at DESC""", params).fetchall()
        return [dict(r) for r in rows]

    def api_create_project(self):
        ident = self.require("member")
        if not ident:
            return
        payload = self._json_body()
        if payload is None:
            return self.send_error_json(400, "invalid JSON")
        name = (payload.get("name") or "").strip()
        if not PROJECT_NAME_RE.match(name):
            return self.send_error_json(400, "project name: letters, digits, . _ - (max 64)")
        token = new_token()
        with self.store.connect() as db:
            # Registration self-grants (AC9), so for a scoped member a name
            # that already carries data — registered or not, registration
            # removed or not — is taken: otherwise registering it would hand
            # her every session of that project.
            if ident["scope"] is not None and db.execute(
                    "SELECT 1 FROM sessions WHERE project = ? LIMIT 1", (name,)).fetchone():
                return self.send_error_json(409, "project already registered")
            try:
                cur = db.execute(
                    "INSERT INTO keys (token_hash, name, role, created_at) VALUES (?,?,?,?)",
                    (hash_token(token), f"project:{name}", "agent", utcnow()))
                db.execute(
                    """INSERT INTO projects (name, created_at, created_by, key_id, agent_token)
                       VALUES (?,?,?,?,?)""",
                    (name, utcnow(), ident["name"], cur.lastrowid, token))
                # Whoever registers a project must be able to hand out its
                # install prompt (AC9). Same transaction: a 409 grants nothing.
                if ident["kind"] == "user" and ident["scope"] is not None:
                    db.execute(
                        """INSERT OR IGNORE INTO user_projects
                           (user_id, project, granted_at, granted_by) VALUES (?,?,?,?)""",
                        (ident["user_id"], name, utcnow(), ident["name"]))
                db.commit()
            except sqlite3.IntegrityError:
                # The connection's context manager would commit the key
                # inserted above even though the registration failed.
                db.rollback()
                return self.send_error_json(409, "project already registered")
        self.send_json({"name": name, "agent_token": token}, 201)

    def api_rotate_project(self, project_id: int):
        ident = self.require("member")
        if not ident:
            return
        token = new_token()
        frag, params = scope_sql(ident, "name")
        with self.store.connect() as db:
            row = db.execute(
                "SELECT * FROM projects WHERE id = ?" + (f" AND {frag}" if frag else ""),
                [project_id] + params).fetchone()
            if not row:
                return self.send_error_json(404, "unknown project")
            if row["key_id"]:
                db.execute("UPDATE keys SET revoked_at = ? WHERE id = ?",
                           (utcnow(), row["key_id"]))
            cur = db.execute(
                "INSERT INTO keys (token_hash, name, role, created_at) VALUES (?,?,?,?)",
                (hash_token(token), f"project:{row['name']}", "agent", utcnow()))
            db.execute("UPDATE projects SET key_id = ?, agent_token = ? WHERE id = ?",
                       (cur.lastrowid, token, project_id))
            db.commit()
        self.send_json({"name": row["name"], "agent_token": token})

    def api_delete_project(self, project_id: int):
        if not self.require("admin"):
            return
        with self.store.connect() as db:
            row = db.execute("SELECT * FROM projects WHERE id = ?",
                             (project_id,)).fetchone()
            if not row:
                return self.send_error_json(404, "unknown project")
            if row["key_id"]:
                db.execute("UPDATE keys SET revoked_at = ? WHERE id = ?",
                           (utcnow(), row["key_id"]))
            db.execute("DELETE FROM projects WHERE id = ?", (project_id,))
            db.commit()
        # Registration + key are gone; already-ingested trace data is kept.
        self.send_json({"ok": True})

    # -- models and prices --

    def api_models(self, ident):
        """The most-used models seen in the data plus every priced model, so
        admins can see which models still need a price. `omitted` counts seen
        models beyond MAX_MODEL_ROWS. model_turns has no project column, so a
        scoped caller joins sessions; everyone else keeps the single-table scan."""
        frag, sp = scope_sql(ident, "s.project")
        src = "model_turns mt" + (" JOIN sessions s ON s.session_id = mt.session_id" if frag else "")
        scoped = f" WHERE {frag}" if frag else ""
        stats = f"""SELECT mt.model AS model, COUNT(*) AS turns,
                           COUNT(DISTINCT mt.session_id) AS sessions, MAX(mt.ts) AS last_ts
                    FROM {src}"""
        with self.store.connect() as db:
            top = {r["model"]: dict(r) for r in db.execute(
                stats + scoped + " GROUP BY mt.model ORDER BY turns DESC, mt.model LIMIT ?",
                sp + [MAX_MODEL_ROWS])}
            seen_total = db.execute(
                f"SELECT COUNT(DISTINCT mt.model) AS n FROM {src}{scoped}", sp).fetchone()["n"]
            prices = load_prices(db)
            # A priced model below the top rows still needs its real usage, and
            # must not be counted as omitted while it is listed.
            priced_rest = [m for m in prices if m not in top]
            seen = dict(top)
            for i in range(0, len(priced_rest), 500):  # stay under SQLite's variable limit
                chunk = priced_rest[i:i + 500]
                seen.update({r["model"]: dict(r) for r in db.execute(
                    stats + f" WHERE mt.model IN ({','.join('?' for _ in chunk)})"
                    + (f" AND {frag}" if frag else "") + " GROUP BY mt.model",
                    chunk + sp)})
        listed = []
        for model in set(seen) | set(prices):
            entry = seen.get(model) or {"model": model, "turns": 0, "sessions": 0,
                                        "last_ts": None}
            price = prices.get(model)
            entry["price"] = ({k: v for k, v in price.items() if k != "model"}
                              if price else None)
            listed.append(entry)
        listed.sort(key=lambda e: (-e["turns"], e["model"]))
        return {"models": listed, "omitted": max(0, seen_total - len(seen))}

    def api_set_price(self):
        ident = self.require("admin")
        if not ident:
            return
        payload = self._json_body()
        if not isinstance(payload, dict):
            return self.send_error_json(400, "body must be a JSON object")
        model = payload.get("model")
        if (not isinstance(model, str) or not model or len(model) > MAX_MODEL_NAME
                or model in PLACEHOLDER_MODELS):
            return self.send_error_json(
                400, f"model must name a real model in 1-{MAX_MODEL_NAME} characters")
        values = []
        for field in PRICE_FIELDS:
            value = payload.get(field)
            # Range before isfinite: isfinite raises on ints too big for a float.
            if (isinstance(value, bool) or not isinstance(value, (int, float))
                    or (isinstance(value, float) and not math.isfinite(value))
                    or not 0 <= value <= MAX_PRICE_PER_MTOK):
                return self.send_error_json(
                    400, f"{field} must be a number from 0 to {MAX_PRICE_PER_MTOK} "
                         "(USD per million tokens)")
            values.append(float(value))
        entry = {"model": model, **dict(zip(PRICE_FIELDS, values)),
                 "updated_at": utcnow(), "updated_by": ident["name"]}
        with self.store.connect() as db:
            db.execute(
                f"""INSERT INTO model_prices ({','.join(entry)})
                    VALUES ({','.join('?' for _ in entry)})
                    ON CONFLICT(model) DO UPDATE SET
                    {', '.join(f'{k} = excluded.{k}' for k in entry if k != 'model')}""",
                list(entry.values()))
            db.commit()
        self.send_json(entry)

    def api_clear_price(self, q):
        if not self.require("admin"):
            return
        model = q.get("model")
        if not model or len(model) > MAX_MODEL_NAME:
            return self.send_error_json(400, f"need ?model= of 1-{MAX_MODEL_NAME} characters")
        with self.store.connect() as db:
            cur = db.execute("DELETE FROM model_prices WHERE model = ?", (model,))
            db.commit()
        if not cur.rowcount:
            return self.send_error_json(404, "no price for that model")
        self.send_json({"ok": True})

    @staticmethod
    def _filters(q, ident, alias=""):
        """Build a WHERE fragment + params from project/from/to query params,
        inside the caller's scope."""
        where, params = [], []
        col = (alias + ".") if alias else ""
        frag, sp = scope_sql(ident, f"{col}project")
        if frag:
            where.append(frag)
            params += sp
        if q.get("project"):
            where.append(f"{col}project = ?")
            params.append(q["project"])
        if q.get("from"):
            where.append(f"{col}ts >= ?")
            params.append(q["from"])
        if q.get("to"):
            where.append(f"{col}ts < ?")
            params.append(q["to"])
        return (" WHERE " + " AND ".join(where)) if where else "", params

    def api_overview(self, q, ident):
        where, params = self._filters(q, ident)
        with self.store.connect() as db:
            totals = db.execute(
                f"""SELECT COUNT(DISTINCT session_id) AS sessions,
                           COUNT(*) AS events,
                           SUM(event = 'prompt.submit') AS prompts,
                           SUM(event = 'tool.call') AS tool_calls,
                           SUM(event = 'tool.fail') AS failures,
                           COUNT(DISTINCT project) AS projects,
                           COUNT(DISTINCT origin) AS origins
                    FROM events{where}""", params).fetchone()
            per_day = db.execute(
                f"""SELECT substr(ts, 1, 10) AS day,
                           SUM(event = 'prompt.submit') AS prompts,
                           SUM(event = 'tool.call') AS tool_calls
                    FROM events{where} GROUP BY day ORDER BY day""", params).fetchall()
            top_tools = db.execute(
                f"""SELECT tool_name AS tool, COUNT(*) AS n FROM events
                    {where + (' AND ' if where else ' WHERE ')}
                    event = 'tool.call' AND tool_name IS NOT NULL
                    GROUP BY tool_name ORDER BY n DESC LIMIT 12""", params).fetchall()
            # Token totals come from transcript snapshots (sessions table).
            swhere, sparams = [], []
            frag, sp = scope_sql(ident, "project")
            if frag:
                swhere.append(frag)
                sparams += sp
            if q.get("project"):
                swhere.append("project = ?")
                sparams.append(q["project"])
            if q.get("from"):
                swhere.append("last_ts >= ?")
                sparams.append(q["from"])
            if q.get("to"):
                swhere.append("first_ts < ?")
                sparams.append(q["to"])
            sw = (" WHERE " + " AND ".join(swhere)) if swhere else ""
            token_cols = ("input_tokens", "output_tokens", "cache_read_tokens",
                          "cache_creation_tokens")
            tokens = db.execute(
                f"""SELECT {', '.join(f'{sum_tokens(c)} AS {c}' for c in token_cols)}
                    FROM sessions{sw}""", sparams).fetchone()
            tokens = {c: int_or_none(tokens[c]) for c in token_cols}
            projects = db.execute(
                f"""SELECT project, COUNT(*) AS sessions, SUM(prompts) AS prompts,
                           SUM(tool_calls) AS tool_calls, SUM(failures) AS failures,
                           MAX(last_ts) AS last_ts
                    FROM sessions{sw} GROUP BY project ORDER BY last_ts DESC""",
                sparams).fetchall()
            origins = db.execute(
                f"""SELECT origin, COUNT(*) AS sessions, SUM(prompts) AS prompts,
                           SUM(tool_calls) AS tool_calls, MAX(last_ts) AS last_ts
                    FROM sessions{sw} GROUP BY origin ORDER BY last_ts DESC""",
                sparams).fetchall()
            models = self._overview_models(db, q, ident)
        return {
            "totals": {**dict(totals), **dict(tokens)},
            "per_day": [dict(r) for r in per_day],
            "top_tools": [dict(r) for r in top_tools],
            "projects": [dict(r) for r in projects],
            "origins": [dict(r) for r in origins],
            "models": models,
        }

    @staticmethod
    def _overview_models(db, q, ident):
        """Per-model statistics for the window. A turn is in the window by its
        own timestamp, so a session crossing the boundary contributes only
        the turns inside it."""
        where, params = [], []
        frag, sp = scope_sql(ident, "s.project")
        if frag:
            where.append(frag)
            params += sp
        if q.get("project"):
            where.append("s.project = ?")
            params.append(q["project"])
        if q.get("from"):
            where.append("mt.ts >= ?")
            params.append(q["from"])
        if q.get("to"):
            where.append("mt.ts < ?")
            params.append(q["to"])
        w = (" WHERE " + " AND ".join(where)) if where else ""
        rows, totals = price_rows(model_usage_rows(db, w, params), load_prices(db))
        for row in rows:
            row["share"] = row["turns"] / totals["turns"]
        # The view's own leaders get the colours (spec AC14). A model can
        # change colour between filters; it is always named in the legend.
        series = [r["model"] for r in rows[:CHART_SERIES]]
        buckets = {}
        for r in db.execute(
                f"""SELECT substr(mt.ts, 1, 10) AS day, mt.model AS model, COUNT(*) AS turns
                    FROM model_turns mt JOIN sessions s ON s.session_id = mt.session_id
                    {w + (' AND ' if w else ' WHERE ')} mt.ts IS NOT NULL
                    GROUP BY day, mt.model""", params):
            key = (r["day"], r["model"] if r["model"] in series else None)
            buckets[key] = buckets.get(key, 0) + r["turns"]
        order = {m: i for i, m in enumerate(series)}
        per_day = [{"day": day, "model": model, "turns": n} for (day, model), n in
                   sorted(buckets.items(),
                          key=lambda kv: (kv[0][0], order.get(kv[0][1], len(series))))]
        # Totals and shares above cover every model; only the listing is cut.
        return {"rows": rows[:MAX_MODEL_ROWS], "models_omitted": max(0, len(rows) - MAX_MODEL_ROWS),
                "series": series, "per_day": per_day, **totals}

    def api_sessions(self, q, ident):
        where, params = [], []
        frag, sp = scope_sql(ident, "project")
        if frag:
            where.append(frag)
            params += sp
        if q.get("project"):
            where.append("project = ?")
            params.append(q["project"])
        if q.get("origin"):
            where.append("origin = ?")
            params.append(q["origin"])
        if q.get("from"):
            where.append("last_ts >= ?")
            params.append(q["from"])
        if q.get("to"):
            where.append("first_ts < ?")
            params.append(q["to"])
        if q.get("q"):
            where.append("session_id LIKE ?")
            params.append(f"%{q['q']}%")
        if q.get("model"):
            where.append("EXISTS (SELECT 1 FROM model_turns mt"
                         " WHERE mt.session_id = sessions.session_id AND mt.model = ?)")
            params.append(q["model"])
        w = (" WHERE " + " AND ".join(where)) if where else ""
        limit = min(int(q.get("limit") or 50), 500)
        offset = max(int(q.get("offset") or 0), 0)
        with self.store.connect() as db:
            total = db.execute(f"SELECT COUNT(*) AS n FROM sessions{w}", params).fetchone()["n"]
            rows = db.execute(
                f"""SELECT * FROM sessions{w}
                    ORDER BY last_ts DESC LIMIT ? OFFSET ?""",
                params + [limit, offset]).fetchall()
        return {"total": total, "sessions": [dict(r) for r in rows]}

    def api_session_detail(self, session_id, ident):
        if not SESSION_ID_RE.match(session_id):
            return self.send_error_json(400, "bad session id")
        frag, sp = scope_sql(ident, "project")
        with self.store.connect() as db:
            # A session outside the scope is "unknown", never "forbidden": an
            # id pasted in chat must not confirm it exists here (AC13).
            sess = db.execute(
                "SELECT * FROM sessions WHERE session_id = ?" + (f" AND {frag}" if frag else ""),
                [session_id] + sp).fetchone()
            if not sess:
                return self.send_error_json(404, "unknown session")
            events = db.execute(
                "SELECT * FROM events WHERE session_id = ? ORDER BY ts",
                (session_id,)).fetchall()
            models, models_total = price_rows(
                model_usage_rows(db, " WHERE mt.session_id = ?", [session_id]),
                load_prices(db))
        self.send_json({
            "session": dict(sess),
            # One hostile transcript can name millions of models; the total
            # still covers them all.
            "models": models[:MAX_MODEL_ROWS],
            "models_omitted": max(0, len(models) - MAX_MODEL_ROWS),
            "models_total": models_total,
            "has_transcript": self.store.transcript_path(session_id) is not None,
            "events": [
                {k: v for k, v in dict(e).items() if v is not None} for e in events
            ],
        })

    def api_get_transcript(self, session_id):
        ident = self.require("member")
        if not ident:
            return
        if not SESSION_ID_RE.match(session_id):
            return self.send_error_json(400, "bad session id")
        p = self.store.transcript_path(session_id)
        if p and ident["scope"] is not None:
            # Same answer as "no snapshot" for a session outside the scope (AC13).
            frag, sp = scope_sql(ident, "project")
            with self.store.connect() as db:
                visible = db.execute(
                    f"SELECT 1 FROM sessions WHERE session_id = ? AND {frag}",
                    [session_id] + sp).fetchone()
            if not visible:
                p = None
        if not p:
            return self.send_error_json(404, "no transcript snapshot for this session")
        data = p.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson; charset=utf-8")
        self.send_header("Content-Disposition",
                         f'attachment; filename="{session_id}.jsonl"')
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def api_export(self, q):
        ident = self.require("member")
        if not ident:
            return
        fmt = q.get("format") or "jsonl"
        if fmt not in ("jsonl", "csv"):
            return self.send_error_json(400, "format must be jsonl or csv")
        where, params = [], []
        frag, sp = scope_sql(ident, "project")
        if frag:
            where.append(frag)
            params += sp
        if q.get("project"):
            where.append("project = ?")
            params.append(q["project"])
        if q.get("session"):
            where.append("session_id = ?")
            params.append(q["session"])
        if q.get("origin"):
            where.append("origin = ?")
            params.append(q["origin"])
        if q.get("from"):
            where.append("ts >= ?")
            params.append(q["from"])
        if q.get("to"):
            where.append("ts < ?")
            params.append(q["to"])
        if q.get("event"):
            where.append("event = ?")
            params.append(q["event"])
        w = (" WHERE " + " AND ".join(where)) if where else ""
        with self.store.connect() as db:
            rows = db.execute(
                f"SELECT * FROM events{w} ORDER BY ts", params).fetchall()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if fmt == "jsonl":
            out = "\n".join(
                json.dumps({k: v for k, v in dict(r).items() if v is not None},
                           ensure_ascii=False)
                for r in rows)
            body = (out + "\n").encode("utf-8") if out else b""
            ctype = "application/x-ndjson; charset=utf-8"
            fname = f"gaide-trace-events-{stamp}.jsonl"
        else:
            buf = io.StringIO()
            writer = csv.DictWriter(buf, fieldnames=EVENT_COLUMNS, extrasaction="ignore")
            writer.writeheader()
            for r in rows:
                writer.writerow(dict(r))
            body = buf.getvalue().encode("utf-8")
            ctype = "text/csv; charset=utf-8"
            fname = f"gaide-trace-events-{stamp}.csv"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Disposition", f'attachment; filename="{fname}"')
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # -- static web console --

    STATIC_TYPES = {".html": "text/html; charset=utf-8",
                    ".css": "text/css; charset=utf-8",
                    ".js": "application/javascript; charset=utf-8",
                    ".svg": "image/svg+xml"}

    def serve_static(self, path):
        if path in ("/", "/index.html") or path.startswith("/#"):
            path = "/index.html"
        name = Path(path.lstrip("/")).name  # flat dir; defeats traversal
        f = self.webui_dir / name
        ext = f.suffix.lower()
        if not f.is_file() or ext not in self.STATIC_TYPES:
            return self.send_error_json(404, "not found")
        data = f.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", self.STATIC_TYPES[ext])
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)


# ---------------------------------------------------------------- CLI


def serve(args):
    data_dir = Path(args.data).resolve()
    store = Store(data_dir)
    Handler.store = store
    Handler.webui_dir = Path(__file__).resolve().parent / "webui"

    # First-run bootstrap: default console account. The console forces a
    # password change on the first login, so admin/admin never survives it.
    with store.connect() as db:
        has_user = db.execute("SELECT 1 FROM users LIMIT 1").fetchone()
    if not has_user:
        create_user(store, "admin", "admin", "admin", must_change=True)
        print("=" * 64, flush=True)
        print("  First run — sign in to the console with admin / admin.", flush=True)
        print("  You will be required to set a new password immediately.", flush=True)
        print("=" * 64, flush=True)

    # Before binding: re-derivation rewrites session rows that live ingest
    # would otherwise race with.
    rederived = store.rederive_if_stale(progress=lambda done, total: print(
        f"re-deriving index: {done}/{total} transcripts", flush=True))
    if rederived:
        print(f"derived-index schema {rederived['from']} -> {rederived['to']}: "
              f"{rederived['transcripts']} transcripts re-indexed in "
              f"{rederived['seconds']}s", flush=True)
        if rederived["failed"]:
            print(f"WARNING: {len(rederived['failed'])} sessions could not be re-derived "
                  "(logged above); they re-derive on their next transcript upload "
                  "or rebuild-index", flush=True)

    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    httpd.daemon_threads = True
    print(f"GAIDE-Trace server v{VERSION}", flush=True)
    print(f"  data:    {data_dir}", flush=True)
    print(f"  console: http://{args.host}:{args.port}/", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


def main():
    parser = argparse.ArgumentParser(description="GAIDE-Trace team server")
    parser.add_argument("--data", default=os.environ.get("GAIDE_TRACE_SERVER_DATA", "./data"))
    sub = parser.add_subparsers(dest="cmd")

    p_serve = sub.add_parser("serve", help="run the server (default)")
    p_serve.add_argument("--host", default=os.environ.get("GAIDE_TRACE_SERVER_HOST", "0.0.0.0"))
    p_serve.add_argument("--port", type=int,
                         default=int(os.environ.get("GAIDE_TRACE_SERVER_PORT", "8321")))

    p_key = sub.add_parser("key", help="manage API keys")
    key_sub = p_key.add_subparsers(dest="key_cmd", required=True)
    p_create = key_sub.add_parser("create")
    p_create.add_argument("--name", required=True)
    p_create.add_argument("--role", choices=["agent", "member", "admin"], default="member")
    key_sub.add_parser("list")
    p_revoke = key_sub.add_parser("revoke")
    p_revoke.add_argument("id", type=int)

    p_user = sub.add_parser("user", help="manage console accounts")
    user_sub = p_user.add_subparsers(dest="user_cmd", required=True)
    user_sub.add_parser("list")
    p_ureset = user_sub.add_parser("reset", help="reset a password (lockout recovery)")
    p_ureset.add_argument("username")

    sub.add_parser("rebuild-index", help="rebuild SQLite index from the JSONL archive")

    args = parser.parse_args()
    if args.cmd in (None, "serve"):
        if args.cmd is None:  # bare invocation: behave like `serve` with defaults
            args.host = os.environ.get("GAIDE_TRACE_SERVER_HOST", "0.0.0.0")
            args.port = int(os.environ.get("GAIDE_TRACE_SERVER_PORT", "8321"))
        return serve(args)

    store = Store(Path(args.data).resolve())
    if args.cmd == "key":
        if args.key_cmd == "create":
            token = create_key(store, args.name, args.role)
            print(f"{args.name} ({args.role}): {token}")
        elif args.key_cmd == "list":
            with store.connect() as db:
                for r in db.execute("SELECT id, name, role, created_at, last_seen_at, revoked_at FROM keys"):
                    status = "revoked" if r["revoked_at"] else "active"
                    print(f"[{r['id']}] {r['name']:<20} {r['role']:<8} {status:<8} "
                          f"created {r['created_at']}  last seen {r['last_seen_at'] or '-'}")
        elif args.key_cmd == "revoke":
            with store.connect() as db:
                db.execute("UPDATE keys SET revoked_at = ? WHERE id = ?", (utcnow(), args.id))
                db.commit()
            print(f"key {args.id} revoked")
    elif args.cmd == "user":
        if args.user_cmd == "list":
            with store.connect() as db:
                for r in db.execute("SELECT * FROM users ORDER BY created_at"):
                    status = "disabled" if r["disabled_at"] else (
                        "must-change-pw" if r["must_change_password"] else "active")
                    print(f"[{r['id']}] {r['username']:<20} {r['role']:<8} {status:<15} "
                          f"last login {r['last_login_at'] or '-'}")
        elif args.user_cmd == "reset":
            with store.connect() as db:
                row = db.execute("SELECT id FROM users WHERE username = ?",
                                 (args.username,)).fetchone()
            if not row:
                sys.exit(f"error: no user '{args.username}'")
            temp = secrets.token_urlsafe(9)
            set_password(store, row["id"], temp, must_change=True)
            with store.connect() as db:
                db.execute("UPDATE users SET disabled_at = NULL WHERE id = ?",
                           (row["id"],))
                db.commit()
            print(f"temporary password for {args.username}: {temp}")
            print("(they must set a new one on the next login)")
    elif args.cmd == "rebuild-index":
        n = store.rebuild_index()
        print(f"index rebuilt: {n} events")


if __name__ == "__main__":
    main()
