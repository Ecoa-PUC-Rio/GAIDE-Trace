"""Store-level derivation of transcript and model usage — specs/model-usage."""

import hashlib
import os
import shutil
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from fixtures import assistant_lines, event, load_server, transcript, usage, user_line

server = load_server()

T0 = "2026-09-01T10:00:00.000Z"


def file_digests(root: Path):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(root.rglob("*.jsonl"))}


class StoreTestCase(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="gaide-trace-test-"))
        self.store = server.Store(self.tmp)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def session_row(self, session_id):
        with self.store.connect() as db:
            return dict(db.execute("SELECT * FROM sessions WHERE session_id = ?",
                                   (session_id,)).fetchone())


class DerivedVersionUpgrade(StoreTestCase):
    """AC24 (token-totals part): an index derived by older rules is corrected
    on start without touching the archive or the transcript snapshots."""

    def seed_v031_index(self):
        self.store.ingest_events(
            [event("sess-a", "prompt.submit", T0, prompt="hi")], origin="alice")
        self.store.store_transcript(
            "sess-a",
            transcript(user_line("hi", T0),
                       assistant_lines("claude-opus-5", usage(output_tokens=500), T0,
                                       blocks=3)),
            project="p", origin="alice")
        self.assertEqual(self.session_row("sess-a")["output_tokens"], 500)
        # What v0.3.1 left behind: per-line sums and no derived_version.
        with self.store.connect() as db:
            db.execute("UPDATE sessions SET output_tokens = 1500 WHERE session_id = 'sess-a'")
            db.execute("DELETE FROM meta")
            db.commit()

    def test_stale_index_is_rederived_and_files_are_untouched(self):
        self.seed_v031_index()
        before = file_digests(self.tmp)
        self.assertTrue(before, "fixture should have written archive + transcript files")

        summary = server.Store(self.tmp).rederive_if_stale()

        self.assertIsNotNone(summary)
        self.assertEqual(summary["to"], server.DERIVED_VERSION)
        self.assertEqual(summary["transcripts"], 1)
        self.assertEqual(self.session_row("sess-a")["output_tokens"], 500)
        self.assertEqual(self.store.derived_version(), server.DERIVED_VERSION)
        self.assertEqual(file_digests(self.tmp), before)

    def test_rederivation_keeps_the_upload_time_of_each_transcript(self):
        self.seed_v031_index()
        snapshot = self.tmp / "transcripts" / "sess-a.jsonl"
        os.utime(snapshot, (1_000_000_000, 1_000_000_000))

        self.store.rederive_if_stale()

        self.assertEqual(self.session_row("sess-a")["transcript_updated_at"],
                         "2001-09-09T01:46:40+00:00")

    def test_corrupted_version_value_is_treated_as_stale(self):
        self.seed_v031_index()
        with self.store.connect() as db:
            db.execute("INSERT INTO meta (key, value) VALUES ('derived_version', 'garbage')")
            db.commit()
        self.assertEqual(self.store.derived_version(), 0)
        self.assertIsNotNone(self.store.rederive_if_stale())
        self.assertEqual(self.session_row("sess-a")["output_tokens"], 500)

    def test_fresh_data_directory_is_not_reported_as_an_upgrade(self):
        self.assertIsNone(self.store.rederive_if_stale())
        self.assertEqual(self.store.derived_version(), server.DERIVED_VERSION)

    def test_current_index_is_left_alone(self):
        self.seed_v031_index()
        self.store.rederive_if_stale()
        self.assertIsNone(self.store.rederive_if_stale())

    def test_rebuild_index_does_not_rewrite_transcripts(self):
        self.seed_v031_index()
        snapshot = self.tmp / "transcripts" / "sess-a.jsonl"
        os.utime(snapshot, (1_000_000_000, 1_000_000_000))
        before = file_digests(self.tmp)

        self.store.rebuild_index()

        self.assertEqual(snapshot.stat().st_mtime, 1_000_000_000)
        self.assertEqual(file_digests(self.tmp), before)
        self.assertEqual(self.session_row("sess-a")["output_tokens"], 500)
        self.assertEqual(self.store.derived_version(), server.DERIVED_VERSION)



def models_by_name(rows):
    return {r["model"]: r for r in rows}


class SessionModelUsage(StoreTestCase):
    """AC4–AC7, AC25, AC30 at the store level."""

    def upload(self, session_id, *groups, project="p"):
        self.store.store_transcript(session_id, transcript(*groups), project, "alice")

    def model_turn_events(self, session_id, model, n, ts=T0):
        return [event(session_id, "model.turn", ts, source="antigravity",
                      model=model, native_event="step.15") for _ in range(n)]

    def test_ac4_per_model_sums_match_session_totals(self):
        self.upload(
            "s1",
            assistant_lines("claude-opus-5", usage(10, 100, 1000, 50), T0, blocks=3),
            assistant_lines("claude-opus-5", usage(20, 200, 2000, 0), T0, blocks=2),
            assistant_lines("claude-sonnet-5", usage(1, 5, 0, 7), T0),
            assistant_lines("<synthetic>", usage(0, 0), T0),
        )
        rows = models_by_name(self.store.session_models("s1"))
        self.assertEqual(set(rows), {"claude-opus-5", "claude-sonnet-5"})
        opus = rows["claude-opus-5"]
        self.assertEqual((opus["turns"], opus["input_tokens"], opus["output_tokens"],
                          opus["cache_read_tokens"], opus["cache_write_5m_tokens"]),
                         (2, 30, 300, 3000, 50))
        self.assertEqual(opus["source"], "transcript")
        session = self.session_row("s1")
        for col in ("input_tokens", "output_tokens", "cache_read_tokens"):
            self.assertEqual(sum(r[col] for r in rows.values()), session[col])
        self.assertEqual(sum(r["cache_write_5m_tokens"] + r["cache_write_1h_tokens"]
                             for r in rows.values()), session["cache_creation_tokens"])
        self.assertEqual((session["dominant_model"], session["model_count"]),
                         ("claude-opus-5", 2))

    def test_ac5_events_only_session_counts_turns_and_unknown_tokens(self):
        self.store.ingest_events(self.model_turn_events("ag", "gemini-3.7-flash", 12),
                                 origin="bob")
        (row,) = self.store.session_models("ag")
        self.assertEqual((row["model"], row["turns"], row["source"]),
                         ("gemini-3.7-flash", 12, "events"))
        for col in ("input_tokens", "output_tokens", "cache_read_tokens",
                    "cache_write_5m_tokens", "cache_write_1h_tokens"):
            self.assertIsNone(row[col], col)
        self.assertEqual(self.session_row("ag")["dominant_model"], "gemini-3.7-flash")

    def test_model_turn_events_without_a_real_model_are_ignored(self):
        self.store.ingest_events(
            [event("ag", "model.turn", T0), *self.model_turn_events("ag", "<synthetic>", 2)],
            origin="bob")
        self.assertEqual(self.store.session_models("ag"), [])
        self.assertEqual(self.session_row("ag")["model_count"], 0)

    def test_ac6_transcript_wins_when_events_arrive_first(self):
        self.store.ingest_events(self.model_turn_events("s1", "event-model", 5), origin="a")
        self.upload("s1", assistant_lines("claude-opus-5", usage(output_tokens=1), T0))
        self.assertEqual([r["model"] for r in self.store.session_models("s1")],
                         ["claude-opus-5"])

    def test_ac6_transcript_wins_when_events_arrive_later(self):
        self.upload("s1", assistant_lines("claude-opus-5", usage(output_tokens=1), T0))
        self.store.ingest_events(self.model_turn_events("s1", "event-model", 5), origin="a")
        rows = self.store.session_models("s1")
        self.assertEqual([(r["model"], r["turns"]) for r in rows], [("claude-opus-5", 1)])
        self.assertEqual(self.session_row("s1")["model_count"], 1)

    def test_transcript_without_models_falls_back_to_events(self):
        self.store.ingest_events(self.model_turn_events("s1", "gemini-3.7-flash", 3), origin="a")
        self.upload("s1", user_line("only a user line", T0))
        (row,) = self.store.session_models("s1")
        self.assertEqual((row["model"], row["turns"], row["source"]),
                         ("gemini-3.7-flash", 3, "events"))

    def test_ac7_reupload_replaces_model_usage(self):
        self.upload("s1",
                    assistant_lines("claude-opus-5", usage(output_tokens=10), T0),
                    assistant_lines("claude-sonnet-5", usage(output_tokens=10), T0))
        self.upload("s1", assistant_lines("claude-opus-5", usage(output_tokens=4), T0))
        rows = self.store.session_models("s1")
        self.assertEqual([(r["model"], r["turns"], r["output_tokens"]) for r in rows],
                         [("claude-opus-5", 1, 4)])

    def test_ac7_duplicate_events_do_not_change_model_usage(self):
        batch = self.model_turn_events("ag", "gemini-3.7-flash", 4)
        self.store.ingest_events(batch, origin="bob")
        inserted, duplicates = self.store.ingest_events(batch, origin="bob")
        self.assertEqual((inserted, duplicates), (0, 4))
        self.assertEqual(self.store.session_models("ag")[0]["turns"], 4)

    def test_dominant_model_ties_break_by_output_tokens_then_name(self):
        self.upload("s1",
                    assistant_lines("model-b", usage(output_tokens=1), T0),
                    assistant_lines("model-a", usage(output_tokens=9), T0))
        self.assertEqual(self.session_row("s1")["dominant_model"], "model-a")
        self.upload("s2",
                    assistant_lines("model-b", usage(output_tokens=5), T0),
                    assistant_lines("model-a", usage(output_tokens=5), T0))
        self.assertEqual(self.session_row("s2")["dominant_model"], "model-a")

    def test_premium_turns_are_counted_per_model(self):
        self.upload("s1",
                    assistant_lines("claude-opus-5", usage(speed="fast"), T0),
                    assistant_lines("claude-opus-5", usage(), T0))
        self.assertEqual(self.store.session_models("s1")[0]["premium_turns"], 1)

    def test_ac30_overlong_event_model_names_are_truncated(self):
        self.store.ingest_events(self.model_turn_events("ag", "g" * 4000, 1), origin="b")
        self.assertEqual(self.store.session_models("ag")[0]["model"],
                         "g" * server.MAX_MODEL_NAME)

    def test_hostile_event_timestamps_do_not_fail_the_batch(self):
        good = event("ag", "prompt.submit", T0, prompt="kept")
        hostile = self.model_turn_events("ag", "gemini-3.7-flash", 1,
                                         ts="0001-01-01T00:00:00+05:00")
        inserted, _ = self.store.ingest_events([good, *hostile], origin="bob")
        self.assertEqual(inserted, 2)
        (row,) = self.store.session_models("ag")
        self.assertEqual((row["turns"], row["first_ts"]), (1, None))

    def test_rederivation_logs_and_skips_a_transcript_it_cannot_index(self):
        self.upload("bad", assistant_lines("claude-opus-5", usage(output_tokens=1), T0))
        self.upload("good", assistant_lines("claude-opus-5", usage(output_tokens=2), T0))
        with self.store.connect() as db:
            db.execute("DELETE FROM model_turns")
            db.execute("DELETE FROM meta")
            db.commit()
        real = server.transcript_turns

        # Passes `on_line` through: the exposure scan rides this same parse
        # (specs/security-scan), and a stub that drops it would fail every
        # session instead of the one this test breaks on purpose.
        def explode_on_bad(source, on_line=None):
            if b"output_tokens\": 1" in source.read():
                raise RuntimeError("synthetic parser failure")
            source.seek(0)
            return real(source, on_line=on_line)

        with mock.patch.object(server, "transcript_turns", side_effect=explode_on_bad), \
                mock.patch("sys.stderr") as stderr:
            summary = self.store.rederive_if_stale()
        self.assertEqual(summary["failed"], ["bad"])
        self.assertIn("bad", "".join(str(c) for c in stderr.write.call_args_list))
        self.assertEqual(self.store.session_models("good")[0]["output_tokens"], 2)
        self.assertEqual(self.store.derived_version(), server.DERIVED_VERSION)

    def test_ac25_rebuild_index_reproduces_model_usage(self):
        self.upload("s1",
                    assistant_lines("claude-opus-5", usage(3, 30, 300, 30, 10, 20), T0, blocks=2),
                    assistant_lines("claude-sonnet-5", usage(1, 2, speed="fast"), T0))
        self.store.ingest_events(
            [event("s1", "prompt.submit", T0, prompt="hi"),
             *self.model_turn_events("s1", "ignored-because-transcript", 2),
             *self.model_turn_events("ag", "gemini-3.7-flash", 6)], origin="bob")

        def snapshot():
            with self.store.connect() as db:
                sessions = {r["session_id"]: (r["dominant_model"], r["model_count"],
                                              r["output_tokens"])
                            for r in db.execute("SELECT * FROM sessions")}
            return sessions, {sid: self.store.session_models(sid) for sid in sessions}

        live = snapshot()
        self.store.rebuild_index()
        self.assertEqual(snapshot(), live)

    def test_ac24_stale_index_gains_model_usage_on_start(self):
        self.upload("s1", assistant_lines("claude-opus-5", usage(output_tokens=8), T0))
        self.store.ingest_events(self.model_turn_events("ag", "gemini-3.7-flash", 2),
                                 origin="bob")
        with self.store.connect() as db:  # an index derived by schema 2
            db.execute("DELETE FROM model_turns")
            db.execute("UPDATE sessions SET dominant_model = NULL, model_count = 0")
            db.execute("UPDATE meta SET value = '2' WHERE key = 'derived_version'")
            db.commit()

        self.assertIsNotNone(self.store.rederive_if_stale())

        self.assertEqual(self.session_row("s1")["dominant_model"], "claude-opus-5")
        self.assertEqual(self.store.session_models("ag")[0]["turns"], 2)


if __name__ == "__main__":
    unittest.main()
