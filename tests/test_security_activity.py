"""Security activity and coverage — specs/security-scan, Sprint 2 (AC8-AC14, AC33).

The activity half reads the ledger's own tool calls: which scanners ran, with
what outcome, and — the point of it — which code-touching sessions ran none.
"""

import json
import unittest
from unittest import mock

from fixtures import fake, load_server
from test_security_scan import StoreCase

server = load_server()
scan = server.security_scan


def call(command=None, tool_name="Bash", event="tool.call", response=None, **payload):
    """One tool-call event, shaped the way an adapter ships it."""
    if command is not None:
        payload["command"] = command
    return {"trace_id": "t1", "ts": "2026-10-14T10:00:00Z", "event": event,
            "session_id": "s1", "project": "app", "tool_name": tool_name,
            "tool_input": json.dumps(payload) if payload else None,
            "tool_response": response}


def classify(**kw):
    return {(a["category"], a["tool"]) for a in scan.classify_tool_call(call(**kw))}


class TestActivityCatalogue(unittest.TestCase):
    """AC8 — categories and tools, read from the invoked command."""

    def test_one_tool_per_category(self):
        cases = {
            "semgrep scan --config p/security-audit .": ("sast", "semgrep"),
            "bandit -r server/": ("sast", "bandit"),
            "osv-scanner scan -r .": ("sca", "osv-scanner"),
            "npm audit --json": ("sca", "npm-audit"),
            "pip-audit -r requirements.txt": ("sca", "pip-audit"),
            "cargo audit": ("sca", "cargo-audit"),
            "gitleaks detect --no-git --redact": ("secrets", "gitleaks"),
            "trufflehog filesystem .": ("secrets", "trufflehog"),
            "checkov -d deploy/": ("iac", "checkov"),
            "tfsec deploy/aws": ("iac", "tfsec"),
            "trivy image gaide-trace:latest": ("container", "trivy"),
            "grype dir:.": ("container", "grype"),
            "nuclei -u https://staging.example.com": ("dast", "nuclei"),
            "syft dir:. -o cyclonedx-json": ("supply-chain", "syft"),
            "pre-commit run --all-files": ("review", "pre-commit"),
        }
        for command, expected in cases.items():
            with self.subTest(command=command):
                self.assertIn(expected, classify(command=command))

    def test_subcommands_pick_the_right_category(self):
        self.assertIn(("sca", "trivy"), classify(command="trivy fs ."))
        self.assertIn(("iac", "trivy"), classify(command="trivy config deploy/"))
        self.assertIn(("sca", "snyk-test"), classify(command="snyk test --all-projects"))
        self.assertIn(("sast", "snyk-code"), classify(command="snyk code test"))

    def test_npm_without_audit_is_not_an_action(self):
        self.assertEqual(classify(command="npm install"), set())

    def test_a_chain_records_every_scanner_in_it(self):
        self.assertEqual(
            classify(command="semgrep scan . && gitleaks detect; trivy fs ."),
            {("sast", "semgrep"), ("secrets", "gitleaks"), ("sca", "trivy")})

    def test_env_prefixes_interpreters_and_paths_do_not_hide_the_tool(self):
        for command in ("SEMGREP_SEND_METRICS=off semgrep scan .",
                        "/usr/local/bin/semgrep scan .",
                        "sudo semgrep scan .",
                        "npx semgrep scan ."):
            with self.subTest(command=command):
                self.assertIn(("sast", "semgrep"), classify(command=command))

    def test_gaide_checks_are_catalogue_entries(self):
        self.assertIn(("sast", "check-security.sh"),
                      classify(command="bash scripts/check-security.sh server/x.py"))
        self.assertIn(("secrets", "check-secrets.sh"),
                      classify(command="cat x | scripts/check-secrets.sh"))
        self.assertIn(("review", "security-reviewer"),
                      classify(tool_name="Skill", skill="security-reviewer"))
        self.assertIn(("review", "security-reviewer"),
                      classify(tool_name="Task", subagent_type="security-reviewer"))
        self.assertIn(("review", "security-review"),
                      classify(tool_name="SlashCommand", command="/security-review"))

    def test_ac14_non_gaide_behaviour_does_not_depend_on_the_gaide_entries(self):
        with mock.patch.object(scan, "ACTION_TOOLS", scan.BASE_ACTION_TOOLS), \
                mock.patch.object(scan, "ACTION_INVOCATIONS", scan.BASE_INVOCATIONS):
            self.assertEqual(classify(command="semgrep scan ."), {("sast", "semgrep")})
            self.assertEqual(classify(command="trivy fs ."), {("sca", "trivy")})
            self.assertEqual(classify(command="scripts/check-security.sh x.py"), set())


class TestActivityNegatives(unittest.TestCase):
    """AC9 — only an invoked command counts."""

    def test_a_prompt_mentioning_a_scanner_is_not_an_action(self):
        self.assertEqual(scan.classify_tool_call(
            {"event": "prompt.submit", "prompt": "please run semgrep and gitleaks"}), [])

    def test_an_assistant_message_mentioning_a_scanner_is_not_an_action(self):
        self.assertEqual(scan.classify_tool_call(
            {"event": "turn.end",
             "last_assistant_message": "I will run semgrep scan . next"}), [])

    def test_reading_a_file_that_contains_a_scanner_command_is_not_an_action(self):
        self.assertEqual(classify(tool_name="Read",
                                  file_path=".github/workflows/security.yml",
                                  response="run: semgrep scan --config p/secrets"),
                         set())

    def test_grepping_or_echoing_a_tool_name_is_not_an_action(self):
        self.assertEqual(classify(command="grep -rn semgrep ."), set())
        self.assertEqual(classify(command="echo 'we should run gitleaks'"), set())

    def test_a_record_without_tool_input_is_not_an_action(self):
        self.assertEqual(scan.classify_tool_call(
            {"event": "tool.call", "tool_name": "Bash"}), [])


class TestOutcomes(unittest.TestCase):
    """AC10 — never guessed."""

    def test_failed_call_is_an_error(self):
        (action,) = scan.classify_tool_call(
            call(command="semgrep scan .", event="tool.fail"))
        self.assertEqual(action["outcome"], "error")

    def test_clean_runs(self):
        for response in ("No findings.", "found 0 vulnerabilities",
                         "no leaks found", "0 findings"):
            with self.subTest(response=response):
                (action,) = scan.classify_tool_call(
                    call(command="gitleaks detect", response=response))
                self.assertEqual(action["outcome"], "clean")

    def test_runs_with_findings(self):
        for response in ("5 findings", "found 3 vulnerabilities",
                         "2 leaks found"):
            with self.subTest(response=response):
                (action,) = scan.classify_tool_call(
                    call(command="gitleaks detect", response=response))
                self.assertEqual(action["outcome"], "findings")

    def test_anything_else_is_unknown(self):
        for response in (None, "", "done", "scanning 412 files"):
            with self.subTest(response=response):
                (action,) = scan.classify_tool_call(
                    call(command="semgrep scan .", response=response))
                self.assertEqual(action["outcome"], "unknown")

    def test_detail_names_the_invocation_and_nothing_else(self):
        (action,) = scan.classify_tool_call(
            call(command="semgrep scan --config p/secrets " + fake("github_token")))
        self.assertNotIn(fake("github_token"), json.dumps(action))
        self.assertIn("semgrep", action["detail"])


class TestSuppressions(unittest.TestCase):
    """AC11 — recorded, and never counted as activity."""

    def test_suppression_is_not_an_action_category(self):
        self.assertNotIn(scan.SUPPRESSION, scan.ACTION_CATEGORIES)

    def test_inline_suppressions_written_into_a_file(self):
        self.assertIn(
            ("suppression", "inline-nosemgrep"),
            classify(tool_name="Write", file_path="server/x.py",
                     content="subprocess.run(cmd)  # nosemgrep"))
        self.assertIn(
            ("suppression", "inline-nosec"),
            classify(tool_name="Edit", file_path="server/x.py",
                     new_string="eval(x)  # nosec B307"))

    def test_scanner_ignore_files(self):
        self.assertIn(("suppression", "ignore-file"),
                      classify(tool_name="Write", file_path=".gitleaksignore",
                               content="abc123"))
        self.assertIn(("suppression", "ignore-file"),
                      classify(command="echo 'rule' >> .semgrepignore"))

    def test_bypassing_the_commit_hooks(self):
        self.assertIn(("suppression", "commit-no-verify"),
                      classify(command="git commit --no-verify -m 'wip'"))
        self.assertIn(("suppression", "commit-no-verify"),
                      classify(command="git commit -n -m 'wip'"))
        self.assertIn(("suppression", "pre-commit-skip"),
                      classify(command="SKIP=gitleaks pre-commit run --all-files"))

    def test_an_ordinary_commit_is_not_a_suppression(self):
        self.assertEqual(classify(command="git commit -m 'fix the parser'"),
                         set())

    def test_reading_a_file_containing_a_suppression_is_not_one(self):
        self.assertEqual(classify(tool_name="Read", file_path="server/x.py",
                                  response="foo()  # nosemgrep"), set())


class TestCodeEdits(unittest.TestCase):
    """AC12 — what makes a session code-touching."""

    def test_file_writing_tools(self):
        for tool in ("Write", "Edit", "MultiEdit", "NotebookEdit", "write_file"):
            with self.subTest(tool=tool):
                self.assertTrue(scan.is_code_edit(
                    {"event": "tool.call", "tool_name": tool,
                     "tool_input": json.dumps({"file_path": "a.py"})}))

    def test_commit_and_patch_commands(self):
        for command in ("git commit -m x", "git apply fix.patch", "patch -p1 < fix.diff"):
            with self.subTest(command=command):
                self.assertTrue(scan.is_code_edit(call(command=command)))

    def test_reading_and_listing_are_not_code_edits(self):
        self.assertFalse(scan.is_code_edit(call(command="ls -la")))
        self.assertFalse(scan.is_code_edit(
            {"event": "tool.call", "tool_name": "Read",
             "tool_input": json.dumps({"file_path": "a.py"})}))

    def test_a_prompt_is_never_a_code_edit(self):
        self.assertFalse(scan.is_code_edit(
            {"event": "prompt.submit", "prompt": "write the file"}))


class TestActivityStore(StoreCase):
    """The derived tables: actions, code-edit counts, coverage inputs."""

    def ingest(self, *records):
        return self.store.ingest_events(list(records), "alice")

    def actions(self):
        with self.store.connect() as db:
            return [dict(r) for r in db.execute(
                "SELECT * FROM security_actions ORDER BY category, tool")]

    def session(self, session_id="s1"):
        with self.store.connect() as db:
            return dict(db.execute("SELECT * FROM sessions WHERE session_id = ?",
                                   (session_id,)).fetchone())

    def test_actions_are_recorded_with_their_attribution(self):
        self.ingest(call(command="semgrep scan ."))
        (row,) = self.actions()
        self.assertEqual((row["category"], row["tool"], row["session_id"],
                          row["project"], row["origin"], row["trace_id"]),
                         ("sast", "semgrep", "s1", "app", "alice", "t1"))

    def test_re_ingesting_the_same_call_adds_nothing(self):
        batch = [call(command="semgrep scan . && gitleaks detect")]
        self.ingest(*batch)
        before = self.actions()
        self.ingest(*batch)
        self.assertEqual(self.actions(), before)

    def test_code_edits_are_counted(self):
        self.ingest(
            dict(call(command="ls"), trace_id="t1"),
            dict(call(tool_name="Write", file_path="a.py", content="x"), trace_id="t2"),
            dict(call(tool_name="Edit", file_path="a.py", new_string="y"), trace_id="t3"),
        )
        self.assertEqual(self.session()["code_edits"], 2)

    def test_a_classification_failure_does_not_cost_the_record(self):
        import contextlib
        import io
        log = io.StringIO()
        with mock.patch.object(scan, "classify_tool_call",
                               side_effect=RuntimeError("boom")), \
                contextlib.redirect_stderr(log):
            inserted, _ = self.ingest(call(command="semgrep scan ."))
        self.assertEqual(inserted, 1)
        self.assertIn("boom", log.getvalue())


class TestRescanAndUpgrade(StoreCase):
    """AC33 — an existing store is scanned once, and a rescan reproduces it."""

    def seed(self):
        self.store.ingest_events([
            dict(call(command="semgrep scan ."), trace_id="t1"),
            dict(call(tool_name="Write", file_path="a.py",
                      content="token = \"" + fake("secret_body") + "\""),
                 trace_id="t2"),
            dict(call(command="ls"), trace_id="t3", session_id="s2", project="other"),
        ], "alice")
        self.store.store_transcript(
            "s1", (json.dumps({"type": "assistant", "message": {
                "model": "claude-opus-5", "id": "m1", "role": "assistant",
                "content": "key " + fake("github_token"),
                "usage": {"output_tokens": 3}}}) + "\n").encode(), "app", "alice")

    def security_state(self):
        with self.store.connect() as db:
            findings = sorted(tuple(r)[1:] for r in db.execute(
                "SELECT * FROM security_findings"))
            actions = sorted(tuple(r)[1:] for r in db.execute(
                "SELECT * FROM security_actions"))
            edits = sorted(tuple(r) for r in db.execute(
                "SELECT session_id, code_edits FROM sessions"))
        return findings, actions, edits

    def test_derived_version_covers_the_security_analysis(self):
        self.assertGreaterEqual(server.DERIVED_VERSION, 4)

    def test_a_store_without_the_analysis_is_scanned_on_the_next_start(self):
        self.seed()
        expected = self.security_state()
        # What a v0.6.0 store looks like: data indexed, no security analysis.
        with self.store.connect() as db:
            db.execute("DELETE FROM security_findings")
            db.execute("DELETE FROM security_actions")
            db.execute("UPDATE sessions SET code_edits = 0, security_truncated = 0")
            db.execute("DELETE FROM meta WHERE key = 'derived_version'")
            db.commit()

        summary = self.store.rederive_if_stale()

        self.assertIsNotNone(summary)
        self.assertEqual(self.security_state(), expected)
        self.assertEqual(self.store.derived_version(), server.DERIVED_VERSION)

    def test_a_current_store_is_not_rescanned(self):
        self.seed()
        self.store.rederive_if_stale()
        self.assertIsNone(self.store.rederive_if_stale())

    def test_rescan_reproduces_the_same_analysis(self):
        self.seed()
        expected = self.security_state()
        self.store.rescan_security()
        self.assertEqual(self.security_state(), expected)

    def test_rescan_of_one_project_leaves_the_others_alone(self):
        self.seed()
        expected = self.security_state()
        self.store.rescan_security(project="other")
        self.assertEqual(self.security_state(), expected)

    def test_rescan_picks_up_a_new_term(self):
        self.store.ingest_events(
            [dict(call(command="echo acme-holdings"), trace_id="t9")], "alice")
        with self.store.connect() as db:
            db.execute("INSERT INTO security_terms (project, term, created_at)"
                       " VALUES ('app', 'acme-holdings', '2026-10-14T00:00:00Z')")
            db.commit()
        self.store.rescan_security(project="app")
        with self.store.connect() as db:
            rules = [r[0] for r in db.execute("SELECT rule FROM security_findings")]
        self.assertIn("custom-term", rules)

    def test_rebuild_index_reproduces_the_security_tables(self):
        self.seed()
        expected = self.security_state()
        self.store.rebuild_index()
        self.assertEqual(self.security_state(), expected)

    def test_every_full_pass_records_that_the_store_was_scanned(self):
        """Otherwise the console reports "never scanned" and keeps the stale
        badge lit after a pass that just ran (found by the code review)."""
        self.seed()
        with self.store.connect() as db:
            db.execute("DELETE FROM meta WHERE key = 'security_scanned_at'")
            db.commit()
        self.store.rebuild_index()
        self.assertIsNotNone(self.store.get_meta("security_scanned_at"))

        with self.store.connect() as db:
            db.execute("DELETE FROM meta")
            db.commit()
        self.store.rederive_if_stale()
        self.assertIsNotNone(self.store.get_meta("security_scanned_at"))

    def test_a_project_scoped_rescan_does_not_claim_a_full_scan(self):
        self.seed()
        with self.store.connect() as db:
            db.execute("DELETE FROM meta WHERE key = 'security_scanned_at'")
            db.commit()
        self.store.rescan_security(project="app")
        self.assertIsNone(self.store.get_meta("security_scanned_at"))


if __name__ == "__main__":
    unittest.main()
