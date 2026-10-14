"""Security analysis over HTTP — specs/security-scan AC15-AC21, AC23-AC24.

One store, three projects. Member `two` is scoped to `app` and `api`, so every
read here doubles as a check that the new endpoints cannot become an oracle
for `research` (ADR 0002's rule, applied to this feature).
"""

import json
import time
import unittest

import server_harness
from fixtures import TEST_CPF, assistant_lines, event, fake, load_server, transcript, usage
from server_harness import ServerHarness

server = load_server()
# The module the harness actually serves from (load_server execs a fresh one
# per call), which is where the single-flight rescan state lives.
live = server_harness.server

TS = "2026-10-01T10:00:00.000Z"
TS2 = "2026-10-02T10:00:00.000Z"
LEAKED = fake("github_token")


class SecurityApiTestCase(unittest.TestCase):

    def setUp(self):
        self.h = ServerHarness()
        self.tokens = self.h.tokens
        self.tokens["two"] = self.h.add_user("two", "member", projects=["app", "api"])
        self.seed()

    def tearDown(self):
        self.h.close()

    def seed(self):
        """app/s1: leak + semgrep + a code edit (covered).
        app/s2: a code edit and nothing else (gap).
        api/s3: a CPF in a tool response, a --no-verify commit (gap).
        research/s4: the same leaked key as s1 (recurring, and out of scope
        for member `two`)."""
        records = [
            event("s1", "prompt.submit", TS, project="app",
                  prompt=f"deploy with {LEAKED} please"),
            event("s1", "tool.call", TS, project="app", tool_name="Bash",
                  tool_input=json.dumps({"command": "semgrep scan --config p/secrets ."}),
                  tool_response="No findings."),
            event("s1", "tool.call", TS, project="app", tool_name="Write",
                  tool_input=json.dumps({"file_path": "a.py", "content": "ok"})),

            event("s2", "tool.call", TS, project="app", tool_name="Write",
                  tool_input=json.dumps({"file_path": "b.py", "content": "ok"})),

            event("s3", "tool.call", TS2, project="api", tool_name="Bash",
                  tool_input=json.dumps({"command": "psql -c 'select cpf from users'"}),
                  tool_response=f"cpf\n{TEST_CPF}\n"),
            event("s3", "tool.call", TS2, project="api", tool_name="Bash",
                  tool_input=json.dumps({"command": "git commit --no-verify -m wip"})),

            event("s4", "prompt.submit", TS, project="research",
                  prompt=f"the same key {LEAKED} again"),
        ]
        status, body = self.h.post_events(records)
        assert status == 200, (status, body)
        self.h.put_transcript("s1", transcript(
            assistant_lines("claude-opus-5", usage(output_tokens=1), TS,
                            session_id="s1")), project="app")

    # -- helpers --

    def security(self, who="admin_user", query=""):
        status, body = self.h.as_role(who, "GET", "/api/v1/security" + query)
        self.assertEqual(status, 200, body)
        return body

    def rules(self, body):
        return {r["rule"]: r for r in body["exposure"]["rules"]}

    def tools(self, body):
        return {r["tool"]: r for r in body["activity"]["tools"]}


class TestShape(SecurityApiTestCase):
    """AC15 — both halves in one response."""

    def test_both_halves_are_present(self):
        body = self.security()
        self.assertEqual(set(body), {"scan", "exposure", "activity"})
        self.assertEqual(
            set(body["exposure"]),
            {"totals", "rules", "per_day", "recurring", "sessions", "rows_omitted"})
        self.assertEqual(
            set(body["activity"]),
            {"totals", "categories", "tools", "per_day", "series", "coverage",
             "gaps", "suppressions", "rows_omitted"})
        self.assertEqual(set(body["scan"]),
                         {"scanned_at", "terms_changed_at", "stale",
                          "truncated_sessions", "rescan"})

    def test_exposure_totals_and_rules(self):
        body = self.security()
        totals = body["exposure"]["totals"]
        self.assertEqual(totals["high"], 2)      # the key in s1 and in s4
        self.assertEqual(totals["medium"], 1)    # the CPF in s3
        self.assertEqual(totals["sessions"], 3)
        rules = self.rules(body)
        self.assertEqual(rules["github-token"]["sessions"], 2)
        self.assertEqual(rules["github-token"]["severity"], "high")
        self.assertEqual(rules["cpf"]["findings"], 1)

    def test_recurring_values_are_grouped(self):
        (row,) = self.security()["exposure"]["recurring"]
        self.assertEqual((row["rule"], row["sessions"]), ("github-token", 2))
        self.assertNotIn(LEAKED, json.dumps(row))

    def test_per_day_series(self):
        days = {r["day"]: r for r in self.security()["exposure"]["per_day"]}
        self.assertEqual(days["2026-10-01"]["high"], 2)
        self.assertEqual(days["2026-10-02"]["medium"], 1)

    def test_affected_sessions_are_ranked(self):
        sessions = {r["session_id"]: r for r in self.security()["exposure"]["sessions"]}
        self.assertEqual(sessions["s1"]["high"], 1)
        self.assertEqual(sessions["s1"]["project"], "app")
        self.assertEqual(sessions["s1"]["origin"], "project:p")

    def test_activity_inventory(self):
        body = self.security()
        tools = self.tools(body)
        self.assertEqual((tools["semgrep"]["runs"], tools["semgrep"]["clean"]), (1, 1))
        self.assertEqual(tools["semgrep"]["category"], "sast")
        self.assertNotIn("inline-nosemgrep", tools)
        self.assertEqual(body["activity"]["totals"]["actions"], 1)

    def test_suppressions_are_listed_and_not_counted_as_activity(self):
        body = self.security()
        (row,) = body["activity"]["suppressions"]
        self.assertEqual((row["tool"], row["session_id"]), ("commit-no-verify", "s3"))
        self.assertEqual(body["activity"]["totals"]["suppressions"], 1)
        self.assertEqual(body["activity"]["totals"]["actions"], 1)
        self.assertNotIn("suppression",
                         {r["category"] for r in body["activity"]["categories"]})

    def test_coverage_and_gaps(self):
        body = self.security()
        coverage = body["activity"]["coverage"]
        self.assertEqual(coverage["code_sessions"], 3)   # s1, s2, s3
        self.assertEqual(coverage["with_any"], 1)        # only s1 ran a scanner
        self.assertEqual(coverage["with_sast"], 1)
        self.assertEqual(coverage["with_sca"], 0)
        gaps = {r["session_id"] for r in body["activity"]["gaps"]}
        self.assertEqual(gaps, {"s2", "s3"})

    def test_date_filters_apply_to_both_halves(self):
        body = self.security(query="?from=2026-10-02&to=2026-10-03")
        self.assertEqual(body["exposure"]["totals"]["high"], 0)
        self.assertEqual(body["exposure"]["totals"]["medium"], 1)
        self.assertEqual(body["activity"]["totals"]["actions"], 0)

    def test_no_response_carries_the_leaked_value(self):
        _, raw = self.h.raw_request("GET", "/api/v1/security",
                                    self.tokens["admin_user"])
        self.assertNotIn(LEAKED.encode(), raw)
        self.assertNotIn(LEAKED[4:].encode(), raw)


class TestScope(SecurityApiTestCase):
    """AC20, AC23 — the new reads are not an oracle for another project."""

    def test_a_scoped_member_sees_only_granted_projects(self):
        body = self.security("two")
        self.assertEqual(body["exposure"]["totals"]["high"], 1)   # s1 only
        self.assertNotIn("research", json.dumps(body))
        self.assertNotIn("s4", json.dumps(body))
        # The key recurs across app and research, but not within this scope.
        self.assertEqual(body["exposure"]["recurring"], [])

    def test_filtering_by_a_project_outside_the_scope_is_empty_not_an_error(self):
        body = self.security("two", query="?project=research")
        self.assertEqual(body["exposure"]["totals"]["findings"], 0)
        self.assertEqual(body["activity"]["totals"]["actions"], 0)
        self.assertEqual(body["activity"]["coverage"]["code_sessions"], 0)

    def test_a_project_with_no_data_looks_the_same_as_one_outside_the_scope(self):
        outside = self.security("two", query="?project=research")
        empty = self.security("two", query="?project=nothing-here")
        self.assertEqual(outside, empty)

    def test_a_member_with_an_empty_scope_sees_nothing(self):
        self.tokens["none"] = self.h.add_user("none", "member", projects=[])
        body = self.security("none")
        self.assertEqual(body["exposure"]["totals"]["findings"], 0)
        self.assertEqual(body["activity"]["gaps"], [])

    def test_the_rescan_state_tells_a_member_nothing_about_other_projects(self):
        """AC23 — counts and a raw exception string are about the whole store
        (found by both reviews)."""
        live.RESCAN.update({"state": "done", "project": "research", "sessions": 7,
                            "transcripts": 3, "failed": ["s4"], "actor": "root",
                            "error": "OperationalError('/data/research.jsonl')"})
        try:
            member = self.security("two")["scan"]["rescan"]
            self.assertEqual(member, {"state": "done"})
            admin = self.security("admin_user")["scan"]["rescan"]
            self.assertEqual(admin["sessions"], 7)
        finally:
            live.RESCAN.clear()
            live.RESCAN["state"] = "idle"

    def test_the_store_salt_is_never_served(self):
        """AC22's second half: a fingerprint is only unguessable while the salt
        stays inside the store."""
        salt = self.h.store.security_salt().hex()
        paths = ["/api/v1/security", "/api/v1/security/export?kind=findings",
                 "/api/v1/security/export?kind=actions", "/api/v1/security/terms",
                 "/api/v1/security/rescan", "/api/v1/sessions/s1", "/api/v1/me",
                 "/api/v1/export?format=jsonl"]
        for path in paths:
            with self.subTest(path=path):
                _, raw = self.h.raw_request("GET", path, self.tokens["admin_user"])
                self.assertNotIn(salt.encode(), raw)
                self.assertNotIn(salt[:16].encode(), raw)

    def test_keys_with_read_access_see_everything(self):
        self.assertEqual(self.security("member_key")["exposure"]["totals"]["high"], 2)

    def test_an_agent_key_cannot_read_the_analysis(self):
        status, _ = self.h.as_role("agent_key", "GET", "/api/v1/security")
        self.assertEqual(status, 403)


class TestSessionBlock(SecurityApiTestCase):
    """AC16 — the session page's own view, additive."""

    def test_session_detail_carries_findings_and_actions(self):
        status, body = self.h.as_role("admin_user", "GET", "/api/v1/sessions/s1")
        self.assertEqual(status, 200, body)
        security = body["security"]
        self.assertEqual([f["rule"] for f in security["findings"]], ["github-token"])
        self.assertEqual(security["findings"][0]["location"], "prompt")
        self.assertEqual([a["tool"] for a in security["actions"]], ["semgrep"])
        self.assertEqual(security["code_edits"], 1)
        self.assertFalse(security["truncated"])
        self.assertNotIn(LEAKED, json.dumps(security))
        self.assertNotIn(LEAKED[4:], json.dumps(security))

    def test_the_analysis_masks_what_the_event_stream_still_carries(self):
        """The boundary of AC21: a *finding* is a pointer, but the ledger
        itself holds what was captured. The event stream of this endpoint has
        always returned the stored text — redacted at capture (D5), raw in
        this fixture — which is exactly why project scope is the control that
        matters here."""
        _, body = self.h.as_role("admin_user", "GET", "/api/v1/sessions/s1")
        self.assertIn(LEAKED, json.dumps(body["events"]))
        self.assertNotIn(LEAKED, json.dumps(body["security"]))

    def test_the_rest_of_the_session_response_is_unchanged(self):
        _, body = self.h.as_role("admin_user", "GET", "/api/v1/sessions/s1")
        for key in ("session", "models", "events", "has_transcript"):
            self.assertIn(key, body)

    def test_a_session_outside_the_scope_stays_unknown(self):
        status, body = self.h.as_role("two", "GET", "/api/v1/sessions/s4")
        self.assertEqual(status, 404)
        self.assertNotIn("research", json.dumps(body))


class TestExport(SecurityApiTestCase):
    """AC17 — the rows behind the page, inside the caller's scope."""

    def export(self, who, query):
        status, raw = self.h.raw_request(
            "GET", "/api/v1/security/export" + query, self.tokens[who])
        self.assertEqual(status, 200, raw[:200])
        return raw.decode("utf-8")

    def test_findings_jsonl(self):
        rows = [json.loads(l) for l in
                self.export("admin_user", "?kind=findings").splitlines()]
        self.assertEqual(len(rows), 3)
        self.assertEqual({r["rule"] for r in rows}, {"github-token", "cpf"})
        self.assertNotIn(LEAKED, json.dumps(rows))

    def test_actions_csv_has_a_header(self):
        text = self.export("admin_user", "?kind=actions&format=csv")
        self.assertTrue(text.startswith("session_id,project,origin,ts,category,"))
        self.assertIn("semgrep", text)
        self.assertIn("commit-no-verify", text)

    def test_a_scoped_member_exports_only_their_projects(self):
        text = self.export("two", "?kind=findings")
        self.assertNotIn("research", text)
        self.assertEqual(len(text.splitlines()), 2)

    def test_csv_cells_cannot_be_executed_by_a_spreadsheet(self):
        """A leading = + - @ makes a spreadsheet treat the cell as a formula.
        Session ids and project names are already charset-validated at ingest;
        a custom term is not, and it reaches `evidence`."""
        self.h.as_role("admin_user", "PUT", "/api/v1/security/terms",
                       {"terms": [{"project": "app", "term": "=cmd|calc"}]})
        self.h.post_events([event("s9", "prompt.submit", TS, project="app",
                                  prompt="the value is =cmd|calc here")])
        text = self.export("admin_user", "?kind=findings&format=csv")
        self.assertIn("custom-term", text)
        self.assertIn("'=cmd", text)
        self.assertNotIn(",=cmd", text)

    def test_bad_arguments_are_rejected(self):
        for query in ("?kind=nonsense", "?kind=findings&format=xml"):
            status, _ = self.h.as_role("admin_user", "GET",
                                       "/api/v1/security/export" + query)
            self.assertEqual(status, 400, query)


class TestTerms(SecurityApiTestCase):
    """AC18, AC24, AC25 — admin-only vocabulary, literal and bounded."""

    def put(self, who, terms):
        return self.h.as_role(who, "PUT", "/api/v1/security/terms",
                              {"terms": terms})

    def test_admin_sets_and_reads_terms(self):
        status, body = self.put("admin_user",
                                [{"project": "app", "term": "acme-holdings"},
                                 {"project": "", "term": "internal.example.net"}])
        self.assertEqual(status, 200, body)
        status, body = self.h.as_role("admin_user", "GET", "/api/v1/security/terms")
        self.assertEqual(status, 200)
        self.assertEqual({(t["project"], t["term"]) for t in body["terms"]},
                         {("app", "acme-holdings"), ("", "internal.example.net")})

    def test_a_term_change_marks_the_stored_analysis_stale(self):
        self.assertFalse(self.security()["scan"]["stale"])
        self.put("admin_user", [{"project": "app", "term": "acme-holdings"}])
        scan_state = self.security()["scan"]
        self.assertTrue(scan_state["stale"])
        self.assertIsNotNone(scan_state["terms_changed_at"])

    def test_members_and_read_keys_cannot_read_or_write_terms(self):
        for who in ("member_user", "two", "member_key"):
            with self.subTest(who=who):
                status, _ = self.h.as_role(who, "GET", "/api/v1/security/terms")
                self.assertEqual(status, 403)
                status, _ = self.put(who, [{"project": "app", "term": "secretive"}])
                self.assertEqual(status, 403)
        with self.h.store.connect() as db:
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM security_terms").fetchone()[0], 0)

    def test_global_terms_count_against_each_project_budget(self):
        cap = server.security_scan.MAX_TERMS_PER_PROJECT
        terms = ([{"project": "", "term": f"global-{i:04d}"} for i in range(cap // 2)]
                 + [{"project": "app", "term": f"app-{i:04d}"} for i in range(cap)])
        status, _ = self.put("admin_user", terms)
        self.assertEqual(status, 400)

    def test_a_body_that_is_not_an_object_is_answered_not_dropped(self):
        """Found by the verifier: these two handlers returned without sending
        anything, so the client got an empty reply — and a JSON array raised
        inside the handler while it waited."""
        for path in ("/api/v1/security/terms", "/api/v1/security/rescan"):
            method = "PUT" if path.endswith("terms") else "POST"
            for body in (b"not json", b"[1,2,3]", b'"a string"', b"42", b"null"):
                with self.subTest(path=path, body=body):
                    status, raw = self.h.raw_request(
                        method, path, self.tokens["admin_user"], body)
                    self.assertEqual(status, 400, raw)
                    self.assertIn(b"JSON object", raw)

    def test_invalid_terms_are_rejected_without_changing_anything(self):
        self.put("admin_user", [{"project": "app", "term": "keepme-please"}])
        bad = [
            [{"project": "app", "term": "abc"}],                      # too short
            [{"project": "app", "term": "x" * 65}],                   # too long
            [{"project": "bad name!", "term": "acme-holdings"}],      # bad project
            [{"project": "app", "term": f"term-{i:04d}"} for i in range(101)],
            [{"term": "no-project-key-is-fine"}, {"project": "app"}],  # missing term
            "not a list",
        ]
        for terms in bad:
            with self.subTest(terms=str(terms)[:40]):
                status, _ = self.h.as_role("admin_user", "PUT",
                                           "/api/v1/security/terms", {"terms": terms})
                self.assertEqual(status, 400)
        status, body = self.h.as_role("admin_user", "GET", "/api/v1/security/terms")
        self.assertEqual([t["term"] for t in body["terms"]], ["keepme-please"])

    def test_terms_are_matched_literally_after_a_rescan(self):
        self.put("admin_user", [{"project": "app", "term": "deploy with"}])
        self.h.as_role("admin_user", "POST", "/api/v1/security/rescan", {})
        self.wait_for_rescan()
        rules = self.rules(self.security())
        self.assertEqual(rules["custom-term"]["sessions"], 1)

    def wait_for_rescan(self, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            _, body = self.h.as_role("admin_user", "GET", "/api/v1/security/rescan")
            if body["state"] != "running":
                return body
            time.sleep(0.05)
        self.fail("rescan did not finish")


class TestRescan(SecurityApiTestCase):
    """AC19 — one at a time, admin only, with a readable state."""

    def test_a_rescan_runs_and_reports_its_result(self):
        status, body = self.h.as_role("admin_user", "POST",
                                      "/api/v1/security/rescan", {})
        self.assertEqual(status, 202, body)
        self.assertEqual(body["state"], "running")
        final = TestTerms.wait_for_rescan(self)
        self.assertEqual(final["state"], "done")
        self.assertEqual(final["sessions"], 4)
        # `total` must not stay null for a job that finished inside the
        # progress throttle window (verifier note on AC19).
        self.assertEqual((final["done"], final["total"]), (4, 4))
        self.assertEqual(final["failed"], [])
        self.assertIsNotNone(final["finished_at"])

    def test_a_second_rescan_while_one_runs_is_refused(self):
        live.RESCAN.update({"state": "running", "started_at": live.utcnow()})
        try:
            status, body = self.h.as_role("admin_user", "POST",
                                          "/api/v1/security/rescan", {})
            self.assertEqual(status, 409, body)
        finally:
            live.RESCAN.clear()
            live.RESCAN["state"] = "idle"

    def test_a_rescan_can_be_scoped_to_one_project(self):
        status, body = self.h.as_role("admin_user", "POST",
                                      "/api/v1/security/rescan", {"project": "api"})
        self.assertEqual(status, 202, body)
        final = TestTerms.wait_for_rescan(self)
        self.assertEqual(final["project"], "api")
        self.assertEqual(final["sessions"], 1)
        # Nothing else lost its analysis.
        self.assertEqual(self.security()["exposure"]["totals"]["high"], 2)

    def test_members_and_read_keys_cannot_start_or_read_a_rescan(self):
        for who in ("member_user", "two", "member_key"):
            for method in ("POST", "GET"):
                with self.subTest(who=who, method=method):
                    status, _ = self.h.as_role(
                        who, method, "/api/v1/security/rescan",
                        {} if method == "POST" else None)
                    self.assertEqual(status, 403)

    def test_an_unknown_project_is_rejected(self):
        status, _ = self.h.as_role("admin_user", "POST", "/api/v1/security/rescan",
                                   {"project": "bad name!"})
        self.assertEqual(status, 400)


if __name__ == "__main__":
    unittest.main()
