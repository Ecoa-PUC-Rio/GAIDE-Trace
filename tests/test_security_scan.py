"""Exposure scan — specs/security-scan, Sprint 1 (AC1-AC7, AC21-AC22, AC25-AC27).

Nothing here uses captured data: every value is synthesized, and every
secret-shaped one is assembled at runtime by `fixtures.fake` so no complete
credential pattern is a literal in this repository (tests/README.md,
Constitution Principle 6 and 10).
"""

import contextlib
import hashlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import fixtures
from fixtures import TEST_CARD, TEST_CNPJ, TEST_CPF, TEST_CPF_DIGITS, fake, load_server

server = load_server()
scan = server.security_scan

SALT = b"test-salt-one"
OTHER_SALT = b"test-salt-two"


def rules_by_name():
    return {r.name: r for r in scan.RULES}


def found(text, salt=SALT, **kw):
    """Rule names found in `text`, as a set."""
    findings, _ = scan.scan_text(text, salt, **kw)
    return {f["rule"] for f in findings}


class TestRuleCatalogue(unittest.TestCase):
    """One positive and one near-miss negative per rule of AC2."""

    def test_every_rule_has_a_severity_and_a_category(self):
        for rule in scan.RULES:
            self.assertIn(rule.severity, ("high", "medium", "low"), rule.name)
            self.assertIn(rule.category, scan.CATEGORIES, rule.name)

    def test_credential_rules(self):
        cases = {
            "private-key-block": fake("private_key_header"),
            "aws-access-key-id": fake("aws_access_key_id"),
            "github-token": fake("github_token"),
            "github-token-pat": fake("github_pat"),
            "anthropic-api-key": fake("anthropic_key"),
            "openai-api-key": fake("openai_key"),
            "google-api-key": fake("google_api_key"),
            "slack-token": fake("slack_token"),
            "slack-webhook": fake("slack_webhook"),
            "npm-token": fake("npm_token"),
            "stripe-key": fake("stripe_key"),
            "pypi-token": fake("pypi_token"),
            "vault-token": fake("vault_token"),
            "secret-assignment": fixtures.assignment(),
            "credentials-in-url": fixtures.conn_string(),
            "jwt": fake("jwt"),
        }
        for rule, text in cases.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, found(f"before {text} after"))

    def test_anthropic_key_is_not_also_reported_as_an_openai_key(self):
        self.assertEqual(found(fake("anthropic_key")), {"anthropic-api-key"})

    def test_placeholders_are_not_secrets(self):
        for value in ('api_key = "[REDACTED]"', 'password = "changeme"',
                      'token = "xxxxxxxxxx"', 'secret = "${MY_SECRET}"',
                      'api_key = "<your-api-key>"', 'password = "aaaaaaaaaa"',
                      'token: "$SOME_ENV_VAR"'):
            with self.subTest(value=value):
                self.assertNotIn("secret-assignment", found(value))

    def test_sensitive_paths(self):
        cases = {
            "env-file": "cat .env",
            "private-key-file": "openssl rsa -in /etc/ssl/server.pem",
            "ssh-private-key-file": "cp ~/.ssh/id_ed25519 /tmp/x",
            "aws-credentials-file": "cat ~/.aws/credentials",
            "kube-config": "KUBECONFIG=~/.kube/config kubectl get pods",
            "gcloud-config": "ls ~/.config/gcloud",
            "docker-config": "cat ~/.docker/config.json",
            "netrc": "cat ~/.netrc",
            "npmrc-or-pypirc": "cat ~/.npmrc",
            "git-credentials": "cat ~/.git-credentials",
        }
        for rule, text in cases.items():
            with self.subTest(rule=rule):
                self.assertIn(rule, found(text))

    def test_near_miss_paths(self):
        self.assertNotIn("env-file", found("source .envrc"))
        self.assertNotIn("ssh-private-key-file", found("the id_rsandom file"))

    def test_pii(self):
        self.assertIn("cpf", found(f"CPF {TEST_CPF}"))
        self.assertIn("cpf", found(f"CPF {TEST_CPF_DIGITS}"))
        self.assertIn("cnpj", found(f"CNPJ {TEST_CNPJ}"))
        self.assertIn("credit-card", found(f"card {TEST_CARD}"))
        self.assertIn("email", found("write to ana.silva@example.com please"))
        self.assertIn("phone-br", found("call +55 11 98765-4321"))

    def test_redaction_marker(self):
        findings, _ = scan.scan_text("tool said [REDACTED] twice [REDACTED]", SALT)
        markers = [f for f in findings if f["rule"] == "redaction-marker"]
        self.assertEqual(len(markers), 1)
        self.assertEqual(markers[0]["count"], 2)
        self.assertEqual(markers[0]["severity"], "low")

    def test_severities_follow_ac4(self):
        rules = rules_by_name()
        for name in ("private-key-block", "aws-access-key-id", "secret-assignment",
                     "env-file", "aws-credentials-file"):
            self.assertEqual(rules[name].severity, "high", name)
        for name in ("cpf", "cnpj", "credit-card", "jwt", "credentials-in-url"):
            self.assertEqual(rules[name].severity, "medium", name)
        for name in ("email", "phone-br", "redaction-marker"):
            self.assertEqual(rules[name].severity, "low", name)


class TestValidators(unittest.TestCase):
    """AC7 — a digit sequence that cannot be a CPF, CNPJ or card is not one."""

    def test_cpf(self):
        self.assertTrue(scan.valid_cpf(TEST_CPF))
        self.assertTrue(scan.valid_cpf(TEST_CPF_DIGITS))
        self.assertFalse(scan.valid_cpf("123.456.789-00"))
        self.assertFalse(scan.valid_cpf("111.111.111-11"))
        self.assertFalse(scan.valid_cpf("1234567890"))

    def test_cnpj(self):
        self.assertTrue(scan.valid_cnpj(TEST_CNPJ))
        self.assertFalse(scan.valid_cnpj("11.222.333/0001-80"))
        self.assertFalse(scan.valid_cnpj("00.000.000/0000-00"))

    def test_card(self):
        self.assertTrue(scan.valid_card(TEST_CARD))
        self.assertFalse(scan.valid_card("4111 1111 1111 1112"))
        self.assertFalse(scan.valid_card("1111 1111 1111 1111"))

    def test_an_eleven_digit_number_that_is_not_a_cpf_is_not_reported(self):
        self.assertNotIn("cpf", found("order 12345678901 shipped"))

    def test_a_sixteen_digit_number_failing_luhn_is_not_a_card(self):
        self.assertNotIn("credit-card", found("id 4111 1111 1111 1112"))


class TestMasking(unittest.TestCase):
    """AC21 — no matched value, and no surrounding text, is ever stored."""

    def test_evidence_never_carries_more_than_the_prefix(self):
        values = [fake(k) for k in ("aws_access_key_id", "github_token",
                                    "anthropic_key", "npm_token", "jwt")]
        values += [TEST_CPF, TEST_CARD, fixtures.conn_string()]
        for value in values:
            with self.subTest(value=value[:6]):
                findings, _ = scan.scan_text(
                    f"secret follows: {value} :end of line", SALT)
                self.assertTrue(findings)
                blob = json.dumps(findings)
                self.assertNotIn(value, blob)
                tail = value[scan.EVIDENCE_PREFIX:]
                if len(tail) >= 6:
                    self.assertNotIn(tail, blob)
                self.assertNotIn("secret follows", blob)
                self.assertNotIn("end of line", blob)

    def test_pii_evidence_reveals_no_characters(self):
        findings, _ = scan.scan_text(f"cpf {TEST_CPF_DIGITS}", SALT)
        evidence = [f["evidence"] for f in findings if f["rule"] == "cpf"][0]
        self.assertNotIn("123", evidence)
        self.assertIn("11", evidence)  # only the length is reported

    def test_evidence_is_printable_and_bounded(self):
        noisy = "A1b2" + chr(7) + "C3d4E5f6G7h8"
        findings, _ = scan.scan_text('api_key = "' + noisy + '"', SALT)
        self.assertTrue(findings)
        for f in findings:
            self.assertTrue(f["evidence"].isprintable(), f["evidence"])
            self.assertLessEqual(len(f["evidence"]), 40)


class TestFingerprints(unittest.TestCase):
    """AC22 — salted, stable within a store, different across stores."""

    def test_stable_and_salt_dependent(self):
        value = fake("aws_access_key_id")
        self.assertEqual(scan.fingerprint(value, SALT), scan.fingerprint(value, SALT))
        self.assertNotEqual(scan.fingerprint(value, SALT),
                            scan.fingerprint(value, OTHER_SALT))

    def test_the_same_value_groups_across_texts(self):
        value = fake("github_token")
        a, _ = scan.scan_text(f"first {value}", SALT)
        b, _ = scan.scan_text(f"second {value}", SALT)
        self.assertEqual(a[0]["fingerprint"], b[0]["fingerprint"])

    def test_different_values_of_one_rule_stay_distinct(self):
        other = "AK" + "IA" + "Z" * 16  # assembled, like every fake here
        findings, _ = scan.scan_text(
            f"{fake('aws_access_key_id')} and {other}", SALT)
        aws = [f for f in findings if f["rule"] == "aws-access-key-id"]
        self.assertEqual(len(aws), 2)
        self.assertNotEqual(aws[0]["fingerprint"], aws[1]["fingerprint"])

    def test_repeats_of_one_value_collapse_with_a_count(self):
        value = fake("anthropic_key")
        findings, _ = scan.scan_text(f"{value} {value} {value}", SALT)
        keys = [f for f in findings if f["rule"] == "anthropic-api-key"]
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["count"], 3)


class TestTerms(unittest.TestCase):
    """AC25 — custom terms are literal, never patterns."""

    def test_literal_and_case_insensitive(self):
        self.assertIn("custom-term", found("the ACME-Holdings deal",
                                           terms=("acme-holdings",)))
        self.assertNotIn("custom-term", found("the acme holdings deal",
                                              terms=("acme-holdings",)))

    def test_a_term_is_not_compiled_as_a_regex(self):
        self.assertNotIn("custom-term", found("abcd", terms=("a.cd",)))
        self.assertIn("custom-term", found("a.cd", terms=("a.cd",)))
        self.assertNotIn("custom-term", found("aaaaa", terms=("a+aa",)))
        self.assertIn("custom-term", found("a+aa", terms=("a+aa",)))

    def test_terms_below_the_storable_minimum_are_ignored(self):
        self.assertNotIn("custom-term", found("abc", terms=("abc",)))

    def test_term_severity_is_medium(self):
        findings, _ = scan.scan_text("project acme-holdings", SALT,
                                     terms=("acme-holdings",))
        self.assertEqual(findings[0]["severity"], "medium")
        self.assertEqual(findings[0]["category"], "internal")


class TestCaps(unittest.TestCase):
    """AC26 — bounded work, with the truncation reported."""

    def test_text_beyond_the_cap_is_not_scanned_and_is_reported(self):
        value = fake("aws_access_key_id")
        text = ("." * (scan.MAX_SCAN_CHARS + 100)) + value
        findings, truncated = scan.scan_text(text, SALT)
        self.assertTrue(truncated)
        self.assertNotIn("aws-access-key-id", {f["rule"] for f in findings})

    def test_a_huge_single_line_stays_bounded(self):
        findings, truncated = scan.scan_text("A1b2C3d4" * 6_500_000, SALT)
        self.assertTrue(truncated)
        self.assertLessEqual(len(findings), scan.MAX_FINDINGS_PER_RECORD)

    def test_findings_per_text_are_capped(self):
        many = " ".join(f"AKIA{i:016d}" for i in range(scan.MAX_FINDINGS_PER_RECORD * 3))
        findings, truncated = scan.scan_text(many, SALT)
        self.assertEqual(len(findings), scan.MAX_FINDINGS_PER_RECORD)
        self.assertTrue(truncated)


class TestEventScan(unittest.TestCase):
    """AC1, AC3 — which fields are scanned, and how a finding is located."""

    def test_each_text_field_is_scanned_and_located(self):
        row = {
            "prompt": "my key is " + fake("github_token"),
            "tool_input": json.dumps({"command": "cat .env"}),
            "tool_response": "value " + fake("npm_token"),
            "last_assistant_message": "contact ana@example.com",
        }
        findings, _ = scan.scan_event(row, SALT)
        located = {(f["rule"], f["location"]) for f in findings}
        self.assertIn(("github-token", "prompt"), located)
        self.assertIn(("env-file", "tool_input"), located)
        self.assertIn(("npm-token", "tool_response"), located)
        self.assertIn(("email", "last_assistant_message"), located)

    def test_path_rules_only_apply_to_tool_input(self):
        findings, _ = scan.scan_event({"prompt": "never read .env files"}, SALT)
        self.assertEqual(findings, [])

    def test_fields_the_record_does_not_carry_are_skipped(self):
        findings, _ = scan.scan_event({"event": "session.start"}, SALT)
        self.assertEqual(findings, [])


class StoreCase(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="gaide-trace-sec-"))
        self.store = server.Store(self.dir)

    def tearDown(self):
        shutil.rmtree(self.dir, ignore_errors=True)

    def findings(self, **where):
        sql = "SELECT * FROM security_findings"
        if where:
            sql += " WHERE " + " AND ".join(f"{k} = ?" for k in where)
        with self.store.connect() as db:
            return [dict(r) for r in db.execute(sql, list(where.values()))]

    def event(self, **kw):
        rec = {"trace_id": kw.pop("trace_id", "t1"), "ts": "2026-10-14T10:00:00Z",
               "event": "tool.call", "session_id": "s1", "project": "app"}
        rec.update(kw)
        return rec


class TestIngestScan(StoreCase):
    """AC1 on the ingest path, plus AC27."""

    def test_findings_are_created_and_attributed(self):
        self.store.ingest_events([self.event(
            tool_input=json.dumps({"command": "aws configure set key "
                                   + fake("aws_access_key_id")}))], "alice")
        rows = self.findings()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["rule"], "aws-access-key-id")
        self.assertEqual(row["severity"], "high")
        self.assertEqual(row["session_id"], "s1")
        self.assertEqual(row["project"], "app")
        self.assertEqual(row["origin"], "alice")
        self.assertEqual(row["source"], "event")
        self.assertEqual(row["trace_id"], "t1")
        self.assertEqual(row["location"], "tool_input")

    def test_re_ingesting_the_same_batch_adds_nothing(self):
        batch = [self.event(prompt="key " + fake("github_token"))]
        self.store.ingest_events(batch, "alice")
        before = self.findings()
        self.store.ingest_events(batch, "alice")
        self.assertEqual(self.findings(), before)

    def test_no_stored_row_contains_the_value(self):
        value = fake("anthropic_key")
        self.store.ingest_events([self.event(prompt=f"use {value} now")], "alice")
        with self.store.connect() as db:
            blob = json.dumps([dict(r) for r in db.execute(
                "SELECT * FROM security_findings")])
        self.assertNotIn(value, blob)
        self.assertNotIn(value[scan.EVIDENCE_PREFIX:], blob)

    def test_a_scan_failure_is_logged_and_does_not_cost_the_record(self):
        log = io.StringIO()
        with mock.patch.object(scan, "scan_event", side_effect=RuntimeError("boom")), \
                contextlib.redirect_stderr(log):
            inserted, _ = self.store.ingest_events(
                [self.event(prompt="hello")], "alice")
        self.assertEqual(inserted, 1)
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM events").fetchone()[0], 1)
        # Logged, not swallowed (Principle 8).
        self.assertIn("boom", log.getvalue())
        self.assertIn("security scan", log.getvalue())

    def test_terms_apply_to_their_project_only(self):
        with self.store.connect() as db:
            db.execute("INSERT INTO security_terms (project, term, created_at)"
                       " VALUES ('app', 'acme-holdings', '2026-10-14T00:00:00Z')")
            db.commit()
        self.store.ingest_events([
            self.event(trace_id="t1", prompt="acme-holdings deal"),
            self.event(trace_id="t2", session_id="s2", project="other",
                       prompt="acme-holdings deal"),
        ], "alice")
        rules = {(r["session_id"], r["rule"]) for r in self.findings()}
        self.assertIn(("s1", "custom-term"), rules)
        self.assertNotIn(("s2", "custom-term"), rules)


class TestTranscriptScan(StoreCase):
    """AC1 and AC6 on the transcript path."""

    def snapshot(self, *lines):
        return ("\n".join(json.dumps(x) if isinstance(x, dict) else x
                          for x in lines) + "\n").encode("utf-8")

    def test_findings_carry_the_line_number(self):
        data = self.snapshot(
            {"type": "user", "message": {"role": "user", "content": "hi"}},
            {"type": "assistant", "message": {"role": "assistant",
                                              "content": "key " + fake("github_token")}},
        )
        self.store.store_transcript("s1", data, "app", "alice")
        rows = self.findings(source="transcript")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["rule"], "github-token")
        self.assertEqual(rows[0]["location"], "line:2")

    def test_re_indexing_is_idempotent_and_leaves_the_file_identical(self):
        data = self.snapshot("plain line with " + fake("npm_token"))
        self.store.ingest_events([{"trace_id": "t1", "ts": "2026-10-14T09:00:00Z",
                                   "event": "session.start", "session_id": "s1",
                                   "project": "app"}], "alice")
        self.store.store_transcript("s1", data, "app", "alice")
        path = self.store.transcript_path("s1")
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        before = self.findings(source="transcript")
        self.store.index_transcript("s1", path, "app", "alice", "2026-10-14T11:00:00Z")
        after = self.findings(source="transcript")
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        self.assertEqual([dict(r, id=None) for r in after],
                         [dict(r, id=None) for r in before])

    def test_one_value_on_many_lines_is_one_finding(self):
        value = fake("anthropic_key")
        self.store.store_transcript(
            "s1", self.snapshot(*[f"line {i} {value}" for i in range(5)]),
            "app", "alice")
        rows = self.findings(source="transcript", rule="anthropic-api-key")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["count"], 5)
        self.assertEqual(rows[0]["location"], "line:1")

    def test_a_session_is_capped_and_the_truncation_is_recorded(self):
        lines = [f"AKIA{i:016d}" for i in range(scan.MAX_FINDINGS_PER_SESSION + 50)]
        self.store.store_transcript("s1", self.snapshot(*lines), "app", "alice")
        self.assertEqual(len(self.findings(source="transcript")),
                         scan.MAX_FINDINGS_PER_SESSION)
        with self.store.connect() as db:
            flag = db.execute("SELECT security_truncated FROM sessions"
                              " WHERE session_id = 's1'").fetchone()[0]
        self.assertEqual(flag, 1)

    def test_transcript_token_accounting_still_works(self):
        lines = fixtures.assistant_lines(
            "claude-opus-5", fixtures.usage(input_tokens=10, output_tokens=5),
            "2026-10-14T10:00:00Z", session_id="s1")
        data = ("\n".join(json.dumps(x) for x in lines) + "\n").encode("utf-8")
        self.store.store_transcript("s1", data, "app", "alice")
        with self.store.connect() as db:
            row = db.execute("SELECT input_tokens, output_tokens FROM sessions"
                             " WHERE session_id = 's1'").fetchone()
        self.assertEqual((row[0], row[1]), (10, 5))


class TestStoreSalt(StoreCase):
    """AC22 — the salt is per store and never served."""

    def test_salt_is_stable(self):
        salt = self.store.security_salt()
        self.assertEqual(salt, self.store.security_salt())
        self.assertGreaterEqual(len(salt), 16)

    def test_two_stores_fingerprint_the_same_value_differently(self):
        other_dir = Path(tempfile.mkdtemp(prefix="gaide-trace-sec2-"))
        self.addCleanup(shutil.rmtree, other_dir, ignore_errors=True)
        other = server.Store(other_dir)
        value = fake("aws_access_key_id")
        self.assertNotEqual(scan.fingerprint(value, self.store.security_salt()),
                            scan.fingerprint(value, other.security_salt()))


if __name__ == "__main__":
    unittest.main()
