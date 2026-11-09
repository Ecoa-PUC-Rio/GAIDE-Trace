"""Capture-time redaction, specs/capture-redaction (AC1 to AC21), issue #3.

Every credential-shaped value is assembled at runtime by `fixtures.fake`, so
no complete pattern is a literal in this repository (tests/README.md,
Constitution Principles 6 and 10). The text under test is what `clean()`
produces: JSON-serialized tool input, with quotes inside string values
escaped, because that is the shape `redact()` actually sees in production.
"""

import json
import re
import time
import unittest
from pathlib import Path

import fixtures
from fixtures import fake, load_hook

hook = load_hook()
redact = hook.redact
clean = hook.clean

MARK = "[REDACTED]"
MAX = 20000


def captured(tool_input):
    """`tool_input` as the hook stores it: serialized, redacted, truncated."""
    return clean(tool_input, MAX)


def assert_gone(testcase, text, secret):
    """No 8-character window of `secret` survives in `text`. Checking windows
    instead of the whole value catches partial redaction too."""
    for i in range(0, max(1, len(secret) - 7)):
        window = secret[i:i + 8]
        testcase.assertNotIn(window, text, f"fragment {window!r} of the credential survived in {text!r}")


class TestAuthorizationSchemes(unittest.TestCase):
    """AC1 to AC4: HTTP authentication schemes (the issue #3 report)."""

    def test_ac1_bearer_header_in_shell_command(self):
        jwt = fake("jwt")
        out = captured({"command": f'curl -H "Authorization: Bearer {jwt}" https://api.example/v1'})
        assert_gone(self, out, jwt)
        self.assertIn("Authorization: Bearer " + MARK, out)
        self.assertIn("https://api.example/v1", out)

    def test_ac1_bearer_with_opaque_token(self):
        token = fake("opaque_token")
        out = captured({"command": f"curl -H 'Authorization: Bearer {token}' https://api.example"})
        assert_gone(self, out, token)
        self.assertIn("Bearer " + MARK, out)

    def test_ac2_bearer_header_as_dict_value(self):
        jwt = fake("jwt")
        out = captured({"url": "https://api.example", "headers": {"Authorization": f"Bearer {jwt}"}})
        assert_gone(self, out, jwt)
        self.assertEqual(json.loads(out)["headers"]["Authorization"], "Bearer " + MARK)

    def test_ac3_lowercase_scheme_and_equals_separator(self):
        token = fake("opaque_token")
        for text in (f"bearer {token}", f"Authorization=Bearer {token}", f"AUTHORIZATION: BEARER {token}"):
            out = redact(text)
            assert_gone(self, out, token)
            self.assertIn(MARK, out)

    def test_ac4_basic_credentials_redacted(self):
        cred = fake("basic_credential")
        out = captured({"command": f'curl -H "Authorization: Basic {cred}" https://api.example'})
        assert_gone(self, out, cred)
        self.assertIn("Basic " + MARK, out)

    def test_ac4_prose_mentioning_schemes_is_untouched(self):
        for text in ("Basic Authentication is simpler than Bearer tokens",
                     "the bearer certificate was basic paperwork",
                     "Use Bearer tokens, not Basic credentials, for the API"):
            self.assertEqual(redact(text), text)


class TestBareJwt(unittest.TestCase):
    """AC5: a JWT with no key and no scheme in front of it."""

    def test_ac5_jwt_in_response_body(self):
        jwt = fake("jwt")
        body = json.dumps({"access_token": jwt, "expires_in": 3600, "kind": "eyJ-looking-but-not"})
        out = clean(body, MAX)
        assert_gone(self, out, jwt)
        self.assertIn('"expires_in": 3600', out)
        self.assertIn("eyJ-looking-but-not", out)

    def test_ac5_jwt_alone_in_text(self):
        jwt = fake("jwt")
        out = redact(f"decoded header of {jwt} says HS256")
        assert_gone(self, out, jwt)
        self.assertEqual(out, f"decoded header of {MARK} says HS256")


class TestQuotedAssignments(unittest.TestCase):
    """AC6: the quoting the serializer and shells actually produce."""

    def test_ac6_escaped_double_quotes_from_serialization(self):
        pw = fake("password_value")
        out = captured({"command": f'mysql --password="{pw}" --host db app'})
        assert_gone(self, out, pw)
        self.assertIn("--password=", out)
        self.assertIn("--host db app", out)

    def test_ac6_single_quoted_value(self):
        pw = fake("password_value")
        out = captured({"command": f"mysql --password='{pw}' app"})
        assert_gone(self, out, pw)
        self.assertIn("--password=", out)

    def test_ac6_exported_variable_with_escaped_quotes(self):
        key = fake("secret_body")
        out = captured({"command": f'export API_KEY="{key}" && ./deploy.sh'})
        assert_gone(self, out, key)
        self.assertIn("API_KEY=", out)
        self.assertIn("./deploy.sh", out)

    def test_ac6_header_style_key_with_escaped_quotes(self):
        key = fake("secret_body")
        out = captured({"command": f'curl -H "x-api-key: {key}" https://api.example'})
        assert_gone(self, out, key)
        self.assertIn("x-api-key: " + MARK, out)
        self.assertIn("https://api.example", out)


class TestReviewFindings(unittest.TestCase):
    """AC12 to AC15: gaps found by the clean-context security review."""

    def test_ac12_punctuation_inside_quoted_value(self):
        pw = fake("password_value")
        for inner in (f"it's{pw}", f"ab,{pw}", f"{pw};{pw}", f"{pw}'{pw}"):
            out = captured({"command": f'mysql --password="{inner}" db'})
            assert_gone(self, out, pw)
            self.assertIn('--password=\\"[REDACTED]\\" db', out)
        out = captured({"command": f"mysql --password='a,b;{pw}' db"})
        assert_gone(self, out, pw)
        self.assertIn("--password='[REDACTED]' db", out)

    def test_ac13_doubly_escaped_json_body_in_shell(self):
        pw = fake("password_value")
        shell = 'curl -d "{\\"password\\": \\"' + pw + '\\"}" https://x'
        out = captured({"command": shell})
        assert_gone(self, out, pw)
        self.assertIn("https://x", out)
        self.assertEqual(json.loads(out)["command"].count("[REDACTED]"), 1)

    def test_ac14_keyword_with_suffix(self):
        key = fake("secret_body") + fake("secret_body")
        out = captured({"command": f"export AWS_SECRET_ACCESS_KEY={key} AWS_REGION=us-east-1"})
        assert_gone(self, out, key)
        self.assertIn("AWS_SECRET_ACCESS_KEY=[REDACTED] AWS_REGION=us-east-1", out)
        self.assertEqual(redact("secretary: Jonathan Appleseed"), "secretary: Jonathan Appleseed")

    def test_ac15_numeric_values_under_sensitive_keys_keep_json_valid(self):
        tool_input = {"max_token": 20000000, "token": 123456789, "password_attempts": 10, "x": 1}
        out = captured(tool_input)
        self.assertEqual(json.loads(out), tool_input)

    def test_ac15_truncated_private_key_is_still_masked(self):
        block = fake("private_key_header") + "\nMIIBogIBAAJBALRiMLAH\nQIDAQABAoIBAE"
        out = redact("head -3 id_rsa\n" + block)
        self.assertEqual(out, "head -3 id_rsa\n" + MARK)


class TestSecondReviewFindings(unittest.TestCase):
    """AC16 to AC18: gaps found by the second clean-context review."""

    def test_ac16_escaped_quote_or_backslash_inside_quoted_value(self):
        pw = fake("password_value")
        for shell in (f'mysql --password="ab\\"{pw}" db',      # a \" inside the value
                      f'mysql --password="ab\\\\{pw}" db',   # a literal backslash inside
                      f"mysql --password='ab\\'{pw}' db"):
            out = captured({"command": shell})
            assert_gone(self, out, pw)
            self.assertIn("[REDACTED]", out)
            self.assertIn(" db", json.loads(out)["command"])

    def test_ac16_bare_value_with_separators_is_masked_whole(self):
        pw = fake("password_value")
        out = captured({"command": f"export TOKEN=abcdefgh,{pw};{pw} && run"})
        assert_gone(self, out, pw)
        self.assertIn("TOKEN=[REDACTED] && run", out)

    def test_ac17_other_authorization_schemes_and_quoted_scheme_value(self):
        token = fake("opaque_token")
        for value in (f"Token {token}", f"ApiKey {token}", f'Bearer "{token}"', f"Digest {token}"):
            out = captured({"headers": {"Authorization": value}})
            assert_gone(self, out, token)
            self.assertTrue(json.loads(out)["headers"]["Authorization"].endswith("[REDACTED]") or
                            json.loads(out)["headers"]["Authorization"].endswith('[REDACTED]"'), out)
        out = captured({"command": f"password=\t{fake('password_value')}"})
        assert_gone(self, out, fake("password_value"))

    def test_ac18_truncated_private_key_inside_record_keeps_siblings(self):
        block = fake("private_key_header") + "\nMIIBogIBAAJBALRiMLAH\nQIDAQABAoIBAE"
        out = captured({"content": block, "file_path": "/home/u/.ssh/id_rsa"})
        parsed = json.loads(out)
        self.assertEqual(parsed, {"content": MARK, "file_path": "/home/u/.ssh/id_rsa"})

    def test_ac18_prose_keywords_untouched(self):
        text = "secretary: Jonathan Appleseed; token_type: Bearer; the tokenizer: fast"
        self.assertEqual(redact(text), text)


class TestThirdReviewFindings(unittest.TestCase):
    """AC19 to AC21: gaps found by the third clean-context review."""

    def test_ac19_non_integer_numbers_under_sensitive_keys_keep_json_valid(self):
        tool_input = {"token_cost": 0.00012345, "secret_delta": -12345678,
                      "password_entropy": 1.5e-10, "token_total": 1234567.89, "x": 1}
        out = captured(tool_input)
        self.assertEqual(json.loads(out), tool_input)

    def test_ac20_depth0_string_ending_in_backslash_keeps_siblings(self):
        tool_input = {"token_path": "C:\\Users\\me\\", "content": "hello", "file_path": "x"}
        out = captured(tool_input)
        parsed = json.loads(out)
        self.assertEqual(parsed["content"], "hello")
        self.assertEqual(parsed["file_path"], "x")
        self.assertIn(MARK, parsed["token_path"])

    def test_ac20_long_quoted_value_is_masked(self):
        long_key = ("A1b2C3d4" * 300) + fake("secret_body")
        out = captured({"api_key": long_key})
        assert_gone(self, out, long_key)
        self.assertEqual(json.loads(out), {"api_key": MARK})

    def test_ac21_scheme_credential_with_non_token68_char_and_tab(self):
        pw = fake("password_value")
        out = captured({"headers": {"Authorization": f"Bearer abc12345|{pw}"}})
        assert_gone(self, out, pw)
        self.assertEqual(json.loads(out)["headers"]["Authorization"], "Bearer " + MARK)
        out = captured({"command": f'curl -H "Authorization: Bearer abc12345|{pw}" https://x'})
        assert_gone(self, out, pw)
        self.assertIn("https://x", json.loads(out)["command"])
        out = captured({"headers": {"Authorization": f"bearer\t{pw}"}})
        assert_gone(self, out, pw)
        self.assertEqual(json.loads(out)["headers"]["Authorization"], "bearer\t" + MARK)


class TestShapeProperties(unittest.TestCase):
    """AC7, AC8: redaction preserves JSON validity and is idempotent."""

    def inputs(self):
        jwt, pw, key = fake("jwt"), fake("password_value"), fake("secret_body")
        return [
            {"command": f'curl -H "Authorization: Bearer {jwt}" u'},
            {"command": f'curl -H "x-api-key: {key}" u'},
            {"command": f'mysql --password="{pw}" db'},
            {"command": f"mysql --password='{pw}' db"},
            {"headers": {"Authorization": f"Basic {fake('basic_credential')}"}},
            {"env": {"TOKEN": key, "PASSWORD": pw}},
            {"body": json.dumps({"access_token": jwt})},
            {"text": f"keys: {fake('anthropic_key')} {fake('github_token')} {fake('aws_access_key_id')}"},
        ]

    def test_ac7_redacted_tool_input_is_still_json(self):
        for tool_input in self.inputs():
            out = captured(tool_input)
            parsed = json.loads(out)
            self.assertEqual(set(parsed), set(tool_input))
            self.assertIn(MARK, out)

    def test_ac8_redaction_is_idempotent(self):
        for tool_input in self.inputs():
            once = captured(tool_input)
            self.assertEqual(redact(once), once)


class TestRegressions(unittest.TestCase):
    """AC9, AC10: pre-existing rules and the D4 guarantees."""

    def test_ac9_vendor_prefixed_keys_still_redacted(self):
        for kind in ("anthropic_key", "openai_key", "github_token", "github_pat", "aws_access_key_id"):
            secret = fake(kind)
            out = redact(f"found {secret} in the logs")
            assert_gone(self, out, secret)
            self.assertEqual(out, f"found {MARK} in the logs")

    def test_ac9_private_key_block_still_redacted(self):
        block = fake("private_key_header") + "\nMIIBogIBAAJBALRiMLAH\n-----END RSA PRIVATE KEY-----"
        out = redact("cat id_rsa\n" + block)
        self.assertNotIn("MIIBogIBAAJBALRiMLAH", out)
        self.assertEqual(out, "cat id_rsa\n" + MARK)

    def test_ac9_plain_key_value_still_redacted(self):
        key = fake("secret_body")
        for text in (f"api_key={key}", f'"api_key": "{key}"', f"API-KEY = {key}", f"secret: {key}"):
            out = redact(text)
            assert_gone(self, out, key)
            self.assertIn(MARK, out)

    def test_ac9_short_values_and_ordinary_text_untouched(self):
        for text in ("password=short", "token: abc", "the secret ingredient is love",
                     "Authorization header missing", "export PATH=/usr/bin:/bin"):
            self.assertEqual(redact(text), text)

    def test_ac10_empty_and_none(self):
        self.assertEqual(redact(""), "")
        self.assertIsNone(clean(None, MAX))

    def test_ac10_nested_credential_through_clean(self):
        jwt = fake("jwt")
        out = clean({"a": [{"b": {"Authorization": f"Bearer {jwt}"}}]}, MAX)
        assert_gone(self, out, jwt)

    def test_ac10_pathological_input_stays_linear(self):
        """A hostile payload must not stall the hook (D4, 15 s budget). One
        worst case per rule, each far above the default field cap because
        redaction runs before truncation."""
        big = 400_000
        payloads = {
            "scheme": ("Authorization: Bearer " + "A" * 7 + " ") * (big // 30),
            "key_value": ("password=\\\"" + "x" * 7 + " ") * (big // 18),
            "key_value_unterminated": ("token=\\\"" + "x" * 20) * (big // 28),
            "keyword_run": "token_" * (big // 6),
            "keyword_hyphen_run": "auth-token-cache-entry-" * (big // 23),
            "depth0_unterminated": ('"token": "' + "x" * 20) * (big // 30),
            "scheme_pipe": ("Bearer abc12345|" + "x" * 10 + " ") * (big // 27),
            "jwt": "-eyJ" * (big // 4),
            "private_key": (fake("private_key_header") + "\n") * (big // 30),
            "quotes": "token" + "\\\"'" * (big // 3),
        }
        for name, junk in payloads.items():
            start = time.monotonic()
            redact(junk)
            self.assertLess(time.monotonic() - start, 1.0, name)


class TestFixtureHygiene(unittest.TestCase):
    """AC11: no complete credential literal in this test module."""

    def test_ac11_no_literal_credentials_in_test_sources(self):
        source = Path(__file__).read_text(encoding="utf-8")
        source += Path(fixtures.__file__).read_text(encoding="utf-8")
        self.assertIsNone(re.search(r"eyJ[A-Za-z0-9_-]{8,}\.", source))
        self.assertIsNone(re.search(r"sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}", source))


if __name__ == "__main__":
    unittest.main()
