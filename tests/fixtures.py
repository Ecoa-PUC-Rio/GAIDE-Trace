"""Synthesized fixtures for the test suite.

Every byte here is hand-written. Real stores carry prompts, file contents and
third-party personal data, so nothing is ever copied from `.gaide-trace/` or a
server archive (see tests/README.md).

The transcript builders mimic the Claude Code JSONL shape the server parses:
one line per content block, each repeating the message's `id`, `model` and
`usage` — which is what made per-line summing double-count tokens.
"""

import importlib.util
import json
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def load_server():
    """Import server/gaide_trace_server.py as a module (it is a script, not a
    package — deployments copy the single file)."""
    spec = importlib.util.spec_from_file_location(
        "gaide_trace_server", REPO / "server" / "gaide_trace_server.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def usage(input_tokens=0, output_tokens=0, cache_read=0, cache_write=0,
          cache_5m=None, cache_1h=None, speed="standard"):
    u = {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "cache_read_input_tokens": cache_read,
        "cache_creation_input_tokens": cache_write,
        "service_tier": "standard",
    }
    if cache_5m is not None or cache_1h is not None:
        u["cache_creation"] = {"ephemeral_5m_input_tokens": cache_5m or 0,
                               "ephemeral_1h_input_tokens": cache_1h or 0}
    if speed is not None:
        u["speed"] = speed
    return u


def assistant_lines(model, u, ts, msg_id="auto", blocks=1, session_id="s"):
    """One assistant message written as `blocks` transcript lines. Pass
    msg_id=None for a message without an id."""
    if msg_id == "auto":
        msg_id = "msg_" + uuid.uuid4().hex[:20]
    lines = []
    for i in range(blocks):
        message = {"model": model, "role": "assistant", "type": "message",
                   "content": [{"type": "text", "text": f"block {i}"}],
                   "usage": u}
        if msg_id is not None:
            message["id"] = msg_id
        lines.append({"type": "assistant", "uuid": uuid.uuid4().hex,
                      "sessionId": session_id, "timestamp": ts,
                      "message": message})
    return lines


def user_line(text, ts, session_id="s"):
    return {"type": "user", "uuid": uuid.uuid4().hex, "sessionId": session_id,
            "timestamp": ts, "message": {"role": "user", "content": text}}


def transcript(*groups, malformed=False):
    """Join lines (or lists of lines) into transcript bytes."""
    out = []
    for g in groups:
        out.extend(g if isinstance(g, list) else [g])
    text = "\n".join(json.dumps(line) for line in out) + "\n"
    if malformed:
        text += "{not json\n"
    return text.encode("utf-8")


def event(session_id, event_name, ts, **fields):
    """A canonical event record as an adapter would ship it."""
    rec = {"trace_id": uuid.uuid4().hex[:12], "ts": ts, "event": event_name,
           "session_id": session_id, "source": fields.pop("source", "claude-code")}
    rec.update(fields)
    return rec


# ---------------------------------------------------------------- fake secrets
#
# Every secret-shaped value is assembled at runtime from fragments. A complete
# key-shaped literal in this repository is exactly what gitleaks and semgrep
# exist to catch, and an allowlist entry to quiet them would violate
# Constitution Principle 10 — so the literals never exist, instead of being
# excused. PII values below are the canonical published test numbers (a valid
# CPF/CNPJ/card shape that belongs to nobody).

_FAKE_FRAGMENTS = {
    "aws_access_key_id": ("AK", "IA", "ABCDEFGHIJKLMNOP"),
    "github_token": ("gh", "p_", "0123456789abcdefghijklmnopqrstuvwxyz"),
    "github_pat": ("github", "_pat_", "11ABCDEFG0abcdefghijkl", "mnopqrstuvwxyz0123456789"),
    "anthropic_key": ("sk-", "ant-", "api03-", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"),
    "openai_key": ("sk-", "proj-", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"),
    "google_api_key": ("AI", "za", "Sy", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5"),
    "slack_token": ("xo", "xb-", "1234567890-0987654321-", "abcdefghijklmnopqrst"),
    "slack_webhook": ("https://hooks.", "slack.com", "/services/", "T0A1B2C3/B4D5E6F7/", "abcdefghij0123456789"),
    "npm_token": ("npm", "_", "0123456789abcdefghijklmnopqrstuvwxyz"),
    "stripe_key": ("sk", "_live_", "0123456789abcdefABCDEF"),
    "pypi_token": ("pypi-", "AgEIcHlwaS5vcmc", "ABCDEFGHIJKLMNOP"),
    "vault_token": ("hv", "s.", "A1b2C3d4E5f6G7h8I9j0K1l2"),
    "private_key_header": ("-----BEGIN RSA ", "PRIVATE KEY", "-----"),
    "jwt": ("ey", "JhbGciOiJIUzI1NiJ9", ".", "eyJzdWIiOiJ0ZXN0LXVzZXIifQ", ".", "c2lnbmF0dXJl"),
    "password_value": ("sup3r", "S3cret", "Value42"),
    "secret_body": ("A1b2", "C3d4E5f6", "G7h8I9j0"),
}

# Published test values: valid check digits / Luhn, nobody's real data.
TEST_CPF = "123.456.789-09"
TEST_CPF_DIGITS = "12345678909"
TEST_CNPJ = "11.222.333/0001-81"
TEST_CARD = "4111 1111 1111 1111"


def fake(kind: str) -> str:
    """A fake credential of `kind`, assembled so no complete pattern is ever a
    literal in the repository (see the note above)."""
    return "".join(_FAKE_FRAGMENTS[kind])


def conn_string() -> str:
    """A database URL carrying a password, assembled the same way."""
    return "postgres://appuser:" + fake("password_value") + "@db.internal:5432/app"


def assignment(key: str = "api_key") -> str:
    """A `key = value` line whose value is a plausible secret."""
    return f'{key} = "' + fake("secret_body") + '"'
