#!/usr/bin/env python3
"""
GAIDE-Trace — ledger security scanner (specs/security-scan, ADR 0003).

Reads the text the server already stores — the indexed event fields and the
transcript snapshots — and reports two things: potentially confidential
information that passed through a session, and (from Sprint 2 on) the security
activity that happened while the work was done.

Three rules shape everything here:

* **A finding is a pointer, not a copy.** The matched value never leaves
  `scan_text`: callers only ever receive masked evidence (at most the first
  `EVIDENCE_PREFIX` characters plus a length) and a fingerprint. Storing the
  value would turn the index into one queryable table holding every secret the
  store has ever seen — a worse exposure than the one this module reports.
* **Fingerprints are salted per store.** A CPF has ~10^11 possible values, so
  an unsalted digest of one is reversible in seconds; an HMAC over a secret the
  store never serves is not.
* **Bounded by construction.** The scanned text is written by whoever holds an
  `agent` key. Every pattern is linear (no nested quantifiers), every input is
  capped, and the caps are reported rather than silently applied.

The catalogue is deliberately code, not configuration: a user-supplied pattern
is arbitrary cost on the ingest path, and two stores with different rules are
not comparable for research. Admins configure *terms* — literal keywords —
which are matched with `str.count`, never compiled.

This module is standard library only (AGENTS.md, Tech stack) and imports
nothing from the server, so a local command over a `.gaide-trace` store can
reuse it unchanged.
"""

import hashlib
import hmac
import re
from collections import namedtuple

# ---------------------------------------------------------------- limits

# Far above any real prompt, tool payload or transcript line, and small enough
# that ~40 patterns over it stay in the millisecond range.
MAX_SCAN_CHARS = 50_000
# One record (or one transcript line) cannot contribute more than this many
# distinct findings; one session cannot contribute more than the session cap.
MAX_FINDINGS_PER_RECORD = 20
MAX_FINDINGS_PER_SESSION = 1_000
# How much of a match may appear in the evidence (AC21).
EVIDENCE_PREFIX = 4
FINGERPRINT_CHARS = 12
# Term rules, enforced by the API (AC18) and documented here next to the use.
TERM_MIN_CHARS, TERM_MAX_CHARS = 4, 64
MAX_TERMS_PER_PROJECT = 100

# ---------------------------------------------------------------- vocabulary

SECRET = "secret"
PATH = "sensitive-path"
PII = "pii"
INTERNAL = "internal"
REDACTION = "redaction"
CATEGORIES = (SECRET, PATH, PII, INTERNAL, REDACTION)

HIGH, MEDIUM, LOW = "high", "medium", "low"
SEVERITIES = (HIGH, MEDIUM, LOW)

Rule = namedtuple("Rule", "name category severity pattern validate reveal")


def _rule(name, category, severity, pattern, validate=None, reveal=EVIDENCE_PREFIX):
    """A catalogue entry. `reveal` is how many leading characters the evidence
    may carry: four for credentials and paths (enough to tell *which* key to
    rotate), none for personal data."""
    return Rule(name, category, severity, re.compile(pattern), validate, reveal)


# ---------------------------------------------------------------- validators


def _digits(value: str) -> str:
    return "".join(c for c in value if c.isdigit())


def valid_cpf(value: str) -> bool:
    """Brazilian individual taxpayer id, by its two check digits. Without this,
    any eleven-digit number — a phone, an order id — would be reported as
    personal data (AC7)."""
    d = [int(c) for c in _digits(value)]
    if len(d) != 11 or len(set(d)) == 1:
        return False
    for i in (9, 10):
        total = sum(d[j] * ((i + 1) - j) for j in range(i))
        if (total * 10) % 11 % 10 != d[i]:
            return False
    return True


def valid_cnpj(value: str) -> bool:
    """Brazilian company taxpayer id, by its two check digits."""
    d = [int(c) for c in _digits(value)]
    if len(d) != 14 or len(set(d)) == 1:
        return False
    for size in (12, 13):
        weights = list(range(size - 7, 1, -1)) + list(range(9, 1, -1))
        total = sum(a * b for a, b in zip(d[:size], weights))
        check = 11 - total % 11
        if (0 if check >= 10 else check) != d[size]:
            return False
    return True


def valid_card(value: str) -> bool:
    """Payment card number by the Luhn checksum."""
    d = [int(c) for c in _digits(value)]
    if not 13 <= len(d) <= 19 or len(set(d)) == 1:
        return False
    total = 0
    for i, n in enumerate(reversed(d)):
        if i % 2:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


_PLACEHOLDER = re.compile(
    r"(?i)^(?:\[?redacted\]?|x{3,}|\*{3,}|\.{3,}|-{3,}|changeme|placeholder|"
    r"your[-_]?\w*|example\w*|dummy\w*|sample\w*|fake\w*|test\w*|secret|"
    r"password|token|none|null|nil|true|false|undefined)$")


def _real_secret(value: str) -> bool:
    """Whether an assigned value looks like an actual secret rather than a
    placeholder, an environment reference or capture's own redaction marker.
    Capture redacts before anything reaches disk (D5), so in event text this
    rule mostly meets `[REDACTED]` — which the redaction rule counts instead."""
    value = value.strip("'\"")
    if not value or _PLACEHOLDER.match(value):
        return False
    if value[0] in "$<%{" or "${" in value or "{{" in value:
        return False
    # "aaaaaaaa", "00000000": no real key has three distinct characters.
    return len(set(value)) >= 4


# ---------------------------------------------------------------- catalogue
#
# Severities follow spec AC4: credentials and sensitive-path access are high;
# taxpayer ids, cards, connection strings, JWTs and custom terms are medium;
# e-mail, phone numbers and capture's redaction markers are low.
# `(?P<v>...)` marks the part that is fingerprinted when the whole match would
# carry context (a key name, a URL) rather than the secret itself.

RULES = (
    # -- credentials ----------------------------------------------------
    _rule("private-key-block", SECRET, HIGH,
          r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----"),
    _rule("aws-access-key-id", SECRET, HIGH,
          r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    _rule("github-token", SECRET, HIGH,
          r"\bgh[pousr]_[A-Za-z0-9]{36}\b"),
    _rule("github-token-pat", SECRET, HIGH,
          r"\bgithub_pat_[A-Za-z0-9_]{22,}"),
    _rule("anthropic-api-key", SECRET, HIGH,
          r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
    # Anything sk- that is not the Anthropic shape above.
    _rule("openai-api-key", SECRET, HIGH,
          r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}"),
    _rule("google-api-key", SECRET, HIGH,
          r"\bAIza[0-9A-Za-z_-]{30,}"),
    _rule("slack-token", SECRET, HIGH,
          r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    _rule("slack-webhook", SECRET, HIGH,
          r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{10,}"),
    _rule("npm-token", SECRET, HIGH,
          r"\bnpm_[A-Za-z0-9]{36}\b"),
    _rule("stripe-key", SECRET, HIGH,
          r"\b[sr]k_live_[A-Za-z0-9]{10,}"),
    _rule("pypi-token", SECRET, HIGH,
          r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{10,}"),
    _rule("vault-token", SECRET, HIGH,
          r"\bhv[sb]\.[A-Za-z0-9_-]{20,}"),
    _rule("secret-assignment", SECRET, HIGH,
          r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd|credential|"
          r"private[_-]?key|access[_-]?key)\b\s*[:=]\s*[\"']?"
          r"(?P<v>[^\s\"',;]{8,128})",
          validate=_real_secret),
    _rule("jwt", SECRET, MEDIUM,
          r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}"),
    _rule("credentials-in-url", SECRET, MEDIUM,
          r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@]{1,64}:(?P<v>[^\s:/@]{1,128})@"),

    # -- sensitive paths (scanned only where a tool addressed a file) ----
    _rule("env-file", PATH, HIGH, r"\.env(?:\.[A-Za-z0-9_-]{1,20})?\b"),
    _rule("private-key-file", PATH, HIGH,
          r"\.(?:keystore|pem|pfx|p12|jks|key)\b"),
    _rule("ssh-private-key-file", PATH, HIGH,
          r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b"),
    _rule("ssh-dir", PATH, HIGH, r"\.ssh/"),
    _rule("aws-credentials-file", PATH, HIGH, r"\.aws/(?:credentials|config)\b"),
    _rule("kube-config", PATH, HIGH, r"\.kube/config\b"),
    _rule("gcloud-config", PATH, HIGH, r"\.config/gcloud\b"),
    _rule("docker-config", PATH, HIGH, r"\.docker/config\.json\b"),
    _rule("netrc", PATH, HIGH, r"\.netrc\b"),
    _rule("npmrc-or-pypirc", PATH, HIGH, r"\.(?:npmrc|pypirc)\b"),
    _rule("git-credentials", PATH, HIGH, r"\.git-credentials\b"),

    # -- personal data (no characters revealed) --------------------------
    _rule("cpf", PII, MEDIUM,
          r"(?<!\d)(?:\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})(?!\d)",
          validate=valid_cpf, reveal=0),
    _rule("cnpj", PII, MEDIUM,
          r"(?<!\d)(?:\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}|\d{14})(?!\d)",
          validate=valid_cnpj, reveal=0),
    _rule("credit-card", PII, MEDIUM,
          r"(?<!\d)(?:\d{4}[ -]?){3}\d{4}(?!\d)",
          validate=valid_card, reveal=0),
    _rule("email", PII, LOW,
          r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,64}\.[A-Za-z]{2,24}\b",
          reveal=0),
    # Requires the country code: an unanchored 11-digit phone pattern reports
    # every order number in the ledger.
    _rule("phone-br", PII, LOW,
          r"\+55\s?\(?\d{2}\)?\s?9?\d{4}[-\s]?\d{4}", reveal=0),

    # -- capture's own redaction (informational) -------------------------
    _rule("redaction-marker", REDACTION, LOW, r"\[REDACTED\]", reveal=0),
)

TERM_RULE = "custom-term"

# Event fields carrying text worth scanning, and the ones where a path rule
# means the session actually addressed the file. A prompt saying "never read
# .env" is not an exposure; a tool input naming it is.
EVENT_TEXT_FIELDS = ("prompt", "tool_input", "tool_response",
                     "last_assistant_message")
PATH_SCANNED_FIELDS = frozenset({"tool_input"})


# ---------------------------------------------------------------- primitives


def fingerprint(value: str, salt: bytes) -> str:
    """Stable, salted, truncated identity of a matched value. Groups one value
    across sessions without storing it (ADR 0003)."""
    if isinstance(salt, str):
        salt = salt.encode("utf-8")
    digest = hmac.new(salt, value.encode("utf-8", "surrogatepass"),
                      hashlib.sha256).hexdigest()
    return digest[:FINGERPRINT_CHARS]


def mask(value: str, reveal: int = EVIDENCE_PREFIX) -> str:
    """Display form of a match: at most `reveal` leading characters plus the
    length. Control characters are dropped so the console can print it."""
    head = "".join(c for c in value[:reveal] if c.isprintable()) if reveal else ""
    return f"{head}\u2026[{len(value)} chars]"


def _finding(rule, value, salt):
    return {
        "category": rule.category,
        "rule": rule.name,
        "severity": rule.severity,
        "evidence": mask(value, rule.reveal),
        "fingerprint": fingerprint(value, salt),
        "count": 1,
    }


def scan_text(text, salt, terms=(), skip_categories=()):
    """Findings in one piece of text, as `(findings, truncated)`.

    The matched value never leaves this function — that is what makes AC21
    structural rather than a convention callers have to remember. Repeats of
    one value collapse into a single finding carrying a count."""
    if not text:
        return [], False
    truncated = False
    if len(text) > MAX_SCAN_CHARS:
        text, truncated = text[:MAX_SCAN_CHARS], True
    agg = {}
    capped = False
    for rule in RULES:
        if rule.category in skip_categories:
            continue
        for match in rule.pattern.finditer(text):
            value = match.groupdict().get("v") or match.group(0)
            if rule.validate and not rule.validate(value):
                continue
            key = (rule.name, fingerprint(value, salt))
            existing = agg.get(key)
            if existing:
                existing["count"] += 1
                continue
            if len(agg) >= MAX_FINDINGS_PER_RECORD:
                capped = truncated = True
                break
            agg[key] = _finding(rule, value, salt)
        if capped:
            break
    if terms and not capped:
        lowered = text.lower()
        for term in terms:
            needle = term.lower()
            if len(needle) < TERM_MIN_CHARS:
                continue
            hits = lowered.count(needle)
            if not hits:
                continue
            key = (TERM_RULE, fingerprint(needle, salt))
            if key in agg:
                agg[key]["count"] += hits
                continue
            if len(agg) >= MAX_FINDINGS_PER_RECORD:
                truncated = True
                break
            agg[key] = {"category": INTERNAL, "rule": TERM_RULE,
                        "severity": MEDIUM, "evidence": mask(needle),
                        "fingerprint": fingerprint(needle, salt), "count": hits}
    return list(agg.values()), truncated


def scan_event(row, salt, terms=()):
    """Findings for one event row, located by the field they came from."""
    out, truncated = [], False
    for field in EVENT_TEXT_FIELDS:
        text = row.get(field)
        if not isinstance(text, str) or not text:
            continue
        skip = () if field in PATH_SCANNED_FIELDS else (PATH,)
        findings, field_truncated = scan_text(text, salt, terms,
                                              skip_categories=skip)
        truncated = truncated or field_truncated
        for finding in findings:
            finding["location"] = field
        out.extend(findings)
    if len(out) > MAX_FINDINGS_PER_RECORD:
        out, truncated = out[:MAX_FINDINGS_PER_RECORD], True
    return out, truncated


class TranscriptScan:
    """Collects a snapshot's findings line by line, under the session cap.

    One value seen on many lines is one finding with a count: a transcript
    repeats whole tool results across content blocks, so per-line rows would be
    thousands of copies of a single fact."""

    def __init__(self, salt, terms=()):
        self.salt = salt
        self.terms = tuple(terms)
        self.truncated = False
        self._agg = {}

    def line(self, number, raw):
        """Scan one line. `number` is its 1-based position in the file."""
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8", "replace")
        findings, truncated = scan_text(raw, self.salt, self.terms)
        self.truncated = self.truncated or truncated
        for finding in findings:
            key = (finding["rule"], finding["fingerprint"])
            existing = self._agg.get(key)
            if existing:
                existing["count"] += finding["count"]
                continue
            if len(self._agg) >= MAX_FINDINGS_PER_SESSION:
                self.truncated = True
                continue
            finding["location"] = f"line:{number}"
            self._agg[key] = finding

    def findings(self):
        return list(self._agg.values())
