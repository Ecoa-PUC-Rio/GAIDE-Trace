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
import json
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

Rule = namedtuple("Rule", "name category severity pattern validate reveal gate")

# A cheap necessary condition for the digit rules, which have no literal of
# their own: one C-speed pass stands in for three backtracking ones. Three, not
# four: a CPF written with separators (123.456.789-09) never has four digits in
# a row, and a gate the pattern does not imply is a silent false negative.
DIGIT_RUN_RE = re.compile(r"\d{3}")


def _rule(name, category, severity, pattern, validate=None,
          reveal=EVIDENCE_PREFIX, gate=()):
    """A catalogue entry. `reveal` is how many leading characters the evidence
    may carry: four for credentials and paths (enough to tell *which* key to
    rotate), none for personal data.

    `gate` is a necessary condition for the pattern, checked before the regex
    runs: a tuple of lowercase literals (any one of which must appear) or a
    cheap pattern. Substring search is C-speed and these rules are specific,
    so on ordinary code and tool output nearly the whole catalogue is skipped
    without the regex engine starting — which is what keeps the scan affordable
    on the ingest path (Task 20: 33 unconditional passes over the four fields
    of one maximal record cost ~19 ms, or 3.7 s for a shipping batch).

    A gate that is not genuinely implied by the pattern would be a silent
    false negative, so every rule's positive case is exercised in the suite and
    one test compares a gated scan against an ungated one over the whole
    corpus."""
    return Rule(name, category, severity, re.compile(pattern), validate,
                reveal, gate)


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
          r"-----BEGIN [A-Z ]{0,30}PRIVATE KEY-----",
          gate=("private key",)),
    _rule("aws-access-key-id", SECRET, HIGH,
          r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b",
          gate=("akia", "asia", "abia", "acca")),
    _rule("github-token", SECRET, HIGH,
          r"\bgh[pousr]_[A-Za-z0-9]{36}\b",
          gate=("ghp_", "gho_", "ghu_", "ghs_", "ghr_")),
    _rule("github-token-pat", SECRET, HIGH,
          r"\bgithub_pat_[A-Za-z0-9_]{22,}",
          gate=("github_pat_",)),
    _rule("anthropic-api-key", SECRET, HIGH,
          r"\bsk-ant-[A-Za-z0-9_-]{20,}",
          gate=("sk-ant-",)),
    # Anything sk- that is not the Anthropic shape above.
    _rule("openai-api-key", SECRET, HIGH,
          r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}",
          gate=("sk-",)),
    _rule("google-api-key", SECRET, HIGH,
          r"\bAIza[0-9A-Za-z_-]{30,}",
          gate=("aiza",)),
    _rule("slack-token", SECRET, HIGH,
          r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
          gate=("xox",)),
    _rule("slack-webhook", SECRET, HIGH,
          r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{10,}",
          gate=("hooks.slack.com",)),
    _rule("npm-token", SECRET, HIGH,
          r"\bnpm_[A-Za-z0-9]{36}\b",
          gate=("npm_",)),
    _rule("stripe-key", SECRET, HIGH,
          r"\b[sr]k_live_[A-Za-z0-9]{10,}",
          gate=("_live_",)),
    _rule("pypi-token", SECRET, HIGH,
          r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{10,}",
          gate=("pypi-",)),
    _rule("vault-token", SECRET, HIGH,
          r"\bhv[sb]\.[A-Za-z0-9_-]{20,}",
          gate=("hvs.", "hvb.")),
    _rule("secret-assignment", SECRET, HIGH,
          r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|pwd|credential|"
          r"private[_-]?key|access[_-]?key)\b\s*[:=]\s*[\"']?"
          r"(?P<v>[^\s\"',;]{8,128})",
          validate=_real_secret,
          gate=("key", "secret", "token", "password",
                "passwd", "pwd", "credential")),
    _rule("jwt", SECRET, MEDIUM,
          r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}",
          gate=("eyj",)),
    _rule("credentials-in-url", SECRET, MEDIUM,
          r"\b[a-z][a-z0-9+.-]{1,20}://[^\s:/@]{1,64}:(?P<v>[^\s:/@]{1,128})@",
          gate=("://",)),

    # -- sensitive paths (scanned only where a tool addressed a file) ----
    _rule("env-file", PATH, HIGH, r"\.env(?:\.[A-Za-z0-9_-]{1,20})?\b",
          gate=(".env",)),
    _rule("private-key-file", PATH, HIGH,
          r"\.(?:keystore|pem|pfx|p12|jks|key)\b",
          gate=(".pem", ".key", ".pfx", ".p12", ".jks", ".keystore")),
    _rule("ssh-private-key-file", PATH, HIGH,
          r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b",
          gate=("id_rsa", "id_dsa", "id_ecdsa", "id_ed25519")),
    _rule("ssh-dir", PATH, HIGH, r"\.ssh/",
          gate=(".ssh/",)),
    _rule("aws-credentials-file", PATH, HIGH, r"\.aws/(?:credentials|config)\b",
          gate=(".aws/",)),
    _rule("kube-config", PATH, HIGH, r"\.kube/config\b",
          gate=(".kube/",)),
    _rule("gcloud-config", PATH, HIGH, r"\.config/gcloud\b",
          gate=(".config/gcloud",)),
    _rule("docker-config", PATH, HIGH, r"\.docker/config\.json\b",
          gate=(".docker/",)),
    _rule("netrc", PATH, HIGH, r"\.netrc\b",
          gate=(".netrc",)),
    _rule("npmrc-or-pypirc", PATH, HIGH, r"\.(?:npmrc|pypirc)\b",
          gate=(".npmrc", ".pypirc")),
    _rule("git-credentials", PATH, HIGH, r"\.git-credentials\b",
          gate=(".git-credentials",)),

    # -- personal data (no characters revealed) --------------------------
    _rule("cpf", PII, MEDIUM,
          r"(?<!\d)(?:\d{3}\.\d{3}\.\d{3}-\d{2}|\d{11})(?!\d)",
          validate=valid_cpf, reveal=0,
          gate=DIGIT_RUN_RE),
    _rule("cnpj", PII, MEDIUM,
          r"(?<!\d)(?:\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}|\d{14})(?!\d)",
          validate=valid_cnpj, reveal=0,
          gate=DIGIT_RUN_RE),
    _rule("credit-card", PII, MEDIUM,
          r"(?<!\d)(?:\d{4}[ -]?){3}\d{4}(?!\d)",
          validate=valid_card, reveal=0,
          gate=DIGIT_RUN_RE),
    _rule("email", PII, LOW,
          r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,64}\.[A-Za-z]{2,24}\b",
          reveal=0,
          gate=("@",)),
    # Requires the country code: an unanchored 11-digit phone pattern reports
    # every order number in the ledger.
    _rule("phone-br", PII, LOW,
          r"\+55\s?\(?\d{2}\)?\s?9?\d{4}[-\s]?\d{4}", reveal=0,
          gate=("+55",)),

    # -- capture's own redaction (informational) -------------------------
    _rule("redaction-marker", REDACTION, LOW, r"\[REDACTED\]", reveal=0,
          gate=("[redacted]",)),
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


def _passes_gate(gate, text, lowered, hits):
    """Whether a rule's necessary condition holds, so its regex is worth
    running. Pattern gates are shared between rules, so each is evaluated once
    per text."""
    if not gate:
        return True
    if isinstance(gate, tuple):
        return any(literal in lowered for literal in gate)
    hit = hits.get(id(gate))
    if hit is None:
        hit = hits[id(gate)] = gate.search(text) is not None
    return hit


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
    lowered = text.lower()
    gate_hits = {}
    agg = {}
    capped = False
    for rule in RULES:
        if rule.category in skip_categories:
            continue
        if not _passes_gate(rule.gate, text, lowered, gate_hits):
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


# ---------------------------------------------------------------- activity
#
# The second half of the analysis: which security activity the ledger actually
# recorded, and — the point of it — which code-touching sessions recorded none.
# Read from what a tool call *invoked*; a prompt, an assistant message or a
# file that merely names a scanner is not an action (AC9).
#
# The catalogue is a code change, never configuration: unrecognised tools are
# simply not counted, never guessed. GAIDE's own checks sit in their own tuple
# so the analysis demonstrably does not depend on GAIDE (AC14).

SAST = "sast"
SCA = "sca"
SECRETS = "secrets"
IAC = "iac"
CONTAINER = "container"
DAST = "dast"
SUPPLY_CHAIN = "supply-chain"
REVIEW = "review"
SUPPRESSION = "suppression"
ACTION_CATEGORIES = (SAST, SCA, SECRETS, IAC, CONTAINER, DAST, SUPPLY_CHAIN,
                     REVIEW)

MAX_COMMAND_CHARS = 4_000

# (category, tool, program, subcommands) — an entry with subcommands matches
# only those; one with () matches any invocation of the program and is the
# fallback, so order the specific entries first.
BASE_ACTION_TOOLS = (
    (SAST, "semgrep", "semgrep", ()),
    (SAST, "bandit", "bandit", ()),
    (SAST, "codeql", "codeql", ()),
    (SAST, "sonar-scanner", "sonar-scanner", ()),
    (SAST, "gosec", "gosec", ()),
    (SAST, "brakeman", "brakeman", ()),
    (SAST, "njsscan", "njsscan", ()),
    (SAST, "snyk-code", "snyk", ("code",)),
    (SCA, "snyk-test", "snyk", ("test", "monitor")),
    (SCA, "osv-scanner", "osv-scanner", ()),
    (SCA, "npm-audit", "npm", ("audit",)),
    (SCA, "yarn-audit", "yarn", ("audit",)),
    (SCA, "pnpm-audit", "pnpm", ("audit",)),
    (SCA, "pip-audit", "pip-audit", ()),
    (SCA, "safety", "safety", ()),
    (SCA, "cargo-audit", "cargo", ("audit",)),
    (SCA, "bundler-audit", "bundle", ("audit",)),
    (SCA, "composer-audit", "composer", ("audit",)),
    (SCA, "govulncheck", "govulncheck", ()),
    (SCA, "retire", "retire", ()),
    (SCA, "dependency-check", "dependency-check", ()),
    # trivy is three scanners in one binary; the subcommand decides.
    (SCA, "trivy", "trivy", ("fs", "filesystem", "repo", "repository", "sbom")),
    (IAC, "trivy", "trivy", ("config",)),
    (CONTAINER, "trivy", "trivy", ()),
    (SECRETS, "gitleaks", "gitleaks", ()),
    (SECRETS, "trufflehog", "trufflehog", ()),
    (SECRETS, "detect-secrets", "detect-secrets", ()),
    (SECRETS, "ggshield", "ggshield", ()),
    (SECRETS, "git-secrets", "git-secrets", ()),
    (IAC, "checkov", "checkov", ()),
    (IAC, "tfsec", "tfsec", ()),
    (IAC, "terrascan", "terrascan", ()),
    (IAC, "kube-score", "kube-score", ()),
    (IAC, "kubesec", "kubesec", ()),
    (IAC, "kube-bench", "kube-bench", ()),
    (IAC, "hadolint", "hadolint", ()),
    (IAC, "conftest", "conftest", ()),
    (CONTAINER, "grype", "grype", ()),
    (CONTAINER, "dockle", "dockle", ()),
    (CONTAINER, "docker-scout", "docker", ("scout",)),
    (DAST, "nuclei", "nuclei", ()),
    (DAST, "nikto", "nikto", ()),
    (DAST, "zap", "zap.sh", ()),
    (DAST, "zap", "zap-cli", ()),
    (DAST, "sqlmap", "sqlmap", ()),
    (DAST, "testssl", "testssl.sh", ()),
    (SUPPLY_CHAIN, "syft", "syft", ()),
    (SUPPLY_CHAIN, "cosign", "cosign", ()),
    (SUPPLY_CHAIN, "cyclonedx", "cyclonedx", ()),
    (SUPPLY_CHAIN, "pip-licenses", "pip-licenses", ()),
    (SUPPLY_CHAIN, "license-checker", "license-checker", ()),
    (REVIEW, "pre-commit", "pre-commit", ("run",)),
)

# GAIDE's enforcement layer (scripts/, the security-reviewer skill). Removing
# this tuple changes nothing for a project that does not use GAIDE — which is
# the whole point: GAIDE-Trace must stay useful without GAIDE.
GAIDE_ACTION_TOOLS = (
    (SAST, "check-security.sh", "check-security.sh", ()),
    (SECRETS, "check-secrets.sh", "check-secrets.sh", ()),
    (REVIEW, "check-clean-state.sh", "check-clean-state.sh", ()),
)

ACTION_TOOLS = BASE_ACTION_TOOLS + GAIDE_ACTION_TOOLS

# Security activity invoked by name rather than as a program: a skill, a
# subagent, a slash command.
BASE_INVOCATIONS = {}
GAIDE_INVOCATIONS = {
    "security-reviewer": (REVIEW, "security-reviewer"),
    "security-review": (REVIEW, "security-review"),
}
ACTION_INVOCATIONS = {**BASE_INVOCATIONS, **GAIDE_INVOCATIONS}
INVOCATION_KEYS = ("skill", "subagent_type", "agent_type", "name", "workflow")

COMMAND_KEYS = ("command", "cmd", "script", "shell", "args", "argv")
CONTENT_KEYS = ("content", "new_string", "text", "body", "edits", "replacement")
PATH_KEYS = ("file_path", "path", "notebook_path", "filename", "target_file")

# Suppressing a check instead of running one (Constitution Principle 10). Kept
# apart from the activity catalogue: `suppression` is not in ACTION_CATEGORIES,
# so no aggregate can ever count it as security work (AC11).
SUPPRESSION_SIGNALS = (
    ("inline-nosemgrep", re.compile(r"(?i)#\s*nosemgrep")),
    ("inline-nosec", re.compile(r"(?i)#\s*nosec\b")),
    ("inline-noqa-security", re.compile(r"(?i)#\s*noqa:\s*S\d")),
    ("inline-eslint-disable-security",
     re.compile(r"eslint-disable[^\n]{0,80}security")),
    ("inline-trivy-ignore", re.compile(r"(?i)#\s*trivy:ignore")),
    ("inline-checkov-skip", re.compile(r"(?i)#\s*checkov:skip")),
)
IGNORE_FILE_RE = re.compile(
    r"(?i)(?:^|[\s\"'/=>])\.(?:semgrepignore|gitleaksignore|trivyignore|snyk)\b")
NO_VERIFY_RE = re.compile(r"\bgit\s+commit\b[^\n]{0,200}?(?:--no-verify|\s-n\b)")
PRECOMMIT_SKIP_RE = re.compile(r"\bSKIP=[A-Za-z0-9_,-]+")

# Tool names that write code, across adapters (normalized to letters+digits).
CODE_EDIT_TOOLS = frozenset({
    "write", "edit", "multiedit", "notebookedit", "writefile", "createfile",
    "editfile", "replacefilecontent", "applypatch", "strreplaceeditor",
})
CODE_COMMAND_RE = re.compile(r"(?i)\b(?:git\s+(?:commit|apply|am)\b|patch\s+-p\d)")

_SEGMENT_SPLIT = re.compile(r"&&|\|\||[;|\n]")
_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Interpreters and runners that stand in front of the tool being invoked.
_WRAPPERS = frozenset({
    "sudo", "env", "time", "nohup", "xargs", "bash", "sh", "zsh", "dash",
    "npx", "pnpx", "bunx", "uv", "uvx", "pipx", "poetry", "pdm", "rye",
    "python", "python3", "py", "deno", "node",
})
_WRAPPER_SUBCOMMANDS = frozenset({"run", "exec", "tool"})

_OUTCOME_ERROR_RE = re.compile(
    r"(?i)(command not found|no such file or directory|permission denied|"
    r"traceback \(most recent call last\))")
_OUTCOME_CLEAN_RE = re.compile(
    r"(?i)\b(?:no (?:findings|issues|vulnerabilities|secrets|leaks|problems)|"
    r"0 (?:findings|issues|vulnerabilities|secrets|leaks)|found 0 \w+|"
    r"nothing to report|all checks passed|no new issues)")
_OUTCOME_FINDINGS_RE = re.compile(
    r"(?i)\b(?:found )?[1-9]\d* (?:findings?|issues?|vulnerabilit(?:y|ies)|"
    r"secrets?|leaks?|errors?)\b")


def _tool_payload(row):
    """The tool call's input as a mapping, or None when it carries none."""
    raw = row.get("tool_input")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        payload = json.loads(raw)
    except (ValueError, RecursionError):
        return {"command": raw}
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, str):
        return {"command": payload}
    return {}


def _payload_text(payload, keys):
    parts = []
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str):
            parts.append(value)
        elif isinstance(value, list):
            parts.append(" ".join(x for x in value if isinstance(x, str))
                         or json.dumps(value, default=str))
        elif isinstance(value, dict):
            parts.append(json.dumps(value, default=str))
    return "\n".join(parts)[:MAX_COMMAND_CHARS]


def _program_tokens(segment):
    """Tokens of one command segment with env assignments, leading flags and
    wrappers removed, so `SEND_METRICS=off sudo npx semgrep scan .` reads as
    `semgrep scan .`."""
    out = []
    skipping = True
    for token in segment.split():
        if skipping:
            if _ENV_ASSIGN.match(token) or token.startswith("-"):
                continue
            base = token.rsplit("/", 1)[-1].lower()
            if base in _WRAPPERS or base in _WRAPPER_SUBCOMMANDS:
                continue
            skipping = False
        out.append(token)
    return out


def _match_tool(tokens, catalogue):
    """`(category, tool, detail)` for the program these tokens invoke."""
    if not tokens:
        return None
    program = tokens[0].rsplit("/", 1)[-1].lower()
    sub = tokens[1].lower() if len(tokens) > 1 else ""
    fallback = None
    for category, tool, prog, subcommands in catalogue:
        if prog != program:
            continue
        if subcommands:
            if sub in subcommands:
                return category, tool, f"{program} {sub}"
        elif fallback is None:
            fallback = (category, tool, program)
    return fallback


def _outcome(row):
    """Best effort, never a guess: `unknown` whenever the response does not
    say plainly how the run ended."""
    if row.get("event") == "tool.fail":
        return "error"
    response = row.get("tool_response")
    if not isinstance(response, str) or not response:
        return "unknown"
    response = response[:MAX_COMMAND_CHARS]
    if _OUTCOME_ERROR_RE.search(response):
        return "error"
    if _OUTCOME_CLEAN_RE.search(response):
        return "clean"
    if _OUTCOME_FINDINGS_RE.search(response):
        return "findings"
    return "unknown"


def classify_tool_call(row):
    """Security activity evidenced by one tool call.

    Returns a list of `{category, tool, outcome, detail}`. `detail` names the
    invocation only — never the command, which can carry a secret."""
    if row.get("event") not in ("tool.call", "tool.fail"):
        return []
    payload = _tool_payload(row)
    if payload is None:
        return []
    command = _payload_text(payload, COMMAND_KEYS)
    written = _payload_text(payload, CONTENT_KEYS)
    paths = _payload_text(payload, PATH_KEYS)
    outcome = _outcome(row)
    out, seen = [], set()

    def add(category, tool, detail):
        if (category, tool) in seen:
            return
        seen.add((category, tool))
        out.append({"category": category, "tool": tool, "outcome": outcome,
                    "detail": detail})

    for segment in _SEGMENT_SPLIT.split(command):
        tokens = _program_tokens(segment)
        hit = _match_tool(tokens, ACTION_TOOLS)
        if hit:
            add(*hit)
            continue
        if tokens:
            name = tokens[0].rsplit("/", 1)[-1].lower().lstrip("/")
            invocation = ACTION_INVOCATIONS.get(name)
            if invocation:
                add(invocation[0], invocation[1], name)
    for key in INVOCATION_KEYS:
        value = payload.get(key)
        if isinstance(value, str):
            invocation = ACTION_INVOCATIONS.get(value.strip().lower().lstrip("/"))
            if invocation:
                add(invocation[0], invocation[1], value.strip().lower())

    for name, pattern in SUPPRESSION_SIGNALS:
        if pattern.search(command) or pattern.search(written):
            add(SUPPRESSION, name, name)
    if IGNORE_FILE_RE.search(paths) or IGNORE_FILE_RE.search(command):
        add(SUPPRESSION, "ignore-file", "scanner ignore file")
    if NO_VERIFY_RE.search(command):
        add(SUPPRESSION, "commit-no-verify", "git commit --no-verify")
    if PRECOMMIT_SKIP_RE.search(command):
        add(SUPPRESSION, "pre-commit-skip", "SKIP= on pre-commit")
    return out


def is_code_edit(row):
    """Whether this call wrote code — what makes a session code-touching, and
    therefore expected to carry some security activity (AC12)."""
    if row.get("event") not in ("tool.call", "tool.fail"):
        return False
    name = re.sub(r"[^a-z0-9]", "", (row.get("tool_name") or "").lower())
    if name in CODE_EDIT_TOOLS:
        return True
    payload = _tool_payload(row)
    if not payload:
        return False
    return bool(CODE_COMMAND_RE.search(_payload_text(payload, COMMAND_KEYS)))
