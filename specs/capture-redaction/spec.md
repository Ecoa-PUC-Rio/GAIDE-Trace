# Spec: Capture-time redaction of credentials in captured text

> **Status:** approved (2026-11-09)
> **Author:** José Menezes (drafted with Claude Code)
> **Date:** 2026-11-09
> **Origin:** [issue #3](https://github.com/jcarlos78/GAIDE-Trace/issues/3), reported by @mattabate

## Context

D5 promises that secrets are redacted before anything reaches disk in the event
layer. The promise is kept by `redact()` in `hooks/trace_hook.py`, a handful of
regular expressions applied to every captured field (`prompt`, `tool_input`,
`tool_response`, `last_assistant_message`) after JSON serialization.

Issue #3 shows the promise broken for the most common credential shape in an
AI-assisted session: an HTTP `Authorization` header. The key/value rule needs
8 or more non-space characters right after `:` or `=`; in
`Authorization: Bearer <jwt>` the run after the colon is the 6-letter scheme
name, followed by a space, so the rule fails and the token is written to the
local store, the outbox and the server in clear.

Reproducing the report exposed two more gaps on the same code path:

- `tool_input` is a dict, so `clean()` serializes it with `json.dumps` before
  redacting. Every double quote inside a shell command therefore arrives as
  `\"`, and the key/value rule, which only accepts a bare `"` around the
  separator, fails on `--password=\"...\"` and `export API_KEY=\"...\"`.
- Single-quoted values (`--password='...'`) are never matched, because the rule
  does not accept `'` as a quote at all.

This is the first behavioural change to capture-time redaction since the
project adopted the GAIDE harness, so this is the spec for *that* behaviour.
It is deliberately scoped to the rules `redact()` applies and to the shape of
the text it receives. It does not back-fill a spec for the rest of the adapter.

## Expected behavior

### Terms

- **Captured text:** the string `redact()` receives from `clean()`. For a
  non-string field this is the JSON serialization of the value, so quotes
  inside string values appear escaped (`\"`).
- **Credential value:** the part of a match that must never reach disk.
- **Context:** the part of a match that is kept so analyses still see *that*
  a credential was used and *how*: the key name (`api_key`, `Authorization`),
  the separator, and the authentication scheme (`Bearer`, `Basic`).

### Rules

1. **HTTP authentication schemes.** `Bearer`, `Basic`, `Negotiate` and `NTLM`
   credentials (RFC 7235 `token68` shape) are redacted wherever they appear,
   with or without an `Authorization` key in front, in any letter case. Once
   the credential looks like one it runs to whitespace or a quote, so a
   non-token68 character inside it (`abc12345|rest`) does not split it. The
   scheme name is kept, the credential is replaced by `[REDACTED]`.
2. **Key/value assignments** keep matching the existing keywords (`api_key`,
   `secret`, `token`, `password`, `passwd`, `authorization`, `bearer`), now
   also with a `_`/`-` suffix (`AWS_SECRET_ACCESS_KEY`, `password_hash`), and
   accept, around the separator, a double quote, a single quote, or a
   JSON-escaped double quote at any escaping depth (`"`, `\"`, `\\\"`), plus
   an optional `Bearer ` / `Basic ` scheme before the value. A quoted value
   runs to its closing quote, recognised by its escaping depth (the shell's
   closing `"` is `\"` in serialized text, a `"` inside the value is `\\\"`),
   so punctuation, escaped quotes or backslashes inside the credential cannot
   end the match early. A quoted value is bounded at 8192 characters. A bare
   value runs to whitespace or a quote, never ends on the backslash of an
   escaped quote, and is never a JSON number (`"max_token": 20000000` and
   `"token_cost": 0.00012345` are counts and prices). Between an `Authorization`-style key
   and its value the accepted schemes widen to `Token`, `ApiKey`, `Digest`.
3. **JSON Web Tokens** (`eyJ…` `.` `…` `.` `…`) are redacted wherever they
   appear, on their own, mirroring the `jwt` rule of the server's security
   scan. Bearer tokens are usually JWTs and travel in response bodies
   (`{"access_token": "eyJ…"}`) as often as in headers.
4. **Existing vendor rules are unchanged:** OpenAI/Anthropic-style keys,
   GitHub tokens, AWS access key ids. The private key rule now also masks a
   block whose `END` marker was cut off by the capture (`head -5 id_rsa`):
   from `BEGIN` to the end of its JSON string or of the text, so sibling
   fields of the record survive.
5. **Redaction is idempotent** and never corrupts the serialized shape of the
   text: redacting a JSON document yields a JSON document.
6. **Bias.** The rules are tuned toward false positives: masking a harmless
   word costs one token of research data, missing a credential ships it to a
   shared server. A scheme match does require the credential to look like
   one (a digit, a `token68` symbol, or a lowercase-to-uppercase transition)
   so that prose such as "Basic Authentication is simple" is left intact.

### Use cases

1. **Bearer header in a shell command (the report)**
   - Given: a `PostToolUse` event whose `tool_input.command` is
     `curl -H "Authorization: Bearer <jwt>" https://api.example`
   - When: the hook captures the event
   - Then: the stored `tool_input` contains `Authorization: Bearer [REDACTED]`
     and no fragment of the token; the stored value is still valid JSON

2. **Header carried as a dict**
   - Given: `tool_input.headers = {"Authorization": "Bearer <token>"}`
   - When: captured
   - Then: `"Authorization": "Bearer [REDACTED]"`

3. **Escaped and single-quoted assignments**
   - Given: `tool_input.command` is `mysql --password="<pw>"` or
     `mysql --password='<pw>'` or `export API_KEY="<key>"`
   - When: captured
   - Then: the value is `[REDACTED]`, the key name is kept

4. **Token in a response body**
   - Given: `tool_response` is `{"access_token": "<jwt>", "expires_in": 3600}`
   - When: captured
   - Then: the JWT is `[REDACTED]`; `expires_in` is untouched

5. **Prose that merely mentions a scheme**
   - Given: `prompt` is `Basic Authentication is simpler than Bearer tokens`
   - When: captured
   - Then: the text is unchanged

6. **Error case (D4)**
   - Given: any captured text, including empty or pathological input
   - When: redacted
   - Then: `redact()` returns a string and never raises

## Acceptance criteria

- [ ] AC1: `Authorization: Bearer <jwt>` inside a serialized shell command is stored as `Authorization: Bearer [REDACTED]`; no 8-character fragment of the token survives.
- [ ] AC2: the same header as a dict value (`{"Authorization": "Bearer …"}`) is redacted.
- [ ] AC3: `bearer <token>` in lowercase and `Authorization=Bearer <token>` are redacted.
- [ ] AC4: `Authorization: Basic <base64>` is redacted; `Basic Authentication is simple` is unchanged.
- [ ] AC5: a JWT standing alone (no key, no scheme) is redacted.
- [ ] AC6: `--password=\"<pw>\"`, `--password='<pw>'` and `export API_KEY=\"<key>\"` are redacted, keeping the key name.
- [ ] AC7: redacting a JSON-serialized `tool_input` yields text that `json.loads` still parses.
- [ ] AC8: `redact(redact(x)) == redact(x)` for every fixture.
- [ ] AC9: existing rules (`sk-…`, `ghp_…`, `github_pat_…`, `AKIA…`, private key block) still redact.
- [ ] AC10: `redact("")` returns `""`; `clean()` of a dict with a nested credential redacts it.
- [ ] AC11 (negative): no test fixture in the repository contains a complete credential-shaped literal; all are assembled at runtime via `tests/fixtures.py`.
- [ ] AC12: a quoted value containing `'`, `,` or `;` is redacted whole, with no suffix left behind.
- [ ] AC13: a doubly escaped JSON body inside a shell command (`curl -d "{\"password\": \"…\"}"`) is redacted.
- [ ] AC14: `AWS_SECRET_ACCESS_KEY=<value>` is redacted; `secretary: Jonathan Appleseed` is unchanged.
- [ ] AC15: numeric values under a sensitive key are left as is and the field stays valid JSON; a private key block without an `END` marker is masked to the end of the text.
- [ ] AC16: a double-quoted value containing `\"` or `\\`, and a bare value containing `,` or `;`, are redacted whole.
- [ ] AC17: `Authorization: Token <opaque>`, `ApiKey`, `Digest` and `Bearer "<token>"` are redacted; a serialized tab after `=` does not defeat the rule.
- [ ] AC18: a truncated private key inside a serialized record masks only its own field; `secretary:`, `token_type: Bearer` and `tokenizer:` stay prose.
- [ ] AC19: non-integer JSON numbers (`0.00012345`, `-12345678`, `1.5e-10`) under a sensitive key are left as is and the field stays valid JSON.
- [ ] AC20: a depth-0 JSON string ending in a backslash under a sensitive key is masked without swallowing sibling keys; a 2400-character quoted value is masked whole.
- [ ] AC21: `Bearer abc12345|<rest>` is masked whole; a serialized tab between scheme and credential keeps the scheme and masks the credential.
- [ ] AC10 (strengthened): one worst-case payload per rule, including unterminated quotes at every depth, keyword runs with no separator and scheme credentials with trailing junk, each above the default field cap, redacts in under one second.

## Out of scope

- Re-redacting data already captured by earlier versions (local stores,
  outboxes, server archives). That is a remediation tool with its own spec;
  this spec only stops the leak going forward.
- `user:password@host` URL credentials and `curl -u user:pass`. Both are
  covered by the server's `connection-string` scan rule after the fact; a
  capture-time rule needs a false-positive study (`host:port` collides) and
  is a separate change.
- Transcript snapshots, which are raw by design (D5).
- The server-side security scan (`specs/security-scan`), which is unchanged.

## Security considerations

- **Data sensitivity:** credentials. This spec exists to keep them out of the
  event layer.
- **Authentication / authorization:** none; the hook runs in the developer's
  own session.
- **Abuse cases:**
  - A tool output crafted so that a credential is split around a quote or a
    scheme word to dodge the rules. Mitigation: rules 1 to 3 overlap (scheme,
    key/value and bare JWT), and the key/value rule accepts every quoting the
    serializer can produce. Negative criterion: AC1 to AC6.
  - A regex with catastrophic backtracking fed by a hostile payload, stalling
    the hook until its 15 s timeout and costing data (D4). Redaction runs
    before truncation, so the whole field is scanned whatever
    `GAIDE_TRACE_MAX_FIELD` says. Mitigation: every pattern is linear (fixed
    alternations, bounded character classes, a bounded keyword suffix and a
    bounded quoted value, a lookbehind rather than `\b` where a class member
    is also a word boundary, a tempered quantifier in the private key rule).
    Negative criterion: AC10, one worst case per rule.
  - Redaction that breaks the JSON shape of a field and makes a downstream
    loader choke on the record. Negative criterion: AC7.

## Dependencies

- Other specs: `specs/security-scan` (the `jwt` rule is mirrored, not shared;
  the hook stays single-file).
- External systems: none.
- Libraries: none (stdlib `re` only).

## Effect on captured data

No field is added or removed. Stores already in the field stay readable.
Records captured before this change may hold unredacted credentials; the
server's security scan (`jwt`, `redaction-marker` rules) is the way to find
them, and rotation is the remedy.

## Invariants touched

- **D5** is the invariant being repaired.
- **D4** is preserved: `redact()` stays exception-free and linear-time.
- **Stdlib only**: preserved.

## Constitution adherence

- **Principle 1:** this spec precedes the code change.
- **Principle 2:** AC1 to AC21 map one-to-one onto `tests/test_capture_redaction.py`.
- **Principle 3:** the change ships as a pull request for the maintainer's approval.
- **Principle 6 / 10:** fixtures are assembled at runtime; no scanner suppression.

## Identified risks

- Risk: over-redaction of prose containing "Basic" or "Bearer" followed by a
  code-like word. | Mitigation: the credential-shape lookahead in rule 1;
  accepted residual cost (one masked word) per rule 6.
- Risk: a store consumer depended on the old (broken) output. | Mitigation:
  none needed; the old output was the bug.
- Known miss, accepted: a bare `Bearer` token made only of letters in a single
  case, with no `Authorization` key before it, is not recognised by the
  credential-shape lookahead. Real tokens virtually always carry a digit or a
  symbol.
- Known limit, unchanged: values shorter than 8 characters are not masked,
  quoted or not.
- Known limits, recorded for a follow-up spec: a list under a sensitive key
  (`"api_keys": ["…", "…"]`) is not masked; a keyword suffix longer than 32
  characters is not recognised; space-separated CLI credentials
  (`--password <pw>`, `-p<pw>`) and `=>` / `:=` separators are not covered.
- Accepted over-masking: at escaping depth 1 and above, a quoted value whose
  last character is a literal backslash (`--password="<pw>\\" -e "…"`) runs
  on to the next quote of that depth, masking the text in between. The
  stored field stays valid JSON; only research text is lost.
