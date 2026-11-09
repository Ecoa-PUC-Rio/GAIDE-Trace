# Plan: Capture-time redaction of credentials

> **Prerequisite:** `spec.md` approved (2026-11-09).

## Architectural decisions

- Keep redaction as ordered regular expressions in the single-file hook, no
  shared module with the server. Minor decision: the hook must stay copyable
  into a target project as-is (AGENTS.md, Code conventions). The server's
  `jwt` rule is mirrored by hand and a comment points at the twin.
- Preserve context (key name, scheme) and mask only the value. Minor
  decision: analyses still see that credentials were used and how, which is
  research signal; the value is the only thing D5 protects.
- Bias toward false positives with a credential-shape lookahead on scheme
  matches. Minor decision, recorded in the spec (rule 6).

## Affected components

- `hooks/trace_hook.py`: redaction section only (`SECRET_PATTERNS`, `redact()`).
- `tests/test_capture_redaction.py`: new, AC1 to AC11.
- `tests/fixtures.py`: `load_hook()` helper and a `basic_credential` fragment.
- `specs/capture-redaction/`: this spec.

## Implementation sequence

1. Write the tests from the spec; confirm they fail on `main` (red).
2. Rewrite the redaction section: quoting helpers, auth-scheme rule,
   key/value rule with escaped and single quotes, bare JWT rule.
3. Run the new tests and the full suite (green).
4. Security review of the diff in a clean context (mandatory for redaction).
5. Pull request referencing issue #3.

## Testing strategy

- Unit tests on `redact()` and `clean()` with synthesized inputs built by
  `fixtures.fake`, so no complete credential is a literal in the repository.
- Regression tests for every pre-existing rule.
- Idempotence and JSON-validity properties over the whole fixture set.
- Manual: `echo '<PostToolUse payload>' | python3 hooks/trace_hook.py` against
  a temp `GAIDE_TRACE_DIR`, then grep the store for the token.

## Implementation risks

- Risk: a pattern with super-linear backtracking. | Mitigation: no nested
  quantifiers; a timing test over a 20 000-character pathological input stays
  well under the hook budget.
- Risk: fixtures trip gitleaks in CI. | Mitigation: fragments only, as the
  rest of the suite already does.

## Sprint contract

- [ ] `Authorization: Bearer <jwt>` in a captured command is stored masked. Verify by: `python3 -m unittest tests.test_capture_redaction -k bearer` (via discovery) and the manual hook run above.
- [ ] Escaped and single-quoted `--password` values are stored masked. Verify by: `-k quoted`.
- [ ] Redacted `tool_input` is still valid JSON. Verify by: `-k json`.
- [ ] Every pre-existing rule still fires. Verify by: `-k regression`.
- [ ] Full suite green. Verify by: `python3 -m unittest discover -s tests`.

## Definition of Done

- [ ] All tests derived from the spec pass
- [ ] Security review (clean context) with no blockers
- [ ] No secrets in the diff
- [ ] Constitution respected
