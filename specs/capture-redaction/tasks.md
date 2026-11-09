# Tasks: Capture-time redaction of credentials

> **Prerequisite:** `plan.md` approved.

---

## Task 1: Tests from the spec (red)

**Status:** done

**Files:** `tests/test_capture_redaction.py`, `tests/fixtures.py`

**Description:** One test method per acceptance criterion, AC1 to AC21, using
runtime-assembled fixtures. Confirm failure on `main` for AC1 to AC6.

**Done when:**
- [x] AC1 to AC6 fail against the pre-fix `redact()` (11 failures on main)
- [x] AC7 to AC21 are present; AC12 to AC21 were added from three clean-context security reviews

**Depends on:** spec approved

## Task 2: Redaction rules

**Status:** done

**Files:** `hooks/trace_hook.py`

**Description:** Quoting helpers accepting `"`, `'` and `\"`; auth-scheme
rule with credential-shape lookahead; key/value rule with optional scheme;
bare JWT rule; ordered application that preserves key and scheme.

**Done when:**
- [x] `tests/test_capture_redaction.py` green (36 tests)
- [x] full suite green (318 tests)

**Depends on:** Task 1

## Task 3: Security review and PR

**Status:** done (verified: pending maintainer review of the PR)

**Files:** PR on `jcarlos78/GAIDE-Trace`

**Description:** Clean-context security review of the diff (rubric in
`agents/reviewers/security-reviewer.md`), then a pull request closing #3.

**Done when:**
- [x] three review rounds; every blocker fixed with a test; third round left only recorded limits
- [x] PR opened and linked from issue #3

**Depends on:** Task 2
