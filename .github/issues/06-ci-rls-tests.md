**Epic:** #98 · **Phase:** 2 — CI

## Problem

Multi-tenancy is a core invariant (RLS + explicit `tenant_id`), but there is no documented **CI gate** that blocks PRs breaking tenant isolation on critical paths.

## Proposed solution

Define a **minimum critical test suite** that runs on every PR:

| Scenario | Assertion |
|----------|-----------|
| Login tenant A | Token scoped to tenant A |
| API call with tenant B header + tenant A token | 403 or empty data |
| User list in tenant A | No users from tenant B |
| Signup in system tenant | Email verification flow works |

Reuse existing tests in `tests/functional/` where possible; extract a `run-critical.sh` batch if the full suite is too slow.

## Acceptance criteria

- [ ] Dedicated CI job (or step) runs critical auth + RLS tests on every PR
- [ ] Failure message clearly indicates tenant isolation regression
- [ ] Documented in `CONTRIBUTING.md` as required before merge
- [ ] Runtime target: < 15 minutes

## Files

- `tests/functional/run-critical.sh` (new or curated from existing batches)
- `.github/workflows/`
