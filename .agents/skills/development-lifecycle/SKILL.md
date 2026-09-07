---
name: development-lifecycle
description: Plan and execute ambiguous, cross-component, high-impact, or risky code changes with a compact contract, proportional gates, and observable evidence. Skip clearly local low-risk edits unless explicitly requested.
---

# GraphPact Development Lifecycle

Use the smallest path that safely fits the change.

## Select the tier

- **Simple:** clear, local, reversible, no public interface or sensitive effect.
- **Structured:** cross-component, dependency, public API, or architectural impact.
  A code change plus its directly related test does not count as cross-component.
- **Critical:** authentication or permissions, secrets, payment-domain code, data
  migration, destructive, production, paid or external action, concurrent/distributed
  state, personal data (`pii`), data loss, input validation and injection surfaces,
  or supply-chain and dependency provenance.

Record risk with `risk.signals`. Add a project-local advisory signal with an `x-`
prefix (for example `x-performance`); it is accepted but does not raise the tier.

Up-tier freely. Down-tier only after explicit human confirmation and record it in
`risk.downgrade`. Protected critical signals — everything critical except
`concurrency-distributed` — can never be downgraded.

## Classify the field

Every structured or critical contract records `project.field`.

- **Greenfield:** a new project, package, or isolated component with no existing
  behavior or consumers to preserve. Build a walking skeleton, keep early decisions
  reversible, and work in small complete slices. Do not set `baseline_revision`,
  `invariants`, or a continuity criterion; there is nothing existing to protect.
- **Brownfield:** any change to a codebase that already has history, users, or
  established, often undocumented, contracts. The goal is not only the new behavior
  but the continuity of everything that already works.

For a brownfield change, extra guardrails must emerge in the contract:

- record `project.baseline_revision`, the commit whose behavior must survive;
- list `project.invariants`, the public interfaces, data formats, and observable
  behaviors that must not break, freezing the invariant core;
- add at least one continuity acceptance criterion (`"continuity": true`) that pins
  current behavior with a characterization, golden-master, or regression check
  before the change and stays green after it;
- when the change must alter existing behavior, prefer a reversible incremental
  rollout and record `project.rollback`.

Investigate before editing, scope each change to its delta, and verify twice: the
change meets its criterion and it does not regress the baseline. Read
[references/brownfield-continuity.md](references/brownfield-continuity.md) for the
full protocol. The checker enforces that a brownfield contract carries a baseline,
invariants, and a continuity check, and that a greenfield contract omits them; it
cannot prove the invariants are complete or the behavior truly preserved.

## Grill the change first

For structured and critical work, grill the change before locking the contract: a
short, proportional challenge that surfaces what a careful reviewer would raise before
any code is written. Unstated or ambiguous intent is the main cause of confidently
wrong changes, and reasoning harder does not reliably catch it — an explicit step
does. Keep it bounded to one round and typically one to five recorded points; a change
with no user-only gaps still produces one entry saying so plus its pre-mortem.

- **Explore, then ask only for user-only inputs.** Resolve navigational gaps by
  reading the code, history, and tests. Ask only for informational gaps the user alone
  holds — intended behavior, business rules, a target or environment, an irreversible
  choice. A gap you can close by reading code is never a question.
- **Surface the few high-value uncertainties**: unstated assumptions, ambiguous
  acceptance, alternatives you reject and why, and — as a short pre-mortem — the most
  plausible way this change fails or breaks existing behavior. If it surfaces a new
  risk signal, up-tier before continuing.
- **Route by reversibility, reusing the tier.** After exploring (and, in `research`,
  looking up what is knowable), assume the cheap, reversible band in every mode; a
  *residual* gap is a costly user-only one that remains. Never invent an answer
  silently. To "block" means do not proceed without confirmation; if the run ends with
  a block unresolved, set `state: blocked` and record what is needed.

Record how the grill was conducted in `grill.mode`. Every mode explores first and
blocks irreversible, protected-signal, or scope-changing gaps; the mode only decides
what happens to a residual gap:

- **`interactive` (human-in-the-loop):** ask the user and wait. You may mark one
  recommended option, disclosed as such, but frame the set neutrally — no leading
  wording or hidden preference. If the user delegates ("proceed on your
  recommendation"), record the delegation and assume; if they decline without
  delegating, block. Highest fidelity; needs a human present.
- **`autonomous`:** record an explicit assumption and proceed on the safest
  interpretation, surfaced in the final report. Fast and unattended; the assumptions
  carry the risk. This is the usual headless choice.
- **`research`:** `autonomous` plus a mandatory external look-up — resolve what is
  knowable from authoritative sources first and name the source in the note; assume
  only what genuinely cannot be looked up.

The point of the grill is fidelity: make the contract a faithful, complete encoding of
the user's expectations and constraints so the delivered result answers the goal by
design, not by luck. Each expectation becomes an acceptance criterion with a real
`verification`; each constraint becomes a `non_goal` or a `project.invariant`; a
resolved ambiguity becomes acceptance. The grill secures this at the front; recorded
evidence and, for critical work, an independent review secure it at the back.

The grill also makes the work divisible into **lots** (`tasks`). Derive them
concretely: list the mutable resources your exploration touched — files, schemas,
migrations, generated files, lockfiles, ports (see
[references/parallel-worktrees.md](references/parallel-worktrees.md)); group by
resource, and each group becomes one task (record its `write_scope` when the mode
makes scope matter — always for `parallel-worktrees`); add a `depends_on` edge
wherever one task consumes what another produces. A discovered coupling is recorded as
an edge or, under three tasks where edges are not allowed, by merging the tasks; an
absence of edges is a claim of independence. Two or more tasks with disjoint scope and
no path between them are a
candidate for `parallel-worktrees` (subject to the gate below); otherwise
`sequential`. Record the mode plus the key questions and accepted assumptions in the
optional `grill` object (`{"mode": ..., "notes": [...]}`) — a trace, not a transcript —
and commit that draft contract before you flip `approvals.contract`, so Git shows the
grill preceded approval.

## Simple changes

Do not create a lifecycle artifact. Inspect the relevant code, make the smallest
coherent edit, run the repository's checks, inspect the diff, and report the
observable result.

## Implementation quality

- Follow existing project conventions and reuse proven boundaries before adding
  a dependency, abstraction, or framework.
- Deliver the contracted behavior completely. Do not leave placeholders, false
  success paths, permanent test doubles, swallowed errors, or unreported partial
  implementations.
- Never weaken tests, types, linters, security controls, or error handling merely
  to make a change pass.
- Keep edits within the agreed scope. Avoid opportunistic refactors and remove
  debug code, dead code, and comments that only restate the implementation.
- Prefer direct, readable code. Add an abstraction only for demonstrated reuse,
  a real domain boundary, or a concrete safety invariant.

## Structured and critical changes

1. Read `.lifecycle/change.example.json` and create
   `.lifecycle/changes/<id>/change.json`. Record `project.field` and, for a
   brownfield change, its baseline, invariants, and continuity check before
   implementing (see Classify the field). `tasks` is required, so a draft already
   holds at least one placeholder task; the grill refines it into real lots.
2. Grill the change (see Grill the change first).
3. Divide the grilled change into lots: an ordered task list where each task is one
   coherent work unit, with `write_scope` and `depends_on` edges derived as above; the
   graph must be acyclic, and edges appear only with at least three meaningful units.
4. Select `execution.mode` and explain the choice; propose it in the summary and
   record `parallel-worktrees` only once the contract leaves `draft`:
   - `parallel-read` for independent read-only reconnaissance, including before
     contract approval;
   - `parallel-worktrees` used only after approval, when at least two substantial tasks
     are dependency-independent, shared foundations are stable, declared mutable
     scopes do not overlap, local and join checks are known, one recorded Git base
     is available, and the active client can isolate every writer;
   - `sequential` otherwise. This is the safe default, especially for local fixes.
5. Present a concise human summary — objective, exclusions, risk, acceptance, and the
   lots with their `execution.mode` — informed by the grill. Set `approvals.contract`
   only after confirmation. In a headless run the originating instruction counts as
   that approval only when the grill surfaced no scope-changing or irreversible gap;
   otherwise leave the contract `draft` or `blocked` and end with the summary and the
   open questions.
6. For `parallel-worktrees`, add `write_scope` and `verification` to every task,
   record `execution.base_revision`, then read and follow
   [references/parallel-worktrees.md](references/parallel-worktrees.md). Never
   treat a normal subagent as isolated unless the active tool actually binds it to
   a separate checkout.
7. Implement in small coherent slices. After a failed attempt, change the
   diagnosis before retrying. After three failed attempts, set the contract to
   `blocked` and report what is needed to continue.
8. Run `.lifecycle/check.py <path>` after contract changes and before claiming
   completion. It rejects unknown fields, so fix typos it reports. To ground the
   recorded revisions against real history, run `.lifecycle/check.py --repo . <path>`;
   it verifies that `baseline_revision`, `base_revision`, evidence, and review
   revisions exist and that the completion evidence descends from the baseline.
9. Record executed commands and their actual exit codes as evidence. For a
   brownfield `done` contract, all successful evidence shares one completion
   revision, that revision must be after the baseline, and a failing run recorded at
   it blocks completion. Agent claims and unexecuted checks are not evidence.

Graphify is an optional navigation aid, not a requirement. If it is already
available, use it for multi-hop dependency or blast-radius analysis, treat inferred
edges as hypotheses, and verify important ones in the code. When a repository is
long-lived and multi-component and the user wants that depth, read
[references/graphify-install.md](references/graphify-install.md) and propose its
project-scoped installation; otherwise use direct reads and search and do not
interrupt work to install tooling. Graphify is never completion evidence.

## Critical gates

- Technical full-access or YOLO permissions do not authorize production,
  destructive, paid, or externally visible actions. Obtain explicit confirmation
  immediately before those actions and record it in `approvals.critical_actions`.
- Before completion, obtain an independent fresh-context review when available.
  Otherwise request human review. Record its result and the reviewed revision in
  `review`.
- Use TLA+ only when a real critical concurrent or distributed protocol has
  invariants that tests cannot cover, and only with explicit human choice and
  competent review. Never treat automatically generated TLA+ as proof.

Approval, review, and `grill.mode` fields are declarations, not authenticated proof.
Never set them without observing the corresponding human confirmation, review, or
grill conduct. The checker validates their consistency but cannot establish who
performed an action or how the grill was actually run.

## Human interface

The JSON contract is the machine record, not the conversation format. Translate it
to the user's language on request. Preview material contract changes in plain
language before changing an approved contract.
