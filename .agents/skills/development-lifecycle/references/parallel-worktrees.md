# Parallel worktree execution

Read this reference only when `execution.mode` is `parallel-worktrees` or when
evaluating whether that mode is safe. Worktrees isolate file edits; they do not
stabilize an ambiguous contract, resolve semantic coupling, or grant permission
for sensitive actions.

## Selection gate

Choose `parallel-worktrees` only after contract approval when all are true:

- at least two substantial tasks are dependency-independent;
- shared foundations and interfaces are stable enough to consume;
- every task declares a non-overlapping `write_scope` and a local
  `verification` command;
- the integrated acceptance checks are already known;
- every worker can start from the same clean, recorded Git revision;
- the active coding tool can bind each writer to a separate worktree.

Use `sequential` when any condition is false. For a fix, default to parallel
read-only diagnosis followed by one writer; use parallel worktrees only when the
diagnosis reveals multiple independent corrections with local regression checks.

Treat `write_scope` as mutable resources, not only file paths. Include shared
schemas, migrations, generated files, lockfiles, test databases, ports, and
external sandboxes where relevant. The checker detects identical declared scopes;
the coordinator must still detect overlapping paths and semantic coupling.

Start with two writers. Use three only when the task graph and verification
boundaries are unusually clear. This is a conservative default, not a universal
limit.

## Prepare the wave

1. Resolve the base with `git rev-parse HEAD` immediately before the wave and
   record it in `execution.base_revision`. Refresh it after integrating any
   predecessor wave. Do not launch from unresolved local changes. Commit or
   otherwise preserve intended changes first; ask when ownership is unclear.
2. Select only tasks whose `depends_on` predecessors are integrated.
3. Give each worker the contract path, task outcome, base revision, write scope,
   non-goals, local verification, and the rule that shared contracts may not be
   changed unilaterally.
4. Create one branch and worktree per selected task, using native isolation when
   it honors the recorded base. A portable Git fallback is:

   ```bash
   git worktree add -b graphpact/<change-id>/<task-id> <worktree-path> <base-revision>
   ```

5. Require each worker to commit its change and return, in its response, the base
   and head revisions, files changed, verification command and exit code, and any
   discovery that could invalidate the contract. Do not create another persistent
   manifest solely to duplicate Git and the lifecycle contract.

If a worker discovers that a shared interface or the approved behavior must
change, stop that task and return the decision to the coordinator. Update and, when
material, re-approve the contract before rescheduling affected nodes.

## Tool adapters

- **Claude Code:** use subagent or session worktree isolation. Record and verify
  the base explicitly because native defaults can differ from the parent session.
- **Grok Build:** use worktree isolation for each writing subagent or session and
  pass the recorded base when supported.
- **Codex:** do not assume a CLI subagent has a separate checkout; current
  subagents inherit the parent working directory. Use Codex-managed worktree
  conversations, or create worktrees first and launch independent sessions in the
  resolved paths. If the active client cannot bind a writer to its path, fall back
  to sequential execution.
- **Other Git-capable CLIs:** use explicit `git worktree` branches and run one
  agent session from each resolved worktree path.

## Integrate and clean up

Keep one coordinator as the owner of integrated state:

1. Review and integrate one completed branch at a time in dependency order.
2. Run its local verification, then the affected integration checks.
3. Update the ready set only after successful integration. Replan rather than
   forcing a merge when a contract or dependency assumption is wrong.
4. After the final wave, run every acceptance verification against one recorded
   final revision and perform any required critical review.
5. Remove only clean, integrated worktrees with
   `git worktree remove <worktree-path>`. Never force-remove a worktree with
   unpreserved changes.

Technical full-access or YOLO permissions remain separate from authorization.
Keep production, destructive, paid, or externally visible actions under the
existing human gate even when their preparatory code was developed in parallel.
