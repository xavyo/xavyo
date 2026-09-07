# Brownfield continuity

Read this reference when `project.field` is `brownfield`, or when deciding whether a
change is greenfield or brownfield. Greenfield builds new behavior; brownfield must
also preserve behavior that already matters. An agent sees the code in front of it,
not the invisible contracts holding the system together, so brownfield work needs
guardrails that make the existing behavior explicit before it changes.

## Decide the field

Treat a change as **greenfield** only when it adds a new project, package, or
isolated component with no current consumers and no behavior to keep. Everything
else is **brownfield**: new features in a live system, bug fixes, refactors,
dependency swaps, migrations, and modernization. When unsure, choose brownfield;
the extra guardrails are cheap next to a silent regression.

## Investigate before you edit

1. Get the system running and trace one real flow end to end.
2. Read version-control history for the area to find hot spots and past workarounds.
3. Identify the seams where old and new behavior can coexist, and the public
   contracts that callers depend on, even if they were never documented.
4. Scope the change to its delta. Do not retroactively specify the whole system,
   and do not let the change grow unrequested features.

## Freeze the invariant core

List in `project.invariants` the things that must not change: public function and
API signatures, return values and error codes, data and file formats, wire
protocols, and externally observable side effects. This is the contract the change
must honor. Keep it concrete and verifiable rather than aspirational.

## Pin behavior with a continuity check

Before changing code, capture what it does today, not what it should do:

- **Characterization tests** assert the current observable output for chosen inputs.
- **Golden-master / approval tests** snapshot a whole output (a document, response,
  or rendered artifact) and diff future runs against the approved file. Keep inputs
  small and named, and never approve a diff you have not read.
- **Differential tests** run the old and new paths on the same inputs and compare.

Record at least one such check as a continuity acceptance criterion
(`"continuity": true`) anchored to `project.baseline_revision`. A characterization
test that fails on day one means your understanding was wrong: record the real
behavior, note it, and fix any genuine bug in a separate change so a refactoring
mistake stays distinguishable from an intentional fix.

## Change gradually and reversibly

When behavior must move, prefer incremental, reversible strategies over a rewrite:

- **Sprout and wrap:** add new code beside the old and route to it at a seam.
- **Strangler fig:** stand up the new implementation behind a facade and shift
  traffic in increments, keeping the old path live until the new one is proven.
- **Feature flags and staged cutover:** ship dark, enable gradually, and define the
  error and latency thresholds that trigger an automatic revert.

Capture the reversal in `project.rollback` so recovery is a decision, not an
improvisation.

## Verify twice

Every brownfield change is checked against two questions: does it meet its own
acceptance criterion, and does it leave the baseline behavior intact? Run the
continuity checks together with the change's own verification, against one recorded
final revision. Agent claims are not evidence; recorded commands with their actual
exit codes are.

The checker validates that these fields are present and internally consistent. It
cannot prove that the invariants are complete, that the characterization suite is
adequate, or that the rollout is genuinely reversible. Those remain engineering
judgments to confirm in the code.
