#!/usr/bin/env python3
"""Check the internal consistency of a lifecycle change record."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

__version__ = "0.3.0"
UPSTREAM_URL = "https://github.com/heartbit-ai/graphpact.git"

TIERS = {"simple": 0, "structured": 1, "critical": 2}
STATES = {"draft", "contracted", "implementing", "verifying", "blocked", "done"}
EXECUTION_MODES = {"sequential", "parallel-read", "parallel-worktrees"}
PROJECT_FIELDS = {"greenfield", "brownfield"}
STRUCTURED = {"cross-component", "public-api", "dependency", "architecture"}
CRITICAL = {
    "auth-permissions",
    "secrets",
    "payments",
    "data-migration",
    "destructive-action",
    "production-action",
    "paid-action",
    "external-side-effect",
    "concurrency-distributed",
    "pii",
    "data-loss",
    "input-validation",
    "supply-chain",
}
PROTECTED = CRITICAL - {"concurrency-distributed"}
LIVE_ACTIONS = {
    "destructive-action",
    "production-action",
    "paid-action",
    "external-side-effect",
}
TASK_STATES = {"pending", "done", "dropped"}
GRILL_MODES = {"interactive", "autonomous", "research"}
ID = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
REVISION = re.compile(r"^[0-9a-f]{7,64}$")
X_SIGNAL = re.compile(r"^x-[a-z0-9-]+$")
AddError = Callable[[str, str], None]


def validate_contract(document: Any, repo: Path | None = None) -> list[str]:
    errors: list[str] = []

    def add(code: str, message: str) -> None:
        errors.append(f"{code}: {message}")

    if not isinstance(document, dict):
        return ["DOC001: contract must be a JSON object"]
    required = {
        "id",
        "state",
        "objective",
        "project",
        "risk",
        "acceptance",
        "execution",
        "tasks",
    }
    for key in sorted(required - document.keys()):
        add("DOC002", f"missing field '{key}'")
    if errors:
        return errors

    reject_unknown(
        document,
        required | {"non_goals", "grill", "approvals", "evidence", "review"},
        "contract",
        add,
    )
    check_id(document["id"], "id", add)
    state = document["state"]
    if not isinstance(state, str) or state not in STATES:
        add("STATE001", f"unknown state '{state}'")
        state = "draft"
    if not nonempty(document["objective"]):
        add("DOC003", "objective must be a non-empty string")
    if "non_goals" in document:
        check_string_list(document["non_goals"], "non_goals", add)
    if "grill" in document:
        grill = document["grill"]
        if not isinstance(grill, dict):
            add("GRILL001", "grill must be an object with mode and notes")
        else:
            reject_unknown(grill, {"mode", "notes"}, "grill", add)
            mode = grill.get("mode")
            if not isinstance(mode, str) or mode not in GRILL_MODES:
                add(
                    "GRILL002",
                    "grill.mode must be one of interactive, autonomous, research",
                )
            notes = grill.get("notes")
            if not isinstance(notes, list) or not notes or any(
                not nonempty(note) for note in notes
            ):
                add(
                    "GRILL003",
                    "grill.notes must be a non-empty array of non-empty strings",
                )
            elif len(set(notes)) != len(notes):
                add("GRILL004", "grill.notes must be unique")

    tier, signals = check_risk(document["risk"], add)
    verifications, continuity_ids = check_acceptance(document["acceptance"], add)
    field, baseline_revision = check_project(document["project"], add)
    if field == "brownfield" and not continuity_ids:
        add(
            "PROJECT007",
            "brownfield changes require at least one continuity acceptance criterion",
        )
    if field == "greenfield" and continuity_ids:
        add(
            "PROJECT008",
            "continuity acceptance criteria are only valid for brownfield changes",
        )
    tasks = check_tasks(document["tasks"], add)
    base_revision = check_execution(document["execution"], state, tasks, add)

    approvals = document.get("approvals", {})
    contract_approved = False
    action_approved = False
    if not isinstance(approvals, dict):
        add("GATE001", "approvals must be an object")
    else:
        reject_unknown(approvals, {"contract", "critical_actions"}, "approvals", add)
        contract_approved = approvals.get("contract") is True
        action_approved = approvals.get("critical_actions") is True
        for key in ("contract", "critical_actions"):
            if key in approvals and not isinstance(approvals[key], bool):
                add("GATE002", f"approvals.{key} must be boolean")
    if state not in {"draft", "blocked"} and not contract_approved:
        add("GATE003", f"state '{state}' requires a recorded contract approval")
    if (
        state in {"implementing", "verifying", "done"}
        and signals & LIVE_ACTIONS
        and not action_approved
    ):
        add(
            "GATE004",
            "live destructive, production, paid, or external actions need approval",
        )

    passed, failed_revisions = check_evidence(
        document.get("evidence", []), verifications, add
    )
    passed_revisions = set().union(*passed.values()) if passed else set()
    completion = next(iter(passed_revisions)) if len(passed_revisions) == 1 else None
    if state == "done":
        for acceptance_id in sorted(set(verifications) - set(passed)):
            add(
                "EVIDENCE001",
                f"acceptance '{acceptance_id}' lacks matching successful evidence",
            )
        if len(passed_revisions) > 1:
            add("EVIDENCE009", "completed evidence must refer to one revision")
        if completion is not None and completion in failed_revisions:
            add(
                "EVIDENCE010",
                "a failing run at the completion revision blocks completion",
            )
        if field == "brownfield" and completion is not None and completion == baseline_revision:
            add(
                "PROJECT012",
                "brownfield evidence must be recorded after the baseline revision",
            )
        if any(task["status"] is not None for task in tasks.values()) and any(
            task["status"] not in {"done", "dropped"} for task in tasks.values()
        ):
            add("TASK014", "every task must be done or dropped before completion")

    review = document.get("review")
    independent = False
    result = "pending"
    review_revision = None
    if review is not None:
        if not isinstance(review, dict):
            add("REVIEW001", "review must be an object")
        else:
            reject_unknown(
                review,
                {"independent", "result", "revision", "findings"},
                "review",
                add,
            )
            independent = review.get("independent") is True
            result = review.get("result")
            review_revision = review.get("revision")
            if "independent" in review and not isinstance(review["independent"], bool):
                add("REVIEW002", "review.independent must be boolean")
            if not isinstance(result, str) or result not in {
                "pending",
                "passed",
                "failed",
            }:
                add("REVIEW003", "review.result must be pending, passed, or failed")
            if "findings" in review:
                check_string_list(review["findings"], "review.findings", add)
    if state == "done" and result == "failed":
        add("REVIEW004", "a failed review blocks completion")
    if (
        state == "done"
        and tier == "critical"
        and not (independent and result == "passed")
    ):
        add(
            "REVIEW005", "a critical completed change needs a passed independent review"
        )
    if (
        state == "done"
        and tier == "critical"
        and (
            not isinstance(review_revision, str)
            or review_revision not in passed_revisions
        )
    ):
        add("REVIEW006", "critical review.revision must match successful evidence")

    if repo is not None:
        labelled = {
            "project.baseline_revision": baseline_revision,
            "execution.base_revision": base_revision,
            "review.revision": (
                review_revision if isinstance(review_revision, str) else None
            ),
        }
        check_git_grounding(repo, labelled, passed_revisions, baseline_revision, add)
    return errors


def check_risk(value: Any, add: AddError) -> tuple[str, set[str]]:
    if not isinstance(value, dict):
        add("RISK001", "risk must be an object")
        return "simple", set()
    reject_unknown(value, {"tier", "signals", "rationale", "downgrade"}, "risk", add)
    if isinstance(value.get("downgrade"), dict):
        reject_unknown(
            value["downgrade"], {"approved", "rationale"}, "risk.downgrade", add
        )
    tier = value.get("tier")
    if not isinstance(tier, str) or tier not in TIERS:
        add("RISK002", f"unknown risk tier '{tier}'")
        tier = "simple"
    raw = value.get("signals")
    if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
        add("RISK003", "risk.signals must be an array of strings")
        signals: set[str] = set()
    else:
        signals = set(raw)
        if len(signals) != len(raw):
            add("RISK004", "risk.signals must be unique")
        for signal in sorted(signals - STRUCTURED - CRITICAL):
            if not X_SIGNAL.fullmatch(signal):
                add(
                    "RISK005",
                    f"unknown risk signal '{signal}' (use an 'x-' prefix to extend)",
                )
    if not nonempty(value.get("rationale")):
        add("RISK006", "risk.rationale must be a non-empty string")

    inferred = (
        "critical"
        if signals & CRITICAL
        else "structured"
        if signals & STRUCTURED
        else "simple"
    )
    if TIERS[tier] < TIERS[inferred]:
        if signals & PROTECTED:
            add("RISK007", "protected critical signals cannot be downgraded")
        downgrade = value.get("downgrade")
        if not (
            isinstance(downgrade, dict)
            and downgrade.get("approved") is True
            and nonempty(downgrade.get("rationale"))
        ):
            add(
                "RISK008",
                f"downgrade from {inferred} to {tier} needs recorded approval",
            )
    elif "downgrade" in value:
        add("RISK009", "risk.downgrade is only valid below the inferred tier")
    return tier, signals


def check_project(value: Any, add: AddError) -> tuple[str | None, str | None]:
    if not isinstance(value, dict):
        add("PROJECT001", "project must be an object")
        return None, None
    reject_unknown(
        value, {"field", "baseline_revision", "invariants", "rollback"}, "project", add
    )
    field = value.get("field")
    if not isinstance(field, str) or field not in PROJECT_FIELDS:
        add("PROJECT002", f"unknown project field '{field}'")
        field = None

    if field == "brownfield":
        baseline = value.get("baseline_revision")
        if not isinstance(baseline, str) or not REVISION.fullmatch(baseline):
            add(
                "PROJECT003",
                "brownfield requires a commit-shaped project.baseline_revision",
            )
        invariants = value.get("invariants")
        if (
            not isinstance(invariants, list)
            or not invariants
            or any(not nonempty(item) for item in invariants)
        ):
            add(
                "PROJECT005",
                "brownfield requires project.invariants as a non-empty array of "
                "non-empty strings",
            )
        elif len(set(invariants)) != len(invariants):
            add("PROJECT011", "project.invariants must be unique")
        if "rollback" in value and not nonempty(value.get("rollback")):
            add("PROJECT009", "project.rollback must be a non-empty string")
    elif field == "greenfield":
        if "baseline_revision" in value:
            add(
                "PROJECT004",
                "project.baseline_revision is only valid for brownfield changes",
            )
        if "invariants" in value:
            add(
                "PROJECT006",
                "project.invariants is only valid for brownfield changes",
            )
        if "rollback" in value:
            add("PROJECT010", "project.rollback is only valid for brownfield changes")
    baseline = value.get("baseline_revision")
    baseline = baseline if isinstance(baseline, str) and REVISION.fullmatch(baseline) else None
    return field, baseline


def check_acceptance(value: Any, add: AddError) -> tuple[dict[str, str], set[str]]:
    if not isinstance(value, list) or not value:
        add("ACCEPT001", "acceptance must be a non-empty array")
        return {}, set()
    verifications: dict[str, str] = {}
    continuity_ids: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            add("ACCEPT002", f"acceptance[{index}] must be an object")
            continue
        reject_unknown(
            item,
            {"id", "criterion", "verification", "continuity"},
            f"acceptance[{index}]",
            add,
        )
        acceptance_id = item.get("id")
        check_id(acceptance_id, f"acceptance[{index}].id", add)
        if isinstance(acceptance_id, str) and acceptance_id in verifications:
            add("ACCEPT003", f"duplicate acceptance id '{acceptance_id}'")
        continuity = item.get("continuity", False)
        if "continuity" in item and not isinstance(continuity, bool):
            add("ACCEPT005", f"acceptance[{index}].continuity must be boolean")
            continuity = False
        if not nonempty(item.get("criterion")) or not nonempty(
            item.get("verification")
        ):
            add("ACCEPT004", f"acceptance[{index}] needs criterion and verification")
        elif isinstance(acceptance_id, str):
            verifications[acceptance_id] = item["verification"]
            if continuity is True:
                continuity_ids.add(acceptance_id)
    return verifications, continuity_ids


def check_tasks(value: Any, add: AddError) -> dict[str, dict[str, Any]]:
    if not isinstance(value, list) or not value:
        add("TASK001", "tasks must be a non-empty array")
        return {}
    graph: dict[str, list[str]] = {}
    tasks: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            add("TASK002", f"tasks[{index}] must be an object")
            continue
        reject_unknown(
            item,
            {"id", "outcome", "depends_on", "write_scope", "verification", "status"},
            f"tasks[{index}]",
            add,
        )
        task_id = item.get("id")
        check_id(task_id, f"tasks[{index}].id", add)
        if not nonempty(item.get("outcome")):
            add("TASK003", f"tasks[{index}].outcome must be non-empty")
        dependencies = item.get("depends_on", [])
        if not isinstance(dependencies, list) or any(
            not isinstance(dep, str) for dep in dependencies
        ):
            add("TASK004", f"tasks[{index}].depends_on must be an array of ids")
            dependencies = []
        elif len(set(dependencies)) != len(dependencies):
            add("TASK005", f"tasks[{index}].depends_on must be unique")
        write_scope = item.get("write_scope")
        if write_scope is not None:
            if (
                not isinstance(write_scope, list)
                or not write_scope
                or any(not nonempty(scope) for scope in write_scope)
            ):
                add(
                    "TASK010",
                    f"tasks[{index}].write_scope must be a non-empty array of strings",
                )
            elif len(set(write_scope)) != len(write_scope):
                add("TASK011", f"tasks[{index}].write_scope must be unique")
        verification = item.get("verification")
        if verification is not None and not nonempty(verification):
            add("TASK012", f"tasks[{index}].verification must be non-empty")
        status = item.get("status")
        if status is not None and status not in TASK_STATES:
            add("TASK013", f"tasks[{index}].status must be pending, done, or dropped")
            status = None
        if isinstance(task_id, str):
            if task_id in graph:
                add("TASK006", f"duplicate task id '{task_id}'")
            graph[task_id] = dependencies
            tasks[task_id] = {
                "depends_on": dependencies,
                "write_scope": write_scope,
                "verification": verification,
                "status": status,
            }
    if len(graph) < 3 and any(graph.values()):
        add("TASK007", "omit dependency edges when fewer than three tasks exist")
    for task_id, dependencies in graph.items():
        for dependency in dependencies:
            if dependency not in graph:
                add(
                    "TASK008",
                    f"task '{task_id}' depends on unknown task '{dependency}'",
                )
    if has_cycle(graph):
        add("TASK009", "task dependency graph contains a cycle")
    return tasks


def check_execution(
    value: Any, state: str, tasks: dict[str, dict[str, Any]], add: AddError
) -> str | None:
    if not isinstance(value, dict):
        add("EXEC001", "execution must be an object")
        return None
    reject_unknown(value, {"mode", "rationale", "base_revision"}, "execution", add)
    mode = value.get("mode")
    if not isinstance(mode, str) or mode not in EXECUTION_MODES:
        add("EXEC002", f"unknown execution mode '{mode}'")
        return None
    if not nonempty(value.get("rationale")):
        add("EXEC003", "execution.rationale must be a non-empty string")
    if mode != "parallel-worktrees":
        if "base_revision" in value:
            add(
                "EXEC004",
                "execution.base_revision is only valid for parallel-worktrees",
            )
        return None

    base_revision = value.get("base_revision")
    if not isinstance(base_revision, str) or not REVISION.fullmatch(base_revision):
        add(
            "EXEC005",
            "parallel-worktrees requires a commit-shaped execution.base_revision",
        )
        base_revision = None
    if state == "draft":
        add("EXEC006", "parallel-worktrees requires a ratified contract")

    graph = {task_id: task["depends_on"] for task_id, task in tasks.items()}
    parallel_pairs = independent_pairs(graph)
    if not parallel_pairs:
        add(
            "EXEC007",
            "parallel-worktrees requires at least two dependency-independent tasks",
        )
    for task_id, task in tasks.items():
        if not (
            isinstance(task["write_scope"], list)
            and task["write_scope"]
            and all(nonempty(scope) for scope in task["write_scope"])
        ):
            add(
                "EXEC008",
                f"task '{task_id}' in a parallel-worktrees plan requires write_scope",
            )
        if not nonempty(task["verification"]):
            add(
                "EXEC009",
                f"task '{task_id}' in a parallel-worktrees plan requires verification",
            )

    for left, right in parallel_pairs:
        left_scope = tasks[left]["write_scope"]
        right_scope = tasks[right]["write_scope"]
        if not isinstance(left_scope, list) or not isinstance(right_scope, list):
            continue
        clash = first_overlap(left_scope, right_scope)
        if clash is not None:
            add(
                "EXEC010",
                f"independent tasks '{left}' and '{right}' share write scope "
                f"'{clash}'",
            )
    return base_revision


def independent_pairs(graph: dict[str, list[str]]) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    task_ids = sorted(graph)
    for index, left in enumerate(task_ids):
        for right in task_ids[index + 1 :]:
            if not depends_on(graph, left, right) and not depends_on(
                graph, right, left
            ):
                pairs.append((left, right))
    return pairs


def depends_on(graph: dict[str, list[str]], task_id: str, dependency: str) -> bool:
    pending = list(graph.get(task_id, []))
    seen: set[str] = set()
    while pending:
        current = pending.pop()
        if current == dependency:
            return True
        if current in seen:
            continue
        seen.add(current)
        pending.extend(graph.get(current, []))
    return False


def first_overlap(left: list[str], right: list[str]) -> str | None:
    for a in left:
        for b in right:
            if scopes_overlap(a, b):
                return a if a == b else f"{a} vs {b}"
    return None


def scopes_overlap(a: str, b: str) -> bool:
    if a == b:
        return True
    path_a = files_segments(a)
    path_b = files_segments(b)
    if path_a is None or path_b is None:
        return False
    shorter, longer = sorted((path_a, path_b), key=len)
    return longer[: len(shorter)] == shorter


def files_segments(scope: str) -> list[str] | None:
    if not isinstance(scope, str) or not scope.startswith("files:"):
        return None
    pattern = scope[len("files:") :]
    segments = [segment for segment in pattern.split("/") if segment]
    while segments and segments[-1] in {"**", "*"}:
        segments.pop()
    return segments


def check_evidence(
    value: Any, verifications: dict[str, str], add: AddError
) -> tuple[dict[str, set[str]], set[str]]:
    if not isinstance(value, list):
        add("EVIDENCE002", "evidence must be an array")
        return {}, set()
    passed: dict[str, set[str]] = {}
    failed_revisions: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            add("EVIDENCE003", f"evidence[{index}] must be an object")
            continue
        reject_unknown(
            item,
            {"acceptance_id", "command", "exit_code", "revision", "observed_at"},
            f"evidence[{index}]",
            add,
        )
        acceptance_id = item.get("acceptance_id")
        expected = (
            verifications.get(acceptance_id) if isinstance(acceptance_id, str) else None
        )
        if expected is None:
            add("EVIDENCE004", f"evidence[{index}] references unknown acceptance")
        command_matches = item.get("command") == expected
        if not command_matches:
            add(
                "EVIDENCE005",
                f"evidence[{index}].command does not match planned verification",
            )
        exit_code = item.get("exit_code")
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            add("EVIDENCE006", f"evidence[{index}].exit_code must be an integer")
        revision = item.get("revision")
        revision_valid = isinstance(revision, str) and bool(REVISION.fullmatch(revision))
        if not revision_valid:
            add(
                "EVIDENCE007",
                f"evidence[{index}].revision must be a commit-shaped identifier",
            )
        timestamp_valid = valid_timestamp(item.get("observed_at"))
        if not timestamp_valid:
            add(
                "EVIDENCE008",
                f"evidence[{index}].observed_at must be a non-future ISO timestamp",
            )
        if expected is None or not command_matches or not revision_valid:
            continue
        if exit_code == 0 and timestamp_valid:
            passed.setdefault(acceptance_id, set()).add(revision)
        elif isinstance(exit_code, int) and not isinstance(exit_code, bool):
            failed_revisions.add(revision)
    return passed, failed_revisions


def has_cycle(graph: dict[str, list[str]]) -> bool:
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(node: str) -> bool:
        if node in visiting:
            return True
        if node in visited:
            return False
        visiting.add(node)
        cyclic = any(dep in graph and visit(dep) for dep in graph[node])
        visiting.remove(node)
        visited.add(node)
        return cyclic

    return any(visit(node) for node in graph)


def parse_version(text: Any) -> tuple[int, int, int] | None:
    if not isinstance(text, str):
        return None
    match = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", text.strip())
    if not match:
        return None
    return (int(match[1]), int(match[2]), int(match[3]))


def latest_upstream_version(source: str) -> str | None:
    result = subprocess.run(
        ["git", "ls-remote", "--tags", "--refs", source],
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    candidates: list[tuple[tuple[int, int, int], str]] = []
    for line in result.stdout.splitlines():
        name = line.split("\t")[-1].rsplit("/", 1)[-1]
        version = parse_version(name)
        if version is not None:
            candidates.append((version, name))
    if not candidates:
        return None
    candidates.sort()
    return candidates[-1][1]


def run_update_check(source: str) -> int:
    local = parse_version(__version__)
    try:
        latest_name = latest_upstream_version(source)
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"UPDATE001: could not reach '{source}': {exc}", file=sys.stderr)
        return 2
    if latest_name is None:
        print(f"UPDATE002: no released versions found at '{source}'", file=sys.stderr)
        return 2
    latest = parse_version(latest_name)
    if local is None or latest is None:
        print("UPDATE003: unrecognized version identifier", file=sys.stderr)
        return 2
    if latest > local:
        print(f"update available: graphpact {__version__} -> {latest_name}")
    else:
        print(f"up to date (graphpact {__version__})")
    return 0


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        timeout=15,
        check=False,
    )


def check_git_grounding(
    repo: Path,
    labelled: dict[str, str | None],
    evidence_revisions: set[str],
    baseline_revision: str | None,
    add: AddError,
) -> None:
    try:
        probe = git(repo, "rev-parse", "--git-dir")
    except (OSError, subprocess.SubprocessError) as exc:
        add("GIT001", f"cannot run git in '{repo}': {exc}")
        return
    if probe.returncode != 0:
        add("GIT001", f"'{repo}' is not a git repository")
        return

    to_check = {
        revision: label
        for label, revision in labelled.items()
        if isinstance(revision, str)
    }
    for revision in sorted(evidence_revisions):
        to_check.setdefault(revision, "evidence.revision")
    for revision, label in sorted(to_check.items()):
        if git(repo, "cat-file", "-e", f"{revision}^{{commit}}").returncode != 0:
            add("GIT002", f"{label} '{revision}' does not exist in '{repo}'")

    completion = (
        next(iter(evidence_revisions)) if len(evidence_revisions) == 1 else None
    )
    if (
        baseline_revision is not None
        and completion is not None
        and completion != baseline_revision
        and git(repo, "cat-file", "-e", f"{baseline_revision}^{{commit}}").returncode == 0
        and git(repo, "cat-file", "-e", f"{completion}^{{commit}}").returncode == 0
        and git(
            repo, "merge-base", "--is-ancestor", baseline_revision, completion
        ).returncode
        != 0
    ):
        add(
            "GIT003",
            f"evidence revision '{completion}' does not descend from baseline "
            f"'{baseline_revision}'",
        )


def reject_unknown(value: Any, allowed: set[str], path: str, add: AddError) -> None:
    if not isinstance(value, dict):
        return
    for key in sorted(set(value) - allowed):
        add("DOC006", f"unexpected field '{path}.{key}'")


def check_id(value: Any, path: str, add: AddError) -> None:
    if not isinstance(value, str) or not ID.fullmatch(value):
        add("ID001", f"{path} must match {ID.pattern}")


def check_string_list(value: Any, path: str, add: AddError) -> None:
    if not isinstance(value, list) or any(not nonempty(item) for item in value):
        add("DOC004", f"{path} must be an array of non-empty strings")
    elif len(set(value)) != len(value):
        add("DOC005", f"{path} must contain unique values")


def nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def valid_timestamp(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed <= datetime.now(
        timezone.utc
    ) + timedelta(minutes=5)


def main(argv: list[str]) -> int:
    usage = "Usage: check.py [--repo PATH] change.json | --version | --check-update"
    repo: Path | None = None
    check_update = False
    source = UPSTREAM_URL
    positional: list[str] = []
    index = 1
    while index < len(argv):
        argument = argv[index]
        if argument in ("--version", "-V"):
            print(f"graphpact {__version__}")
            return 0
        if argument == "--check-update":
            check_update = True
        elif argument == "--source":
            index += 1
            if index >= len(argv):
                print(usage, file=sys.stderr)
                return 2
            source = argv[index]
        elif argument.startswith("--source="):
            source = argument[len("--source=") :]
        elif argument == "--repo":
            index += 1
            if index >= len(argv):
                print(usage, file=sys.stderr)
                return 2
            repo = Path(argv[index])
        elif argument.startswith("--repo="):
            repo = Path(argument[len("--repo=") :])
        else:
            positional.append(argument)
        index += 1
    if check_update:
        return run_update_check(source)
    if len(positional) != 1:
        print(usage, file=sys.stderr)
        return 2
    path = Path(positional[0])
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"LOAD001: {exc}", file=sys.stderr)
        return 2
    errors = validate_contract(document, repo=repo)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        f"OK: {path} (field={document['project']['field']}, "
        f"tier={document['risk']['tier']}, "
        f"state={document['state']}, mode={document['execution']['mode']})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
