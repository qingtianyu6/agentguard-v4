"""Conservative validation of proposed recovery plans.

This module checks proposed actions against the same guard; it does not claim
that a plan succeeds until a real tool result and task-specific oracle exist.
"""
from __future__ import annotations
from typing import Any
from .runtime_guard import evaluate_action


def validate_recovery(body: dict[str, Any]) -> dict[str, Any]:
    original = body.get("original_plan")
    proposed = body.get("safe_plan")
    contracts = body.get("contracts")
    history = body.get("history")
    if not isinstance(original, list) or not isinstance(proposed, list) or not isinstance(contracts, list) or not isinstance(history, list):
        return {"safe": False, "constraint_violations": ["MISSING_EXECUTION_CONTEXT"], "utility_preserved": None, "action_distance": None, "status": "unverified"}
    if not proposed or not all(isinstance(x, dict) and x.get("tool_id") for x in proposed):
        return {"safe": False, "constraint_violations": ["INVALID_PLAN"], "utility_preserved": None, "action_distance": None, "status": "unverified"}
    violations = []
    for index, step in enumerate(proposed):
        decision = evaluate_action(step, contracts, history, mode="trajectory_full")["decision"]
        if decision != "ALLOW":
            violations.append({"step": index, "decision": decision})
        # Future actions are never inserted into trusted history before execution.
    distance = abs(len(original) - len(proposed))
    distance += sum(a != b for a, b in zip(original, proposed))
    return {"safe": not violations, "constraint_violations": violations, "utility_preserved": None, "action_distance": distance, "status": "candidate_checked" if not violations else "rejected", "execution_verified": False}
