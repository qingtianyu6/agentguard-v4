from __future__ import annotations

import itertools
import json
from typing import Any

from .runtime_guard import is_sensitive

try:
    import z3  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    z3 = None

FORMAL_SCHEMA = "agentguard-formal-ir-v3"


def build_formal_ir(structured: dict[str, Any], rule_id: str = "SEC_AUTO") -> dict[str, Any]:
    constraints: list[dict[str, Any]] = []
    if structured.get("action") not in (None, "execute", "AnyAction"):
        constraints.append({"kind": "match", "field": "action", "op": "==", "value": structured["action"]})
    if structured.get("resource") not in (None, "AnyResource"):
        constraints.append({"kind": "match", "field": "resource", "op": "class", "value": structured["resource"]})
    if structured.get("destination") not in (None, "AnyDestination"):
        constraints.append({"kind": "match", "field": "destination", "op": "==", "value": structured["destination"]})
    for cond in structured.get("conditions", []):
        constraints.append({"kind": "condition", **cond})
    for idx, step in enumerate(structured.get("temporal_constraints", [])):
        constraints.append({"kind": "temporal", "relation": "BEFORE", "step": step, "order": idx})
    if structured.get("exception"):
        constraints.append({"kind": "exception", "name": structured["exception"]})
    return {
        "schema": FORMAL_SCHEMA,
        "rule_id": rule_id,
        "effect": structured.get("effect", "DENY"),
        "constraints": constraints,
        "source_text": structured.get("source_text", ""),
    }


def formal_ir_to_smt2(ir: dict[str, Any]) -> str:
    lines = [
        "; AgentGuard V3 generated SMT-LIB2 safety model",
        "(set-logic QF_LIA)",
        "(declare-const approval Bool)",
        "(declare-const amount Int)",
    ]
    temporal = [c["step"] for c in ir.get("constraints", []) if c.get("kind") == "temporal"]
    for step in temporal:
        lines.append(f"(declare-const hist_{step} Bool)")
    threshold = next((c for c in ir.get("constraints", []) if c.get("kind") == "condition" and c.get("field") == "amount"), None)
    needs_approval = any(c.get("kind") in {"condition", "exception"} and (c.get("field") == "manager_approval" or c.get("name") == "manager_approval") for c in ir.get("constraints", []))
    violation_terms: list[str] = []
    if threshold and needs_approval:
        violation_terms.append(f"(and (>= amount {int(float(threshold.get('value', 0)))}) (not approval))")
    elif needs_approval:
        violation_terms.append("(not approval)")
    if temporal:
        violation_terms.extend([f"(not hist_{s})" for s in temporal])
    if ir.get("effect") == "DENY":
        violation_terms.append("true")
    expr = "false" if not violation_terms else (violation_terms[0] if len(violation_terms) == 1 else "(or " + " ".join(violation_terms) + ")")
    lines += [f"(define-fun unsafe () Bool {expr})", "(assert unsafe)", "(check-sat)", "(get-model)"]
    return "\n".join(lines) + "\n"


def _resource_matches(c_resource: str, resource: str) -> bool:
    if c_resource == "AnyResource":
        return True
    if c_resource == "SensitiveData":
        return is_sensitive(resource)
    if c_resource == "FinanceData":
        return any(x in resource.lower() for x in ["finance", "transfer", "amount", "payment", "财务", "转账"])
    if c_resource == "Order":
        return "order" in resource.lower()
    if c_resource == "File":
        return "." in resource or "file" in resource.lower()
    return c_resource.lower() in resource.lower()


def evaluate_ir(structured: dict[str, Any], state: dict[str, Any]) -> str:
    action = str(state.get("action", "execute"))
    resource = str(state.get("resource", ""))
    destination = str(state.get("destination", "AnyDestination"))
    amount = float(state.get("amount", 0) or 0)
    approval = bool(state.get("manager_approval", False))
    history = set(state.get("history", []))

    c_action = str(structured.get("action", "execute"))
    c_resource = str(structured.get("resource", "AnyResource"))
    c_dest = str(structured.get("destination", "AnyDestination"))
    if c_action not in ("execute", "AnyAction") and c_action != action:
        return "ALLOW"
    if not _resource_matches(c_resource, resource):
        return "ALLOW"
    if c_dest != "AnyDestination" and c_dest == "ExternalService" and destination not in ("ExternalService", "external", "third-party"):
        return "ALLOW"

    missing = [s for s in structured.get("temporal_constraints", []) if s not in history]
    if missing:
        return "REPAIR"
    threshold = next((c for c in structured.get("conditions", []) if c.get("field") == "amount"), None)
    approval_required = any(c.get("field") == "manager_approval" for c in structured.get("conditions", [])) or structured.get("exception") == "manager_approval"
    if threshold and amount >= float(threshold.get("value", 0)) and not approval:
        return "ASK"
    if approval_required and not threshold and not approval:
        return "ASK"
    effect = structured.get("effect", "DENY")
    if effect == "DENY":
        return "DENY"
    if effect == "DENY_UNLESS" and approval_required and not approval:
        return "ASK"
    return "ALLOW"


def _domain(structured: dict[str, Any]) -> list[dict[str, Any]]:
    threshold = next((c for c in structured.get("conditions", []) if c.get("field") == "amount"), None)
    amounts = [0.0]
    if threshold:
        v = float(threshold.get("value", 0))
        amounts = [max(0.0, v - 1), v, v + 1]
    actions = [structured.get("action", "execute")]
    if actions[0] == "execute":
        actions += ["read", "send"]
    resources = [
        "customer_contact" if structured.get("resource") == "SensitiveData" else
        "finance:transfer" if structured.get("resource") == "FinanceData" else
        "order:1042" if structured.get("resource") == "Order" else
        "readme.txt"
    ]
    resources.append("readme.txt" if resources[0] != "readme.txt" else "customer_contact")
    destinations = ["external", "internal"] if structured.get("destination") in ("ExternalService", "AnyDestination") else [structured.get("destination")]
    temporal = list(structured.get("temporal_constraints", []))
    histories = [[]]
    if temporal:
        histories = [[], temporal[:1], temporal]
    states = []
    for action, resource, dest, amount, approval, history in itertools.product(actions, resources, destinations, amounts, [False, True], histories):
        states.append({
            "action": action, "resource": resource, "destination": dest,
            "amount": amount, "manager_approval": approval, "history": history,
        })
    return states[:160]


def _state_matches_scope(structured: dict[str, Any], state: dict[str, Any]) -> bool:
    c_action = str(structured.get("action", "execute"))
    if c_action not in ("execute", "AnyAction") and c_action != str(state.get("action", "")):
        return False
    if not _resource_matches(str(structured.get("resource", "AnyResource")), str(state.get("resource", ""))):
        return False
    c_dest = str(structured.get("destination", "AnyDestination"))
    if c_dest == "ExternalService" and str(state.get("destination", "")) not in ("ExternalService", "external", "third-party"):
        return False
    if c_dest == "InternalService" and str(state.get("destination", "")) not in ("InternalService", "internal"):
        return False
    return True


def _expected_invariants(structured: dict[str, Any], state: dict[str, Any]) -> list[dict[str, Any]]:
    obligations: list[dict[str, Any]] = []
    if not _state_matches_scope(structured, state):
        return obligations
    decision = evaluate_ir(structured, state)
    # In V3 these are explicit proof obligations over states inside the contract's matching scope.
    if structured.get("effect") == "DENY" and decision == "ALLOW":
        obligations.append({"property": "explicit-deny-never-allows", "expected": "DENY", "actual": decision})
    temporal = structured.get("temporal_constraints", [])
    if temporal and any(s not in set(state.get("history", [])) for s in temporal) and decision == "ALLOW":
        obligations.append({"property": "temporal-prerequisite", "expected": "REPAIR", "actual": decision})
    threshold = next((c for c in structured.get("conditions", []) if c.get("field") == "amount"), None)
    if threshold and float(state.get("amount", 0)) >= float(threshold.get("value", 0)) and not state.get("manager_approval") and decision == "ALLOW":
        obligations.append({"property": "threshold-approval", "expected": "ASK", "actual": decision})
    if (structured.get("exception") == "manager_approval" or any(c.get("field") == "manager_approval" for c in structured.get("conditions", []))) and not threshold and not state.get("manager_approval") and decision == "ALLOW":
        obligations.append({"property": "approval-required", "expected": "ASK", "actual": decision})
    return obligations


def bounded_model_check(structured: dict[str, Any], ir: dict[str, Any]) -> dict[str, Any]:
    states = _domain(structured)
    counterexamples = []
    witnesses = []
    for state in states:
        decision = evaluate_ir(structured, state)
        violations = _expected_invariants(structured, state)
        if violations:
            counterexamples.append({"state": state, "violations": violations, "decision": decision})
        elif len(witnesses) < 8:
            witnesses.append({"state": state, "decision": decision})
    return {
        "backend": "bounded-model-checker",
        "state_space": len(states),
        "counterexamples": counterexamples[:20],
        "counterexample_count": len(counterexamples),
        "witnesses": witnesses,
        "proved": len(counterexamples) == 0,
        "scope": "bounded enumerated states only; not natural-language semantic equivalence",
        "smt2": formal_ir_to_smt2(ir),
    }


def z3_probe(ir: dict[str, Any]) -> dict[str, Any]:
    """Solve a scoped safety obligation and return a concrete witness.

    This checks consistency of the compiled authorization/temporal condition,
    not equivalence with the original natural-language policy.
    """
    if z3 is None:
        return {"available": False, "backend": "z3", "version": None, "status": "unavailable"}
    approval = z3.Bool('approval')
    amount = z3.Int('amount')
    conditions = [c for c in ir.get('constraints', []) if c.get('kind') == 'condition']
    threshold = next((c for c in conditions if c.get('field') == 'amount'), None)
    approval_needed = any(c.get('field') == 'manager_approval' for c in conditions) or any(c.get('kind') == 'exception' and c.get('name') == 'manager_approval' for c in ir.get('constraints', []))
    temporal = [str(c['step']) for c in ir.get('constraints', []) if c.get('kind') == 'temporal']
    prerequisites = {name: z3.Bool('hist_' + str(i)) for i, name in enumerate(temporal)}
    hazards = [z3.Not(v) for v in prerequisites.values()]
    if approval_needed:
        hazards.append(z3.And(amount >= int(float(threshold.get('value', 0))), z3.Not(approval)) if threshold else z3.Not(approval))
    if ir.get('effect') == 'DENY':
        hazards.append(z3.BoolVal(True))
    unsafe = z3.Or(*hazards) if hazards else z3.BoolVal(False)
    solver = z3.Solver()
    solver.add(amount >= 0)
    solver.add(unsafe)
    status = solver.check()
    witness = None
    if status == z3.sat:
        model = solver.model()
        witness = {'amount': model.eval(amount, model_completion=True).as_long(),
                   'manager_approval': z3.is_true(model.eval(approval, model_completion=True)),
                   'history': {name: z3.is_true(model.eval(var, model_completion=True)) for name, var in prerequisites.items()}}
    return {'available': True, 'backend': 'z3', 'version': z3.get_version_string(),
            'status': str(status), 'unsafe_witness': witness,
            'scope': 'symbolic hazard satisfiability in supported authorization/temporal fragment'}


def verify_formal(structured: dict[str, Any], rule_id: str = "SEC_AUTO") -> dict[str, Any]:
    ir = build_formal_ir(structured, rule_id)
    bounded = bounded_model_check(structured, ir)
    return {
        "ir": ir,
        "model_check": bounded,
        "solver": z3_probe(ir),
        "verified": bounded["proved"],
        "verification_scope": "bounded model check of implementation-derived invariants; human semantic review required",
        "proof_obligations": [
            "explicit deny cannot allow matching state",
            "temporal prerequisites must precede protected action",
            "approval-gated thresholds cannot allow without approval",
            "approval-gated actions cannot allow without approval",
        ],
    }
