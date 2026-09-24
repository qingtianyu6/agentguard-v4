from __future__ import annotations

from typing import Any

from .llm_extractor import extract_policy
from .p2cv import build_requirement_graph, generate_counterexamples, generate_dsl, semantic_repair, semantic_verify
from .formal_verifier import verify_formal


def graph_ir_v3(structured: dict[str, Any]) -> dict[str, Any]:
    graph = build_requirement_graph(structured)
    evidence = structured.get("evidence_spans", [])
    for idx, node in enumerate(graph.get("nodes", [])):
        node.setdefault("meta", {})
        node["meta"].update({
            "ir_version": "v3",
            "source_evidence": evidence[min(idx, len(evidence)-1)] if evidence else structured.get("source_text", ""),
        })
    graph["schema"] = "agentguard-requirement-graph-v3"
    graph["typed"] = True
    return graph


def compile_policy_v3(text: str, rule_id: str = "SEC_AUTO", provider: str | None = None, max_repair_rounds: int = 2) -> dict[str, Any]:
    extraction = extract_policy(text, provider=provider)
    structured = extraction.structured
    repair_log: list[dict[str, Any]] = []
    formal: dict[str, Any] = {}
    graph: dict[str, Any] = {}
    dsl = ""

    for round_index in range(max_repair_rounds + 1):
        graph = graph_ir_v3(structured)
        dsl = generate_dsl(structured, rule_id)
        formal = verify_formal(structured, rule_id)
        if formal["verified"]:
            break
        repaired = semantic_repair(structured)
        if not repaired.get("repaired"):
            break
        repair_log.append({
            "round": round_index + 1,
            "counterexamples": formal["model_check"]["counterexamples"],
            "changes": repaired["changes"],
        })
        structured = repaired["structured"]

    semantic = semantic_verify(structured, graph, dsl)
    adversarial = generate_counterexamples(structured)
    ambiguity = structured.get("ambiguity_flags", [])
    needs_human_review = bool(ambiguity) or not formal.get("verified", False)
    verified = bool(semantic.get("verified")) and bool(formal.get("verified")) and not needs_human_review
    status = "VERIFIED" if verified else "REVIEW"
    return {
        "structured": structured,
        "graph": graph,
        "dsl": dsl,
        "formal_ir": formal.get("ir"),
        "smt2": formal.get("model_check", {}).get("smt2", ""),
        "counterexamples": adversarial,
        "formal_verification": formal,
        "verification": {
            **semantic,
            "formal_verified": formal.get("verified", False),
            "model_checker_backend": formal.get("model_check", {}).get("backend"),
            "state_space": formal.get("model_check", {}).get("state_space", 0),
            "formal_counterexamples": formal.get("model_check", {}).get("counterexample_count", 0),
            "human_review_required": needs_human_review,
        },
        "extraction": extraction.as_dict(),
        "cegar": {
            "rounds": len(repair_log),
            "repairs": repair_log,
            "converged": formal.get("verified", False),
        },
        "verified": verified,
        "status": status,
        "pipeline": [
            "STRUCTURED_EXTRACTION", "TYPED_GRAPH_IR", "CONTRACT_CANDIDATE",
            "FORMAL_IR", "BOUNDED_MODEL_CHECK", "COUNTEREXAMPLE_GUIDED_REPAIR", "FINAL_VERIFY",
        ],
        "syntax_validity": semantic.get("syntax_validity", 0),
        "semantic_confidence": semantic.get("semantic_confidence", 0),
        "constraint_coverage": semantic.get("constraint_coverage", 0),
        "critical_rule_recall": semantic.get("critical_rule_recall", 0),
    }
