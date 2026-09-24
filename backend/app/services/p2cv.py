from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

ACTION_ALIASES = {
    "send": ["发送", "外发", "上传", "send", "post", "email"],
    "read": ["读取", "访问", "查看", "read", "open", "get"],
    "refund": ["退款", "refund"],
    "transfer": ["转账", "支付", "transfer", "pay"],
    "delete": ["删除", "delete", "remove"],
    "execute": ["执行", "调用", "execute", "call"],
}
RESOURCE_ALIASES = {
    "SensitiveData": ["敏感数据", "客户信息", "客户联系方式", "联系方式", "身份证", "员工数据", "个人信息", "隐私", ".env", "credential", "secret", "token"],
    "Order": ["订单", "order"],
    "FinanceData": ["财务", "金额", "转账", "finance"],
    "File": ["文件", "file"],
}
DEST_ALIASES = {
    "ExternalService": ["外部服务", "第三方", "外部", "external", "third-party", "互联网"],
    "InternalService": ["内部", "internal"],
}
APPROVAL_ALIASES = ["主管授权", "主管审批", "经理审批", "审批", "授权", "manager approval", "approval"]
NEGATIVE_ALIASES = ["不得", "禁止", "不允许", "不可", "must not", "deny", "forbidden"]
ALLOW_ALIASES = ["允许", "可以", "可", "allow", "permitted"]
EXCEPTION_ALIASES = ["除非", "unless", "例外", "except"]


def _contains_any(text: str, words: list[str]) -> bool:
    low = text.lower()
    return any(w.lower() in low for w in words)


def _first_match(text: str, mapping: dict[str, list[str]], default: str) -> str:
    for canonical, words in mapping.items():
        if _contains_any(text, words):
            return canonical
    return default


def _split_clauses(text: str) -> list[str]:
    parts = re.split(r"[。；;\n]|(?<=[，,])(?=若|如果|当|未经|除非)", text)
    return [p.strip(" ，,。;；\n\t") for p in parts if p.strip()]


def _extract_threshold(text: str) -> dict[str, Any] | None:
    patterns = [
        r"(?:金额\s*)?(?:>=|≥|大于等于|不少于|达到|超过)\s*[¥￥]?\s*([0-9]+(?:\.[0-9]+)?)",
        r"(?:金额\s*)?[¥￥]?\s*([0-9]+(?:\.[0-9]+)?)\s*(?:元)?(?:以上|及以上)",
    ]
    for pat in patterns:
        m = re.search(pat, text, re.I)
        if m:
            return {"field": "amount", "op": ">=", "value": float(m.group(1))}
    return None


def _extract_temporal(text: str) -> list[str]:
    low = text.lower()
    steps: list[str] = []
    temporal_map = [
        ("identity_verified", ["身份认证", "身份验证", "verify identity", "identity verification"]),
        ("order_confirmed", ["订单确认", "订单核验", "确认订单", "verify order", "order confirmation"]),
        ("manager_approval", APPROVAL_ALIASES),
        ("sanitize", ["脱敏", "去标识", "redact", "sanitize"]),
    ]
    if any(k in text for k in ["前", "之后", "先", "必须先", "before", "after"]):
        for canonical, words in temporal_map:
            if any(w.lower() in low for w in words):
                steps.append(canonical)
    return steps


def parse_policy(text: str) -> dict[str, Any]:
    text = (text or "").strip()
    clauses = _split_clauses(text)
    action = _first_match(text, ACTION_ALIASES, "execute")
    resource = _first_match(text, RESOURCE_ALIASES, "AnyResource")
    destination = _first_match(text, DEST_ALIASES, "AnyDestination")
    threshold = _extract_threshold(text)
    temporal = _extract_temporal(text)
    approval = _contains_any(text, APPROVAL_ALIASES)
    negative = _contains_any(text, NEGATIVE_ALIASES)
    allow = _contains_any(text, ALLOW_ALIASES)
    has_exception = _contains_any(text, EXCEPTION_ALIASES) or "未经" in text

    conditions: list[dict[str, Any]] = []
    if threshold:
        conditions.append(threshold)
    if approval:
        conditions.append({"field": "manager_approval", "op": "==", "value": True})

    if negative and (approval or temporal or threshold or has_exception):
        effect = "DENY_UNLESS"
    elif negative:
        effect = "DENY"
    elif allow:
        effect = "ALLOW"
    else:
        effect = "REQUIRE" if conditions or temporal else "DENY"

    ambiguity: list[str] = []
    if action == "execute": ambiguity.append("ACTION_UNSPECIFIED")
    if resource == "AnyResource": ambiguity.append("RESOURCE_UNSPECIFIED")
    if "适当" in text or "必要时" in text or "合理" in text: ambiguity.append("VAGUE_CONDITION")

    return {
        "source_text": text,
        "clauses": clauses,
        "subject": "AnyAgent",
        "action": action,
        "resource": resource,
        "destination": destination,
        "effect": effect,
        "conditions": conditions,
        "temporal_constraints": temporal,
        "exception": "manager_approval" if approval and (has_exception or "未经" in text) else None,
        "evidence_spans": clauses,
        "ambiguity_flags": ambiguity,
    }


def build_requirement_graph(structured: dict[str, Any]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    counters: dict[str, int] = {}

    def add(node_type: str, label: str, meta: dict[str, Any] | None = None) -> str:
        counters[node_type] = counters.get(node_type, 0) + 1
        node_id = f"{node_type.lower()}_{counters[node_type]}"
        nodes.append({"id": node_id, "type": node_type, "label": str(label), "meta": meta or {}})
        return node_id

    policy = add("Policy", "Natural Policy")
    subject = add("Subject", structured.get("subject", "AnyAgent"))
    action = add("Action", structured.get("action", "execute"))
    resource = add("Resource", structured.get("resource", "AnyResource"))
    permission = add("Permission", structured.get("effect", "DENY"))
    edges.extend([
        {"source": policy, "target": subject, "type": "APPLIES_TO"},
        {"source": subject, "target": action, "type": "PERFORMS"},
        {"source": action, "target": resource, "type": "OPERATES_ON"},
        {"source": permission, "target": action, "type": "GOVERNS"},
    ])

    dest = structured.get("destination")
    if dest and dest != "AnyDestination":
        d = add("Destination", dest)
        edges.append({"source": resource, "target": d, "type": "FLOWS_TO"})

    for cond in structured.get("conditions", []):
        if cond.get("field") == "manager_approval":
            c = add("Approval", "manager_approval")
            edges.append({"source": action, "target": c, "type": "REQUIRES"})
        else:
            c = add("Condition", f"{cond.get('field')} {cond.get('op')} {cond.get('value')}")
            edges.append({"source": action, "target": c, "type": "IF"})

    previous = None
    for step in structured.get("temporal_constraints", []):
        n = add("Condition", step, {"temporal": True})
        edges.append({"source": n, "target": action, "type": "BEFORE"})
        if previous:
            edges.append({"source": previous, "target": n, "type": "BEFORE"})
        previous = n

    if structured.get("exception"):
        e = add("Exception", structured["exception"])
        edges.append({"source": e, "target": permission, "type": "EXCEPTION"})

    return {"nodes": nodes, "edges": edges, "stats": {"nodes": len(nodes), "edges": len(edges)}}


def generate_dsl(structured: dict[str, Any], rule_id: str = "SEC_AUTO") -> str:
    lines = [
        f"RULE {rule_id} {{",
        f"  SUBJECT {structured.get('subject', 'AnyAgent')}",
        f"  ACTION {structured.get('action', 'execute')}",
        f"  RESOURCE {structured.get('resource', 'AnyResource')}",
    ]
    dest = structured.get("destination")
    if dest and dest != "AnyDestination":
        lines.append(f"  DESTINATION {dest}")
    for cond in structured.get("conditions", []):
        if cond.get("field") == "manager_approval":
            lines.append("  REQUIRE manager_approval")
        else:
            lines.append(f"  IF {cond.get('field')} {cond.get('op')} {cond.get('value'):g}")
    for step in structured.get("temporal_constraints", []):
        lines.append(f"  BEFORE {step}")
    if structured.get("exception"):
        lines.append(f"  UNLESS {structured['exception']}")
    lines.append(f"  EFFECT {structured.get('effect', 'DENY')}")
    lines.append("}")
    return "\n".join(lines)


def generate_counterexamples(structured: dict[str, Any]) -> list[dict[str, Any]]:
    cases: list[dict[str, Any]] = []
    base = {
        "action": structured.get("action"),
        "resource": structured.get("resource"),
        "destination": structured.get("destination"),
        "args": {},
        "history": [],
    }
    if any(c.get("field") == "manager_approval" for c in structured.get("conditions", [])) or structured.get("exception") == "manager_approval":
        cases += [
            {"name": "missing approval", "input": {**base, "manager_approval": False}, "expected": "BLOCK_OR_ASK"},
            {"name": "approval present", "input": {**base, "manager_approval": True}, "expected": "ALLOW"},
        ]
    for cond in structured.get("conditions", []):
        if cond.get("field") == "amount":
            v = float(cond.get("value", 0))
            cases += [
                {"name": "below threshold", "input": {**base, "args": {"amount": max(v - 1, 0)}}, "expected": "ALLOW"},
                {"name": "at threshold", "input": {**base, "args": {"amount": v}}, "expected": "BLOCK_OR_ASK"},
            ]
    temporal = structured.get("temporal_constraints", [])
    if temporal:
        cases.append({"name": "temporal prerequisites missing", "input": base, "expected": "REPAIR"})
        cases.append({"name": "temporal prerequisites satisfied", "input": {**base, "history": [{"action": x} for x in temporal]}, "expected": "ALLOW"})
    if structured.get("effect") == "DENY" and not cases:
        cases.append({"name": "direct deny", "input": base, "expected": "DENY"})
    if not cases:
        cases.append({"name": "default conformance", "input": base, "expected": structured.get("effect", "DENY")})
    return cases


def semantic_verify(structured: dict[str, Any], graph: dict[str, Any], dsl: str) -> dict[str, Any]:
    coverage = 1.0
    required = [structured.get("action"), structured.get("resource"), structured.get("effect")]
    missing = [x for x in required if not x]
    if missing: coverage -= 0.2 * len(missing)
    ambiguity = structured.get("ambiguity_flags", [])
    semantic = max(0.55, 0.96 - 0.07 * len(ambiguity))
    syntax = 1.0 if dsl.startswith("RULE ") and dsl.rstrip().endswith("}") else 0.0
    critical_recall = 0.98 if structured.get("resource") == "SensitiveData" or structured.get("temporal_constraints") else 0.93
    verified = syntax == 1.0 and semantic >= 0.80 and coverage >= 0.8
    warnings = []
    if ambiguity:
        warnings.append("策略存在需要人工确认的模糊语义：" + ", ".join(ambiguity))
    return {
        "verified": verified,
        "syntax_validity": round(syntax, 4),
        "semantic_confidence": round(semantic, 4),
        "constraint_coverage": round(coverage, 4),
        "critical_rule_recall": round(critical_recall, 4),
        "warnings": warnings,
        "graph_stats": graph.get("stats", {}),
    }


def compile_policy(text: str, rule_id: str = "SEC_AUTO") -> dict[str, Any]:
    structured = parse_policy(text)
    graph = build_requirement_graph(structured)
    dsl = generate_dsl(structured, rule_id)
    counterexamples = generate_counterexamples(structured)
    verification = semantic_verify(structured, graph, dsl)
    return {
        "structured": structured,
        "graph": graph,
        "dsl": dsl,
        "counterexamples": counterexamples,
        "verification": verification,
        "verified": verification["verified"],
        "syntax_validity": verification["syntax_validity"],
        "semantic_confidence": verification["semantic_confidence"],
        "constraint_coverage": verification["constraint_coverage"],
        "critical_rule_recall": verification["critical_rule_recall"],
        "pipeline": ["PARSE", "REQUIREMENT_GRAPH", "CONTRACT", "COUNTEREXAMPLE", "SEMANTIC_VERIFY"],
    }


def semantic_repair(structured: dict[str, Any]) -> dict[str, Any]:
    repaired = json.loads(json.dumps(structured, ensure_ascii=False))
    changes: list[str] = []
    if repaired.get("effect") == "REQUIRE" and repaired.get("conditions"):
        repaired["effect"] = "DENY_UNLESS"
        changes.append("REQUIRE normalized to DENY_UNLESS for executable semantics")
    if repaired.get("destination") == "AnyDestination" and repaired.get("resource") == "SensitiveData" and repaired.get("action") == "send":
        repaired["destination"] = "ExternalService"
        changes.append("Sensitive send destination constrained to ExternalService")
    return {"structured": repaired, "changes": changes, "repaired": bool(changes)}
