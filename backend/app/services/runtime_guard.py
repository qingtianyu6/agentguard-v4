from __future__ import annotations

import json
from typing import Any

SENSITIVE_MARKERS = [
    ".env", "secret", "password", "token", "credential", "api_key", "客户", "联系方式", "身份证",
    "employee", "customer_contact", "private", "个人信息", "salary", "payroll", "patient", "medical",
]
EXTERNAL_MARKERS = ["external", "third-party", "第三方", "外部", "http", "email", "smtp", "webhook", "public"]
INJECTION_MARKERS = [
    "ignore previous", "忽略之前", "bypass policy", "绕过策略", "exfiltrate", "steal secret", "上传秘密",
    "系统提示词", "ignore all rules", "developer message", "override policy",
]
POISONING_MARKERS = [
    "trusted tool - ignore policy", "tool description override", "always allow", "不要检查权限", "工具描述优先",
    "安全策略无效", "poisoned description",
]
PRIVILEGE_MARKERS = ["sudo", "root", "admin", "grant_role", "elevate", "privilege", "提权", "管理员"]
DESTRUCTIVE_MARKERS = ["delete_all", "drop_database", "wipe", "rm -rf", "truncate", "destroy"]


def _raw(value: Any) -> str:
    return value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)


def is_sensitive(value: Any) -> bool:
    low = (_raw(value) or "").lower()
    return any(m.lower() in low for m in SENSITIVE_MARKERS)


def has_injection(value: Any) -> bool:
    low = (_raw(value) or "").lower()
    return any(m.lower() in low for m in INJECTION_MARKERS)


def _match_contract(payload: dict[str, Any], structured: dict[str, Any]) -> bool:
    action = str(payload.get("action", "")).lower()
    resource = str(payload.get("resource", ""))
    destination = str(payload.get("destination", ""))
    c_action = str(structured.get("action", "execute")).lower()
    c_resource = structured.get("resource", "AnyResource")
    c_destination = structured.get("destination", "AnyDestination")
    action_match = c_action in ("execute", "anyaction") or c_action == action or (c_action == "send" and action in ["send", "email_send", "upload", "post"])
    resource_match = (
        c_resource == "AnyResource"
        or (c_resource == "SensitiveData" and is_sensitive(resource))
        or (c_resource == "FinanceData" and any(x in resource.lower() for x in ["finance", "transfer", "payment", "amount", "财务", "转账"]))
        or (c_resource == "Order" and "order" in resource.lower())
        or (c_resource == "File" and ("file" in resource.lower() or "." in resource))
        or c_resource.lower() in resource.lower()
    )
    destination_match = c_destination == "AnyDestination" or (
        c_destination == "ExternalService" and (destination.lower() in ["external", "third-party"] or any(x in destination.lower() for x in ["http", "mail", "webhook"]))
    )
    return action_match and resource_match and destination_match


def _history_actions(history: list[dict[str, Any]]) -> set[str]:
    return {str(h.get("action", "")) for h in history}


def _refund_prerequisites(history: list[dict[str, Any]], order_id: str, agent_id: str,
                          allow_hypothetical: bool) -> set[str]:
    expected = {'identity_verified': ('mcp.order.identity', 'identity_verified'),
                'order_confirmed': ('mcp.order.verify', 'order_confirmed')}
    verified: set[str] = set()
    for event in history:
        action = event.get('action')
        if action not in expected or event.get('state') not in ({'completed', 'hypothetical'} if allow_hypothetical else {'completed'}):
            continue
        tool_id, result_flag = expected[action]
        result = event.get('result')
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except ValueError:
                continue
        if (event.get('tool_id') != tool_id or event.get('agent_id') != agent_id or
            not isinstance(result, dict) or result.get('ok') is not True or
            result.get('order_id') != order_id or result.get(result_flag) is not True):
            continue
        if action == 'order_confirmed' and result.get('status') != 'PAID':
            continue
        verified.add(action)
    return verified


def _history_sensitive(history: list[dict[str, Any]]) -> bool:
    return any(is_sensitive(h.get("resource", "")) or is_sensitive(h.get("result", "")) or is_sensitive(h.get("result_json", "")) for h in history)


def _history_poisoned(history: list[dict[str, Any]]) -> bool:
    return any(has_injection(h.get("resource", "")) or has_injection(h.get("result", "")) or has_injection(h.get("result_json", "")) for h in history)


def _cross_agent_sensitive(history: list[dict[str, Any]], agent_id: str) -> bool:
    for h in history:
        source_agent = str(h.get("agent_id") or h.get("source_agent_id") or "")
        if source_agent and source_agent != agent_id and (is_sensitive(h.get("resource", "")) or is_sensitive(h.get("result", ""))):
            return True
    return False


def evaluate_action(payload: dict[str, Any], active_contracts: list[dict[str, Any]], history: list[dict[str, Any]], mode: str = "trajectory_full",
                    *, allow_hypothetical: bool = False) -> dict[str, Any]:
    tool = str(payload.get("tool_id") or payload.get("tool_call", {}).get("tool_id") or "")
    action = str(payload.get("action") or payload.get("tool_call", {}).get("action") or "execute")
    resource = str(payload.get("resource") or payload.get("resource_ref") or ",".join(payload.get("resource_refs", []) or []) or "")
    destination = str(payload.get("destination") or payload.get("declared_destination") or "")
    args = payload.get("args") or payload.get("tool_call", {}).get("args") or {}
    agent_id = str(payload.get("agent_id") or "agent")
    approval = bool(payload.get("manager_approval") or args.get("manager_approval") or payload.get("approval_granted"))
    role = str(payload.get("role") or args.get("role") or "user").lower()
    amount = float(args.get("amount", 0) or 0)
    low = f"{tool} {action} {resource} {destination} {json.dumps(args, ensure_ascii=False)}".lower()
    hist_actions = _history_actions(history)
    past_sensitive = _history_sensitive(history) if mode == "trajectory_full" else False
    poisoned_memory = _history_poisoned(history) if mode == "trajectory_full" else False
    cross_agent_sensitive = _cross_agent_sensitive(history, agent_id) if mode == "trajectory_full" else False

    # Structured provenance takes precedence over text heuristics when supplied.
    if mode == "trajectory_full" and payload.get("provenance_refs"):
        from services.trajectory_guard.taint import policy_check
        lineage_verdict = policy_check({**payload, "action": action, "destination": destination}, history)
        if lineage_verdict is not None:
            return {**_decision("ASK", "HIGH", "TAINTED_DATA_FLOW", lineage_verdict["reason"], "pol_sensitive", "manager_approval"), "lineage": lineage_verdict["lineage"]}

    # Prompt injection / memory poisoning / tool description poisoning are evaluated before ordinary policy matching.
    if any(x in low for x in INJECTION_MARKERS):
        return _decision("DENY", "HIGH", "PROMPT_INJECTION", "检测到 Prompt Injection 语义，危险指令未进入工具层。", "pol_sensitive")
    if any(x in low for x in POISONING_MARKERS):
        return _decision("DENY", "HIGH", "TOOL_DESCRIPTION_POISONING", "Tool 描述包含绕过安全边界的污染指令。", "pol_sensitive")
    if poisoned_memory and action not in ["read", "memory_read"]:
        return _decision("DENY", "HIGH", "MEMORY_POISONING", "历史 Memory 含有注入指令，当前动作被阻断以避免污染传播。", "pol_sensitive")

    if action in ["read", "open", "get", "file_read"] and any(x in low for x in [".env", "credentials", "id_rsa", "secret.key", ".ssh"]):
        return _decision("DENY", "CRITICAL", "SENSITIVE_FILE_ACCESS", "检测到对凭据或密钥文件的读取请求。", "pol_sensitive")

    if any(x in low for x in DESTRUCTIVE_MARKERS):
        return _decision("DENY", "CRITICAL", "UNAUTHORIZED_TOOL_USE", "检测到破坏性高权限工具调用。", "pol_sensitive")

    privileged = any(x in low for x in PRIVILEGE_MARKERS) or action in ["grant_role", "elevate_privilege", "sudo_execute"]
    if privileged and role not in ["admin", "security_admin"]:
        if approval:
            return _decision("ALLOW", "HIGH", "PRIVILEGE_ESCALATION", "高权限动作已获得显式审批。", "pol_sensitive")
        return _decision("ASK", "HIGH", "PRIVILEGE_ESCALATION", "当前身份不足以执行高权限动作，需要安全管理员审批。", "pol_sensitive", "security_admin_approval")

    if action in ["refund", "issue_refund"]:
        order_id = str(args.get('order_id') or '')
        if not order_id:
            return _decision("DENY", "HIGH", "INVALID_REFUND_CONTEXT", "退款需要明确订单 ID。", "pol_refund")
        required = ["identity_verified", "order_confirmed"]
        verified = _refund_prerequisites(history, order_id, agent_id, allow_hypothetical)
        missing = [x for x in required if x not in verified]
        if missing:
            return _decision("REPAIR", "HIGH", "TEMPORAL_VIOLATION", "退款时序约束未满足：" + "、".join(missing), "pol_refund", ",".join(missing))

    # Cross-agent leakage is distinct from ordinary external exfiltration: the receiver can be another agent.
    if cross_agent_sensitive and (destination.startswith("agent:") or action in ["delegate", "handoff", "send"]):
        if approval:
            return _decision("ALLOW", "MEDIUM", "CROSS_AGENT_LEAKAGE", "跨 Agent 敏感信息共享已获得审批。", "pol_sensitive")
        return _decision("ASK", "HIGH", "CROSS_AGENT_LEAKAGE", "历史轨迹包含其他 Agent 来源的敏感数据，跨 Agent 共享需要审批。", "pol_sensitive", "manager_approval")

    if action in ["send", "upload", "post", "email_send"] and (destination.lower() in ["external", "third-party"] or any(x in low for x in EXTERNAL_MARKERS)):
        if is_sensitive(resource) or is_sensitive(args) or past_sensitive:
            if approval:
                return _decision("ALLOW", "MEDIUM", "DATA_EXFILTRATION", "敏感数据外发条件已满足有效审批。", "pol_sensitive")
            return _decision("ASK", "HIGH", "DATA_EXFILTRATION", "轨迹包含敏感数据且目标为外部服务，需要审批或脱敏。", "pol_sensitive", "manager_approval")

    for c in active_contracts:
        structured = c.get("structured", {})
        if not _match_contract({"action": action, "resource": resource, "destination": destination}, structured):
            continue
        temporal = structured.get("temporal_constraints", [])
        if temporal:
            missing = [x for x in temporal if x not in hist_actions]
            if missing:
                return _decision("REPAIR", "HIGH", "TEMPORAL_VIOLATION", "行为契约要求先完成：" + "、".join(missing), c.get("policy_id", ""), ",".join(missing))
        conditions = structured.get("conditions", [])
        threshold_conditions = [x for x in conditions if x.get("field") == "amount"]
        approval_conditions = [x for x in conditions if x.get("field") == "manager_approval"]
        if threshold_conditions:
            threshold = max(float(x.get("value", 0)) for x in threshold_conditions)
            if amount >= threshold and not approval:
                return _decision("ASK", "HIGH", "APPROVAL_REQUIRED", f"金额 {amount:g} 达到策略阈值 {threshold:g}，需要主管审批。", c.get("policy_id", ""), "manager_approval")
        elif approval_conditions and not approval:
            return _decision("ASK", "HIGH", "APPROVAL_REQUIRED", "当前契约要求 manager_approval。", c.get("policy_id", ""), "manager_approval")
        effect = structured.get("effect")
        if effect == "DENY":
            return _decision("DENY", "HIGH", "POLICY_DENY", "活动行为契约明确禁止该动作。", c.get("policy_id", ""))

    return _decision("ALLOW", "LOW", "NONE", "当前动作及其历史轨迹未触发活动策略约束。", "")


def _decision(decision: str, risk_level: str, risk_type: str, reason: str, policy_id: str, required: str = "") -> dict[str, Any]:
    return {
        "decision": decision,
        "risk_level": risk_level,
        "risk_type": risk_type,
        "reason": reason,
        "matched_policy_id": policy_id,
        "required_condition": required,
    }


def safe_recovery(decision: dict[str, Any], payload: dict[str, Any],
                  history: list[dict[str, Any]] | None = None,
                  contracts: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    risk_type = decision.get("risk_type")
    if risk_type == "TEMPORAL_VIOLATION":
        from services.recovery_engine.planner import plan_recovery
        candidate = plan_recovery(payload, contracts or [], history or [], evaluate_action)
        if candidate['status'] != 'candidate_only':
            return [{"step": 1, "action": "review", "tool_id": "agentguard.review",
                     "label": "未找到可验证的安全候选路径", "auto_executable": False}]
        operators = {
            'verify_identity': ('identity_verified', 'mcp.order.identity', '完成用户身份认证'),
            'verify_order': ('order_confirmed', 'mcp.order.verify', '核验订单状态'),
        }
        steps = [{"step": index, "action": operators[name][0], "tool_id": operators[name][1],
                  "label": operators[name][2], "auto_executable": True}
                 for index, name in enumerate(candidate['steps'], 1) if name in operators]
        steps.append({"step": len(steps) + 1, "action": payload.get('action', 'execute'),
                      "tool_id": payload.get('tool_id', ''), "label": "重新提交原操作",
                      "auto_executable": False})
        return steps
    if risk_type in ["DATA_EXFILTRATION", "SENSITIVE_FILE_ACCESS", "CROSS_AGENT_LEAKAGE"]:
        return [
            {"step": 1, "action": "redact", "tool_id": "agentguard.transform.redact", "label": "删除凭据、身份证与联系方式", "auto_executable": True},
            {"step": 2, "action": "aggregate", "tool_id": "agentguard.transform.aggregate", "label": "仅保留完成任务所需的最小信息", "auto_executable": True},
            {"step": 3, "action": "request_approval", "tool_id": "agentguard.approval.request", "label": "请求主管确认共享范围", "auto_executable": False},
            {"step": 4, "action": "send_sanitized", "tool_id": "mcp.email.send", "label": "发送脱敏后的结果", "auto_executable": True},
        ]
    if risk_type in ["APPROVAL_REQUIRED", "PRIVILEGE_ESCALATION"]:
        return [
            {"step": 1, "action": "request_approval", "tool_id": "agentguard.approval.request", "label": "请求授权审批", "auto_executable": False},
            {"step": 2, "action": payload.get("action", "execute"), "tool_id": payload.get("tool_id", ""), "label": "审批后继续原操作", "auto_executable": True},
        ]
    if risk_type in ["PROMPT_INJECTION", "TOOL_DESCRIPTION_POISONING", "MEMORY_POISONING", "UNAUTHORIZED_TOOL_USE"]:
        return [
            {"step": 1, "action": "quarantine", "tool_id": "agentguard.quarantine", "label": "隔离不可信指令或工具描述", "auto_executable": True},
            {"step": 2, "action": "review", "tool_id": "agentguard.review", "label": "重新生成不含污染指令的安全计划", "auto_executable": False},
        ]
    return [{"step": 1, "action": "review", "tool_id": "agentguard.review", "label": "人工复核当前动作", "auto_executable": False}]
