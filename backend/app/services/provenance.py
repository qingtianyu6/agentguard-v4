from __future__ import annotations

from typing import Any
from .runtime_guard import is_sensitive


def build_provenance(trace_id: str, agent_id: str, history: list[dict[str, Any]], decisions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    seen: set[str] = set()

    def node(node_id: str, node_type: str, label: str, **meta: Any) -> str:
        if node_id not in seen:
            seen.add(node_id)
            nodes.append({"id": node_id, "type": node_type, "label": label, "meta": meta})
        return node_id

    user = node("user_current", "User", "Current User")
    agent = node(f"agent_{agent_id}", "Agent", agent_id)
    edges.append({"source": user, "target": agent, "type": "DELEGATES"})
    risk_paths: list[dict[str, Any]] = []

    for idx, h in enumerate(history, 1):
        action_id = h.get("action_id") or f"action_{idx}"
        action = node(action_id, "Action", h.get("action", "execute"), state=h.get("state", ""))
        tool_id = h.get("tool_id") or "unknown-tool"
        tool = node(f"tool_{tool_id}", "Tool", tool_id)
        edges += [
            {"source": agent, "target": action, "type": "PERFORMS"},
            {"source": action, "target": tool, "type": "CALLS"},
        ]
        resource_raw = h.get("resource", "") or "no-resource"
        resources = [x.strip() for x in str(resource_raw).split(",") if x.strip()] or ["no-resource"]
        for ridx, raw in enumerate(resources, 1):
            rnode = node(f"data_{idx}_{ridx}", "Data", raw, sensitive=is_sensitive(raw))
            if h.get("action") in ["read", "open", "get", "file_read"]:
                edges.append({"source": tool, "target": rnode, "type": "READS"})
                edges.append({"source": rnode, "target": agent, "type": "FLOWS_TO"})
            else:
                edges.append({"source": agent, "target": rnode, "type": "USES"})
        destination = h.get("destination")
        if destination:
            dnode = node(f"dest_{idx}", "Destination", destination)
            edges.append({"source": tool, "target": dnode, "type": "FLOWS_TO"})
            if any(is_sensitive(x) for x in resources) and destination.lower() in ["external", "third-party"]:
                risk_paths.append({"from": resources, "to": destination, "reason": "Sensitive data may flow outside the trust boundary"})

    for d in decisions or []:
        did = d.get("decision_id") or d.get("id") or "decision"
        dnode = node(f"decision_{did}", "Decision", d.get("decision", "UNKNOWN"), risk_level=d.get("risk_level", "LOW"))
        action_id = d.get("action_id")
        if action_id:
            edges.append({"source": action_id, "target": dnode, "type": "DECIDED_AS"})
        policy = d.get("matched_policy_id")
        if policy:
            pnode = node(f"policy_{policy}", "Policy", policy)
            edges.append({"source": pnode, "target": dnode, "type": "JUSTIFIES"})

    return {"trace_id": trace_id, "nodes": nodes, "edges": edges, "risk_paths": risk_paths, "stats": {"nodes": len(nodes), "edges": len(edges), "risk_paths": len(risk_paths)}}
