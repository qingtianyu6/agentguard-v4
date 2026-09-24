"""Conservative data-lineage propagation for structured events."""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any

SENSITIVE = 'SENSITIVE'

@dataclass
class TaintState:
    labels: dict[str, set[str]] = field(default_factory=dict)
    parents: dict[str, set[str]] = field(default_factory=dict)

    def record(self, event: dict[str, Any]) -> None:
        output = event.get('result_ref') or event.get('output_ref')
        if not output or event.get('state') not in ('completed', 'COMPLETED'):
            return
        source_refs = [str(x) for x in event.get('provenance_refs', [])]
        self.parents[str(output)] = set(source_refs)
        explicit = {str(x) for x in event.get('taint_labels', [])}
        inherited = set().union(*(self.labels.get(x, set()) for x in source_refs)) if source_refs else set()
        # Ordinary summaries, rewrites and model output preserve sensitive labels.
        # Explicit declassification requires a separate trusted validator and cannot
        # be asserted by the source event or a model-generated tool result.
        self.labels[str(output)] = explicit | inherited

    def has_sensitive_ancestor(self, reference: str) -> bool:
        return SENSITIVE in self.labels.get(reference, set())

    def lineage(self, reference: str) -> set[str]:
        found: set[str] = set()
        stack = [reference]
        while stack:
            for parent in self.parents.get(stack.pop(), set()):
                if parent not in found:
                    found.add(parent)
                    stack.append(parent)
        return found


def policy_check(action: dict[str, Any], history: list[dict[str, Any]]) -> dict[str, Any] | None:
    state = TaintState()
    for event in history:
        state.record(event)
    refs = [str(x) for x in action.get('provenance_refs', [])]
    external = str(action.get('destination', '')).lower() in {'external', 'third-party'}
    if external and action.get('action') in {'send', 'upload', 'post', 'email_send'}:
        tainted = [ref for ref in refs if state.has_sensitive_ancestor(ref)]
        if tainted:
            return {'decision': 'ASK', 'risk_level': 'HIGH', 'risk_type': 'TAINTED_DATA_FLOW',
                    'reason': '外发数据来源于敏感节点，需要有效审批或可信脱敏验证。',
                    'tainted_refs': tainted, 'lineage': {ref: sorted(state.lineage(ref)) for ref in tainted}}
    return None
