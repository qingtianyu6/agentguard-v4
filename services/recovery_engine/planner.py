"""Bounded candidate search over trusted recovery operators."""
from __future__ import annotations
from dataclasses import dataclass
from heapq import heappush, heappop
from typing import Any, Callable

@dataclass(frozen=True)
class Operator:
    name: str
    cost: int
    requires_human: bool = False

OPS = {
    'verify_identity': Operator('verify_identity', 1),
    'verify_order': Operator('verify_order', 1),
    'request_approval': Operator('request_approval', 2, True),
}


def plan_recovery(original: dict[str, Any], contracts: list[dict[str, Any]], history: list[dict[str, Any]],
                  evaluator: Callable, max_depth: int = 3) -> dict[str, Any]:
    """Find the least-cost safe *candidate*; execution rechecks real results.

    Simulated prerequisites only prove a possible path. They never become
    trusted runtime events until the corresponding real tools succeed.
    """
    queue = [(0, (), list(history))]
    seen = set()
    while queue:
        cost, names, hypothetical = heappop(queue)
        if names in seen: continue
        seen.add(names)
        action = dict(original)
        if 'request_approval' in names:
            action['approval_granted'] = True
        verdict = evaluator(action, contracts, hypothetical, allow_hypothetical=True)
        if verdict['decision'] == 'ALLOW':
            return {'status': 'candidate_only', 'steps': list(names), 'action_distance': cost,
                    'requires_human': any(OPS[n].requires_human for n in names),
                    'utility_preserved': None, 'execution_verified': False,
                    'validation': verdict}
        if len(names) >= max_depth: continue
        for name, op in OPS.items():
            if name in names: continue
            if name == 'request_approval' and verdict['decision'] not in {'ASK', 'REPAIR'}: continue
            if name in {'verify_identity', 'verify_order'} and verdict['risk_type'] != 'TEMPORAL_VIOLATION': continue
            updated = list(hypothetical)
            order_id = str(original.get('args', {}).get('order_id') or '')
            agent_id = str(original.get('agent_id') or 'agent')
            if name == 'verify_identity': updated.append({'action': 'identity_verified', 'state': 'hypothetical',
                'tool_id': 'mcp.order.identity', 'agent_id': agent_id,
                'result': {'ok': True, 'identity_verified': True, 'order_id': order_id}})
            if name == 'verify_order': updated.append({'action': 'order_confirmed', 'state': 'hypothetical',
                'tool_id': 'mcp.order.verify', 'agent_id': agent_id,
                'result': {'ok': True, 'order_confirmed': True, 'order_id': order_id, 'status': 'PAID'}})
            heappush(queue, (cost + op.cost, names + (name,), updated))
    return {'status': 'no_safe_candidate', 'steps': [], 'action_distance': None,
            'utility_preserved': None, 'execution_verified': False}
