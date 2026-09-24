"""LangGraph only orchestrates proposal and validation; no business action executes here."""
from __future__ import annotations
from typing import Any, TypedDict
from langgraph.graph import StateGraph, START, END
from .planner import plan_recovery
from app.services.runtime_guard import evaluate_action
from app.services.recovery_validation import validate_recovery

class RecoveryState(TypedDict, total=False):
    original_action: dict[str, Any]
    contracts: list[dict[str, Any]]
    history: list[dict[str, Any]]
    candidate: dict[str, Any]
    validation: dict[str, Any]


def propose(state: RecoveryState) -> dict:
    return {'candidate': plan_recovery(state['original_action'], state['contracts'], state['history'], evaluate_action)}


def validate(state: RecoveryState) -> dict:
    candidate = state['candidate']
    # The planner uses hypothetical prerequisites to locate a candidate; this
    # workflow cannot certify real-world execution or implied authorization.
    if candidate['status'] != 'candidate_only' or candidate['steps']:
        return {'validation': {'safe': False, 'status': 'requires_real_execution_and_recheck'}}
    return {'validation': validate_recovery({'original_plan':[state['original_action']],
        'safe_plan':[state['original_action']], 'contracts':state['contracts'], 'history':state['history']})}


def build_workflow():
    graph = StateGraph(RecoveryState)
    graph.add_node('propose', propose)
    graph.add_node('validate', validate)
    graph.add_edge(START, 'propose')
    graph.add_edge('propose', 'validate')
    graph.add_edge('validate', END)
    return graph.compile()
