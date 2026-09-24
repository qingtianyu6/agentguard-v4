"""AgentDojo 0.1.35 tool execution adapter; no model calls or dataset copies."""
from __future__ import annotations
from collections.abc import Callable, Sequence
from typing import Any
from agentdojo.agent_pipeline.tool_execution import ToolsExecutor
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.types import ChatMessage


class _GuardedRuntime:
    def __init__(self, delegate: FunctionsRuntime, decide: Callable[[dict], dict], allowed_tools: frozenset[str],
                 trace_id: str, events: list[dict]):
        self.delegate, self.decide, self.allowed_tools = delegate, decide, allowed_tools
        self.trace_id, self.events = trace_id, events
        self.functions = delegate.functions

    def run_function(self, env: Any, function: str, kwargs: dict, raise_on_error: bool = False):
        request = {'trace_id': self.trace_id, 'tool_id': function, 'args': dict(kwargs), 'action': function}
        if _contains_nested_call(kwargs):
            decision = {'decision': 'DENY', 'reason': 'NESTED_CALL_NOT_AUTHORIZED'}
        elif function not in self.allowed_tools:
            decision = {'decision': 'DENY', 'reason': 'UNREGISTERED_TOOL'}
        else:
            try:
                decision = self.decide(request)
            except Exception:
                decision = {'decision': 'DENY', 'reason': 'PDP_ERROR'}
        admitted = isinstance(decision, dict) and decision.get('decision') == 'ALLOW'
        event = {'trace_id': self.trace_id, 'tool_id': function, 'decision': 'ALLOW' if admitted else 'DENY'}
        self.events.append(event)
        if not admitted:
            return '', 'AgentGuardDenied: tool call refused before execution'
        result, error = self.delegate.run_function(env, function, kwargs, raise_on_error=raise_on_error)
        event['result'] = 'failed' if error is not None else 'completed'
        return result, error


def _contains_nested_call(value: Any) -> bool:
    if isinstance(value, FunctionCall):
        return True
    if isinstance(value, dict):
        return any(_contains_nested_call(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_contains_nested_call(item) for item in value)
    return False


class AgentGuardToolsExecutor(ToolsExecutor):
    """Drop-in ToolsExecutor for an AgentDojo ToolsExecutionLoop.

    Only an explicit allowlist and an authoritative synchronous PDP can admit
    a call. Baseline attack/task success is computed by AgentDojo, never here.
    """
    def __init__(self, decide: Callable[[dict], dict], allowed_tools: Sequence[str]):
        super().__init__()
        self.decide = decide
        self.allowed_tools = frozenset(allowed_tools)
        self.events: list[dict] = []

    def query(self, query: str, runtime: FunctionsRuntime, env: Any = None,
              messages: Sequence[ChatMessage] = (), extra_args: dict | None = None):
        args = extra_args if extra_args is not None else {}
        guard = _GuardedRuntime(runtime, self.decide, self.allowed_tools, str(args.get('agentguard_trace_id', '')), self.events)
        q, _, e, m, a = super().query(query, guard, env, messages, args)
        return q, runtime, e, m, a
