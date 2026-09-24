"""Optional OpenTelemetry instrumentation with explicit trace attributes."""
from __future__ import annotations
from contextlib import contextmanager
from opentelemetry import trace

@contextmanager
def decision_span(trace_id: str, server_id: str, tool_id: str):
    with trace.get_tracer('agentguard.gateway').start_as_current_span('agentguard.preflight') as span:
        span.set_attribute('agentguard.trace_id', trace_id)
        span.set_attribute('agentguard.server_id', server_id)
        span.set_attribute('agentguard.tool_id', tool_id)
        yield span
