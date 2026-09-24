from app.services.mcp_runtime import execute_tool
from app.services.recovery_validation import validate_recovery
from app.services.benchmark_engine import evaluate_benchmark


def test_unknown_tool_fails_closed():
    assert execute_tool('unregistered', 'send', {'to': 'x'})['error'] == 'UNKNOWN_TOOL'
    assert execute_tool('mcp.files.list', 'list_files', {})['ok'] is True


def test_recovery_requires_context_and_does_not_invent_utility():
    assert validate_recovery({})['safe'] is False
    result = validate_recovery({'original_plan': [], 'safe_plan': [{'tool_id': 'mcp.files.list', 'action': 'list_files'}], 'contracts': [], 'history': []})
    assert result['safe'] is True
    assert result['execution_verified'] is False
    assert result['utility_preserved'] is None


def test_benchmark_reports_measured_decision_latency():
    metrics = evaluate_benchmark([], split='test')['metrics']
    assert metrics['decision_latency_p95_ms'] >= metrics['decision_latency_p50_ms'] >= 0
