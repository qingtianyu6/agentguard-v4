import asyncio
from pathlib import Path
import sys
import os
import tempfile
import pytest
from gateway.adapters.mcp_client import connect_stdio, GuardDenied
from services.trust_registry.registry import ToolTrustRegistry

SERVER = Path(__file__).with_name('mcp_fixture_server.py')
MARKER = Path(tempfile.gettempdir()) / 'agentguard_mcp_test_marker'

@pytest.mark.parametrize('allowed', [False, True])
def test_three_real_mcp_tools_and_block_before_side_effect(allowed, monkeypatch):
    monkeypatch.setenv('AGENTGUARD_TEST_MARKER', str(MARKER))
    async def run():
        MARKER.unlink(missing_ok=True)
        registry = ToolTrustRegistry()
        async def decide(action):
            return {'decision': 'ALLOW' if allowed else 'DENY'}
        async with connect_stdio(sys.executable, [str(SERVER)], 'fixture', registry, decide,
                                 env={'AGENTGUARD_TEST_MARKER': str(MARKER)}) as client:
            tools = await client.list_tools()
            assert len(tools) >= 3
            for t in tools:
                registry.register('fixture', t.name, t.description or '', t.input_schema, scan_reference='controlled-fixture')
            if not allowed:
                with pytest.raises(GuardDenied):
                    await client.call_tool('save_record', {'record': 'no'}, {'trace_id': 'trace-one'})
                assert not MARKER.exists()
            else:
                out = await client.call_tool('echo_safe', {'text': 'ok'}, {'trace_id': 'trace-two'})
                assert out['trace_id'] == 'trace-two'
                out = await client.call_tool('save_record', {'record': 'yes'}, {'trace_id': 'trace-two'})
                assert MARKER.read_text() == 'yes'
                out = await client.call_tool('repeat_count', {'value': 'a', 'count': 2}, {'trace_id': 'trace-two'})
                assert out['result'].is_error is False
        MARKER.unlink(missing_ok=True)
    asyncio.run(run())
