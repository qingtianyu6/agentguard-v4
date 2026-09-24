import asyncio
import sys
from pathlib import Path

import httpx
from app.main import app
from gateway.adapters.mcp_client import GuardDenied, connect_stdio
from gateway.adapters.runtime_bridge import GatewayRuntimeBridge
from services.trust_registry.registry import ToolTrustRegistry


SERVER = Path(__file__).with_name('mcp_fixture_server.py')


def test_real_mcp_result_drives_next_trajectory_decision():
    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='http://test') as http:
            session=(await http.post('/gateway/v1/sessions',json={'agent_id':'ops'})).json()['data']
            trace_id=session['trace_id']
            bridge=GatewayRuntimeBridge(http)
            registry=ToolTrustRegistry()
            async with connect_stdio(sys.executable,[str(SERVER)],'fixture',registry,bridge.preflight,
                                     lifecycle=bridge) as client:
                for tool in await client.list_tools():
                    registry.register('fixture',tool.name,tool.description or '',tool.input_schema,
                                      scan_reference='controlled-fixture')
                first=await client.call_tool('echo_safe',{'text':'sample'},
                    {'trace_id':trace_id,'agent_id':'ops','action':'read',
                     'resource':'customer_contacts.csv','destination':'internal'})
                assert first['result'].is_error is False
                assert len(first['result_ref'])==64
                try:
                    await client.call_tool('save_record',{'record':'must-not-write'},
                        {'trace_id':trace_id,'agent_id':'ops','action':'send',
                         'destination':'external','resource':'ordinary summary',
                         'provenance_refs':[first['result_ref']]})
                except GuardDenied as error:
                    assert str(error)=='ASK'
                else:
                    raise AssertionError('Sensitive lineage was not blocked')

    asyncio.run(run())
