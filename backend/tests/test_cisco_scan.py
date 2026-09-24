import asyncio
from pathlib import Path
import sys
from gateway.adapters.mcp_client import connect_stdio
from services.trust_registry.registry import ToolTrustRegistry
from services.trust_registry.cisco_scanner import scan_and_register

SERVER=Path(__file__).with_name('mcp_fixture_server.py')

def test_real_scanner_enrolls_three_fixture_tools():
    async def run():
        registry=ToolTrustRegistry()
        async def decide(_):return {'decision':'ALLOW'}
        async with connect_stdio(sys.executable,[str(SERVER)],'fixture',registry,decide) as client:
            tools=await client.list_tools()
            report=await scan_and_register(sys.executable,[str(SERVER)],'fixture',registry,tools)
            assert len(report['results'])>=3
            for t in tools:
                assert registry.check('fixture',t.name,t.description or '',t.input_schema)==(True,'TRUSTED')
    asyncio.run(run())
