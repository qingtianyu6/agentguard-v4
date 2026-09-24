import asyncio
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import tempfile
import pytest
from gateway.adapters.mcp_client import GuardDenied, connect_http
from services.trust_registry.registry import ToolTrustRegistry

SERVER = Path(__file__).with_name('mcp_http_fixture_server.py')
MARKER = Path(tempfile.gettempdir()) / 'agentguard_mcp_test_marker'


def test_streamable_http_transport_enforces_preflight_before_side_effect(monkeypatch):
    monkeypatch.setenv('NO_PROXY', '127.0.0.1,localhost')
    monkeypatch.setenv('no_proxy', '127.0.0.1,localhost')
    monkeypatch.setenv('AGENTGUARD_TEST_MARKER', str(MARKER))
    for key in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy'):
        monkeypatch.delenv(key, raising=False)
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port=sock.getsockname()[1]
    process=subprocess.Popen([sys.executable, str(SERVER)], env={**os.environ, 'AGENTGUARD_TEST_HTTP_PORT':str(port)},
                             stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(80):
            if process.poll() is not None:
                pytest.fail('MCP HTTP server failed: '+process.stderr.read().decode(errors='replace')[-1000:])
            try:
                with socket.create_connection(('127.0.0.1',port), timeout=.1): break
            except OSError: time.sleep(.05)
        else: pytest.fail('MCP HTTP server never started')

        async def run():
            MARKER.unlink(missing_ok=True)
            registry=ToolTrustRegistry()
            allowed=False
            async def decide(action): return {'decision':'ALLOW' if allowed else 'DENY'}
            async with connect_http(f'http://127.0.0.1:{port}/mcp','http-fixture',registry,decide) as client:
                tools=await client.list_tools()
                assert len(tools)>=3
                for tool in tools:registry.register('http-fixture',tool.name,tool.description or '',tool.input_schema,scan_reference='controlled-fixture')
                with pytest.raises(GuardDenied):
                    await client.call_tool('save_record',{'record':'blocked'},{'trace_id':'http-trace'})
                assert not MARKER.exists()
                allowed=True
                result=await client.call_tool('save_record',{'record':'allowed'},{'trace_id':'http-trace'})
                assert result['trace_id']=='http-trace'
                assert MARKER.read_text()=='allowed'
            MARKER.unlink(missing_ok=True)
        asyncio.run(run())
    finally:
        process.terminate()
        try:process.wait(timeout=5)
        except subprocess.TimeoutExpired:process.kill();process.wait()
        process.stderr.close()
        MARKER.unlink(missing_ok=True)
