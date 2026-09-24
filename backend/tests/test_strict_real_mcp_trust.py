import asyncio
import hashlib
import sys
from pathlib import Path

import httpx
from app.main import app
from gateway.adapters.mcp_client import GuardDenied, connect_stdio
from gateway.adapters.runtime_bridge import GatewayRuntimeBridge
from services.trust_registry.registry import ToolTrustRegistry


SERVER=Path(__file__).with_name('mcp_fixture_server.py')


def test_strict_real_mcp_requires_reviewed_identity_and_blocks_quarantine(monkeypatch):
    monkeypatch.setenv('AGENTGUARD_SECURITY_PROFILE','strict')
    monkeypatch.setenv('AGENTGUARD_GATEWAY_TOKEN','gateway-secret')
    monkeypatch.setenv('AGENTGUARD_APPROVER_TOKEN','approver-secret')

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),base_url='http://test') as http:
            approver={'x-agentguard-token':'approver-secret'}
            gateway={'x-agentguard-token':'gateway-secret'}
            policy=(await http.post('/api/v1/policies',headers=approver,json={'name':'MCP trust test',
                'natural_text':'未经主管授权，任何 Agent 不得向外部服务发送客户联系方式或敏感数据。'})).json()['data']
            pid=policy['id']
            assert (await http.post(f'/api/v1/policies/{pid}/compile',headers=approver,json={})).status_code==200
            assert (await http.post(f'/api/v1/policies/{pid}/review',headers=approver,
                                    json={'source_matches_contract':True})).status_code==200
            assert (await http.post(f'/api/v1/policies/{pid}/activate',headers=approver)).status_code==200
            session=(await http.post('/gateway/v1/sessions',headers=gateway,
                                     json={'agent_id':'ops'})).json()['data']
            bridge=GatewayRuntimeBridge(http,'gateway-secret')
            registry=ToolTrustRegistry()
            async with connect_stdio(sys.executable,[str(SERVER)],'strict-fixture',registry,
                                     bridge.preflight,lifecycle=bridge) as client:
                tool=next(item for item in await client.list_tools() if item.name=='echo_safe')
                registry.register('strict-fixture',tool.name,tool.description or '',tool.input_schema,
                                  scan_reference='controlled-fixture')
                context={'trace_id':session['trace_id'],'agent_id':'ops','action':'read',
                         'resource':'customer_contacts.csv','destination':'internal'}
                try:
                    await client.call_tool('echo_safe',{'text':'sample'},context)
                except GuardDenied as error:
                    assert str(error)=='DENY'
                else:
                    raise AssertionError('Unreviewed tool was allowed')

                registration=(await http.post('/api/v1/trust/mcp-tools',headers=approver,json={
                    'server_id':'strict-fixture','tool_id':'echo_safe','actions':['read'],
                    'description':tool.description or '', 'schema':tool.input_schema,
                    'scan_reference':'controlled-fixture',
                    'scan_report_sha256':hashlib.sha256(b'controlled-fixture').hexdigest(),
                    'reviewed':True})).json()['data']
                allowed=await client.call_tool('echo_safe',{'text':'sample'},context)
                assert allowed['result'].is_error is False
                assert len(allowed['result_ref'])==64

                drift=(await http.post('/gateway/v1/actions/preflight',headers=gateway,json={
                    **context,'server_id':'strict-fixture','tool_id':'echo_safe','args':{},
                    'tool_description_hash':'0'*64,
                    'tool_schema_hash':registration['schema_hash']})).json()['data']
                assert drift['risk_type']=='DESCRIPTION_DRIFT'
                pending=(await http.post('/gateway/v1/actions/preflight',headers=gateway,json={
                    **context,'server_id':'strict-fixture','tool_id':'echo_safe','args':{},
                    'tool_description_hash':registration['description_hash'],
                    'tool_schema_hash':registration['schema_hash']})).json()['data']
                assert pending['decision']=='ALLOW'
                evidence=(await http.get('/api/v1/audit/traces/'+session['trace_id']+'/evidence-bundle',
                                         headers=approver)).json()['data']
                assert any(x['scan_report_sha256']==registration['scan_report_sha256']
                           for x in evidence['content']['tool_fingerprints'])
                assert (await http.post('/api/v1/trust/mcp-tools/'+registration['id']+'/quarantine',
                                        headers=approver)).status_code==200
                revoked=await http.post('/gateway/v1/actions/'+pending['action_id']+'/commit',headers=gateway)
                assert revoked.status_code==409
                try:
                    await client.call_tool('echo_safe',{'text':'sample'},context)
                except GuardDenied as error:
                    assert str(error)=='DENY'
                else:
                    raise AssertionError('Quarantined tool was allowed')

    asyncio.run(run())
