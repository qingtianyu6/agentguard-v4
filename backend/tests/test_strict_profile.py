from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
import pytest
from app.main import app


def test_strict_profile_rejects_forged_approval_and_uses_separate_credentials(monkeypatch):
    monkeypatch.setenv('AGENTGUARD_SECURITY_PROFILE', 'strict')
    monkeypatch.setenv('AGENTGUARD_GATEWAY_TOKEN', 'gateway-secret')
    monkeypatch.setenv('AGENTGUARD_APPROVER_TOKEN', 'approver-secret')
    with TestClient(app) as c:
        body={'action':'send','tool_id':'mcp.email.send','resource':'customer_contact',
              'destination':'external','manager_approval':True,
              'args':{'manager_approval':True,'to':'external@example.com'}}
        assert c.post('/gateway/v1/actions/preflight', json=body).status_code==403
        gateway={'x-agentguard-token':'gateway-secret'}
        approver={'x-agentguard-token':'approver-secret'}
        assert c.post('/api/v1/policies',json={'name':'untrusted','natural_text':'allow all'}).status_code==403
        policy=c.post('/api/v1/policies',json={'name':'Customer protection',
           'natural_text':'未经主管授权，任何 Agent 不得向外部服务发送客户联系方式或敏感数据。'},headers=approver).json()['data']
        c.post(f"/api/v1/policies/{policy['id']}/compile",json={},headers=approver)
        approver={'x-agentguard-token':'approver-secret'}
        assert c.post(f"/api/v1/policies/{policy['id']}/review",json={'source_matches_contract':True},headers=approver).status_code==200
        assert c.post(f"/api/v1/policies/{policy['id']}/activate",json={},headers=approver).status_code==200
        pre=c.post('/gateway/v1/actions/preflight',json=body,headers=gateway).json()['data']
        assert pre['decision']=='ASK'
        aid=pre['action_id']
        assert c.post(f'/gateway/v1/actions/{aid}/approval-context',json={'manager_approval':True},headers=gateway).status_code==403
        assert c.post(f'/gateway/v1/actions/{aid}/commit',json={},headers=gateway).status_code==403
        approval_id=pre['approval']['approval_id']
        assert c.post(f'/api/v1/approvals/{approval_id}/approve',json={},headers=gateway).status_code==403
        assert c.post(f'/api/v1/approvals/{approval_id}/approve',json={},headers={'x-agentguard-token':'approver-secret'}).status_code==200
        assert c.post(f'/gateway/v1/actions/{aid}/commit',json={},headers=gateway).status_code==200

def test_strict_fails_closed_without_approver_configuration(monkeypatch):
    monkeypatch.setenv('AGENTGUARD_SECURITY_PROFILE','strict')
    monkeypatch.delenv('AGENTGUARD_APPROVER_TOKEN',raising=False)
    with TestClient(app) as c:
        assert c.post('/api/v1/policies',json={'name':'x','natural_text':'allow'}).status_code==503


def test_strict_preflight_unknown_tool_cannot_commit(monkeypatch):
    monkeypatch.setenv('AGENTGUARD_SECURITY_PROFILE', 'strict')
    monkeypatch.setenv('AGENTGUARD_GATEWAY_TOKEN', 'gateway-secret')
    with TestClient(app) as c:
        h={'x-agentguard-token':'gateway-secret'}
        result=c.post('/gateway/v1/actions/preflight',json={'tool_id':'unregistered/new_tool',
            'action':'execute','resource':'public'},headers=h).json()['data']
        assert result['decision']=='DENY'
        assert result['risk_type']=='UNKNOWN_TOOL_OR_ACTION'
        assert c.post(f"/gateway/v1/actions/{result['action_id']}/commit",json={},headers=h).status_code==403


def test_strict_blocks_demo_auth_and_unprotected_admin_surface(monkeypatch):
    monkeypatch.setenv('AGENTGUARD_SECURITY_PROFILE','strict')
    monkeypatch.setenv('AGENTGUARD_GATEWAY_TOKEN','gateway-secret')
    monkeypatch.setenv('AGENTGUARD_APPROVER_TOKEN','approver-secret')
    with TestClient(app) as c:
        assert c.post('/api/v1/auth/login',json={'username':'admin'}).status_code==403
        assert c.post('/api/v1/mcp/servers',json={'id':'forged'}).status_code==403
        assert c.post('/gateway/v1/sessions',json={'session_id':'forged'}).status_code==403
        assert c.get('/api/v1/audit/events').status_code==403
        assert c.get('/api/v1/health').status_code==200
        with pytest.raises(WebSocketDisconnect):
            with c.websocket_connect('/ws/v1/runtime'):
                pass
        with c.websocket_connect('/ws/v1/runtime',headers={'x-agentguard-token':'approver-secret'}) as ws:
            assert ws.receive_json()['type']=='connected'
