import hashlib
import hmac
import json
import time
import uuid
from fastapi.testclient import TestClient
from app.main import app


def signed(body):
    timestamp = str(int(time.time()))
    raw = json.dumps(body).encode()
    signature = hmac.new(b'webhook-secret', timestamp.encode() + b'.' + raw, hashlib.sha256).hexdigest()
    return {'x-toolhive-timestamp': timestamp, 'x-toolhive-signature': 'sha256=' + signature}


def post_signed(client, body):
    return client.post('/gateway/v1/toolhive/validate', content=json.dumps(body).encode(), headers=signed(body))


def test_toolhive_webhook_auth_shape_and_fail_closed(monkeypatch):
    monkeypatch.setattr('app.main.active_contracts', lambda db: [])
    monkeypatch.setenv('AGENTGUARD_SECURITY_PROFILE', 'strict')
    monkeypatch.setenv('AGENTGUARD_TOOLHIVE_WEBHOOK_SECRET', 'webhook-secret')
    monkeypatch.setenv('AGENTGUARD_TOOLHIVE_ALLOWED_TOOLS', 'files/read_file')
    body = {'version': 'v0.1.0', 'uid': 'request-1', 'principal': {'sub': 'agent-1'},
            'context': {'server_name': 'files', 'transport': 'stdio', 'source_ip': '127.0.0.1'},
            'mcp_request': {'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                            'params': {'name': 'read_file', 'arguments': {'path': 'public.txt'}}}}
    with TestClient(app) as client:
        assert client.post('/gateway/v1/toolhive/validate', json=body).status_code == 403
        missing_policy = post_signed(client, body)
        assert missing_policy.status_code == 200
        assert missing_policy.json()['uid'] == 'request-1'
        assert missing_policy.json()['allowed'] is False
        for bad in ({**body, 'principal': None},
                    {**body, 'mcp_request': {**body['mcp_request'], 'method': 'resources/read'}},
                    {**body, 'context': {'server_name': 'unknown'}}):
            assert post_signed(client, bad).json()['allowed'] is False


def test_toolhive_webhook_only_allows_explicitly_named_tool_with_policy(monkeypatch):
    monkeypatch.setenv('AGENTGUARD_TOOLHIVE_WEBHOOK_SECRET', 'webhook-secret')
    monkeypatch.setenv('AGENTGUARD_TOOLHIVE_ALLOWED_TOOLS', 'files/read_file')
    monkeypatch.setattr('app.main.active_contracts', lambda db: [{'policy_id': 'p', 'structured': {'action': 'file_read', 'resource': 'AnyResource', 'destination': 'AnyDestination', 'effect': 'ALLOW'}}])
    body = {'version': 'v0.1.0', 'uid': 'request-2', 'principal': {'sub': 'agent-1'},
            'context': {'server_name': 'files'},
            'mcp_request': {'jsonrpc': '2.0', 'method': 'tools/call',
                            'params': {'name': 'read_file', 'arguments': {'path': 'public.txt'}}}}
    with TestClient(app) as client:
        assert post_signed(client, body).json()['allowed'] is True
        from app import main
        monkeypatch.setattr(main, 'active_contracts', lambda db: [{'policy_id': 'other', 'structured': {'action': 'refund', 'resource': 'Order', 'destination': 'AnyDestination', 'effect': 'ALLOW'}}])
        assert post_signed(client, body).json()['allowed'] is False
        monkeypatch.setattr(main, 'active_contracts', lambda db: [{'policy_id': 'p', 'structured': {'action': 'file_read', 'resource': 'AnyResource', 'destination': 'AnyDestination', 'effect': 'ALLOW'}}])
        body['mcp_request']['params']['arguments']['path'] = '.env'
        assert post_signed(client, body).json()['allowed'] is False
        body['mcp_request']['params']['name'] = 'delete_file'
        assert post_signed(client, body).json()['allowed'] is False


def test_toolhive_resource_read_requires_allowlist_and_matching_contract(monkeypatch):
    monkeypatch.setenv('AGENTGUARD_TOOLHIVE_WEBHOOK_SECRET', 'webhook-secret')
    monkeypatch.setenv('AGENTGUARD_TOOLHIVE_ALLOWED_TOOLS', 'files/resources/read')
    monkeypatch.setattr('app.main.active_contracts', lambda db: [{'policy_id':'p','structured':{
        'action':'read','resource':'AnyResource','destination':'AnyDestination','effect':'ALLOW'}}])
    body={'version':'v0.1.0','uid':'resource-1','principal':{'sub':'reader'},
          'context':{'server_name':'files'},'mcp_request':{'jsonrpc':'2.0',
          'method':'resources/read','params':{'uri':'file:///public.txt'}}}
    with TestClient(app) as client:
        assert post_signed(client,body).json()['allowed'] is True
        body['mcp_request']['params']['uri']='file:///.env'
        assert post_signed(client,body).json()['allowed'] is False


def test_toolhive_tool_arguments_cannot_claim_admin_or_approval(monkeypatch):
    monkeypatch.setenv('AGENTGUARD_TOOLHIVE_WEBHOOK_SECRET', 'webhook-secret')
    monkeypatch.setenv('AGENTGUARD_TOOLHIVE_ALLOWED_TOOLS', 'roles/grant_role')
    monkeypatch.setattr('app.main.active_contracts', lambda db: [{'policy_id':'p','structured':{
        'action':'grant_role','resource':'AnyResource','destination':'AnyDestination','effect':'ALLOW'}}])
    body={'version':'v0.1.0','uid':'privileged-1','principal':{'sub':'agent-1'},
          'context':{'server_name':'roles'},'mcp_request':{'jsonrpc':'2.0','method':'tools/call',
          'params':{'name':'grant_role','arguments':{'role':'admin','manager_approval':True}}}}
    with TestClient(app) as client:
        assert post_signed(client,body).json()['allowed'] is False


def test_strict_toolhive_webhook_blocks_replayed_signed_request(monkeypatch):
    monkeypatch.setenv('AGENTGUARD_SECURITY_PROFILE', 'strict')
    monkeypatch.setenv('AGENTGUARD_TOOLHIVE_WEBHOOK_SECRET', 'webhook-secret')
    monkeypatch.setenv('AGENTGUARD_TOOLHIVE_ALLOWED_TOOLS', 'files/read_file')
    monkeypatch.setattr('app.main.active_contracts', lambda db: [{'policy_id':'p','structured':{
        'action':'file_read','resource':'AnyResource','destination':'AnyDestination','effect':'ALLOW'}}])
    body={'version':'v0.1.0','uid':str(uuid.uuid4()),'principal':{'sub':'agent-1'},
          'context':{'server_name':'files'},'mcp_request':{'jsonrpc':'2.0','method':'tools/call',
          'params':{'name':'read_file','arguments':{'path':'public.txt'}}}}
    with TestClient(app) as client:
        assert post_signed(client,body).json()['allowed'] is True
        replay=post_signed(client,body).json()
        assert replay['allowed'] is False
        assert replay['reason']=='REPLAYED_REQUEST'
