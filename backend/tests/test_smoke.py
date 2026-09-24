from fastapi.testclient import TestClient
from app.main import app
client=TestClient(app)

def test_health():
    assert client.get('/api/v1/health').status_code==200

def test_policy_compile():
    p=client.post('/api/v1/policies',json={'name':'Test','natural_text':'未经主管授权不得向外部发送客户联系方式'}).json()['data']
    r=client.post(f"/api/v1/policies/{p['id']}/compile",json={})
    assert r.status_code==200
    assert 'dsl' in r.json()['data']

def test_gateway_blocks_env():
    s=client.post('/gateway/v1/sessions',json={'agent_id':'agent_ops'}).json()['data']
    r=client.post('/gateway/v1/actions/preflight',json={'session_id':s['session_id'],'agent_id':'agent_ops','tool_call':{'tool_id':'mcp.files.read','action':'read','args':{}},'resource_refs':['.env']}).json()['data']
    assert r['decision']=='DENY'
