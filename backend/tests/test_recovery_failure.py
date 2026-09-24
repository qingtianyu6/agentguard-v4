from fastapi.testclient import TestClient
from app import main
from app.main import app


def test_sandbox_recovery_failed_prerequisite_cannot_become_trusted_history(monkeypatch):
    with TestClient(app) as client:
        pre=client.post('/gateway/v1/actions/preflight',json={
            'tool_id':'mcp.order.refund','action':'refund','args':{'order_id':'ORD-1042','amount':7},
            'resource':'order:ORD-1042','destination':'internal'}).json()['data']
        assert pre['decision']=='REPAIR'
        original=main.execute_tool
        def failing(tool_id, action, args, resource='', destination=''):
            if action=='identity_verified': return {'ok':False,'error':'TEST_FAILURE'}
            return original(tool_id, action, args, resource, destination)
        monkeypatch.setattr(main,'execute_tool',failing)
        rec=client.post(f"/api/v1/recovery/{pre['recovery_id']}/execute",json={}).json()['data']
        assert rec['status']=='failed'
        assert rec['executed_steps'][0]['result']['ok'] is False
        assert len(rec['executed_steps'])==1
        assert rec['recheck']['decision']=='DENY'
        trace=pre['trace_id']
        events=client.get(f'/api/v1/trajectories/{trace}/events').json()['data']
        assert not any(e.get('action')=='identity_verified' and e.get('state')=='completed' for e in events)
