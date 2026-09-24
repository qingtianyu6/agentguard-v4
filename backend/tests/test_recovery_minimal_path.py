from fastapi.testclient import TestClient
from app.main import app


def test_recovery_only_executes_missing_refund_prerequisite():
    with TestClient(app) as client:
        session=client.post('/gateway/v1/sessions',json={'agent_id':'ops'}).json()['data']
        trace_id=session['trace_id']
        identity=client.post('/gateway/v1/mcp/call',json={'trace_id':trace_id,'agent_id':'ops',
            'tool_id':'mcp.order.identity','action':'identity_verified','resource':'order:ORD-1042',
            'destination':'internal','args':{'user_id':'USR-DEMO','order_id':'ORD-1042'}}).json()['data']
        assert identity['executed'] is True
        pre=client.post('/gateway/v1/actions/preflight',json={'trace_id':trace_id,'agent_id':'ops',
            'tool_id':'mcp.order.refund','action':'refund','resource':'order:ORD-1042',
            'destination':'internal','args':{'order_id':'ORD-1042','amount':7}}).json()['data']
        assert pre['decision']=='REPAIR'
        recovery=client.get('/api/v1/recovery/'+pre['recovery_id']).json()['data']
        assert [step['action'] for step in recovery['safe_plan']]==['order_confirmed','refund']

        result=client.post('/api/v1/recovery/'+pre['recovery_id']+'/execute',json={}).json()['data']
        assert result['status']=='ready_to_retry'
        assert result['original_executed'] is False
        assert [step['step']['action'] for step in result['executed_steps']]==['order_confirmed']
        assert result['recheck']['decision']=='ALLOW'
        assert client.post('/api/v1/recovery/'+pre['recovery_id']+'/execute',json={}).status_code==409
        events=client.get(f'/api/v1/trajectories/{trace_id}/events').json()['data']
        assert not any(event['action']=='refund' and event['state']=='completed' for event in events)
        order=next(event for event in events if event['action']=='order_confirmed')
        assert order['state']=='completed'
        decisions=client.get('/api/v1/decisions').json()['data']
        assert any(decision['action_id']==order['action_id'] and decision['decision']=='ALLOW'
                   for decision in decisions)
        lineage=client.get(f'/api/v1/trajectories/{trace_id}/information-flow').json()['data']
        assert lineage is not None
        retried=client.post('/gateway/v1/mcp/call',json={'trace_id':trace_id,'agent_id':'ops',
            'tool_id':'mcp.order.refund','action':'refund','resource':'order:ORD-1042',
            'destination':'internal','args':{'order_id':'ORD-1042','amount':7}}).json()['data']
        assert retried['decision']=='ALLOW'
        assert retried['executed'] is True
        assert retried['tool_result']['ok'] is True
