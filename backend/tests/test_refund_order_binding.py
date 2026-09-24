from fastapi.testclient import TestClient
from app.main import app


def test_completed_verifications_for_other_order_cannot_authorize_refund():
    with TestClient(app) as client:
        trace=client.post('/gateway/v1/sessions',json={'agent_id':'agent_support'}).json()['data']['trace_id']
        for tool_id, action in [('mcp.order.identity','identity_verified'),
                                ('mcp.order.verify','order_confirmed')]:
            result=client.post('/gateway/v1/mcp/call',json={'trace_id':trace,
                'agent_id':'agent_support','tool_id':tool_id,'action':action,
                'resource':'order:ORD-A','destination':'internal',
                'args':{'order_id':'ORD-A'}}).json()['data']
            assert result['executed'] is True
        other=client.post('/gateway/v1/actions/preflight',json={'trace_id':trace,
            'agent_id':'agent_support','tool_id':'mcp.order.refund','action':'refund',
            'resource':'order:ORD-B','destination':'internal',
            'args':{'order_id':'ORD-B','amount':7}}).json()['data']
        assert other['decision']=='REPAIR'
        assert other['risk_type']=='TEMPORAL_VIOLATION'
        different_agent=client.post('/gateway/v1/actions/preflight',json={'trace_id':trace,
            'agent_id':'agent_other','tool_id':'mcp.order.refund','action':'refund',
            'resource':'order:ORD-A','destination':'internal',
            'args':{'order_id':'ORD-A','amount':7}}).json()['data']
        assert different_agent['decision']=='REPAIR'
        missing_order=client.post('/gateway/v1/actions/preflight',json={'trace_id':trace,
            'agent_id':'agent_support','tool_id':'mcp.order.refund','action':'refund',
            'resource':'order:ORD-A','destination':'internal',
            'args':{'amount':7}}).json()['data']
        assert missing_order['decision']=='DENY'
        assert missing_order['risk_type']=='INVALID_REFUND_CONTEXT'
        same=client.post('/gateway/v1/actions/preflight',json={'trace_id':trace,
            'agent_id':'agent_support','tool_id':'mcp.order.refund','action':'refund',
            'resource':'order:ORD-A','destination':'internal',
            'args':{'order_id':'ORD-A','amount':7}}).json()['data']
        assert same['decision']=='ALLOW'
