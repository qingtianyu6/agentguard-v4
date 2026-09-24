from fastapi.testclient import TestClient
from app.main import app


def get_client():
    return TestClient(app)


def test_p2cv_produces_graph_counterexamples_and_verification():
    client=get_client()
    with client:
        p=client.post('/api/v1/policies',json={'name':'Threshold V2','natural_text':'金额 >= 2000 的操作需要主管审批。'}).json()['data']
        out=client.post(f"/api/v1/policies/{p['id']}/compile",json={}).json()['data']
        assert out['graph']['stats']['nodes'] >= 5
        assert len(out['counterexamples']) >= 2
        assert out['verification']['syntax_validity'] == 1.0
        assert 'EFFECT' in out['dsl']


def test_real_mcp_sandbox_executes_safe_file_and_blocks_env():
    client=get_client()
    with client:
        s=client.post('/gateway/v1/sessions',json={'agent_id':'agent_ops'}).json()['data']
        safe=client.post('/gateway/v1/mcp/call',json={
            'session_id':s['session_id'],'trace_id':s['trace_id'],'agent_id':'agent_ops',
            'tool_call':{'tool_id':'mcp.files.read','action':'read','args':{}},
            'resource_refs':['readme.txt'],'declared_destination':'internal'
        }).json()['data']
        assert safe['decision']=='ALLOW'
        assert safe['executed'] is True
        assert 'AgentGuard controlled sandbox' in safe['tool_result']['content']

        s2=client.post('/gateway/v1/sessions',json={'agent_id':'agent_ops'}).json()['data']
        denied=client.post('/gateway/v1/mcp/call',json={
            'session_id':s2['session_id'],'trace_id':s2['trace_id'],'agent_id':'agent_ops',
            'tool_call':{'tool_id':'mcp.files.read','action':'read','args':{}},
            'resource_refs':['.env'],'declared_destination':'internal'
        }).json()['data']
        assert denied['decision']=='DENY'
        assert denied.get('executed') is None


def test_ask_cannot_commit_before_approval_but_can_after_approval():
    client=get_client()
    with client:
        s=client.post('/gateway/v1/sessions',json={'agent_id':'agent_finance'}).json()['data']
        pre=client.post('/gateway/v1/actions/preflight',json={
            'session_id':s['session_id'],'trace_id':s['trace_id'],'agent_id':'agent_finance',
            'tool_call':{'tool_id':'mcp.email.send','action':'send','args':{'to':'external@example.com'}},
            'resource_refs':['customer_contact'],'declared_destination':'external'
        }).json()['data']
        assert pre['decision']=='ASK'
        assert client.post(f"/gateway/v1/actions/{pre['action_id']}/commit",json={}).status_code == 403
        approval_id=pre['approval']['approval_id']
        assert client.post(f'/api/v1/approvals/{approval_id}/approve',json={'comment':'test approval'}).status_code == 200
        assert client.post(f"/gateway/v1/actions/{pre['action_id']}/commit",json={}).status_code == 200


def test_refund_recovery_adds_prerequisites_and_rechecks_allow():
    client=get_client()
    with client:
        s=client.post('/gateway/v1/sessions',json={'agent_id':'agent_support'}).json()['data']
        pre=client.post('/gateway/v1/actions/preflight',json={
            'session_id':s['session_id'],'trace_id':s['trace_id'],'agent_id':'agent_support',
            'tool_call':{'tool_id':'mcp.order.refund','action':'refund','args':{'order_id':'ORD-1042','amount':980}},
            'resource_refs':['order:ORD-1042'],'declared_destination':'internal'
        }).json()['data']
        assert pre['decision']=='REPAIR'
        rec=client.post(f"/api/v1/recovery/{pre['recovery_id']}/execute",json={}).json()['data']
        assert len(rec['executed_steps']) >= 2
        assert rec['recheck']['decision']=='ALLOW'


def test_benchmark_shows_trajectory_value():
    client=get_client()
    with client:
        no_guard=client.post('/api/v1/benchmarks/bench_v20/evaluate',json={'mode':'no_guard'}).json()['data']['metrics']
        single=client.post('/api/v1/benchmarks/bench_v20/evaluate',json={'mode':'single_step'}).json()['data']['metrics']
        full=client.post('/api/v1/benchmarks/bench_v20/evaluate',json={'mode':'trajectory_full'}).json()['data']['metrics']
        assert full['attack_success_rate'] < no_guard['attack_success_rate']
        assert full['policy_fidelity'] >= single['policy_fidelity']
