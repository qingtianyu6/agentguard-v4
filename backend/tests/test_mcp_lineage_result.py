from fastapi.testclient import TestClient
from app.main import app

def test_successful_real_sandbox_read_records_lineage():
    with TestClient(app) as c:
        session=c.post('/gateway/v1/sessions',json={'agent_id':'ops'}).json()['data']
        res=c.post('/gateway/v1/mcp/call',json={'trace_id':session['trace_id'],
            'tool_id':'mcp.files.read','action':'read','resource':'customer_contacts.csv',
            'destination':'internal','args':{}}).json()['data']
        assert res['executed'] is True
        assert len(res['result_ref'])==64
        pre=c.post('/gateway/v1/actions/preflight',json={'trace_id':session['trace_id'],
            'tool_id':'mcp.email.send','action':'send','destination':'external',
            'resource':'ordinary summary','args':{'body':'Weekly count'},
            'provenance_refs':[res['result_ref']]}).json()['data']
        assert pre['risk_type']=='TAINTED_DATA_FLOW'


def test_preflight_rejects_unknown_and_cross_trace_lineage_refs():
    with TestClient(app) as c:
        first=c.post('/gateway/v1/sessions',json={'agent_id':'ops'}).json()['data']
        second=c.post('/gateway/v1/sessions',json={'agent_id':'ops'}).json()['data']
        read=c.post('/gateway/v1/mcp/call',json={'trace_id':first['trace_id'],
            'tool_id':'mcp.files.read','action':'read','resource':'customer_contacts.csv',
            'destination':'internal','args':{}}).json()['data']
        assert read['executed'] is True
        for ref in ('nonexistent-result',read['result_ref']):
            pre=c.post('/gateway/v1/actions/preflight',json={'trace_id':second['trace_id'],
                'tool_id':'mcp.email.send','action':'send','destination':'external',
                'resource':'ordinary summary','args':{'body':'Weekly count'},
                'provenance_refs':[ref]}).json()['data']
            assert pre['decision']=='DENY'
            assert pre['risk_type']=='UNKNOWN_PROVENANCE_REF'


def test_committed_result_enters_runtime_lineage_once():
    with TestClient(app) as c:
        session=c.post('/gateway/v1/sessions',json={'agent_id':'ops'}).json()['data']
        trace_id=session['trace_id']
        pre=c.post('/gateway/v1/actions/preflight',json={'trace_id':trace_id,
            'tool_id':'mcp.files.read','action':'read','resource':'customer_contacts.csv',
            'destination':'internal','args':{}}).json()['data']
        assert pre['decision']=='ALLOW'
        action_id=pre['action_id']
        assert c.post(f'/gateway/v1/actions/{action_id}/commit',json={}).status_code==200
        completed=c.post(f'/gateway/v1/actions/{action_id}/result',json={
            'result':{'ok':True,'content':'name,phone,email'}}).json()['data']
        assert len(completed['result_ref'])==64
        lineage=c.get(f'/api/v1/trajectories/{trace_id}/information-flow').json()['data']
        assert lineage is not None
        pre_send=c.post('/gateway/v1/actions/preflight',json={'trace_id':trace_id,
            'tool_id':'mcp.email.send','action':'send','destination':'external',
            'resource':'ordinary summary','args':{'body':'Weekly count'},
            'provenance_refs':[completed['result_ref']]}).json()['data']
        assert pre_send['risk_type']=='TAINTED_DATA_FLOW'
        assert c.post(f'/gateway/v1/actions/{action_id}/result',json={'result':{'ok':True}}).status_code==409
