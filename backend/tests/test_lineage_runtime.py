from fastapi.testclient import TestClient
from app.main import app

def test_structured_lineage_from_completed_events_drives_preflight():
    with TestClient(app) as c:
        sess=c.post('/gateway/v1/sessions',json={'agent_id':'finance'}).json()['data']
        base={'trace_id':sess['trace_id'],'subject_id':'finance','tool_id':'mcp.files.read',
              'action':'read','resource_refs':['opaque'], 'phase':'completed'}
        source=c.post('/gateway/v1/lineage',json={**base,'result_digest':'secret_blob',
              'taint_labels':['SENSITIVE']})
        assert source.status_code==200
        summary=c.post('/gateway/v1/lineage',json={**base,'result_digest':'summary_without_keywords',
              'taint_labels':[],'provenance_refs':['secret_blob']})
        assert summary.status_code==200
        pre=c.post('/gateway/v1/actions/preflight',json={'trace_id':sess['trace_id'],
              'tool_id':'mcp.email.send','action':'send','resource':'weekly trends',
              'destination':'external','args':{'body':'overview'},
              'provenance_refs':['summary_without_keywords']}).json()['data']
        assert pre['risk_type']=='TAINTED_DATA_FLOW'
        assert pre['decision']=='ASK'
