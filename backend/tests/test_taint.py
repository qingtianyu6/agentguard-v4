from app.services.runtime_guard import evaluate_action
from services.trajectory_guard.taint import TaintState

def test_source_sensitive_summary_without_keyword_is_guarded():
    hist=[{'state':'completed', 'result_ref':'opaque_a', 'taint_labels':['SENSITIVE'], 'provenance_refs':[]},
          {'state':'completed', 'result_ref':'plain_summary', 'taint_labels':[], 'provenance_refs':['opaque_a']}]
    payload={'tool_id':'mcp.email.send','action':'send','resource':'weekly digest','destination':'external',
             'args':{'body':'Weekly trends'},'provenance_refs':['plain_summary']}
    assert evaluate_action(payload,[],hist)['risk_type']=='TAINTED_DATA_FLOW'
    assert evaluate_action(payload,[],hist,mode='single_step')['decision']=='ALLOW'
    state=TaintState()
    for item in hist:state.record(item)
    assert 'opaque_a' in state.lineage('plain_summary')
