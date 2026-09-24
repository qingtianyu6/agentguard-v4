from app.services.runtime_guard import evaluate_action
from services.recovery_engine.planner import plan_recovery

def test_refund_candidate_is_search_result_but_not_execution():
    action={'tool_id':'mcp.order.refund','action':'refund','agent_id':'agent_support','resource':'order:1042','destination':'internal','args':{'order_id':'1042'}}
    out=plan_recovery(action,[],[],evaluate_action)
    assert set(out['steps']) == {'verify_identity','verify_order'}
    assert out['action_distance']==2
    assert out['execution_verified'] is False

def test_unsafe_unrecoverable_action_is_not_automatically_approved():
    action={'tool_id':'mcp.files.read','action':'read','resource':'.env','args':{}}
    out=plan_recovery(action,[],[],evaluate_action)
    assert out['status']=='no_safe_candidate'
