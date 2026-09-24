from services.recovery_engine.workflow import build_workflow

def test_workflow_does_not_execute_refund_from_simulated_prerequisites():
    state=build_workflow().invoke({'original_action':{'action':'refund','tool_id':'mcp.order.refund',
      'agent_id':'agent_support','resource':'order:1042', 'args':{'order_id':'1042'}}, 'contracts':[], 'history':[]})
    assert state['candidate']['status']=='candidate_only'
    assert state['validation']['safe'] is False
