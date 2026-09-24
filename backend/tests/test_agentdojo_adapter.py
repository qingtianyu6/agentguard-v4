from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from benchmark.external.agentdojo.adapter import AgentGuardToolsExecutor


def test_agentdojo_real_executor_blocks_before_tool_and_allows_safe_tool():
    effects = []
    def record(value: str) -> str:
        """Store a text value in the controlled test runtime.

        :param value: Text to store.
        """
        effects.append(value)
        return value

    runtime=FunctionsRuntime()
    runtime.register_function(record)
    allowed=False
    def decide(request):
        return {'decision': 'ALLOW' if allowed else 'DENY'}
    executor=AgentGuardToolsExecutor(decide, ['record'])
    message={'role':'assistant','content':None,'tool_calls':[FunctionCall(function='record',args={'value':'safe'},id='call-1')]}
    _, returned, _, output, _=executor.query('save',runtime,messages=[message],extra_args={'agentguard_trace_id':'external-1'})
    assert returned is runtime
    assert not effects
    assert output[-1]['error'].startswith('AgentGuardDenied')
    assert executor.events[-1]['decision']=='DENY'
    allowed=True
    _, _, _, output, _=executor.query('save',runtime,messages=[message],extra_args={'agentguard_trace_id':'external-1'})
    assert effects==['safe']
    assert output[-1]['error'] is None
    assert executor.events[-1]['result']=='completed'
    nested={'role':'assistant','content':None,'tool_calls':[FunctionCall(function='record',
        args={'value':FunctionCall(function='record',args={'value':'hidden'},id='nested')},id='outer')]}
    _, _, _, output, _=executor.query('save',runtime,messages=[nested])
    assert effects==['safe']
    assert output[-1]['error'].startswith('AgentGuardDenied')
