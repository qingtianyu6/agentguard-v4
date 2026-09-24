import os
import pytest
from services.contract_engine.formal.backends.cedar_cli import evaluate, UnsupportedContract

@pytest.mark.skipif(not os.environ.get('AGENTGUARD_CEDAR_CLI'), reason='provide a verified Cedar binary path')
def test_cedar_validates_and_authorizes_approval_gate():
    contract={'action':'send','resource':'SensitiveData','effect':'DENY_UNLESS','exception':'manager_approval'}
    assert evaluate(contract,approved=False)['decision']=='DENY'
    assert evaluate(contract,approved=True)['decision']=='ALLOW'

def test_cedar_does_not_silently_accept_unsupported_temporal_semantics():
    with pytest.raises(UnsupportedContract):
        evaluate({'action':'refund','resource':'Order','effect':'REQUIRE','temporal_constraints':['identity_verified']},approved=False,binary=__file__)
