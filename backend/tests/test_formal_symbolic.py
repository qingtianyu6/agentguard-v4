from app.services.formal_verifier import verify_formal

def test_real_solver_returns_witness_for_missing_approval():
    structured = {'source_text':'approval required','action':'send','resource':'SensitiveData',
                  'destination':'ExternalService','effect':'DENY_UNLESS',
                  'conditions':[{'field':'manager_approval','op':'==','value':True}], 'temporal_constraints':[]}
    out = verify_formal(structured)
    assert out['solver']['status'] == 'sat'
    assert out['solver']['unsafe_witness']['manager_approval'] is False
    assert 'bounded' in out['verification_scope']
