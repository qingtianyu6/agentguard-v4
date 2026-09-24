from services.trajectory_guard.graph_store import LineageGraph

def test_graph_inherits_labels_through_opaque_summary():
    g=LineageGraph()
    g.ingest({'state':'completed','result_ref':'a','taint_labels':['SENSITIVE']})
    g.ingest({'state':'completed','result_ref':'b','provenance_refs':['a']})
    assert g.ancestry('b')=={'a'}
    assert 'SENSITIVE' in g.labels('b')
    g.ingest({'state':'failed','result_ref':'c','provenance_refs':['b']})
    assert not g.labels('c')
