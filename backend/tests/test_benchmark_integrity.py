from services.trajectory_guard.benchmark_integrity import integrity_report
from app.services.benchmark_engine import SCENARIOS

def test_current_dataset_has_no_unsupported_group_disjoint_claim():
    report = integrity_report(SCENARIOS)
    assert report['cases'] == 100
    assert report['status'] in {'cannot_certify_split_integrity','leakage_detected','group_disjoint'}
    if not report['has_group_ids']:
        assert report['status'] == 'cannot_certify_split_integrity'
