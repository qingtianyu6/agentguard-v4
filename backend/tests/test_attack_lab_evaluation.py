from fastapi.testclient import TestClient

from app.main import app


def test_attack_compare_uses_guard_without_invoking_tool():
    with TestClient(app) as client:
        for scenario, decision in [('attack_env', 'DENY'), ('attack_refund', 'REPAIR'), ('attack_injection', 'DENY')]:
            response = client.post('/api/v1/attack-lab/compare', json={'scenario_id': scenario})
            assert response.status_code == 200
            result = response.json()['data']
            assert result['simulation'] is True
            assert result['tool_invoked'] is False
            assert result['off']['decision'] == 'ALLOW'
            assert result['on']['decision'] == decision
            assert result['off']['would_allow'] is True
            assert result['on']['would_allow'] is False
            assert result['on']['attack_success_observed'] is None
            assert result['on']['source_case_id'].startswith('AGB3-')
            assert result['on']['latency_ms'] >= 0
            assert result['off']['latency_ms'] >= 0
        assert client.post('/api/v1/attack-lab/compare', json={'scenario_id': 'unknown'}).status_code == 404


def test_attack_run_persists_measured_candidate_decision():
    with TestClient(app) as client:
        response = client.post('/api/v1/attack-lab/runs', json={'scenario_id': 'attack_refund', 'guard_enabled': True})
        assert response.status_code == 200
        result = response.json()['data']
        assert result['decision'] == 'REPAIR'
        assert result['tool_invoked'] is False
        stored = client.get(f"/api/v1/attack-lab/runs/{result['run_id']}").json()['data']
        assert stored['decision'] == result['decision']
        assert stored['latency_ms'] == result['latency_ms']
        assert client.get('/api/v1/attack-lab/runs/missing').status_code == 404
