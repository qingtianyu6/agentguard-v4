from fastapi.testclient import TestClient

from app.main import app


def test_experiment_draft_run_and_result_snapshot():
    with TestClient(app) as client:
        draft = client.post('/api/v1/experiments', json={'kind': 'runtime-ablation', 'metrics': {'fake': 1}})
        assert draft.status_code == 200
        experiment = draft.json()['data']
        assert experiment['status'] == 'draft'
        assert client.get(f"/api/v1/experiments/{experiment['id']}/results").status_code == 409
        completed = client.post(f"/api/v1/experiments/{experiment['id']}/run", json={'split': 'test'})
        assert completed.status_code == 200
        run_id = completed.json()['data']['run_id']
        result = client.get(f"/api/v1/experiments/{experiment['id']}/results").json()['data']
        assert result['run_id'] == run_id
        assert 'runtime' in result['metrics']
        assert 'compiler' not in result['metrics']
        assert client.get(f'/api/v1/experiments/runs/{run_id}/results').json()['data']['runtime'] == result['metrics']['runtime']


def test_experiment_routes_and_unknown_run():
    with TestClient(app) as client:
        compare = client.get('/api/v1/experiments/compare')
        assert compare.status_code == 200
        assert len(compare.json()['data']['series']) == 3
        assert client.get('/api/v1/experiments/configs').json()['data']
        assert client.get('/api/v1/experiments/runs/missing').status_code == 404
        assert client.get('/api/v1/experiments/runs/missing/results').status_code == 404
        assert client.post('/api/v1/experiments/runs', json={'kind': 'unknown'}).status_code == 422
