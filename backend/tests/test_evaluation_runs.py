from fastapi.testclient import TestClient

from app.main import app


def test_benchmark_run_is_persisted_and_queryable():
    with TestClient(app) as client:
        response = client.post('/api/v1/benchmarks/bench_v30/runs', json={'mode': 'no_guard', 'split': 'test'})
        assert response.status_code == 200
        run = response.json()['data']
        run_id = run['run_id']
        assert run['config']['mode'] == 'no_guard'
        assert run['artifact_path']
        status = client.get(f'/api/v1/benchmarks/runs/{run_id}').json()['data']
        assert status['config']['split'] == 'test'
        metrics = client.get(f'/api/v1/benchmarks/runs/{run_id}/metrics').json()['data']
        assert metrics['run_id'] == run_id
        assert client.get(f'/api/v1/benchmarks/runs/{run_id}/failures').status_code == 200
        assert client.get('/api/v1/benchmarks/runs/missing/metrics').status_code == 404


def test_benchmark_run_rejects_unknown_inputs():
    with TestClient(app) as client:
        assert client.post('/api/v1/benchmarks/missing/runs', json={}).status_code == 404
        assert client.post('/api/v1/benchmarks/bench_v30/runs', json={'mode': 'invented'}).status_code == 422
