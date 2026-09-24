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


def test_saved_experiment_config_is_immutable_run_input():
    with TestClient(app) as client:
        created = client.post('/api/v1/experiments/configs', json={
            'name': 'Compiler test', 'kind': 'compiler-ablation', 'split': 'test', 'frozen': False,
        })
        assert created.status_code == 200
        config = created.json()['data']
        assert config['frozen'] is True
        assert config in client.get('/api/v1/experiments/configs').json()['data']
        assert client.post('/api/v1/experiments/runs', json={
            'config_id': config['id'], 'kind': 'runtime-ablation',
        }).status_code == 409
        run = client.post('/api/v1/experiments/runs', json={'config_id': config['id']})
        assert run.status_code == 200
        result = run.json()['data']
        assert result['config']['config_id'] == config['id']
        assert result['config']['kind'] == 'compiler-ablation'
        stored = client.get(f"/api/v1/experiments/runs/{result['run_id']}/results").json()['data']
        assert 'compiler' in stored and 'runtime' not in stored
        figure = client.post(f"/api/v1/experiments/{result['run_id']}/figures").json()['data']['figures'][0]
        assert figure['format'] == 'svg'
        assert 'Semantic Accuracy' in figure['svg']
        assert 'direct_dsl' in figure['svg']
        assert client.post('/api/v1/experiments/missing/figures').status_code == 404
        assert client.post('/api/v1/experiments/runs', json={'config_id': 'missing'}).status_code == 404
