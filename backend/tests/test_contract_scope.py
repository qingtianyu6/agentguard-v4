import json
import uuid

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import Contract, Policy


def add_contract(effect, conditions=None):
    suffix = uuid.uuid4().hex[:12]
    policy_id, contract_id = f'pol_scope_{suffix}', f'ctr_scope_{suffix}'
    structured = {
        'action': 'send', 'resource': 'AnyResource', 'destination': 'AnyDestination',
        'effect': effect, 'conditions': conditions or [], 'temporal_constraints': [],
    }
    with SessionLocal() as db:
        db.add(Policy(id=policy_id, name='Scope fixture', natural_text='fixture', status='draft'))
        db.add(Contract(id=contract_id, policy_id=policy_id, dsl='RULE fixture {}',
                        structured_json=json.dumps(structured), graph_json='{}', verified=True))
        db.commit()
    return contract_id


def test_contract_evaluation_is_bound_to_requested_contract():
    with TestClient(app) as client:
        denied = add_contract('DENY')
        allowed = add_contract('ALLOW')
        payload = {'action': 'send', 'resource': 'public_note', 'destination': 'internal'}
        deny_result = client.post(f'/api/v1/contracts/{denied}/evaluate', json=payload).json()['data']
        allow_result = client.post(f'/api/v1/contracts/{allowed}/evaluate', json=payload).json()['data']
        assert deny_result['decision'] == 'DENY'
        assert deny_result['contract_id'] == denied
        assert allow_result['decision'] == 'ALLOW'
        assert allow_result['contract_id'] == allowed
        assert client.post('/api/v1/contracts/missing/evaluate', json=payload).status_code == 404
        assert client.get('/api/v1/contracts/missing/logic').status_code == 404
        assert client.post(f'/api/v1/contracts/{denied}/evaluate', json={**payload, 'history': {}}).status_code == 422


def test_generated_contract_cases_are_executed_not_auto_passed():
    with TestClient(app) as client:
        contract_id = add_contract('DENY', [{'field': 'amount', 'op': '>=', 'value': 100}])
        result = client.post(f'/api/v1/contracts/{contract_id}/test-cases').json()['data']
        assert result['scope'] == 'generated_synthetic_cases_only'
        assert result['passed'] + result['failed'] == len(result['cases'])
        assert result['failed'] >= 1
        assert all('actual' in case and 'passed' in case for case in result['cases'])
        assert client.post('/api/v1/contracts/missing/test-cases').status_code == 404


def test_compilation_job_resolves_its_own_contract():
    with TestClient(app) as client:
        policy = client.post('/api/v1/policies', json={
            'name': 'Compilation history', 'natural_text': '未经主管授权，不得向外部发送客户联系方式。',
        }).json()['data']
        pid = policy['id']
        first = client.post(f'/api/v1/policies/{pid}/compile', json={})
        second = client.post(f'/api/v1/policies/{pid}/compile', json={})
        assert first.status_code == second.status_code == 200
        first_data, second_data = first.json()['data'], second.json()['data']
        assert first_data['contract_id'] != second_data['contract_id']
        resolved = client.get(f"/api/v1/policies/{pid}/compilations/{first_data['job_id']}")
        assert resolved.json()['data']['contract']['id'] == first_data['contract_id']
        assert client.get(f'/api/v1/policies/{pid}/compilations/missing').status_code == 404
        assert client.get(f"/api/v1/policies/other/compilations/{first_data['job_id']}").status_code == 404
