from fastapi.testclient import TestClient
from app.main import app

def test_strict_policy_activation_needs_review_and_is_revoked_on_text_change(monkeypatch):
    monkeypatch.setenv('AGENTGUARD_SECURITY_PROFILE','strict')
    monkeypatch.setenv('AGENTGUARD_APPROVER_TOKEN','review-secret')
    h={'x-agentguard-token':'review-secret'}
    with TestClient(app) as c:
        p=c.post('/api/v1/policies',json={'name':'Test review','natural_text':'退款前必须完成身份认证和订单确认。'},headers=h).json()['data']
        cid=c.post(f"/api/v1/policies/{p['id']}/compile",json={},headers=h).json()['data']['contract_id']
        assert c.post(f"/api/v1/policies/{p['id']}/activate",json={},headers=h).status_code==409
        assert c.post(f"/api/v1/policies/{p['id']}/review",json={'comment':'checked'},headers=h).status_code==422
        r=c.post(f"/api/v1/policies/{p['id']}/review",json={'source_matches_contract':True},headers=h)
        assert r.status_code==200 and r.json()['data']['contract_id']==cid
        assert c.post(f"/api/v1/policies/{p['id']}/activate",json={},headers=h).status_code==200
        assert c.patch(f"/api/v1/policies/{p['id']}",json={'natural_text':'退款前先确认订单。'},headers=h).json()['data']['status']=='draft'
        assert c.post(f"/api/v1/policies/{p['id']}/activate",json={},headers=h).status_code==409
