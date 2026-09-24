import uuid
import json
from copy import deepcopy
from pathlib import Path
import subprocess
import sys
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from app.main import app
from app.services.evidence_bundle import verify_trace_evidence, verify_signed_trace_evidence


def test_trace_evidence_snapshot_digest_detects_tamper():
    trace_id='evidence-'+uuid.uuid4().hex
    with TestClient(app) as client:
        pre=client.post('/gateway/v1/actions/preflight',json={'trace_id':trace_id,
            'tool_id':'mcp.files.list','action':'list_files','resource':'public'}).json()['data']
        response=client.get(f'/api/v1/audit/traces/{trace_id}/evidence-bundle')
        assert response.status_code==200
        bundle=response.json()['data']
        assert verify_trace_evidence(bundle)
        assert bundle['content']['trace_id']==trace_id
        assert any(x['action_id']==pre['action_id'] for x in bundle['content']['actions'])
        assert any(x['decision_id']==pre['decision_id'] for x in bundle['content']['decisions'])
        snapshots=bundle['content']['decision_context_snapshots']
        assert any(x['decision_id']==pre['decision_id'] and len(x['input_hash'])==64 for x in snapshots)
        context=json.loads(next(x['contracts_json'] for x in snapshots if x['decision_id']==pre['decision_id']))
        assert context['schema']=='agentguard.decision-context/1'
        assert context['normalized_action']['tool_id']=='mcp.files.list'
        assert isinstance(context['history'],list)
        bundle['content']['actions'][0]['resource']='forged'
        assert not verify_trace_evidence(bundle)


def test_signed_bundle_requires_pinned_public_key_and_detects_tamper(tmp_path, monkeypatch):
    private=Ed25519PrivateKey.generate()
    private_pem=private.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption())
    public_pem=private.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    key_file=tmp_path/'evidence-key.pem'
    key_file.write_bytes(private_pem)
    monkeypatch.setenv('AGENTGUARD_EVIDENCE_SIGNING_KEY_FILE',str(key_file))
    trace_id='signed-evidence-'+uuid.uuid4().hex
    with TestClient(app) as client:
        client.post('/gateway/v1/actions/preflight',json={'trace_id':trace_id,
            'tool_id':'mcp.files.list','action':'list_files','resource':'public'})
        response=client.get(f'/api/v1/audit/traces/{trace_id}/evidence-bundle')
        assert response.status_code==200
        bundle=response.json()['data']
    assert verify_signed_trace_evidence(bundle,public_pem)
    other=Ed25519PrivateKey.generate().public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo)
    assert not verify_signed_trace_evidence(bundle,other)
    changed=deepcopy(bundle)
    changed['content']['actions'][0]['resource']='forged'
    assert not verify_signed_trace_evidence(changed,public_pem)
    changed=deepcopy(bundle)
    changed['generated_at']='2000-01-01T00:00:00+00:00'
    assert not verify_signed_trace_evidence(changed,public_pem)
    changed=deepcopy(bundle)
    changed['signature']['value']='invalid'
    assert not verify_signed_trace_evidence(changed,public_pem)
    bundle_file=tmp_path/'bundle.json'
    public_file=tmp_path/'trusted-public.pem'
    bundle_file.write_text(json.dumps({'data':bundle},ensure_ascii=False),encoding='utf-8')
    public_file.write_bytes(public_pem)
    cli=Path(__file__).resolve().parents[2]/'scripts/evidence_keys.py'
    verification=subprocess.run([sys.executable,str(cli),'verify',str(bundle_file),str(public_file)],
                                capture_output=True,text=True)
    assert verification.returncode==0
    assert verification.stdout.strip()=='VALID'


def test_keygen_refuses_overwrite(tmp_path):
    cli=Path(__file__).resolve().parents[2]/'scripts/evidence_keys.py'
    private=tmp_path/'private.pem'
    public=tmp_path/'public.pem'
    command=[sys.executable,str(cli),'keygen','--private',str(private),'--public',str(public)]
    assert subprocess.run(command,capture_output=True).returncode==0
    original=private.read_bytes()
    assert subprocess.run(command,capture_output=True).returncode!=0
    assert private.read_bytes()==original
