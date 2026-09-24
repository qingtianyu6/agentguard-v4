from hashlib import sha256
from types import SimpleNamespace
from concurrent.futures import ThreadPoolExecutor
import json
import subprocess
import sys
import uuid
from app.services.audit_verifier import verify_chain
from app.database import SessionLocal
from app.main import audit
from app.models import AuditEvent
from fastapi.testclient import TestClient
from app.main import app

def test_audit_verifier_detects_changed_payload():
    body='{"ok":true}'
    entry=SimpleNamespace(event_id='evt',prev_hash='GENESIS',payload_json=body,
                          hash=sha256(('GENESIS'+body).encode()).hexdigest())
    assert verify_chain([entry])['valid']
    entry.payload_json='{"ok":false}'
    assert verify_chain([entry])['reason']=='PAYLOAD_HASH_MISMATCH'


def test_v2_audit_chain_detects_trace_and_event_type_tamper():
    body='{"ok":true}'
    encoded=json.dumps({'trace_id':'trace-1','event_type':'ACTION_COMMITTED','payload':body},
                       sort_keys=True,ensure_ascii=False,separators=(',',':'))
    entry=SimpleNamespace(event_id='evt-v2',prev_hash='GENESIS',trace_id='trace-1',
                          event_type='ACTION_COMMITTED',payload_json=body,
                          hash='v2:'+sha256(('GENESIS'+encoded).encode()).hexdigest())
    assert verify_chain([entry])['valid']
    entry.trace_id='trace-forged'
    assert verify_chain([entry])['reason']=='PAYLOAD_HASH_MISMATCH'
    entry.trace_id='trace-1'
    entry.event_type='ACTION_ABORTED'
    assert verify_chain([entry])['reason']=='PAYLOAD_HASH_MISMATCH'


def test_concurrent_audit_appends_do_not_fork_chain():
    trace_id='audit-concurrency-'+uuid.uuid4().hex
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda index: audit(None,trace_id,'CONCURRENT_TEST',{'index':index}),range(12)))
    with SessionLocal() as db:
        all_events=db.query(AuditEvent).order_by(AuditEvent.id).all()
        selected=[event for event in all_events if event.trace_id==trace_id]
        assert len(selected)==12
        assert verify_chain(all_events)['valid'] is True


def test_multi_process_audit_appends_do_not_fork_chain():
    trace_id='audit-process-'+uuid.uuid4().hex
    code=('import sys; from app.main import audit; '
          'trace=sys.argv[1]; start=int(sys.argv[2]); '
          '[audit(None,trace,"PROCESS_TEST",{"index":start+i}) for i in range(4)]')
    processes=[subprocess.Popen([sys.executable,'-c',code,trace_id,str(worker*4)],
                                stdout=subprocess.PIPE,stderr=subprocess.PIPE)
               for worker in range(3)]
    for process in processes:
        _,errors=process.communicate(timeout=30)
        assert process.returncode==0,errors.decode(errors='replace')
    with SessionLocal() as db:
        all_events=db.query(AuditEvent).order_by(AuditEvent.id).all()
        assert sum(event.trace_id==trace_id for event in all_events)==12
        assert verify_chain(all_events)['valid'] is True


def test_audit_center_endpoint_uses_v2_verifier():
    with TestClient(app) as client:
        result=client.post('/api/v1/audit/verify-chain',json={}).json()['data']
        assert result['valid'] is True
        assert result['head_hash'].startswith('v2:')
