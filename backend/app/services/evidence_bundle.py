"""Trace evidence snapshots with optional externally verifiable signatures."""
from __future__ import annotations
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
from sqlalchemy.orm import Session
from ..models import ActionEvent, Decision, Recovery, AuditEvent, LineageEvent, Contract, Policy, DecisionContextSnapshot
from .audit_verifier import verify_chain
from shared.evidence_signature import canonical, sign_trace_evidence, verify_trace_evidence, verify_signed_trace_evidence


def row_data(row):
    return {col.name: getattr(row,col.name).isoformat() if isinstance(getattr(row,col.name),datetime)
            else getattr(row,col.name) for col in row.__table__.columns}


def build_trace_evidence(db: Session, trace_id: str) -> dict:
    actions=db.query(ActionEvent).filter(ActionEvent.trace_id==trace_id).order_by(ActionEvent.id).all()
    decisions=db.query(Decision).filter(Decision.trace_id==trace_id).order_by(Decision.id).all()
    audit_all=db.query(AuditEvent).order_by(AuditEvent.id).all()
    audits=[x for x in audit_all if x.trace_id==trace_id]
    lineage=db.query(LineageEvent).filter(LineageEvent.trace_id==trace_id).order_by(LineageEvent.id).all()
    snapshots=db.query(DecisionContextSnapshot).filter(DecisionContextSnapshot.trace_id==trace_id).order_by(DecisionContextSnapshot.created_at).all()
    tool_trust=[json.loads(x.contracts_json).get('tool_trust') for x in snapshots]
    tool_trust=[x for x in tool_trust if x]
    if not actions and not decisions and not audits and not lineage:
        raise ValueError('TRACE_NOT_FOUND')
    action_ids=[x.action_id for x in actions]
    recovery=db.query(Recovery).filter(Recovery.action_id.in_(action_ids)).order_by(Recovery.id).all() if action_ids else []
    policy_ids={x.matched_policy_id for x in decisions if x.matched_policy_id}
    policies=db.query(Policy).filter(Policy.id.in_(policy_ids)).all() if policy_ids else []
    contracts=db.query(Contract).filter(Contract.policy_id.in_(policy_ids)).all() if policy_ids else []
    content={'schema':'agentguard.trace-evidence/1','trace_id':trace_id,
             'actions':[row_data(x) for x in actions],
             'decisions':[row_data(x) for x in decisions],
             'decision_context_snapshots':[row_data(x) for x in snapshots],
             'recoveries':[row_data(x) for x in recovery],
             'lineage':[row_data(x) for x in lineage],
             'policy_snapshots':[row_data(x) for x in policies],
             'contract_snapshots':[row_data(x) for x in contracts],
             'audit_events':[row_data(x) for x in audits],
             'audit_chain_verification':verify_chain(audit_all),
             'tool_fingerprints':tool_trust}
    bundle={'content':content,'sha256':sha256(canonical(content)).hexdigest(),
            'generated_at':datetime.now(timezone.utc).isoformat(),
            'limitations':['legacy decisions and sandbox calls can lack tool trust snapshots',
                           'legacy decisions can lack a decision-time snapshot; exported policy rows reflect current state']}
    key_path=os.environ.get('AGENTGUARD_EVIDENCE_SIGNING_KEY_FILE')
    if key_path:
        sign_trace_evidence(bundle,Path(key_path).read_bytes())
    else:
        bundle['limitations'].append('unsigned export: digest does not authenticate the exporter')
    return bundle
