from __future__ import annotations
from typing import Any, Literal
from pydantic import BaseModel, Field

class ContractIR(BaseModel):
    schema_version: Literal['agentguard.contract/1'] = 'agentguard.contract/1'
    contract_id: str
    source_span: str
    source_document_hash: str | None = None
    subject: str = 'AnyAgent'
    action: str
    resource: str = 'AnyResource'
    destination: str = 'AnyDestination'
    effect: Literal['ALLOW', 'DENY', 'REQUIRE', 'DENY_UNLESS']
    conditions: list[dict[str, Any]] = Field(default_factory=list)
    temporal_constraints: list[str] = Field(default_factory=list)
    review_status: Literal['unreviewed', 'human_confirmed'] = 'unreviewed'
    proof_scope: Literal['not_checked', 'bounded', 'symbolic'] = 'not_checked'
