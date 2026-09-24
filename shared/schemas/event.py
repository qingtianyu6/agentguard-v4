"""Versioned event contract shared across the gateway and the research engines."""
from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4
from pydantic import BaseModel, Field

SCHEMA_VERSION = "agentguard.event/1"

class EventPhase(str, Enum):
    PROPOSED = "proposed"
    DECIDED = "decided"
    COMMITTED = "committed"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"

class AgentGuardEvent(BaseModel):
    schema_version: str = SCHEMA_VERSION
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    trace_id: str
    session_id: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    phase: EventPhase
    subject_id: str
    tool_id: str
    server_id: str | None = None
    tool_fingerprint: str | None = None
    action: str
    resource_refs: list[str] = Field(default_factory=list)
    destination: str | None = None
    args_digest: str | None = None
    result_digest: str | None = None
    contract_versions: dict[str, str] = Field(default_factory=dict)
    provenance_refs: list[str] = Field(default_factory=list)
    taint_labels: list[str] = Field(default_factory=list)
    decision: str | None = None
    extensions: dict[str, Any] = Field(default_factory=dict)
