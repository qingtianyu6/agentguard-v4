from __future__ import annotations
from datetime import datetime
from sqlalchemy import String, Text, Integer, Boolean, DateTime, ForeignKey, Float
from sqlalchemy.orm import Mapped, mapped_column
from .database import Base

def now(): return datetime.utcnow()

class Agent(Base):
    __tablename__ = "agents"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    type: Mapped[str] = mapped_column(String(50), default="tool-agent")
    status: Mapped[str] = mapped_column(String(30), default="active")
    description: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

class Policy(Base):
    __tablename__ = "policies"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    natural_text: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(30), default="draft")
    version: Mapped[int] = mapped_column(Integer, default=1)
    tags: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)

class Contract(Base):
    __tablename__ = "contracts"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    policy_id: Mapped[str] = mapped_column(ForeignKey("policies.id"))
    dsl: Mapped[str] = mapped_column(Text)
    structured_json: Mapped[str] = mapped_column(Text)
    graph_json: Mapped[str] = mapped_column(Text)
    verified: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

class CompilationJob(Base):
    __tablename__ = "compilation_jobs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    policy_id: Mapped[str] = mapped_column(String(64), index=True)
    contract_id: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(30), default="completed")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

class Trajectory(Base):
    __tablename__ = "trajectories"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(30), default="active")
    started_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

class ActionEvent(Base):
    __tablename__ = "action_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    action_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    trace_id: Mapped[str] = mapped_column(String(64), index=True)
    agent_id: Mapped[str] = mapped_column(String(64))
    tool_id: Mapped[str] = mapped_column(String(120), default="")
    action: Mapped[str] = mapped_column(String(80))
    resource: Mapped[str] = mapped_column(String(255), default="")
    destination: Mapped[str] = mapped_column(String(255), default="")
    args_json: Mapped[str] = mapped_column(Text, default="{}")
    result_json: Mapped[str] = mapped_column(Text, default="{}")
    state: Mapped[str] = mapped_column(String(30), default="preflight")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

class Decision(Base):
    __tablename__ = "decisions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    decision_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    action_id: Mapped[str] = mapped_column(String(64), index=True)
    trace_id: Mapped[str] = mapped_column(String(64), index=True)
    decision: Mapped[str] = mapped_column(String(20))
    risk_level: Mapped[str] = mapped_column(String(20), default="LOW")
    reason: Mapped[str] = mapped_column(Text, default="")
    matched_policy_id: Mapped[str] = mapped_column(String(64), default="")
    required_condition: Mapped[str] = mapped_column(String(120), default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

class Risk(Base):
    __tablename__ = "risks"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(64), index=True)
    decision_id: Mapped[str] = mapped_column(String(64), index=True)
    type: Mapped[str] = mapped_column(String(80))
    severity: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(30), default="open")
    description: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

class Approval(Base):
    __tablename__ = "approvals"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    action_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(30), default="pending")
    reason: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=now, onupdate=now)

class Recovery(Base):
    __tablename__ = "recoveries"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    action_id: Mapped[str] = mapped_column(String(64), index=True)
    status: Mapped[str] = mapped_column(String(30), default="suggested")
    original_plan: Mapped[str] = mapped_column(Text, default="[]")
    safe_plan: Mapped[str] = mapped_column(Text, default="[]")
    rationale: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

class AuditEvent(Base):
    __tablename__ = "audit_events"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(64), unique=True)
    trace_id: Mapped[str] = mapped_column(String(64), index=True)
    event_type: Mapped[str] = mapped_column(String(80))
    payload_json: Mapped[str] = mapped_column(Text)
    prev_hash: Mapped[str] = mapped_column(String(128), default="")
    hash: Mapped[str] = mapped_column(String(128))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

class AuditHead(Base):
    __tablename__ = 'audit_head'
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    head_hash: Mapped[str] = mapped_column(String(128), default='GENESIS')
    version: Mapped[int] = mapped_column(Integer, default=0)

class McpServer(Base):
    __tablename__ = "mcp_servers"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    endpoint: Mapped[str] = mapped_column(String(255), default="")
    status: Mapped[str] = mapped_column(String(30), default="connected")

class Tool(Base):
    __tablename__ = "tools"
    id: Mapped[str] = mapped_column(String(120), primary_key=True)
    server_id: Mapped[str] = mapped_column(String(64), default="")
    name: Mapped[str] = mapped_column(String(140))
    description: Mapped[str] = mapped_column(Text, default="")
    risk_level: Mapped[str] = mapped_column(String(20), default="LOW")

class TrustedMcpTool(Base):
    __tablename__ = "trusted_mcp_tools"
    id: Mapped[str] = mapped_column(String(255), primary_key=True)
    server_id: Mapped[str] = mapped_column(String(64), index=True)
    tool_id: Mapped[str] = mapped_column(String(120))
    actions_json: Mapped[str] = mapped_column(Text)
    description_hash: Mapped[str] = mapped_column(String(64))
    schema_hash: Mapped[str] = mapped_column(String(64))
    scan_reference: Mapped[str] = mapped_column(String(255))
    scan_report_sha256: Mapped[str] = mapped_column(String(64))
    quarantined: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

class AttackRun(Base):
    __tablename__ = "attack_runs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scenario: Mapped[str] = mapped_column(String(80))
    guard_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    success: Mapped[bool] = mapped_column(Boolean, default=False)
    decision: Mapped[str] = mapped_column(String(20), default="ALLOW")
    latency_ms: Mapped[float] = mapped_column(Float, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

class Benchmark(Base):
    __tablename__ = "benchmarks"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(120))
    version: Mapped[str] = mapped_column(String(40), default="v0.1")
    scenario_count: Mapped[int] = mapped_column(Integer, default=50)
    status: Mapped[str] = mapped_column(String(30), default="draft")

class BenchmarkScenario(Base):
    __tablename__ = "benchmark_scenarios"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    benchmark_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    case_json: Mapped[str] = mapped_column(Text)

class Experiment(Base):
    __tablename__ = "experiments"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(160))
    kind: Mapped[str] = mapped_column(String(80), default="runtime-security")
    status: Mapped[str] = mapped_column(String(30), default="completed")
    metrics_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

class ExperimentConfig(Base):
    __tablename__ = "experiment_configs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    config_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

class EvaluationRun(Base):
    __tablename__ = "evaluation_runs"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    kind: Mapped[str] = mapped_column(String(80))
    target_id: Mapped[str] = mapped_column(String(64), default="")
    config_json: Mapped[str] = mapped_column(Text)
    result_json: Mapped[str] = mapped_column(Text)
    artifact_path: Mapped[str] = mapped_column(String(500))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

class PolicyReview(Base):
    __tablename__ = "policy_reviews"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    policy_id: Mapped[str] = mapped_column(String(64), index=True)
    contract_id: Mapped[str] = mapped_column(String(64), index=True)
    policy_hash: Mapped[str] = mapped_column(String(64))
    reviewer: Mapped[str] = mapped_column(String(120), default="approver-service")
    comment: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)

class LineageEvent(Base):
    __tablename__ = "lineage_events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(64), index=True)
    event_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class WebhookRequest(Base):
    __tablename__ = "toolhive_webhook_requests"
    uid: Mapped[str] = mapped_column(String(128), primary_key=True)
    body_hash: Mapped[str] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)


class DecisionContextSnapshot(Base):
    __tablename__ = "decision_context_snapshots"
    decision_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    trace_id: Mapped[str] = mapped_column(String(64), index=True)
    input_hash: Mapped[str] = mapped_column(String(64))
    contracts_json: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=now)
