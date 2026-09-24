# AgentGuard API 总设计 V1.0

> 目标：覆盖 AgentGuard Web、Policy Studio、P2C-V、Policy Engine、Gateway、Trajectory Guard、Safe Recovery、Evidence Engine、Attack Lab、AgentGuard-Bench 与实验体系。

**接口总数：118 个（REST + Gateway + WebSocket/SSE）**。

## 1. API 分层原则

1. `/api/v1/*`：产品控制面（Web 前端、研究管理、审计、Benchmark）。
2. `/gateway/v1/*`：数据面/运行时拦截，必须低延迟、可幂等、可审计。
3. `/ws/v1/*`：实时可视化与实验进度。
4. 核心算法 `services/*` 默认不直接暴露公网；MVP 采用 Python 内部调用，后续如拆微服务再映射到 `/internal/v1/*`。
5. 所有真实 Tool Call 必须先 `preflight`，得到 `ALLOW/ASK/REPAIR/DENY` 后再决定是否执行。

## 2. 统一协议

### 2.1 Base URL
`https://<host>/api/v1`，运行时网关：`https://<host>/gateway/v1`。

### 2.2 Headers
- `Authorization: Bearer <JWT>`：Web 控制面。
- `X-AgentGuard-Key: agk_...`：Agent/Gateway。
- `X-Trace-Id`：端到端链路 ID；无则服务端生成。
- `Idempotency-Key`：所有会造成状态变化或真实动作的 POST 必填。
- `X-Policy-Snapshot`：可选，锁定本次执行使用的策略快照。

### 2.3 统一成功响应
```json
{
  "request_id": "req_01...",
  "trace_id": "tr_01...",
  "data": {},
  "meta": {"timestamp": "2026-09-21T08:00:00Z"}
}
```

### 2.4 统一错误响应
```json
{
  "request_id": "req_01...",
  "error": {
    "code": "POLICY_SEMANTIC_MISMATCH",
    "message": "Contract conflicts with source policy",
    "details": {},
    "retryable": false
  }
}
```

建议状态码：`400` 参数错误；`401/403` 鉴权/权限；`404` 不存在；`409` 版本/幂等冲突；`422` 策略语义或契约校验失败；`429` 限流；`503` 模型/求解器暂不可用。

## 3. 全量接口清单

### 3.1 System & Auth

| Method | Path | 作用 | 权限 | 主要输入 | 主要输出 |
|---|---|---|---|---|---|
| GET | /api/v1/health | 健康检查 | public | - | HealthResponse |
| GET | /api/v1/version | 版本/构建信息 | public | - | VersionResponse |
| GET | /api/v1/capabilities | 当前启用能力与算法版本 | user | - | CapabilitiesResponse |
| POST | /api/v1/auth/login | 登录获取 access token | public | LoginRequest | TokenResponse |
| POST | /api/v1/auth/refresh | 刷新 token | user | RefreshRequest | TokenResponse |
| GET | /api/v1/auth/me | 当前用户信息 | user | - | UserProfile |
| GET | /api/v1/api-keys | API Key 列表 | admin | - | ApiKeyList |
| POST | /api/v1/api-keys | 创建 Agent/Gateway API Key | admin | ApiKeyCreate | ApiKeyCreated |
| DELETE | /api/v1/api-keys/{key_id} | 吊销 API Key | admin | - | OperationResult |

### 3.2 Dashboard

| Method | Path | 作用 | 权限 | 主要输入 | 主要输出 |
|---|---|---|---|---|---|
| GET | /api/v1/dashboard/overview | Security Overview 总览 | user | query: from,to | DashboardOverview |
| GET | /api/v1/dashboard/metrics | ALLOW/ASK/REPAIR/DENY、ASR/FPR 等指标 | user | query: from,to,agent_id | MetricSeries |
| GET | /api/v1/dashboard/risks | 活跃风险列表 | user | query: severity,status | RiskList |
| GET | /api/v1/dashboard/timeline | 安全事件时间线 | user | query: from,to | TimelineList |

### 3.3 Agents

| Method | Path | 作用 | 权限 | 主要输入 | 主要输出 |
|---|---|---|---|---|---|
| GET | /api/v1/agents | Agent 列表 | user | query: status,type | AgentList |
| POST | /api/v1/agents | 注册 Agent | user | AgentCreate | Agent |
| GET | /api/v1/agents/{agent_id} | Agent 详情 | user | - | Agent |
| PATCH | /api/v1/agents/{agent_id} | 修改 Agent 配置 | user | AgentPatch | Agent |
| DELETE | /api/v1/agents/{agent_id} | 停用/删除 Agent | admin | - | OperationResult |
| POST | /api/v1/agents/{agent_id}/test-connection | 连接测试 | user | - | ConnectionTestResult |
| GET | /api/v1/agents/{agent_id}/sessions | Agent 会话/轨迹列表 | user | query: from,to | TrajectoryList |

### 3.4 MCP & Tools

| Method | Path | 作用 | 权限 | 主要输入 | 主要输出 |
|---|---|---|---|---|---|
| GET | /api/v1/mcp/servers | MCP Server 列表 | user | - | McpServerList |
| POST | /api/v1/mcp/servers | 注册 MCP Server | user | McpServerCreate | McpServer |
| GET | /api/v1/mcp/servers/{server_id} | MCP Server 详情 | user | - | McpServer |
| PATCH | /api/v1/mcp/servers/{server_id} | 修改 MCP Server | user | McpServerPatch | McpServer |
| DELETE | /api/v1/mcp/servers/{server_id} | 停用 MCP Server | admin | - | OperationResult |
| POST | /api/v1/mcp/servers/{server_id}/discover | 发现 tools/resources/prompts | user | - | McpDiscoveryResult |
| GET | /api/v1/tools | 工具目录 | user | query: server_id,risk_level | ToolList |
| GET | /api/v1/tools/{tool_id} | 工具详情/描述/风险标签 | user | - | Tool |
| PATCH | /api/v1/tools/{tool_id}/risk-profile | 更新工具风险画像 | admin | ToolRiskProfilePatch | Tool |

### 3.5 Policy Studio

| Method | Path | 作用 | 权限 | 主要输入 | 主要输出 |
|---|---|---|---|---|---|
| GET | /api/v1/policies | 策略列表 | user | query: status,tag | PolicyList |
| POST | /api/v1/policies | 新建自然语言策略 | user | PolicyCreate | Policy |
| GET | /api/v1/policies/{policy_id} | 策略详情 | user | - | Policy |
| PATCH | /api/v1/policies/{policy_id} | 编辑草稿策略 | user | PolicyPatch | Policy |
| DELETE | /api/v1/policies/{policy_id} | 删除草稿/归档策略 | admin | - | OperationResult |
| POST | /api/v1/policies/{policy_id}/compile | 执行 P2C-V 完整编译 | user | CompileOptions | CompilationJob |
| GET | /api/v1/policies/{policy_id}/compilations/{job_id} | 编译状态/结果 | user | - | CompilationResult |
| POST | /api/v1/policies/{policy_id}/validate | 语法+语义校验 | user | ValidatePolicyRequest | PolicyValidationResult |
| POST | /api/v1/policies/{policy_id}/review | 人工 Review 结论 | reviewer | PolicyReviewRequest | PolicyReview |
| POST | /api/v1/policies/{policy_id}/activate | 激活已验证策略 | admin | ActivatePolicyRequest | PolicyVersion |
| POST | /api/v1/policies/{policy_id}/deactivate | 停用策略 | admin | - | PolicyVersion |
| GET | /api/v1/policies/{policy_id}/versions | 策略版本历史 | user | - | PolicyVersionList |
| GET | /api/v1/policies/{policy_id}/diff | 版本 Diff | user | query: from_version,to_version | PolicyDiff |
| GET | /api/v1/policies/{policy_id}/impact | 受影响 Agent/Tool/Workflow | user | query: version | ImpactAnalysis |
| POST | /api/v1/policies/{policy_id}/historical-replay | 历史轨迹回放 | user | HistoricalReplayRequest | ReplayJob |

### 3.6 P2C-V Compiler

| Method | Path | 作用 | 权限 | 主要输入 | 主要输出 |
|---|---|---|---|---|---|
| POST | /api/v1/compiler/parse | 自然语言 → Structured Requirement | user | PolicyTextRequest | StructuredRequirement |
| POST | /api/v1/compiler/requirement-graph | Structured Requirement → Requirement Graph | user | StructuredRequirement | RequirementGraph |
| POST | /api/v1/compiler/generate-contract | Requirement Graph → Policy DSL/逻辑约束 | user | RequirementGraphRequest | ContractCandidate |
| POST | /api/v1/compiler/counterexamples | 反例搜索/验证 | user | CounterexampleRequest | CounterexampleSet |
| POST | /api/v1/compiler/semantic-repair | 根据反例进行语义修复 | user | SemanticRepairRequest | ContractCandidate |
| POST | /api/v1/compiler/verify | 最终 Verified Contract 验证 | user | ContractVerifyRequest | VerificationResult |

### 3.7 Contracts & Policy Engine

| Method | Path | 作用 | 权限 | 主要输入 | 主要输出 |
|---|---|---|---|---|---|
| GET | /api/v1/contracts | 可执行契约列表 | user | query: policy_id,status | ContractList |
| GET | /api/v1/contracts/{contract_id} | 契约详情 | user | - | Contract |
| POST | /api/v1/contracts/{contract_id}/evaluate | 离线评估单个动作/轨迹 | user | EvaluationRequest | Decision |
| POST | /api/v1/contracts/{contract_id}/test-cases | 执行契约测试用例 | user | ContractTestRequest | ContractTestResult |
| GET | /api/v1/contracts/{contract_id}/logic | 查看 DSL/FSM/Datalog/SMT 表示 | user | query: format | FormalLogicView |

### 3.8 Gateway Runtime

| Method | Path | 作用 | 权限 | 主要输入 | 主要输出 |
|---|---|---|---|---|---|
| POST | /gateway/v1/sessions | 建立受保护 Agent Session | agent_key | GatewaySessionCreate | GatewaySession |
| POST | /gateway/v1/actions/preflight | Tool Call 执行前拦截判定 | agent_key | ActionPreflightRequest | Decision |
| POST | /gateway/v1/actions/{action_id}/approval-context | 补充用户/主管审批上下文 | agent_key | ApprovalContextRequest | Decision |
| POST | /gateway/v1/actions/{action_id}/commit | 声明动作即将真实执行 | agent_key | ActionCommitRequest | ActionCommitAck |
| POST | /gateway/v1/actions/{action_id}/result | 上报 Tool 执行结果 | agent_key | ActionResultRequest | ActionRecord |
| POST | /gateway/v1/actions/{action_id}/abort | Agent 放弃该动作 | agent_key | ActionAbortRequest | OperationResult |
| POST | /gateway/v1/sessions/{session_id}/close | 关闭 Session | agent_key | - | OperationResult |
| POST | /gateway/v1/mcp/call | MCP Tool Call 代理入口 | agent_key | McpCallRequest | McpCallResponse |

### 3.9 Trajectory & Provenance

| Method | Path | 作用 | 权限 | 主要输入 | 主要输出 |
|---|---|---|---|---|---|
| GET | /api/v1/trajectories | 轨迹列表 | user | query: agent_id,decision,risk_type | TrajectoryList |
| GET | /api/v1/trajectories/{trace_id} | 轨迹详情 | user | - | Trajectory |
| GET | /api/v1/trajectories/{trace_id}/events | 轨迹事件序列 | user | query: cursor,limit | ActionEventPage |
| GET | /api/v1/trajectories/{trace_id}/context | Context Reconstruction 结果 | user | query: at_action_id | TrajectoryContext |
| GET | /api/v1/trajectories/{trace_id}/provenance | Provenance Graph | user | query: format=json|cytoscape | ProvenanceGraph |
| GET | /api/v1/trajectories/{trace_id}/information-flow | 数据流/敏感传播分析 | user | - | InformationFlowGraph |
| POST | /api/v1/trajectories/{trace_id}/replay | 按指定契约重放 | user | TrajectoryReplayRequest | ReplayJob |

### 3.10 Decisions, Risks & Approvals

| Method | Path | 作用 | 权限 | 主要输入 | 主要输出 |
|---|---|---|---|---|---|
| GET | /api/v1/decisions | 安全判定列表 | user | query: decision,agent_id,policy_id | DecisionList |
| GET | /api/v1/decisions/{decision_id} | 判定详情+证据 | user | - | DecisionDetail |
| GET | /api/v1/risks | 风险事件列表 | user | query: severity,status,type | RiskList |
| GET | /api/v1/risks/{risk_id} | 风险详情 | user | - | RiskIncident |
| PATCH | /api/v1/risks/{risk_id} | 风险处置状态/备注 | user | RiskPatch | RiskIncident |
| GET | /api/v1/approvals | 待审批列表 | approver | query: status,agent_id | ApprovalList |
| GET | /api/v1/approvals/{approval_id} | 审批详情 | approver | - | Approval |
| POST | /api/v1/approvals/{approval_id}/approve | 同意 | approver | ApprovalDecisionRequest | Approval |
| POST | /api/v1/approvals/{approval_id}/reject | 拒绝 | approver | ApprovalDecisionRequest | Approval |

### 3.11 Safe Recovery

| Method | Path | 作用 | 权限 | 主要输入 | 主要输出 |
|---|---|---|---|---|---|
| POST | /api/v1/recovery/plan | 生成安全替代路径 | user | RecoveryPlanRequest | RecoveryPlan |
| POST | /api/v1/recovery/validate | 验证恢复路径 Safe(P',C) | user | RecoveryValidateRequest | RecoveryValidation |
| POST | /api/v1/recovery/{recovery_id}/approve | 人工批准恢复路径 | approver | RecoveryApprovalRequest | RecoveryPlan |
| POST | /api/v1/recovery/{recovery_id}/execute | 执行/返回可执行恢复步骤 | user | RecoveryExecuteRequest | RecoveryExecution |
| GET | /api/v1/recovery/{recovery_id} | 恢复记录详情 | user | - | RecoveryPlan |

### 3.12 Evidence & Audit

| Method | Path | 作用 | 权限 | 主要输入 | 主要输出 |
|---|---|---|---|---|---|
| GET | /api/v1/audit/events | 不可变审计事件 | auditor | query: from,to,type | AuditEventPage |
| GET | /api/v1/audit/traces/{trace_id} | 单轨迹完整证据链 | auditor | - | AuditTrace |
| GET | /api/v1/audit/evidence/{evidence_id} | 证据对象/哈希链验证 | auditor | - | EvidenceObject |
| POST | /api/v1/audit/verify-chain | 验证 hash chain | auditor | HashChainVerifyRequest | HashChainVerifyResult |
| POST | /api/v1/audit/reports | 生成审计报告 | auditor | AuditReportRequest | ReportJob |
| GET | /api/v1/audit/reports/{report_id} | 报告元数据/生成状态 | auditor | - | AuditReport |
| GET | /api/v1/audit/reports/{report_id}/download | 下载 PDF/JSON 报告 | auditor | query: format | binary |

### 3.13 Attack Lab

| Method | Path | 作用 | 权限 | 主要输入 | 主要输出 |
|---|---|---|---|---|---|
| GET | /api/v1/attack-lab/scenarios | 攻击场景库 | user | query: type,level | AttackScenarioList |
| GET | /api/v1/attack-lab/scenarios/{scenario_id} | 场景详情 | user | - | AttackScenario |
| POST | /api/v1/attack-lab/runs | 运行攻击实验 | user | AttackRunRequest | AttackRun |
| GET | /api/v1/attack-lab/runs/{run_id} | 运行状态/结果 | user | - | AttackRun |
| POST | /api/v1/attack-lab/compare | AgentGuard OFF vs ON 对比 | user | AttackCompareRequest | AttackCompareResult |

### 3.14 Benchmark

| Method | Path | 作用 | 权限 | 主要输入 | 主要输出 |
|---|---|---|---|---|---|
| GET | /api/v1/benchmarks | Benchmark 版本列表 | user | - | BenchmarkList |
| POST | /api/v1/benchmarks | 创建 Benchmark 版本 | researcher | BenchmarkCreate | Benchmark |
| GET | /api/v1/benchmarks/{benchmark_id}/scenarios | Scenario 列表 | user | query: split,risk_type,label | BenchmarkScenarioList |
| POST | /api/v1/benchmarks/{benchmark_id}/scenarios | 新增 Scenario | researcher | BenchmarkScenarioCreate | BenchmarkScenario |
| POST | /api/v1/benchmarks/{benchmark_id}/validate | 格式/标签/泄漏检查 | researcher | BenchmarkValidateRequest | BenchmarkValidation |
| POST | /api/v1/benchmarks/{benchmark_id}/freeze | 冻结 Test Split | admin | BenchmarkFreezeRequest | Benchmark |
| POST | /api/v1/benchmarks/{benchmark_id}/runs | 执行 Benchmark | researcher | BenchmarkRunRequest | BenchmarkRun |
| GET | /api/v1/benchmarks/runs/{run_id} | 运行状态 | user | - | BenchmarkRun |
| GET | /api/v1/benchmarks/runs/{run_id}/metrics | ASR/FPR/STC/Recovery/Latency 等 | user | - | BenchmarkMetrics |
| GET | /api/v1/benchmarks/runs/{run_id}/failures | 失败案例分析 | user | - | FailureCaseList |

### 3.15 Experiments

| Method | Path | 作用 | 权限 | 主要输入 | 主要输出 |
|---|---|---|---|---|---|
| GET | /api/v1/experiments/configs | 正式实验配置 | researcher | - | ExperimentConfigList |
| POST | /api/v1/experiments/configs | 创建实验配置快照 | researcher | ExperimentConfigCreate | ExperimentConfig |
| POST | /api/v1/experiments/runs | 启动 baseline/main/ablation/sensitivity/efficiency | researcher | ExperimentRunRequest | ExperimentRun |
| GET | /api/v1/experiments/runs/{run_id} | 实验运行状态 | user | - | ExperimentRun |
| GET | /api/v1/experiments/runs/{run_id}/results | raw/metrics/summary 索引 | user | - | ExperimentResult |
| GET | /api/v1/experiments/compare | 多实验对比 | user | query: run_ids | ExperimentComparison |
| POST | /api/v1/experiments/{run_id}/figures | 生成比赛图表数据/图 | researcher | FigureRequest | FigureJob |

### 3.16 Realtime

| Method | Path | 作用 | 权限 | 主要输入 | 主要输出 |
|---|---|---|---|---|---|
| WS | /ws/v1/runtime | Live Runtime 实时动作/判定/恢复事件 | user | subscribe filters | RuntimeEvent |
| WS | /ws/v1/trajectories/{trace_id} | 指定轨迹实时事件 | user | - | TrajectoryEvent |
| WS | /ws/v1/attack-lab/runs/{run_id} | 攻击实验实时步骤 | user | - | AttackRunEvent |
| WS | /ws/v1/experiments/runs/{run_id} | 实验进度与指标 | user | - | ExperimentEvent |
| SSE | /api/v1/compilations/{job_id}/events | P2C-V 编译阶段流 | user | - | CompilationEvent |

## 4. 核心数据模型

### 4.1 ActionEvent（整个系统最重要的事件）
```json
{
  "event_id": "evt_...",
  "trace_id": "tr_...",
  "session_id": "ses_...",
  "action_id": "act_...",
  "parent_action_id": null,
  "subject": {"type":"agent","id":"finance-agent"},
  "tool": {"id":"mcp.email.send","server_id":"mcp_01"},
  "action": "send",
  "resource": {"type":"customer_contact","id":"res_01","sensitivity":"PII"},
  "destination": {"type":"external_service","id":"crm_vendor"},
  "args": {},
  "result_summary": null,
  "data_refs": ["data_01"],
  "approval_refs": [],
  "environment": {"network":"external","tenant":"demo"},
  "occurred_at": "2026-09-21T08:00:00Z"
}
```

### 4.2 Decision
```json
{
  "decision_id": "dec_...",
  "action_id": "act_...",
  "decision": "REPAIR",
  "risk_level": "HIGH",
  "matched_contracts": ["ctr_001"],
  "violations": [{"rule_id":"SEC_001","reason":"manager approval missing"}],
  "required_conditions": ["manager_approval"],
  "evidence_refs": ["ev_..."],
  "recovery_id": "rec_...",
  "policy_snapshot": "ps_20260921_03",
  "latency_ms": 23
}
```
`decision` 严格枚举：`ALLOW | ASK | REPAIR | DENY`。

### 4.3 StructuredRequirement
```json
{
  "subject":"FinanceAgent",
  "action":"external_send",
  "resource":"customer_contact",
  "permission":"ALLOW",
  "conditions":["manager_approval == true"],
  "temporal_constraints":[],
  "destination":"external",
  "sensitivity":"PII",
  "approval":"manager_approval",
  "exceptions":[],
  "evidence":[{"source_span":"未经主管授权..."}]
}
```

### 4.4 RequirementGraph
```json
{
  "graph_id":"rg_...",
  "nodes":[{"id":"n1","type":"Subject","value":"FinanceAgent"}],
  "edges":[{"source":"n1","target":"n2","type":"CANNOT"}],
  "source_policy_id":"pol_...",
  "schema_version":"rg-1.0"
}
```
节点类型：`Policy/Subject/Action/Resource/Tool/Condition/Permission/Approval/Data/Destination/Exception`；关系：`CAN/CANNOT/REQUIRES/BEFORE/AFTER/READS/WRITES/SENDS/DERIVED_FROM/FLOWS_TO/APPROVED_BY/EXCEPTION`。

### 4.5 Contract
```json
{
  "contract_id":"ctr_...",
  "policy_id":"pol_...",
  "version":3,
  "dsl":"RULE SEC_001 { ... }",
  "logic":{"type":"FSM+Datalog","artifact_ref":"..."},
  "verification":{"status":"VERIFIED","fidelity":0.93},
  "status":"ACTIVE"
}
```

### 4.6 RecoveryPlan
```json
{
  "recovery_id":"rec_...",
  "original_action_id":"act_...",
  "status":"PROPOSED",
  "steps":[
    {"op":"REDACT","fields":["id_card","phone"]},
    {"op":"AGGREGATE","method":"count_by_region"},
    {"op":"REQUEST_APPROVAL","role":"manager"},
    {"op":"RESUME_TOOL_CALL"}
  ],
  "safety_verified":true,
  "utility_score":0.91,
  "action_distance":0.24
}
```

## 5. 最关键的运行时调用链

```text
Agent wants Tool Call
  -> POST /gateway/v1/actions/preflight
      -> Context Reconstruction
      -> Trajectory Query / Provenance
      -> Contract Match
      -> Temporal/SMT/FSM Verification
      -> Decision(ALLOW|ASK|REPAIR|DENY)

ALLOW  -> commit -> real tool -> result
ASK    -> create Approval -> approve/reject -> re-evaluate
REPAIR -> Recovery Plan -> validate -> approve(optional) -> execute/resume
DENY   -> stop + evidence + risk incident
```

### 5.1 preflight 请求
```json
{
  "session_id":"ses_01",
  "agent_id":"agent_01",
  "tool_call":{
    "tool_id":"mcp.email.send",
    "action":"send",
    "args":{"to":"external@example.com","attachment_refs":["data_01"]}
  },
  "resource_refs":["data_01"],
  "declared_destination":"external",
  "client_context":{"task_id":"task_01"}
}
```
### 5.2 preflight 响应
```json
{
  "decision_id":"dec_01",
  "action_id":"act_01",
  "decision":"ASK",
  "risk_level":"HIGH",
  "matched_contracts":["ctr_01"],
  "required_conditions":["manager_approval"],
  "approval":{"approval_id":"apr_01","status":"PENDING"},
  "expires_at":"2026-09-21T08:05:00Z"
}
```

## 6. P2C-V 编译状态机
`DRAFT -> PARSING -> GRAPH_BUILT -> CONTRACT_CANDIDATE -> COUNTEREXAMPLE_CHECK -> REPAIRING -> VERIFIED -> REVIEWED -> ACTIVE`。
任何阶段失败都保留输入、模型版本、prompt hash、反例、修复历史，保证论文/比赛可复现。

## 7. WebSocket 事件统一 envelope
```json
{
  "type":"runtime.decision",
  "seq":128,
  "trace_id":"tr_...",
  "timestamp":"...",
  "payload":{}
}
```
建议事件：`runtime.action.requested`、`runtime.context.reconstructed`、`runtime.policy.matched`、`runtime.decision`、`runtime.approval.requested`、`runtime.recovery.proposed`、`runtime.tool.executed`、`runtime.risk.created`、`policy.compilation.stage`、`experiment.metric.updated`。

## 8. 内部 Service 接口（不直接给前端）

| Service | 建议 Python Protocol / Internal RPC | 输入 | 输出 |
|---|---|---|---|
| PolicyCompiler | `compile(policy_text, options)` | PolicyText | CompilationResult |
| RequirementGraphBuilder | `build(structured_requirement)` | StructuredRequirement | RequirementGraph |
| ContractEngine | `evaluate(action, context, contracts)` | ActionEvent + Context | Decision |
| TemporalVerifier | `verify(trace, constraint)` | Trace + Constraint | VerificationResult |
| ProvenanceService | `update(event)` / `query(trace_id)` | ActionEvent | Graph/Context |
| InformationFlowDetector | `analyze(graph, candidate_action)` | Graph + Action | FlowRisk[] |
| RecoveryEngine | `plan(action, violations, context)` | Decision Context | RecoveryPlan |
| RecoveryValidator | `validate(plan, contracts)` | RecoveryPlan | RecoveryValidation |
| EvidenceEngine | `append(event)` / `seal(trace)` | Audit Event | EvidenceRef |
| BenchmarkRunner | `run(config)` | BenchmarkRunConfig | Metrics + Failures |

## 9. 关键错误码

`POLICY_PARSE_FAILED`、`POLICY_SEMANTIC_MISMATCH`、`CONTRACT_SYNTAX_INVALID`、`CONTRACT_NOT_VERIFIED`、`COUNTEREXAMPLE_FOUND`、`POLICY_VERSION_CONFLICT`、`ACTION_ALREADY_COMMITTED`、`ACTION_DENIED`、`APPROVAL_REQUIRED`、`APPROVAL_EXPIRED`、`RECOVERY_UNSAFE`、`TRACE_CONTEXT_INCOMPLETE`、`PROVENANCE_GRAPH_ERROR`、`MCP_SERVER_UNAVAILABLE`、`TOOL_SCHEMA_CHANGED`、`BENCHMARK_FROZEN`、`TEST_SPLIT_ACCESS_DENIED`、`EXPERIMENT_CONFIG_NOT_FROZEN`。

## 10. 数据一致性与安全约束

- `preflight -> commit -> result` 三阶段必须共享同一 `action_id`。
- `commit` 只能对 `ALLOW` 或已经满足条件的 `ASK/REPAIR` 调用。
- 策略判定必须记录 `policy_snapshot`，防止规则更新后无法解释历史决策。
- `args`/`result` 默认只存摘要或加密引用；敏感原文进入 Evidence Vault，不直接出现在普通日志。
- `tool schema hash` 必须进入动作事件；工具描述变化时触发 poisoning 风险复检。
- 审批 token 一次性、短时有效、绑定 `action_id + policy_snapshot + args_hash`。
- Test split 冻结后，普通开发身份不得读取 `expected_decision`。
- 实验结果保存 `config/model/prompt/dataset/code commit/random seed` 指纹。

## 11. MVP 实现优先级

**P0（先做，形成真实安全闭环）**：`/policies`、`/compiler/parse`、`/compiler/requirement-graph`、`/compiler/generate-contract`、`/contracts/{id}/evaluate`、`/gateway/v1/sessions`、`/gateway/v1/actions/preflight|commit|result`、`/trajectories/{id}`、`/audit/traces/{id}`。

**P1（形成三大创新）**：Counterexample/Repair、Provenance/Information Flow、Recovery/Approval。

**P2（形成国赛证据链）**：Attack Lab、Benchmark、Experiments、Policy Diff/Historical Replay、PDF Audit。

**P3（产品化）**：Dashboard、实时 WS、API Key 管理、更多 MCP adapters。
