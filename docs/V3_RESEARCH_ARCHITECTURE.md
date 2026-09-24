# AgentGuard V3 Research Architecture

## 1. Research Question

AgentGuard V3 聚焦三个可以实验验证的问题：

1. 自然语言策略经过 Graph IR 和 Formal Verification 后，能否提高可执行契约的可审计性与约束完整性？
2. Full Trajectory 是否比 Single-Step Guard 更能识别跨步骤、跨 Agent 与 Memory Poisoning 风险？
3. 被阻断后，Constraint-Guided Recovery 能否在不突破安全边界的情况下提升 Task Completion？

## 2. P2C-V V3

```text
Policy Text
→ Extractor
→ Typed Requirement Graph
→ DSL Candidate
→ Formal IR
→ Bounded Model Checker
→ Counterexample / Witness
→ CEGAR
→ Verified / Review Contract
```

Extractor 有两个适配层：

- deterministic（默认、离线、可复现）
- OpenAI-compatible（可连接 Ollama 或其他兼容端点）

编译结果必须记录 provider、model、fallback、Graph IR、Formal IR、SMT-LIB2 和 Verification。

## 3. Formal Verification

V3 内置 bounded model checker，针对有限状态空间验证：

- explicit deny 不得在匹配范围内 ALLOW；
- temporal prerequisite 缺失不得 ALLOW；
- threshold approval 缺失不得 ALLOW；
- approval-gated operation 缺失审批不得 ALLOW。

同时生成 SMT-LIB2，并保留 Z3 adapter。

## 4. Trajectory Guard V3 Threat Model

覆盖：

- Indirect Prompt Injection
- Tool Description Poisoning
- Sensitive Data Leakage
- Unauthorized Tool Use
- Privilege Escalation
- Temporal Constraint Violation
- Cross-Agent Leakage
- Memory Poisoning

单步与轨迹模式使用相同 Runtime Guard，只改变历史上下文是否可见，从而保证消融变量清晰。

## 5. Reproducibility

正式实验每次生成：

```text
config.json
raw.jsonl
metrics.json
summary.md
```

任何后续论文图表必须引用 run_id。
