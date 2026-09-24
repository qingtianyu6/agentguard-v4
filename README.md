> 工程实施进度和 V4.0 阶段验收差距见 [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md)。本包不是 V4.0 最终完成版。

# 智契 · AgentGuard V3.0

> Verifiable Policy-to-Contract Compilation and Trajectory-Aware Runtime Safety for Tool-Using AI Agents

AgentGuard V3.0 是面向 **MCP / Tool-Using Agent / Multi-Agent** 的运行时安全研究与产品原型。核心目标不是只判断模型“说了什么”，而是在 Agent 真正调用文件、邮件、订单、API、其他 Agent 之前，对行为契约和历史轨迹进行验证，并给出 `ALLOW / ASK / REPAIR / DENY` 四态判定。

V3.0 的重点从“完整软件能跑”继续推进到“研究结论可验证、实验结果可复现、竞赛现场能解释”。

## V3.0 相对 V2.0 的关键升级

### 1. P2C-V V3：完整可追踪编译链

```text
Natural Policy
   ↓
Structured Extraction
   ↓
Typed Requirement Graph IR
   ↓
Executable Contract Candidate
   ↓
Formal IR
   ↓
Bounded Model Checking
   ↓
Counterexample / Witness
   ↓
CEGAR Repair
   ↓
Final Verification
```

核心模块：

- `backend/app/services/llm_extractor.py`
- `backend/app/services/p2cv_v3.py`
- `backend/app/services/formal_verifier.py`

默认使用 **离线确定性抽取器**，不依赖任何外部 API；配置 OpenAI-compatible endpoint 后，可以替换为 LLM Structured Extraction，同时保留确定性 fallback。

### 2. Formal Verification V3

V3 为每条策略生成：

- Typed Formal IR
- SMT-LIB2 文本
- Proof Obligations
- 有界状态空间
- Counterexample Count
- Witness States
- Optional Z3 Adapter

默认零依赖使用内置 bounded model checker；如需启用 Z3：

```bash
pip install -r backend/requirements-formal.txt
```

### 3. Trajectory Guard V3

除 V2 已支持的敏感文件、外发、退款时序外，V3 新增：

- Cross-Agent Leakage
- Memory Poisoning
- Tool Description Poisoning
- Privilege Escalation
- Unauthorized Destructive Tool Use

因此可以真正做：

```text
Single-Step Guard
vs
Full Trajectory Guard
```

而不是只比较不同提示词。

### 4. AgentGuard-Bench V3 Candidate Set

代码包自带：

- 100 条 Runtime Scenario Candidate
- 8 类 Threat Type
- 固定 60 / 20 / 20 Train / Dev / Test
- 50 条 Policy Compilation Candidate
- SHA-256 manifest
- 固定 seed = 42

目录：

```text
benchmark/
├── scenarios/agentguard_bench_v3_100.json
├── policies/policy_ground_truth_v3_50.json
└── manifests/v3_manifest.json
```

**重要：** 当前 100 条场景和 50 条策略标签是 V3 研发候选集，已经进入自动回归测试，但在论文或国赛材料中正式称为“人工 Ground Truth”之前，还必须完成团队人工复核/双人标注。这一点刻意保留在 manifest 中，避免把自动生成标签误写成人工标注。

### 5. 可复现实验链

V3 新增：

- Compiler Benchmark
- Compiler Ablation
- Runtime Ablation
- Full Research Suite

每次正式研究运行可自动保存：

```text
experiments/results/<run_id>/
├── config.json
├── raw.jsonl
├── metrics.json
└── summary.md
```

因此 PPT 上任何正式数字都可以继续建立：

```text
Figure → Experiment → Config → Raw Result
```

### 6. 比赛级 UI V3

仍然只保留六个主页面：

1. Security Overview
2. Policy Studio
3. Live Runtime
4. Provenance Graph
5. Attack & Benchmark Lab
6. Evidence Center

Policy Studio 新增 Formal IR / Model Check / CEGAR / SMT-LIB2；Attack Lab 新增 Candidate Dataset、Frozen Test、Runtime Ablation、Compiler Ablation。

## 技术栈

### Frontend

- React 18
- TypeScript
- Vite
- Lucide React
- 自研 CSS 数据可视化组件

### Backend

- FastAPI
- SQLAlchemy 2
- Pydantic
- SQLite（默认） / PostgreSQL（可切换）
- WebSocket + SSE

### Research Services

```text
backend/app/services/
├── llm_extractor.py
├── p2cv.py
├── p2cv_v3.py
├── formal_verifier.py
├── runtime_guard.py
├── mcp_runtime.py
├── provenance.py
├── benchmark_engine.py
└── research_experiments.py
```

## 目录结构

```text
agentguard_fullstack_v3.0/
├── backend/
├── frontend/
├── benchmark/
├── experiments/
├── docs/
├── scripts/
└── START_HERE_运行说明.txt
```

## Windows 一键启动

```powershell
.\scripts\start_all.ps1
```

访问：

```text
Frontend: http://127.0.0.1:5173
Backend:  http://127.0.0.1:8000
Swagger:  http://127.0.0.1:8000/docs
```

## 手动启动

### Backend

```powershell
cd backend
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Frontend

```powershell
cd frontend
npm install
npm run dev
```

## 数据库

默认：

```text
backend/agentguard.db
```

PostgreSQL 示例：

```text
DATABASE_URL=postgresql+psycopg://agentguard:agentguard@127.0.0.1:5432/agentguard
```

## 可选 LLM Structured Extraction

默认不需要 LLM。

如果接本地 Ollama OpenAI-compatible endpoint：

```text
AGENTGUARD_EXTRACTOR=auto
AGENTGUARD_LLM_BASE_URL=http://127.0.0.1:11434/v1
AGENTGUARD_LLM_MODEL=qwen3:8b
AGENTGUARD_LLM_API_KEY=
```

如果 LLM 调用失败，系统会自动回退到 deterministic extractor，并在编译证据中标记 `fallback_used=true`。

## 推荐 V3 现场 Demo

### Demo A：`.env` 真实阻断

```text
Agent → mcp.files.read(.env)
      → Gateway Preflight
      → DENY
      → Tool NOT REACHED
```

### Demo B：退款时序 Safe Recovery

```text
refund
  ↓
REPAIR
  ↓
identity_verified
  ↓
order_confirmed
  ↓
recheck
  ↓
ALLOW
```

### Demo C：P2C-V V3 Formal Verification

在 Policy Studio 输入：

```text
未经主管授权，任何 Agent 不得向外部服务发送客户联系方式或敏感数据。
```

展示：

```text
Structured Requirement
→ Graph IR
→ DSL
→ Formal IR
→ Model Check
→ SMT-LIB2
→ Verification
```

### Demo D：Trajectory Value

Live Runtime 运行：

- Cross-Agent Leakage
- Memory Poisoning

Attack Lab 查看：

```text
No Guard
vs
Single-Step Guard
vs
AgentGuard Full
```

## 测试与当前验证结果

```powershell
cd backend
python -m pytest -q
```

V3.0 打包前：

```text
15 passed
```

API 兼容性检查：

```text
Original V1 API HTTP operations : 113
V3 HTTP operations             : 131
Missing original operations    : 0
```

当前 V3 Candidate Set 的冻结 `test` split 在本地规则引擎回归中：

```text
AgentGuard Full
Policy Fidelity = 1.00
Attack Success Rate = 0.00
```

这只是**当前候选测试集上的软件回归结果**，不等同于对真实世界安全效果的外部证明；正式论文结论必须在完成标签人工复核、扩大场景覆盖和加入外部 baseline 后再冻结。

## 下一阶段

V3 之后不应继续无目的加页面。下一阶段优先级：

1. 100 Scenario Candidate 双人标注，升级为正式 Ground Truth。
2. Policy Candidate 50 → 100，记录 inter-annotator agreement。
3. 接真实 LLM extractor，跑模型版本对照。
4. 安装 Z3，增加真实 SMT solver 对照。
5. 加外部 Agent baseline / guard baseline。
6. 固定 Competition Test Set，禁止继续调参。
7. 自动生成论文图表和失败案例报告。
