# AgentGuard V4.0 设计书实施核对（2026-09-23）

此代码包是 **V3 基础上的阶段性工程增量**。未达到 V4.0 设计书的 M0–M8 全部验收条件，不能以「最终完成版」参赛或部署生产。下表列出实际完成与缺项，避免将接口或模拟器包装为已完成研究结果。

| 阶段 | 已实现并验证 | 尚未通过的验收门槛 |
| --- | --- | --- |
| M0 架构与接口 | versioned Event/Contract/Tool schema；威胁模型；当前可运行回归见下文 | 第三方依赖完整 commit/license 锁；Contract IR 全业务接管 |
| M1 真实 MCP | 官方 MCP Python SDK 的 stdio/HTTP client adapter；真实 stdio fixture 三工具；真实调用结果经 GatewayRuntimeBridge 回传轨迹；危险写入在执行前被拦截；ToolHive validating webhook 适配及 HMAC 验证 | ToolHive 容器部署与端到端调用；三个独立真实第三方 server；独立第三方 HTTP 服务集成；不可绕过的网络和凭据隔离 |
| M2 Trust Registry | 描述与 schema 指纹、漂移、隔离机制；Cisco MCP Scanner 的 YARA 扫描连接本地 MCP 服务并登记三工具 | Cisco 的远端多分析器扫描、扫描持久化与生产注册闭环 |
| M3 P2C-V | 原编译链、bounded 检查；Z3 实际符号求解与模型 witness；验证范围标注 | Cedar CLI 子集验证与授权测试已通过；SymCC/cvc5、>=100 条人工独立规则；语义保真门槛与人工复核流程 |
| M4 Trajectory Guard | structured provenance taint 传播，关键词缺失的衍生敏感内容测试；已完成动作才入历史 | NetworkX 已用于可验证祖先节点测试；Neo4j/跨 Agent 完整语义、Neo4j 与统一 Event Store 决策闭环、冻结独立测试验证增益 |
| M5 Recovery | 有界最小代价候选搜索、沙箱恢复逐步 guard 校验及失败停机、缺少上下文时拒绝给出伪效用 | 自主可信脱敏算子、任务效用 oracle、LangGraph 候选编排已实现；可信效用 oracle 与自动安全执行闭环 |
| M6 Benchmark | 100 原场景、分组泄漏检查；新增独立人工复核 schema 与来源/泄漏校验器；AgentDojo 0.1.35 工具执行组件适配并经实际运行时测试；明确 REPAIR 标签不是恢复成功 | 500–800 人工核验高质量场景；AgentDojo/Promptfoo/外部 baseline 真跑与统计检验 |
| M7 Evidence | 决策 p50/p95/p99 实测、实验文件哈希 manifest、决策时上下文与工具信任快照；可选 Ed25519 签名、离线公钥验签和数据库链头版本控制已通过单/多进程测试 | OTLP 全链性能、多个确定性重跑、业务动作与审计同事务、外部独立复现和签名密钥部署验收 |
| M8 产品冻结 | 六页前端可构建；取消误导性的“已证明”展示 | 三套真实工具 Demo 连续运行、许可证与原创性终验、完整比赛冻结 |

## 可复现检查

在项目根目录安装 `backend/requirements-dev.txt` 后：

```bash
PYTHONPATH=backend:. python -m pytest backend/tests -q
cd frontend && npm install && npm run build
```

本次环境中结果：49 passed；前端 `tsc && vite build` 通过。后端测试仍有弃用警告。真实 MCP fixture 是本地测试服务；不能据此声明所有 Agent 工具流量都经过强制网关。

## 保留的关键安全边界

- 未知工具及工具 ID/动作错配被拒绝；失败事件不计入可信时序历史。
- 无真实成功执行与任务 oracle 的 Recovery 不报告成功率和保留效用。
- 模型检查不证明原始自然语言语义等价；有界与符号保证分别标记。
- AgentGuard 代理之外的网络出口与工具访问仍需独立部署隔离。

## 追加实施：严格模式与数据来源决策

- 设置 `AGENTGUARD_SECURITY_PROFILE=strict` 时，网关操作需 Gateway Token，策略写入、审批和策略激活需独立 Approver Token。未配置则拒绝请求。
- 客户端传来的 `manager_approval` 与 `approval_granted` 不被当作真实审批；策略需最新契约对应的人工复核记录才能激活；原文变更会使活跃策略变为草稿。
- `POST /gateway/v1/lineage` 接受有结果摘要的已完成结构化事件，实际 Runtime preflight 可据衍生来源拒绝或请求审批；该事件当前由持有 Gateway Token 的服务提交，尚未实现端到端不可伪造证明。
- 严格模式自动恢复执行关闭，待可信算子、任务效用与重放验证完成后再开启。
- 审计链增加检验 API，但当前 SHA-256 链无数字签名且未解决并发写入事务与管理员重写风险。

## 追加实施：真实 MCP 结果回传闭环

- `GatewayRuntimeBridge` 将真实 MCP 客户端调用接入 preflight、commit 和 result API；成功结果由统一 result 端点写入 lineage，供同一 trace 的后续动作判定使用。独立 stdio fixture 的读后外发测试已验证第二步被拦截。
- preflight 拒绝未知或跨 trace 的 provenance 引用；失败或未提交动作不进入可信 lineage。
- Windows 测试夹具改用系统临时目录；本次环境下可运行的后端测试 48 passed、1 skipped，前端构建通过。AgentDojo、Cisco Scanner、LangGraph 三组测试因集成依赖未安装而未计入该结果。
- Strict 模式现支持经 Approver Token 审核登记的真实 MCP 工具；服务/工具/动作/描述/Schema 指纹和隔离状态在 preflight 与 commit 时校验，决策时信任快照进入 Evidence Bundle。测试覆盖真实 stdio 调用、指纹漂移、隔离及 preflight 后隔离。
- 注册接口目前只保存审核者提交的扫描报告引用与 SHA-256，尚未验证报告由扫描器真实产生；数据库迁移、独立第三方服务、ToolHive 端到端代理、隔离部署和跨服务 trace 仍待完成，M1/M2 Gate 仍未通过。

## 本轮环境验证

- LangGraph 恢复工作流测试和 AgentDojo 工具运行时适配测试已在本地实际通过；它们分别证明工作流可运行、外部工具组件可接入，不等同于 M5 自动恢复或 M6 完整外部 Benchmark 通过。
- Cisco MCP Scanner 4.8.4 的 Windows 安装受其固定依赖 `litellm==1.93.0` 阻碍：该依赖在本机需要 Rust/Cargo 构建，当前不可用。扫描器主体与 YARA 已安装，但扫描测试因缺 `litellm` 无法收集，因此扫描闭环未验收。

## 追加实施：时序恢复的受控沙箱闭环

- 退款时序违规的恢复建议现使用有界候选搜索生成，只包含当前可信历史中缺失的先决步骤；已完成身份认证时不会重复执行。
- 自动执行的先决步骤统一经过 preflight、commit、result，形成判定、结果和 lineage；失败步骤不计入可信历史，重复执行同一恢复记录被拒绝。
- 先决条件补齐后状态为 `ready_to_retry`，原退款仍未执行。前端可在同一 trace 内明确重新提交原操作，并再次通过网关判定；定向测试覆盖重试前后状态。
- 此闭环目前只证明受控沙箱退款案例。Strict 自动恢复仍关闭，真实 MCP 恢复算子、可信脱敏、人工审批暂停恢复、任务效用 oracle 和正式完成率实验仍缺，M5 Gate 未通过。

## 追加实施：退款时序的对象绑定

- 退款判定现在要求已完成的身份核验与订单核验都返回成功结果，且工具类型、订单 ID 和 Agent 与当前退款一致；不同订单或不同 Agent 的历史不能借用，缺订单 ID 的退款拒绝。
- 恢复搜索使用显式标记的假设事件寻找候选，但运行时只接受实际完成事件。恢复执行后的重检保留原 Agent 身份。
- V3 100 条候选 Benchmark 中的 12 条时序样本已机械升级为带订单 ID 和结构化成功结果的合成事件；manifest SHA-256 已同步。标签仍待独立人工审核，不能把当前回归准确率当成正式测试集成绩。

## 追加实施：可签名证据与并发审计

- `AGENTGUARD_EVIDENCE_SIGNING_KEY_FILE` 配置 Ed25519 私钥后，Evidence Bundle 对完整导出对象签名；共享模块与离线 CLI 使用预先信任的公钥验证摘要、审计状态和签名。无密钥时明确标为未签名。
- 审计追加使用数据库链头版本比较和重试；SQLite 线程及多进程并发测试确认不分叉。审计中心的 `verify-chain` API 已复用统一的 v2/legacy 验证器。
- 当前环境后端 65 passed、1 skipped，另有 Cisco 扫描器测试因 `litellm` 依赖缺失未运行；前端构建通过。生产密钥保管、跨数据库并发验收、业务与审计同事务、外部独立验证仍待完成，M7 Gate 未通过。

## 追加实施：可追溯实验运行

- Benchmark evaluate/runs 现在实际执行并将配置、结果及证据文件写入持久化运行记录；metrics/failures 按 run ID 读取同一份快照，未知 ID 返回 404。
- Experiment 创建为 draft，运行时真实计算 runtime/compiler 消融并保存结果；compare/configs 的 GET 路由已放在动态实验 ID 路由之前，避免前端请求被误匹配。
- 实验配置创建和图表生成已接入真实持久化配置及运行结果；完整 M6/M7 验收仍未通过。

## 追加实施：Benchmark 草稿与冻结门槛

- 自建 Benchmark 的场景写入数据库，运行只读取对应集合并记录场景 SHA-256；新增场景需通过单项结构和标注一致性校验，重复 ID 被拒绝。
- Validate 返回实际的 schema、重复内容、标注一致性和模板族跨 split 检查结果；Freeze 要求整体校验通过且 500–800 条，未达标返回 409。
- 内置 V3 100 条仍为只读候选集，不能被 API 冻结。自动校验不能证明 reviewer 身份或完成独立人工复核，M6 Gate 仍未通过。

## 追加实施：实验配置快照与图表

- 实验配置创建后持久化为不可变快照；按 `config_id` 运行时拒绝与快照冲突的参数，并在运行配置里记录所用 ID。
- 图表接口从已保存运行结果生成 SVG，不再为未知 run ID 返回虚构图表。当前图表为单指标比较，完整多指标报告和外部复现仍待实施。
