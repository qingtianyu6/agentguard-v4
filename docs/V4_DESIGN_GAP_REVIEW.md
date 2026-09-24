# V4.0 设计书与代码对照（2026-09-23）

依据 `01-AgentGuard_-_V4.0.docx` 第六部分的 M0–M8 Stage Gate 审查；状态反映实际运行证据，不将接口存在等同于验收完成。

| 阶段 | 已有实现或证据 | 尚未达到设计书验收的关键项 | Gate |
| --- | --- | --- | --- |
| M0 | Event/Contract/Tool schema，威胁模型，40 个后端回归测试 | 统一 Contract IR 并贯穿全业务、完整第三方版本/许可证锁及 Benchmark schema 冻结 | 未通过 |
| M1 | 官方 MCP SDK stdio 三工具 fixture 可阻止危险调用；ToolHive validating webhook v0.1.0 适配及 HMAC 校验 | 真实独立三服务、第三方 HTTP 实例和 ToolHive 端到端代理、trace 一致性、物理网络/凭据隔离 | 未通过 |
| M2 | 指纹/隔离核心逻辑、Cisco Scanner YARA-only 本地 fixture 扫描 | 受控 drift 统计与每服务注册前扫描、隔离工具经实际网关不可调用 | 未通过 |
| M3 | Native 约束、Z3 witness、Cedar CLI 授权子集 | ≥100 人工真值规则、语义准确率/召回率和语义修复闭环、SymCC | 未通过 |
| M4 | provenance/taint、NetworkX、衍生敏感信息案例、已完成结果入历史 | 真实 MCP 输出统一入 Event Store、跨 Agent 等各组测试及检测增益/FPR 实测 | 未通过 |
| M5 | 约束候选搜索和验证接口；不可靠执行保持关闭 | 任务效用的真实 oracle、完整审批暂停恢复、安全与完成率实验 | 未通过 |
| M6 | V3 100 条场景及完整性检查 | 500–800 高质量案例、≥200 人工核心案例、公开外部基准实跑 | 未通过 |
| M7 | OTel 基本 span、真实判定时延、hash run manifest 和审计链校验 | 包含持久工具指纹、签名和跨服务验证的完整 Evidence Bundle、可复现实验链、端到端性能测量 | 未通过 |
| M8 | 六页原型，前端编译通过 | 连续三场 Demo、许可证/原创日志和竞赛交付冻结 | 未通过 |

此次代码修复：严格模式未知 tool/action 的 preflight DENY，ToolHive webhook 只接受与动作匹配的已审核活动契约；后端当时 49 passed。仍须部署和独立测试，不能将单元测试结果外推为 M1 Gate 通过。现已创建公开仓库并同步源码；当前工程状态以 `IMPLEMENTATION_STATUS.md` 和实际测试为准。
