# 开源项目迁移与接入状态

此处“迁移”指通过依赖、外部进程、协议适配或基线接入；原仓库不复制到本项目。版本只记录本环境验证过的版本；未实测项不标成已接入。

| 上游 | 使用方式 | 实际状态 |
| --- | --- | --- |
| modelcontextprotocol/python-sdk | mcp 2.2.0 SDK，stdio 和 HTTP | 本地 stdio/HTTP fixture 实际调用通过，非独立第三方服务 |
| stacklok/toolhive | 外部代理的 validating webhook v0.1.0；配置片段 | 协议适配及测试；容器未部署 |
| cedar-policy/cedar | 独立 Cedar CLI 4.13.0 | 授权子集执行，CLI 未打包 |
| Z3Prover/z3 | z3-solver 5.1.0.0 | 真实 witness 测试 |
| cisco-ai-defense/mcp-scanner | cisco-ai-mcp-scanner 4.8.4 | 本地 fixture 的 YARA-only 扫描 |
| networkx/networkx | networkx 3.7 | 本地图推理测试 |
| neo4j/neo4j-python-driver | neo4j 6.3.1 已安装 | 数据库未部署，驱动未接线 |
| langchain-ai/langgraph | langgraph 1.2.12 | 建议计划状态图，自动执行未启用 |
| open-telemetry/opentelemetry-python | opentelemetry-sdk 1.44.0 | 基础 span；跨服务 trace 未验收 |
| ethz-spylab/agentdojo | agentdojo 0.1.35 已安装 | 真实 ToolsExecutor/FunctionsRuntime 适配及局部测试；完整外部任务未运行 |
| Arize-ai/phoenix | 外部研发服务 | 未部署，且不并入代码 |
| invariantlabs-ai/invariant | 独立基线 | 未运行 |
| promptfoo/promptfoo 与 evil-mcp-server | 独立红队基线 | 未安装/运行 |
| open-policy-agent/opa | 可选策略后端 | 未接入 |

许可证及版本需逐个复核上游正式发布资产；第三方源代码、攻击案例和官方数据集均未并入原创代码或案例。尚无用户目标 GitHub 仓库地址和发布权限，因此未推送至用户 GitHub。
