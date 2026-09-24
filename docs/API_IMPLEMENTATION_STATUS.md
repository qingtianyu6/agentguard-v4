# AgentGuard API Implementation Status — V3.0

## Compatibility

- Original API design HTTP operations: **113**
- AgentGuard V3 HTTP operations: **131**
- Missing original operations: **0**

## V3 Additive APIs

主要新增：

- `GET /api/v1/compiler/providers`
- `POST /api/v1/compiler/extract`
- `POST /api/v1/compiler/formal-ir`
- `POST /api/v1/compiler/model-check`
- `POST /api/v1/compiler/compile-v3`
- `GET /api/v1/research/manifest`
- `POST /api/v1/research/compiler-benchmark`
- `POST /api/v1/research/compiler-ablation`
- `POST /api/v1/research/runtime-ablation`
- `POST /api/v1/research/full-suite`

以及原 V2 兼容路由、WebSocket 和 SSE。

完整规范：

- `docs/02_protocol/openapi-v3.json`
- `docs/02_protocol/openapi-v3.yaml`
