# ToolHive validating webhook (experimental)

ToolHive's validating webhook v0.1.0 POSTs a JSON request with `uid`, `principal`, `context.server_name`, and the raw `mcp_request`. The AgentGuard endpoint is `/gateway/v1/toolhive/validate` and echoes `version`, `uid`, and `allowed`. Configure ToolHive's `validating-webhook` middleware with `failure_policy: fail`, a TLS URL, and `hmac_secret_ref`; use the same secret as `AGENTGUARD_TOOLHIVE_WEBHOOK_SECRET`. Requests must include ToolHive's HMAC SHA-256 headers. `AGENTGUARD_TOOLHIVE_ALLOWED_TOOLS` is a comma separated allowlist of `server_name/tool_name` identifiers. Set `AGENTGUARD_SECURITY_PROFILE=strict`, configure separate gateway and approver credentials, and activate reviewed contracts.

This adapter currently permits only authenticated `tools/call` and `resources/read` entries in the explicit allowlist after contract evaluation. It denies other methods, anonymous principals, absent contracts, uncertain outcomes, and policy ASK/REPAIR. ToolHive deployment and the actual end-to-end proxy path are unverified here. The webhook request does not contain server results, and this adapter has no authoritative cross-call history. Before production use, bind identities and sessions to trusted transport, persist completed results from the proxy, resolve tool argument schemas into typed resource/destination fields, and test the full proxy chain with container isolation and network credentials outside the agent.

Tool arguments cannot assert approver status or administrator role; trusted identity-to-role mapping remains a deployment requirement.

Strict profile persists webhook request UIDs and rejects duplicate signed requests; the replay table requires operational retention management.
