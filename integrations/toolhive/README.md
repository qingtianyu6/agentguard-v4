# ToolHive integration (sidecar, source not vendored)

Based on ToolHive source commit `2b299c1f48ad3b64aadceb5bf89582ff686f590a`. Merge `configs/validating-webhook.fragment.json` into a ToolHive workload RunConfig. Provision the same HMAC bytes as ToolHive's absolute secret file and the AgentGuard `AGENTGUARD_TOOLHIVE_WEBHOOK_SECRET`. The URL must be reachable over TLS from the ToolHive proxy. Enable strict profile, register approved `server_name/tool_name` and `server_name/resources/read` identifiers in `AGENTGUARD_TOOLHIVE_ALLOWED_TOOLS`, and activate reviewed policies. Configure and test ToolHive independently; this workspace has no Docker/Podman. The fragment is configuration source, not evidence of deployment. See `gateway/adapters/TOOLHIVE_WEBHOOK.md`.

Do not distribute ToolHive source as AgentGuard's implementation. ToolHive's Apache-2.0 license remains with ToolHive; AgentGuard implements only a separate validating endpoint.
