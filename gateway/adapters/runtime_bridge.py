"""Connect guarded MCP calls to the runtime decision and result APIs."""
from __future__ import annotations

from typing import Any

import httpx


class GatewayRuntimeBridge:
    def __init__(self, client: httpx.AsyncClient, token: str | None = None):
        self.client = client
        self.headers = {'x-agentguard-token': token} if token else {}

    async def _post(self, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
        response = await self.client.post(path, json=body or {}, headers=self.headers)
        response.raise_for_status()
        return response.json()['data']

    async def preflight(self, action: dict[str, Any]) -> dict[str, Any]:
        return await self._post('/gateway/v1/actions/preflight', action)

    async def commit(self, verdict: dict[str, Any]) -> None:
        await self._post(f"/gateway/v1/actions/{verdict['action_id']}/commit")

    async def abort(self, verdict: dict[str, Any]) -> None:
        await self._post(f"/gateway/v1/actions/{verdict['action_id']}/abort")

    async def record_result(self, verdict: dict[str, Any], result: Any) -> dict[str, Any]:
        payload = result.model_dump(mode='json')
        return await self._post(f"/gateway/v1/actions/{verdict['action_id']}/result",
                                {'result': {'ok': not result.is_error, 'mcp_result': payload}})
