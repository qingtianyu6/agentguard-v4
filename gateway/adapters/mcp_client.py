"""Guarded client for real MCP servers; transport access is held by this client."""
from __future__ import annotations
from contextlib import asynccontextmanager
from typing import Any, AsyncIterator
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.client.streamable_http import streamable_http_client
from services.trust_registry.registry import ToolTrustRegistry, fingerprint
from observability.otel import decision_span

class GuardDenied(Exception):
    pass

class GuardedMCPClient:
    def __init__(self, session: ClientSession, server_id: str, registry: ToolTrustRegistry, decide, lifecycle=None):
        self.session, self.server_id, self.registry, self.decide = session, server_id, registry, decide
        self.lifecycle = lifecycle

    async def list_tools(self):
        return (await self.session.list_tools()).tools

    async def call_tool(self, name: str, arguments: dict[str, Any], context: dict[str, Any]):
        tools = {t.name: t for t in await self.list_tools()}
        tool = tools.get(name)
        if tool is None:
            raise GuardDenied('UNKNOWN_TOOL')
        schema = tool.input_schema
        trusted, reason = self.registry.check(self.server_id, name, tool.description or '', schema)
        if not trusted:
            raise GuardDenied(reason)
        with decision_span(str(context.get('trace_id', '')), self.server_id, name) as span:
            verdict = await self.decide({**context, 'server_id': self.server_id, 'tool_id': name,
                                         'tool_description_hash': fingerprint(tool.description or ''),
                                         'tool_schema_hash': fingerprint(schema), 'args': arguments})
            span.set_attribute('agentguard.decision', str(verdict.get('decision', 'UNKNOWN')))
            if verdict.get('decision') != 'ALLOW':
                raise GuardDenied(verdict.get('decision', 'UNVERIFIED_DECISION'))
            if self.lifecycle:
                await self.lifecycle.commit(verdict)
            try:
                result = await self.session.call_tool(name, arguments)
            except Exception:
                if self.lifecycle:
                    await self.lifecycle.abort(verdict)
                raise
            span.set_attribute('agentguard.tool_error', bool(result.is_error))
            recorded = await self.lifecycle.record_result(verdict, result) if self.lifecycle else None
        return {'trace_id': context.get('trace_id'), 'decision': verdict, 'result': result,
                'result_ref': recorded.get('result_ref') if recorded else None}

@asynccontextmanager
async def connect_stdio(command: str, args: list[str], server_id: str, registry: ToolTrustRegistry, decide,
                        env: dict[str, str] | None = None, lifecycle=None) -> AsyncIterator[GuardedMCPClient]:
    params = StdioServerParameters(command=command, args=args, env=env)
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield GuardedMCPClient(session, server_id, registry, decide, lifecycle)

@asynccontextmanager
async def connect_http(url: str, server_id: str, registry: ToolTrustRegistry, decide, lifecycle=None) -> AsyncIterator[GuardedMCPClient]:
    async with streamable_http_client(url) as streams:
        read, write = streams[0], streams[1]
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield GuardedMCPClient(session, server_id, registry, decide, lifecycle)
