"""Cisco MCP Scanner adapter for local stdio server registration."""
from __future__ import annotations
from hashlib import sha256
import json
from mcpscanner import Config, Scanner, AnalyzerEnum
from mcpscanner.core.mcp_models import StdioServer
from .registry import ToolTrustRegistry


async def scan_and_register(command: str, args: list[str], server_id: str,
                            registry: ToolTrustRegistry, tools: list,
                            *, timeout: int = 20) -> dict:
    results = await Scanner(Config()).scan_stdio_server_tools(
        StdioServer(command=command, args=args), analyzers=[AnalyzerEnum.YARA], timeout=timeout)
    report = []
    by_name = {}
    for r in results:
        findings = [f.model_dump(mode='json') if hasattr(f, 'model_dump') else vars(f) for f in r.findings]
        item = {'tool_name': r.tool_name, 'status': r.status, 'findings': findings,
                'analyzers': [str(a.value) for a in r.analyzers]}
        report.append(item)
        by_name[r.tool_name] = item
    report_hash = sha256(json.dumps(report, sort_keys=True, default=str).encode()).hexdigest()
    for tool in tools:
        item = by_name.get(tool.name)
        clean = item is not None and item['status'] == 'completed' and not item['findings']
        registry.register(server_id, tool.name, tool.description or '', tool.input_schema,
                          scan_reference=f'cisco:yara:{report_hash}' if clean else None)
    return {'server_id': server_id, 'scanner': 'cisco-ai-mcp-scanner',
            'analyzers': ['yara'], 'report_sha256': report_hash, 'results': report,
            'limitations': 'YARA-only result; does not prove tool implementation trustworthy'}
