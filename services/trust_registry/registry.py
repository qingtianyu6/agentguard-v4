"""Fail-closed tool identity registry; scanner findings are externally supplied."""
from __future__ import annotations
from hashlib import sha256
import json
from shared.schemas.tool import ToolIdentity


def fingerprint(obj: object) -> str:
    return sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':'), default=str).encode()).hexdigest()

class ToolTrustRegistry:
    def __init__(self):
        self._tools: dict[tuple[str, str], ToolIdentity] = {}

    def register(self, server_id: str, tool_id: str, description: str, schema: dict, *, scan_reference: str | None = None) -> ToolIdentity:
        key = (server_id, tool_id)
        identity = ToolIdentity(server_id=server_id, tool_id=tool_id,
            description_hash=fingerprint(description), schema_hash=fingerprint(schema),
            quarantined=not bool(scan_reference), scan_reference=scan_reference)
        self._tools[key] = identity
        return identity

    def check(self, server_id: str, tool_id: str, description: str, schema: dict) -> tuple[bool, str]:
        t = self._tools.get((server_id, tool_id))
        if t is None: return False, 'UNKNOWN_TOOL'
        if t.quarantined: return False, 'QUARANTINED'
        if t.description_hash != fingerprint(description): return False, 'DESCRIPTION_DRIFT'
        if t.schema_hash != fingerprint(schema): return False, 'SCHEMA_DRIFT'
        return True, 'TRUSTED'
