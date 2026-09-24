from pydantic import BaseModel, Field

class ToolIdentity(BaseModel):
    server_id: str
    tool_id: str
    description_hash: str
    schema_hash: str
    version: str = 'unknown'
    quarantined: bool = True
    scan_reference: str | None = None
    metadata: dict = Field(default_factory=dict)
