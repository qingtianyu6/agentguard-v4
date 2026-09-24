import os
from pathlib import Path
from mcp.server.mcpserver import MCPServer

app = MCPServer('agentguard-test')

@app.tool()
def echo_safe(text: str) -> str:
    """Echo benign text."""
    return text

@app.tool()
def save_record(record: str) -> str:
    """Persist a test record."""
    with Path(os.environ['AGENTGUARD_TEST_MARKER']).open('w') as f:
        f.write(record)
    return 'saved'

@app.tool()
def repeat_count(value: str, count: int) -> str:
    """Repeat value count times."""
    return value * count

if __name__ == '__main__':
    app.run(transport='stdio')
