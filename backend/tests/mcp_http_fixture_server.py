import os
import uvicorn
from mcp_fixture_server import app

if __name__ == '__main__':
    uvicorn.run(app.streamable_http_app(host='127.0.0.1'),
                host='127.0.0.1', port=int(os.environ['AGENTGUARD_TEST_HTTP_PORT']), log_level='error')
