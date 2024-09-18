from quart import Quart, request, jsonify
from quart_cors import cors
from functools import wraps
import logging
import os
import json
from typing import Dict, Any, List
from iptables_manager import IPTablesManager
from system_manager import SystemManager
from application_manager import ApplicationManager
from agent_initializer import AgentInitializer
import asyncio

app = Quart(__name__)
app = cors(app, allow_origin="*")

logging.basicConfig(filename='agent.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

iptables_manager = IPTablesManager()
system_manager = SystemManager()
app_manager = ApplicationManager()
agent_initializer = AgentInitializer(iptables_manager)

def require_api_key(f):
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key != os.environ.get('API_KEY', 'alpha'):
            return jsonify({'error': 'Unauthorized'}), 401
        return await f(*args, **kwargs)
    return decorated_function

@app.before_serving
async def initialize_agent():
    await agent_initializer.initialize()
    connectivity = await agent_initializer.test_connectivity()
    if not connectivity:
        logger.error("Connectivity test failed after initialization. Exiting.")
        os._exit(1)
    logger.info("Agent initialized with default rules and passed connectivity test.")


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=25025, debug=True)