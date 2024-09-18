from functools import wraps
from quart import request, jsonify
import os
from typing import Dict, Any

def require_api_key(f):
    @wraps(f)
    async def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if api_key != os.environ.get('API_KEY', 'alpha'):
            return jsonify({'error': 'Unauthorized'}), 401
        return await f(*args, **kwargs)
    return decorated_function

def validate_rule_data(rule_data: Dict[str, Any], required_fields: list) -> Dict[str, Any]:
    errors = {}
    for field in required_fields:
        if field not in rule_data:
            errors[field] = f"Missing required field: {field}"
        elif field == 'port' and not isinstance(rule_data[field], int):
            errors[field] = "Port must be an integer"
        elif field == 'protocol' and rule_data[field] not in ['tcp', 'udp']:
            errors[field] = "Protocol must be 'tcp' or 'udp'"
    return errors