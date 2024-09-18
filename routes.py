from quart import jsonify, request
from utils import require_api_key, validate_rule_data
import logging

logger = logging.getLogger(__name__)



def register_routes(app, iptables_manager, system_manager, app_manager):
    @app.route('/')
    async def agent_status():
        status = await agent_initializer.get_initial_status()
        return jsonify(status)

    @app.route('/reset', methods=['POST'])
    @require_api_key
    async def reset_agent():
        await agent_initializer.initialize()
        connectivity = await agent_initializer.test_connectivity()
        if not connectivity:
            await agent_initializer._rollback()
            return jsonify({"error": "Reset failed connectivity test. Rolled back to previous rules."}), 500
        return jsonify({"message": "Agent reset successfully"})

    @app.route('/apply-rules', methods=['POST'])
    @require_api_key
    async def apply_rules():
        rules = (await request.json).get('rules', [])
        if not rules:
            return jsonify({'error': 'No rules provided'}), 400

        results = []
        for rule in rules:
            errors = validate_rule_data(rule, ['protocol', 'port', 'action'])
            if errors:
                results.append({'rule': rule, 'success': False, 'errors': errors})
            else:
                try:
                    success = await iptables_manager.add_rule(
                        protocol=rule['protocol'],
                        port=rule['port'],
                        action=rule['action'],
                        chain=rule.get('chain', 'INPUT'),
                        source_ip=rule.get('source_ip'),
                        destination_ip=rule.get('destination_ip'),
                        table=rule.get('table', 'filter')
                    )
                    results.append({'rule': rule, 'success': success})
                except Exception as e:
                    results.append({'rule': rule, 'success': False, 'error': str(e)})

        return jsonify({'status': 'completed', 'results': results})

    @app.route('/iptables_rules')
    @require_api_key
    async def get_iptables_rules_route():
        try:
            rules = await iptables_manager.get_rules()
            return jsonify({
                'status': 'success',
                'rules': rules
            })
        except Exception as e:
            logger.error(f"Unexpected error in get_iptables_rules route: {e}")
            return jsonify({
                'status': 'error',
                'message': 'An unexpected error occurred while retrieving iptables rules',
                'error': str(e)
            }), 500

    @app.route('/processes')
    @require_api_key
    async def get_processes():
        processes = await system_manager.get_running_processes()
        return jsonify(processes)

    @app.route('/add_user', methods=['POST'])
    @require_api_key
    async def add_user_route():
        data = await request.json
        username = data.get('username')
        password = data.get('password')
        groups = data.get('groups', [])

        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        success, message = await system_manager.add_user(username, password, groups)
        return jsonify({'message': message}), 200 if success else 400

    @app.route('/remove_user', methods=['POST'])
    @require_api_key
    async def remove_user_route():
        data = await request.json
        username = data.get('username')
        if not username:
            return jsonify({'error': 'Username is required'}), 400

        success, message = await system_manager.remove_user(username)
        return jsonify({'message': message}), 200 if success else 400

    @app.route('/users', methods=['GET'])
    @require_api_key
    async def get_users_route():
        users = await system_manager.get_non_default_users()
        return jsonify({'users': users})

    @app.route('/applications')
    @require_api_key
    async def get_applications():
        try:
            applications = await app_manager.get_installed_applications()
            return jsonify({
                'status': 'success',
                'count': len(applications),
                'applications': applications
            })
        except Exception as e:
            logger.error(f"Error in get_applications route: {e}")
            return jsonify({
                'status': 'error',
                'message': 'An error occurred while retrieving installed applications',
                'error': str(e)
            }), 500


    @app.route('/block_port', methods=['POST'])
    @require_api_key
    async def block_port():
        data = await request.json
        port = data.get('port')
        protocol = data.get('protocol', 'tcp')
        chain = data.get('chain', 'INPUT')

        if not port:
            return jsonify({"error": "Port is required"}), 400

        try:
            port = int(port)
        except ValueError:
            return jsonify({"error": "Port must be an integer"}), 400

        success = await iptables_manager.block_port(port, protocol, chain)
        if success:
            return jsonify({"message": f"Successfully blocked {protocol} port {port} on chain {chain}"}), 200
        else:
            return jsonify({"error": f"Failed to block {protocol} port {port} on chain {chain}"}), 500

    @app.route('/allow_port', methods=['POST'])
    @require_api_key
    async def allow_port():
        data = await request.json
        port = data.get('port')
        protocol = data.get('protocol', 'tcp')
        chain = data.get('chain', 'INPUT')

        if not port:
            return jsonify({"error": "Port is required"}), 400

        try:
            port = int(port)
        except ValueError:
            return jsonify({"error": "Port must be an integer"}), 400

        success = await iptables_manager.allow_port(port, protocol, chain)
        if success:
            return jsonify({"message": f"Successfully allowed {protocol} port {port} on chain {chain}"}), 200
        else:
            return jsonify({"error": f"Failed to allow {protocol} port {port} on chain {chain}"}), 500