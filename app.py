"""
ServerControl - Backend Application
===================================
A Flask-based server management system with REST API
Author: ServerControl Team
Version: 1.0.0
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from functools import wraps
import json
import os
import random
import logging
from datetime import datetime
import hashlib

# ============================================
# FLASK APPLICATION INITIALIZATION
# ============================================

app = Flask(__name__)
# Secret key for session management - change this in production!
app.secret_key = 'servercontrol-secret-key-2024-change-me'

# ============================================
# CONFIGURATION
# ============================================

# File paths
SERVERS_FILE = 'servers.json'
LOG_DIR = 'logs'
LOG_FILE = os.path.join(LOG_DIR, 'server_actions.log')

# Authentication - Default password (change in production!)
ADMIN_PASSWORD = 'admin123'

# Create logs directory if it doesn't exist
os.makedirs(LOG_DIR, exist_ok=True)

# ============================================
# LOGGING SETUP
# ============================================

# Configure logging for server actions
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()  # Also print to console
    ]
)
logger = logging.getLogger('ServerControl')

# ============================================
# IN-MEMORY SERVER STATE STORAGE
# ============================================

# Dictionary to store current server states
# In production, this would be stored in a database
server_states = {}

# ============================================
# HELPER FUNCTIONS
# ============================================

def load_servers():
    """
    Load server configuration from JSON file.

    Returns:
        dict: Server configuration dictionary
    """
    try:
        with open(SERVERS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            logger.debug(f"Loaded {len(data.get('servers', []))} servers from config")
            return data
    except FileNotFoundError:
        logger.warning(f"Config file {SERVERS_FILE} not found, creating default")
        default_config = {"servers": []}
        save_servers(default_config)
        return default_config
    except json.JSONDecodeError as e:
        logger.error(f"Error parsing {SERVERS_FILE}: {e}")
        return {"servers": []}


def save_servers(data):
    """
    Save server configuration to JSON file.

    Args:
        data (dict): Server configuration to save
    """
    with open(SERVERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    logger.debug("Server configuration saved")


def init_server_states():
    """
    Initialize server states from configuration file.
    Sets up initial status, CPU, and RAM values for each server.
    """
    servers = load_servers()
    for server in servers.get('servers', []):
        server_id = server['id']
        if server_id not in server_states:
            # Initialize with config values or defaults
            initial_status = server.get('initial_status', 'offline')
            server_states[server_id] = {
                'status': initial_status,
                'cpu': random.randint(15, 45) if initial_status == 'online' else 0,
                'ram': random.randint(25, 55) if initial_status == 'online' else 0,
                'uptime': datetime.now().isoformat() if initial_status == 'online' else None
            }
    logger.info(f"Initialized states for {len(server_states)} servers")


def generate_mock_metrics(state):
    """
    Generate realistic-looking mock metrics for a server.
    Simulates CPU and RAM fluctuations.

    Args:
        state (dict): Current server state

    Returns:
        dict: Updated state with new metrics
    """
    if state['status'] == 'online':
        # Simulate realistic CPU fluctuation (+/- 15%)
        cpu_change = random.randint(-15, 15)
        state['cpu'] = max(5, min(95, state['cpu'] + cpu_change))

        # Simulate realistic RAM fluctuation (+/- 8%)
        ram_change = random.randint(-8, 8)
        state['ram'] = max(10, min(90, state['ram'] + ram_change))
    else:
        state['cpu'] = 0
        state['ram'] = 0

    return state


def log_action(action, server_name, details=None):
    """
    Log a server action to the log file.

    Args:
        action (str): Action performed (START, STOP, RESTART)
        server_name (str): Name of the server
        details (str, optional): Additional details
    """
    message = f"ACTION: {action} | SERVER: {server_name}"
    if details:
        message += f" | DETAILS: {details}"
    logger.info(message)


# ============================================
# AUTHENTICATION DECORATOR
# ============================================

def login_required(f):
    """
    Decorator that requires user authentication.
    Redirects to login page or returns 401 for API calls.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session or not session['logged_in']:
            # Check if it's an API request
            if request.path.startswith('/api/'):
                return jsonify({
                    'error': 'Unauthorized',
                    'message': 'Please login to access this resource'
                }), 401
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# ============================================
# WEB ROUTES
# ============================================

@app.route('/')
@login_required
def index():
    """
    Main dashboard page.
    Requires authentication.
    """
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Login page and authentication handler.

    GET: Display login page
    POST: Process login attempt
    """
    # If already logged in, redirect to dashboard
    if session.get('logged_in'):
        return redirect(url_for('index'))

    if request.method == 'POST':
        # Get password from JSON or form data
        if request.is_json:
            data = request.get_json()
            password = data.get('password', '')
        else:
            password = request.form.get('password', '')

        # Verify password
        if password == ADMIN_PASSWORD:
            session['logged_in'] = True
            session['login_time'] = datetime.now().isoformat()
            logger.info(f"Successful login from {request.remote_addr}")

            if request.is_json:
                return jsonify({
                    'success': True,
                    'message': 'Login successful'
                })
            return redirect(url_for('index'))
        else:
            logger.warning(f"Failed login attempt from {request.remote_addr}")

            if request.is_json:
                return jsonify({
                    'success': False,
                    'error': 'Invalid password'
                }), 401
            return render_template('login.html', error='Invalid password')

    return render_template('login.html')


@app.route('/logout')
def logout():
    """
    Logout user and clear session.
    """
    session.clear()
    logger.info(f"User logged out from {request.remote_addr}")
    return redirect(url_for('login'))


# ============================================
# REST API ROUTES
# ============================================

@app.route('/api/servers', methods=['GET'])
@login_required
def get_servers():
    """
    Get list of all servers with their current status.

    Returns:
        JSON array of server objects with status, CPU, and RAM
    """
    # Ensure states are initialized
    init_server_states()

    # Load server configurations
    servers_config = load_servers()

    result = []
    for server in servers_config.get('servers', []):
        server_id = server['id']

        # Get current state or create default
        state = server_states.get(server_id, {
            'status': 'offline',
            'cpu': 0,
            'ram': 0,
            'uptime': None
        })

        # Generate mock metrics for online servers
        state = generate_mock_metrics(state)
        server_states[server_id] = state

        # Build response object
        result.append({
            'id': server_id,
            'name': server['name'],
            'ip': server.get('ip', 'N/A'),
            'type': server.get('type', 'Unknown'),
            'description': server.get('description', ''),
            'status': state['status'],
            'cpu': state['cpu'],
            'ram': state['ram'],
            'uptime': state.get('uptime')
        })

    return jsonify(result)


@app.route('/api/servers/<server_id>', methods=['GET'])
@login_required
def get_server(server_id):
    """
    Get details of a specific server.

    Args:
        server_id: Unique server identifier

    Returns:
        JSON object with server details and status
    """
    init_server_states()

    servers_config = load_servers()
    server = next(
        (s for s in servers_config.get('servers', []) if s['id'] == server_id),
        None
    )

    if not server:
        return jsonify({
            'error': 'Server not found',
            'server_id': server_id
        }), 404

    state = server_states.get(server_id, {
        'status': 'offline',
        'cpu': 0,
        'ram': 0
    })

    return jsonify({
        'id': server_id,
        'name': server['name'],
        'ip': server.get('ip', 'N/A'),
        'type': server.get('type', 'Unknown'),
        'status': state['status'],
        'cpu': state['cpu'],
        'ram': state['ram']
    })


@app.route('/api/servers/<server_id>/start', methods=['POST'])
@login_required
def start_server(server_id):
    """
    Start a server.

    Args:
        server_id: Unique server identifier

    Returns:
        JSON object with operation result
    """
    init_server_states()

    # Check if server exists
    servers_config = load_servers()
    server = next(
        (s for s in servers_config.get('servers', []) if s['id'] == server_id),
        None
    )

    if not server:
        return jsonify({
            'success': False,
            'error': 'Server not found'
        }), 404

    # Check if already online
    if server_states.get(server_id, {}).get('status') == 'online':
        return jsonify({
            'success': False,
            'error': 'Server is already running'
        }), 400

    # Start the server (mock)
    server_states[server_id] = {
        'status': 'online',
        'cpu': random.randint(10, 25),
        'ram': random.randint(20, 35),
        'uptime': datetime.now().isoformat()
    }

    # Log the action
    log_action('START', server['name'], f"Server started by user")

    return jsonify({
        'success': True,
        'message': f"Server '{server['name']}' started successfully",
        'server_id': server_id,
        'status': 'online'
    })


@app.route('/api/servers/<server_id>/stop', methods=['POST'])
@login_required
def stop_server(server_id):
    """
    Stop a server.

    Args:
        server_id: Unique server identifier

    Returns:
        JSON object with operation result
    """
    init_server_states()

    # Check if server exists
    servers_config = load_servers()
    server = next(
        (s for s in servers_config.get('servers', []) if s['id'] == server_id),
        None
    )

    if not server:
        return jsonify({
            'success': False,
            'error': 'Server not found'
        }), 404

    # Check if already offline
    if server_states.get(server_id, {}).get('status') == 'offline':
        return jsonify({
            'success': False,
            'error': 'Server is already stopped'
        }), 400

    # Stop the server (mock)
    server_states[server_id] = {
        'status': 'offline',
        'cpu': 0,
        'ram': 0,
        'uptime': None
    }

    # Log the action
    log_action('STOP', server['name'], f"Server stopped by user")

    return jsonify({
        'success': True,
        'message': f"Server '{server['name']}' stopped successfully",
        'server_id': server_id,
        'status': 'offline'
    })


@app.route('/api/servers/<server_id>/restart', methods=['POST'])
@login_required
def restart_server(server_id):
    """
    Restart a server.

    Args:
        server_id: Unique server identifier

    Returns:
        JSON object with operation result
    """
    init_server_states()

    # Check if server exists
    servers_config = load_servers()
    server = next(
        (s for s in servers_config.get('servers', []) if s['id'] == server_id),
        None
    )

    if not server:
        return jsonify({
            'success': False,
            'error': 'Server not found'
        }), 404

    # Restart the server (mock)
    server_states[server_id] = {
        'status': 'online',
        'cpu': random.randint(10, 25),
        'ram': random.randint(20, 35),
        'uptime': datetime.now().isoformat()
    }

    # Log the action
    log_action('RESTART', server['name'], f"Server restarted by user")

    return jsonify({
        'success': True,
        'message': f"Server '{server['name']}' restarted successfully",
        'server_id': server_id,
        'status': 'online'
    })


@app.route('/api/servers/<server_id>/status', methods=['GET'])
@login_required
def get_server_status(server_id):
    """
    Get current status of a specific server.

    Args:
        server_id: Unique server identifier

    Returns:
        JSON object with server status information
    """
    init_server_states()

    if server_id not in server_states:
        return jsonify({
            'error': 'Server not found'
        }), 404

    state = server_states[server_id]
    state = generate_mock_metrics(state)

    return jsonify({
        'server_id': server_id,
        'status': state['status'],
        'cpu': state['cpu'],
        'ram': state['ram'],
        'uptime': state.get('uptime')
    })


@app.route('/api/logs', methods=['GET'])
@login_required
def get_logs():
    """
    Get recent action logs.

    Returns:
        JSON array of recent log entries
    """
    try:
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            # Return last 50 log entries
            return jsonify({
                'logs': lines[-50:] if len(lines) > 50 else lines
            })
    except FileNotFoundError:
        return jsonify({'logs': []})


# ============================================
# ERROR HANDLERS
# ============================================

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Resource not found'}), 404
    return render_template('login.html', error='Page not found'), 404


@app.errorhandler(500)
def server_error(e):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {e}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('login.html', error='Server error'), 500


# ============================================
# APPLICATION ENTRY POINT
# ============================================

if __name__ == '__main__':
    # Initialize server states on startup
    init_server_states()

    # Print startup banner
    print("\n" + "=" * 60)
    print("  ⚡ ServerControl - Server Management Dashboard")
    print("=" * 60)
    print(f"  🌐 URL:      http://127.0.0.1:5000")
    print(f"  🔑 Password: {ADMIN_PASSWORD}")
    print(f"  📁 Logs:     {LOG_FILE}")
    print(f"  📋 Config:   {SERVERS_FILE}")
    print("=" * 60)
    print("  Press Ctrl+C to stop the server")
    print("=" * 60 + "\n")

    # Run the Flask application
    app.run(
        debug=True,
        host='127.0.0.1',
        port=5000,
        threaded=True
    )