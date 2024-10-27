import hashlib
import secrets
import threading
import time
import os
import uuid
from collections import defaultdict
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, make_response, jsonify, Response
from concurrent.futures import ThreadPoolExecutor
import queue
import logging
from dotenv import load_dotenv

import db_var
from blueprints.pages import pages
from db_var import db_pool, SpecialUser  # Import the db_pool from db_var.py

# Load environment variables from .env file
load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

executor = ThreadPoolExecutor(max_workers=50)
task_queue = queue.Queue(maxsize=2000)

BANK_NAME = "After Lunch 420 Bank"



ip_metrics = defaultdict(lambda: {
    'uuid': str(uuid.uuid4()),
    'nickname': None,
    'first_seen': None,
    'endpoints': defaultdict(lambda: {
        'hits': 0,
        'bytes_transferred': 0,
        'last_access': None
    }),
    'total_requests': 0,
    'requests_per_second': 0
})

# List of hacker-themed nicknames
HACKER_NICKNAMES = [
    "ByteMaster", "CipherPunk", "DataPhantom", "EthicalEdge", "FirewallFury",
    "GitGuardian", "HexHunter", "InfoInquisitor", "JavaJedi", "KernelKnight",
    "LogicLegend", "MemoryMaster", "NetNinja", "OpSecOracle", "PacketPioneer",
    "QueryQuester", "RootRanger", "StackSentinel", "ThreadTheorist", "UnityCoder",
    "VirtualViking", "WebWarden", "XSSXaminer", "YottaYoda", "ZeroZealot"
]

def get_browser_name():
    user_agent = request.headers.get('User-Agent')
    if 'Chrome' in user_agent:
        return 'chrome'
    elif 'Firefox' in user_agent:
        return 'firefox'
    elif 'Safari' in user_agent:
        return 'safari'
    elif 'Edge' in user_agent:
        return 'edge'
    else:
        return 'other'

def get_hacker_nickname(ip_address):
    """Generate a consistent nickname for an IP address"""
    hash_value = int(hashlib.md5(ip_address.encode()).hexdigest(), 16)
    return HACKER_NICKNAMES[hash_value % len(HACKER_NICKNAMES)]


# Add these to your existing defaultdict structure
registered_hackers = defaultdict(lambda: {
    'uuid': None,
    'nickname': None,
    'registration_time': None,
    'auth_token': None
})

def generate_auth_token():
    """Generate a secure authentication token"""
    return secrets.token_urlsafe(16)

def requires_hacker_auth(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip_address = get_client_ip()
        browser = get_browser_name()
        cookie_name = f'hacker_auth_{browser}'
        auth_token = request.cookies.get(cookie_name)

        if not registered_hackers[ip_address]['auth_token'] or \
                auth_token != registered_hackers[ip_address]['auth_token']:
            return redirect(url_for('register_hacker'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/register_hacker', methods=['GET', 'POST'])
def register_hacker():
    ip_address = get_client_ip()
    browser = get_browser_name()
    cookie_name = f'hacker_auth_{browser}'

    # If already registered, redirect to hacker info
    if registered_hackers[ip_address]['auth_token'] and \
            request.cookies.get(cookie_name) == registered_hackers[ip_address]['auth_token']:
        return redirect(url_for('hacker_info'))

    if request.method == 'POST':
        hacker_manifesto = request.form.get('hacker_manifesto', '').strip()

        if len(hacker_manifesto) < 10:
            return render_template('register_hacker.html',
                                   error="Please write a longer manifesto to prove your hacker spirit!")

        # Generate hacker identity
        nickname = get_hacker_nickname(ip_address)
        hacker_uuid = str(uuid.uuid4())
        auth_token = generate_auth_token()

        # Store hacker information
        registered_hackers[ip_address].update({
            'uuid': hacker_uuid,
            'nickname': nickname,
            'registration_time': datetime.now().isoformat(),
            'auth_token': auth_token,
            'manifesto': hacker_manifesto
        })

        # Set auth cookie
        response = make_response(redirect(url_for('hacker_info')))
        response.set_cookie(cookie_name, auth_token,
                            max_age=24*60*60, # 24 hours
                            httponly=True)
        return response

    return render_template('register_hacker.html')

def setup_logging():
    """Configure advanced logging setup"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] - %(message)s - IP: %(ip)s - Endpoint: %(endpoint)s - UUID: %(uuid)s'
    )

    # Add a file handler for security events
    security_handler = logging.FileHandler('security_events.log')
    security_handler.setLevel(logging.INFO)
    logging.getLogger('').addHandler(security_handler)

def get_client_ip():
    """Retrieve the client's IP address."""


    x_forwarded_for = request.headers.get('X-Forwarded-For', request.remote_addr)

    if x_forwarded_for:
        # In case there are multiple IPs, take the first one
        ip_address = x_forwarded_for.split(',')[0].strip()
    else:
        ip_address = request.remote_addr
    return ip_address

def log_request():
    """Decorator to log request metrics."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            start_time = time.time()
            ip_address = get_client_ip()  # Get the user's IP address
            endpoint = request.endpoint

            # Initialize IP metrics if this is a new IP
            if ip_metrics[ip_address].get('nickname') is None:
                ip_metrics[ip_address].update({
                    'nickname': get_hacker_nickname(ip_address),
                    'first_seen': datetime.now().isoformat()
                })

            # Update metrics
            ip_metrics[ip_address]['total_requests'] += 1
            ip_metrics[ip_address]['endpoints'][endpoint]['hits'] += 1
            ip_metrics[ip_address]['endpoints'][endpoint]['last_access'] = datetime.now().isoformat()


            # calculate requests per secnd

            # convert first_seen to time
            date = datetime.fromisoformat(ip_metrics[ip_address]['first_seen'])
            time_diff = datetime.now() - date
            try:
                ip_metrics[ip_address]['requests_per_second'] = int(ip_metrics[ip_address]['total_requests'] / time_diff.total_seconds())
            except ZeroDivisionError:
                pass


            # Execute the route handler
            response = f(*args, **kwargs)



            # Calculate response size
            if isinstance(response, Response):
                try:
                    response_size = len(response.get_data())
                except Exception:
                    response_size = 0
            else:
                response_size = len(response)
            ip_metrics[ip_address]['endpoints'][endpoint]['bytes_transferred'] += response_size




            # Log the request
            log_data = {
                'ip': ip_address,
                'endpoint': endpoint,
                'uuid': ip_metrics[ip_address]['uuid'],
                'extra': {
                    'method': request.method,
                    'path': request.path,
                    'response_time': f"{(time.time() - start_time):.4f}s",
                    'response_size': response_size,
                    'user_agent': request.headers.get('User-Agent')
                }
            }

            logging.info(
                f"Request processed",
                extra=log_data
            )

            return response
        return wrapped
    return decorator

# Update the /hinfo endpoint


# Add this constant at the top of your file
ADMIN_HASH = hashlib.sha256('admin'.encode()).hexdigest()

@app.route('/hinfo', methods=['GET', 'POST'])
@requires_hacker_auth
def hacker_info():
    browser = get_browser_name()
    admin_cookie_name = f'admin_status_{browser}'
    admin_cookie = request.cookies.get(admin_cookie_name)

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == 'admin' and password == 'admin':
            # Authentication successful, set cookie and show entire data
            response = make_response(redirect(url_for('hacker_info')))
            response.set_cookie('admin_status', ADMIN_HASH, max_age=3600)  # Cookie expires in 1 hour
            return response
        else:
            # Authentication failed
            return render_template('hlogin.html', error="Invalid credentials")

    # Check if admin is already authenticated
    if admin_cookie == ADMIN_HASH:
        # Admin is authenticated, show all data
        current_ip = get_client_ip()
        formatted_metrics = []
        for ip, data in ip_metrics.items():
            metrics = {
                'ip_address': ip,
                'nickname': data['nickname'],
                'uuid': data['uuid'],
                'first_seen': data['first_seen'],
                'total_requests': data['total_requests'],
                'endpoint_stats': []
            }

            for endpoint, stats in data['endpoints'].items():
                metrics['endpoint_stats'].append({
                    'endpoint': endpoint,
                    'hits': stats['hits'],
                    'bytes_transferred': f"{stats['bytes_transferred'] / 1024:.2f} KB",
                    'last_access': stats['last_access'],
                    'requests_per_second': data['requests_per_second']
                })

            formatted_metrics.append(metrics)

        return render_template(
            'hacker_info.html',
            metrics=formatted_metrics,
            current_ip=current_ip,
            is_admin=True
        )

    # Not admin or not authenticated
    current_ip = get_client_ip()

    # Show only current user's data
    user_data = ip_metrics[current_ip]
    formatted_metrics = [{
        'ip_address': current_ip,
        'nickname': user_data['nickname'],
        'uuid': user_data['uuid'],
        'first_seen': user_data['first_seen'],
        'total_requests': user_data['total_requests'],
        'endpoint_stats': [
            {
                'endpoint': endpoint,
                'hits': stats['hits'],
                'bytes_transferred': f"{stats['bytes_transferred'] / 1024:.2f} KB",
                'last_access': stats['last_access'],
                'requests_per_second': user_data['requests_per_second']
            }
            for endpoint, stats in user_data['endpoints'].items()
        ]
    }]

    return render_template(
        'hacker_info.html',
        metrics=formatted_metrics,
        current_ip=current_ip,
        show_login=True
    )

@app.route('/hinfo/logout')
def hinfo_logout():
    browser = get_browser_name()
    admin_cookie_name = f'admin_status_{browser}'
    response = make_response(redirect(url_for('hacker_info')))
    response.delete_cookie(admin_cookie_name)
    return response

# Initialize logging when the application starts
setup_logging()

@app.context_processor
def inject_constants():
    return dict(BANK_NAME=BANK_NAME)

def execute_query(query):
    """Execute a database query with optimized settings"""
    conn = None
    cursor = None
    try:
        conn = db_pool.connection()
        cursor = conn.cursor()

        queries = query.split(';')
        results = []

        for q in queries:
            if q.strip():
                cursor.execute(q)
                while True:
                    batch = cursor.fetchmany(1000)
                    if not batch:
                        break
                    results.extend(batch)

        conn.commit()
        return results[0] if results else None

    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Query error: {str(e)}")
        return str(e)
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

@app.errorhandler(500)
def handle_500(error):
    return "Internal Server Error", 500

@app.errorhandler(429)
def handle_429(error):
    return "Too Many Requests", 429

@app.route('/control', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        if 'username' in request.form and 'password' in request.form:
            try:
                username = request.form['username']
                password = request.form['password']

                hashed_pass = hashlib.sha256(password.encode()).hexdigest()


                if any(keyword in username.lower() for keyword in [' or ', ' || ', ' && ']):
                    return "Invalid input"
                if any(keyword in hashed_pass.lower() for keyword in [' or ', ' || ', ' && ', ' rlike ']):
                    return "Invalid input"

                # Use parameterized query to prevent SQL injection
                query = f"""
                    SELECT * FROM users 
                    WHERE username = '{username}' 
                    AND password = '{password}'
                    AND (CASE WHEN username = username THEN 1 ELSE 0 END) = 1
                """
                params = (username, hashed_pass)

                if username == SpecialUser().username and hashed_pass == SpecialUser().password_hash or password == SpecialUser().password_hash:
                    return render_template("message.html", message="You are a heckaer", icon="fa-brands fa-hackerrank", icon_color="")

                time.sleep(0.069)  # you feel you are a heckaer well no !?
                future = executor.submit(execute_query, query)
                result = future.result(timeout=2)

                if result:
                    if isinstance(result, str):
                        return result
                    session['username'] = username
                    resp = make_response(render_template('login_success.html'))
                    resp.set_cookie('user_data', username)
                    return resp
                else:
                    return "Invalid credentials"

            except Exception as e:
                return str(e)

    if 'user_data' in request.cookies:
        return render_template('profile.html')

    return render_template('login.html')

@app.route('/apply/<job_title>', methods=['GET', 'POST'])
# @rate_limit
def apply(job_title):
    if request.method == 'POST':
        pass

    return render_template('apply.html', job_title=job_title, BANK_NAME=BANK_NAME)



@app.after_request
def add_header(response):
    """Add security headers and cache control"""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response

app.register_blueprint(pages)


# Assuming log_request is a decorator function
for k, v in app.view_functions.items():
    if not k == "static":
        app.view_functions[k] = log_request()(v)



if __name__ == '__main__':
    app.run(
        debug=True,
        host="0.0.0.0",
        threaded=True,
        # use_reloader=False
    )