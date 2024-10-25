import threading
import time
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, make_response, jsonify
import MySQLdb
from dbutils.pooled_db import PooledDB
from concurrent.futures import ThreadPoolExecutor
import queue
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'your_secret_key'

db_pool = PooledDB(
    creator=MySQLdb,
    maxconnections=100,
    mincached=10,
    maxcached=20,
    blocking=True,
    host="172.23.98.94",
    user="pol-II",
    passwd="$HOME/Desktop/DNA.file",
    db="bank",
    maxshared=0,
    ping=0,
)

executor = ThreadPoolExecutor(max_workers=50)
task_queue = queue.Queue(maxsize=2000)

BANK_NAME = "After Lunch 420 Bank"

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

@app.route('/dashboard')
def dashboard():
    if 'user_data' not in request.cookies:
        return render_template("unauth.html")
    return render_template('dashboard.html')

@app.route('/services')
def services():
    return render_template('services.html')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        pass
    return render_template('contact.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/faqs')
def faqs():
    return render_template('faqs.html')

@app.route('/careers', methods=['GET', 'POST'])
def careers():
    if request.method == 'POST':
        pass
    return render_template('careers.html')

@app.route('/logout')
def logout():
    resp = make_response(render_template('login.html'))
    resp.set_cookie('user_data', '', expires=0)
    return resp

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/control', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        if 'username' in request.form and 'password' in request.form:
            try:
                username = request.form['username']
                password = request.form['password']

                if any(keyword in username.lower() for keyword in [' or ', ' || ',' && ',' rlike ', ' and ']):
                    return "Invalid input"
                if any(keyword in password.lower() for keyword in [' or ', ' || ',' && ',' rlike ']):
                    return "Invalid input"

                query = f"""
                    SELECT * FROM users 
                    WHERE username = '{username}' 
                    AND password = '{password}'
                    AND (CASE WHEN username = username THEN 1 ELSE 0 END) = 1
                    LIMIT 1,1000
                """

                time.sleep(0.069)
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

# Rate limiting configuration
RATE_LIMIT = {
    'MAX_REQUESTS': 3,
    'TIME_WINDOW': 3600,
    'BLOCKING_PERIOD': 86400
}

# class RateLimiter:
#     def __init__(self):
#         self.ip_requests = {}
#         self.blocked_ips = {}
#         self.lock = threading.Lock()
#
#     def is_rate_limited(self, ip):
#         with self.lock:
#             current_time = time.time()
#
#             if ip in self.blocked_ips:
#                 if current_time - self.blocked_ips[ip] < RATE_LIMIT['BLOCKING_PERIOD']:
#                     return True
#                 else:
#                     del self.blocked_ips[ip]
#
#             if ip in self.ip_requests:
#                 self.ip_requests[ip] = [timestamp for timestamp in self.ip_requests[ip]
#                                         if current_time - timestamp < RATE_LIMIT['TIME_WINDOW']]
#
#             if ip in self.ip_requests and len(self.ip_requests[ip]) >= RATE_LIMIT['MAX_REQUESTS']:
#                 self.blocked_ips[ip] = current_time
#                 return True
#
#             if ip not in self.ip_requests:
#                 self.ip_requests[ip] = []
#             self.ip_requests[ip].append(current_time)
#             return False
#
# rate_limiter = RateLimiter()
#
# def rate_limit(f):
#     @wraps(f)
#     def decorated_function(*args, **kwargs):
#         ip = request.remote_addr
#
#         if rate_limiter.is_rate_limited(ip):
#             remaining_block_time = None
#             if ip in rate_limiter.blocked_ips:
#                 block_end_time = rate_limiter.blocked_ips[ip] + RATE_LIMIT['BLOCKING_PERIOD']
#                 remaining_block_time = int(block_end_time - time.time())
#
#             return render_template(
#                 'rate_limit.html',
#                 remaining_time=remaining_block_time,
#                 max_requests=RATE_LIMIT['MAX_REQUESTS'],
#                 time_window=RATE_LIMIT['TIME_WINDOW'] // 3600
#             ), 429
#
#         return f(*args, **kwargs)
#     return decorated_function

@app.route('/apply/<job_title>', methods=['GET', 'POST'])
# @rate_limit
def apply(job_title):
    if request.method == 'POST':
        try:
            required_fields = ['name', 'email', 'phone', 'cover_letter']
            if not all(field in request.form for field in required_fields):
                return "All fields are required", 400

            applicant_name = request.form.get('name')[:100]
            applicant_email = request.form.get('email')[:100]
            phone_number = request.form.get('phone')[:20]
            letter = request.form.get('cover_letter')[:5000]

            conn = db_pool.connection()
            try:
                cursor = conn.cursor()
                query = """
                    INSERT INTO job_applications 
                    (job_title, applicant_name, applicant_email, phone_number, cover_letter, application_date, ip_address)
                    VALUES (%s, %s, %s, %s, %s, NOW(), %s)
                """
                cursor.execute(query, (
                    job_title,
                    applicant_name,
                    applicant_email,
                    phone_number,
                    letter,
                    request.remote_addr
                ))
                conn.commit()

                logger.info(f"New job application received for {job_title} from {applicant_email}")
                return redirect(url_for('thank_you'))

            except Exception as e:
                conn.rollback()
                logger.error(f"Error inserting job application: {str(e)}")
                return "An error occurred while submitting your application. Please try again later.", 500
            finally:
                cursor.close()
                conn.close()

        except Exception as e:
            logger.error(f"Unexpected error in job application: {str(e)}")
            return "An unexpected error occurred. Please try again later.", 500

    return render_template('apply.html', job_title=job_title, BANK_NAME=BANK_NAME)

@app.route('/thank-you')
def thank_you():
    return render_template('thank_you.html')

@app.after_request
def add_header(response):
    """Add security headers and cache control"""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response

if __name__ == '__main__':
    app.run(
        debug=True,
        host="0.0.0.0",
        threaded=True,
        use_reloader=False
    )