import time
from functools import wraps

import MySQLdb  # MySQL connector
from flask import Flask, render_template, request, session, make_response

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Set a secret key for session management

# MySQL connection setup (replace with your credentials)
db = MySQLdb.connect("172.23.98.94", "pol-II", "$HOME/Desktop/DNA.file", "bank")
cursor = db.cursor()


def delay_request(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        time.sleep(0.5)  # Sleep for 0.5 seconds
        return f(*args, **kwargs)

    return decorated_function


# Home Page
@app.route('/')
def index():
    return render_template('index.html')


# Services Page
@app.route('/services')
def services():
    return render_template('services.html')


# Contact Page
@app.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        # Form submission logic here
        pass
    return render_template('contact.html')


# About Us Page
@app.route('/about')
def about():
    return render_template('about.html')


# FAQs Page
@app.route('/faqs')
def faqs():
    return render_template('faqs.html')


# Careers Page
@app.route('/careers', methods=['GET', 'POST'])
def careers():
    if request.method == 'POST':
        # Handle job application submission
        pass
    return render_template('careers.html')


@app.route('/logout')
def logout():
    # remove cookie
    resp = make_response(render_template('login.html'))
    resp.set_cookie('user_data', '', expires=0)
    return resp


# Hidden Login Page (intentionally vulnerable to SQL injection)
@app.route('/config', methods=['POST', 'GET'])
def login():
    # Handle only POST method
    if 'username' in request.form and 'password' in request.form:
        # Retrieve username and password from the form
        username = request.form['username']
        password = request.form['password']

        # Construct a vulnerable SQL query using f-strings (insecure)
        query = f"SELECT * FROM bank WHERE username = '{username}' AND email = '{password}'"

        # Print the query for debugging (remove in production)
        print(f"Executing query: {query}")

        # Execute the query
        cursor.execute(query)
        result = cursor.fetchone()

        if result:
            session['username'] = username  # Store username in session

            # Store the username in the cookies
            resp = make_response(render_template('login_success.html'))
            resp.set_cookie('user_data', str(result))

            return resp
        else:
            return "Invalid credentials"

    # check if cookie is set
    if 'user_data' in request.cookies:
        user_data = request.cookies.get('user_data')
        return render_template('profile.html')

    # Render the login form for GET requests without credentials
    return render_template('login.html')


@app.route('/insecure')
def get_user_data():
    # Get user input
    username = request.args.get('username')
    password = request.args.get('password')

    # Prepare SQL query using fstrings
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    # Execute the query
    cursor.execute(query)

    # Fetch the result
    result = cursor.fetchone()

    # Return the result
    return str(result)


# Dashboard (private page with authentication check)
@app.route('/dashboard')
def dashboard():
    # check if cookies have user_data
    if 'user_data' not in request.cookies:
        return render_template("unauth.html")
    return render_template('dashboard.html')


@app.after_request
def add_header(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    time.sleep(1.69)  # ;) Hecker ?
    return response


# Run the app
if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0")
