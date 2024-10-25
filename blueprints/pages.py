from flask import Blueprint, render_template, request, make_response

pages = Blueprint('pages', __name__)



@pages.route('/dashboard')
def dashboard():
    if 'user_data' not in request.cookies:
        return render_template("unauth.html")
    return render_template('dashboard.html')

@pages.route('/services')
def services():
    return render_template('services.html')

@pages.route('/contact', methods=['GET', 'POST'])
def contact():
    if request.method == 'POST':
        pass
    return render_template('contact.html')

@pages.route('/about')
def about():
    return render_template('about.html')

@pages.route('/faqs')
def faqs():
    return render_template('faqs.html')

@pages.route('/careers', methods=['GET', 'POST'])
def careers():
    if request.method == 'POST':
        pass
    return render_template('careers.html')

@pages.route('/logout')
def logout():
    resp = make_response(render_template('login.html'))
    resp.set_cookie('user_data', '', expires=0)
    return resp

@pages.route('/')
def index():
    return render_template('index.html')

@pages.route('/thank-you')
def thank_you():
    return render_template('thank_you.html')
