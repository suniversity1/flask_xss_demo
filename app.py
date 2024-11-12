import sqlite3
import bleach
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
from flask import Flask, request, redirect, url_for, render_template, session, flash, g
from datetime import timedelta
import os
from authlib.integrations.flask_client import OAuth
import time


app = Flask(__name__)
app.secret_key = '!secret'
app.config.from_object('config')



CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
oauth = OAuth(app)
oauth.register(
    name='google',
    server_metadata_url=CONF_URL,
    client_kwargs={
        'scope': 'openid email profile'
    }
)

RATE_LIMIT = 3
TIMEOUT_DURATION = 60

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.before_request
def rate_limit():
    if request.endpoint == 'login' and request.method == 'POST':
        if 'attempts' in session and 'first_attempt_time' in session:
            attempts = session['attempts']
            first_attempt_time = session['first_attempt_time']
            current_time = time.time()

            if attempts >= RATE_LIMIT:
                if current_time - first_attempt_time < TIMEOUT_DURATION:
                    remaining_time = int(TIMEOUT_DURATION - (current_time - first_attempt_time))
                    flash(f'Too many failed login attempts. Please try again after {remaining_time} seconds.')
                    return render_template('login.html')
                else:
                    session['attempts'] = 0
                    session['first_attempt_time'] = None
        else:
            session['attempts'] = 0
            session['first_attempt_time'] = time.time()

@app.route('/login_with_google')
def login_with_google():
    redirect_uri = url_for('auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = bleach.clean(request.form['email'])
        password = bleach.clean(request.form['password'])
        totp_code = bleach.clean(request.form['totp'])
        error = None
        client_ip = request.remote_addr

        if not email:
            error = 'Email is required.'
        elif not password:
            error = 'Password is required.'
        elif not totp_code:
            error = 'TOTP code is required.'

        if error is None:
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            conn.close()

            if user is None:
                error = 'User not found.'
            elif not check_password_hash(user['password_hash'], password):
                error = 'Incorrect password.'
            else:
                totp = pyotp.TOTP(user['totp_secret'])
                if not totp.verify(totp_code):
                    error = 'Invalid TOTP code.'

            if error is None:
                session.clear()
                session['user_id'] = user['user_id']
                flash("Login successful!")
                session.pop('attempts', None)
                session.pop('first_attempt_time', None)
                return redirect(url_for('index'))
            else:
                if 'attempts' not in session:
                    session['attempts'] = 1
                    session['first_attempt_time'] = time.time()
                else:
                    session['attempts'] += 1
                    if session['attempts'] == RATE_LIMIT:
                        session['first_attempt_time'] = time.time()
                if session['attempts'] >= RATE_LIMIT:
                    remaining_time = int(TIMEOUT_DURATION - (time.time() - session['first_attempt_time']))
                    flash(f"Too many failed attempts. Please try again after {remaining_time} seconds.")
                else:
                    remaining_attempts = RATE_LIMIT - session['attempts']
                    flash(f"{error}. You have {remaining_attempts} attempt(s) left.")
        else:
            flash(error)

        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = bleach.clean(request.form['email'])
        password = bleach.clean(request.form['password'])
        confirm_password = bleach.clean(request.form['confirm_password'])
        error = None

        if not email:
            error = 'Email is required.'
        elif not password:
            error = 'Password is required.'
        elif not confirm_password:
            error = 'Confirm password is required.'
        elif password != confirm_password:
            error = 'Passwords do not match.'

        if error is not None:
            flash(error)
        else:
            hashed_password = generate_password_hash(password)
            totp_secret = pyotp.random_base32()
            totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(email, issuer_name="FlaskBlog")

            conn = get_db_connection()
            try:
                conn.execute('INSERT INTO users (email, password_hash, totp_secret) VALUES (?, ?, ?)',
                             (email, hashed_password, totp_secret))
                conn.commit()
                flash("Registration successful! Please scan the QR code below to set up two-factor authentication.")
                return redirect(url_for('register'))
            except sqlite3.IntegrityError:
                flash("An account with this email already exists.")
                return redirect(url_for('register'))
            finally:
                conn.close()

        return render_template('register.html')

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        conn = get_db_connection()
        g.user = conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()
        conn.close()

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/auth')
def auth():
    token = oauth.google.authorize_access_token()
    user_info = token['userinfo']
    session['user'] = user_info

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (user_info['email'],)).fetchone()

    if user is None:
        conn.execute('INSERT INTO users (email, name) VALUES (?, ?)', (user_info['email'], user_info['name']))
        conn.commit()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (user_info['email'],)).fetchone()


    session['user_id'] = user['user_id']
    conn.close()

    return redirect(url_for('index'))


@app.route('/create', methods=('GET', 'POST'))
def create():
    if g.user is None:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = bleach.clean(request.form['title'])
        content = bleach.clean(request.form['content'])
        error = None

        if not title:
            error = 'Title is required.'

        if error is not None:
            flash(error)
        else:
            conn = get_db_connection()
            conn.execute('INSERT INTO posts (title, content) VALUES (?, ?)', (title, content))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))

    return render_template('create_post.html')

@app.route('/')
def index():
    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts').fetchall()
    conn.close()
    return render_template('index.html', posts=posts)

if __name__ == "__main__":
    app.run(debug=True)
