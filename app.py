import sqlite3
import bleach
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
from flask import Flask, request, redirect, url_for, render_template, session, flash, g
from datetime import datetime, timedelta
import os
from authlib.integrations.flask_client import OAuth
import time

app = Flask(__name__)
app.secret_key = os.urandom(24)
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
failed_login_attempts = {}


def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


@app.before_request
def rate_limit():
    client_ip = request.remote_addr
    current_time = time.time()

    if client_ip in failed_login_attempts:
        attempts, first_attempt_time = failed_login_attempts[client_ip]
        if attempts >= RATE_LIMIT:
            if current_time - first_attempt_time < TIMEOUT_DURATION:
                flash('Too many failed login attempts. Please try again later.')
                return render_template('login.html')
            else:
                # Reset the attempts after the timeout duration
                failed_login_attempts[client_ip] = (0, current_time)


@app.route('/login_with_google')
def login_with_google():
    redirect_uri = url_for('auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = bleach.clean(request.form['email'])
        password = bleach.clean(request.form['password'])
        error = None
        client_ip = request.remote_addr

        if not email:
            error = 'Email is required.'
        elif not password:
            error = 'Password is required.'

        if error is not None:
            flash(error)
        else:
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            conn.close()

            # Redirect if TOTP secret is missing
            if user and not user['totp_secret']:
                session['totp_uri'] = pyotp.TOTP(pyotp.random_base32()).provisioning_uri(email, issuer_name="FlaskBlog")
                return redirect(url_for('totp_setup'))

            if user is None:
                error = 'User not found.'
            elif not check_password_hash(user['password_hash'], password):
                error = 'Incorrect password.'

            if error is None:
                session.clear()
                session['user_id'] = user['user_id']
                flash("Login successful!")
                if client_ip in failed_login_attempts:
                    del failed_login_attempts[client_ip]
                return redirect(url_for('verify_totp'))
            else:
                if client_ip not in failed_login_attempts:
                    failed_login_attempts[client_ip] = (1, time.time())
                else:
                    attempts, first_attempt_time = failed_login_attempts[client_ip]
                    failed_login_attempts[client_ip] = (attempts + 1, first_attempt_time)

                flash(error)

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

            conn = get_db_connection()
            try:
                conn.execute(
                    'INSERT INTO users (email, password_hash) VALUES (?, ?)',
                    (email, hashed_password)
                )
                conn.commit()

                user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
                session['user_id'] = user['user_id']

                return redirect(url_for('totp_setup'))
            except sqlite3.IntegrityError:
                flash("An account with this email already exists.")
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


@app.route('/totp_setup', methods=['GET', 'POST'])
def totp_setup():
    user_id = session.get('user_id')
    if user_id is None:
        return redirect(url_for('register'))

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()

    # Ensure `user` exists to avoid issues
    if not user:
        conn.close()
        flash("User not found. Please register again.")
        return redirect(url_for('register'))

    if request.method == 'POST':
        totp_code = bleach.clean(request.form['totp'])

        if user:
            totp = pyotp.TOTP(session['totp_secret'])
            if totp.verify(totp_code):
                # Update user with TOTP secret after verification
                conn.execute('UPDATE users SET totp_secret = ? WHERE user_id = ?', (session['totp_secret'], user_id))
                conn.commit()
                session.pop('totp_secret', None)

                # Mark the user as authenticated and redirect to index
                session['authenticated'] = True
                flash("TOTP setup successful!")
                return redirect(url_for('index'))
            else:
                flash("Invalid TOTP code.")
        conn.close()

    # Generate TOTP secret and URI for setup
    totp_secret = pyotp.random_base32()
    session['totp_secret'] = totp_secret
    totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(user['email'], issuer_name="FlaskBlog")

    conn.close()
    return render_template('totp_setup.html', totp_uri=totp_uri)


@app.route('/auth')
def auth():
    token = oauth.google.authorize_access_token()
    user_info = token['userinfo']
    session['user'] = user_info

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (user_info['email'],)).fetchone()

    # Redirect if TOTP secret is missing
    if user and not user['totp_secret']:
        session['user_id'] = user['user_id']
        return redirect(url_for('totp_setup'))

    if user is None:

        conn.execute(
            'INSERT INTO users (email, name) VALUES (?, ?)',
            (user_info['email'], user_info['name'])
        )
        conn.commit()

        # Store the new user's ID in session and redirect to a page displaying the QR code
        user = conn.execute('SELECT * FROM users WHERE email = ?', (user_info['email'],)).fetchone()
        session['user_id'] = user['user_id']
        conn.close()

        flash("Please scan the QR code to enable two-factor authentication.")
        return render_template('totp_setup.html')
    else:
        if user['totp_secret']:
            session['user_id'] = user['user_id']
            conn.close()
            return redirect(url_for('verify_totp'))

        # Existing user, check for 2FA setup and proceed
        session['user_id'] = user['user_id']
        conn.close()

        return redirect(url_for('index'))


@app.route('/verify_totp', methods=['GET', 'POST'])
def verify_totp():
    if request.method == 'POST':
        totp_code = bleach.clean(request.form['totp'])
        user_id = session.get('user_id')

        if user_id is None:
            flash("Authentication error. Please log in again.")
            return redirect(url_for('login'))

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()
        conn.close()

        if user:
            totp = pyotp.TOTP(user['totp_secret'])
            if totp.verify(totp_code):
                session['authenticated'] = True
                flash("Login successful!")
                return redirect(url_for('index'))
            else:
                flash("Invalid TOTP code.")
        else:
            flash("User not found.")

    return render_template('verify_totp.html')

@app.before_request
def before_request():
    user_id = session.get('user_id')
    authenticated = session.get('authenticated')
    client_ip = request.remote_addr
    current_time = time.time()

    # Check rate limit
    if client_ip in failed_login_attempts:
        attempts, first_attempt_time = failed_login_attempts[client_ip]
        if attempts >= RATE_LIMIT:
            if current_time - first_attempt_time < TIMEOUT_DURATION:
                flash('Too many failed login attempts. Please try again later.')
                return render_template('login.html')
            else:
                # Reset attempts after the timeout duration
                failed_login_attempts[client_ip] = (0, current_time)

    # Load the user if they are logged in
    if user_id and authenticated:
        conn = get_db_connection()
        g.user = conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()
        conn.close()
    else:
        g.user = None


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
            conn.execute('INSERT INTO posts (title, content) VALUES (?, ?)',
                         (title, content))
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
