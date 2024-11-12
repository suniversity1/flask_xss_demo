import os
import sqlite3
import time

import bleach
import pyotp
from authlib.integrations.flask_client import OAuth
from flask import Flask, request, redirect, url_for, render_template, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash

# Initialize the Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config.from_object('config')

# OAuth configuration for Google login
CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
oauth = OAuth(app)
oauth.register(
    name='google',
    server_metadata_url=CONF_URL,
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# Rate-limiting configuration
RATE_LIMIT = 3
TIMEOUT_DURATION = 60 # in seconds


# Database connection function
def get_db_connection():
    """
    Establishes a connection to the SQLite database.
    Returns:
        sqlite3.Connection: A connection object to the database.
    """
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.before_request
def before_request():
    """
    Handles rate-limiting logic and loads the user for each request.
    Ensures the login route is rate-limited to prevent brute-force attacks.
    """
    if request.endpoint == 'login' and request.method == 'POST':
        if 'attempts' in session and 'first_attempt_time' in session:
            attempts = session['attempts']
            first_attempt_time = session['first_attempt_time']
            current_time = time.time()

            # If rate limit exceeded within the timeout duration
            if attempts >= RATE_LIMIT:
                if current_time - first_attempt_time < TIMEOUT_DURATION:
                    remaining_time = int(TIMEOUT_DURATION - (current_time - first_attempt_time))
                    flash(f'Too many failed login attempts. Please try again after {remaining_time} seconds.')
                    return render_template('login.html')
                else:
                    # Reset attempts after timeout
                    session['attempts'] = 0
                    session['first_attempt_time'] = None
        else:
            session['attempts'] = 0
            session['first_attempt_time'] = time.time()

    # Load the user if they are logged in
    user_id = session.get('user_id')
    authenticated = session.get('authenticated')

    if user_id and authenticated:
        conn = get_db_connection()
        g.user = conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()
        conn.close()
    else:
        g.user = None

# Route for Google OAuth login
@app.route('/login_with_google')
def login_with_google():
    """
    Redirects the user to Google for OAuth login.
    Returns:
        Response: Redirect response to Google OAuth.
    """
    redirect_uri = url_for('auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

# User login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login with email and password.
    Uses rate limiting to prevent brute-force attacks.
    """
    if request.method == 'POST':
        email = bleach.clean(request.form['email'])
        password = bleach.clean(request.form['password'])
        error = None

        if not email:
            error = 'Email is required.'
        elif not password:
            error = 'Password is required.'

        if error is None:
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
            conn.close()

            if user is None:
                error = 'User not found.'
            elif not check_password_hash(user['password_hash'], password):
                error = 'Incorrect password.'

            if error is None:
                session.clear()
                session['user_id'] = user['user_id']
                flash("Login successful!")
                session.pop('attempts', None)
                session.pop('first_attempt_time', None)
                # Redirect if TOTP secret is missing
                if user and not user['totp_secret']:
                    session['totp_uri'] = pyotp.TOTP(pyotp.random_base32()).provisioning_uri(email,
                                                                 issuer_name="FlaskBlog")
                    return redirect(url_for('totp_setup'))
                return redirect(url_for('verify_totp'))
            else:
                # Increment rate-limiting attempt counters
                if 'attempts' not in session:
                    session['attempts'] = 1
                    session['first_attempt_time'] = time.time()
                else:
                    session['attempts'] += 1
                    if session['attempts'] == RATE_LIMIT:
                        session['first_attempt_time'] = time.time()

                # Display remaining attempts or timeout warning
                if session['attempts'] >= RATE_LIMIT:
                    remaining_time = int(TIMEOUT_DURATION - (time.time() - session['first_attempt_time']))
                    flash(f"Too many failed attempts. Please try again after {remaining_time} seconds.")
                else:
                    remaining_attempts = RATE_LIMIT - session['attempts']
                    flash(f"{error}. You have {remaining_attempts} attempt(s) left.")
        else:
            flash(error)
    return render_template('login.html')

# User registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handles user registration with email and password confirmation.
    Verifies fields and checks for existing accounts.
    """
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

# User logout route
@app.route('/logout')
def logout():
    """
    Logs out the user by clearing the session.
    """
    session.clear()
    return redirect(url_for('index'))

# TOTP setup route
@app.route('/totp_setup', methods=['GET', 'POST'])
def totp_setup():
    """
    Handles TOTP setup for the user. Verifies the TOTP code entered and saves the TOTP secret in the database.
    """
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

# Authentication callback route for Google OAuth
@app.route('/auth')
def auth():
    """
    Handles the callback for Google OAuth authentication. Registers a new user if not already in the database.
    """
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

# Verify TOTP route
@app.route('/verify_totp', methods=['GET', 'POST'])
def verify_totp():
    """
    Verifies the user's TOTP code before granting access. Required for users with TOTP setup.
    """
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
