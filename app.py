import sqlite3
import bleach
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
from flask import Flask, request, redirect, url_for, render_template, session, flash,  g
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.secret_key = os.urandom(24)

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = bleach.clean(request.form['email'])
        password = bleach.clean(request.form['password'])
        totp_code = bleach.clean(request.form['totp'])
        error = None

        if not email:
            error = 'Email is required.'
        elif not password:
            error = 'Password is required.'
        elif not totp_code:
            error = 'TOTP code is required.'

        if error is not None:
            flash(error)
        else:
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
                return redirect(url_for('index'))
            else:
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
            totp_secret = pyotp.random_base32()
            totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(email, issuer_name="FlaskBlog")
            conn = get_db_connection()
            try:
                conn.execute('INSERT INTO users (email, password_hash, totp_secret) VALUES (?, ?, ?)',
                             (email, hashed_password, totp_secret))
                conn.commit()
                flash("Registration successful!, Scan the QR code below to setup 2FA")
                return render_template('register.html', totp_uri=totp_uri)
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

@app.route('/create', methods=('GET', 'POST'))
def create():
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
