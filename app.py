import sqlite3
import bcrypt
import bleach
import pyotp
from flask import Flask, request, redirect, url_for, render_template, session, flash, g
import os



app = Flask(__name__)
app.secret_key = os.urandom(24)

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn


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
            totp_secret = pyotp.random_base32()
            conn = get_db_connection()
            conn.execute('INSERT INTO users (email, password_hash, totp_secret) VALUES (?, ?, ?)',
                         (email, bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()), totp_secret))
            conn.commit()
            conn.close()
            totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(email, issuer_name="YourApp")
            return render_template('register.html', totp_uri=totp_uri)

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = bleach.clean(request.form['email'])
        password = bleach.clean(request.form['password'])
        totp = bleach.clean(request.form['totp'])
        error = None

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user is None:
            error = 'Incorrect email.'
        elif not bcrypt.checkpw(password.encode('utf-8'), user['password_hash']):
            error = 'Incorrect password.'
        elif not pyotp.TOTP(user['totp_secret']).verify(totp):
            error = 'Invalid TOTP.'

        if error is None:
            session.clear()
            session['user_id'] = user['user_id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('login.html')

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    if user_id is None:
        g.user = None
    else:
        conn = get_db_connection()
        g.user = conn.execute('SELECT * FROM users WHERE user_id = ?', (user_id,)).fetchone()
        conn.close()

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
            conn.execute('INSERT INTO posts (title, content, user_id) VALUES (?, ?, ?)',
                         (title, content, g.user['user_id']))
            conn.commit()
            conn.close()
            return redirect(url_for('index'))

    return render_template('create_post.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))
@app.route('/')
def index():
    conn = get_db_connection()
    posts = conn.execute('SELECT * FROM posts').fetchall()
    conn.close()
    return render_template('index.html', posts=posts)