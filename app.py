import sqlite3
from flask import Flask, render_template, request, url_for, flash, redirect
import bleach

app = Flask(__name__)

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn



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