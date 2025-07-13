import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from collections import OrderedDict

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Change this in production
DATABASE = 'site.db'

# --- Database Setup ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        # Users table
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            fullname TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL
        )''')
        # Grievances table (add mood, severity, suggestion)
        cursor.execute('''CREATE TABLE IF NOT EXISTS grievances (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT NOT NULL,
            mood TEXT,
            severity TEXT,
            suggestion TEXT,
            timestamp TEXT NOT NULL
        )''')
        # Try to add new columns if they don't exist (for migration)
        try:
            cursor.execute('ALTER TABLE grievances ADD COLUMN mood TEXT')
        except Exception:
            pass
        try:
            cursor.execute('ALTER TABLE grievances ADD COLUMN severity TEXT')
        except Exception:
            pass
        try:
            cursor.execute('ALTER TABLE grievances ADD COLUMN suggestion TEXT')
        except Exception:
            pass
        # Good Boy Moments table
        cursor.execute('''CREATE TABLE IF NOT EXISTS good_boy_moments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )''')
        # Bad Boy Moments table
        cursor.execute('''CREATE TABLE IF NOT EXISTS bad_boy_moments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp TEXT NOT NULL
        )''')
        # Insert superuser if not exists
        cursor.execute('SELECT * FROM users WHERE username = ?', ('becca23.11',))
        if cursor.fetchone() is None:
            cursor.execute('''INSERT INTO users (username, fullname, password, role) VALUES (?, ?, ?, ?)''',
                ('becca23.11', 'Becca', generate_password_hash('beccahatessamar29'), 'superuser'))
        db.commit()

if not os.path.exists(DATABASE):
    init_db()

# --- Routes will be added here ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        fullname = request.form['fullname']
        password = request.form['password']
        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute('INSERT INTO users (username, fullname, password, role) VALUES (?, ?, ?, ?)',
                           (username, fullname, generate_password_hash(password), 'normal'))
            db.commit()
            flash('Sign up successful! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists.')
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        login_type = request.form['login_type']
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], password):
            # Role check
            if login_type == 'normal' and user['role'] == 'normal':
                session['username'] = user['username']
                session['role'] = user['role']
                return redirect(url_for('grievance'))
            elif login_type == 'special':
                # Only allow if user is actually special or superuser
                if user['role'] in ('special', 'superuser'):
                    session['username'] = user['username']
                    session['role'] = user['role']
                    return redirect(url_for('dashboard'))
                else:
                    flash('You are not registered as a special user. Please contact the admin.')
            elif user['role'] == 'superuser':
                session['username'] = user['username']
                session['role'] = user['role']
                return redirect(url_for('dashboard'))
            else:
                flash('Role mismatch. Please select the correct login type.')
        else:
            flash('Invalid credentials.')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully.')
    return redirect(url_for('index'))

@app.route('/grievance', methods=['GET', 'POST'])
def grievance():
    if 'username' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        message = request.form['message']
        mood = request.form.get('mood')
        severity = request.form.get('severity')
        suggestion = request.form.get('suggestion')
        db = get_db()
        cursor = db.cursor()
        cursor.execute('INSERT INTO grievances (username, message, mood, severity, suggestion, timestamp) VALUES (?, ?, ?, ?, ?, ?)',
                       (session['username'], message, mood, severity, suggestion, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        db.commit()
        flash('Grievance submitted!')
        return redirect(url_for('grievance'))
    return render_template('grievance.html')

@app.route('/dashboard')
def dashboard():
    if 'username' not in session or session.get('role') not in ('special', 'superuser'):
        return redirect(url_for('login'))
    return render_template('dashboard.html')

@app.route('/good_boy', methods=['GET', 'POST'])
def good_boy():
    if 'username' not in session or session.get('role') not in ('special', 'superuser'):
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        message = request.form['message'][:2000]
        cursor.execute('INSERT INTO good_boy_moments (username, message, timestamp) VALUES (?, ?, ?)',
                       (session['username'], message, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        db.commit()
        flash('Good boy moment submitted!')
        return redirect(url_for('good_boy'))
    # Today's count
    today = datetime.now().strftime('%Y-%m-%d')
    cursor.execute('SELECT COUNT(*) FROM good_boy_moments WHERE username = ? AND timestamp LIKE ?',
                   (session['username'], today + '%'))
    today_count = cursor.fetchone()[0]
    # 7-day stats
    stats = OrderedDict()
    for i in range(6, -1, -1):
        day = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
        cursor.execute('SELECT COUNT(*) FROM good_boy_moments WHERE username = ? AND timestamp LIKE ?',
                       (session['username'], day + '%'))
        stats[day] = cursor.fetchone()[0]
    return render_template('good_boy.html', today_count=today_count, stats=stats)

@app.route('/bad_boy', methods=['GET', 'POST'])
def bad_boy():
    if 'username' not in session or session.get('role') not in ('special', 'superuser'):
        return redirect(url_for('login'))
    if request.method == 'POST':
        message = request.form['message'][:2000]
        db = get_db()
        cursor = db.cursor()
        cursor.execute('INSERT INTO bad_boy_moments (username, message, timestamp) VALUES (?, ?, ?)',
                       (session['username'], message, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        db.commit()
        flash('Bad boy moment submitted!')
        return redirect(url_for('bad_boy'))
    return render_template('bad_boy.html')

@app.route('/view_content')
def view_content():
    if 'username' not in session or session.get('role') not in ('special', 'superuser'):
        return redirect(url_for('login'))
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM grievances ORDER BY timestamp DESC')
    grievances = cursor.fetchall()
    cursor.execute('SELECT * FROM good_boy_moments ORDER BY timestamp DESC')
    good_boys = cursor.fetchall()
    cursor.execute('SELECT * FROM bad_boy_moments ORDER BY timestamp DESC')
    bad_boys = cursor.fetchall()
    return render_template('view_content.html', grievances=grievances, good_boys=good_boys, bad_boys=bad_boys)

if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(host='0.0.0.0', port=3000, debug=True) 