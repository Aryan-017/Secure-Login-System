from flask import Flask, render_template_string, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3

# ----------------------------------------------------------
# SECURE LOGIN SYSTEM
# ----------------------------------------------------------
# Features:
# - User Registration
# - Secure Password Hashing
# - Login Authentication
# - Session Management
# - SQL Injection Protection
# - Logout Functionality
# ----------------------------------------------------------
# Humanity invented "password123" and then wondered
# why cybersecurity became necessary.
# ----------------------------------------------------------

app = Flask(__name__)
app.secret_key = "super_secret_key_change_this"

DATABASE = "users.db"

# ----------------------------------------------------------
# DATABASE SETUP
# ----------------------------------------------------------

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')

    conn.commit()
    conn.close()


init_db()

# ----------------------------------------------------------
# HTML TEMPLATE
# ----------------------------------------------------------

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Login System</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: #f4f6f9;
            margin: 0;
            padding: 0;
        }

        .container {
            width: 400px;
            margin: 60px auto;
            background: white;
            padding: 30px;
            border-radius: 15px;
            box-shadow: 0px 0px 15px rgba(0,0,0,0.1);
        }

        h1 {
            text-align: center;
            color: #1e293b;
        }

        input {
            width: 100%;
            padding: 12px;
            margin-top: 10px;
            margin-bottom: 20px;
            border: 1px solid #ccc;
            border-radius: 8px;
        }

        button {
            width: 100%;
            padding: 12px;
            background: #2563eb;
            color: white;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            cursor: pointer;
        }

        button:hover {
            background: #1d4ed8;
        }

        .message {
            color: red;
            text-align: center;
        }

        .success {
            color: green;
            text-align: center;
        }

        .dashboard {
            text-align: center;
        }

    </style>
</head>
<body>

<div class="container">
    <h1>{{ title }}</h1>

    {% with messages = get_flashed_messages() %}
        {% if messages %}
            {% for message in messages %}
                <p class="message">{{ message }}</p>
            {% endfor %}
        {% endif %}
    {% endwith %}

    {{ content|safe }}
</div>

</body>
</html>
'''

# ----------------------------------------------------------
# HOME
# ----------------------------------------------------------

@app.route('/')
def home():
    if 'user' in session:
        content = f'''
        <div class="dashboard">
            <h2>Welcome, {session['user']} 👋</h2>
            <p>Your session is securely active.</p>
            <p>Hackers are disappointed today.</p>
            <a href="/logout"><button>Logout</button></a>
        </div>
        '''

        return render_template_string(HTML_TEMPLATE, title="Dashboard", content=content)

    return redirect(url_for('login'))

# ----------------------------------------------------------
# REGISTER
# ----------------------------------------------------------

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        if len(password) < 8:
            flash("Password must be at least 8 characters")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)

        try:
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            # Parameterized query protects from SQL Injection
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
            )

            conn.commit()
            conn.close()

            flash("Registration successful. Please login.")
            return redirect(url_for('login'))

        except sqlite3.IntegrityError:
            flash("Username already exists")
            return redirect(url_for('register'))

    content = '''
    <form method="POST">
        <input type="text" name="username" placeholder="Enter Username" required>
        <input type="password" name="password" placeholder="Enter Password" required>
        <button type="submit">Register</button>
    </form>

    <p style="text-align:center; margin-top:15px;">
        Already have an account?
        <a href="/login">Login</a>
    </p>
    '''

    return render_template_string(HTML_TEMPLATE, title="Register", content=content)

# ----------------------------------------------------------
# LOGIN
# ----------------------------------------------------------

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()

        # Parameterized query protects from SQL Injection
        cursor.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        )

        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[2], password):
            session['user'] = username
            return redirect(url_for('home'))

        flash("Invalid username or password")
        return redirect(url_for('login'))

    content = '''
    <form method="POST">
        <input type="text" name="username" placeholder="Enter Username" required>
        <input type="password" name="password" placeholder="Enter Password" required>
        <button type="submit">Login</button>
    </form>

    <p style="text-align:center; margin-top:15px;">
        Don't have an account?
        <a href="/register">Register</a>
    </p>
    '''

    return render_template_string(HTML_TEMPLATE, title="Login", content=content)

# ----------------------------------------------------------
# LOGOUT
# ----------------------------------------------------------

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out successfully")
    return redirect(url_for('login'))

# ----------------------------------------------------------
# MAIN
# ----------------------------------------------------------

if __name__ == '__main__':
    app.run(debug=True)
