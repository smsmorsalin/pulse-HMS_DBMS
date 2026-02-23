from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Required for session management

db = sqlite3.connect('database.db', check_same_thread=False)  # Connect to the SQLite database

db.commit()
@app.route('/')
def index():
    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    session.clear()  # Clear any existing session data
    if request.method == 'POST':
        # Handle login logic here
        # Validate credentials and redirect accordingly
        if not request.form.get('username') or not request.form.get('password'):
            return render_template("login.html", error="Please enter both username and password.")
        else:
            username = request.form.get('username')
            password = request.form.get('password')

            user_checker = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            if user_checker and check_password_hash(user_checker[2], password):
                session['user_id'] = user_checker[0]  # Store user_id in session
                return redirect(url_for('index', success="login successful"))  # Redirect to the home page after successful login
            else:
                return render_template("login.html", error="Invalid username or password.")
    else:
        return render_template("login.html")


if __name__ == '__main__':
    app.run(debug=True)