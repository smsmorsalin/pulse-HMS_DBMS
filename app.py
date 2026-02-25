from flask import Flask, render_template, request, redirect, session, url_for
import sqlite3
from werkzeug.security import check_password_hash, generate_password_hash

root_admin_username = "admin"
root_admin_password = "admin123"  # In a production environment, use a strong password and consider storing it securely (e.g., in environment variables or a secure vault)

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Required for session management

db = sqlite3.connect('hospital.db', check_same_thread=False)  # Connect to the SQLite database

# Function to initialize the database and create tables if they don't exist
def init_db():
    """Initialize the hospital database with required tables if they don't exist."""
    cursor = db.cursor()
    
    # Check if users table exists
    cursor.execute('''
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='users'
    ''')
    
    if not cursor.fetchone():
        # Create users table if it doesn't exist
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        db.commit()
        print("✓ Hospital database initialized: 'users' table created successfully.")
    else:
        print("✓ Hospital database already exists with 'users' table.")

# Initialize database on app startup
init_db()
@app.route('/')
def index():
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    return render_template("register.html")

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
            if user_checker and check_password_hash(user_checker[2], password) or (username == root_admin_username and password == root_admin_password):
                if username == root_admin_username and password == root_admin_password:
                    session['user_id'] = 'root_admin'  # Store a special identifier for the root admin in session
                    return redirect(url_for('admin_portal', admin_success="root admin login successful"))  # Redirect to the admin portal page after successful login
                else:
                    session['user_id'] = user_checker[0]  # Store user_id in session
                    return redirect(url_for('dashboard', user_success="login successful"))  # Redirect to the dashboard page after successful login
            else:
                return render_template("login.html", error="Invalid username or password.")
    else:
        return render_template("login.html")

@app.route('/logout')
def logout():
    session.clear()  # Clear the session data
    return redirect(url_for('index'))

@app.route('/admin_portal')
def admin_portal():
    """Admin portal page - only accessible to root admin."""
    if session.get('user_id') == 'root_admin':
        return render_template("admin_portal.html")
    else:
        return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    """User dashboard page - only accessible to logged-in users."""
    if session.get('user_id'):
        return render_template("dashboard.html")
    else:
        return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)