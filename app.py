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
    
    users_exists = cursor.fetchone() is not None
    
    if not users_exists:
        # Create users table if it doesn't exist
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        print("Users table created successfully.")
    
    # Check if admins table exists
    cursor.execute('''
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='admins'
    ''')
    
    admins_exists = cursor.fetchone() is not None
    
    if not admins_exists:
        # Create admins table if it doesn't exist
        cursor.execute('''
            CREATE TABLE admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        print("Admins table created successfully.")
    
    if not users_exists or not admins_exists:
        db.commit()
        print("Hospital database initialized successfully.")
    else:
        print("Hospital database already exists.")

# Initialize database on app startup
init_db()

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        role = request.form.get('role')
        username = request.form.get('username')
        password = request.form.get('password')
        if not role or not username or not password:
            return render_template("register.html", error="Please fill in all fields.")
        else:
            admin_checker = db.execute('SELECT * FROM admins WHERE username = ?', (username,)).fetchone()
            if session.get('user_id') == 'root_admin' or (admin_checker and admin_checker[0] == session.get('user_id')):
                hashed_password = generate_password_hash(password)
                if role == 'admin':
                    try:
                        db.execute('INSERT INTO admins (username, password) VALUES (?, ?)', (username, hashed_password))
                        db.commit()
                        return redirect(url_for('register', asuccess=f"Admin registered successfully."))
                    except sqlite3.IntegrityError:
                        return render_template("register.html", error="Username already exists. Please choose a different username.")
                else:  # role == 'user'
                    try:
                        db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                        db.commit()
                        return redirect(url_for('register', success=f"Employee registered successfully."))
                    except sqlite3.IntegrityError:
                        return render_template("register.html", error="Username already exists. Please choose a different username.")

    return render_template("register.html")

@app.route('/', methods=['GET', 'POST'])
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
            admin_checker = db.execute('SELECT * FROM admins WHERE username = ?', (username,)).fetchone()

            if user_checker and check_password_hash(user_checker[2], password) or (username == root_admin_username and password == root_admin_password) or (admin_checker and check_password_hash(admin_checker[2], password)):
                if (username == root_admin_username and password == root_admin_password) or (admin_checker and check_password_hash(admin_checker[2], password)):
                    if (username == root_admin_username and password == root_admin_password):
                        session['user_id'] = 'root_admin'  # Store a special identifier for the root admin in session
                    else:
                        session['user_id'] = admin_checker[0]  # Store admin_id in session
                    return redirect(url_for('admin_portal', admin_success="admin login successful"))  # Redirect to the admin portal page after successful login
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
    return redirect(url_for('login'))  # Redirect to the login page after logout

@app.route('/admin_portal')
def admin_portal():
    """Admin portal page - only accessible to admin."""
    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (session.get('user_id'),)).fetchone()
    if session.get('user_id') == 'root_admin' or (admin_checker and admin_checker[0] == session.get('user_id')):
        return render_template("admin_portal.html")
    else:
        return redirect(url_for('login'))


@app.route('/dashboard')
def dashboard():
    """User dashboard page - only accessible to logged-in users."""
    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (session.get('user_id'),)).fetchone()
    user_checker = db.execute('SELECT * FROM users WHERE id = ?', (session.get('user_id'),)).fetchone()

    if session.get('user_id') == 'root_admin' or (admin_checker and admin_checker[0] == session.get('user_id')) or (user_checker and user_checker[0] == session.get('user_id')):
        return render_template("dashboard.html")
    else:
        return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)