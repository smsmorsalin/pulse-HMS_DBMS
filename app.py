from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory
import sqlite3
from werkzeug.security import check_password_hash, generate_password_hash

root_admin_username = "admin"
root_admin_password = "admin123"  # In a production environment, use a strong password and consider storing it securely (e.g., in environment variables or a secure vault)

app = Flask(__name__)
app.secret_key = 'xs12a'  # Required for session management

db = sqlite3.connect('hospital.db', check_same_thread=False)  # Connect to the SQLite database
db.execute("PRAGMA foreign_keys = ON")  # Enable foreign key support

# Function to initialize the database and create tables if they don't exist
def init_db():
    """Initialize the hospital database with required tables if they don't exist."""
    cursor = db.cursor()

    #users table
    cursor.execute('''
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='users'
    ''')
    users_exists = cursor.fetchone() is not None
    if not users_exists:
        cursor.execute('''
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        print("Users table created successfully.")
    
    #admins table
    cursor.execute('''
        SELECT name FROM sqlite_master 
        WHERE type='table' AND name='admins'
    ''') 
    admins_exists = cursor.fetchone() is not None 
    if not admins_exists:
        cursor.execute('''
            CREATE TABLE admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        ''')
        print("Admins table created successfully.")
    
    #patients table
    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="patients"')
    patients_exists = cursor.fetchone() is not None
    if not patients_exists:
        cursor.execute('''
            CREATE TABLE patients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                age INTEGER NOT NULL,
                gender TEXT NOT NULL,
                phone TEXT NOT NULL,
                email TEXT,
                dob TEXT NOT NULL,
                blood_group TEXT NOT NULL,
                address TEXT NOT NULL,
                emergency_contact_name TEXT NOT NULL,
                emergency_contact_phone TEXT NOT NULL,
                medical_history TEXT
             )
        ''')
        print("Patients table created successfully.")
    
    #doctors table
    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="doctors"')
    doctors_exists = cursor.fetchone() is not None
    if not doctors_exists:
        cursor.execute('''
            CREATE TABLE doctors (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                email TEXT NOT NULL,
                specialization TEXT NOT NULL,
                department TEXT NOT NULL,
                license_number TEXT NOT NULL,
                availability TEXT NOT NULL,
                experience INTEGER NOT NULL,
                room_number TEXT NOT NULL
            )
        ''')
        print("Doctors table created successfully.")

    #services table
    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="services"')
    services_exists = cursor.fetchone() is not None
    if not services_exists:
        cursor.execute('''
            CREATE TABLE services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                type TEXT CHECK(type IN ('doctor','test')) NOT NULL,
                price REAL NOT NULL
            )
        ''')
        print("Services table created successfully.")

    #appointments table
    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="appointments"')
    appointments_exists = cursor.fetchone() is not None
    if not appointments_exists:
        cursor.execute('''
            CREATE TABLE appointments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER,
                doctor_id INTEGER,
                service_id INTEGER,
                appointment_date TEXT,
                created_by INTEGER,

                FOREIGN KEY (patient_id) REFERENCES patients(id),
                FOREIGN KEY (doctor_id) REFERENCES doctors(id),
                FOREIGN KEY (service_id) REFERENCES services(id)
            )
        ''')
        print("Appointments table created successfully.")
    
    #test_orders table
    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="test_orders"')
    test_orders_exists = cursor.fetchone() is not None
    if not test_orders_exists:
        cursor.execute('''
            CREATE TABLE test_orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER,
                service_id INTEGER,
                test_date TEXT,

                FOREIGN KEY (patient_id) REFERENCES patients(id),
                FOREIGN KEY (service_id) REFERENCES services(id)
            )
        ''')
        print("Test Orders table created successfully.")

    #bills table
    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="bills"')
    bills_exists = cursor.fetchone() is not None
    if not bills_exists:
        cursor.execute('''
            CREATE TABLE bills (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER,
                created_by INTEGER,
                total_amount REAL DEFAULT 0,
                created_at TEXT,

                FOREIGN KEY (patient_id) REFERENCES patients(id)
            )
        ''')
        print("Bills table created successfully.")

    #bill_items table
    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="bill_items"')
    bill_items_exists = cursor.fetchone() is not None
    if not bill_items_exists:
        cursor.execute('''
            CREATE TABLE bill_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                bill_id INTEGER,
                service_id INTEGER,
                quantity INTEGER,
                price REAL,

                FOREIGN KEY (bill_id) REFERENCES bills(id),
                FOREIGN KEY (service_id) REFERENCES services(id)
            )
        ''')
        print("Bill Items table created successfully.")

    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="logs"')
    logs_exists = cursor.fetchone() is not None

    #logs table
    if not logs_exists:
        cursor.execute('''
            CREATE TABLE logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                role TEXT CHECK(role IN ('admin','user')) NOT NULL,
                patient_id INTEGER,
                action TEXT,
                timestamp TEXT
            )
        ''')
        print("Logs table created successfully.")

    else:
        print("Hospital database already exists.")
        # commit the changes to the database
        db.commit()
        print("Hospital database initialized successfully.")
        
# Initialize database on app startup
init_db()

def isadmin():
    """Helper function to check if the current user is an admin."""
    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (session.get('user_id'),)).fetchone()
    return session.get('user_id') == 'root_admin' or (admin_checker and admin_checker[0] == session.get('user_id'))

def isuser():
    """Helper function to check if the current user is a regular user."""
    user_checker = db.execute('SELECT * FROM users WHERE id = ?', (session.get('user_id'),)).fetchone()
    return user_checker and user_checker[0] == session.get('user_id')

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
                        return redirect(url_for('registered_users', success=f"Admin registered successfully."))
                    except sqlite3.IntegrityError:
                        return render_template("register.html", error="Username already exists. Please choose a different username.")
                else:  # role == 'user'
                    try:
                        db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed_password))
                        db.commit()
                        return redirect(url_for('registered_users', success=f"Employee registered successfully."))
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

# Route to serve static assets (CSS, JS, images, etc.)
@app.route('/assets/<path:filename>')
def assets(filename):
    return send_from_directory('assets', filename)

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

    if isadmin() or isuser():
        patient_details = db.execute('SELECT * FROM patients').fetchall()
        patient_count = len(patient_details)
        doctor_count = db.execute('SELECT COUNT(*) FROM doctors').fetchone()[0]
        # Show the authenticated account name in the dashboard profile dropdown.
        if session.get('user_id') == 'root_admin':
            profile_name = root_admin_username
        elif admin_checker and admin_checker[0] == session.get('user_id'):
            profile_name = admin_checker[1]
        else:
            profile_name = user_checker[1]
        if session.get('user_id') == 'root_admin' or (admin_checker and admin_checker[0] == session.get('user_id')):
            return render_template("dashboard.html", admin=True, patient_count=patient_count, doctor_count=doctor_count, profile_name=profile_name)
        return render_template("dashboard.html", admin=False, patient_count=patient_count, doctor_count=doctor_count, profile_name=profile_name)
    else:
        return redirect(url_for('login'))

@app.route('/patient')
def patient():
    """Patient information page - only accessible to logged-in users."""
    if isadmin() or isuser():
        patient_list = db.execute('SELECT * FROM patients').fetchall()
        is_admin = isadmin()
        return render_template("patient.html", patients=patient_list, admin=is_admin)
    else:
        return redirect(url_for('login'))

@app.route('/add_patient', methods=['GET', 'POST'])
def add_patient():
    """Page/API to add new patient information - accessible to any logged-in account."""
    if isadmin() or isuser():
        if request.method == 'POST':
            name = request.form.get('name')
            age = request.form.get('age')
            gender = request.form.get('gender')
            phone = request.form.get('phone')
            email = request.form.get('email')
            dob = request.form.get('dob')
            blood_group = request.form.get('blood_group')
            address = request.form.get('address')
            emergency_contact_name = request.form.get('emergency_contact_name')
            emergency_contact_phone = request.form.get('emergency_contact_phone')
            medical_history = request.form.get('medical_history')
            is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

            if not name or not age or not gender or not phone or not dob or not blood_group or not address or not emergency_contact_name or not emergency_contact_phone:
                if is_ajax:
                    return {"success": False, "error": "Please fill in all required fields."}, 400
                return render_template("add_patient.html", error="Please fill in all required fields.")
            if not age.isdigit() or int(age) <= 0:
                if is_ajax:
                    return {"success": False, "error": "Please enter a valid age."}, 400
                return render_template("add_patient.html", error="Please enter a valid age.")
            if not phone.isdigit() or len(phone) < 7:
                if is_ajax:
                    return {"success": False, "error": "Please enter a valid phone number."}, 400
                return render_template("add_patient.html", error="Please enter a valid phone number.")
            
            cursor = db.execute('''INSERT INTO patients (name, age, gender, phone, email, dob, blood_group, address, emergency_contact_name, emergency_contact_phone, medical_history) 
                                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                                (name, age, gender, phone, email, dob, blood_group, address, emergency_contact_name, emergency_contact_phone, medical_history))
            db.commit()

            if is_ajax:
                return {"success": True, "patient_id": cursor.lastrowid}, 200

            return redirect(url_for('patient', success="Patient added successfully."))
        return render_template("add_patient.html")
    else:
        return redirect(url_for('login'))

@app.route('/registered_users', methods=['GET', 'POST'])
def registered_users():
    """Page to display registered users - only accessible to admin."""
    if isadmin():
        user_list = db.execute('SELECT * FROM users').fetchall()
        admin_list = db.execute('SELECT * FROM admins').fetchall()
        return render_template("registered_users.html", users=user_list, admins=admin_list)
    else:
        return redirect(url_for('login'))

@app.route('/delete', methods=['POST'])
def delete_user():
    if request.method == 'POST':
        if request.form.get('delete_user'):
            user_id = request.form.get('delete_user')
            db.execute('DELETE FROM users WHERE id = ?', (user_id,))
            db.commit()
            return redirect(url_for('registered_users', delete_message="Employee deleted successfully."))
        
        elif request.form.get('delete_admin'):
                admin_id = request.form.get('delete_admin')
                db.execute('DELETE FROM admins WHERE id = ?', (admin_id,))
                db.commit()
                return redirect(url_for('registered_users', delete_message="Admin deleted successfully."))
    else:
        return redirect(url_for('login'))

@app.route('/doctors', methods=['GET', 'POST'])
def doctors():
    if not isuser() and not isadmin():
        return redirect(url_for('login'))
    """Page to display doctor information."""
    admin_varifier = isadmin()
    doctor_list = db.execute('SELECT * FROM doctors').fetchall()
    return render_template("doctors.html", doctors=doctor_list, admin=admin_varifier)

@app.route('/add_doctor', methods=['GET', 'POST'])
def add_doctor():
    """Page to add new doctor information - only accessible to admin."""
    if not isadmin():
        return redirect(url_for('doctors', message="Only admins can add new doctors."))
    if isadmin():
        if request.method == 'POST':
            name = request.form.get('name')
            phone = request.form.get('phone')
            email = request.form.get('email')
            specialization = request.form.get('specialization')
            department = request.form.get('department')
            license_number = request.form.get('license_number')
            availability = request.form.get('availability')
            experience = request.form.get('experience')
            room_number = request.form.get('room_number')

            if not name or not phone or not email or not specialization or not department or not license_number or not availability or not experience or not room_number:
                return render_template("add_doctor.html", error="Please fill in all required fields.")
            if not phone.isdigit() or len(phone) < 7:
                return render_template("add_doctor.html", error="Please enter a valid phone number.")
            if not experience.isdigit() or int(experience) < 0:
                return render_template("add_doctor.html", error="Please enter a valid number of years of experience.")
            
            db.execute('''INSERT INTO doctors (name, phone, email, specialization, department, license_number, availability, experience, room_number) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (name, phone, email, specialization, department, license_number, availability, experience, room_number))
            db.commit()
            return redirect(url_for('doctors', success="Doctor added successfully."))
        return render_template("add_doctor.html")
    else:
        return redirect(url_for('login'))
    
if __name__ == '__main__':
    app.run(debug=True)