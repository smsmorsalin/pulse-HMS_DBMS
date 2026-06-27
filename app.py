from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory, jsonify
import sqlite3
from datetime import datetime, timedelta
from werkzeug.security import check_password_hash, generate_password_hash

root_admin_username = "admin"
root_admin_password = "admin123"  # In a production environment, use a strong password and consider storing it securely (e.g., in environment variables or a secure vault)

app = Flask(__name__)
app.secret_key = 'xs12a'  # Required for session management

db = sqlite3.connect('hospital.db', check_same_thread=False)  # Connect to the SQLite database
db.execute("PRAGMA foreign_keys = ON")  # Enable foreign key support

PAGE_OPTIONS = [
    {'key': 'dashboard', 'label': 'Dashboard', 'endpoint': 'dashboard', 'icon': 'fas fa-home'},
    {'key': 'patients_registration', 'label': 'Patients Registration', 'endpoint': 'patients_registration', 'icon': 'fas fa-user-plus'},
    {'key': 'ticket_print', 'label': 'Patient Ticket Print', 'endpoint': None, 'icon': 'fas fa-ticket', 'nav': False},
    {'key': 'doctors', 'label': 'Doctors', 'endpoint': 'doctors', 'icon': 'fas fa-user-md'},
    {'key': 'duty_management', 'label': 'Doctor and Nurse Duty', 'endpoint': 'duty_management', 'icon': 'fas fa-clipboard-check'},
    {'key': 'admissions', 'label': 'Admission', 'endpoint': 'admissions', 'icon': 'fas fa-file-medical'},
    {'key': 'appointments_info', 'label': 'Appointments Info', 'endpoint': 'appointments_info', 'icon': 'fa-solid fa-book-medical'},
    {'key': 'appointment_doctors', 'label': 'Appointment Doctors', 'endpoint': 'appointment_doctors', 'icon': 'fas fa-stethoscope'},
    {'key': 'appointment_patients', 'label': 'Appointment Patients', 'endpoint': 'appointment_patients', 'icon': 'fas fa-hospital-user'},
    {'key': 'pathology_dashboard', 'label': 'Pathology', 'endpoint': 'pathology_dashboard', 'icon': 'fas fa-microscope'},
    {'key': 'tests', 'label': 'View Tests', 'endpoint': 'tests', 'icon': 'fas fa-vial'},
    {'key': 'service_desk', 'label': 'Services', 'endpoint': 'service_desk', 'icon': 'fas fa-hand-holding-medical'},
    {'key': 'patient_service', 'label': 'Patient Service Order', 'endpoint': None, 'icon': 'fas fa-notes-medical', 'nav': False},
    {'key': 'medicine_sales', 'label': 'Medicine Sales', 'endpoint': 'medicine_sales', 'icon': 'fas fa-pills'},
    {'key': 'medicine_sales_print', 'label': 'Medicine Sales Print', 'endpoint': None, 'icon': 'fas fa-print', 'nav': False},
    {'key': 'medicine_sales_list', 'label': 'Medicine Sales List', 'endpoint': 'medicine_sales_list', 'icon': 'fas fa-calendar-days'},
    {'key': 'billing', 'label': 'Billing', 'endpoint': 'billing', 'icon': 'fas fa-file-invoice'},
    {'key': 'bill_print', 'label': 'Bill Print', 'endpoint': None, 'icon': 'fas fa-receipt', 'nav': False},
    {'key': 'services', 'label': 'Service Catalog', 'endpoint': 'services', 'icon': 'fas fa-procedures'},
]
DASHBOARD_NAV_KEYS = (
    'dashboard',
    'patients_registration',
    'doctors',
    'duty_management',
    'admissions',
    'appointments_info',
    'pathology_dashboard',
    'tests',
    'service_desk',
    'medicine_sales',
    'billing',
)
PAGE_KEYS = [page['key'] for page in PAGE_OPTIONS]
PAGE_BY_KEY = {page['key']: page for page in PAGE_OPTIONS}
ENDPOINT_PERMISSIONS = {
    'dashboard': ('dashboard',),
    'admin_portal': ('admin_portal',),
    'follow_up_dashboard': ('follow_up_dashboard',),
    'register': ('register',),
    'registered_users': ('registered_users',),
    'logs': ('logs',),
    'patients_registration': ('patients_registration',),
    'patient': ('patients_registration',),
    'add_patient': ('patients_registration',),
    'ticket_print': ('ticket_print', 'patients_registration'),
    'tickets': ('patients_registration',),
    'doctors': ('doctors',),
    'duty_management': ('duty_management',),
    'add_doctor': ('add_doctor',),
    'edit_doctor': ('edit_doctor',),
    'admissions': ('admissions',),
    'discharge_admission': ('admissions',),
    'appointments_info': ('appointments_info',),
    'appointment_doctors': ('appointment_doctors', 'appointments_info'),
    'appointment_patients': ('appointment_patients', 'appointments_info'),
    'pathology_dashboard': ('pathology_dashboard',),
    'tests': ('tests',),
    'service_desk': ('service_desk',),
    'patient_service': ('patient_service', 'service_desk'),
    'bill_print': ('bill_print', 'service_desk', 'billing'),
    'medicine_stock_dashboard': ('medicine_stock_dashboard',),
    'edit_medicine_transaction': ('medicine_stock_dashboard',),
    'delete_medicine_transaction': ('medicine_stock_dashboard',),
    'delete_medicine_balance': ('medicine_stock_dashboard',),
    'medicine_sales': ('medicine_sales',),
    'save_medicine_sale': ('medicine_sales',),
    'medicine_sales_print': ('medicine_sales_print', 'medicine_sales', 'medicine_sales_list'),
    'medicine_sales_list': ('medicine_sales_list',),
    'medicine_monthly_report': ('medicine_monthly_report',),
    'delete_medicine_sale': ('medicine_sales_list',),
    'billing': ('billing',),
    'services': ('services',),
    'add_service': ('add_service',),
    'edit_service': ('edit_service',),
    'delete_service': ('services',),
}

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
                password TEXT NOT NULL,
                email TEXT UNIQUE
            )
        ''')
        print("Users table created successfully.")
    else:
        users_columns = [row[1] for row in cursor.execute("PRAGMA table_info(users)").fetchall()]
        if 'email' not in users_columns:
            cursor.execute('ALTER TABLE users ADD COLUMN email TEXT')
            print("Users table migrated: email column added.")

    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="user_permissions"')
    user_permissions_exists = cursor.fetchone() is not None
    if not user_permissions_exists:
        cursor.execute('''
            CREATE TABLE user_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                page_key TEXT NOT NULL,
                UNIQUE(user_id, page_key),
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        ''')
        existing_user_ids = [row[0] for row in cursor.execute('SELECT id FROM users').fetchall()]
        for existing_user_id in existing_user_ids:
            for page_key in PAGE_KEYS:
                cursor.execute(
                    'INSERT OR IGNORE INTO user_permissions (user_id, page_key) VALUES (?, ?)',
                    (existing_user_id, page_key)
                )
        print("User permissions table created successfully.")
    else:
        placeholders = ','.join('?' for _ in PAGE_KEYS)
        cursor.execute(
            f'DELETE FROM user_permissions WHERE page_key NOT IN ({placeholders})',
            PAGE_KEYS
        )
    
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
                password TEXT NOT NULL,
                email TEXT UNIQUE
            )
        ''')
        print("Admins table created successfully.")
    else:
        admins_columns = [row[1] for row in cursor.execute("PRAGMA table_info(admins)").fetchall()]
        if 'email' not in admins_columns:
            cursor.execute('ALTER TABLE admins ADD COLUMN email TEXT')
            print("Admins table migrated: email column added.")
    
    #patients table
    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="patients"')
    patients_exists = cursor.fetchone() is not None
    if not patients_exists:
        cursor.execute('''
            CREATE TABLE patients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                daily_patient_id INTEGER,
                name TEXT NOT NULL,
                age INTEGER NOT NULL,
                gender TEXT NOT NULL,
                phone TEXT NOT NULL,
                email TEXT,
                dob TEXT NOT NULL,
                blood_group TEXT NOT NULL,
                address TEXT NOT NULL,
                emergency_contact_name TEXT ,
                emergency_contact_phone TEXT ,
                medical_history TEXT,
                created_at TEXT,
                age_unit TEXT DEFAULT 'Y',
                serial_no TEXT,
                patient_status TEXT,
                doctor_name TEXT,
                doctor_designation TEXT,
                referer_name TEXT,
                doctor_fee REAL DEFAULT 0
             )
        ''')
        print("Patients table created successfully.")
    else:
        cursor.execute('PRAGMA table_info(patients)')
        patients_columns = {row[1] for row in cursor.fetchall()}
        if 'created_at' not in patients_columns:
            cursor.execute("ALTER TABLE patients ADD COLUMN created_at TEXT")
            cursor.execute("UPDATE patients SET created_at = datetime('now', '+6 hours') WHERE created_at IS NULL")
        if 'age_unit' not in patients_columns:
            cursor.execute("ALTER TABLE patients ADD COLUMN age_unit TEXT DEFAULT 'Y'")
            cursor.execute("UPDATE patients SET age_unit = 'Y' WHERE age_unit IS NULL OR age_unit = ''")
        if 'daily_patient_id' not in patients_columns:
            cursor.execute("ALTER TABLE patients ADD COLUMN daily_patient_id INTEGER")
        if 'serial_no' not in patients_columns:
            cursor.execute("ALTER TABLE patients ADD COLUMN serial_no TEXT")
        if 'patient_status' not in patients_columns:
            cursor.execute("ALTER TABLE patients ADD COLUMN patient_status TEXT")
        if 'doctor_name' not in patients_columns:
            cursor.execute("ALTER TABLE patients ADD COLUMN doctor_name TEXT")
        if 'doctor_designation' not in patients_columns:
            cursor.execute("ALTER TABLE patients ADD COLUMN doctor_designation TEXT")
        if 'referer_name' not in patients_columns:
            cursor.execute("ALTER TABLE patients ADD COLUMN referer_name TEXT")
        if 'doctor_fee' not in patients_columns:
            cursor.execute("ALTER TABLE patients ADD COLUMN doctor_fee REAL DEFAULT 0")

        patients_missing_daily_id = cursor.execute('''
            SELECT id, COALESCE(date(created_at), date('now', '+6 hours')) AS entry_date
            FROM patients
            WHERE daily_patient_id IS NULL OR daily_patient_id = ''
            ORDER BY entry_date ASC, id ASC
        ''').fetchall()
        for patient_id, entry_date in patients_missing_daily_id:
            next_daily_id = cursor.execute('''
                SELECT COALESCE(MAX(daily_patient_id), 0) + 1
                FROM patients
                WHERE date(created_at) = ?
                  AND daily_patient_id IS NOT NULL
            ''', (entry_date,)).fetchone()[0]
            cursor.execute(
                "UPDATE patients SET daily_patient_id = ? WHERE id = ?",
                (next_daily_id, patient_id)
            )
    
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
                designation TEXT,
                department TEXT NOT NULL,
                license_number TEXT NOT NULL,
                availability TEXT NOT NULL,
                experience INTEGER NOT NULL,
                room_number TEXT NOT NULL
            )
        ''')
        print("Doctors table created successfully.")
    else:
        doctors_columns = {row[1] for row in cursor.execute("PRAGMA table_info(doctors)").fetchall()}
        if 'designation' not in doctors_columns:
            cursor.execute("ALTER TABLE doctors ADD COLUMN designation TEXT")
            print("Doctors table migrated: designation column added.")

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

    #admissions table
    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="admissions"')
    admissions_exists = cursor.fetchone() is not None
    if not admissions_exists:
        cursor.execute('''
            CREATE TABLE admissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER NOT NULL,
                doctor_id INTEGER,
                admission_date TEXT NOT NULL,
                ward TEXT NOT NULL,
                room_number TEXT,
                bed_number TEXT NOT NULL,
                reason TEXT NOT NULL,
                notes TEXT,
                status TEXT NOT NULL DEFAULT 'Admitted',
                discharged_at TEXT,
                created_by INTEGER,
                created_at TEXT NOT NULL,

                FOREIGN KEY (patient_id) REFERENCES patients(id),
                FOREIGN KEY (doctor_id) REFERENCES doctors(id)
            )
        ''')
        print("Admissions table created successfully.")
    else:
        cursor.execute('PRAGMA table_info(admissions)')
        admission_columns = {row[1] for row in cursor.fetchall()}
        admission_migrations = {
            'doctor_id': 'ALTER TABLE admissions ADD COLUMN doctor_id INTEGER',
            'notes': 'ALTER TABLE admissions ADD COLUMN notes TEXT',
            'status': "ALTER TABLE admissions ADD COLUMN status TEXT NOT NULL DEFAULT 'Admitted'",
            'discharged_at': 'ALTER TABLE admissions ADD COLUMN discharged_at TEXT',
            'created_by': 'ALTER TABLE admissions ADD COLUMN created_by INTEGER',
            'created_at': "ALTER TABLE admissions ADD COLUMN created_at TEXT NOT NULL DEFAULT ''"
        }
        for column_name, alter_sql in admission_migrations.items():
            if column_name not in admission_columns:
                cursor.execute(alter_sql)
        cursor.execute("UPDATE admissions SET status = 'Admitted' WHERE status IS NULL OR status = ''")
        cursor.execute("UPDATE admissions SET created_at = datetime('now', '+6 hours') WHERE created_at IS NULL OR created_at = ''")

    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="duty_records"')
    duty_records_exists = cursor.fetchone() is not None
    if not duty_records_exists:
        cursor.execute('''
            CREATE TABLE duty_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                staff_role TEXT CHECK(staff_role IN ('doctor','nurse')) NOT NULL,
                doctor_id INTEGER,
                staff_name TEXT NOT NULL,
                duty_date TEXT NOT NULL,
                shift TEXT NOT NULL,
                ward TEXT NOT NULL,
                round_completed INTEGER NOT NULL DEFAULT 0,
                notes TEXT,
                created_by TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (doctor_id) REFERENCES doctors(id)
            )
        ''')
        print("Duty Records table created successfully.")

    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="medicine_transactions"')
    medicine_transactions_exists = cursor.fetchone() is not None
    if not medicine_transactions_exists:
        cursor.execute('''
            CREATE TABLE medicine_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                medicine_name TEXT NOT NULL,
                batch_no TEXT NOT NULL,
                unit_type TEXT NOT NULL DEFAULT 'strip',
                transaction_type TEXT CHECK(transaction_type IN ('in', 'out')) NOT NULL,
                quantity INTEGER NOT NULL,
                price REAL NOT NULL,
                transaction_date TEXT NOT NULL,
                note TEXT,
                created_by TEXT,
                created_at TEXT NOT NULL
            )
        ''')
        print("Medicine Transactions table created successfully.")
    else:
        cursor.execute('PRAGMA table_info(medicine_transactions)')
        medicine_transactions_columns = {row[1] for row in cursor.fetchall()}
        if 'unit_type' not in medicine_transactions_columns:
            cursor.execute("ALTER TABLE medicine_transactions ADD COLUMN unit_type TEXT NOT NULL DEFAULT 'strip'")

    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="medicine_sales"')
    medicine_sales_exists = cursor.fetchone() is not None
    if not medicine_sales_exists:
        cursor.execute('''
            CREATE TABLE medicine_sales (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice_no TEXT UNIQUE NOT NULL,
                customer_name TEXT NOT NULL,
                customer_phone TEXT,
                subtotal REAL NOT NULL DEFAULT 0,
                discount_type TEXT NOT NULL DEFAULT 'flat',
                discount_value REAL NOT NULL DEFAULT 0,
                discount_amount REAL NOT NULL DEFAULT 0,
                tax_type TEXT NOT NULL DEFAULT 'none',
                tax_value REAL NOT NULL DEFAULT 0,
                tax_amount REAL NOT NULL DEFAULT 0,
                delivery_cost REAL NOT NULL DEFAULT 0,
                grand_total REAL NOT NULL DEFAULT 0,
                received_amount REAL NOT NULL DEFAULT 0,
                due_amount REAL NOT NULL DEFAULT 0,
                change_amount REAL NOT NULL DEFAULT 0,
                payment_type TEXT NOT NULL DEFAULT 'Cash',
                sale_date TEXT NOT NULL,
                created_by TEXT,
                created_at TEXT NOT NULL
            )
        ''')
        print("Medicine Sales table created successfully.")

    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="medicine_sale_items"')
    medicine_sale_items_exists = cursor.fetchone() is not None
    if not medicine_sale_items_exists:
        cursor.execute('''
            CREATE TABLE medicine_sale_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sale_id INTEGER NOT NULL,
                medicine_name TEXT NOT NULL,
                batch_no TEXT NOT NULL,
                unit_type TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                unit_price REAL NOT NULL,
                discount REAL NOT NULL DEFAULT 0,
                line_total REAL NOT NULL DEFAULT 0,
                FOREIGN KEY (sale_id) REFERENCES medicine_sales(id)
            )
        ''')
        print("Medicine Sale Items table created successfully.")

    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="logs"')
    logs_exists = cursor.fetchone() is not None

    #logs table
    if not logs_exists:
        cursor.execute('''
            CREATE TABLE logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                role TEXT CHECK(role IN ('admin','user')) NOT NULL,
                actor_name TEXT,
                patient_id INTEGER,
                action TEXT,
                timestamp TEXT
            )
        ''')
        print("Logs table created successfully.")

    else:
        cursor.execute('PRAGMA table_info(logs)')
        logs_columns = {row[1] for row in cursor.fetchall()}
        if 'actor_name' not in logs_columns:
            cursor.execute("ALTER TABLE logs ADD COLUMN actor_name TEXT")
            print("Logs table migrated: actor_name column added.")
        print("Hospital database already exists.")

    #Triggers
    #update total_amount in bills table after inserting a new bill item
    cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS update_bill_total
        AFTER INSERT ON bill_items
        BEGIN
            UPDATE bills
            SET total_amount = (
                SELECT SUM(price * quantity)
                FROM bill_items
                WHERE bill_id = NEW.bill_id
            )
            WHERE id = NEW.bill_id;
        END;
        ''')

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

def get_user_page_keys(user_id=None):
    """Return page keys assigned to a regular user."""
    if user_id is None:
        user_id = session.get('user_id')
    if not user_id or user_id == 'root_admin':
        return []
    rows = db.execute(
        '''
        SELECT page_key
        FROM user_permissions
        WHERE user_id = ?
        ORDER BY id ASC
        ''',
        (user_id,)
    ).fetchall()
    return [row[0] for row in rows if row[0] in PAGE_BY_KEY]

def get_user_pages(user_id=None):
    """Return the page metadata assigned to a regular user."""
    assigned_keys = set(get_user_page_keys(user_id))
    return [page for page in PAGE_OPTIONS if page['key'] in assigned_keys]

def get_direct_nav_pages(pages, include_admin_only=True):
    """Return pages that can be opened directly from a menu."""
    return [
        page for page in pages
        if page.get('endpoint') and page.get('nav', True)
        and (include_admin_only or not page.get('admin_only'))
    ]

def set_user_page_permissions(user_id, page_keys):
    """Replace a regular user's page permissions."""
    clean_keys = [page_key for page_key in page_keys if page_key in PAGE_BY_KEY]
    db.execute('DELETE FROM user_permissions WHERE user_id = ?', (user_id,))
    for page_key in clean_keys:
        db.execute(
            'INSERT OR IGNORE INTO user_permissions (user_id, page_key) VALUES (?, ?)',
            (user_id, page_key)
        )

def user_has_any_page(page_keys, user_id=None):
    """Check whether a regular user has at least one requested page key."""
    assigned_keys = set(get_user_page_keys(user_id))
    return any(page_key in assigned_keys for page_key in page_keys)

def can_access_page(page_key):
    """Template helper for hiding links the signed-in account cannot open."""
    if isadmin():
        return True
    if not isuser():
        return False
    return user_has_any_page((page_key,))

def get_first_allowed_page(user_id=None):
    """Return the first assigned page for a user, or None when no access is set."""
    pages = get_direct_nav_pages(get_user_pages(user_id), include_admin_only=False)
    return pages[0] if pages else None

@app.context_processor
def inject_permission_helpers():
    return {
        'page_options': PAGE_OPTIONS,
        'can_access_page': can_access_page,
        'format_date_display': format_date_display,
    }

@app.before_request
def enforce_user_page_permissions():
    """Enforce page-level permissions for regular users."""
    if request.endpoint in (None, 'login', 'logout', 'assets', 'static'):
        return None
    if isadmin() or not isuser():
        return None

    required_page_keys = ENDPOINT_PERMISSIONS.get(request.endpoint)
    if not required_page_keys or user_has_any_page(required_page_keys):
        return None

    if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({'success': False, 'error': 'You do not have permission to open this page.'}), 403

    first_allowed_page = get_first_allowed_page()
    if first_allowed_page:
        return redirect(url_for(first_allowed_page['endpoint']))
    session.clear()
    return redirect(url_for('login'))

def get_current_actor():
    """Return the current actor id, role, and display name for audit logs."""
    user_id = session.get('user_id')

    if user_id == 'root_admin':
        return None, 'admin', root_admin_username

    admin_checker = db.execute('SELECT username FROM admins WHERE id=?', (user_id,)).fetchone()
    if admin_checker:
        return user_id, 'admin', admin_checker[0]

    user_checker = db.execute('SELECT username FROM users WHERE id=?', (user_id,)).fetchone()
    if user_checker:
        return user_id, 'user', user_checker[0]

    return user_id, 'user', 'Unknown user'


def amount_to_words(amount):
    """Convert a Taka amount into simple uppercase English words."""
    try:
        amount = int(round(float(amount or 0)))
    except (TypeError, ValueError):
        amount = 0

    if amount == 0:
        return 'ZERO'

    ones = [
        '', 'One', 'Two', 'Three', 'Four', 'Five', 'Six', 'Seven', 'Eight',
        'Nine', 'Ten', 'Eleven', 'Twelve', 'Thirteen', 'Fourteen', 'Fifteen',
        'Sixteen', 'Seventeen', 'Eighteen', 'Nineteen'
    ]
    tens = [
        '', '', 'Twenty', 'Thirty', 'Forty', 'Fifty', 'Sixty', 'Seventy',
        'Eighty', 'Ninety'
    ]

    def under_hundred(number):
        if number < 20:
            return ones[number]
        return (tens[number // 10] + ' ' + ones[number % 10]).strip()

    def under_thousand(number):
        if number < 100:
            return under_hundred(number)
        return (ones[number // 100] + ' Hundred ' + under_hundred(number % 100)).strip()

    parts = []
    for value, label in ((10000000, 'Crore'), (100000, 'Lakh'), (1000, 'Thousand')):
        if amount >= value:
            parts.append(under_thousand(amount // value) + ' ' + label)
            amount %= value
    if amount:
        parts.append(under_thousand(amount))

    return ' '.join(parts).upper()


def format_invoice_datetime(value):
    """Format stored ISO-like dates as DD-MM-YYYY for printable invoices."""
    if not value:
        return '-'

    text_value = str(value)
    for date_format, output_format in (
        ('%Y-%m-%d %H:%M:%S', '%d-%m-%Y %H:%M:%S'),
        ('%Y-%m-%d', '%d-%m-%Y'),
    ):
        try:
            return datetime.strptime(text_value, date_format).strftime(output_format)
        except ValueError:
            continue

    return text_value

def format_date_display(value):
    """Format date text as DD-MM-YYYY, preserving time when present."""
    if not value:
        return '-'

    text_value = str(value)
    for date_format, output_format in (
        ('%Y-%m-%d %H:%M:%S', '%d-%m-%Y %H:%M:%S'),
        ('%Y-%m-%d %H:%M', '%d-%m-%Y %H:%M'),
        ('%Y-%m-%d', '%d-%m-%Y'),
    ):
        try:
            return datetime.strptime(text_value, date_format).strftime(output_format)
        except ValueError:
            continue

    return text_value


def add_log(patient_id, action, actor=None):
    user_id_db, role, actor_name = actor or get_current_actor()

    db.execute('''
        INSERT INTO logs (user_id, role, actor_name, patient_id, action, timestamp)
        VALUES (?, ?, ?, ?, ?, datetime('now', '+6 hours'))
    ''', (user_id_db, role, actor_name, patient_id, action))
    db.commit()


def add_system_log(action, patient_id=None, actor=None):
    """Record an admin/user activity in the existing logs table."""
    add_log(patient_id, action, actor)


def get_medicine_balance_rows(search_query='', positive_only=False, limit=None):
    """Return medicine stock balances using one calculation for stock and sales screens."""
    transaction_rows = db.execute(
        '''
        SELECT id, medicine_name, batch_no, unit_type, transaction_type, quantity, price, transaction_date, note, created_by, created_at
        FROM medicine_transactions
        ORDER BY transaction_date ASC, id ASC
        '''
    ).fetchall()

    summary = {}
    for row in transaction_rows:
        medicine_name = row[1]
        batch_no = row[2] or 'General'
        unit_type = row[3] or 'strip'
        summary_key = (medicine_name, batch_no, unit_type)
        medicine_summary = summary.setdefault(summary_key, {
            'medicine_name': medicine_name,
            'batch_no': batch_no,
            'unit_type': unit_type,
            'stock_in': 0,
            'stock_out': 0,
            'balance': 0,
            'latest_price': row[6],
            'latest_date': row[7],
        })

        if row[4] == 'in':
            medicine_summary['stock_in'] += row[5]
            medicine_summary['balance'] += row[5]
        else:
            medicine_summary['stock_out'] += row[5]
            medicine_summary['balance'] -= row[5]

        medicine_summary['latest_price'] = row[6]
        medicine_summary['latest_date'] = row[7]

    summary_rows = list(summary.values())
    if search_query:
        search_text = search_query.lower()
        summary_rows = [
            row for row in summary_rows
            if search_text in row['medicine_name'].lower() or search_text in row['batch_no'].lower()
        ]
    if positive_only:
        summary_rows = [row for row in summary_rows if row['balance'] > 0]

    summary_rows.sort(key=lambda row: (row['medicine_name'].lower(), row['batch_no'].lower(), row['unit_type'].lower()))
    if limit is not None:
        summary_rows = summary_rows[:limit]
    return summary_rows


@app.route('/register', methods=['GET', 'POST'])
def register():
    if not isadmin():
        return redirect(url_for('login'))

    if request.method == 'POST':
        role = request.form.get('role')
        username = request.form.get('username')
        password = request.form.get('password')
        email = request.form.get('email')
        page_keys = request.form.getlist('page_permissions')
        if not role or not username or not password or not email:
            return render_template("register.html", error="Please fill in all fields.")
        if role == 'user' and not page_keys:
            return render_template("register.html", error="Please choose at least one page this user can access.")
        else:
            if isadmin():
                hashed_password = generate_password_hash(password)
                if role == 'admin':
                    try:
                        db.execute('INSERT INTO admins (username, password, email) VALUES (?, ?, ?)', (username, hashed_password, email))
                        db.commit()
                        add_system_log(f"Admin account created: {username} ({email})")
                        return redirect(url_for('registered_users', success=f"Admin registered successfully."))
                    except sqlite3.IntegrityError:
                        return render_template("register.html", error="Username or email already exists. Please use different credentials.")
                else:  # role == 'user'
                    try:
                        user_cursor = db.execute('INSERT INTO users (username, password, email) VALUES (?, ?, ?)', (username, hashed_password, email))
                        set_user_page_permissions(user_cursor.lastrowid, page_keys)
                        db.commit()
                        add_system_log(f"Employee account created: {username} ({email})")
                        return redirect(url_for('registered_users', success=f"Employee registered successfully."))
                    except sqlite3.IntegrityError:
                        return render_template("register.html", error="Username or email already exists. Please use different credentials.")

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
                    first_allowed_page = get_first_allowed_page(user_checker[0])
                    if not first_allowed_page:
                        session.clear()
                        return render_template("login.html", error="No page permission assigned. Please contact admin.")
                    return redirect(url_for(first_allowed_page['endpoint'], user_success="login successful"))
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


@app.route('/logs')
def logs():
    """Admin activity logs page."""
    if not isadmin():
        return redirect(url_for('login'))

    log_rows = db.execute(
        '''
        SELECT
            l.id,
            l.user_id,
            l.role,
            l.actor_name,
            l.patient_id,
            l.action,
            l.timestamp,
            COALESCE(a.username, u.username) AS actor_name,
            p.name AS patient_name
        FROM logs l
        LEFT JOIN admins a ON l.role = 'admin' AND l.user_id = a.id
        LEFT JOIN users u ON l.role = 'user' AND l.user_id = u.id
        LEFT JOIN patients p ON l.patient_id = p.id
        ORDER BY l.id DESC
        LIMIT 300
        '''
    ).fetchall()

    logs_list = []
    for row in log_rows:
        actor_name = row[3] or row[7]
        if not actor_name and row[2] == 'admin' and row[1] is None:
            actor_name = root_admin_username
        logs_list.append({
            'id': row[0],
            'user_id': row[1],
            'role': row[2],
            'patient_id': row[4],
            'action': row[5],
            'timestamp': row[6],
            'actor_name': actor_name or 'Unknown user',
            'patient_name': row[8] or ('Deleted patient' if row[4] else ''),
        })

    return render_template("logs.html", logs=logs_list, total_logs=len(logs_list))


@app.route('/follow_up_dashboard')
def follow_up_dashboard():
    """Admin follow-up dashboard with daily operational records in one screen."""
    if not isadmin():
        return redirect(url_for('login'))

    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (session.get('user_id'),)).fetchone()
    profile_name = root_admin_username if session.get('user_id') == 'root_admin' else admin_checker[1]

    selected_date = request.args.get('date', '').strip() or datetime.now().strftime('%Y-%m-%d')
    try:
        datetime.strptime(selected_date, '%Y-%m-%d')
    except ValueError:
        selected_date = datetime.now().strftime('%Y-%m-%d')

    selected_month = selected_date[:7]

    patient_count = db.execute(
        'SELECT COUNT(*) FROM patients WHERE date(created_at) = ?',
        (selected_date,)
    ).fetchone()[0]
    active_admission_count = db.execute(
        "SELECT COUNT(*) FROM admissions WHERE status = 'Admitted'"
    ).fetchone()[0]
    test_order_count = db.execute(
        'SELECT COUNT(*) FROM test_orders WHERE date(test_date) = ?',
        (selected_date,)
    ).fetchone()[0]
    appointment_count = db.execute(
        'SELECT COUNT(*) FROM appointments WHERE date(appointment_date) = ?',
        (selected_date,)
    ).fetchone()[0]
    bill_summary = db.execute(
        '''
        SELECT COUNT(*), COALESCE(SUM(total_amount), 0)
        FROM bills
        WHERE date(created_at) = ?
        ''',
        (selected_date,)
    ).fetchone()
    medicine_summary = db.execute(
        '''
        SELECT
            COUNT(*),
            COALESCE(SUM(grand_total), 0),
            COALESCE(SUM(received_amount), 0),
            COALESCE(SUM(due_amount), 0)
        FROM medicine_sales
        WHERE date(sale_date) = ?
        ''',
        (selected_date,)
    ).fetchone()
    compliance_count = db.execute(
        'SELECT COUNT(*) FROM logs WHERE date(timestamp) = ?',
        (selected_date,)
    ).fetchone()[0]
    duty_rows = db.execute(
        '''
        SELECT id, staff_role, staff_name, duty_date, shift, ward, round_completed, notes, created_at
        FROM duty_records
        WHERE date(duty_date) = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 25
        ''',
        (selected_date,)
    ).fetchall()
    duty_completed = sum(1 for row in duty_rows if row[6])

    summary_cards = [
        {'label': 'Daily Patients', 'value': patient_count, 'icon': 'fas fa-hospital-user', 'note': 'Registered today'},
        {'label': 'Appointments', 'value': appointment_count, 'icon': 'fas fa-stethoscope', 'note': 'Doctor visits today'},
        {'label': 'Test Orders', 'value': test_order_count, 'icon': 'fas fa-vial', 'note': 'Pathology orders today'},
        {'label': 'Active Admissions', 'value': active_admission_count, 'icon': 'fas fa-bed-pulse', 'note': 'Currently admitted'},
        {'label': 'Service Bills', 'value': bill_summary[0] or 0, 'icon': 'fas fa-file-invoice', 'note': f"Tk {float(bill_summary[1] or 0):.2f}"},
        {'label': 'Medicine Sales', 'value': medicine_summary[0] or 0, 'icon': 'fas fa-pills', 'note': f"Tk {float(medicine_summary[1] or 0):.2f}"},
        {'label': 'Medicine Due', 'value': f"Tk {float(medicine_summary[3] or 0):.2f}", 'icon': 'fas fa-hand-holding-dollar', 'note': 'Pending pharmacy amount'},
        {'label': 'Compliance Logs', 'value': compliance_count, 'icon': 'fas fa-shield-halved', 'note': 'Actions recorded today'},
    ]

    compliance_logs = db.execute(
        '''
        SELECT
            l.id,
            l.user_id,
            l.role,
            l.actor_name,
            l.patient_id,
            l.action,
            l.timestamp,
            COALESCE(a.username, u.username) AS resolved_actor_name,
            p.name AS patient_name
        FROM logs l
        LEFT JOIN admins a ON l.role = 'admin' AND l.user_id = a.id
        LEFT JOIN users u ON l.role = 'user' AND l.user_id = u.id
        LEFT JOIN patients p ON l.patient_id = p.id
        WHERE date(l.timestamp) = ?
        ORDER BY l.id DESC
        LIMIT 25
        ''',
        (selected_date,)
    ).fetchall()

    medicine_sales_rows = db.execute(
        '''
        SELECT
            id, invoice_no, customer_name, customer_phone, subtotal, discount_amount,
            grand_total, received_amount, due_amount, payment_type, sale_date, created_at
        FROM medicine_sales
        WHERE date(sale_date) = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 20
        ''',
        (selected_date,)
    ).fetchall()

    medicine_sales = []
    for row in medicine_sales_rows:
        item_rows = db.execute(
            '''
            SELECT medicine_name, batch_no, unit_type, quantity, unit_price, discount, line_total
            FROM medicine_sale_items
            WHERE sale_id = ?
            ORDER BY id ASC
            ''',
            (row[0],)
        ).fetchall()
        medicine_sales.append({
            'id': row[0],
            'invoice_no': row[1],
            'customer_name': row[2],
            'customer_phone': row[3],
            'subtotal': float(row[4] or 0),
            'discount_amount': float(row[5] or 0),
            'grand_total': float(row[6] or 0),
            'received_amount': float(row[7] or 0),
            'due_amount': float(row[8] or 0),
            'payment_type': row[9],
            'sale_date': row[10],
            'created_at': row[11],
            'items': item_rows,
        })

    patient_rows = db.execute(
        '''
        SELECT id, daily_patient_id, name, age, age_unit, gender, phone, patient_status,
               doctor_name, doctor_fee, created_at
        FROM patients
        WHERE date(created_at) = ?
        ORDER BY id DESC
        LIMIT 20
        ''',
        (selected_date,)
    ).fetchall()

    service_bills = db.execute(
        '''
        SELECT b.id, p.name, p.phone, b.total_amount, b.created_at
        FROM bills b
        JOIN patients p ON b.patient_id = p.id
        WHERE date(b.created_at) = ?
        ORDER BY b.id DESC
        LIMIT 20
        ''',
        (selected_date,)
    ).fetchall()

    appointments = db.execute(
        '''
        SELECT a.id, p.name, p.phone, COALESCE(d.name, 'Not assigned'),
               COALESCE(s.name, 'Doctor service'), a.appointment_date
        FROM appointments a
        JOIN patients p ON a.patient_id = p.id
        LEFT JOIN doctors d ON a.doctor_id = d.id
        LEFT JOIN services s ON a.service_id = s.id
        WHERE date(a.appointment_date) = ?
        ORDER BY a.id DESC
        LIMIT 15
        ''',
        (selected_date,)
    ).fetchall()

    test_orders = db.execute(
        '''
        SELECT t.id, p.name, p.phone, s.name, s.price, t.test_date
        FROM test_orders t
        JOIN patients p ON p.id = t.patient_id
        JOIN services s ON s.id = t.service_id
        WHERE date(t.test_date) = ?
        ORDER BY t.id DESC
        LIMIT 15
        ''',
        (selected_date,)
    ).fetchall()

    admissions_today = db.execute(
        '''
        SELECT a.id, p.name, p.phone, a.ward, a.bed_number, a.status, a.admission_date, a.created_at
        FROM admissions a
        JOIN patients p ON a.patient_id = p.id
        WHERE date(a.created_at) = ?
        ORDER BY a.id DESC
        LIMIT 15
        ''',
        (selected_date,)
    ).fetchall()

    low_stock_rows = [
        row for row in get_medicine_balance_rows(positive_only=True)
        if row['balance'] <= 10
    ][:10]

    month_totals = db.execute(
        '''
        SELECT
            COALESCE((SELECT SUM(total_amount) FROM bills WHERE strftime('%Y-%m', created_at) = ?), 0),
            COALESCE((SELECT SUM(grand_total) FROM medicine_sales WHERE strftime('%Y-%m', sale_date) = ?), 0),
            COALESCE((SELECT COUNT(*) FROM patients WHERE strftime('%Y-%m', created_at) = ?), 0)
        ''',
        (selected_month, selected_month, selected_month)
    ).fetchone()

    return render_template(
        'follow_up_dashboard.html',
        profile_name=profile_name,
        selected_date=selected_date,
        selected_month=selected_month,
        summary_cards=summary_cards,
        compliance_logs=compliance_logs,
        medicine_sales=medicine_sales,
        patient_rows=patient_rows,
        service_bills=service_bills,
        appointments=appointments,
        test_orders=test_orders,
        admissions_today=admissions_today,
        low_stock_rows=low_stock_rows,
        duty_rows=duty_rows,
        duty_completed=duty_completed,
        duty_pending=len(duty_rows) - duty_completed,
        month_totals={
            'service_revenue': float(month_totals[0] or 0),
            'medicine_revenue': float(month_totals[1] or 0),
            'patients': int(month_totals[2] or 0),
        },
    )


@app.route('/dashboard')
def dashboard():
    """User dashboard page - only accessible to logged-in users."""
    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (session.get('user_id'),)).fetchone()
    user_checker = db.execute('SELECT * FROM users WHERE id = ?', (session.get('user_id'),)).fetchone()

    if isadmin() or isuser():
        patient_count = db.execute('SELECT COUNT(*) FROM patients').fetchone()[0]
        doctor_count = db.execute('SELECT COUNT(*) FROM doctors').fetchone()[0]
        active_admission_count = db.execute("SELECT COUNT(*) FROM admissions WHERE status = 'Admitted'").fetchone()[0]
        # Show the authenticated account name in the dashboard profile dropdown.
        if session.get('user_id') == 'root_admin':
            profile_name = root_admin_username
        elif admin_checker and admin_checker[0] == session.get('user_id'):
            profile_name = admin_checker[1]
        else:
            profile_name = user_checker[1]
        nav_pages = get_direct_nav_pages(
            PAGE_OPTIONS if isadmin() else get_user_pages(),
            include_admin_only=isadmin()
        )
        if isadmin():
            return render_template("dashboard.html", admin=True, patient_count=patient_count, doctor_count=doctor_count, active_admission_count=active_admission_count, profile_name=profile_name, nav_pages=nav_pages)
        return render_template("dashboard.html", admin=False, patient_count=patient_count, doctor_count=doctor_count, active_admission_count=active_admission_count, profile_name=profile_name, nav_pages=nav_pages)
    else:
        return redirect(url_for('login'))

@app.route('/pathology_dashboard')
def pathology_dashboard():
    """Pathology lab dashboard backed by test services and test orders."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (session.get('user_id'),)).fetchone()
    user_checker = db.execute('SELECT * FROM users WHERE id = ?', (session.get('user_id'),)).fetchone()

    if session.get('user_id') == 'root_admin':
        profile_name = root_admin_username
    elif admin_checker and admin_checker[0] == session.get('user_id'):
        profile_name = admin_checker[1]
    else:
        profile_name = user_checker[1]

    selected_date = request.args.get('date', '').strip() or datetime.now().strftime('%Y-%m-%d')
    try:
        selected_day = datetime.strptime(selected_date, '%Y-%m-%d')
    except ValueError:
        selected_date = datetime.now().strftime('%Y-%m-%d')
        selected_day = datetime.strptime(selected_date, '%Y-%m-%d')

    selected_month = selected_date[:7]
    week_start = (selected_day - timedelta(days=6)).strftime('%Y-%m-%d')

    available_tests = db.execute("SELECT COUNT(*) FROM services WHERE type = 'test'").fetchone()[0]
    day_orders = db.execute(
        "SELECT COUNT(*) FROM test_orders WHERE date(test_date) = ?",
        (selected_date,)
    ).fetchone()[0]
    day_patients = db.execute(
        "SELECT COUNT(DISTINCT patient_id) FROM test_orders WHERE date(test_date) = ?",
        (selected_date,)
    ).fetchone()[0]
    month_orders = db.execute(
        "SELECT COUNT(*) FROM test_orders WHERE strftime('%Y-%m', test_date) = ?",
        (selected_month,)
    ).fetchone()[0]
    month_revenue = db.execute(
        '''
        SELECT COALESCE(SUM(bi.price * bi.quantity), 0)
        FROM bill_items bi
        JOIN bills b ON b.id = bi.bill_id
        JOIN services s ON s.id = bi.service_id
        WHERE s.type = 'test'
          AND strftime('%Y-%m', b.created_at) = ?
        ''',
        (selected_month,)
    ).fetchone()[0] or 0

    recent_orders = db.execute(
        '''
        SELECT t.id, p.name, p.phone, s.name, s.price, t.test_date
        FROM test_orders t
        JOIN patients p ON p.id = t.patient_id
        JOIN services s ON s.id = t.service_id
        WHERE date(t.test_date) = ?
        ORDER BY t.id DESC
        LIMIT 10
        ''',
        (selected_date,)
    ).fetchall()

    popular_tests = db.execute(
        '''
        SELECT s.name, s.price, COUNT(t.id) AS order_count
        FROM services s
        LEFT JOIN test_orders t
            ON t.service_id = s.id
           AND strftime('%Y-%m', t.test_date) = ?
        WHERE s.type = 'test'
        GROUP BY s.id, s.name, s.price
        ORDER BY order_count DESC, s.name ASC
        LIMIT 6
        ''',
        (selected_month,)
    ).fetchall()
    max_test_orders = max([row[2] for row in popular_tests], default=0)

    daily_rows = db.execute(
        '''
        SELECT date(test_date), COUNT(*)
        FROM test_orders
        WHERE date(test_date) BETWEEN ? AND ?
        GROUP BY date(test_date)
        ''',
        (week_start, selected_date)
    ).fetchall()
    daily_counts = {row[0]: row[1] for row in daily_rows}
    day_activity = []
    max_day_orders = max(daily_counts.values(), default=0)
    for offset in range(7):
        current_day = selected_day - timedelta(days=6 - offset)
        date_key = current_day.strftime('%Y-%m-%d')
        count = daily_counts.get(date_key, 0)
        day_activity.append({
            'label': current_day.strftime('%a'),
            'date': date_key,
            'count': count,
            'percent': round((count / max_day_orders) * 100) if max_day_orders else 0
        })

    return render_template(
        'pathology_dashboard.html',
        profile_name=profile_name,
        admin=isadmin(),
        selected_date=selected_date,
        available_tests=available_tests,
        day_orders=day_orders,
        day_patients=day_patients,
        month_orders=month_orders,
        month_revenue=month_revenue,
        recent_orders=recent_orders,
        popular_tests=popular_tests,
        max_test_orders=max_test_orders,
        day_activity=day_activity
    )


@app.route('/medicine_stock_dashboard', methods=['GET', 'POST'])
def medicine_stock_dashboard():
    """Medicine stock dashboard page - only accessible to admins."""
    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (session.get('user_id'),)).fetchone()
    user_checker = db.execute('SELECT * FROM users WHERE id = ?', (session.get('user_id'),)).fetchone()

    if not (isadmin() or isuser()):
        return redirect(url_for('login'))
    if not isadmin():
        return redirect(url_for('medicine_sales'))

    if session.get('user_id') == 'root_admin':
        profile_name = root_admin_username
    elif admin_checker and admin_checker[0] == session.get('user_id'):
        profile_name = admin_checker[1]
    else:
        profile_name = user_checker[1]

    transaction_rows = db.execute(
        '''
        SELECT id, medicine_name, batch_no, unit_type, transaction_type, quantity, price, transaction_date, note, created_by, created_at
        FROM medicine_transactions
        ORDER BY transaction_date ASC, id ASC
        '''
    ).fetchall()

    transactions = [
        {
            'id': row[0],
            'medicine_name': row[1],
            'batch_no': row[2],
            'unit_type': row[3],
            'transaction_type': row[4],
            'quantity': row[5],
            'price': row[6],
            'transaction_date': row[7],
            'note': row[8] or 'No remarks added',
            'created_by': row[9],
            'created_at': row[10],
        }
        for row in transaction_rows
    ]

    error = None

    if request.method == 'POST':
        medicine_name = request.form.get('medicine_name', '').strip()
        batch_no = request.form.get('batch_no', '').strip()
        unit_type = request.form.get('unit_type', 'strip').strip().lower()
        transaction_type = request.form.get('transaction_type', '').strip()
        quantity = request.form.get('quantity', '').strip()
        price = request.form.get('price', '').strip()
        transaction_date = request.form.get('transaction_date', '').strip() or datetime.now().strftime('%Y-%m-%d')
        note = request.form.get('note', '').strip()

        try:
            quantity_value = int(quantity)
            price_value = float(price)
            if transaction_type == 'in' and not isadmin():
                raise PermissionError
            if not medicine_name or unit_type not in ('strip', 'box') or transaction_type != 'in' or quantity_value <= 0 or price_value <= 0:
                raise ValueError

            db.execute(
                '''
                INSERT INTO medicine_transactions (
                    medicine_name, batch_no, unit_type, transaction_type, quantity, price,
                    transaction_date, note, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    medicine_name,
                    batch_no or 'General',
                    unit_type,
                    transaction_type,
                    quantity_value,
                    price_value,
                    transaction_date,
                    note or 'No remarks added',
                    str(session.get('user_id')),
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                )
            )
            db.commit()
            return redirect(url_for('medicine_stock_dashboard'))
        except PermissionError:
            error = 'Only admin can stock in medicine.'
        except (ValueError, TypeError):
            if not error:
                error = 'Please enter a valid medicine name, unit, quantity, and price.'

    summary_rows = get_medicine_balance_rows()
    total_stock_in = sum(row['stock_in'] for row in summary_rows)
    total_stock_out = sum(row['stock_out'] for row in summary_rows)
    active_medicines = len(summary_rows)
    low_stock_count = sum(1 for row in summary_rows if 0 < row['balance'] <= 10)
    inventory_value = sum(row['balance'] * row['latest_price'] for row in summary_rows if row['balance'] > 0)

    newest_transactions = list(reversed(transactions))
    recent_stock_in = [entry for entry in newest_transactions if entry['transaction_type'] == 'in'][:8]
    recent_stock_out = [entry for entry in newest_transactions if entry['transaction_type'] == 'out'][:8]

    return render_template(
        "medicine_stock_dashboard.html",
        profile_name=profile_name,
        error=error,
        summary_rows=summary_rows,
        recent_stock_in=recent_stock_in,
        recent_stock_out=recent_stock_out,
        total_stock_in=total_stock_in,
        total_stock_out=total_stock_out,
        active_medicines=active_medicines,
        low_stock_count=low_stock_count,
        inventory_value=inventory_value,
        today=datetime.now().strftime('%Y-%m-%d'),
        admin=isadmin(),
    )


@app.route('/medicine_sales')
def medicine_sales():
    """Medicine POS sales screen - only accessible to logged-in users."""
    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (session.get('user_id'),)).fetchone()
    user_checker = db.execute('SELECT * FROM users WHERE id = ?', (session.get('user_id'),)).fetchone()

    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    if session.get('user_id') == 'root_admin':
        profile_name = root_admin_username
    elif admin_checker and admin_checker[0] == session.get('user_id'):
        profile_name = admin_checker[1]
    else:
        profile_name = user_checker[1]

    search_query = request.args.get('q', '').strip()
    medicine_rows = get_medicine_balance_rows(search_query=search_query, positive_only=True)

    customers = [
        {'name': row[0], 'phone': row[1]}
        for row in db.execute(
            '''
            SELECT name, phone
            FROM patients
            ORDER BY id DESC
            LIMIT 8
            '''
        ).fetchall()
    ]

    cart_items = []
    for row in medicine_rows:
        price = float(row['latest_price'] or 0)
        cart_items.append({
            'product': row['medicine_name'],
            'batch': row['batch_no'],
            'unit': row['unit_type'].title(),
            'available': row['balance'],
            'qty': 0,
            'price': price,
            'discount': 0.00,
            'total': 0.00,
        })

    subtotal = sum(item['qty'] * item['price'] for item in cart_items)
    total_discount = sum(item['discount'] for item in cart_items)
    taxable_amount = max(subtotal - total_discount, 0)
    vat_tax = 0.0
    grand_total = taxable_amount + vat_tax
    paid_amount = grand_total
    due_change = paid_amount - grand_total
    today = datetime.now().strftime('%Y-%m-%d')
    invoice_count = db.execute(
        "SELECT COUNT(*) FROM medicine_sales WHERE date(sale_date) = ?",
        (today,)
    ).fetchone()[0]

    return render_template(
        "medicine_sales.html",
        profile_name=profile_name,
        customers=customers,
        cart_items=cart_items,
        search_query=search_query,
        subtotal=subtotal,
        total_discount=total_discount,
        vat_tax=vat_tax,
        grand_total=grand_total,
        paid_amount=paid_amount,
        due_change=due_change,
        invoice_no=f"MS-{datetime.now().strftime('%y%m%d')}-{invoice_count + 1:03d}",
        today=today,
        admin=isadmin(),
    )


@app.route('/medicine_sales/save', methods=['POST'])
def save_medicine_sale():
    """Persist a medicine sale, sale items, and matching stock-out entries."""
    if not (isadmin() or isuser()):
        return jsonify({'success': False, 'error': 'Please login to save a sale.'}), 401

    payload = request.get_json(silent=True) or {}
    items = payload.get('items') or []
    if not items:
        return jsonify({'success': False, 'error': 'Please add at least one item with quantity before saving.'}), 400

    cleaned_items = []
    for item in items:
        try:
            medicine_name = str(item.get('product', '')).strip()
            batch_no = str(item.get('batch', '')).strip() or 'General'
            unit_type = str(item.get('unit', 'strip')).strip().lower()
            quantity = int(item.get('quantity', 0))
            unit_price = float(item.get('price', 0))
            line_discount = max(float(item.get('discount', 0)), 0)
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'One or more sale items are invalid.'}), 400

        if not medicine_name or quantity <= 0 or unit_price < 0:
            continue
        if unit_type not in ('strip', 'box'):
            unit_type = 'strip'

        available_row = db.execute(
            '''
            SELECT COALESCE(SUM(CASE WHEN transaction_type = 'in' THEN quantity ELSE -quantity END), 0)
            FROM medicine_transactions
            WHERE medicine_name = ? AND COALESCE(NULLIF(batch_no, ''), 'General') = ? AND unit_type = ?
            ''',
            (medicine_name, batch_no, unit_type)
        ).fetchone()
        available_quantity = int(available_row[0] or 0)
        if quantity > available_quantity:
            return jsonify({
                'success': False,
                'error': f'Only {available_quantity} {unit_type}(s) available for {medicine_name} batch {batch_no}.'
            }), 400

        line_total = max((quantity * unit_price) - line_discount, 0)
        cleaned_items.append({
            'medicine_name': medicine_name,
            'batch_no': batch_no,
            'unit_type': unit_type,
            'quantity': quantity,
            'unit_price': unit_price,
            'discount': line_discount,
            'line_total': line_total,
        })

    if not cleaned_items:
        return jsonify({'success': False, 'error': 'Please set quantity above 0 before saving.'}), 400

    subtotal = sum(item['quantity'] * item['unit_price'] for item in cleaned_items)
    line_subtotal = sum(item['line_total'] for item in cleaned_items)
    line_discounts = sum(item['discount'] for item in cleaned_items)
    discount_type = payload.get('discountType') if payload.get('discountType') in ('flat', 'percent') else 'flat'
    try:
        discount_value = max(float(payload.get('discountValue') or 0), 0)
        tax_value = max(float(payload.get('taxValue') or 0), 0)
        delivery_cost = max(float(payload.get('deliveryCost') or 0), 0)
        received_amount = max(float(payload.get('receivedAmount') or 0), 0)
    except (TypeError, ValueError):
        return jsonify({'success': False, 'error': 'Payment summary contains invalid values.'}), 400

    order_discount = line_subtotal * (discount_value / 100) if discount_type == 'percent' else discount_value
    discount_amount = min(order_discount + line_discounts, subtotal)
    taxable_amount = max(line_subtotal - order_discount, 0)
    tax_type = payload.get('taxType') if payload.get('taxType') in ('none', 'flat', 'percent') else 'none'
    tax_amount = taxable_amount * (tax_value / 100) if tax_type == 'percent' else (tax_value if tax_type == 'flat' else 0)
    grand_total = taxable_amount + tax_amount + delivery_cost
    due_amount = max(grand_total - received_amount, 0)
    change_amount = max(received_amount - grand_total, 0)
    payment_type = str(payload.get('paymentType') or 'Cash').strip() or 'Cash'
    customer_name = str(payload.get('customerName') or 'Walk-in Customer').strip() or 'Walk-in Customer'
    customer_phone = str(payload.get('customerPhone') or '').strip()
    sale_date = datetime.now().strftime('%Y-%m-%d')
    created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    invoice_count = db.execute(
        "SELECT COUNT(*) FROM medicine_sales WHERE date(sale_date) = ?",
        (sale_date,)
    ).fetchone()[0]
    invoice_no = f"MS-{datetime.now().strftime('%y%m%d')}-{invoice_count + 1:03d}"

    try:
        cursor = db.execute(
            '''
            INSERT INTO medicine_sales (
                invoice_no, customer_name, customer_phone, subtotal, discount_type,
                discount_value, discount_amount, tax_type, tax_value, tax_amount,
                delivery_cost, grand_total, received_amount, due_amount, change_amount,
                payment_type, sale_date, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                invoice_no, customer_name, customer_phone, subtotal, discount_type,
                discount_value, discount_amount, tax_type, tax_value, tax_amount,
                delivery_cost, grand_total, received_amount, due_amount, change_amount,
                payment_type, sale_date, str(session.get('user_id')), created_at
            )
        )
        sale_id = cursor.lastrowid

        for item in cleaned_items:
            db.execute(
                '''
                INSERT INTO medicine_sale_items (
                    sale_id, medicine_name, batch_no, unit_type, quantity,
                    unit_price, discount, line_total
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    sale_id, item['medicine_name'], item['batch_no'], item['unit_type'],
                    item['quantity'], item['unit_price'], item['discount'], item['line_total']
                )
            )
            db.execute(
                '''
                INSERT INTO medicine_transactions (
                    medicine_name, batch_no, unit_type, transaction_type, quantity, price,
                    transaction_date, note, created_by, created_at
                ) VALUES (?, ?, ?, 'out', ?, ?, ?, ?, ?, ?)
                ''',
                (
                    item['medicine_name'], item['batch_no'], item['unit_type'],
                    item['quantity'], item['unit_price'], sale_date,
                    f'Sold on invoice {invoice_no}', str(session.get('user_id')), created_at
                )
            )

        db.commit()
    except sqlite3.Error:
        db.rollback()
        return jsonify({'success': False, 'error': 'Could not save this sale. Please try again.'}), 500

    return jsonify({
        'success': True,
        'sale': {
            'id': sale_id,
            'invoice_no': invoice_no,
            'customer_name': customer_name,
            'customer_phone': customer_phone,
            'subtotal': subtotal,
            'discount_amount': discount_amount,
            'tax_amount': tax_amount,
            'delivery_cost': delivery_cost,
            'grand_total': grand_total,
            'received_amount': received_amount,
            'due_amount': due_amount,
            'change_amount': change_amount,
            'payment_type': payment_type,
            'sale_date': sale_date,
            'created_at': created_at,
            'print_url': url_for('medicine_sales_print', sale_id=sale_id),
            'items': cleaned_items,
        }
    })


@app.route('/medicine-sales-print/<int:sale_id>')
def medicine_sales_print(sale_id):
    """Printable medicine sales invoice."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    sale_row = db.execute(
        '''
        SELECT id, invoice_no, customer_name, customer_phone, subtotal, discount_type,
               discount_value, discount_amount, tax_type, tax_value, tax_amount,
               delivery_cost, grand_total, received_amount, due_amount, change_amount,
               payment_type, sale_date, created_by, created_at
        FROM medicine_sales
        WHERE id = ?
        ''',
        (sale_id,)
    ).fetchone()

    if not sale_row:
        return redirect(url_for('medicine_sales_list', message='Medicine sale invoice not found.'))

    item_rows = db.execute(
        '''
        SELECT medicine_name, batch_no, unit_type, quantity, unit_price, discount, line_total
        FROM medicine_sale_items
        WHERE sale_id = ?
        ORDER BY id ASC
        ''',
        (sale_id,)
    ).fetchall()

    created_by_id = sale_row[18]
    if created_by_id == 'root_admin':
        prepared_by = root_admin_username
    else:
        prepared_user = db.execute('SELECT username FROM admins WHERE id = ?', (created_by_id,)).fetchone()
        if not prepared_user:
            prepared_user = db.execute('SELECT username FROM users WHERE id = ?', (created_by_id,)).fetchone()
        prepared_by = prepared_user[0] if prepared_user and prepared_user[0] else 'Unknown user'

    sale = {
        'id': sale_row[0],
        'invoice_no': sale_row[1],
        'customer_name': sale_row[2],
        'customer_phone': sale_row[3],
        'subtotal': sale_row[4],
        'discount_type': sale_row[5],
        'discount_value': sale_row[6],
        'discount_amount': sale_row[7],
        'tax_type': sale_row[8],
        'tax_value': sale_row[9],
        'tax_amount': sale_row[10],
        'delivery_cost': sale_row[11],
        'grand_total': sale_row[12],
        'received_amount': sale_row[13],
        'due_amount': sale_row[14],
        'change_amount': sale_row[15],
        'payment_type': sale_row[16],
        'sale_date': sale_row[17],
        'sale_date_display': format_invoice_datetime(sale_row[17]),
        'created_by': created_by_id,
        'created_at': sale_row[19],
        'created_at_display': format_invoice_datetime(sale_row[19]),
        'barcode': sale_row[1],
    }
    items = [
        {
            'medicine_name': item[0],
            'batch_no': item[1],
            'unit_type': item[2],
            'quantity': item[3],
            'unit_price': item[4],
            'discount': item[5],
            'line_total': item[6],
        }
        for item in item_rows
    ]
    printed_by = get_current_actor()[2]
    return_url = url_for('medicine_sales_list', date=sale['sale_date'])

    return render_template(
        'medicine_sales_print.html',
        sale=sale,
        items=items,
        amount_in_words=amount_to_words(sale['grand_total']),
        prepared_by=prepared_by,
        printed_by=printed_by,
        return_url=return_url
    )


@app.route('/medicine_sales_list')
def medicine_sales_list():
    """Date-wise medicine sales list."""
    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (session.get('user_id'),)).fetchone()
    user_checker = db.execute('SELECT * FROM users WHERE id = ?', (session.get('user_id'),)).fetchone()

    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    if session.get('user_id') == 'root_admin':
        profile_name = root_admin_username
    elif admin_checker and admin_checker[0] == session.get('user_id'):
        profile_name = admin_checker[1]
    else:
        profile_name = user_checker[1]

    selected_date = request.args.get('date', '').strip() or datetime.now().strftime('%Y-%m-%d')
    sales_rows = db.execute(
        '''
        SELECT id, invoice_no, customer_name, customer_phone, subtotal, discount_amount,
               tax_amount, delivery_cost, grand_total, received_amount, due_amount,
               change_amount, payment_type, sale_date, created_at
        FROM medicine_sales
        WHERE date(sale_date) = ?
        ORDER BY created_at DESC, id DESC
        ''',
        (selected_date,)
    ).fetchall()

    sales = []
    for row in sales_rows:
        item_rows = db.execute(
            '''
            SELECT medicine_name, batch_no, unit_type, quantity, unit_price, discount, line_total
            FROM medicine_sale_items
            WHERE sale_id = ?
            ORDER BY id ASC
            ''',
            (row[0],)
        ).fetchall()
        sales.append({
            'id': row[0],
            'invoice_no': row[1],
            'customer_name': row[2],
            'customer_phone': row[3],
            'subtotal': row[4],
            'discount_amount': row[5],
            'tax_amount': row[6],
            'delivery_cost': row[7],
            'grand_total': row[8],
            'received_amount': row[9],
            'due_amount': row[10],
            'change_amount': row[11],
            'payment_type': row[12],
            'sale_date': row[13],
            'created_at': row[14],
            'items': [
                {
                    'medicine_name': item[0],
                    'batch_no': item[1],
                    'unit_type': item[2],
                    'quantity': item[3],
                    'unit_price': item[4],
                    'discount': item[5],
                    'line_total': item[6],
                }
                for item in item_rows
            ],
        })

    return render_template(
        "medicine_sales_list.html",
        profile_name=profile_name,
        selected_date=selected_date,
        sales=sales,
        total_sales=sum(sale['grand_total'] for sale in sales),
        total_due=sum(sale['due_amount'] for sale in sales),
        admin=isadmin(),
    )


@app.route('/medicine_monthly_report')
def medicine_monthly_report():
    """Admin-only monthly medicine sales report."""
    if not isadmin():
        return redirect(url_for('login'))

    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (session.get('user_id'),)).fetchone()
    profile_name = root_admin_username if session.get('user_id') == 'root_admin' else admin_checker[1]

    selected_month = request.args.get('month', '').strip() or datetime.now().strftime('%Y-%m')
    try:
        month_start = datetime.strptime(selected_month, '%Y-%m')
    except ValueError:
        month_start = datetime.now().replace(day=1)
        selected_month = month_start.strftime('%Y-%m')

    next_month = (month_start.replace(day=28) + timedelta(days=4)).replace(day=1)
    month_start_text = month_start.strftime('%Y-%m-%d')
    next_month_text = next_month.strftime('%Y-%m-%d')
    report_month_label = month_start.strftime('%B %Y')

    summary_row = db.execute(
        '''
        SELECT
            COUNT(*) AS invoice_count,
            COALESCE(SUM(subtotal), 0) AS gross_sales,
            COALESCE(SUM(discount_amount), 0) AS discount_amount,
            COALESCE(SUM(tax_amount), 0) AS tax_amount,
            COALESCE(SUM(delivery_cost), 0) AS delivery_cost,
            COALESCE(SUM(grand_total), 0) AS net_sales,
            COALESCE(SUM(received_amount), 0) AS received_amount,
            COALESCE(SUM(due_amount), 0) AS due_amount
        FROM medicine_sales
        WHERE date(sale_date) >= ? AND date(sale_date) < ?
        ''',
        (month_start_text, next_month_text)
    ).fetchone()

    item_summary_row = db.execute(
        '''
        SELECT
            COALESCE(SUM(msi.quantity), 0) AS total_units,
            COUNT(DISTINCT msi.medicine_name || '|' || msi.batch_no || '|' || msi.unit_type) AS product_count
        FROM medicine_sale_items msi
        JOIN medicine_sales ms ON ms.id = msi.sale_id
        WHERE date(ms.sale_date) >= ? AND date(ms.sale_date) < ?
        ''',
        (month_start_text, next_month_text)
    ).fetchone()

    product_rows_raw = db.execute(
        '''
        SELECT
            msi.medicine_name,
            msi.batch_no,
            msi.unit_type,
            COUNT(DISTINCT ms.id) AS invoice_count,
            SUM(msi.quantity) AS quantity,
            AVG(msi.unit_price) AS avg_price,
            SUM(msi.quantity * msi.unit_price) AS gross_amount,
            SUM(msi.discount) AS discount_amount,
            SUM(msi.line_total) AS net_amount
        FROM medicine_sale_items msi
        JOIN medicine_sales ms ON ms.id = msi.sale_id
        WHERE date(ms.sale_date) >= ? AND date(ms.sale_date) < ?
        GROUP BY msi.medicine_name, msi.batch_no, msi.unit_type
        ORDER BY net_amount DESC, quantity DESC, msi.medicine_name ASC
        ''',
        (month_start_text, next_month_text)
    ).fetchall()

    daily_rows_raw = db.execute(
        '''
        SELECT
            date(sale_date) AS sale_day,
            COUNT(*) AS invoice_count,
            COALESCE(SUM(grand_total), 0) AS net_sales,
            COALESCE(SUM(received_amount), 0) AS received_amount,
            COALESCE(SUM(due_amount), 0) AS due_amount
        FROM medicine_sales
        WHERE date(sale_date) >= ? AND date(sale_date) < ?
        GROUP BY date(sale_date)
        ORDER BY sale_day ASC
        ''',
        (month_start_text, next_month_text)
    ).fetchall()

    report_summary = {
        'invoice_count': int(summary_row[0] or 0),
        'gross_sales': float(summary_row[1] or 0),
        'discount_amount': float(summary_row[2] or 0),
        'tax_amount': float(summary_row[3] or 0),
        'delivery_cost': float(summary_row[4] or 0),
        'net_sales': float(summary_row[5] or 0),
        'received_amount': float(summary_row[6] or 0),
        'due_amount': float(summary_row[7] or 0),
        'total_units': int(item_summary_row[0] or 0),
        'product_count': int(item_summary_row[1] or 0),
    }

    product_rows = [
        {
            'medicine_name': row[0],
            'batch_no': row[1],
            'unit_type': row[2],
            'invoice_count': int(row[3] or 0),
            'quantity': int(row[4] or 0),
            'avg_price': float(row[5] or 0),
            'gross_amount': float(row[6] or 0),
            'discount_amount': float(row[7] or 0),
            'net_amount': float(row[8] or 0),
        }
        for row in product_rows_raw
    ]

    daily_rows = [
        {
            'sale_day': row[0],
            'invoice_count': int(row[1] or 0),
            'net_sales': float(row[2] or 0),
            'received_amount': float(row[3] or 0),
            'due_amount': float(row[4] or 0),
        }
        for row in daily_rows_raw
    ]

    return render_template(
        "medicine_monthly_report.html",
        profile_name=profile_name,
        selected_month=selected_month,
        report_month_label=report_month_label,
        generated_at=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        report_summary=report_summary,
        product_rows=product_rows,
        daily_rows=daily_rows,
        admin=True,
    )


@app.route('/medicine_sales/delete/<int:sale_id>', methods=['POST'])
def delete_medicine_sale(sale_id):
    """Allow admins to delete a medicine sale and its matching stock-out records."""
    if not isadmin():
        return redirect(url_for('medicine_sales_list'))

    selected_date = request.form.get('selected_date', '').strip()
    sale_row = db.execute(
        'SELECT invoice_no, sale_date FROM medicine_sales WHERE id = ?',
        (sale_id,)
    ).fetchone()
    if not sale_row:
        return redirect(url_for('medicine_sales_list', date=selected_date or datetime.now().strftime('%Y-%m-%d')))

    invoice_no = sale_row[0]
    sale_date = selected_date or sale_row[1] or datetime.now().strftime('%Y-%m-%d')

    try:
        db.execute(
            "DELETE FROM medicine_transactions WHERE transaction_type = 'out' AND note = ?",
            (f'Sold on invoice {invoice_no}',)
        )
        db.execute('DELETE FROM medicine_sale_items WHERE sale_id = ?', (sale_id,))
        db.execute('DELETE FROM medicine_sales WHERE id = ?', (sale_id,))
        db.commit()
    except sqlite3.Error:
        db.rollback()

    return redirect(url_for('medicine_sales_list', date=sale_date))


@app.route('/medicine_stock_dashboard/edit/<int:transaction_id>', methods=['POST'])
def edit_medicine_transaction(transaction_id):
    """Allow admins to update medicine quantity and price for an existing stock entry."""
    if not isadmin():
        return redirect(url_for('medicine_stock_dashboard'))

    quantity = request.form.get('quantity', '').strip()
    price = request.form.get('price', '').strip()

    try:
        quantity_value = int(quantity)
        price_value = float(price)
        if quantity_value <= 0 or price_value <= 0:
            raise ValueError

        db.execute(
            '''
            UPDATE medicine_transactions
            SET quantity = ?, price = ?
            WHERE id = ?
            ''',
            (quantity_value, price_value, transaction_id)
        )
        db.commit()
    except (ValueError, TypeError):
        pass

    return redirect(url_for('medicine_stock_dashboard'))


@app.route('/medicine_stock_dashboard/delete/<int:transaction_id>', methods=['POST'])
def delete_medicine_transaction(transaction_id):
    """Allow admins to delete one stock movement."""
    if not isadmin():
        return redirect(url_for('medicine_sales'))

    db.execute('DELETE FROM medicine_transactions WHERE id = ?', (transaction_id,))
    db.commit()
    return redirect(url_for('medicine_stock_dashboard'))


@app.route('/medicine_stock_dashboard/delete_medicine', methods=['POST'])
def delete_medicine_balance():
    """Allow admins to delete all stock movements for a medicine batch and unit."""
    if not isadmin():
        return redirect(url_for('medicine_sales'))

    medicine_name = request.form.get('medicine_name', '').strip()
    batch_no = request.form.get('batch_no', '').strip() or 'General'
    unit_type = request.form.get('unit_type', '').strip().lower()
    if medicine_name and unit_type in ('strip', 'box'):
        db.execute(
            '''
            DELETE FROM medicine_transactions
            WHERE medicine_name = ?
              AND COALESCE(NULLIF(batch_no, ''), 'General') = ?
              AND unit_type = ?
            ''',
            (medicine_name, batch_no, unit_type)
        )
        db.commit()

    return redirect(url_for('medicine_stock_dashboard'))

@app.route('/patient')
def patient():
    return redirect(url_for('patients_registration'))

@app.route('/add_patient', methods=['POST'])
def add_patient():
    """Page/API to add new patient information - accessible to any logged-in account."""
    if isadmin() or isuser():
        redirect_endpoint = request.args.get('next')
        if redirect_endpoint != 'patients_registration':
            redirect_endpoint = 'patients_registration'

        def patient_redirect(**kwargs):
            return redirect(url_for(redirect_endpoint, **kwargs))

        if request.method == 'POST':
            name = request.form.get('name')
            age = request.form.get('age')
            age_unit = (request.form.get('age_unit') or 'Y').upper()
            gender = request.form.get('gender')
            phone = request.form.get('phone')
            email = request.form.get('email')
            dob = request.form.get('dob') or ''
            blood_group = request.form.get('blood_group')
            address = request.form.get('address')
            emergency_contact_name = request.form.get('emergency_contact_name') or ''
            emergency_contact_phone = request.form.get('emergency_contact_phone') or ''
            medical_history = request.form.get('medical_history')
            serial_no = request.form.get('serial_no', '').strip()
            patient_status = request.form.get('patient_status')
            doctor_name = request.form.get('doctor_name')
            doctor_designation = request.form.get('doctor_designation')
            referer_name = request.form.get('referer_name')
            doctor_fee = request.form.get('doctor_fee')
            save_action = request.form.get('save_action')
            is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

            if not name or not age or not gender or not phone or not blood_group or not address or not patient_status or not doctor_name or not doctor_fee:
                if is_ajax:
                    return {"success": False, "error": "Please fill in all required fields."}, 400
                return patient_redirect(error="Please fill in all required fields.")
            if not age.isdigit() or int(age) < 0:
                if is_ajax:
                    return {"success": False, "error": "Please enter a valid age."}, 400
                return patient_redirect(error="Please enter a valid age.")
            if age_unit not in ('Y', 'M', 'D'):
                age_unit = 'Y'
            if not phone.isdigit() or len(phone) < 7:
                if is_ajax:
                    return {"success": False, "error": "Please enter a valid phone number."}, 400
                return patient_redirect(error="Please enter a valid phone number.")
            try:
                doctor_fee_value = float(doctor_fee)
            except (TypeError, ValueError):
                if is_ajax:
                    return {"success": False, "error": "Please enter a valid doctor fee."}, 400
                return patient_redirect(error="Please enter a valid doctor fee.")

            daily_ticket_no = db.execute('''
                SELECT COALESCE(MAX(daily_patient_id), 0) + 1
                FROM patients
                WHERE date(created_at) = date('now', '+6 hours')
            ''').fetchone()[0]

            cursor = db.execute('''INSERT INTO patients (
                                      daily_patient_id, serial_no, name, age, age_unit, gender, phone, email,
                                      dob, blood_group, address, emergency_contact_name, emergency_contact_phone,
                                      medical_history, patient_status, doctor_name, doctor_designation,
                                      referer_name, doctor_fee, created_at
                                  ) 
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+6 hours'))''',
                                (
                                    daily_ticket_no, serial_no, name, age, age_unit, gender, phone, email,
                                    dob, blood_group, address, emergency_contact_name, emergency_contact_phone,
                                    medical_history, patient_status, doctor_name, doctor_designation,
                                    referer_name, doctor_fee_value
                                ))
            db.commit()
            patient_id = cursor.lastrowid
            add_system_log(f"Patient created: {name} ({phone}), ticket no {daily_ticket_no}", patient_id)

            if is_ajax:
                return {"success": True, "patient_id": patient_id, "ticket_no": daily_ticket_no, "print_url": url_for('ticket_print', patient_id=patient_id)}, 200

            if save_action == 'save_print':
                return redirect(url_for('ticket_print', patient_id=patient_id))

            return patient_redirect(success="Patient added successfully.")
        return patient_redirect()
    else:
        return redirect(url_for('login'))

@app.route('/delete_patient/<int:patient_id>')
def delete_patient(patient_id):
    """Delete a patient - only admin can delete."""
    if not isadmin():
        return redirect(url_for('dashboard'))

    patient = db.execute('SELECT id, name, phone FROM patients WHERE id = ?', (patient_id,)).fetchone()
    if not patient:
        return redirect(url_for('patients_registration', message="Patient not found."))

    try:
        db.execute('DELETE FROM patients WHERE id = ?', (patient_id,))
        db.commit()
        add_system_log(f"Patient deleted: {patient[1]} ({patient[2]})", patient_id)
        return redirect(url_for('patients_registration', message="Patient deleted successfully."))
    except sqlite3.IntegrityError:
        return redirect(url_for('patients_registration', message="Cannot delete patient because they have associated records."))

@app.route('/admissions', methods=['GET', 'POST'])
def admissions():
    """Admit patients and display admission records."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    if request.method == 'POST':
        patient_id = request.form.get('patient_id')
        doctor_id = request.form.get('doctor_id') or None
        admission_date = request.form.get('admission_date')
        ward = request.form.get('ward')
        room_number = request.form.get('room_number')
        bed_number = request.form.get('bed_number')
        reason = request.form.get('reason')
        notes = request.form.get('notes')

        if not patient_id or not patient_id.isdigit():
            return redirect(url_for('admissions', message="Please select a valid patient."))

        patient = db.execute('SELECT id FROM patients WHERE id = ?', (patient_id,)).fetchone()
        if not patient:
            return redirect(url_for('admissions', message="Patient not found."))

        if not admission_date or not ward or not bed_number or not reason:
            return redirect(url_for('admissions', message="Please fill in all required admission fields."))

        if doctor_id and not doctor_id.isdigit():
            doctor_id = None

        if doctor_id:
            doctor = db.execute('SELECT id FROM doctors WHERE id = ?', (doctor_id,)).fetchone()
            if not doctor:
                doctor_id = None

        db.execute('''
            INSERT INTO admissions (
                patient_id, doctor_id, admission_date, ward, room_number,
                bed_number, reason, notes, status, created_by, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Admitted', ?, datetime('now', '+6 hours'))
        ''', (
            patient_id, doctor_id, admission_date, ward, room_number,
            bed_number, reason, notes, session.get('user_id')
        ))
        db.commit()
        add_log(patient_id, "Patient admitted")
        return redirect(url_for('admissions', success="Patient admitted successfully."))

    selected_date = request.args.get('date', '').strip() or datetime.now().strftime('%Y-%m-%d')
    patient_list = db.execute('''
        SELECT id, name, age, age_unit, gender, phone, address
        FROM patients
        ORDER BY id DESC
    ''').fetchall()
    doctor_list = db.execute('''
        SELECT id, name, specialization
        FROM doctors
        ORDER BY name ASC
    ''').fetchall()
    admission_list = db.execute('''
        SELECT
            a.id,
            p.id,
            p.name,
            p.phone,
            p.age,
            p.age_unit,
            p.gender,
            a.admission_date,
            a.ward,
            a.room_number,
            a.bed_number,
            COALESCE(d.name, 'Not assigned'),
            a.reason,
            a.status,
            a.created_at
        FROM admissions a
        JOIN patients p ON a.patient_id = p.id
        LEFT JOIN doctors d ON a.doctor_id = d.id
        WHERE date(a.created_at) = ?
        ORDER BY a.id DESC
    ''', (selected_date,)).fetchall()

    return render_template(
        "admission.html",
        patients=patient_list,
        doctors=doctor_list,
        admissions=admission_list,
        admin=isadmin(),
        selected_date=selected_date,
        message=request.args.get('message'),
        success=request.args.get('success')
    )

@app.route('/discharge_admission/<int:admission_id>')
def discharge_admission(admission_id):
    """Mark an active admission as discharged."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    admission = db.execute(
        "SELECT patient_id, status FROM admissions WHERE id = ?",
        (admission_id,)
    ).fetchone()
    if not admission:
        return redirect(url_for('admissions', message="Admission record not found."))

    if admission[1] == 'Discharged':
        return redirect(url_for('admissions', message="Patient is already discharged."))

    db.execute('''
        UPDATE admissions
        SET status = 'Discharged', discharged_at = datetime('now', '+6 hours')
        WHERE id = ?
    ''', (admission_id,))
    db.commit()
    add_log(admission[0], "Patient discharged")
    return redirect(url_for('admissions', success="Admission marked as discharged."))

@app.route('/registered_users', methods=['GET', 'POST'])
def registered_users():
    """Page to display registered users - only accessible to admin."""
    if isadmin():
        user_list = db.execute('SELECT * FROM users').fetchall()
        admin_list = db.execute('SELECT * FROM admins').fetchall()
        user_permissions = {
            user[0]: set(get_user_page_keys(user[0]))
            for user in user_list
        }
        return render_template(
            "registered_users.html",
            users=user_list,
            admins=admin_list,
            page_options=PAGE_OPTIONS,
            user_permissions=user_permissions,
            success=request.args.get('success'),
            delete_message=request.args.get('delete_message')
        )
    else:
        return redirect(url_for('login'))
    

@app.route('/update_user_permissions', methods=['POST'])
def update_user_permissions():
    """Allow admins to edit which pages a regular user can open."""
    if not isadmin():
        return redirect(url_for('login'))

    user_id = request.form.get('user_id')
    if not user_id or not user_id.isdigit():
        return redirect(url_for('registered_users', delete_message="Invalid employee selected."))

    user_row = db.execute('SELECT username FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user_row:
        return redirect(url_for('registered_users', delete_message="Employee not found."))

    page_keys = request.form.getlist('page_permissions')
    if not page_keys:
        return redirect(url_for('registered_users', delete_message="Please choose at least one page for this employee."))

    set_user_page_permissions(user_id, page_keys)
    db.commit()
    add_system_log(f"Employee permissions updated: {user_row[0]}")
    return redirect(url_for('registered_users', success="Employee permissions updated successfully."))


@app.route('/delete', methods=['POST'])
def delete_user():
    if not isadmin():
        return redirect(url_for('login'))

    if request.method == 'POST':
        actor = get_current_actor()
        if request.form.get('delete_user'):
            user_id = request.form.get('delete_user')
            user_row = db.execute('SELECT username, email FROM users WHERE id = ?', (user_id,)).fetchone()
            db.execute('DELETE FROM user_permissions WHERE user_id = ?', (user_id,))
            db.execute('DELETE FROM users WHERE id = ?', (user_id,))
            db.commit()
            if user_row:
                add_system_log(f"Employee account deleted: {user_row[0]} ({user_row[1] or 'no email'})", actor=actor)
            return redirect(url_for('registered_users', delete_message="Employee deleted successfully."))
        
        elif request.form.get('delete_admin'):
                admin_id = request.form.get('delete_admin')
                admin_row = db.execute('SELECT username, email FROM admins WHERE id = ?', (admin_id,)).fetchone()
                db.execute('DELETE FROM admins WHERE id = ?', (admin_id,))
                db.commit()
                if admin_row:
                    add_system_log(f"Admin account deleted: {admin_row[0]} ({admin_row[1] or 'no email'})", actor=actor)
                return redirect(url_for('registered_users', delete_message="Admin deleted successfully."))
    else:
        return redirect(url_for('login'))

@app.route('/doctors', methods=['GET', 'POST'])
def doctors():
    if not isuser() and not isadmin():
        return redirect(url_for('login'))
    """Page to display doctor information."""
    admin_varifier = isadmin()
    doctor_list = db.execute('''
        SELECT id, name, phone, email, specialization, designation,
               department, license_number, availability, experience, room_number
        FROM doctors
        ORDER BY id ASC
    ''').fetchall()
    message = request.args.get('message') or request.args.get('success')
    return render_template("doctors.html", doctors=doctor_list, admin=admin_varifier, message=message)

@app.route('/duty-management', methods=['GET', 'POST'])
def duty_management():
    """Track doctor rounds and nurse duty completion."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    selected_date = request.args.get('date', '').strip() or datetime.now().strftime('%Y-%m-%d')

    if request.method == 'POST':
        staff_role = request.form.get('staff_role', '').strip().lower()
        doctor_id = request.form.get('doctor_id', '').strip()
        staff_name = request.form.get('staff_name', '').strip()
        duty_date = request.form.get('duty_date', '').strip() or datetime.now().strftime('%Y-%m-%d')
        shift = request.form.get('shift', '').strip()
        ward = request.form.get('ward', '').strip()
        round_completed = 1 if request.form.get('round_completed') == 'on' else 0
        notes = request.form.get('notes', '').strip()

        if staff_role not in ('doctor', 'nurse'):
            return redirect(url_for('duty_management', date=duty_date, message="Please choose Doctor or Nurse."))
        if not shift or not ward:
            return redirect(url_for('duty_management', date=duty_date, message="Please choose shift and ward/unit."))

        doctor_id_value = None
        if staff_role == 'doctor':
            if not doctor_id or not doctor_id.isdigit():
                return redirect(url_for('duty_management', date=duty_date, message="Please select a doctor."))
            doctor_row = db.execute('SELECT id, name FROM doctors WHERE id = ?', (doctor_id,)).fetchone()
            if not doctor_row:
                return redirect(url_for('duty_management', date=duty_date, message="Doctor not found."))
            doctor_id_value = doctor_row[0]
            staff_name = doctor_row[1]
        elif not staff_name:
            return redirect(url_for('duty_management', date=duty_date, message="Please write the nurse name."))

        db.execute(
            '''
            INSERT INTO duty_records (
                staff_role, doctor_id, staff_name, duty_date, shift, ward,
                round_completed, notes, created_by, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+6 hours'))
            ''',
            (
                staff_role, doctor_id_value, staff_name, duty_date, shift, ward,
                round_completed, notes, str(session.get('user_id'))
            )
        )
        db.commit()
        add_system_log(f"{staff_role.title()} duty record saved: {staff_name}")
        return redirect(url_for('duty_management', date=duty_date, success="Duty record saved successfully."))

    doctor_list = db.execute('''
        SELECT id, name, COALESCE(designation, ''), department
        FROM doctors
        ORDER BY name ASC
    ''').fetchall()
    duty_rows = db.execute(
        '''
        SELECT id, staff_role, staff_name, duty_date, shift, ward, round_completed, notes, created_by, created_at
        FROM duty_records
        WHERE date(duty_date) = ?
        ORDER BY created_at DESC, id DESC
        ''',
        (selected_date,)
    ).fetchall()

    duty_records = [
        {
            'id': row[0],
            'staff_role': row[1],
            'staff_name': row[2],
            'duty_date': row[3],
            'shift': row[4],
            'ward': row[5],
            'round_completed': bool(row[6]),
            'notes': row[7] or '',
            'created_by': row[8],
            'created_at': row[9],
        }
        for row in duty_rows
    ]
    total_records = len(duty_records)
    completed_records = sum(1 for row in duty_records if row['round_completed'])
    doctor_completed = sum(1 for row in duty_records if row['staff_role'] == 'doctor' and row['round_completed'])
    nurse_completed = sum(1 for row in duty_records if row['staff_role'] == 'nurse' and row['round_completed'])

    return render_template(
        'duty_management.html',
        doctors=doctor_list,
        duty_records=duty_records,
        selected_date=selected_date,
        total_records=total_records,
        completed_records=completed_records,
        pending_records=total_records - completed_records,
        doctor_completed=doctor_completed,
        nurse_completed=nurse_completed,
        admin=isadmin(),
        message=request.args.get('message'),
        success=request.args.get('success')
    )

@app.route('/patients-registration')
def patients_registration():
    """Patient registration page from the dashboard sidebar."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    list_view = request.args.get('view', '').strip().lower()
    show_all_patients = list_view == 'all'
    selected_date = request.args.get('date', '').strip() or datetime.now().strftime('%Y-%m-%d')
    patient_query = '''
        SELECT
            id,
            daily_patient_id,
            name,
            age,
            COALESCE(NULLIF(age_unit, ''), 'Y') AS age_unit,
            gender,
            phone,
            address
        FROM patients
    '''
    if show_all_patients:
        patient_query += ' ORDER BY datetime(created_at) DESC, id DESC'
        patient_list = db.execute(patient_query).fetchall()
    else:
        patient_query += '''
            WHERE date(created_at) = ?
            ORDER BY COALESCE(daily_patient_id, id) ASC, id ASC
        '''
        patient_list = db.execute(patient_query, (selected_date,)).fetchall()
    next_daily_ticket_no = db.execute('''
        SELECT COALESCE(MAX(daily_patient_id), 0) + 1
        FROM patients
        WHERE date(created_at) = date('now', '+6 hours')
    ''').fetchone()[0]
    doctor_options = db.execute('''
        SELECT id, name, COALESCE(designation, '') AS designation
        FROM doctors
        ORDER BY name ASC
    ''').fetchall()
    return render_template(
        'patients_registration.html',
        patients=patient_list,
        admin=isadmin(),
        show_all_patients=show_all_patients,
        selected_date=selected_date,
        next_daily_ticket_no=next_daily_ticket_no,
        doctor_options=doctor_options
    )

@app.route('/ticket-print/<int:patient_id>')
def ticket_print(patient_id):
    """Printable doctor ticket invoice for a registered patient."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    ticket = db.execute('''
        SELECT
            id,
            daily_patient_id,
            serial_no,
            name,
            age,
            COALESCE(NULLIF(age_unit, ''), 'Y') AS age_unit,
            gender,
            phone,
            blood_group,
            address,
            emergency_contact_phone,
            patient_status,
            doctor_name,
            doctor_designation,
            referer_name,
            doctor_fee,
            created_at
        FROM patients
        WHERE id = ?
    ''', (patient_id,)).fetchone()

    if not ticket:
        return redirect(url_for('patients_registration', message="Patient ticket not found."))

    doctor_fee = ticket[15] or 0
    ticket_info = {
        'uhid': ticket[0],
        'ticket_no': ticket[1],
        'serial_no': ticket[2],
        'name': ticket[3],
        'age': ticket[4],
        'age_unit': ticket[5],
        'gender': ticket[6],
        'phone': ticket[7],
        'blood_group': ticket[8],
        'address': ticket[9],
        'emergency_contact_phone': ticket[10],
        'patient_status': ticket[11],
        'doctor_name': ticket[12],
        'doctor_designation': ticket[13],
        'referer_name': ticket[14],
        'doctor_fee': doctor_fee,
        'created_at': ticket[16],
        'bill_no': ticket[1] or ticket[0],
        'barcode': ticket[1] or ticket[0]
    }

    prepared_log = db.execute('''
        SELECT actor_name
        FROM logs
        WHERE patient_id = ?
          AND action LIKE 'Patient created:%'
        ORDER BY timestamp ASC, id ASC
        LIMIT 1
    ''', (patient_id,)).fetchone()
    prepared_by = prepared_log[0] if prepared_log and prepared_log[0] else 'Unknown user'
    printed_by = get_current_actor()[2]
    ticket_created_date = str(ticket[16]).split(' ')[0] if ticket[16] else None
    return_url = url_for('patients_registration', view='list', date=ticket_created_date) if ticket_created_date else url_for('patients_registration', view='list')

    return render_template(
        'ticket_print.html',
        ticket=ticket_info,
        amount_in_words=amount_to_words(doctor_fee),
        prepared_by=prepared_by,
        printed_by=printed_by,
        return_url=return_url
    )

@app.route('/tickets')
def tickets():
    return redirect(url_for('patients_registration'))

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
            designation = request.form.get('designation')
            department = request.form.get('department')
            license_number = request.form.get('license_number')
            availability = request.form.get('availability')
            experience = request.form.get('experience')
            room_number = request.form.get('room_number')

            if not name or not phone or not email or not specialization or not designation or not department or not license_number or not availability or not experience or not room_number:
                return render_template("add_doctor.html", error="Please fill in all required fields.")
            if not phone.isdigit() or len(phone) < 7:
                return render_template("add_doctor.html", error="Please enter a valid phone number.")
            if not experience.isdigit() or int(experience) < 0:
                return render_template("add_doctor.html", error="Please enter a valid number of years of experience.")
            
            db.execute('''INSERT INTO doctors (name, phone, email, specialization, designation, department, license_number, availability, experience, room_number) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (name, phone, email, specialization, designation, department, license_number, availability, experience, room_number))
            db.commit()
            return redirect(url_for('doctors', success="Doctor added successfully."))
        return render_template("add_doctor.html")
    else:
        return redirect(url_for('login'))

@app.route('/edit_doctor/<int:doctor_id>', methods=['GET', 'POST'])
def edit_doctor(doctor_id):
    """Edit doctor information - only accessible to admin."""
    if not isadmin():
        return redirect(url_for('doctors', message="Only admins can edit doctor information."))

    doctor = db.execute('''
        SELECT id, name, phone, email, specialization, designation,
               department, license_number, availability, experience, room_number
        FROM doctors
        WHERE id = ?
    ''', (doctor_id,)).fetchone()
    if not doctor:
        return redirect(url_for('doctors', message="Doctor not found."))

    if request.method == 'POST':
        name = request.form.get('name')
        phone = request.form.get('phone')
        email = request.form.get('email')
        specialization = request.form.get('specialization')
        designation = request.form.get('designation')
        department = request.form.get('department')
        license_number = request.form.get('license_number')
        availability = request.form.get('availability')
        experience = request.form.get('experience')
        room_number = request.form.get('room_number')

        if not name or not phone or not email or not specialization or not designation or not department or not license_number or not availability or not experience or not room_number:
            return render_template("add_doctor.html", error="Please fill in all required fields.", doctor=doctor, mode="edit")
        if not phone.isdigit() or len(phone) < 7:
            return render_template("add_doctor.html", error="Please enter a valid phone number.", doctor=doctor, mode="edit")
        if not experience.isdigit() or int(experience) < 0:
            return render_template("add_doctor.html", error="Please enter a valid number of years of experience.", doctor=doctor, mode="edit")

        db.execute('''
            UPDATE doctors
            SET name = ?, phone = ?, email = ?, specialization = ?, designation = ?,
                department = ?, license_number = ?, availability = ?, experience = ?, room_number = ?
            WHERE id = ?
        ''', (name, phone, email, specialization, designation, department, license_number, availability, experience, room_number, doctor_id))
        db.commit()
        return redirect(url_for('doctors', success="Doctor information updated successfully."))

    return render_template("add_doctor.html", doctor=doctor, mode="edit")
    
@app.route('/services')
def services():
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    service_list = db.execute('''
        SELECT id, name, type, price
        FROM services
        ORDER BY type, name
    ''').fetchall()

    is_admin = isadmin()
    message = request.args.get('message') or request.args.get('success')

    return render_template("services.html", services=service_list, admin=is_admin, message=message)
    
@app.route('/add_service', methods=['GET', 'POST'])
def add_service():
    # Only admin can access
    if not isadmin():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        service_type = request.form.get('type')  # 'doctor' or 'test'
        price = request.form.get('price')

        # Validation
        if not name or not service_type or not price:
            return render_template("add_new_service.html", error="All fields are required.")

        if service_type not in ['doctor', 'test']:
            return render_template("add_new_service.html", error="Invalid service type.")

        try:
            price = float(price)
            if price < 0:
                return render_template("add_new_service.html", error="Price must be positive.")
        except:
            return render_template("add_new_service.html", error="Invalid price format.")

        #  Insert into DB
        db.execute('''
            INSERT INTO services (name, type, price)
            VALUES (?, ?, ?)
        ''', (name, service_type, price))
        db.commit()

        return redirect(url_for('services', success="Service added successfully."))

    return render_template("add_new_service.html")

@app.route('/edit_service/<int:service_id>', methods=['GET', 'POST'])
def edit_service(service_id):
    # Only admin can edit services
    if not isadmin():
        return redirect(url_for('dashboard'))

    service = db.execute(
        'SELECT id, name, type, price FROM services WHERE id = ?',
        (service_id,)
    ).fetchone()

    if not service:
        return redirect(url_for('services', message="Service not found."))

    if request.method == 'POST':
        name = request.form.get('name')
        service_type = request.form.get('type')
        price = request.form.get('price')

        if not name or not service_type or not price:
            return render_template("edit_service.html", service=service, error="All fields are required.")

        if service_type not in ['doctor', 'test']:
            return render_template("edit_service.html", service=service, error="Invalid service type.")

        try:
            price = float(price)
            if price < 0:
                return render_template("edit_service.html", service=service, error="Price must be positive.")
        except ValueError:
            return render_template("edit_service.html", service=service, error="Invalid price format.")

        db.execute(
            'UPDATE services SET name = ?, type = ?, price = ? WHERE id = ?',
            (name, service_type, price, service_id)
        )
        db.commit()
        return redirect(url_for('services', message="Service updated successfully."))

    return render_template("edit_service.html", service=service)

@app.route('/delete_service/<int:service_id>')
def delete_service(service_id):
    # Only admin can delete services
    if not isadmin():
        return redirect(url_for('dashboard'))

    service = db.execute('SELECT id FROM services WHERE id = ?', (service_id,)).fetchone()
    if not service:
        return redirect(url_for('services', message="Service not found."))

    try:
        db.execute('DELETE FROM services WHERE id = ?', (service_id,))
        db.commit()
        return redirect(url_for('services', message="Service deleted successfully."))
    except sqlite3.IntegrityError:
        return redirect(url_for('services', message="Cannot delete service because it is in use."))

@app.route('/tests')
def tests():
    # Only logged-in users (admin or user)
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    test_list = db.execute('''
        SELECT id, name, price
        FROM services
        WHERE type = 'test'
        ORDER BY name ASC
    ''').fetchall()

    is_admin = isadmin()

    return render_template("tests.html", tests=test_list, admin=is_admin)

@app.route('/patient_service/<int:patient_id>', methods=['GET', 'POST'])
def patient_service(patient_id):
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    if request.method == 'POST':
        service_type = request.form.get('service_type')

        #  CREATE BILL FIRST
        bill_cursor = db.execute('''
            INSERT INTO bills (patient_id, created_by, total_amount, created_at)
            VALUES (?, ?, 0, datetime('now', '+6 hours'))
        ''', (patient_id, session.get('user_id')))
        bill_id = bill_cursor.lastrowid

        #  DOCTOR APPOINTMENT
        if service_type == 'doctor':
            doctor_id = request.form.get('doctor_id')
            service_id = request.form.get('service_id')  # doctor service

            # create appointment
            db.execute('''
                INSERT INTO appointments (patient_id, doctor_id, service_id, appointment_date, created_by)
                VALUES (?, ?, ?, datetime('now', '+6 hours'), ?)
            ''', (patient_id, doctor_id, service_id, session.get('user_id')))

            # get price
            service = db.execute('SELECT price FROM services WHERE id=?', (service_id,)).fetchone()

            # add to bill
            db.execute('''
                INSERT INTO bill_items (bill_id, service_id, quantity, price)
                VALUES (?, ?, ?, ?)
            ''', (bill_id, service_id, 1, service[0]))

            add_log(patient_id, "Doctor appointment + bill created")

        # TEST SERVICES
        elif service_type == 'test':
            selected_tests = request.form.getlist('test_ids')

            for test_id in selected_tests:
                service = db.execute('SELECT price FROM services WHERE id=?', (test_id,)).fetchone()

                # add test order
                db.execute('''
                    INSERT INTO test_orders (patient_id, service_id, test_date)
                    VALUES (?, ?, datetime('now', '+6 hours'))
                ''', (patient_id, test_id))

                # add to bill
                db.execute('''
                    INSERT INTO bill_items (bill_id, service_id, quantity, price)
                    VALUES (?, ?, ?, ?)
                ''', (bill_id, test_id, 1, service[0]))

            add_log(patient_id, "Test services added + bill created")

        db.commit()

        # Redirect to bill print page
        return redirect(url_for('bill_print', bill_id=bill_id))

    # GET REQUEST (SHOW PAGE)
    doctors = db.execute('SELECT id, name FROM doctors').fetchall()
    doctor_services = db.execute("SELECT * FROM services WHERE type='doctor'").fetchall()
    tests = db.execute("SELECT * FROM services WHERE type='test'").fetchall()

    return render_template(
        "patient_service.html",
        patient_id=patient_id,
        doctors=doctors,
        doctor_services=doctor_services,
        tests=tests
    )

@app.route('/service_desk', methods=['GET', 'POST'])
def service_desk():
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    selected_date = request.args.get('date', '').strip() or datetime.now().strftime('%Y-%m-%d')
    patients = db.execute('''
        SELECT * FROM patients
        WHERE date(created_at) = ?
        ORDER BY id ASC
    ''', (selected_date,)).fetchall()

    return render_template("service_desk.html", patients=patients, selected_date=selected_date)

@app.route('/billing', methods=['GET', 'POST'])
def billing():
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    bills = []

    if request.method == 'POST':
        keyword = request.form.get('keyword')

        bills = db.execute('''
            SELECT b.id, p.name, p.phone, b.total_amount, b.created_at
            FROM bills b
            JOIN patients p ON b.patient_id = p.id
            WHERE b.id LIKE ? OR p.name LIKE ? OR p.phone LIKE ?
            ORDER BY b.id ASC
        ''', (f"%{keyword}%", f"%{keyword}%", f"%{keyword}%")).fetchall()

    else:
        # Default: show latest bills
        bills = db.execute('''
            SELECT b.id, p.name, p.phone, b.total_amount, b.created_at
            FROM bills b
            JOIN patients p ON b.patient_id = p.id
            ORDER BY b.id ASC
            LIMIT 10
        ''').fetchall()

    return render_template("billing.html", bills=bills)

@app.route('/bill/<int:bill_id>')
def bill_print(bill_id):
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    # patient info
    bill = db.execute('''
        SELECT b.id, b.total_amount, b.created_at, p.name, p.phone
        FROM bills b
        JOIN patients p ON b.patient_id = p.id
        WHERE b.id = ?
    ''', (bill_id,)).fetchone()

    # bill items
    items = db.execute('''
        SELECT s.name, s.type, bi.price
        FROM bill_items bi
        JOIN services s ON bi.service_id = s.id
        WHERE bi.bill_id = ?
    ''', (bill_id,)).fetchall()

    # doctor info (if exists)
    doctor_info = db.execute('''
        SELECT d.name, d.room_number
        FROM appointments a
        JOIN doctors d ON a.doctor_id = d.id
        WHERE a.patient_id = (
            SELECT patient_id FROM bills WHERE id = ?
        )
        ORDER BY a.id ASC LIMIT 1
    ''', (bill_id,)).fetchone()

    return render_template("bill_print.html",
                           bill=bill,
                           items=items,
                           doctor=doctor_info)

@app.route('/appointments_info')
def appointments_info():
    if not isadmin() and not isuser(): return redirect(url_for('login'))
    return render_template('appointments_info.html')

@app.route('/appointments_info/doctors')
@app.route('/appointments_info/doctors/<int:doctor_id>')
def appointment_doctors(doctor_id=None):
    if not isadmin() and not isuser(): return redirect(url_for('login'))
    
    if doctor_id:
        doctor = db.execute("SELECT name FROM doctors WHERE id = ?", (doctor_id,)).fetchone()
        patients = db.execute('''
            SELECT DISTINCT p.id, p.name, p.phone, p.gender, p.age
            FROM patients p
            JOIN appointments a ON p.id = a.patient_id
            WHERE a.doctor_id = ?
        ''', (doctor_id,)).fetchall()
        return render_template('appointment_doctors.html', doctor=doctor, patients=patients, view_type='detail')
    else:
        # Get the search term and remove any accidental spaces
        search = request.args.get('search', '').strip()
        if search:
            doctors = db.execute("SELECT id, name, specialization FROM doctors WHERE name LIKE ?", (f'%{search}%',)).fetchall()
        else:
            doctors = db.execute("SELECT id, name, specialization FROM doctors").fetchall()
        
        return render_template('appointment_doctors.html', doctors=doctors, view_type='list', search=search)

@app.route('/appointments_info/patients')
@app.route('/appointments_info/patients/<int:patient_id>')
def appointment_patients(patient_id=None):
    if not isadmin() and not isuser(): return redirect(url_for('login'))
    
    if patient_id:
        patient = db.execute("SELECT name FROM patients WHERE id = ?", (patient_id,)).fetchone()
        services = db.execute('''
            SELECT DISTINCT s.id, s.name, s.type
            FROM services s
            JOIN bill_items bi ON s.id = bi.service_id
            JOIN bills b ON bi.bill_id = b.id
            WHERE b.patient_id = ?
            UNION
            SELECT DISTINCT s.id, s.name, s.type
            FROM services s
            JOIN appointments a ON s.id = a.service_id
            WHERE a.patient_id = ?
            UNION
            SELECT DISTINCT s.id, s.name, s.type
            FROM services s
            JOIN test_orders t ON s.id = t.service_id
            WHERE t.patient_id = ?
        ''', (patient_id, patient_id, patient_id)).fetchall()
        return render_template('appointment_patients.html', patient=patient, services=services, view_type='detail')
    else:
        # Get the search term and remove any accidental spaces
        search = request.args.get('search', '').strip()
        if search:
            patients = db.execute("SELECT id, name, phone FROM patients WHERE name LIKE ? OR phone LIKE ?", (f'%{search}%', f'%{search}%')).fetchall()
        else:
            patients = db.execute("SELECT id, name, phone FROM patients").fetchall()
            
        return render_template('appointment_patients.html', patients=patients, view_type='list', search=search)

#debug showing in web browser
if __name__ == '__main__':
    app.run(debug=True)
