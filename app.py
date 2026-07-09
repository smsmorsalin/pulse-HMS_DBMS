from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory, jsonify
import sqlite3
from datetime import datetime, timedelta
import time
import os
from werkzeug.security import check_password_hash, generate_password_hash

root_admin_username = "admin"
root_admin_password = "admin123456"  # In a production environment, use a strong password and consider storing it securely (e.g., in environment variables or a secure vault)

app = Flask(__name__)
app.secret_key = 'xs12a'  # Required for session management

# Path to the SQLite database file. Init runs with a short-lived connection
# to perform migrations, then a long-lived global connection is opened.
DB_PATH = 'hospital.db'

BED_NUMBER_OPTIONS = (
    '102',
    '103',
    '104',
    '106',
    '201-A',
    '201-B',
    '202-A',
    '202-B',
    '203-A',
    '203-B',
    '205-A',
    '205-B',
)


PAGE_OPTIONS = [
    {'key': 'dashboard', 'label': 'Dashboard', 'endpoint': 'dashboard', 'icon': 'fas fa-home'},
    {'key': 'patients_registration', 'label': 'Patients Registration', 'endpoint': 'patients_registration', 'icon': 'fas fa-user-plus'},
    {'key': 'patients_info', 'label': 'Patients Info', 'endpoint': 'patients_info', 'icon': 'fas fa-address-card', 'nav': False},
    {'key': 'ticket_print', 'label': 'Patient Ticket Print', 'endpoint': None, 'icon': 'fas fa-ticket', 'nav': False},
    {'key': 'doctors', 'label': 'Doctors', 'endpoint': 'doctors', 'icon': 'fas fa-user-md'},
    {'key': 'duty_management', 'label': 'Doctor and Nurse Duty', 'endpoint': 'duty_management', 'icon': 'fas fa-clipboard-check'},
    {'key': 'admissions', 'label': 'Admission', 'endpoint': 'admissions', 'icon': 'fas fa-file-medical'},
    {'key': 'appointments_info', 'label': 'Appointments Info', 'endpoint': 'appointments_info', 'icon': 'fa-solid fa-book-medical'},
    {'key': 'appointment_doctors', 'label': 'Appointment Doctors', 'endpoint': 'appointment_doctors', 'icon': 'fas fa-stethoscope'},
    {'key': 'appointment_patients', 'label': 'Appointment Patients', 'endpoint': 'appointment_patients', 'icon': 'fas fa-hospital-user'},
    {'key': 'pathology_dashboard', 'label': 'Pathology', 'endpoint': 'pathology_dashboard', 'icon': 'fas fa-microscope'},
    {'key': 'test_billing', 'label': 'Test', 'endpoint': 'test_billing', 'icon': 'fas fa-file-medical-alt'},
    {'key': 'tests', 'label': 'View Tests', 'endpoint': 'tests', 'icon': 'fas fa-vial'},
    {'key': 'medicine_sales', 'label': 'Medicine Sales', 'endpoint': 'medicine_sales', 'icon': 'fas fa-pills'},
    {'key': 'daily_expenses', 'label': 'Daily Expenses', 'endpoint': 'daily_expenses', 'icon': 'fas fa-wallet'},
    {'key': 'medicine_sales_print', 'label': 'Medicine Sales Print', 'endpoint': None, 'icon': 'fas fa-print', 'nav': False},
    {'key': 'medicine_sales_list', 'label': 'Medicine Sales List', 'endpoint': 'medicine_sales_list', 'icon': 'fas fa-calendar-days'},
    {'key': 'medicine_monthly_report', 'label': 'Medicine Monthly Report', 'endpoint': 'medicine_monthly_report', 'icon': 'fas fa-chart-column'},
    {'key': 'medicine_return', 'label': 'Medicine Return', 'endpoint': 'medicine_return', 'icon': 'fas fa-rotate-left'},
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
    'test_billing',
    'tests',
    'medicine_sales',
    'daily_expenses',
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
    'patients_info': ('patients_registration',),
    'edit_patient_profile': ('patients_registration',),
    'patient_details_bill': ('patients_registration',),
    'patient_visits_print': ('patients_registration',),
    'patient_pathology_print': ('patients_registration',),
    'visit_return': ('patients_registration',),
    'patient': ('patients_registration',),
    'add_patient': ('patients_registration',),
    'delete_patient': ('patients_registration',),
    'search_registered_patient': ('patients_registration',),
    'ticket_print': ('ticket_print', 'patients_registration'),
    'tickets': ('patients_registration',),
    'doctors': ('doctors',),
    'duty_management': ('duty_management',),
    'add_doctor': ('add_doctor',),
    'edit_doctor': ('edit_doctor',),
    'admissions': ('admissions',),
    'search_old_admitted_patient': ('admissions',),
    'concern_paper': ('admissions',),
    'discharge_bill': ('admissions',),
    'discharge_bill_print': ('admissions',),
    'discharge_patients_list': ('admissions',),
    'discharge_admission': ('admissions',),
    'appointments_info': ('appointments_info',),
    'appointment_doctors': ('appointment_doctors', 'appointments_info'),
    'appointment_patients': ('appointment_patients', 'appointments_info'),
    'pathology_dashboard': ('pathology_dashboard',),
    'update_pathology_status': ('pathology_dashboard',),
    'save_pathology_result': ('pathology_dashboard',),
    'test_billing': ('test_billing',),
    'test_bill_print': ('test_billing',),
    'test_return': ('test_billing',),
    'due': ('tests', 'test_billing'),
    'test_due_collection': ('tests', 'test_billing'),
    'collect_test_due': ('tests', 'test_billing'),
    'tests': ('tests',),
    'medicine_stock_dashboard': ('medicine_stock_dashboard',),
    'edit_medicine_transaction': ('medicine_stock_dashboard',),
    'delete_medicine_transaction': ('medicine_stock_dashboard',),
    'delete_medicine_balance': ('medicine_stock_dashboard',),
    'medicine_sales': ('medicine_sales',),
    'save_medicine_sale': ('medicine_sales',),
    'daily_expenses': ('daily_expenses',),
    'delete_daily_expense': ('daily_expenses',),
    'medicine_sales_print': ('medicine_sales_print', 'medicine_sales', 'medicine_sales_list'),
    'medicine_sales_list': ('medicine_sales_list',),
    'medicine_sales_list_print': ('medicine_sales_list',),
    'medicine_monthly_report': ('medicine_monthly_report', 'medicine_sales', 'medicine_sales_list'),
    'medicine_return': ('medicine_return', 'medicine_sales', 'medicine_sales_list'),
    'delete_medicine_monthly_day_sales': ('medicine_monthly_report',),
    'delete_medicine_monthly_product_sales': ('medicine_monthly_report',),
    'delete_medicine_sale': ('medicine_sales_list',),
    'services': ('services',),
    'add_service': ('add_service',),
    'edit_service': ('edit_service',),
    'delete_service': ('services',),
}

# Function to initialize the database and create tables if they don't exist
def init_db():
    """Initialize the hospital database with required tables if they don't exist."""
    # Use a short-lived connection for initialization/migrations to avoid
    # holding the module-global connection during potentially long-running
    # migrations which can cause 'database is locked' errors.
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA busy_timeout = 5000")
    except Exception:
        pass
    cursor = conn.cursor()

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
        params = PAGE_KEYS
        # Retry transient locked errors when cleaning up obsolete permission rows
        for attempt in range(6):
            try:
                cursor.execute(f'DELETE FROM user_permissions WHERE page_key NOT IN ({placeholders})', params)
                break
            except sqlite3.OperationalError:
                if attempt == 5:
                    raise
                time.sleep(0.25)
    
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
                doctor_fee REAL DEFAULT 0,
                source_patient_id INTEGER
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
        if 'source_patient_id' not in patients_columns:
            cursor.execute("ALTER TABLE patients ADD COLUMN source_patient_id INTEGER")

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

    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="patient_visit_returns"')
    patient_visit_returns_exists = cursor.fetchone() is not None
    if not patient_visit_returns_exists:
        cursor.execute('''
            CREATE TABLE patient_visit_returns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                return_no TEXT UNIQUE NOT NULL,
                patient_id INTEGER NOT NULL UNIQUE,
                patient_uhid INTEGER,
                ticket_no INTEGER,
                patient_name TEXT NOT NULL,
                phone TEXT,
                doctor_name TEXT,
                doctor_fee REAL NOT NULL DEFAULT 0,
                refund_amount REAL NOT NULL DEFAULT 0,
                reason TEXT,
                return_date TEXT NOT NULL,
                created_by TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (patient_id) REFERENCES patients(id)
            )
        ''')
        print("Patient Visit Returns table created successfully.")

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

    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="test_bills"')
    test_bills_exists = cursor.fetchone() is not None
    if not test_bills_exists:
        cursor.execute('''
            CREATE TABLE test_bills (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                invoice_no TEXT UNIQUE NOT NULL,
                patient_id INTEGER NOT NULL,
                doctor_name TEXT,
                referred_by TEXT,
                sample_status TEXT,
                delivery_time TEXT,
                subtotal REAL NOT NULL DEFAULT 0,
                discount_amount REAL NOT NULL DEFAULT 0,
                total_amount REAL NOT NULL DEFAULT 0,
                received_amount REAL NOT NULL DEFAULT 0,
                due_amount REAL NOT NULL DEFAULT 0,
                change_amount REAL NOT NULL DEFAULT 0,
                payment_method TEXT,
                remarks TEXT,
                created_by TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (patient_id) REFERENCES patients(id)
            )
        ''')
        print("Test Bills table created successfully.")

    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="test_bill_items"')
    test_bill_items_exists = cursor.fetchone() is not None
    if not test_bill_items_exists:
        cursor.execute('''
            CREATE TABLE test_bill_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                test_bill_id INTEGER NOT NULL,
                service_id INTEGER,
                test_name TEXT NOT NULL,
                price REAL NOT NULL DEFAULT 0,
                result_value TEXT,
                result_note TEXT,
                result_updated_at TEXT,
                result_updated_by TEXT,
                FOREIGN KEY (test_bill_id) REFERENCES test_bills(id) ON DELETE CASCADE,
                FOREIGN KEY (service_id) REFERENCES services(id)
            )
        ''')
        print("Test Bill Items table created successfully.")
    else:
        cursor.execute('PRAGMA table_info(test_bill_items)')
        test_bill_items_columns = {row[1] for row in cursor.fetchall()}
        test_bill_item_migrations = {
            'result_value': 'ALTER TABLE test_bill_items ADD COLUMN result_value TEXT',
            'result_note': 'ALTER TABLE test_bill_items ADD COLUMN result_note TEXT',
            'result_updated_at': 'ALTER TABLE test_bill_items ADD COLUMN result_updated_at TEXT',
            'result_updated_by': 'ALTER TABLE test_bill_items ADD COLUMN result_updated_by TEXT',
        }
        for column_name, alter_sql in test_bill_item_migrations.items():
            if column_name not in test_bill_items_columns:
                cursor.execute(alter_sql)

    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="test_bill_returns"')
    test_bill_returns_exists = cursor.fetchone() is not None
    if not test_bill_returns_exists:
        cursor.execute('''
            CREATE TABLE test_bill_returns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                return_no TEXT UNIQUE NOT NULL,
                test_bill_id INTEGER NOT NULL UNIQUE,
                invoice_no TEXT NOT NULL,
                patient_id INTEGER NOT NULL,
                patient_uhid INTEGER,
                ticket_no INTEGER,
                patient_name TEXT NOT NULL,
                phone TEXT,
                original_subtotal REAL NOT NULL DEFAULT 0,
                original_discount_amount REAL NOT NULL DEFAULT 0,
                original_total_amount REAL NOT NULL DEFAULT 0,
                original_received_amount REAL NOT NULL DEFAULT 0,
                original_due_amount REAL NOT NULL DEFAULT 0,
                refund_amount REAL NOT NULL DEFAULT 0,
                reason TEXT,
                return_date TEXT NOT NULL,
                created_by TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (test_bill_id) REFERENCES test_bills(id)
            )
        ''')
        print("Test Bill Returns table created successfully.")

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
                guardian_name TEXT,
                guardian_relation TEXT,
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
            'created_at': "ALTER TABLE admissions ADD COLUMN created_at TEXT NOT NULL DEFAULT ''",
            'guardian_name': 'ALTER TABLE admissions ADD COLUMN guardian_name TEXT',
            'guardian_relation': 'ALTER TABLE admissions ADD COLUMN guardian_relation TEXT'
        }
        for column_name, alter_sql in admission_migrations.items():
            if column_name not in admission_columns:
                cursor.execute(alter_sql)
        cursor.execute("UPDATE admissions SET status = 'Admitted' WHERE status IS NULL OR status = ''")
        cursor.execute("UPDATE admissions SET created_at = datetime('now', '+6 hours') WHERE created_at IS NULL OR created_at = ''")

    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="discharge_bills"')
    discharge_bills_exists = cursor.fetchone() is not None
    if not discharge_bills_exists:
        cursor.execute('''
            CREATE TABLE discharge_bills (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                admission_id INTEGER NOT NULL UNIQUE,
                patient_id INTEGER NOT NULL,
                patient_uhid INTEGER,
                bill_no TEXT NOT NULL,
                admission_date TEXT,
                discharge_date TEXT,
                stay_days INTEGER NOT NULL DEFAULT 1,
                bed_charge REAL NOT NULL DEFAULT 0,
                doctor_fee REAL NOT NULL DEFAULT 0,
                medicine_charge REAL NOT NULL DEFAULT 0,
                pathology_charge REAL NOT NULL DEFAULT 0,
                service_charge REAL NOT NULL DEFAULT 0,
                other_charge REAL NOT NULL DEFAULT 0,
                total_amount REAL NOT NULL DEFAULT 0,
                discount REAL NOT NULL DEFAULT 0,
                gross_amount REAL NOT NULL DEFAULT 0,
                paid_amount REAL NOT NULL DEFAULT 0,
                due_amount REAL NOT NULL DEFAULT 0,
                change_amount REAL NOT NULL DEFAULT 0,
                remarks TEXT,
                prepared_by TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (admission_id) REFERENCES admissions(id),
                FOREIGN KEY (patient_id) REFERENCES patients(id)
            )
        ''')
        print("Discharge Bills table created successfully.")
    else:
        cursor.execute('PRAGMA table_info(discharge_bills)')
        discharge_bill_columns = {row[1] for row in cursor.fetchall()}
        discharge_bill_migrations = {
            'patient_uhid': 'ALTER TABLE discharge_bills ADD COLUMN patient_uhid INTEGER',
            'remarks': 'ALTER TABLE discharge_bills ADD COLUMN remarks TEXT',
            'prepared_by': 'ALTER TABLE discharge_bills ADD COLUMN prepared_by TEXT',
            'updated_at': "ALTER TABLE discharge_bills ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''"
        }
        for column_name, alter_sql in discharge_bill_migrations.items():
            if column_name not in discharge_bill_columns:
                cursor.execute(alter_sql)

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

    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="daily_expenses"')
    daily_expenses_exists = cursor.fetchone() is not None
    if not daily_expenses_exists:
        cursor.execute('''
            CREATE TABLE daily_expenses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                expense_date TEXT NOT NULL,
                category TEXT NOT NULL,
                description TEXT NOT NULL,
                vendor TEXT,
                amount REAL NOT NULL,
                payment_method TEXT NOT NULL DEFAULT 'Cash',
                note TEXT,
                created_by TEXT,
                created_at TEXT NOT NULL
            )
        ''')
        print("Daily Expenses table created successfully.")

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
                customer_address TEXT,
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
    else:
        cursor.execute('PRAGMA table_info(medicine_sales)')
        medicine_sales_columns = {row[1] for row in cursor.fetchall()}
        if 'customer_address' not in medicine_sales_columns:
            cursor.execute("ALTER TABLE medicine_sales ADD COLUMN customer_address TEXT")

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

    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="medicine_returns"')
    medicine_returns_exists = cursor.fetchone() is not None
    if not medicine_returns_exists:
        cursor.execute('''
            CREATE TABLE medicine_returns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                return_no TEXT UNIQUE NOT NULL,
                sale_id INTEGER NOT NULL,
                invoice_no TEXT NOT NULL,
                customer_name TEXT NOT NULL,
                customer_phone TEXT,
                reason TEXT,
                subtotal REAL NOT NULL DEFAULT 0,
                discount_amount REAL NOT NULL DEFAULT 0,
                refund_amount REAL NOT NULL DEFAULT 0,
                return_date TEXT NOT NULL,
                created_by TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (sale_id) REFERENCES medicine_sales(id)
            )
        ''')
        print("Medicine Returns table created successfully.")

    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="medicine_return_items"')
    medicine_return_items_exists = cursor.fetchone() is not None
    if not medicine_return_items_exists:
        cursor.execute('''
            CREATE TABLE medicine_return_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                return_id INTEGER NOT NULL,
                sale_item_id INTEGER NOT NULL,
                medicine_name TEXT NOT NULL,
                batch_no TEXT NOT NULL,
                unit_type TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                unit_price REAL NOT NULL,
                discount REAL NOT NULL DEFAULT 0,
                line_total REAL NOT NULL DEFAULT 0,
                FOREIGN KEY (return_id) REFERENCES medicine_returns(id),
                FOREIGN KEY (sale_item_id) REFERENCES medicine_sale_items(id)
            )
        ''')
        print("Medicine Return Items table created successfully.")

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

    # commit the changes to the database and close the temporary connection
    conn.commit()
    conn.close()
    print("Hospital database initialized successfully.")

# Initialize database on app startup (run migrations using a temp connection)
init_db()

# Now open the long-lived global connection used by the app
db = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
db.execute("PRAGMA foreign_keys = ON")
try:
    db.execute("PRAGMA journal_mode = WAL")
    db.execute("PRAGMA busy_timeout = 5000")
except Exception:
    pass

def _current_session_user_id():
    user_id = session.get('user_id')
    if user_id in (None, ''):
        return None
    if isinstance(user_id, (int, str)):
        return user_id
    return None


def isadmin():
    """Helper function to check if the current user is an admin."""
    user_id = _current_session_user_id()
    if not user_id:
        return False
    if user_id == 'root_admin':
        return True
    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (user_id,)).fetchone()
    return bool(admin_checker and admin_checker[0] == user_id)

def isuser():
    """Helper function to check if the current user is a regular user."""
    user_id = _current_session_user_id()
    if not user_id:
        return False
    user_checker = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    return bool(user_checker and user_checker[0] == user_id)

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
        'format_invoice_date': format_invoice_date,
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

    text_value = str(value).strip()
    for date_format, output_format in (
        ('%Y-%m-%d %H:%M:%S', '%d-%m-%Y %H:%M:%S'),
        ('%Y-%m-%dT%H:%M:%S', '%d-%m-%Y %H:%M:%S'),
        ('%Y-%m-%d %H:%M:%S.%f', '%d-%m-%Y %H:%M:%S'),
        ('%Y-%m-%dT%H:%M:%S.%f', '%d-%m-%Y %H:%M:%S'),
        ('%Y-%m-%d', '%d-%m-%Y'),
    ):
        try:
            return datetime.strptime(text_value, date_format).strftime(output_format)
        except ValueError:
            continue

    return text_value

def format_invoice_date(value):
    """Format stored ISO-like dates as DD-MM-YYYY without time."""
    formatted_value = format_invoice_datetime(value)
    return formatted_value.split(' ')[0] if formatted_value and formatted_value != '-' else formatted_value

def format_date_display(value):
    """Format date text as DD-MM-YYYY, preserving time when present."""
    if not value:
        return '-'

    text_value = str(value).strip()
    for date_format, output_format in (
        ('%Y-%m-%d %H:%M:%S', '%d-%m-%Y %H:%M:%S'),
        ('%Y-%m-%dT%H:%M:%S', '%d-%m-%Y %H:%M:%S'),
        ('%Y-%m-%d %H:%M:%S.%f', '%d-%m-%Y %H:%M:%S'),
        ('%Y-%m-%dT%H:%M:%S.%f', '%d-%m-%Y %H:%M:%S'),
        ('%Y-%m-%d %H:%M', '%d-%m-%Y %H:%M'),
        ('%Y-%m-%dT%H:%M', '%d-%m-%Y %H:%M'),
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


def is_medicine_return_stock_note(note):
    """Return stock transactions restore balance but should not count as purchase stock-in."""
    return str(note or '').strip().lower().startswith('returned on ')


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
            'return_in': 0,
            'stock_out': 0,
            'balance': 0,
            'latest_price': row[6],
            'latest_date': row[7],
        })

        if row[4] == 'in':
            if is_medicine_return_stock_note(row[8]):
                medicine_summary['return_in'] += row[5]
            else:
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


@app.route('/duty-management-dashboard')
def duty_management_dashboard():
    """Records-only dashboard for one selected doctor and nurse duty day."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (session.get('user_id'),)).fetchone()
    user_checker = db.execute('SELECT * FROM users WHERE id = ?', (session.get('user_id'),)).fetchone()
    if session.get('user_id') == 'root_admin':
        profile_name = root_admin_username
    elif admin_checker and admin_checker[0] == session.get('user_id'):
        profile_name = admin_checker[1]
    elif user_checker and user_checker[0] == session.get('user_id'):
        profile_name = user_checker[1]
    else:
        profile_name = 'User'

    selected_date = request.args.get('date', '').strip() or datetime.now().strftime('%Y-%m-%d')
    try:
        datetime.strptime(selected_date, '%Y-%m-%d')
    except ValueError:
        selected_date = datetime.now().strftime('%Y-%m-%d')

    duty_rows = db.execute(
        '''
        SELECT id, staff_role, staff_name, duty_date, shift, ward, round_completed, notes, created_by, created_at
        FROM duty_records
        WHERE date(duty_date) = ?
        ORDER BY date(duty_date) DESC, created_at DESC, id DESC
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
    doctor_records = sum(1 for row in duty_records if row['staff_role'] == 'doctor')
    nurse_records = sum(1 for row in duty_records if row['staff_role'] == 'nurse')
    today_records = total_records
    completion_rate = round((completed_records / total_records) * 100) if total_records else 0

    return render_template(
        'duty_management_dashboard.html',
        profile_name=profile_name,
        selected_date=selected_date,
        duty_records=duty_records,
        total_records=total_records,
        completed_records=completed_records,
        pending_records=total_records - completed_records,
        doctor_records=doctor_records,
        nurse_records=nurse_records,
        today_records=today_records,
        completion_rate=completion_rate,
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


@app.route('/daily_expenses', methods=['GET', 'POST'])
def daily_expenses():
    """Record and review daily hospital expenses."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    expense_categories = [
        'Medicine Purchase',
        'Pathology Supplies',
        'Doctor / Staff Payment',
        'Utility Bill',
        'Maintenance',
        'Food / Kitchen',
        'Transport',
        'Office Supplies',
        'Cleaning',
        'Other',
    ]
    payment_methods = ['Cash', 'Bkash', 'Nagad', 'Bank', 'Card', 'Due']

    selected_date = request.args.get('date', '').strip() or datetime.now().strftime('%Y-%m-%d')
    selected_category = request.args.get('category', '').strip()
    keyword = request.args.get('keyword', '').strip()
    message = request.args.get('message', '').strip()
    success = request.args.get('success', '').strip()

    try:
        datetime.strptime(selected_date, '%Y-%m-%d')
    except ValueError:
        selected_date = datetime.now().strftime('%Y-%m-%d')

    if request.method == 'POST':
        expense_date = request.form.get('expense_date', '').strip() or datetime.now().strftime('%Y-%m-%d')
        category = request.form.get('category', '').strip()
        description = request.form.get('description', '').strip()
        vendor = request.form.get('vendor', '').strip()
        payment_method = request.form.get('payment_method', '').strip() or 'Cash'
        note = request.form.get('note', '').strip()

        try:
            datetime.strptime(expense_date, '%Y-%m-%d')
            amount = float(request.form.get('amount') or 0)
            if amount <= 0:
                raise ValueError
        except (TypeError, ValueError):
            return redirect(url_for(
                'daily_expenses',
                date=selected_date,
                category=selected_category,
                keyword=keyword,
                message='Please enter a valid date and expense amount.'
            ))

        if not category or not description:
            return redirect(url_for(
                'daily_expenses',
                date=selected_date,
                category=selected_category,
                keyword=keyword,
                message='Please choose a category and write an expense description.'
            ))

        if category not in expense_categories:
            category = 'Other'
        if payment_method not in payment_methods:
            payment_method = 'Cash'

        try:
            db.execute(
                '''
                INSERT INTO daily_expenses (
                    expense_date, category, description, vendor, amount,
                    payment_method, note, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    expense_date,
                    category,
                    description,
                    vendor,
                    amount,
                    payment_method,
                    note,
                    str(session.get('user_id')),
                    datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                )
            )
            db.commit()
            add_system_log(f'Daily expense added: {category} Tk {amount:.2f}')
            return redirect(url_for('daily_expenses', date=expense_date, success='Expense saved successfully.'))
        except sqlite3.Error:
            db.rollback()
            return redirect(url_for('daily_expenses', date=selected_date, message='Could not save this expense. Please try again.'))

    where_clauses = ['date(expense_date) = ?']
    params = [selected_date]
    if selected_category:
        where_clauses.append('category = ?')
        params.append(selected_category)
    if keyword:
        where_clauses.append('''
            (
                description LIKE ?
                OR vendor LIKE ?
                OR note LIKE ?
                OR payment_method LIKE ?
            )
        ''')
        params.extend([f'%{keyword}%'] * 4)

    where_sql = ' AND '.join(where_clauses)
    expense_rows = db.execute(
        f'''
        SELECT id, expense_date, category, description, vendor, amount,
               payment_method, note, created_by, created_at
        FROM daily_expenses
        WHERE {where_sql}
        ORDER BY datetime(created_at) DESC, id DESC
        ''',
        params
    ).fetchall()

    category_rows = db.execute(
        '''
        SELECT category, COALESCE(SUM(amount), 0), COUNT(*)
        FROM daily_expenses
        WHERE date(expense_date) = ?
        GROUP BY category
        ORDER BY SUM(amount) DESC, category ASC
        ''',
        (selected_date,)
    ).fetchall()
    today_total = db.execute(
        'SELECT COALESCE(SUM(amount), 0), COUNT(*) FROM daily_expenses WHERE date(expense_date) = ?',
        (selected_date,)
    ).fetchone()
    month_key = selected_date[:7]
    month_total = db.execute(
        "SELECT COALESCE(SUM(amount), 0) FROM daily_expenses WHERE strftime('%Y-%m', expense_date) = ?",
        (month_key,)
    ).fetchone()[0]
    highest_expense = max((float(row[5] or 0) for row in expense_rows), default=0)

    return render_template(
        'daily_expenses.html',
        expense_rows=expense_rows,
        category_rows=category_rows,
        expense_categories=expense_categories,
        payment_methods=payment_methods,
        selected_date=selected_date,
        selected_category=selected_category,
        keyword=keyword,
        today_total=float(today_total[0] or 0),
        today_count=int(today_total[1] or 0),
        month_total=float(month_total or 0),
        highest_expense=highest_expense,
        message=message,
        success=success,
        admin=isadmin(),
    )


@app.route('/daily_expenses/delete/<int:expense_id>', methods=['POST'])
def delete_daily_expense(expense_id):
    """Delete one daily expense entry. Admins only."""
    selected_date = request.form.get('selected_date', '').strip() or datetime.now().strftime('%Y-%m-%d')
    if not isadmin():
        return redirect(url_for('daily_expenses', date=selected_date, message='Only admin can delete expenses.'))

    expense = db.execute(
        'SELECT category, description, amount FROM daily_expenses WHERE id = ?',
        (expense_id,)
    ).fetchone()
    if not expense:
        return redirect(url_for('daily_expenses', date=selected_date, message='Expense entry not found.'))

    try:
        db.execute('DELETE FROM daily_expenses WHERE id = ?', (expense_id,))
        db.commit()
        add_system_log(f'Daily expense deleted: {expense[0]} Tk {float(expense[2] or 0):.2f}')
        return redirect(url_for('daily_expenses', date=selected_date, success='Expense deleted successfully.'))
    except sqlite3.Error:
        db.rollback()
        return redirect(url_for('daily_expenses', date=selected_date, message='Could not delete this expense.'))

@app.route('/pathology_dashboard')
def pathology_dashboard():
    """Professional pathology workbench backed by patient test invoices."""
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

    selected_date = request.args.get('date', '').strip()
    if selected_date:
        try:
            datetime.strptime(selected_date, '%Y-%m-%d')
        except ValueError:
            selected_date = ''

    date_where = 'WHERE date(tb.created_at) = ?' if selected_date else ''
    bill_date_where = 'WHERE date(created_at) = ?' if selected_date else ''
    query_params = (selected_date,) if selected_date else ()
    date_label = format_date_display(selected_date) if selected_date else 'All pathology records'

    available_tests = db.execute("SELECT COUNT(*) FROM services WHERE type = 'test'").fetchone()[0]
    total_bills = db.execute(
        f"SELECT COUNT(*) FROM test_bills {bill_date_where}",
        query_params
    ).fetchone()[0]
    total_patients = db.execute(
        f"SELECT COUNT(DISTINCT patient_id) FROM test_bills {bill_date_where}",
        query_params
    ).fetchone()[0]
    total_test_items = db.execute(
        '''
        SELECT COUNT(*)
        FROM test_bill_items tbi
        JOIN test_bills tb ON tb.id = tbi.test_bill_id
        {date_where}
        '''.format(date_where=date_where),
        query_params
    ).fetchone()[0]
    resulted_items = db.execute(
        '''
        SELECT COUNT(*)
        FROM test_bill_items tbi
        JOIN test_bills tb ON tb.id = tbi.test_bill_id
        {date_where}
        {where_joiner} NULLIF(TRIM(COALESCE(tbi.result_value, '')), '') IS NOT NULL
        '''.format(
            date_where=date_where,
            where_joiner='AND' if date_where else 'WHERE'
        ),
        query_params
    ).fetchone()[0]
    open_result_items = max(int(total_test_items or 0) - int(resulted_items or 0), 0)
    totals = db.execute(
        '''
        SELECT
            COALESCE(SUM(total_amount), 0),
            COALESCE(SUM(due_amount), 0),
            SUM(CASE WHEN sample_status = 'Pending' THEN 1 ELSE 0 END),
            SUM(CASE WHEN sample_status = 'Collected' THEN 1 ELSE 0 END),
            SUM(CASE WHEN sample_status = 'Delivered' THEN 1 ELSE 0 END)
        FROM test_bills
        {bill_date_where}
        '''.format(bill_date_where=bill_date_where),
        query_params
    ).fetchone()

    pathology_orders = db.execute(
        '''
        SELECT
            tbi.id,
            tb.id,
            tb.invoice_no,
            tb.created_at,
            tb.doctor_name,
            tb.referred_by,
            tb.sample_status,
            tb.delivery_time,
            tb.total_amount,
            tb.due_amount,
            p.name,
            p.phone,
            p.age,
            COALESCE(NULLIF(p.age_unit, ''), 'Y'),
            p.gender,
            COALESCE(p.source_patient_id, p.id) AS patient_uhid,
            tbi.test_name,
            tbi.price,
            tbi.result_value,
            tbi.result_note,
            tbi.result_updated_at,
            tbi.result_updated_by
        FROM test_bills tb
        JOIN patients p ON p.id = tb.patient_id
        JOIN test_bill_items tbi ON tbi.test_bill_id = tb.id
        {date_where}
        ORDER BY
            CASE WHEN NULLIF(TRIM(COALESCE(tbi.result_value, '')), '') IS NULL THEN 1 ELSE 2 END,
            CASE tb.sample_status
                WHEN 'Pending' THEN 1
                WHEN 'Collected' THEN 2
                WHEN 'Delivered' THEN 3
                ELSE 4
            END,
            datetime(tb.created_at) DESC,
            tb.id DESC,
            tbi.id ASC
        '''.format(date_where=date_where),
        query_params
    ).fetchall()

    patient_cases = db.execute(
        '''
        SELECT
            tb.id,
            tb.invoice_no,
            tb.created_at,
            tb.sample_status,
            tb.delivery_time,
            tb.total_amount,
            tb.due_amount,
            p.name,
            p.phone,
            p.age,
            COALESCE(NULLIF(p.age_unit, ''), 'Y'),
            p.gender,
            COALESCE(p.source_patient_id, p.id) AS patient_uhid,
            tb.doctor_name,
            tb.referred_by,
            COUNT(tbi.id) AS test_count,
            SUM(CASE WHEN NULLIF(TRIM(COALESCE(tbi.result_value, '')), '') IS NOT NULL THEN 1 ELSE 0 END) AS completed_count,
            GROUP_CONCAT(tbi.test_name, ', ') AS test_names
        FROM test_bills tb
        JOIN patients p ON p.id = tb.patient_id
        JOIN test_bill_items tbi ON tbi.test_bill_id = tb.id
        {date_where}
        GROUP BY tb.id
        ORDER BY
            CASE tb.sample_status
                WHEN 'Pending' THEN 1
                WHEN 'Collected' THEN 2
                WHEN 'Delivered' THEN 3
                ELSE 4
            END,
            datetime(tb.created_at) DESC,
            tb.id DESC
        '''.format(date_where=date_where),
        query_params
    ).fetchall()
    patient_cases = [
        {
            'bill_id': row[0],
            'invoice_no': row[1],
            'created_at': row[2],
            'sample_status': row[3] or 'Pending',
            'delivery_time': row[4],
            'total_amount': float(row[5] or 0),
            'due_amount': float(row[6] or 0),
            'patient_name': row[7],
            'phone': row[8],
            'age': row[9],
            'age_unit': row[10],
            'gender': row[11],
            'patient_uhid': row[12],
            'doctor_name': row[13],
            'referred_by': row[14],
            'test_count': int(row[15] or 0),
            'completed_count': int(row[16] or 0),
            'test_names': row[17] or '',
        }
        for row in patient_cases
    ]

    category_rows = db.execute(
        '''
        SELECT tbi.test_name, COUNT(*)
        FROM test_bill_items tbi
        JOIN test_bills tb ON tb.id = tbi.test_bill_id
        {date_where}
        GROUP BY tbi.test_name
        '''.format(date_where=date_where),
        query_params
    ).fetchall()
    category_rules = [
        ('Hematology', ('cbc', 'blood', 'hb', 'hemoglobin', 'esr', 'platelet', 'tc', 'dc')),
        ('Biochemistry', ('glucose', 'sugar', 'creatinine', 'urea', 'lipid', 'cholesterol', 'bilirubin', 'sgpt', 'sgot', 'lft', 'rft', 'uric')),
        ('Microbiology', ('culture', 'urine', 'stool', 'sputum', 'widal', 'gram')),
        ('Serology', ('hbsag', 'vdrl', 'hiv', 'antigen', 'antibody', 'crp', 'aso', 'ra factor')),
    ]
    category_colors = {
        'Hematology': '#2378ff',
        'Biochemistry': '#24c486',
        'Microbiology': '#f59e0b',
        'Serology': '#7357f6',
        'Others': '#8aa4ca',
    }
    category_counts = {name: 0 for name, _ in category_rules}
    category_counts['Others'] = 0
    for test_name, count in category_rows:
        normalized_name = (test_name or '').lower()
        matched_category = 'Others'
        for category_name, keywords in category_rules:
            if any(keyword in normalized_name for keyword in keywords):
                matched_category = category_name
                break
        category_counts[matched_category] += int(count or 0)
    category_total = sum(category_counts.values()) or 0
    test_categories = [
        {
            'name': name,
            'count': count,
            'percent': round((count / category_total) * 100) if category_total else 0,
            'color': category_colors[name],
        }
        for name, count in category_counts.items()
        if count > 0
    ]

    ready_to_deliver_count = db.execute(
        '''
        SELECT COUNT(DISTINCT tb.id)
        FROM test_bills tb
        JOIN test_bill_items tbi ON tbi.test_bill_id = tb.id
        {date_where}
        {where_joiner} tb.sample_status = 'Collected'
          AND NULLIF(TRIM(COALESCE(tbi.result_value, '')), '') IS NOT NULL
        '''.format(
            date_where=date_where,
            where_joiner='AND' if date_where else 'WHERE'
        ),
        query_params
    ).fetchone()[0]
    pending_summary = [
        {'label': 'Sample Pending', 'value': int(totals[2] or 0), 'icon': 'fas fa-hourglass-half', 'tone': 'amber'},
        {'label': 'Sample Collected', 'value': int(totals[3] or 0), 'icon': 'fas fa-vial-circle-check', 'tone': 'blue'},
        {'label': 'Awaiting Result', 'value': open_result_items, 'icon': 'fas fa-file-circle-question', 'tone': 'purple'},
        {'label': 'Ready to Deliver', 'value': int(ready_to_deliver_count or 0), 'icon': 'fas fa-file-circle-check', 'tone': 'green'},
    ]

    trend_rows = db.execute(
        '''
        SELECT date(created_at), COUNT(*), COALESCE(SUM(total_amount), 0)
        FROM test_bills
        GROUP BY date(created_at)
        ORDER BY date(created_at) DESC
        LIMIT 14
        '''
    ).fetchall()
    trend_points = [
        {
            'date': row[0],
            'label': format_date_display(row[0]),
            'invoices': int(row[1] or 0),
            'revenue': float(row[2] or 0),
        }
        for row in reversed(trend_rows)
    ]

    recent_reports = db.execute(
        '''
        SELECT tb.id, tb.invoice_no, p.name, tbi.test_name, tbi.result_updated_at, tb.sample_status, tbi.id
        FROM test_bill_items tbi
        JOIN test_bills tb ON tb.id = tbi.test_bill_id
        JOIN patients p ON p.id = tb.patient_id
        WHERE NULLIF(TRIM(COALESCE(tbi.result_value, '')), '') IS NOT NULL
        {date_filter}
        ORDER BY datetime(tbi.result_updated_at) DESC, tbi.id DESC
        LIMIT 8
        '''.format(date_filter=('AND date(tb.created_at) = ?' if selected_date else '')),
        query_params
    ).fetchall()
    recent_reports = [
        {
            'bill_id': row[0],
            'invoice_no': row[1],
            'patient_name': row[2],
            'test_name': row[3],
            'updated_at': row[4],
            'sample_status': row[5] or 'Pending',
            'item_id': row[6],
        }
        for row in recent_reports
    ]

    pathology_orders = [
        {
            'item_id': row[0],
            'bill_id': row[1],
            'invoice_no': row[2],
            'created_at': row[3],
            'doctor_name': row[4],
            'referred_by': row[5],
            'sample_status': row[6] or 'Pending',
            'delivery_time': row[7],
            'total_amount': float(row[8] or 0),
            'due_amount': float(row[9] or 0),
            'patient_name': row[10],
            'phone': row[11],
            'age': row[12],
            'age_unit': row[13],
            'gender': row[14],
            'patient_uhid': row[15],
            'test_name': row[16],
            'price': float(row[17] or 0),
            'result_value': row[18] or '',
            'result_note': row[19] or '',
            'result_updated_at': row[20] or '',
            'result_updated_by': row[21] or '',
        }
        for row in pathology_orders
    ]

    return render_template(
        'pathology_dashboard.html',
        profile_name=profile_name,
        admin=isadmin(),
        selected_date=selected_date,
        date_label=date_label,
        selected_item=request.args.get('selected_item', '').strip(),
        available_tests=available_tests,
        total_bills=total_bills,
        total_patients=total_patients,
        total_test_items=total_test_items,
        resulted_items=resulted_items,
        open_result_items=open_result_items,
        total_revenue=float(totals[0] or 0),
        total_due=float(totals[1] or 0),
        pending_count=int(totals[2] or 0),
        collected_count=int(totals[3] or 0),
        delivered_count=int(totals[4] or 0),
        trend_points=trend_points,
        pending_summary=pending_summary,
        test_categories=test_categories,
        recent_reports=recent_reports,
        patient_cases=patient_cases,
        pathology_orders=pathology_orders,
    )


@app.route('/pathology_dashboard/status/<int:test_bill_id>', methods=['POST'])
def update_pathology_status(test_bill_id):
    """Update sample/report status for one test invoice from Pathology."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    selected_date = request.form.get('selected_date', '').strip()
    sample_status = request.form.get('sample_status', '').strip()
    redirect_args = {'date': selected_date} if selected_date else {}
    if sample_status not in ('Pending', 'Collected', 'Delivered'):
        return redirect(url_for('pathology_dashboard', **redirect_args))

    db.execute(
        'UPDATE test_bills SET sample_status = ? WHERE id = ?',
        (sample_status, test_bill_id)
    )
    db.commit()
    return redirect(url_for('pathology_dashboard', **redirect_args))


@app.route('/pathology_dashboard/result/<int:test_item_id>', methods=['POST'])
def save_pathology_result(test_item_id):
    """Save the entered result value for one billed pathology test item."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    selected_date = request.form.get('selected_date', '').strip()
    result_value = request.form.get('result_value', '').strip()
    result_note = request.form.get('result_note', '').strip()
    actor = get_current_actor()
    actor_name = actor[2]
    redirect_args = {'date': selected_date} if selected_date else {}

    test_item = db.execute(
        '''
        SELECT tbi.id, tbi.test_name, tb.patient_id, tb.invoice_no
        FROM test_bill_items tbi
        JOIN test_bills tb ON tb.id = tbi.test_bill_id
        WHERE tbi.id = ?
        ''',
        (test_item_id,)
    ).fetchone()
    if not test_item:
        return redirect(url_for('pathology_dashboard', **redirect_args))

    db.execute(
        '''
        UPDATE test_bill_items
        SET result_value = ?,
            result_note = ?,
            result_updated_at = CASE
                WHEN ? = '' THEN NULL
                ELSE datetime('now', '+6 hours')
            END,
            result_updated_by = CASE
                WHEN ? = '' THEN NULL
                ELSE ?
            END
        WHERE id = ?
        ''',
        (result_value, result_note, result_value, result_value, actor_name, test_item_id)
    )
    if result_value:
        add_system_log(f"Pathology result saved for {test_item[1]} on invoice {test_item[3]}", test_item[2], actor)
    else:
        add_system_log(f"Pathology result cleared for {test_item[1]} on invoice {test_item[3]}", test_item[2], actor)

    db.commit()
    redirect_args['selected_item'] = test_item_id
    return redirect(url_for('pathology_dashboard', **redirect_args))


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
    total_return_in = sum(row['return_in'] for row in summary_rows)
    total_stock_out = sum(row['stock_out'] for row in summary_rows)
    active_medicines = len(summary_rows)
    low_stock_count = sum(1 for row in summary_rows if 0 < row['balance'] <= 10)
    inventory_value = sum(row['balance'] * row['latest_price'] for row in summary_rows if row['balance'] > 0)

    newest_transactions = list(reversed(transactions))
    recent_stock_in = [
        entry for entry in newest_transactions
        if entry['transaction_type'] == 'in' and not is_medicine_return_stock_note(entry['note'])
    ][:8]
    recent_return_in = [
        entry for entry in newest_transactions
        if entry['transaction_type'] == 'in' and is_medicine_return_stock_note(entry['note'])
    ][:8]
    recent_stock_out = [entry for entry in newest_transactions if entry['transaction_type'] == 'out'][:8]

    return render_template(
        "medicine_stock_dashboard.html",
        profile_name=profile_name,
        error=error,
        summary_rows=summary_rows,
        recent_stock_in=recent_stock_in,
        recent_return_in=recent_return_in,
        recent_stock_out=recent_stock_out,
        total_stock_in=total_stock_in,
        total_return_in=total_return_in,
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
    selected_customer = request.args.get('customer', '').strip()

    customers = [
        {'name': row[0], 'phone': row[1], 'address': row[2]}
        for row in db.execute(
            '''
            SELECT name, phone, address
            FROM patients
            ORDER BY id DESC
            LIMIT 8
            '''
        ).fetchall()
    ]
    selected_customer_info = next(
        (customer for customer in customers if customer['name'] == selected_customer),
        None
    )
    customer_name_value = request.args.get('customer_name', '').strip()
    customer_phone_value = request.args.get('customer_phone', '').strip()
    customer_address_value = request.args.get('customer_address', '').strip()
    if selected_customer_info:
        customer_name_value = customer_name_value or selected_customer_info['name']
        customer_phone_value = customer_phone_value or selected_customer_info['phone']
        customer_address_value = customer_address_value or selected_customer_info['address']

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
        selected_customer=selected_customer,
        customer_name_value=customer_name_value,
        customer_phone_value=customer_phone_value,
        customer_address_value=customer_address_value,
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
    customer_phone = ''.join(character for character in str(payload.get('customerPhone') or '') if character.isdigit())[:11]
    customer_address = str(payload.get('customerAddress') or '').strip()
    registered_customer = db.execute(
        '''
        SELECT phone, address
        FROM patients
        WHERE name = ?
        ORDER BY id DESC
        LIMIT 1
        ''',
        (customer_name,)
    ).fetchone()
    if registered_customer:
        customer_phone = customer_phone or (registered_customer[0] or '')
        customer_address = customer_address or (registered_customer[1] or '')
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
                invoice_no, customer_name, customer_phone, customer_address, subtotal, discount_type,
                discount_value, discount_amount, tax_type, tax_value, tax_amount,
                delivery_cost, grand_total, received_amount, due_amount, change_amount,
                payment_type, sale_date, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                invoice_no, customer_name, customer_phone, customer_address, subtotal, discount_type,
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
            'customer_address': customer_address,
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
        SELECT id, invoice_no, customer_name, customer_phone, customer_address, subtotal, discount_type,
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

    created_by_id = sale_row[19]
    if created_by_id == 'root_admin':
        prepared_by = root_admin_username
    else:
        prepared_user = db.execute('SELECT username FROM admins WHERE id = ?', (created_by_id,)).fetchone()
        if not prepared_user:
            prepared_user = db.execute('SELECT username FROM users WHERE id = ?', (created_by_id,)).fetchone()
        prepared_by = prepared_user[0] if prepared_user and prepared_user[0] else 'Unknown user'

    customer_phone = sale_row[3] or ''
    customer_address = sale_row[4] or ''
    if not customer_address and sale_row[2] and sale_row[2] != 'Walk-in Customer':
        registered_customer = db.execute(
            '''
            SELECT phone, address
            FROM patients
            WHERE name = ?
            ORDER BY id DESC
            LIMIT 1
            ''',
            (sale_row[2],)
        ).fetchone()
        if registered_customer:
            customer_phone = customer_phone or (registered_customer[0] or '')
            customer_address = registered_customer[1] or ''

    sale = {
        'id': sale_row[0],
        'invoice_no': sale_row[1],
        'customer_name': sale_row[2],
        'customer_phone': customer_phone,
        'customer_address': customer_address,
        'subtotal': sale_row[5],
        'discount_type': sale_row[6],
        'discount_value': sale_row[7],
        'discount_amount': sale_row[8],
        'tax_type': sale_row[9],
        'tax_value': sale_row[10],
        'tax_amount': sale_row[11],
        'delivery_cost': sale_row[12],
        'grand_total': sale_row[13],
        'received_amount': sale_row[14],
        'due_amount': sale_row[15],
        'change_amount': sale_row[16],
        'payment_type': sale_row[17],
        'sale_date': sale_row[18],
        'sale_date_display': format_invoice_date(sale_row[18]),
        'created_by': created_by_id,
        'created_at': sale_row[20],
        'created_at_display': format_invoice_datetime(sale_row[20]),
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


@app.route('/medicine_return', methods=['GET', 'POST'])
def medicine_return():
    """Return sold medicines, add stock back, and keep reports auditable."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (session.get('user_id'),)).fetchone()
    user_checker = db.execute('SELECT * FROM users WHERE id = ?', (session.get('user_id'),)).fetchone()
    if session.get('user_id') == 'root_admin':
        profile_name = root_admin_username
    elif admin_checker and admin_checker[0] == session.get('user_id'):
        profile_name = admin_checker[1]
    elif user_checker and user_checker[0] == session.get('user_id'):
        profile_name = user_checker[1]
    else:
        profile_name = 'User'

    message = None
    success = None
    selected_sale = None
    selected_items = []
    sale_search_results = []
    invoice_query = request.args.get('invoice', '').strip()

    if request.method == 'POST':
        sale_id = request.form.get('sale_id', '').strip()
        reason = request.form.get('reason', '').strip()
        if not sale_id.isdigit():
            return redirect(url_for('medicine_return', message='Please select a valid invoice.'))

        sale_row = db.execute(
            '''
            SELECT id, invoice_no, customer_name, customer_phone
            FROM medicine_sales
            WHERE id = ?
            ''',
            (sale_id,)
        ).fetchone()
        if not sale_row:
            return redirect(url_for('medicine_return', message='Invoice not found.'))

        item_rows = db.execute(
            '''
            SELECT
                msi.id,
                msi.medicine_name,
                msi.batch_no,
                msi.unit_type,
                msi.quantity,
                msi.unit_price,
                msi.discount,
                msi.line_total,
                COALESCE((
                    SELECT SUM(mri.quantity)
                    FROM medicine_return_items mri
                    JOIN medicine_returns mr ON mr.id = mri.return_id
                    WHERE mri.sale_item_id = msi.id
                ), 0) AS returned_quantity
            FROM medicine_sale_items msi
            WHERE msi.sale_id = ?
            ORDER BY msi.id ASC
            ''',
            (sale_row[0],)
        ).fetchall()

        item_by_id = {str(row[0]): row for row in item_rows}
        return_items = []
        for sale_item_id in request.form.getlist('sale_item_id'):
            row = item_by_id.get(str(sale_item_id))
            if not row:
                continue
            try:
                return_qty = int(request.form.get(f'return_qty_{sale_item_id}', 0) or 0)
            except (TypeError, ValueError):
                return_qty = 0
            remaining_qty = max(int(row[4] or 0) - int(row[8] or 0), 0)
            if return_qty <= 0:
                continue
            if return_qty > remaining_qty:
                return redirect(url_for(
                    'medicine_return',
                    invoice=sale_row[1],
                    message=f'Only {remaining_qty} {row[3]}(s) can be returned for {row[1]}.'
                ))

            original_qty = max(int(row[4] or 0), 1)
            discount_per_unit = float(row[6] or 0) / original_qty
            line_total_per_unit = float(row[7] or 0) / original_qty
            return_items.append({
                'sale_item_id': row[0],
                'medicine_name': row[1],
                'batch_no': row[2] or 'General',
                'unit_type': row[3] or 'strip',
                'quantity': return_qty,
                'unit_price': float(row[5] or 0),
                'discount': round(discount_per_unit * return_qty, 2),
                'line_total': round(line_total_per_unit * return_qty, 2),
            })

        if not return_items:
            return redirect(url_for('medicine_return', invoice=sale_row[1], message='Enter at least one return quantity.'))

        return_date = datetime.now().strftime('%Y-%m-%d')
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return_count = db.execute(
            "SELECT COUNT(*) FROM medicine_returns WHERE date(return_date) = ?",
            (return_date,)
        ).fetchone()[0]
        return_no = f"MR-{datetime.now().strftime('%y%m%d')}-{return_count + 1:03d}"
        subtotal = sum(item['quantity'] * item['unit_price'] for item in return_items)
        discount_amount = sum(item['discount'] for item in return_items)
        refund_amount = sum(item['line_total'] for item in return_items)

        try:
            cursor = db.execute(
                '''
                INSERT INTO medicine_returns (
                    return_no, sale_id, invoice_no, customer_name, customer_phone,
                    reason, subtotal, discount_amount, refund_amount, return_date,
                    created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    return_no, sale_row[0], sale_row[1], sale_row[2], sale_row[3],
                    reason, subtotal, discount_amount, refund_amount, return_date,
                    str(session.get('user_id')), created_at
                )
            )
            return_id = cursor.lastrowid
            for item in return_items:
                db.execute(
                    '''
                    INSERT INTO medicine_return_items (
                        return_id, sale_item_id, medicine_name, batch_no, unit_type,
                        quantity, unit_price, discount, line_total
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        return_id, item['sale_item_id'], item['medicine_name'], item['batch_no'],
                        item['unit_type'], item['quantity'], item['unit_price'],
                        item['discount'], item['line_total']
                    )
                )
                db.execute(
                    '''
                    INSERT INTO medicine_transactions (
                        medicine_name, batch_no, unit_type, transaction_type, quantity, price,
                        transaction_date, note, created_by, created_at
                    ) VALUES (?, ?, ?, 'in', ?, ?, ?, ?, ?, ?)
                    ''',
                    (
                        item['medicine_name'], item['batch_no'], item['unit_type'],
                        item['quantity'], item['unit_price'], return_date,
                        f'Returned on {return_no} from invoice {sale_row[1]}',
                        str(session.get('user_id')), created_at
                    )
                )
            db.commit()
            add_system_log(f'Medicine return {return_no} saved for invoice {sale_row[1]}')
            return redirect(url_for('medicine_return', invoice=sale_row[1], success=f'{return_no} saved. Stock and reports updated.'))
        except sqlite3.Error:
            db.rollback()
            return redirect(url_for('medicine_return', invoice=sale_row[1], message='Could not save medicine return. Please try again.'))

    if invoice_query:
        selected_sale = db.execute(
            '''
            SELECT id, invoice_no, customer_name, customer_phone, customer_address,
                   grand_total, sale_date, created_at
            FROM medicine_sales
            WHERE invoice_no = ? OR CAST(id AS TEXT) = ?
            ORDER BY id DESC
            LIMIT 1
            ''',
            (invoice_query, invoice_query)
        ).fetchone()
        if not selected_sale:
            search_term = f'%{invoice_query}%'
            sale_search_results = db.execute(
                '''
                SELECT id, invoice_no, customer_name, customer_phone, customer_address,
                       grand_total, sale_date, created_at
                FROM medicine_sales
                WHERE customer_name LIKE ? OR customer_phone LIKE ?
                ORDER BY datetime(created_at) DESC, id DESC
                LIMIT 12
                ''',
                (search_term, search_term)
            ).fetchall()
            if len(sale_search_results) == 1:
                selected_sale = sale_search_results[0]
        if selected_sale:
            item_rows = db.execute(
                '''
                SELECT
                    msi.id,
                    msi.medicine_name,
                    msi.batch_no,
                    msi.unit_type,
                    msi.quantity,
                    msi.unit_price,
                    msi.discount,
                    msi.line_total,
                    COALESCE((
                        SELECT SUM(mri.quantity)
                        FROM medicine_return_items mri
                        JOIN medicine_returns mr ON mr.id = mri.return_id
                        WHERE mri.sale_item_id = msi.id
                    ), 0) AS returned_quantity
                FROM medicine_sale_items msi
                WHERE msi.sale_id = ?
                ORDER BY msi.id ASC
                ''',
                (selected_sale[0],)
            ).fetchall()
            for row in item_rows:
                sold_qty = int(row[4] or 0)
                returned_qty = int(row[8] or 0)
                remaining_qty = max(sold_qty - returned_qty, 0)
                unit_refund = float(row[7] or 0) / max(sold_qty, 1)
                selected_items.append({
                    'id': row[0],
                    'medicine_name': row[1],
                    'batch_no': row[2],
                    'unit_type': row[3],
                    'sold_quantity': sold_qty,
                    'returned_quantity': returned_qty,
                    'remaining_quantity': remaining_qty,
                    'unit_price': float(row[5] or 0),
                    'discount': float(row[6] or 0),
                    'line_total': float(row[7] or 0),
                    'unit_refund': unit_refund,
                })
        else:
            if sale_search_results:
                message = 'Select a matching invoice to continue the return.'
            else:
                message = 'No medicine sale invoice, customer name, or phone number found.'

    recent_returns = db.execute(
        '''
        SELECT return_no, invoice_no, customer_name, refund_amount, return_date, created_at
        FROM medicine_returns
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT 12
        '''
    ).fetchall()

    return render_template(
        'medicine_return.html',
        profile_name=profile_name,
        invoice_query=invoice_query,
        selected_sale=selected_sale,
        selected_items=selected_items,
        sale_search_results=sale_search_results,
        recent_returns=recent_returns,
        message=message or request.args.get('message'),
        success=success or request.args.get('success'),
        admin=isadmin(),
    )


def build_medicine_sales_list_report(selected_date):
    """Return daily sales, return, and medicine summary data for list and print views."""
    sales_rows = db.execute(
        '''
        SELECT id, invoice_no, customer_name, customer_phone, customer_address, subtotal, discount_amount,
               tax_amount, delivery_cost, grand_total, received_amount, due_amount,
               change_amount, payment_type, sale_date, created_at
        FROM medicine_sales
        WHERE date(sale_date) = ?
        ORDER BY created_at DESC, id DESC
        ''',
        (selected_date,)
    ).fetchall()

    sales = []
    medicine_summary_map = {}
    total_medicine_quantity = 0
    total_line_items = 0

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
        sale_items = []
        for item in item_rows:
            quantity = int(item[3] or 0)
            unit_price = float(item[4] or 0)
            discount = float(item[5] or 0)
            line_total = float(item[6] or 0)
            sale_item = {
                'medicine_name': item[0],
                'batch_no': item[1],
                'unit_type': item[2],
                'quantity': quantity,
                'unit_price': unit_price,
                'discount': discount,
                'line_total': line_total,
            }
            sale_items.append(sale_item)
            total_medicine_quantity += quantity
            total_line_items += 1

            summary_key = (
                sale_item['medicine_name'] or 'Unknown Medicine',
                sale_item['batch_no'] or '-',
                sale_item['unit_type'] or '-',
            )
            if summary_key not in medicine_summary_map:
                medicine_summary_map[summary_key] = {
                    'medicine_name': summary_key[0],
                    'batch_no': summary_key[1],
                    'unit_type': summary_key[2],
                    'quantity': 0,
                    'gross_amount': 0.0,
                    'discount_amount': 0.0,
                    'net_amount': 0.0,
                    'invoice_count': set(),
                }
            medicine_summary_map[summary_key]['quantity'] += quantity
            medicine_summary_map[summary_key]['gross_amount'] += quantity * unit_price
            medicine_summary_map[summary_key]['discount_amount'] += discount
            medicine_summary_map[summary_key]['net_amount'] += line_total
            medicine_summary_map[summary_key]['invoice_count'].add(row[1])

        sales.append({
            'id': row[0],
            'invoice_no': row[1],
            'customer_name': row[2],
            'customer_phone': row[3],
            'customer_address': row[4],
            'subtotal': float(row[5] or 0),
            'discount_amount': float(row[6] or 0),
            'tax_amount': float(row[7] or 0),
            'delivery_cost': float(row[8] or 0),
            'grand_total': float(row[9] or 0),
            'received_amount': float(row[10] or 0),
            'due_amount': float(row[11] or 0),
            'change_amount': float(row[12] or 0),
            'payment_type': row[13],
            'sale_date': row[14],
            'created_at': row[15],
            'items': sale_items,
        })

    return_rows = db.execute(
        '''
        SELECT return_no, invoice_no, customer_name, customer_phone, subtotal,
               discount_amount, refund_amount, reason, return_date, created_at
        FROM medicine_returns
        WHERE date(return_date) = ?
        ORDER BY created_at DESC, id DESC
        ''',
        (selected_date,)
    ).fetchall()
    returns = [
        {
            'return_no': row[0],
            'invoice_no': row[1],
            'customer_name': row[2],
            'customer_phone': row[3],
            'subtotal': float(row[4] or 0),
            'discount_amount': float(row[5] or 0),
            'refund_amount': float(row[6] or 0),
            'reason': row[7],
            'return_date': row[8],
            'created_at': row[9],
        }
        for row in return_rows
    ]
    total_returns = sum(item['refund_amount'] for item in returns)
    medicine_summary = []
    for item in medicine_summary_map.values():
        item['invoice_count'] = len(item['invoice_count'])
        medicine_summary.append(item)
    medicine_summary.sort(key=lambda item: item['medicine_name'].lower())

    return {
        'sales': sales,
        'returns': returns,
        'medicine_summary': medicine_summary,
        'total_sales': sum(sale['grand_total'] for sale in sales) - total_returns,
        'gross_sales': sum(sale['subtotal'] for sale in sales),
        'total_discount': sum(sale['discount_amount'] for sale in sales),
        'total_returns': total_returns,
        'total_due': sum(sale['due_amount'] for sale in sales),
        'sales_count': len(sales),
        'return_count': len(returns),
        'total_line_items': total_line_items,
        'total_medicine_quantity': total_medicine_quantity,
    }


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
    report_data = build_medicine_sales_list_report(selected_date)

    return render_template(
        "medicine_sales_list.html",
        profile_name=profile_name,
        selected_date=selected_date,
        admin=isadmin(),
        **report_data,
    )


@app.route('/medicine_sales_list/print')
def medicine_sales_list_print():
    """Printable daily medicine sales list."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    selected_date = request.args.get('date', '').strip() or datetime.now().strftime('%Y-%m-%d')
    _, _, profile_name = get_current_actor()
    report_data = build_medicine_sales_list_report(selected_date)

    return render_template(
        "medicine_sales_list_print.html",
        profile_name=profile_name,
        selected_date=selected_date,
        return_url=url_for('medicine_sales_list', date=selected_date),
        **report_data,
    )


@app.route('/medicine_monthly_report') 
def medicine_monthly_report():
    """Monthly medicine sales report for admins and permitted users."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))
    if isuser() and not user_has_any_page(ENDPOINT_PERMISSIONS['medicine_monthly_report']):
        return redirect(url_for('login'))

    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (session.get('user_id'),)).fetchone()
    user_checker = db.execute('SELECT * FROM users WHERE id = ?', (session.get('user_id'),)).fetchone()
    if session.get('user_id') == 'root_admin':
        profile_name = root_admin_username
    elif admin_checker and admin_checker[0] == session.get('user_id'):
        profile_name = admin_checker[1]
    elif user_checker and user_checker[0] == session.get('user_id'):
        profile_name = user_checker[1]
    else:
        profile_name = 'User'

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

    return_summary_row = db.execute(
        '''
        SELECT
            COUNT(*) AS return_count,
            COALESCE(SUM(subtotal), 0) AS returned_subtotal,
            COALESCE(SUM(discount_amount), 0) AS returned_discount,
            COALESCE(SUM(refund_amount), 0) AS refund_amount
        FROM medicine_returns
        WHERE date(return_date) >= ? AND date(return_date) < ?
        ''',
        (month_start_text, next_month_text)
    ).fetchone()

    item_summary_row = db.execute(
        '''
        SELECT
            COALESCE(SUM(quantity), 0) AS total_units,
            COUNT(DISTINCT medicine_name || '|' || batch_no || '|' || unit_type) AS product_count
        FROM (
            SELECT msi.medicine_name, msi.batch_no, msi.unit_type, msi.quantity
            FROM medicine_sale_items msi
            JOIN medicine_sales ms ON ms.id = msi.sale_id
            WHERE date(ms.sale_date) >= ? AND date(ms.sale_date) < ?
            UNION ALL
            SELECT mri.medicine_name, mri.batch_no, mri.unit_type, -mri.quantity
            FROM medicine_return_items mri
            JOIN medicine_returns mr ON mr.id = mri.return_id
            WHERE date(mr.return_date) >= ? AND date(mr.return_date) < ?
        )
        ''',
        (month_start_text, next_month_text, month_start_text, next_month_text)
    ).fetchone()

    product_rows_raw = db.execute(
        '''
        WITH product_activity AS (
            SELECT
                msi.medicine_name,
                msi.batch_no,
                msi.unit_type,
                ms.id AS document_id,
                msi.quantity AS quantity,
                msi.unit_price AS unit_price,
                msi.quantity * msi.unit_price AS gross_amount,
                msi.discount AS discount_amount,
                msi.line_total AS net_amount
            FROM medicine_sale_items msi
            JOIN medicine_sales ms ON ms.id = msi.sale_id
            WHERE date(ms.sale_date) >= ? AND date(ms.sale_date) < ?
            UNION ALL
            SELECT
                mri.medicine_name,
                mri.batch_no,
                mri.unit_type,
                -mr.id AS document_id,
                -mri.quantity AS quantity,
                mri.unit_price AS unit_price,
                -(mri.quantity * mri.unit_price) AS gross_amount,
                -mri.discount AS discount_amount,
                -mri.line_total AS net_amount
            FROM medicine_return_items mri
            JOIN medicine_returns mr ON mr.id = mri.return_id
            WHERE date(mr.return_date) >= ? AND date(mr.return_date) < ?
        )
        SELECT
            medicine_name,
            batch_no,
            unit_type,
            COUNT(DISTINCT document_id) AS invoice_count,
            SUM(quantity) AS quantity,
            AVG(unit_price) AS avg_price,
            SUM(gross_amount) AS gross_amount,
            SUM(discount_amount) AS discount_amount,
            SUM(net_amount) AS net_amount
        FROM product_activity
        GROUP BY medicine_name, batch_no, unit_type
        HAVING quantity != 0 OR net_amount != 0
        ORDER BY net_amount DESC, quantity DESC, medicine_name ASC
        ''',
        (month_start_text, next_month_text, month_start_text, next_month_text)
    ).fetchall()

    daily_rows_raw = db.execute(
        '''
        WITH daily_activity AS (
            SELECT
                date(sale_date) AS sale_day,
                1 AS invoice_count,
                grand_total AS net_sales,
                received_amount AS received_amount,
                due_amount AS due_amount
            FROM medicine_sales
            WHERE date(sale_date) >= ? AND date(sale_date) < ?
            UNION ALL
            SELECT
                date(return_date) AS sale_day,
                0 AS invoice_count,
                -refund_amount AS net_sales,
                -refund_amount AS received_amount,
                0 AS due_amount
            FROM medicine_returns
            WHERE date(return_date) >= ? AND date(return_date) < ?
        )
        SELECT
            sale_day,
            COALESCE(SUM(invoice_count), 0) AS invoice_count,
            COALESCE(SUM(net_sales), 0) AS net_sales,
            COALESCE(SUM(received_amount), 0) AS received_amount,
            COALESCE(SUM(due_amount), 0) AS due_amount
        FROM daily_activity
        GROUP BY sale_day
        ORDER BY sale_day ASC
        ''',
        (month_start_text, next_month_text, month_start_text, next_month_text)
    ).fetchall()

    date_product_rows_raw = db.execute(
        '''
        WITH date_product_activity AS (
            SELECT
                date(ms.sale_date) AS sale_day,
                msi.medicine_name,
                msi.batch_no,
                msi.unit_type,
                ms.id AS document_id,
                msi.quantity AS quantity,
                msi.quantity * msi.unit_price AS gross_amount,
                msi.discount AS discount_amount,
                msi.line_total AS net_amount
            FROM medicine_sale_items msi
            JOIN medicine_sales ms ON ms.id = msi.sale_id
            WHERE date(ms.sale_date) >= ? AND date(ms.sale_date) < ?
            UNION ALL
            SELECT
                date(mr.return_date) AS sale_day,
                mri.medicine_name,
                mri.batch_no,
                mri.unit_type,
                -mr.id AS document_id,
                -mri.quantity AS quantity,
                -(mri.quantity * mri.unit_price) AS gross_amount,
                -mri.discount AS discount_amount,
                -mri.line_total AS net_amount
            FROM medicine_return_items mri
            JOIN medicine_returns mr ON mr.id = mri.return_id
            WHERE date(mr.return_date) >= ? AND date(mr.return_date) < ?
        )
        SELECT
            sale_day,
            medicine_name,
            batch_no,
            unit_type,
            COUNT(DISTINCT document_id) AS invoice_count,
            SUM(quantity) AS quantity,
            SUM(gross_amount) AS gross_amount,
            SUM(discount_amount) AS discount_amount,
            SUM(net_amount) AS net_amount
        FROM date_product_activity
        GROUP BY sale_day, medicine_name, batch_no, unit_type
        HAVING quantity != 0 OR net_amount != 0
        ORDER BY sale_day ASC, medicine_name ASC, batch_no ASC, unit_type ASC
        ''',
        (month_start_text, next_month_text, month_start_text, next_month_text)
    ).fetchall()

    report_summary = {
        'invoice_count': int(summary_row[0] or 0),
        'return_count': int(return_summary_row[0] or 0),
        'return_amount': float(return_summary_row[3] or 0),
        'gross_sales': float(summary_row[1] or 0) - float(return_summary_row[1] or 0),
        'discount_amount': float(summary_row[2] or 0) - float(return_summary_row[2] or 0),
        'tax_amount': float(summary_row[3] or 0),
        'delivery_cost': float(summary_row[4] or 0),
        'net_sales': float(summary_row[5] or 0) - float(return_summary_row[3] or 0),
        'received_amount': float(summary_row[6] or 0) - float(return_summary_row[3] or 0),
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

    date_product_rows = [
        {
            'sale_day': row[0],
            'medicine_name': row[1],
            'batch_no': row[2],
            'unit_type': row[3],
            'invoice_count': int(row[4] or 0),
            'quantity': int(row[5] or 0),
            'gross_amount': float(row[6] or 0),
            'discount_amount': float(row[7] or 0),
            'net_amount': float(row[8] or 0),
        }
        for row in date_product_rows_raw
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
        date_product_rows=date_product_rows,
        admin=isadmin(),
    )


def delete_medicine_sale_records(sale_ids):
    """Delete medicine sale invoices, returns, and matching stock rows as one operation."""
    cleaned_sale_ids = [int(sale_id) for sale_id in sale_ids if sale_id]
    if not cleaned_sale_ids:
        return 0

    placeholders = ','.join('?' for _ in cleaned_sale_ids)
    sale_rows = db.execute(
        f'SELECT id, invoice_no FROM medicine_sales WHERE id IN ({placeholders})',
        cleaned_sale_ids
    ).fetchall()
    if not sale_rows:
        return 0

    return_rows = db.execute(
        f'SELECT id, return_no FROM medicine_returns WHERE sale_id IN ({placeholders})',
        cleaned_sale_ids
    ).fetchall()
    if return_rows:
        return_ids = [row[0] for row in return_rows]
        return_placeholders = ','.join('?' for _ in return_ids)
        return_notes = [f'Returned on {row[1]}' for row in return_rows]
        note_clauses = ' OR '.join('note LIKE ?' for _ in return_notes)
        db.execute(
            f"DELETE FROM medicine_transactions WHERE transaction_type = 'in' AND ({note_clauses})",
            [f'{note}%' for note in return_notes]
        )
        db.execute(
            f'DELETE FROM medicine_return_items WHERE return_id IN ({return_placeholders})',
            return_ids
        )
        db.execute(
            f'DELETE FROM medicine_returns WHERE id IN ({return_placeholders})',
            return_ids
        )

    invoice_notes = [f'Sold on invoice {row[1]}' for row in sale_rows]
    note_placeholders = ','.join('?' for _ in invoice_notes)
    db.execute(
        f"DELETE FROM medicine_transactions WHERE transaction_type = 'out' AND note IN ({note_placeholders})",
        invoice_notes
    )
    db.execute(
        f'DELETE FROM medicine_sale_items WHERE sale_id IN ({placeholders})',
        cleaned_sale_ids
    )
    db.execute(
        f'DELETE FROM medicine_sales WHERE id IN ({placeholders})',
        cleaned_sale_ids
    )
    return len(sale_rows)


@app.route('/medicine_monthly_report/delete_day', methods=['POST'])
@app.route('/medicine_monthly_report/delete_day/', methods=['POST'])
def delete_medicine_monthly_day_sales():
    """Delete all medicine sale invoices for one report date."""
    if not isadmin():
        return redirect(url_for('medicine_monthly_report'))

    sale_day = request.form.get('sale_day', '').strip()
    selected_month = request.form.get('month', '').strip() or datetime.now().strftime('%Y-%m')
    try:
        datetime.strptime(sale_day, '%Y-%m-%d')
    except ValueError:
        return redirect(url_for('medicine_monthly_report', month=selected_month))

    sale_rows = db.execute(
        'SELECT id FROM medicine_sales WHERE date(sale_date) = ?',
        (sale_day,)
    ).fetchall()

    try:
        delete_medicine_sale_records([row[0] for row in sale_rows])
        db.commit()
    except sqlite3.Error:
        db.rollback()

    return redirect(url_for('medicine_monthly_report', month=selected_month))


@app.route('/medicine_monthly_report/delete_product', methods=['POST'])
@app.route('/medicine_monthly_report/delete_product/', methods=['POST'])
def delete_medicine_monthly_product_sales():
    """Delete all invoices in the selected month that contain a product batch/unit."""
    if not isadmin():
        return redirect(url_for('medicine_monthly_report'))

    selected_month = request.form.get('month', '').strip() or datetime.now().strftime('%Y-%m')
    medicine_name = request.form.get('medicine_name', '').strip()
    batch_no = request.form.get('batch_no', '').strip() or 'General'
    unit_type = request.form.get('unit_type', '').strip().lower()
    try:
        month_start = datetime.strptime(selected_month, '%Y-%m')
    except ValueError:
        month_start = datetime.now().replace(day=1)
        selected_month = month_start.strftime('%Y-%m')

    if not medicine_name or unit_type not in ('strip', 'box'):
        return redirect(url_for('medicine_monthly_report', month=selected_month))

    next_month = (month_start.replace(day=28) + timedelta(days=4)).replace(day=1)
    sale_rows = db.execute(
        '''
        SELECT DISTINCT ms.id
        FROM medicine_sales ms
        JOIN medicine_sale_items msi ON msi.sale_id = ms.id
        WHERE date(ms.sale_date) >= ?
          AND date(ms.sale_date) < ?
          AND msi.medicine_name = ?
          AND COALESCE(NULLIF(msi.batch_no, ''), 'General') = ?
          AND msi.unit_type = ?
        ''',
        (
            month_start.strftime('%Y-%m-%d'),
            next_month.strftime('%Y-%m-%d'),
            medicine_name,
            batch_no,
            unit_type,
        )
    ).fetchall()

    try:
        delete_medicine_sale_records([row[0] for row in sale_rows])
        db.commit()
    except sqlite3.Error:
        db.rollback()

    return redirect(url_for('medicine_monthly_report', month=selected_month))


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

    sale_date = selected_date or sale_row[1] or datetime.now().strftime('%Y-%m-%d')

    try:
        delete_medicine_sale_records([sale_id])
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
            existing_patient_id = request.form.get('existing_patient_id', '').strip()
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

            source_patient_id = None
            if existing_patient_id:
                if not existing_patient_id.isdigit():
                    if is_ajax:
                        return {"success": False, "error": "Selected old patient is invalid."}, 400
                    return patient_redirect(error="Selected old patient is invalid.")
                existing_patient = db.execute(
                    '''
                    SELECT id
                    FROM patients
                    WHERE id = ?
                      AND source_patient_id IS NULL
                    ''',
                    (existing_patient_id,)
                ).fetchone()
                if not existing_patient:
                    if is_ajax:
                        return {"success": False, "error": "Old patient was not found in All Patients List."}, 404
                    return patient_redirect(error="Old patient was not found in All Patients List.")
                source_patient_id = existing_patient[0]
                patient_status = patient_status or 'OLD'

            daily_ticket_no = db.execute('''
                SELECT COALESCE(MAX(daily_patient_id), 0) + 1
                FROM patients
                WHERE date(created_at) = date('now', '+6 hours')
            ''').fetchone()[0]

            cursor = db.execute('''INSERT INTO patients (
                                      daily_patient_id, serial_no, name, age, age_unit, gender, phone, email,
                                      dob, blood_group, address, emergency_contact_name, emergency_contact_phone,
                                      medical_history, patient_status, doctor_name, doctor_designation,
                                      referer_name, doctor_fee, source_patient_id, created_at
                                  ) 
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+6 hours'))''',
                                (
                                    daily_ticket_no, serial_no, name, age, age_unit, gender, phone, email,
                                    dob, blood_group, address, emergency_contact_name, emergency_contact_phone,
                                    medical_history, patient_status, doctor_name, doctor_designation,
                                    referer_name, doctor_fee_value, source_patient_id
                                ))
            db.commit()
            patient_id = cursor.lastrowid
            if source_patient_id:
                add_system_log(f"Old patient daily bill created: {name} ({phone}), ticket no {daily_ticket_no}", patient_id)
            else:
                add_system_log(f"Patient created: {name} ({phone}), ticket no {daily_ticket_no}", patient_id)

            if is_ajax:
                return {"success": True, "patient_id": patient_id, "ticket_no": daily_ticket_no, "print_url": url_for('ticket_print', patient_id=patient_id)}, 200

            if save_action == 'save_print':
                return redirect(url_for('ticket_print', patient_id=patient_id))

            return patient_redirect(success="Patient bill created successfully." if source_patient_id else "Patient added successfully.")
        return patient_redirect()
    else:
        return redirect(url_for('login'))

@app.route('/delete_patient/<int:patient_id>', methods=['POST'])
def delete_patient(patient_id):
    """Delete a patient - only admin can delete."""
    return_view = request.form.get('return_view', 'list').strip().lower()
    selected_date = request.form.get('selected_date', '').strip()
    redirect_args = {'view': 'all'} if return_view == 'all' else {'view': 'list'}
    if selected_date and return_view != 'all':
        redirect_args['date'] = selected_date

    if not isadmin():
        return redirect(url_for('patients_registration', **redirect_args, error="Only admin can delete patients."))

    patient = db.execute('SELECT id, name, phone FROM patients WHERE id = ?', (patient_id,)).fetchone()
    if not patient:
        return redirect(url_for('patients_registration', **redirect_args, error="Patient not found."))

    try:
        db.execute('DELETE FROM patients WHERE id = ?', (patient_id,))
        db.commit()
        add_system_log(f"Patient deleted: {patient[1]} ({patient[2]})", patient_id)
        return redirect(url_for('patients_registration', **redirect_args, success="Patient deleted successfully."))
    except sqlite3.IntegrityError:
        return redirect(url_for('patients_registration', **redirect_args, error="Cannot delete patient because they have associated records."))


@app.route('/visit_return', methods=['GET', 'POST'])
def visit_return():
    """Return a doctor visit ticket. Admins and permitted users can use this page."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    query = request.args.get('q', '').strip()
    selected_patient_id = request.args.get('patient_id', '').strip()
    message = request.args.get('message', '').strip()
    success = request.args.get('success', '').strip()

    if request.method == 'POST':
        patient_id = request.form.get('patient_id', '').strip()
        reason = request.form.get('reason', '').strip()
        try:
            patient_id_value = int(patient_id)
            refund_amount = max(float(request.form.get('refund_amount') or 0), 0)
        except (TypeError, ValueError):
            return redirect(url_for('visit_return', message='Please select a valid visit and refund amount.'))

        patient_row = db.execute(
            '''
            SELECT id, COALESCE(source_patient_id, id) AS patient_uhid, daily_patient_id,
                   name, phone, doctor_name, doctor_fee
            FROM patients
            WHERE id = ?
            ''',
            (patient_id_value,)
        ).fetchone()
        if not patient_row:
            return redirect(url_for('visit_return', message='Visit ticket not found.'))

        existing_return = db.execute(
            'SELECT return_no FROM patient_visit_returns WHERE patient_id = ?',
            (patient_id_value,)
        ).fetchone()
        if existing_return:
            return redirect(url_for(
                'visit_return',
                patient_id=patient_id_value,
                message=f'This visit is already returned on {existing_return[0]}.'
            ))

        return_date = datetime.now().strftime('%Y-%m-%d')
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return_count = db.execute(
            "SELECT COUNT(*) FROM patient_visit_returns WHERE date(return_date) = ?",
            (return_date,)
        ).fetchone()[0]
        return_no = f"VR-{datetime.now().strftime('%y%m%d')}-{return_count + 1:03d}"

        try:
            db.execute(
                '''
                INSERT INTO patient_visit_returns (
                    return_no, patient_id, patient_uhid, ticket_no, patient_name, phone,
                    doctor_name, doctor_fee, refund_amount, reason, return_date,
                    created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    return_no,
                    patient_row[0],
                    patient_row[1],
                    patient_row[2],
                    patient_row[3],
                    patient_row[4],
                    patient_row[5] or '',
                    float(patient_row[6] or 0),
                    refund_amount,
                    reason,
                    return_date,
                    str(session.get('user_id')),
                    created_at,
                )
            )
            db.execute(
                "UPDATE patients SET patient_status = 'Returned' WHERE id = ?",
                (patient_id_value,)
            )
            db.commit()
            add_system_log(f"Visit return {return_no} saved for {patient_row[3]} ticket {patient_row[2]}", patient_id_value)
            return redirect(url_for('visit_return', patient_id=patient_id_value, success=f'{return_no} saved successfully.'))
        except sqlite3.IntegrityError:
            db.rollback()
            return redirect(url_for('visit_return', patient_id=patient_id_value, message='This visit return is already saved.'))
        except sqlite3.Error:
            db.rollback()
            return redirect(url_for('visit_return', patient_id=patient_id_value, message='Could not save this visit return. Please try again.'))

    selected_visit = None
    if selected_patient_id.isdigit():
        selected_visit = db.execute(
            '''
            SELECT
                p.id,
                COALESCE(p.source_patient_id, p.id) AS patient_uhid,
                p.daily_patient_id,
                p.name,
                p.age,
                COALESCE(NULLIF(p.age_unit, ''), 'Y') AS age_unit,
                p.gender,
                p.phone,
                p.address,
                p.doctor_name,
                p.doctor_designation,
                p.referer_name,
                p.doctor_fee,
                p.patient_status,
                p.created_at,
                pvr.return_no,
                pvr.refund_amount,
                pvr.reason,
                pvr.created_at
            FROM patients p
            LEFT JOIN patient_visit_returns pvr ON pvr.patient_id = p.id
            WHERE p.id = ?
            ''',
            (int(selected_patient_id),)
        ).fetchone()
        if not selected_visit:
            message = message or 'Visit ticket not found.'
    elif query:
        selected_visit = db.execute(
            '''
            SELECT
                p.id,
                COALESCE(p.source_patient_id, p.id) AS patient_uhid,
                p.daily_patient_id,
                p.name,
                p.age,
                COALESCE(NULLIF(p.age_unit, ''), 'Y') AS age_unit,
                p.gender,
                p.phone,
                p.address,
                p.doctor_name,
                p.doctor_designation,
                p.referer_name,
                p.doctor_fee,
                p.patient_status,
                p.created_at,
                pvr.return_no,
                pvr.refund_amount,
                pvr.reason,
                pvr.created_at
            FROM patients p
            LEFT JOIN patient_visit_returns pvr ON pvr.patient_id = p.id
            WHERE CAST(p.id AS TEXT) = ?
               OR CAST(COALESCE(p.daily_patient_id, '') AS TEXT) = ?
               OR p.phone = ?
               OR p.name LIKE ?
            ORDER BY datetime(p.created_at) DESC, p.id DESC
            LIMIT 1
            ''',
            (query, query, query, f'%{query}%')
        ).fetchone()
        if not selected_visit:
            message = message or 'No visit ticket found.'

    recent_returns = db.execute(
        '''
        SELECT return_no, patient_uhid, ticket_no, patient_name, refund_amount, return_date, created_at
        FROM patient_visit_returns
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT 12
        '''
    ).fetchall()

    return render_template(
        'visit_return.html',
        query=query,
        selected_visit=selected_visit,
        recent_returns=recent_returns,
        message=message,
        success=success,
        admin=isadmin(),
    )

def get_admission_print_record(admission_id):
    """Return admission details used by the admission form and concern paper."""
    row = db.execute('''
        SELECT
            a.id,
            a.patient_id,
            a.doctor_id,
            COALESCE(p.source_patient_id, p.id),
            p.name,
            p.age,
            COALESCE(NULLIF(p.age_unit, ''), 'Y'),
            p.gender,
            p.phone,
            p.address,
            a.admission_date,
            a.ward,
            a.room_number,
            a.bed_number,
            a.guardian_name,
            a.guardian_relation,
            a.reason,
            a.notes,
            a.status,
            COALESCE(d.name, 'Not assigned')
        FROM admissions a
        JOIN patients p ON a.patient_id = p.id
        LEFT JOIN doctors d ON a.doctor_id = d.id
        WHERE a.id = ?
    ''', (admission_id,)).fetchone()

    if not row:
        return None

    return {
        'id': row[0],
        'patient_id': row[1],
        'doctor_id': row[2],
        'registration_no': row[3],
        'patient_name': row[4],
        'age': row[5],
        'age_unit': row[6],
        'gender': row[7],
        'phone': row[8],
        'address': row[9],
        'admission_date': row[10],
        'ward': row[11],
        'room_number': row[12],
        'bed_number': row[13],
        'guardian_name': row[14],
        'guardian_relation': row[15],
        'reason': row[16],
        'notes': row[17],
        'status': row[18],
        'doctor_name': row[19],
    }


def format_concern_paper_date(value):
    """Format an ISO date as 04.Jul.2026 for the concern paper."""
    if not value:
        return '-'

    text_value = str(value).strip()
    for date_format in ('%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S'):
        try:
            date_value = datetime.strptime(text_value, date_format)
            return date_value.strftime('%d.%b.%Y')
        except ValueError:
            continue

    return text_value


@app.route('/admissions', methods=['GET', 'POST'])
def admissions():
    """Admit patients and display admission records."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    if request.method == 'POST':
        patient_id = request.form.get('patient_id')
        doctor_id = request.form.get('doctor_id') or None
        admission_date = request.form.get('admission_date')
        room_number = (request.form.get('room_number') or '').strip()
        bed_number = (request.form.get('bed_number') or '').strip()
        guardian_name = (request.form.get('guardian_name') or '').strip()
        guardian_relation = (request.form.get('guardian_relation') or '').strip()
        reason = (request.form.get('reason') or '').strip()
        notes = request.form.get('notes')
        ward = 'Cabin' if room_number.lower().startswith('cabin') else 'Room'

        if not patient_id or not patient_id.isdigit():
            return redirect(url_for('admissions', message="Please select a valid patient."))

        patient = db.execute('SELECT id FROM patients WHERE id = ?', (patient_id,)).fetchone()
        if not patient:
            return redirect(url_for('admissions', message="Patient not found."))

        if not admission_date or not room_number or not guardian_name or not guardian_relation or not reason:
            return redirect(url_for('admissions', message="Please fill in all required admission fields."))

        if room_number not in BED_NUMBER_OPTIONS:
            return redirect(url_for('admissions', message="Please select a valid bed number."))

        occupied_bed = db.execute('''
            SELECT a.patient_id, p.name
            FROM admissions a
            JOIN patients p ON a.patient_id = p.id
            WHERE a.status = 'Admitted'
              AND a.room_number = ?
            LIMIT 1
        ''', (room_number,)).fetchone()
        if occupied_bed:
            return redirect(url_for(
                'admissions',
                message=f"Bed {room_number} is already assigned to {occupied_bed[1]}."
            ))

        if doctor_id and not doctor_id.isdigit():
            doctor_id = None

        if doctor_id:
            doctor = db.execute('SELECT id FROM doctors WHERE id = ?', (doctor_id,)).fetchone()
            if not doctor:
                doctor_id = None

        admission_cursor = db.execute('''
            INSERT INTO admissions (
                patient_id, doctor_id, admission_date, ward, room_number,
                bed_number, guardian_name, guardian_relation, reason, notes,
                status, created_by, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Admitted', ?, datetime('now', '+6 hours'))
        ''', (
            patient_id, doctor_id, admission_date, ward, room_number,
            bed_number, guardian_name, guardian_relation, reason, notes,
            session.get('user_id')
        ))
        admission_id = admission_cursor.lastrowid
        db.commit()
        session['last_admission_id'] = admission_id
        add_log(patient_id, "Patient admitted")
        return redirect(url_for(
            'admissions',
            admission_id=admission_id,
            date=datetime.now().strftime('%Y-%m-%d'),
            success="Patient admitted successfully."
        ))

    selected_date = request.args.get('date', '').strip() or datetime.now().strftime('%Y-%m-%d')
    active_admission = None
    active_admission_id = request.args.get('admission_id', '').strip() or str(session.get('last_admission_id') or '')
    if active_admission_id.isdigit():
        active_admission = get_admission_print_record(active_admission_id)
        if not active_admission and session.get('last_admission_id') == int(active_admission_id):
            session.pop('last_admission_id', None)

    patient_list = db.execute('''
        SELECT id, name, age, age_unit, gender, phone, address, COALESCE(source_patient_id, id) AS patient_uhid
        FROM patients
        ORDER BY id DESC
    ''').fetchall()
    doctor_list = db.execute('''
        SELECT id, name, specialization
        FROM doctors
        ORDER BY name ASC
    ''').fetchall()
    occupied_bed_rows = db.execute('''
        SELECT room_number, patient_id
        FROM admissions
        WHERE status = 'Admitted'
          AND room_number IS NOT NULL
          AND room_number != ''
    ''').fetchall()
    occupied_beds = {row[0]: row[1] for row in occupied_bed_rows}
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
            a.guardian_name,
            a.guardian_relation,
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
        active_admission=active_admission,
        bed_options=BED_NUMBER_OPTIONS,
        occupied_beds=occupied_beds,
        admin=isadmin(),
        selected_date=selected_date,
        message=request.args.get('message'),
        success=request.args.get('success')
    )

@app.route('/admissions/search-old')
def search_old_admitted_patient():
    """Find discharged patients who can be admitted again."""
    if not isadmin() and not isuser():
        return jsonify({'success': False, 'patients': []}), 401

    keyword = request.args.get('keyword', '').strip()
    if len(keyword) < 2:
        return jsonify({'success': True, 'patients': []})

    search_term = f'%{keyword}%'
    rows = db.execute('''
        SELECT
            a.id,
            p.id,
            COALESCE(p.source_patient_id, p.id) AS patient_uhid,
            p.name,
            p.phone,
            p.age,
            COALESCE(NULLIF(p.age_unit, ''), 'Y') AS age_unit,
            p.gender,
            a.room_number,
            a.guardian_name,
            a.guardian_relation,
            COALESCE(a.doctor_id, ''),
            COALESCE(d.name, 'Not assigned') AS doctor_name,
            a.reason,
            a.notes,
            a.admission_date,
            a.discharged_at
        FROM admissions a
        JOIN patients p ON a.patient_id = p.id
        LEFT JOIN doctors d ON a.doctor_id = d.id
        WHERE a.status = 'Discharged'
          AND a.id = (
              SELECT MAX(a2.id)
              FROM admissions a2
              WHERE a2.patient_id = a.patient_id
                AND a2.status = 'Discharged'
          )
          AND NOT EXISTS (
              SELECT 1
              FROM admissions active
              WHERE active.patient_id = a.patient_id
                AND active.status = 'Admitted'
          )
          AND (
              CAST(a.id AS TEXT) LIKE ?
              OR CAST(p.id AS TEXT) LIKE ?
              OR CAST(COALESCE(p.source_patient_id, p.id) AS TEXT) LIKE ?
              OR p.name LIKE ?
              OR p.phone LIKE ?
              OR a.room_number LIKE ?
          )
        ORDER BY
            CASE WHEN p.phone = ? THEN 0 ELSE 1 END,
            datetime(COALESCE(a.discharged_at, a.created_at)) DESC,
            a.id DESC
        LIMIT 12
    ''', (
        search_term, search_term, search_term, search_term, search_term, search_term, keyword
    )).fetchall()

    patients = [
        {
            'admission_id': row[0],
            'patient_id': row[1],
            'patient_uhid': row[2],
            'name': row[3],
            'phone': row[4] or '',
            'age': row[5],
            'age_unit': row[6],
            'gender': row[7] or '',
            'room_number': row[8] or '',
            'guardian_name': row[9] or '',
            'guardian_relation': row[10] or '',
            'doctor_id': row[11] or '',
            'doctor_name': row[12] or 'Not assigned',
            'reason': row[13] or '',
            'notes': row[14] or '',
            'admission_date': format_date_display(row[15]),
            'discharged_at': format_date_display(row[16]),
        }
        for row in rows
    ]
    return jsonify({'success': True, 'patients': patients})

@app.route('/concern-paper/<int:admission_id>')
def concern_paper(admission_id):
    """Print the consent/concern paper for an admitted patient."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    record = get_admission_print_record(admission_id)
    if not record:
        return redirect(url_for('admissions', message="Admission record not found."))

    return render_template(
        'concern_paper.html',
        record=record,
        print_date=format_concern_paper_date(record['admission_date'])
    )

@app.route('/discharge-bill')
def discharge_bill():
    """Create a professional discharge bill from active admission records."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    selected_admission_id = request.args.get('admission_id', '').strip()
    active_admissions = db.execute('''
        SELECT
            a.id,
            p.name,
            p.phone,
            p.age,
            COALESCE(NULLIF(p.age_unit, ''), 'Y'),
            p.gender,
            p.address,
            a.admission_date,
            a.room_number,
            a.guardian_name,
            a.guardian_relation,
            COALESCE(d.name, 'Not assigned'),
            a.reason,
            a.status,
            COALESCE(p.source_patient_id, p.id)
        FROM admissions a
        JOIN patients p ON a.patient_id = p.id
        LEFT JOIN doctors d ON a.doctor_id = d.id
        WHERE a.status = 'Admitted'
        ORDER BY a.id DESC
    ''').fetchall()

    selected_admission = None
    if selected_admission_id.isdigit():
        selected_admission = db.execute('''
            SELECT
                a.id,
                p.id,
                COALESCE(p.source_patient_id, p.id),
                p.name,
                p.phone,
                p.age,
                COALESCE(NULLIF(p.age_unit, ''), 'Y'),
                p.gender,
                p.address,
                a.admission_date,
                a.room_number,
                a.guardian_name,
                a.guardian_relation,
                COALESCE(d.name, 'Not assigned'),
                a.reason,
                a.notes,
                a.created_at
            FROM admissions a
            JOIN patients p ON a.patient_id = p.id
            LEFT JOIN doctors d ON a.doctor_id = d.id
            WHERE a.id = ?
              AND a.status = 'Admitted'
        ''', (selected_admission_id,)).fetchone()

    if not selected_admission and active_admissions:
        first_admission_id = active_admissions[0][0]
        return redirect(url_for('discharge_bill', admission_id=first_admission_id))

    return render_template(
        'discharge_bill.html',
        admissions=active_admissions,
        selected_admission=selected_admission,
        today_date=datetime.now().strftime('%Y-%m-%d'),
        printed_by=get_current_actor()[2]
    )

@app.route('/discharge-bill-print/<int:admission_id>')
def discharge_bill_print(admission_id):
    """A5 printable discharge bill matching the pathology test bill style."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    admission = db.execute('''
        SELECT
            a.id,
            p.id,
            COALESCE(p.source_patient_id, p.id),
            p.name,
            p.phone,
            p.age,
            COALESCE(NULLIF(p.age_unit, ''), 'Y'),
            p.gender,
            p.address,
            a.admission_date,
            a.room_number,
            a.guardian_name,
            a.guardian_relation,
            COALESCE(d.name, 'Not assigned'),
            a.reason,
            a.notes,
            a.created_at
        FROM admissions a
        JOIN patients p ON a.patient_id = p.id
        LEFT JOIN doctors d ON a.doctor_id = d.id
        WHERE a.id = ?
    ''', (admission_id,)).fetchone()
    if not admission:
        return redirect(url_for('discharge_bill', message='Admission record not found.'))

    def query_float(name):
        try:
            return max(0, float(request.args.get(name, 0) or 0))
        except (TypeError, ValueError):
            return 0

    discharge_date = request.args.get('discharge_date', '').strip() or datetime.now().strftime('%Y-%m-%d')
    try:
        stay_days = max(1, int(float(request.args.get('stay_days', 1) or 1)))
    except (TypeError, ValueError):
        stay_days = 1

    bed_rate = query_float('bed_charge')
    items = [
        {'name': 'Bed Charge', 'qty': stay_days, 'rate': bed_rate, 'amount': bed_rate * stay_days},
        {'name': 'Doctor Fee', 'qty': 1, 'rate': query_float('doctor_fee'), 'amount': query_float('doctor_fee')},
        {'name': 'Medicine Charge', 'qty': 1, 'rate': query_float('medicine_charge'), 'amount': query_float('medicine_charge')},
        {'name': 'Pathology Charge', 'qty': 1, 'rate': query_float('pathology_charge'), 'amount': query_float('pathology_charge')},
        {'name': 'Service Charge', 'qty': 1, 'rate': query_float('service_charge'), 'amount': query_float('service_charge')},
        {'name': 'Other Charge', 'qty': 1, 'rate': query_float('other_charge'), 'amount': query_float('other_charge')},
    ]

    total_amount = sum(item['amount'] for item in items)
    discount = min(query_float('discount'), total_amount)
    gross_amount = max(0, total_amount - discount)
    paid_amount = min(query_float('paid'), gross_amount)
    due_amount = max(0, gross_amount - paid_amount)
    change_amount = max(0, query_float('paid') - gross_amount)
    printed_by = get_current_actor()[2]
    remarks = request.args.get('remarks', '').strip()
    bill_no = f'DB-{admission[0]}'

    existing_bill = db.execute(
        'SELECT id FROM discharge_bills WHERE admission_id = ?',
        (admission[0],)
    ).fetchone()
    bill_values = (
        admission[0], admission[1], admission[2], bill_no, admission[9], discharge_date,
        stay_days, bed_rate, items[1]['amount'], items[2]['amount'], items[3]['amount'],
        items[4]['amount'], items[5]['amount'], total_amount, discount, gross_amount,
        paid_amount, due_amount, change_amount, remarks, printed_by
    )
    if existing_bill:
        db.execute('''
            UPDATE discharge_bills
            SET
                patient_id = ?,
                patient_uhid = ?,
                bill_no = ?,
                admission_date = ?,
                discharge_date = ?,
                stay_days = ?,
                bed_charge = ?,
                doctor_fee = ?,
                medicine_charge = ?,
                pathology_charge = ?,
                service_charge = ?,
                other_charge = ?,
                total_amount = ?,
                discount = ?,
                gross_amount = ?,
                paid_amount = ?,
                due_amount = ?,
                change_amount = ?,
                remarks = ?,
                prepared_by = ?,
                updated_at = datetime('now', '+6 hours')
            WHERE admission_id = ?
        ''', bill_values[1:] + (admission[0],))
    else:
        db.execute('''
            INSERT INTO discharge_bills (
                admission_id, patient_id, patient_uhid, bill_no, admission_date,
                discharge_date, stay_days, bed_charge, doctor_fee, medicine_charge,
                pathology_charge, service_charge, other_charge, total_amount, discount,
                gross_amount, paid_amount, due_amount, change_amount, remarks, prepared_by,
                created_at, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    datetime('now', '+6 hours'), datetime('now', '+6 hours'))
        ''', bill_values)

    discharge_cursor = db.execute('''
        UPDATE admissions
        SET status = 'Discharged',
            discharged_at = COALESCE(NULLIF(discharged_at, ''), datetime('now', '+6 hours'))
        WHERE id = ?
          AND status != 'Discharged'
    ''', (admission[0],))
    db.commit()
    if discharge_cursor.rowcount:
        add_log(admission[1], "Patient discharged after discharge bill print")

    return render_template(
        'discharge_bill_print.html',
        admission=admission,
        items=items,
        bill_no=bill_no,
        discharge_date=discharge_date,
        remarks=remarks,
        total_amount=total_amount,
        discount=discount,
        gross_amount=gross_amount,
        paid_amount=paid_amount,
        due_amount=due_amount,
        change_amount=change_amount,
        amount_in_words=amount_to_words(gross_amount),
        prepared_by=printed_by,
        printed_by=printed_by
    )

@app.route('/discharge-patients-list')
def discharge_patients_list():
    """Show discharged patients with admission details and saved discharge bill information."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    rows = db.execute('''
        SELECT
            a.id,
            p.id,
            COALESCE(p.source_patient_id, p.id) AS patient_uhid,
            p.name,
            p.phone,
            p.age,
            COALESCE(NULLIF(p.age_unit, ''), 'Y') AS age_unit,
            p.gender,
            p.address,
            a.admission_date,
            a.discharged_at,
            a.room_number,
            a.guardian_name,
            a.guardian_relation,
            COALESCE(d.name, 'Not assigned') AS doctor_name,
            a.reason,
            a.notes,
            dbill.bill_no,
            dbill.discharge_date,
            dbill.stay_days,
            dbill.bed_charge,
            dbill.doctor_fee,
            dbill.medicine_charge,
            dbill.pathology_charge,
            dbill.service_charge,
            dbill.other_charge,
            dbill.total_amount,
            dbill.discount,
            dbill.gross_amount,
            dbill.paid_amount,
            dbill.due_amount,
            dbill.change_amount,
            dbill.remarks,
            dbill.prepared_by,
            dbill.updated_at
        FROM admissions a
        JOIN patients p ON a.patient_id = p.id
        LEFT JOIN doctors d ON a.doctor_id = d.id
        LEFT JOIN discharge_bills dbill ON dbill.admission_id = a.id
        WHERE a.status = 'Discharged'
        ORDER BY datetime(COALESCE(a.discharged_at, a.created_at)) DESC, a.id DESC
    ''').fetchall()

    records = []
    for row in rows:
        print_url = None
        if row[17]:
            print_url = url_for(
                'discharge_bill_print',
                admission_id=row[0],
                discharge_date=row[18] or '',
                stay_days=row[19] or 1,
                bed_charge=row[20] or 0,
                doctor_fee=row[21] or 0,
                medicine_charge=row[22] or 0,
                pathology_charge=row[23] or 0,
                service_charge=row[24] or 0,
                other_charge=row[25] or 0,
                discount=row[27] or 0,
                paid=row[29] or 0,
                remarks=row[32] or ''
            )

        records.append({
            'admission_id': row[0],
            'patient_id': row[1],
            'patient_uhid': row[2],
            'name': row[3],
            'phone': row[4],
            'age': row[5],
            'age_unit': row[6],
            'gender': row[7],
            'address': row[8],
            'admission_date': row[9],
            'discharged_at': row[10],
            'bed_no': row[11],
            'guardian_name': row[12],
            'guardian_relation': row[13],
            'doctor_name': row[14],
            'reason': row[15],
            'notes': row[16],
            'bill_no': row[17],
            'bill_discharge_date': row[18],
            'stay_days': row[19],
            'bed_charge': row[20] or 0,
            'doctor_fee': row[21] or 0,
            'medicine_charge': row[22] or 0,
            'pathology_charge': row[23] or 0,
            'service_charge': row[24] or 0,
            'other_charge': row[25] or 0,
            'total_amount': row[26] or 0,
            'discount': row[27] or 0,
            'gross_amount': row[28] or 0,
            'paid_amount': row[29] or 0,
            'due_amount': row[30] or 0,
            'change_amount': row[31] or 0,
            'remarks': row[32],
            'prepared_by': row[33],
            'bill_updated_at': row[34],
            'print_url': print_url,
        })

    summary = {
        'patient_count': len(records),
        'bill_count': sum(1 for record in records if record['bill_no']),
        'gross_total': sum(record['gross_amount'] for record in records),
        'paid_total': sum(record['paid_amount'] for record in records),
        'due_total': sum(record['due_amount'] for record in records),
    }

    return render_template(
        'discharge_patients_list.html',
        records=records,
        summary=summary
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
    doctor_records = sum(1 for row in duty_records if row['staff_role'] == 'doctor')
    nurse_records = sum(1 for row in duty_records if row['staff_role'] == 'nurse')
    doctor_completed = sum(1 for row in duty_records if row['staff_role'] == 'doctor' and row['round_completed'])
    nurse_completed = sum(1 for row in duty_records if row['staff_role'] == 'nurse' and row['round_completed'])
    completion_rate = round((completed_records / total_records) * 100) if total_records else 0

    return render_template(
        'duty_management.html',
        doctors=doctor_list,
        duty_records=duty_records,
        selected_date=selected_date,
        total_records=total_records,
        completed_records=completed_records,
        pending_records=total_records - completed_records,
        doctor_records=doctor_records,
        nurse_records=nurse_records,
        doctor_completed=doctor_completed,
        nurse_completed=nurse_completed,
        completion_rate=completion_rate,
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
            address,
            source_patient_id,
            (
                SELECT return_no
                FROM patient_visit_returns pvr
                WHERE pvr.patient_id = patients.id
                LIMIT 1
            ) AS visit_return_no
        FROM patients
    '''
    if show_all_patients:
        patient_query += '''
            WHERE source_patient_id IS NULL
            ORDER BY datetime(created_at) DESC, id DESC
        '''
        patient_list = db.execute(patient_query).fetchall()
        daily_patient_total = db.execute(
            "SELECT COUNT(*) FROM patients WHERE date(created_at) = ?",
            (selected_date,)
        ).fetchone()[0]
    else:
        patient_query += '''
            WHERE date(created_at) = ?
            ORDER BY COALESCE(daily_patient_id, id) ASC, id ASC
        '''
        patient_list = db.execute(patient_query, (selected_date,)).fetchall()
        daily_patient_total = len(patient_list)
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
        daily_patient_total=daily_patient_total,
        next_daily_ticket_no=next_daily_ticket_no,
        doctor_options=doctor_options
    )


@app.route('/patients-info')
def patients_info():
    """Show all registered patient details with full service and bill history."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    keyword = request.args.get('keyword', '').strip()
    message = request.args.get('message', '').strip()
    patient_query = '''
        SELECT
            id,
            daily_patient_id,
            name,
            age,
            COALESCE(NULLIF(age_unit, ''), 'Y') AS age_unit,
            gender,
            phone,
            email,
            dob,
            blood_group,
            address,
            emergency_contact_name,
            emergency_contact_phone,
            medical_history,
            patient_status,
            doctor_name,
            doctor_designation,
            referer_name,
            doctor_fee,
            created_at
        FROM patients
        WHERE source_patient_id IS NULL
    '''
    patient_params = []
    if keyword:
        patient_query += '''
            AND (
                CAST(id AS TEXT) LIKE ?
                OR CAST(COALESCE(daily_patient_id, '') AS TEXT) LIKE ?
                OR name LIKE ?
                OR phone LIKE ?
                OR address LIKE ?
                OR EXISTS (
                    SELECT 1
                    FROM patients child
                    WHERE child.source_patient_id = patients.id
                      AND (
                          CAST(child.id AS TEXT) LIKE ?
                          OR CAST(COALESCE(child.daily_patient_id, '') AS TEXT) LIKE ?
                          OR child.name LIKE ?
                          OR child.phone LIKE ?
                      )
                )
            )
        '''
        like_keyword = f'%{keyword}%'
        patient_params.extend([like_keyword] * 9)
    patient_query += ' ORDER BY datetime(created_at) DESC, id DESC'

    patient_rows = db.execute(patient_query, patient_params).fetchall()
    patient_records = []
    total_visit_count = 0
    grand_bill_total = 0

    for patient in patient_rows:
        patient_id = patient[0]
        visit_rows = db.execute(
            '''
            SELECT
                id,
                daily_patient_id,
                serial_no,
                patient_status,
                doctor_name,
                doctor_designation,
                referer_name,
                doctor_fee,
                created_at
            FROM patients
            WHERE id = ? OR source_patient_id = ?
            ORDER BY datetime(created_at) DESC, id DESC
            ''',
            (patient_id, patient_id)
        ).fetchall()
        visit_ids = [row[0] for row in visit_rows]
        total_visit_count += len(visit_rows)

        consultation_total = sum(float(row[7] or 0) for row in visit_rows)
        service_bills = []
        test_bills = []
        service_names = []

        if visit_ids:
            placeholders = ','.join('?' for _ in visit_ids)
            service_bill_rows = db.execute(
                f'''
                SELECT
                    b.id,
                    b.patient_id,
                    b.created_at,
                    COALESCE(SUM(COALESCE(bi.quantity, 1) * COALESCE(bi.price, 0)), b.total_amount, 0) AS calculated_total,
                    GROUP_CONCAT(s.name, ', ') AS service_names
                FROM bills b
                LEFT JOIN bill_items bi ON bi.bill_id = b.id
                LEFT JOIN services s ON s.id = bi.service_id
                WHERE b.patient_id IN ({placeholders})
                GROUP BY b.id
                ORDER BY datetime(b.created_at) DESC, b.id DESC
                ''',
                visit_ids
            ).fetchall()
            service_bills = [
                {
                    'id': row[0],
                    'patient_id': row[1],
                    'created_at': row[2],
                    'total': float(row[3] or 0),
                    'services': row[4] or 'Service bill',
                }
                for row in service_bill_rows
            ]

            test_bill_rows = db.execute(
                f'''
                SELECT
                    tb.id,
                    tb.patient_id,
                    tb.invoice_no,
                    tb.created_at,
                    tb.discount_amount,
                    tb.total_amount,
                    tb.received_amount,
                    tb.due_amount,
                    GROUP_CONCAT(tbi.test_name, ', ') AS test_names
                FROM test_bills tb
                LEFT JOIN test_bill_items tbi ON tbi.test_bill_id = tb.id
                WHERE tb.patient_id IN ({placeholders})
                GROUP BY tb.id
                ORDER BY datetime(tb.created_at) DESC, tb.id DESC
                ''',
                visit_ids
            ).fetchall()
            test_bills = [
                {
                    'id': row[0],
                    'patient_id': row[1],
                    'invoice_no': row[2],
                    'created_at': row[3],
                    'discount': float(row[4] or 0),
                    'total': float(row[5] or 0),
                    'received': float(row[6] or 0),
                    'due': float(row[7] or 0),
                    'tests': row[8] or 'Pathology bill',
                }
                for row in test_bill_rows
            ]

        for visit in visit_rows:
            if visit[4]:
                service_names.append(f"Doctor Consultation - {visit[4]}")
        for bill in service_bills:
            service_names.extend([name.strip() for name in bill['services'].split(',') if name.strip()])
        for bill in test_bills:
            service_names.extend([name.strip() for name in bill['tests'].split(',') if name.strip()])

        unique_services = []
        for service_name in service_names:
            if service_name and service_name not in unique_services:
                unique_services.append(service_name)

        patient_total = consultation_total + sum(bill['total'] for bill in service_bills) + sum(bill['total'] for bill in test_bills)
        grand_bill_total += patient_total
        due_total = sum(bill['due'] for bill in test_bills)
        bill_count = len(service_bills) + len(test_bills)
        last_visit_at = visit_rows[0][8] if visit_rows else patient[19]
        last_service_name = unique_services[0] if unique_services else 'No service yet'

        patient_records.append({
            'patient': {
                'id': patient[0],
                'daily_patient_id': patient[1],
                'name': patient[2],
                'age': patient[3],
                'age_unit': patient[4],
                'gender': patient[5],
                'phone': patient[6],
                'email': patient[7] or '',
                'dob': patient[8] or '',
                'blood_group': patient[9] or '',
                'address': patient[10] or '',
                'emergency_contact_name': patient[11] or '',
                'emergency_contact_phone': patient[12] or '',
                'medical_history': patient[13] or '',
                'patient_status': patient[14] or '',
                'doctor_name': patient[15] or '',
                'doctor_designation': patient[16] or '',
                'referer_name': patient[17] or '',
                'doctor_fee': float(patient[18] or 0),
                'created_at': patient[19],
            },
            'visits': [
                {
                    'id': row[0],
                    'daily_patient_id': row[1],
                    'serial_no': row[2] or '',
                    'patient_status': row[3] or '',
                    'doctor_name': row[4] or '',
                    'doctor_designation': row[5] or '',
                    'referer_name': row[6] or '',
                    'doctor_fee': float(row[7] or 0),
                    'created_at': row[8],
                }
                for row in visit_rows
            ],
            'service_bills': service_bills,
            'test_bills': test_bills,
            'service_names': unique_services,
            'consultation_total': consultation_total,
            'patient_total': patient_total,
            'due_total': due_total,
            'bill_count': bill_count,
            'last_visit_at': last_visit_at,
            'last_service_name': last_service_name,
        })

    summary = {
        'patient_count': len(patient_records),
        'visit_count': total_visit_count,
        'bill_total': grand_bill_total,
    }

    return render_template(
        'patients_info.html',
        patient_records=patient_records,
        summary=summary,
        keyword=keyword,
        message=message
    )


@app.route('/patients-info/edit-profile/<int:patient_id>', methods=['GET', 'POST'])
def edit_patient_profile(patient_id):
    """Update shared patient profile fields across the original patient and visits."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    keyword = request.args.get('keyword', '').strip()
    message = request.args.get('message', '').strip()

    patient_row = db.execute(
        'SELECT id, source_patient_id FROM patients WHERE id = ?',
        (patient_id,)
    ).fetchone()
    if not patient_row:
        return redirect(url_for('patients_info', keyword=keyword, message='Patient not found.'))

    root_patient_id = patient_row[1] or patient_row[0]

    if request.method == 'GET':
        profile_row = db.execute(
            '''
            SELECT
                id,
                daily_patient_id,
                name,
                age,
                COALESCE(NULLIF(age_unit, ''), 'Y') AS age_unit,
                gender,
                phone,
                email,
                dob,
                blood_group,
                address,
                emergency_contact_name,
                emergency_contact_phone,
                medical_history,
                patient_status,
                created_at
            FROM patients
            WHERE id = ?
            ''',
            (root_patient_id,)
        ).fetchone()
        if not profile_row:
            return redirect(url_for('patients_info', keyword=keyword, message='Patient not found.'))

        patient = {
            'id': profile_row[0],
            'daily_patient_id': profile_row[1],
            'name': profile_row[2] or '',
            'age': profile_row[3] or '',
            'age_unit': profile_row[4] or 'Y',
            'gender': profile_row[5] or '',
            'phone': profile_row[6] or '',
            'email': profile_row[7] or '',
            'dob': profile_row[8] or '',
            'blood_group': profile_row[9] or '',
            'address': profile_row[10] or '',
            'emergency_contact_name': profile_row[11] or '',
            'emergency_contact_phone': profile_row[12] or '',
            'medical_history': profile_row[13] or '',
            'patient_status': profile_row[14] or '',
            'created_at': profile_row[15],
        }
        return render_template(
            'patient_profile_edit.html',
            patient=patient,
            keyword=keyword,
            message=message
        )

    name = (request.form.get('name') or '').strip()
    age = (request.form.get('age') or '').strip()
    age_unit = (request.form.get('age_unit') or 'Y').strip().upper()
    gender = (request.form.get('gender') or '').strip()
    phone = (request.form.get('phone') or '').strip()
    email = (request.form.get('email') or '').strip()
    dob = (request.form.get('dob') or '').strip()
    blood_group = (request.form.get('blood_group') or '').strip()
    address = (request.form.get('address') or '').strip()
    emergency_contact_name = (request.form.get('emergency_contact_name') or '').strip()
    emergency_contact_phone = (request.form.get('emergency_contact_phone') or '').strip()
    medical_history = (request.form.get('medical_history') or '').strip()
    patient_status = (request.form.get('patient_status') or '').strip()

    if not name or not age or not gender or not phone or not blood_group or not address or not patient_status:
        return redirect(url_for('edit_patient_profile', patient_id=root_patient_id, keyword=keyword, message='Please fill in all required profile fields.'))
    if not age.isdigit() or int(age) < 0:
        return redirect(url_for('edit_patient_profile', patient_id=root_patient_id, keyword=keyword, message='Please enter a valid age.'))
    if age_unit not in ('Y', 'M', 'D'):
        age_unit = 'Y'
    if not phone.isdigit() or len(phone) < 7:
        return redirect(url_for('edit_patient_profile', patient_id=root_patient_id, keyword=keyword, message='Please enter a valid phone number.'))
    if emergency_contact_phone and (not emergency_contact_phone.isdigit() or len(emergency_contact_phone) < 7):
        return redirect(url_for('edit_patient_profile', patient_id=root_patient_id, keyword=keyword, message='Please enter a valid emergency contact number.'))

    db.execute(
        '''
        UPDATE patients
        SET
            name = ?,
            age = ?,
            age_unit = ?,
            gender = ?,
            phone = ?,
            email = ?,
            dob = ?,
            blood_group = ?,
            address = ?,
            emergency_contact_name = ?,
            emergency_contact_phone = ?,
            medical_history = ?,
            patient_status = ?
        WHERE id = ? OR source_patient_id = ?
        ''',
        (
            name,
            int(age),
            age_unit,
            gender,
            phone,
            email,
            dob,
            blood_group,
            address,
            emergency_contact_name,
            emergency_contact_phone,
            medical_history,
            patient_status,
            root_patient_id,
            root_patient_id,
        )
    )
    db.commit()
    add_system_log(f"Patient profile updated: {name} ({phone})", root_patient_id)

    return redirect(url_for('patients_info', keyword=keyword, message='Patient profile updated successfully.'))


def get_patient_detail_record(patient_id):
    """Build one patient's complete visit and billing history for printable details."""
    patient_row = db.execute(
        '''
        SELECT
            id,
            daily_patient_id,
            name,
            age,
            COALESCE(NULLIF(age_unit, ''), 'Y') AS age_unit,
            gender,
            phone,
            email,
            blood_group,
            address,
            emergency_contact_phone,
            patient_status,
            doctor_name,
            doctor_designation,
            referer_name,
            doctor_fee,
            created_at,
            source_patient_id
        FROM patients
        WHERE id = ?
        ''',
        (patient_id,)
    ).fetchone()
    if not patient_row:
        return None

    master_patient_id = patient_row[17] or patient_row[0]
    if master_patient_id != patient_row[0]:
        master_row = db.execute(
            '''
            SELECT
                id,
                daily_patient_id,
                name,
                age,
                COALESCE(NULLIF(age_unit, ''), 'Y') AS age_unit,
                gender,
                phone,
                email,
                blood_group,
                address,
                emergency_contact_phone,
                patient_status,
                doctor_name,
                doctor_designation,
                referer_name,
                doctor_fee,
                created_at,
                source_patient_id
            FROM patients
            WHERE id = ?
            ''',
            (master_patient_id,)
        ).fetchone()
        if master_row:
            patient_row = master_row

    visit_rows = db.execute(
        '''
        SELECT
            id,
            daily_patient_id,
            serial_no,
            patient_status,
            doctor_name,
            doctor_designation,
            referer_name,
            doctor_fee,
            created_at
        FROM patients
        WHERE id = ? OR source_patient_id = ?
        ORDER BY datetime(created_at) DESC, id DESC
        ''',
        (master_patient_id, master_patient_id)
    ).fetchall()
    visit_ids = [row[0] for row in visit_rows]
    consultation_total = sum(float(row[7] or 0) for row in visit_rows)
    service_bills = []
    test_bills = []

    if visit_ids:
        placeholders = ','.join('?' for _ in visit_ids)
        service_bill_rows = db.execute(
            f'''
            SELECT
                b.id,
                b.patient_id,
                b.created_at,
                COALESCE(SUM(COALESCE(bi.quantity, 1) * COALESCE(bi.price, 0)), b.total_amount, 0) AS calculated_total,
                GROUP_CONCAT(s.name, ', ') AS service_names
            FROM bills b
            LEFT JOIN bill_items bi ON bi.bill_id = b.id
            LEFT JOIN services s ON s.id = bi.service_id
            WHERE b.patient_id IN ({placeholders})
            GROUP BY b.id
            ORDER BY datetime(b.created_at) DESC, b.id DESC
            ''',
            visit_ids
        ).fetchall()
        service_bills = [
            {
                'id': row[0],
                'patient_id': row[1],
                'created_at': row[2],
                'total': float(row[3] or 0),
                'services': row[4] or 'Service bill',
            }
            for row in service_bill_rows
        ]

        test_bill_rows = db.execute(
            f'''
            SELECT
                tb.id,
                tb.patient_id,
                tb.invoice_no,
                tb.created_at,
                tb.discount_amount,
                tb.total_amount,
                tb.received_amount,
                tb.due_amount,
                GROUP_CONCAT(tbi.test_name, ', ') AS test_names
            FROM test_bills tb
            LEFT JOIN test_bill_items tbi ON tbi.test_bill_id = tb.id
            WHERE tb.patient_id IN ({placeholders})
            GROUP BY tb.id
            ORDER BY datetime(tb.created_at) DESC, tb.id DESC
            ''',
            visit_ids
        ).fetchall()
        test_bills = [
            {
                'id': row[0],
                'patient_id': row[1],
                'invoice_no': row[2],
                'created_at': row[3],
                'discount': float(row[4] or 0),
                'total': float(row[5] or 0),
                'received': float(row[6] or 0),
                'due': float(row[7] or 0),
                'tests': row[8] or 'Pathology bill',
            }
            for row in test_bill_rows
        ]

    patient_total = consultation_total + sum(bill['total'] for bill in service_bills) + sum(bill['total'] for bill in test_bills)
    due_total = sum(bill['due'] for bill in test_bills)
    received_total = sum(bill['received'] for bill in test_bills)
    discount_total = sum(bill['discount'] for bill in test_bills)

    return {
        'patient': {
            'id': patient_row[0],
            'daily_patient_id': patient_row[1],
            'name': patient_row[2],
            'age': patient_row[3],
            'age_unit': patient_row[4],
            'gender': patient_row[5],
            'phone': patient_row[6],
            'email': patient_row[7] or '',
            'blood_group': patient_row[8] or '',
            'address': patient_row[9] or '',
            'emergency_contact_phone': patient_row[10] or '',
            'patient_status': patient_row[11] or '',
            'doctor_name': patient_row[12] or '',
            'doctor_designation': patient_row[13] or '',
            'referer_name': patient_row[14] or '',
            'doctor_fee': float(patient_row[15] or 0),
            'created_at': patient_row[16],
        },
        'visits': [
            {
                'id': row[0],
                'daily_patient_id': row[1],
                'serial_no': row[2] or '',
                'patient_status': row[3] or '',
                'doctor_name': row[4] or '',
                'doctor_designation': row[5] or '',
                'referer_name': row[6] or '',
                'doctor_fee': float(row[7] or 0),
                'created_at': row[8],
            }
            for row in visit_rows
        ],
        'service_bills': service_bills,
        'test_bills': test_bills,
        'consultation_total': consultation_total,
        'service_total': sum(bill['total'] for bill in service_bills),
        'test_total': sum(bill['total'] for bill in test_bills),
        'received_total': received_total,
        'discount_total': discount_total,
        'due_total': due_total,
        'patient_total': patient_total,
        'bill_count': len(service_bills) + len(test_bills),
    }


@app.route('/patients-info/details-bill/<int:patient_id>')
def patient_details_bill(patient_id):
    """Printable all-details bill for one registered patient."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    record = get_patient_detail_record(patient_id)
    if not record:
        return redirect(url_for('patients_info', keyword='', message='Patient not found.'))

    printed_by = get_current_actor()[2]
    return render_template(
        'patient_details_bill.html',
        record=record,
        patient=record['patient'],
        amount_in_words=amount_to_words(record['patient_total']),
        printed_by=printed_by
    )


@app.route('/patients-info/visits-print/<int:patient_id>')
def patient_visits_print(patient_id):
    """Printable all registration visits for one registered patient."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    record = get_patient_detail_record(patient_id)
    if not record:
        return redirect(url_for('patients_info', keyword='', message='Patient not found.'))

    printed_by = get_current_actor()[2]
    return render_template(
        'patient_visits_print.html',
        record=record,
        patient=record['patient'],
        printed_by=printed_by,
        amount_in_words=amount_to_words(record['consultation_total'])
    )


@app.route('/patients-info/pathology-print/<int:patient_id>')
def patient_pathology_print(patient_id):
    """Printable all pathology bills for one registered patient."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    record = get_patient_detail_record(patient_id)
    if not record:
        return redirect(url_for('patients_info', keyword='', message='Patient not found.'))

    printed_by = get_current_actor()[2]
    return render_template(
        'patient_pathology_print.html',
        record=record,
        patient=record['patient'],
        printed_by=printed_by,
        amount_in_words=amount_to_words(record['test_total'])
    )


@app.route('/patients-registration/search')
def search_registered_patient():
    """Find existing master patients so a new daily bill can be created without duplicating All Patients."""
    if not isadmin() and not isuser():
        return jsonify({'success': False, 'patients': []}), 401

    keyword = request.args.get('keyword', '').strip()
    if len(keyword) < 2:
        return jsonify({'success': True, 'patients': []})

    rows = db.execute(
        '''
        SELECT
            id,
            daily_patient_id,
            name,
            age,
            COALESCE(NULLIF(age_unit, ''), 'Y') AS age_unit,
            gender,
            phone,
            email,
            dob,
            blood_group,
            address,
            emergency_contact_name,
            emergency_contact_phone,
            medical_history,
            patient_status,
            doctor_name,
            doctor_designation,
            referer_name,
            doctor_fee,
            created_at
        FROM patients
        WHERE source_patient_id IS NULL
          AND (
              CAST(id AS TEXT) LIKE ?
              OR CAST(COALESCE(daily_patient_id, '') AS TEXT) LIKE ?
              OR name LIKE ?
              OR phone LIKE ?
          )
        ORDER BY
            CASE WHEN phone = ? THEN 0 ELSE 1 END,
            datetime(created_at) DESC,
            id DESC
        LIMIT 12
        ''',
        (f'%{keyword}%', f'%{keyword}%', f'%{keyword}%', f'%{keyword}%', keyword)
    ).fetchall()

    patients = [
        {
            'id': row[0],
            'daily_patient_id': row[1],
            'name': row[2],
            'age': row[3],
            'age_unit': row[4],
            'gender': row[5],
            'phone': row[6],
            'email': row[7] or '',
            'dob': row[8] or '',
            'blood_group': row[9] or '',
            'address': row[10] or '',
            'emergency_contact_name': row[11] or '',
            'emergency_contact_phone': row[12] or '',
            'medical_history': row[13] or '',
            'patient_status': row[14] or 'OLD',
            'doctor_name': row[15] or '',
            'doctor_designation': row[16] or '',
            'referer_name': row[17] or '',
            'doctor_fee': row[18] or '',
            'created_at': format_date_display(row[19]),
        }
        for row in rows
    ]
    return jsonify({'success': True, 'patients': patients})


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
            created_at,
            source_patient_id
        FROM patients
        WHERE id = ?
    ''', (patient_id,)).fetchone()

    if not ticket:
        return redirect(url_for('patients_registration', message="Patient ticket not found."))

    doctor_fee = ticket[15] or 0
    source_patient_id = ticket[17]
    ticket_info = {
        'uhid': source_patient_id or ticket[0],
        'visit_id': ticket[0],
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


def _to_positive_float(value, default=0):
    try:
        amount = float(value or default)
        return amount if amount > 0 else 0
    except (TypeError, ValueError):
        return default


def generate_test_invoice_no():
    today_prefix = f"TB-{datetime.now().strftime('%y%m%d')}"
    invoice_count = db.execute(
        "SELECT COUNT(*) FROM test_bills WHERE invoice_no LIKE ?",
        (f"{today_prefix}-%",)
    ).fetchone()[0]
    return f"{today_prefix}-{invoice_count + 1:03d}"


def get_recent_test_bills(bill_date, keyword=''):
    recent_query = '''
        SELECT tb.id, tb.invoice_no, p.name, p.phone, tb.total_amount, tb.due_amount, tb.created_at,
               COALESCE(p.source_patient_id, p.id) AS patient_uhid, p.daily_patient_id,
               tbr.return_no
        FROM test_bills tb
        JOIN patients p ON p.id = tb.patient_id
        LEFT JOIN test_bill_returns tbr ON tbr.test_bill_id = tb.id
        WHERE date(tb.created_at) = ?
    '''
    recent_params = [bill_date]

    if keyword:
        recent_query += '''
            AND (
                tb.invoice_no LIKE ?
                OR p.name LIKE ?
                OR p.phone LIKE ?
                OR tb.doctor_name LIKE ?
                OR CAST(COALESCE(p.source_patient_id, p.id) AS TEXT) LIKE ?
                OR CAST(COALESCE(p.daily_patient_id, '') AS TEXT) LIKE ?
            )
        '''
        recent_params.extend([f'%{keyword}%', f'%{keyword}%', f'%{keyword}%', f'%{keyword}%', f'%{keyword}%', f'%{keyword}%'])

    recent_query += '''
        ORDER BY datetime(tb.created_at) DESC, tb.id DESC
    '''

    return db.execute(recent_query, recent_params).fetchall()


@app.route('/test-billing', methods=['GET', 'POST'])
def test_billing():
    """Create hospital test bills for registered patients."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    if request.method == 'POST':
        patient_id = request.form.get('patient_id', '').strip()
        if not patient_id.isdigit():
            return redirect(url_for('test_billing', message='Please select a registered patient.'))

        patient = db.execute(
            'SELECT id, name FROM patients WHERE id = ?',
            (patient_id,)
        ).fetchone()
        if not patient:
            return redirect(url_for('test_billing', message='Selected patient was not found.'))

        selected_test_ids = []
        for test_id in request.form.getlist('test_ids'):
            if str(test_id).isdigit() and int(test_id) not in selected_test_ids:
                selected_test_ids.append(int(test_id))

        bill_items = []
        if selected_test_ids:
            placeholders = ','.join('?' for _ in selected_test_ids)
            service_rows = db.execute(
                f"SELECT id, name, price FROM services WHERE type = 'test' AND id IN ({placeholders})",
                selected_test_ids
            ).fetchall()
            service_by_id = {row[0]: row for row in service_rows}
            for test_id in selected_test_ids:
                service = service_by_id.get(test_id)
                if service:
                    bill_items.append({
                        'service_id': service[0],
                        'test_name': service[1],
                        'price': float(service[2] or 0),
                    })

        custom_names = request.form.getlist('custom_test_name[]')
        custom_prices = request.form.getlist('custom_test_price[]')
        for name, price in zip(custom_names, custom_prices):
            clean_name = (name or '').strip()
            clean_price = _to_positive_float(price)
            if clean_name and clean_price:
                bill_items.append({
                    'service_id': None,
                    'test_name': clean_name,
                    'price': clean_price,
                })

        if not bill_items:
            return redirect(url_for('test_billing', message='Please select or add at least one test.'))

        subtotal = sum(item['price'] for item in bill_items)
        flat_discount_amount = _to_positive_float(request.form.get('flat_discount_amount'))
        percentage_discount_amount = min(_to_positive_float(request.form.get('percentage_discount_amount')), 100)
        percentage_discount_value = subtotal * (percentage_discount_amount / 100)
        discount_amount = min(flat_discount_amount + percentage_discount_value, subtotal)
        total_amount = max(subtotal - discount_amount, 0)
        received_amount = _to_positive_float(request.form.get('received_amount'))
        due_amount = max(total_amount - received_amount, 0)
        change_amount = max(received_amount - total_amount, 0)

        invoice_no = generate_test_invoice_no()
        doctor_name = request.form.get('doctor_name', '').strip()
        referred_by = request.form.get('referred_by', '').strip()
        sample_status = request.form.get('sample_status', '').strip() or 'Pending'
        delivery_time = request.form.get('delivery_time', '').strip()
        payment_method = request.form.get('payment_method', '').strip() or 'Cash'
        remarks = request.form.get('remarks', '').strip()

        try:
            bill_cursor = db.execute(
                '''
                INSERT INTO test_bills (
                    invoice_no, patient_id, doctor_name, referred_by, sample_status, delivery_time,
                    subtotal, discount_amount, total_amount, received_amount, due_amount, change_amount,
                    payment_method, remarks, created_by, created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+6 hours'))
                ''',
                (
                    invoice_no, int(patient_id), doctor_name, referred_by, sample_status, delivery_time,
                    subtotal, discount_amount, total_amount, received_amount, due_amount, change_amount,
                    payment_method, remarks, str(session.get('user_id'))
                )
            )
            test_bill_id = bill_cursor.lastrowid

            for item in bill_items:
                db.execute(
                    '''
                    INSERT INTO test_bill_items (test_bill_id, service_id, test_name, price)
                    VALUES (?, ?, ?, ?)
                    ''',
                    (test_bill_id, item['service_id'], item['test_name'], item['price'])
                )
                if item['service_id']:
                    db.execute(
                        '''
                        INSERT INTO test_orders (patient_id, service_id, test_date)
                        VALUES (?, ?, datetime('now', '+6 hours'))
                        ''',
                        (int(patient_id), item['service_id'])
                    )

            db.commit()
            add_log(int(patient_id), f"Test bill created: {invoice_no}")
            return redirect(url_for('test_bill_print', test_bill_id=test_bill_id))
        except sqlite3.Error:
            db.rollback()
            return redirect(url_for('test_billing', message='Test bill could not be saved. Please try again.'))

    keyword = request.args.get('keyword', '').strip()
    today_text = datetime.now().strftime('%Y-%m-%d')
    bill_date = request.args.get('bill_date', '').strip() or today_text
    try:
        datetime.strptime(bill_date, '%Y-%m-%d')
    except ValueError:
        bill_date = today_text

    recent_bills = get_recent_test_bills(bill_date, keyword)

    if request.args.get('partial') == 'day_bills':
        return render_template(
            '_day_wise_pathology_bills.html',
            recent_bills=recent_bills,
            keyword=keyword,
            bill_date=bill_date,
            bill_date_label=format_date_display(bill_date),
            today_bill_date=today_text
        )

    patient_rows = db.execute(
        '''
        SELECT id, daily_patient_id, name, age, COALESCE(NULLIF(age_unit, ''), 'Y'),
               gender, phone, address, doctor_name, doctor_designation, referer_name,
               created_at, COALESCE(source_patient_id, id) AS patient_uhid
        FROM patients
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT 250
        '''
    ).fetchall()
    selected_patient_id = request.args.get('patient_id', '').strip()
    patients = [
        {
            'id': row[0],
            'daily_patient_id': row[1],
            'name': row[2],
            'age': row[3],
            'age_unit': row[4],
            'gender': row[5],
            'phone': row[6],
            'address': row[7],
            'doctor_name': row[8] or '',
            'doctor_designation': row[9] or '',
            'referer_name': row[10] or '',
            'created_at': row[11],
            'patient_uhid': row[12],
        }
        for row in patient_rows
    ]

    test_rows = db.execute(
        '''
        SELECT id, name, price
        FROM services
        WHERE type = 'test'
        ORDER BY name ASC
        '''
    ).fetchall()
    tests = [{'id': row[0], 'name': row[1], 'price': float(row[2] or 0)} for row in test_rows]

    return render_template(
        'test_billing.html',
        patients=patients,
        tests=tests,
        recent_bills=recent_bills,
        keyword=keyword,
        bill_date=bill_date,
        bill_date_label=format_date_display(bill_date),
        today_bill_date=today_text,
        selected_patient_id=selected_patient_id,
        message=request.args.get('message')
    )


@app.route('/test-bill/<int:test_bill_id>')
def test_bill_print(test_bill_id):
    """Print one professional test bill invoice."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    bill = db.execute(
        '''
        SELECT tb.id, tb.invoice_no, tb.doctor_name, tb.referred_by, tb.sample_status,
               tb.delivery_time, tb.subtotal, tb.discount_amount, tb.total_amount,
               tb.received_amount, tb.due_amount, tb.change_amount, tb.payment_method,
               tb.remarks, tb.created_at,
               p.name, p.age, COALESCE(NULLIF(p.age_unit, ''), 'Y'), p.gender, p.phone,
               p.address, p.daily_patient_id, COALESCE(p.source_patient_id, p.id) AS patient_uhid
        FROM test_bills tb
        JOIN patients p ON p.id = tb.patient_id
        WHERE tb.id = ?
        ''',
        (test_bill_id,)
    ).fetchone()
    if not bill:
        return redirect(url_for('test_billing', message='Test bill not found.'))

    items = db.execute(
        '''
        SELECT test_name, price
        FROM test_bill_items
        WHERE test_bill_id = ?
        ORDER BY id ASC
        ''',
        (test_bill_id,)
    ).fetchall()

    return render_template(
        'test_bill_print.html',
        bill=bill,
        items=items,
        patient_uhid=bill[22] or bill[0],
        total_in_words=amount_to_words(bill[8])
    )


@app.route('/test_return', methods=['GET', 'POST'])
def test_return():
    """Return a pathology bill and keep an auditable refund record."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    query = request.args.get('q', '').strip()
    selected_bill_id = request.args.get('bill_id', '').strip()
    message = request.args.get('message', '').strip()
    success = request.args.get('success', '').strip()

    if request.method == 'POST':
        test_bill_id = request.form.get('test_bill_id', '').strip()
        reason = request.form.get('reason', '').strip()
        try:
            test_bill_id_value = int(test_bill_id)
            refund_amount = max(float(request.form.get('refund_amount') or 0), 0)
        except (TypeError, ValueError):
            return redirect(url_for('test_return', message='Please select a valid pathology bill and refund amount.'))

        bill = db.execute(
            '''
            SELECT
                tb.id,
                tb.invoice_no,
                tb.patient_id,
                tb.subtotal,
                tb.discount_amount,
                tb.total_amount,
                tb.received_amount,
                tb.due_amount,
                p.name,
                p.phone,
                COALESCE(p.source_patient_id, p.id) AS patient_uhid,
                p.daily_patient_id
            FROM test_bills tb
            JOIN patients p ON p.id = tb.patient_id
            WHERE tb.id = ?
            ''',
            (test_bill_id_value,)
        ).fetchone()
        if not bill:
            return redirect(url_for('test_return', message='Pathology bill not found.'))

        existing_return = db.execute(
            'SELECT return_no FROM test_bill_returns WHERE test_bill_id = ?',
            (test_bill_id_value,)
        ).fetchone()
        if existing_return:
            return redirect(url_for(
                'test_return',
                bill_id=test_bill_id_value,
                message=f'This pathology bill is already returned on {existing_return[0]}.'
            ))

        paid_amount = min(float(bill[6] or 0), float(bill[5] or 0))
        refund_amount = min(refund_amount, paid_amount)
        return_date = datetime.now().strftime('%Y-%m-%d')
        created_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return_count = db.execute(
            "SELECT COUNT(*) FROM test_bill_returns WHERE date(return_date) = ?",
            (return_date,)
        ).fetchone()[0]
        return_no = f"TR-{datetime.now().strftime('%y%m%d')}-{return_count + 1:03d}"

        try:
            db.execute(
                '''
                INSERT INTO test_bill_returns (
                    return_no, test_bill_id, invoice_no, patient_id, patient_uhid,
                    ticket_no, patient_name, phone, original_subtotal,
                    original_discount_amount, original_total_amount, original_received_amount,
                    original_due_amount, refund_amount, reason, return_date, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    return_no,
                    bill[0],
                    bill[1],
                    bill[2],
                    bill[10],
                    bill[11],
                    bill[8],
                    bill[9],
                    float(bill[3] or 0),
                    float(bill[4] or 0),
                    float(bill[5] or 0),
                    float(bill[6] or 0),
                    float(bill[7] or 0),
                    refund_amount,
                    reason,
                    return_date,
                    str(session.get('user_id')),
                    created_at,
                )
            )
            db.execute(
                '''
                UPDATE test_bills
                SET subtotal = 0,
                    discount_amount = 0,
                    total_amount = 0,
                    received_amount = 0,
                    due_amount = 0,
                    change_amount = 0,
                    sample_status = 'Returned',
                    remarks = CASE
                        WHEN remarks IS NULL OR remarks = '' THEN ?
                        ELSE remarks || ' | ' || ?
                    END
                WHERE id = ?
                ''',
                (f'Returned on {return_no}', f'Returned on {return_no}', test_bill_id_value)
            )
            db.commit()
            add_log(int(bill[2]), f"Pathology bill returned: {bill[1]} ({return_no})")
            return redirect(url_for('test_return', bill_id=test_bill_id_value, success=f'{return_no} saved successfully.'))
        except sqlite3.IntegrityError:
            db.rollback()
            return redirect(url_for('test_return', bill_id=test_bill_id_value, message='This pathology bill return is already saved.'))
        except sqlite3.Error:
            db.rollback()
            return redirect(url_for('test_return', bill_id=test_bill_id_value, message='Could not save this pathology return. Please try again.'))

    selected_bill = None
    selected_items = []
    if selected_bill_id.isdigit() or query:
        if selected_bill_id.isdigit():
            bill_where = 'tb.id = ?'
            bill_params = [int(selected_bill_id)]
        else:
            bill_where = '''
                tb.invoice_no = ?
                OR CAST(tb.id AS TEXT) = ?
                OR p.phone = ?
                OR p.name LIKE ?
                OR CAST(COALESCE(p.source_patient_id, p.id) AS TEXT) = ?
                OR CAST(COALESCE(p.daily_patient_id, '') AS TEXT) = ?
            '''
            bill_params = [query, query, query, f'%{query}%', query, query]

        selected_bill = db.execute(
            f'''
            SELECT
                tb.id,
                tb.invoice_no,
                tb.patient_id,
                tb.subtotal,
                tb.discount_amount,
                tb.total_amount,
                tb.received_amount,
                tb.due_amount,
                tb.sample_status,
                tb.created_at,
                p.name,
                p.phone,
                p.address,
                COALESCE(p.source_patient_id, p.id) AS patient_uhid,
                p.daily_patient_id,
                tbr.return_no,
                tbr.refund_amount,
                tbr.reason,
                tbr.created_at,
                tbr.original_total_amount,
                tbr.original_due_amount,
                tbr.original_received_amount
            FROM test_bills tb
            JOIN patients p ON p.id = tb.patient_id
            LEFT JOIN test_bill_returns tbr ON tbr.test_bill_id = tb.id
            WHERE {bill_where}
            ORDER BY datetime(tb.created_at) DESC, tb.id DESC
            LIMIT 1
            ''',
            bill_params
        ).fetchone()

        if selected_bill:
            selected_items = db.execute(
                '''
                SELECT test_name, price
                FROM test_bill_items
                WHERE test_bill_id = ?
                ORDER BY id ASC
                ''',
                (selected_bill[0],)
            ).fetchall()
        else:
            message = message or 'No pathology bill found.'

    recent_returns = db.execute(
        '''
        SELECT return_no, invoice_no, patient_name, refund_amount, return_date, created_at
        FROM test_bill_returns
        ORDER BY datetime(created_at) DESC, id DESC
        LIMIT 12
        '''
    ).fetchall()

    return render_template(
        'test_return.html',
        query=query,
        selected_bill=selected_bill,
        selected_items=selected_items,
        recent_returns=recent_returns,
        message=message,
        success=success,
        admin=isadmin(),
    )


@app.route('/test-billing/collect-due/<int:test_bill_id>', methods=['POST'], endpoint='collect_test_due')
def collect_test_due(test_bill_id):
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    bill = db.execute(
        'SELECT id, patient_id, invoice_no, total_amount, received_amount, due_amount FROM test_bills WHERE id = ?',
        (test_bill_id,)
    ).fetchone()
    if not bill:
        return redirect(url_for('test_billing', message='Test bill not found.'))

    due_amount = float(bill[5] or 0)
    if due_amount <= 0:
        return redirect(url_for('test_billing', message='No due amount is pending for this bill.'))

    collection_amount = min(_to_positive_float(request.form.get('collection_amount')), due_amount)
    if collection_amount <= 0:
        return redirect(url_for('test_billing', message='Please enter a valid due collection amount.'))

    payment_method = request.form.get('payment_method', '').strip()
    new_received = float(bill[4] or 0) + collection_amount
    total_amount = float(bill[3] or 0)
    new_due = max(total_amount - new_received, 0)
    new_change = max(new_received - total_amount, 0)

    try:
        if payment_method:
            db.execute(
                '''
                UPDATE test_bills
                SET received_amount = ?, due_amount = ?, change_amount = ?, payment_method = ?
                WHERE id = ?
                ''',
                (new_received, new_due, new_change, payment_method, test_bill_id)
            )
        else:
            db.execute(
                '''
                UPDATE test_bills
                SET received_amount = ?, due_amount = ?, change_amount = ?
                WHERE id = ?
                ''',
                (new_received, new_due, new_change, test_bill_id)
            )
        db.commit()
        add_log(int(bill[1]), f"Test due collection recorded: {bill[2]} (+{collection_amount:.2f})")
        return redirect(url_for('test_bill_print', test_bill_id=test_bill_id))
    except sqlite3.Error:
        db.rollback()
        return redirect(url_for('test_billing', message='Due collection could not be saved. Please try again.'))


@app.route('/due', endpoint='due')
@app.route('/test-billing/due-collection', endpoint='test_due_collection')
def test_due_collection():
    """Focused pathology due collection desk."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    keyword = request.args.get('keyword', '').strip()
    sort = request.args.get('sort', 'newest')
    sort_options = {
        'newest': 'datetime(tb.created_at) DESC, tb.id DESC',
        'oldest': 'datetime(tb.created_at) ASC, tb.id ASC',
        'highest': 'tb.due_amount DESC, datetime(tb.created_at) DESC',
        'patient': 'p.name COLLATE NOCASE ASC, datetime(tb.created_at) DESC',
    }
    order_clause = sort_options.get(sort, sort_options['newest'])

    where_clauses = ['tb.due_amount > 0']
    params = []
    if keyword:
        like_keyword = f'%{keyword}%'
        where_clauses.append(
            '''
            (
                tb.invoice_no LIKE ?
                OR p.name LIKE ?
                OR p.phone LIKE ?
                OR tb.doctor_name LIKE ?
                OR EXISTS (
                    SELECT 1
                    FROM test_bill_items tbi_search
                    WHERE tbi_search.test_bill_id = tb.id
                      AND tbi_search.test_name LIKE ?
                )
            )
            '''
        )
        params.extend([like_keyword, like_keyword, like_keyword, like_keyword, like_keyword])

    where_sql = ' AND '.join(where_clauses)
    due_rows = db.execute(
        f'''
        SELECT
            tb.id,
            tb.invoice_no,
            tb.total_amount,
            tb.received_amount,
            tb.due_amount,
            tb.payment_method,
            tb.created_at,
            p.name,
            p.phone,
            COALESCE(p.source_patient_id, p.id) AS patient_uhid,
            p.daily_patient_id,
            tb.doctor_name,
            GROUP_CONCAT(tbi.test_name, ', ') AS test_names
        FROM test_bills tb
        JOIN patients p ON p.id = tb.patient_id
        LEFT JOIN test_bill_items tbi ON tbi.test_bill_id = tb.id
        WHERE {where_sql}
        GROUP BY tb.id
        ORDER BY {order_clause}
        LIMIT 120
        ''',
        params
    ).fetchall()

    due_bills = [
        {
            'id': row[0],
            'invoice_no': row[1],
            'total_amount': float(row[2] or 0),
            'received_amount': float(row[3] or 0),
            'due_amount': float(row[4] or 0),
            'payment_method': row[5] or 'Cash',
            'created_at': row[6],
            'patient_name': row[7],
            'phone': row[8],
            'patient_uhid': row[9],
            'daily_patient_id': row[10],
            'doctor_name': row[11] or 'Not assigned',
            'test_names': row[12] or 'No test items found',
        }
        for row in due_rows
    ]

    summary_row = db.execute(
        '''
        SELECT
            COUNT(*),
            COALESCE(SUM(due_amount), 0),
            COALESCE(SUM(CASE WHEN received_amount > 0 THEN 1 ELSE 0 END), 0),
            MIN(created_at)
        FROM test_bills
        WHERE due_amount > 0
        '''
    ).fetchone()
    today_due = db.execute(
        '''
        SELECT COALESCE(SUM(due_amount), 0)
        FROM test_bills
        WHERE due_amount > 0
          AND date(created_at) = date('now', '+6 hours')
        '''
    ).fetchone()[0]

    summary = {
        'pending_count': int(summary_row[0] or 0),
        'total_due': float(summary_row[1] or 0),
        'partial_count': int(summary_row[2] or 0),
        'oldest_due_date': summary_row[3],
        'today_due': float(today_due or 0),
    }

    return render_template(
        'test_due_collection.html',
        due_bills=due_bills,
        summary=summary,
        keyword=keyword,
        sort=sort,
        message=request.args.get('message')
    )


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

if __name__ == '__main__':
    app_host = os.environ.get('PULSE_HMS_HOST', '127.0.0.1')
    app_port = int(os.environ.get('PULSE_HMS_PORT', '5000'))
    app_debug = os.environ.get('PULSE_HMS_DEBUG', '1') == '1'
    app.run(host=app_host, port=app_port, debug=app_debug, use_reloader=app_debug, threaded=True)
