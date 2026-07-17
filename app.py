from flask import Flask, render_template, request, redirect, session, url_for, send_from_directory, jsonify
import sqlite3
from datetime import datetime, timedelta
import time
import os
import json
import math
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

root_admin_username = "admin"
root_admin_password = "admin123"  # In a production environment, use a strong password and consider storing it securely (e.g., in environment variables or a secure vault)

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
    {'key': 'dashboard', 'label': 'Dashboard', 'endpoint': 'dashboard', 'icon': 'fas fa-home', 'category': 'General'},
    {'key': 'follow_up_dashboard', 'label': 'Follow Up Dashboard', 'endpoint': 'follow_up_dashboard', 'icon': 'fas fa-clipboard-list', 'category': 'General'},

    {'key': 'patients_registration', 'label': 'Patients Registration', 'endpoint': 'patients_registration', 'icon': 'fas fa-user-plus', 'category': 'Patients'},
    {'key': 'patients_info', 'label': 'Patients Information', 'endpoint': 'patients_info', 'icon': 'fas fa-address-card', 'category': 'Patients'},
    {'key': 'patient_reports', 'label': 'Reports', 'endpoint': 'patient_reports', 'icon': 'fas fa-chart-column', 'category': 'Patients'},
    {'key': 'visit_return', 'label': 'Patient Visit Return', 'endpoint': 'visit_return', 'icon': 'fas fa-rotate-left', 'category': 'Patients'},
    {'key': 'ticket_print', 'label': 'Patient Ticket Print', 'endpoint': None, 'icon': 'fas fa-ticket', 'nav': False, 'category': 'Patients'},

    {'key': 'doctors', 'label': 'Doctors', 'endpoint': 'doctors', 'icon': 'fas fa-user-md', 'category': 'Doctors & Duty'},
    {'key': 'add_doctor', 'label': 'Add Doctor', 'endpoint': 'add_doctor', 'icon': 'fas fa-user-doctor', 'category': 'Doctors & Duty'},
    {'key': 'edit_doctor', 'label': 'Edit Doctor', 'endpoint': None, 'icon': 'fas fa-user-pen', 'nav': False, 'category': 'Doctors & Duty'},
    {'key': 'delete_doctor', 'label': 'Delete Doctor', 'endpoint': None, 'icon': 'fas fa-user-xmark', 'nav': False, 'category': 'Doctors & Duty'},
    {'key': 'doctor_prescription', 'label': 'Doctor Prescription', 'endpoint': 'doctor_prescription', 'icon': 'fas fa-prescription-bottle-medical', 'category': 'Doctors & Duty'},
    {'key': 'doctor_prescription_print', 'label': 'Prescription Print', 'endpoint': None, 'icon': 'fas fa-print', 'nav': False, 'category': 'Doctors & Duty'},
    {'key': 'doctor_prescription_list', 'label': 'Prescription List', 'endpoint': 'doctor_prescription_list', 'icon': 'fas fa-list', 'category': 'Doctors & Duty'},
    {'key': 'patients_serial', 'label': 'Patients Serial', 'endpoint': 'patients_serial', 'icon': 'fas fa-tv', 'category': 'Doctors & Duty'},
    {'key': 'hospital_advertisement', 'label': 'Hospital Advertisement', 'endpoint': 'hospital_advertisement', 'icon': 'fas fa-bullhorn', 'category': 'Doctors & Duty'},
    {'key': 'duty_management', 'label': 'Doctor and Nurse Duty', 'endpoint': 'duty_management', 'icon': 'fas fa-clipboard-check', 'category': 'Doctors & Duty'},
    {'key': 'duty_management_dashboard', 'label': 'Duty Management Dashboard', 'endpoint': 'duty_management_dashboard', 'icon': 'fas fa-chart-column', 'category': 'Doctors & Duty'},

    {'key': 'admissions', 'label': 'Patient Admission', 'endpoint': 'admissions', 'icon': 'fas fa-file-medical', 'category': 'Admission'},
    {'key': 'admission_form_print', 'label': 'Admission Form Print', 'endpoint': None, 'icon': 'fas fa-print', 'nav': False, 'category': 'Admission'},
    {'key': 'concern_paper', 'label': 'Concern Paper', 'endpoint': None, 'icon': 'fas fa-file-signature', 'nav': False, 'category': 'Admission'},
    {'key': 'discharge_bill', 'label': 'Discharge Bill', 'endpoint': 'discharge_bill', 'icon': 'fas fa-file-invoice-dollar', 'category': 'Admission'},
    {'key': 'discharge_patients_list', 'label': 'Discharged Patients List', 'endpoint': 'discharge_patients_list', 'icon': 'fas fa-clipboard-list', 'category': 'Admission'},

    {'key': 'pathology_dashboard', 'label': 'Pathology Dashboard', 'endpoint': 'pathology_dashboard', 'icon': 'fas fa-microscope', 'category': 'Pathology & Tests'},
    {'key': 'pathology_result_print', 'label': 'Pathology Result Print', 'endpoint': None, 'icon': 'fas fa-print', 'nav': False, 'category': 'Pathology & Tests'},
    {'key': 'test_billing', 'label': 'Test Billing', 'endpoint': 'test_billing', 'icon': 'fas fa-file-medical-alt', 'category': 'Pathology & Tests'},
    {'key': 'test_bill_print', 'label': 'Test Bill Print', 'endpoint': None, 'icon': 'fas fa-print', 'nav': False, 'category': 'Pathology & Tests'},
    {'key': 'test_return', 'label': 'Test Return', 'endpoint': 'test_return', 'icon': 'fas fa-rotate-left', 'category': 'Pathology & Tests'},
    {'key': 'tests', 'label': 'View Tests', 'endpoint': 'tests', 'icon': 'fas fa-vial', 'category': 'Pathology & Tests'},
    {'key': 'test_due_collection', 'label': 'Test Due Collection', 'endpoint': 'test_due_collection', 'icon': 'fas fa-hand-holding-dollar', 'category': 'Pathology & Tests'},

    {'key': 'medicine_stock_dashboard', 'label': 'Medicine Stock', 'endpoint': 'medicine_stock_dashboard', 'icon': 'fas fa-boxes-stacked', 'category': 'Medicine'},
    {'key': 'medicine_sales', 'label': 'Medicine Sales', 'endpoint': 'medicine_sales', 'icon': 'fas fa-pills', 'category': 'Medicine'},
    {'key': 'medicine_sales_print', 'label': 'Medicine Sales Print', 'endpoint': None, 'icon': 'fas fa-print', 'nav': False, 'category': 'Medicine'},
    {'key': 'medicine_sales_list', 'label': 'Medicine Sales List', 'endpoint': 'medicine_sales_list', 'icon': 'fas fa-calendar-days', 'category': 'Medicine'},
    {'key': 'medicine_monthly_report', 'label': 'Medicine Monthly Report', 'endpoint': 'medicine_monthly_report', 'icon': 'fas fa-chart-column', 'category': 'Medicine'},
    {'key': 'medicine_return', 'label': 'Medicine Return', 'endpoint': 'medicine_return', 'icon': 'fas fa-rotate-left', 'category': 'Medicine'},
    {'key': 'medicine_payments', 'label': 'Medicine Payments', 'endpoint': 'medicine_payments', 'icon': 'fas fa-money-check-dollar', 'category': 'Medicine'},

    {'key': 'daily_expenses', 'label': 'Daily Expenses', 'endpoint': 'daily_expenses', 'icon': 'fas fa-wallet', 'category': 'Accounts'},
    {'key': 'daily_expenses_print', 'label': 'Daily Expenses Print', 'endpoint': 'daily_expenses_print', 'icon': 'fas fa-print', 'category': 'Accounts'},
    {'key': 'due_collection', 'label': 'Due Collection', 'endpoint': 'due_collection_hub', 'icon': 'fas fa-hand-holding-dollar', 'category': 'Accounts'},
    {'key': 'all_transation', 'label': 'All Transactions', 'endpoint': 'all_transation', 'icon': 'fas fa-chart-pie', 'category': 'Accounts'},
    {'key': 'all_transation_print', 'label': 'All Transactions Print', 'endpoint': 'all_transation_print', 'icon': 'fas fa-print', 'category': 'Accounts'},

    {'key': 'services', 'label': 'Service Catalog', 'endpoint': 'services', 'icon': 'fas fa-procedures', 'category': 'Services'},
    {'key': 'add_service', 'label': 'Add Service', 'endpoint': 'add_service', 'icon': 'fas fa-plus', 'category': 'Services'},
    {'key': 'edit_service', 'label': 'Edit Service', 'endpoint': None, 'icon': 'fas fa-pen', 'nav': False, 'category': 'Services'},
]
DASHBOARD_NAV_KEYS = (
    'dashboard',
    'patients_registration',
    'patient_reports',
    'doctors',
    'doctor_prescription',
    'patients_serial',
    'duty_management',
    'admissions',
    'pathology_dashboard',
    'test_billing',
    'tests',
    'medicine_sales',
    'daily_expenses',
    'due_collection',
    'all_transation',
    'medicine_stock_dashboard',
)
PAGE_KEYS = [page['key'] for page in PAGE_OPTIONS]
PAGE_BY_KEY = {page['key']: page for page in PAGE_OPTIONS}
PERMISSION_GROUPS = []
for permission_page in PAGE_OPTIONS:
    permission_category = permission_page.get('category', 'Other')
    permission_group = next((group for group in PERMISSION_GROUPS if group['name'] == permission_category), None)
    if permission_group is None:
        permission_group = {'name': permission_category, 'pages': []}
        PERMISSION_GROUPS.append(permission_group)
    permission_group['pages'].append(permission_page)

ENDPOINT_PERMISSIONS = {
    'dashboard': ('dashboard',),
    'due_collection_hub': ('due_collection',),
    'doctor_fee_due_collection': ('due_collection',),
    'collect_doctor_fee_due': ('due_collection',),
    'admin_portal': ('admin_portal',),
    'follow_up_dashboard': ('follow_up_dashboard',),
    'register': ('register',),
    'registered_users': ('registered_users',),
    'logs': ('logs',),
    'patients_registration': ('patients_registration',),
    'patient_reports': ('patient_reports',),
    'patient_reports_print': ('patient_reports',),
    'patients_info': ('patients_info',),
    'edit_patient_profile': ('patients_info',),
    'patient_details_bill': ('patient_reports',),
    'patient_visits_print': ('patient_reports',),
    'patient_pathology_print': ('patient_reports',),
    'visit_return': ('visit_return',),
    'patient': ('patients_registration',),
    'add_patient': ('patients_registration',),
    'delete_patient': ('patients_registration',),
    'search_registered_patient': ('patients_registration',),
    'ticket_print': ('ticket_print',),
    'tickets': ('patients_registration',),
    'doctors': ('doctors',),
    'doctor_prescription': ('doctor_prescription',),
    'saved_doctor_prescription': ('doctor_prescription',),
    'doctor_prescription_print': ('doctor_prescription_print',),
    'doctor_prescription_list': ('doctor_prescription_list',),
    'save_doctor_prescription_draft': ('doctor_prescription',),
    'get_doctor_prescription_draft': ('doctor_prescription',),
    'patients_serial': ('patients_serial',),
    'patients_serial_status': ('patients_serial', 'doctor_prescription'),
    'hospital_advertisement': ('hospital_advertisement',),
    'upload_hospital_advertisement': ('hospital_advertisement',),
    'advance_patient_serial': ('doctor_prescription',),
    'duty_management': ('duty_management',),
    'duty_management_dashboard': ('duty_management_dashboard',),
    'add_doctor': ('add_doctor',),
    'edit_doctor': ('edit_doctor',),
    'delete_doctor': ('delete_doctor',),
    'admissions': ('admissions',),
    'admission_details': ('admissions',),
    'search_old_admitted_patient': ('admissions',),
    'admission_form_print': ('admission_form_print',),
    'concern_paper': ('concern_paper',),
    'discharge_bill': ('discharge_bill',),
    'discharge_bill_print': ('discharge_bill',),
    'discharge_due_collection': ('discharge_bill', 'due_collection'),
    'discharge_due_details': ('discharge_bill', 'due_collection'),
    'collect_discharge_due': ('discharge_bill', 'due_collection'),
    'saved_discharge_bill_print': ('discharge_bill', 'due_collection'),
    'discharge_patients_list': ('discharge_patients_list',),
    'discharge_admission': ('admissions',),
    'pathology_dashboard': ('pathology_dashboard',),
    'update_pathology_status': ('pathology_dashboard',),
    'save_pathology_result': ('pathology_dashboard',),
    'pathology_result_print': ('pathology_result_print', 'patient_reports'),
    'test_billing': ('test_billing',),
    'patient_prescribed_tests': ('test_billing',),
    'test_bill_details': ('test_billing',),
    'test_bill_print': ('test_bill_print', 'due_collection'),
    'test_return': ('test_return',),
    'due': ('test_due_collection', 'due_collection'),
    'test_due_collection': ('test_due_collection', 'due_collection'),
    'test_due_details': ('test_due_collection', 'due_collection'),
    'collect_test_due': ('test_due_collection', 'due_collection'),
    'tests': ('tests',),
    'medicine_stock_dashboard': ('medicine_stock_dashboard',),
    'edit_medicine_transaction': ('medicine_stock_dashboard',),
    'delete_medicine_transaction': ('medicine_stock_dashboard',),
    'delete_medicine_balance': ('medicine_stock_dashboard',),
    'medicine_sales': ('medicine_sales',),
    'save_medicine_sale': ('medicine_sales',),
    'daily_expenses': ('daily_expenses',),
    'daily_expenses_print': ('daily_expenses_print',),
    'all_transation': ('all_transation',),
    'all_transation_print': ('all_transation_print',),
    'delete_daily_expense': ('daily_expenses',),
    'medicine_sales_print': ('medicine_sales_print',),
    'medicine_sales_list': ('medicine_sales_list',),
    'medicine_sales_list_print': ('medicine_sales_list',),
    'medicine_monthly_report': ('medicine_monthly_report',),
    'medicine_return': ('medicine_return',),
    'medicine_payments': ('medicine_payments', 'medicine_sales', 'medicine_stock_dashboard'),
    'medicine_stock_movements': ('medicine_stock_dashboard',),
    'delete_medicine_monthly_day_sales': ('medicine_monthly_report',),
    'delete_medicine_monthly_product_sales': ('medicine_monthly_report',),
    'delete_medicine_sale': ('medicine_sales_list',),
    'services': ('services',),
    'add_service': ('add_service',),
    'edit_service': ('edit_service',),
    'delete_service': ('services',),
}

APP_TIME_OFFSET = timedelta(hours=6)


def current_app_datetime():
    """Return the hospital-local current time used by SQLite '+6 hours' timestamps."""
    return datetime.utcnow() + APP_TIME_OFFSET


def current_timestamp_text():
    return current_app_datetime().strftime('%Y-%m-%d %H:%M:%S')


def current_calendar_date_text():
    return current_app_datetime().strftime('%Y-%m-%d')


def current_admission_date_text(now=None):
    """Use the next calendar date for admissions created from 12:00 PM onward."""
    admission_datetime = now or current_app_datetime()
    if admission_datetime.hour >= 12:
        admission_datetime += timedelta(days=1)
    return admission_datetime.strftime('%Y-%m-%d')


def current_calendar_month_text():
    return current_app_datetime().strftime('%Y-%m')


def current_invoice_date_code():
    return current_app_datetime().strftime('%y%m%d')


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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS app_migrations (
            migration_key TEXT PRIMARY KEY,
            applied_at TEXT NOT NULL
        )
    ''')
    permission_expansion_key = 'expand_all_page_permissions_v1'
    permission_expansion_done = cursor.execute(
        'SELECT 1 FROM app_migrations WHERE migration_key = ?',
        (permission_expansion_key,)
    ).fetchone()
    if not permission_expansion_done:
        inherited_permissions = {
            'patients_registration': ('patients_info', 'patient_reports', 'visit_return', 'ticket_print'),
            'doctors': ('add_doctor', 'edit_doctor'),
            'doctor_prescription': ('doctor_prescription_print', 'doctor_prescription_list'),
            'patients_serial': ('hospital_advertisement',),
            'duty_management': ('duty_management_dashboard',),
            'admissions': ('admission_form_print', 'concern_paper', 'discharge_bill', 'discharge_patients_list'),
            'pathology_dashboard': ('pathology_result_print',),
            'test_billing': ('test_bill_print', 'test_return', 'test_due_collection'),
            'medicine_sales': ('medicine_sales_print', 'medicine_sales_list', 'medicine_monthly_report', 'medicine_return'),
            'daily_expenses': ('daily_expenses_print',),
            'all_transation': ('all_transation_print',),
            'services': ('add_service', 'edit_service'),
        }
        for parent_key, child_keys in inherited_permissions.items():
            user_ids = cursor.execute(
                'SELECT user_id FROM user_permissions WHERE page_key = ?',
                (parent_key,)
            ).fetchall()
            for (permission_user_id,) in user_ids:
                for child_key in child_keys:
                    cursor.execute(
                        'INSERT OR IGNORE INTO user_permissions (user_id, page_key) VALUES (?, ?)',
                        (permission_user_id, child_key)
                    )
        cursor.execute(
            "INSERT INTO app_migrations (migration_key, applied_at) VALUES (?, datetime('now', '+6 hours'))",
            (permission_expansion_key,)
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
                doctor_fee REAL DEFAULT 0,
                doctor_paid_amount REAL DEFAULT 0,
                doctor_due_amount REAL DEFAULT 0,
                source_patient_id INTEGER,
                served_by TEXT NOT NULL
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
        if 'doctor_paid_amount' not in patients_columns:
            cursor.execute("ALTER TABLE patients ADD COLUMN doctor_paid_amount REAL DEFAULT 0")
            cursor.execute("UPDATE patients SET doctor_paid_amount = COALESCE(doctor_fee, 0)")
        if 'doctor_due_amount' not in patients_columns:
            cursor.execute("ALTER TABLE patients ADD COLUMN doctor_due_amount REAL DEFAULT 0")
            cursor.execute(
                "UPDATE patients SET doctor_due_amount = MAX(COALESCE(doctor_fee, 0) - COALESCE(doctor_paid_amount, 0), 0)"
            )
        if 'source_patient_id' not in patients_columns:
            cursor.execute("ALTER TABLE patients ADD COLUMN source_patient_id INTEGER")
        if 'served_by' not in patients_columns:
            cursor.execute("ALTER TABLE patients ADD COLUMN served_by TEXT NOT NULL DEFAULT ''")
        cursor.execute("UPDATE patients SET served_by = 'Admin' WHERE served_by IS NULL OR served_by = ''")

        patients_missing_daily_id = cursor.execute('''
            SELECT id, COALESCE(date(created_at), ?) AS entry_date
            FROM patients
            WHERE daily_patient_id IS NULL OR daily_patient_id = ''
            ORDER BY entry_date ASC, id ASC
        ''', (current_calendar_date_text(),)).fetchall()
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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS doctor_fee_due_collections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            previous_due REAL NOT NULL,
            collection_amount REAL NOT NULL DEFAULT 0,
            discount_amount REAL NOT NULL DEFAULT 0,
            remaining_due REAL NOT NULL DEFAULT 0,
            payment_method TEXT NOT NULL DEFAULT 'Cash',
            note TEXT,
            collected_by TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (patient_id) REFERENCES patients(id)
        )
    ''')

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
                room_number TEXT NOT NULL,
                consultation_fee REAL NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1
            )
        ''')
        print("Doctors table created successfully.")
    else:
        doctors_columns = {row[1] for row in cursor.execute("PRAGMA table_info(doctors)").fetchall()}
        if 'designation' not in doctors_columns:
            cursor.execute("ALTER TABLE doctors ADD COLUMN designation TEXT")
            print("Doctors table migrated: designation column added.")
        if 'consultation_fee' not in doctors_columns:
            cursor.execute("ALTER TABLE doctors ADD COLUMN consultation_fee REAL NOT NULL DEFAULT 0")
            print("Doctors table migrated: consultation_fee column added.")
        if 'is_active' not in doctors_columns:
            cursor.execute("ALTER TABLE doctors ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
            print("Doctors table migrated: is_active column added.")

    #services table
    cursor.execute('SELECT name FROM sqlite_master WHERE type="table" AND name="services"')
    services_exists = cursor.fetchone() is not None
    if not services_exists:
        cursor.execute('''
            CREATE TABLE services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                type TEXT CHECK(type IN ('doctor','test')) NOT NULL,
                price REAL NOT NULL,
                sample_type TEXT,
                test_category TEXT,
                unit TEXT,
                reference_ranges TEXT,
                is_active INTEGER NOT NULL DEFAULT 1
            )
        ''')
        print("Services table created successfully.")
    else:
        services_columns = {row[1] for row in cursor.execute("PRAGMA table_info(services)").fetchall()}
        for column_name in ('sample_type', 'test_category', 'unit', 'reference_ranges'):
            if column_name not in services_columns:
                cursor.execute(f"ALTER TABLE services ADD COLUMN {column_name} TEXT")
                print(f"Services table migrated: {column_name} column added.")
        if 'is_active' not in services_columns:
            cursor.execute("ALTER TABLE services ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
            print("Services table migrated: is_active column added.")

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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS doctor_prescriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            prescription_no TEXT UNIQUE NOT NULL,
            prescription_date TEXT NOT NULL,
            patient_id INTEGER NOT NULL,
            doctor_id INTEGER NOT NULL,
            vitals_json TEXT,
            clinical_json TEXT,
            medicines_json TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY (patient_id) REFERENCES patients(id),
            FOREIGN KEY (doctor_id) REFERENCES doctors(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS doctor_prescription_drafts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL UNIQUE,
            doctor_id INTEGER,
            draft_json TEXT NOT NULL,
            updated_by TEXT,
            updated_at TEXT NOT NULL,
            FOREIGN KEY (patient_id) REFERENCES patients(id),
            FOREIGN KEY (doctor_id) REFERENCES doctors(id)
        )
    ''')

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
                admission_fee REAL NOT NULL,
                guardian_name TEXT,
                guardian_relation TEXT,
                reason TEXT NOT NULL,
                notes TEXT,
                status TEXT NOT NULL DEFAULT 'Admitted',
                discharged_at TEXT,
                created_by INTEGER,
                admitted_by TEXT NOT NULL,
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
            'admitted_by': "ALTER TABLE admissions ADD COLUMN admitted_by TEXT NOT NULL DEFAULT ''",
            'created_at': "ALTER TABLE admissions ADD COLUMN created_at TEXT NOT NULL DEFAULT ''",
            'guardian_name': 'ALTER TABLE admissions ADD COLUMN guardian_name TEXT',
            'guardian_relation': 'ALTER TABLE admissions ADD COLUMN guardian_relation TEXT',
            'admission_fee': 'ALTER TABLE admissions ADD COLUMN admission_fee REAL NOT NULL DEFAULT 0'
        }
        for column_name, alter_sql in admission_migrations.items():
            if column_name not in admission_columns:
                cursor.execute(alter_sql)
        cursor.execute("UPDATE admissions SET status = 'Admitted' WHERE status IS NULL OR status = ''")
        cursor.execute("UPDATE admissions SET created_at = datetime('now', '+6 hours') WHERE created_at IS NULL OR created_at = ''")
        cursor.execute('''
            UPDATE admissions
            SET admitted_by = CASE
                WHEN created_by IS NULL THEN 'Admin'
                ELSE COALESCE(
                    (SELECT username FROM admins WHERE admins.id = admissions.created_by),
                    (SELECT username FROM users WHERE users.id = admissions.created_by),
                    CAST(created_by AS TEXT),
                    'Staff'
                )
            END
            WHERE admitted_by IS NULL OR admitted_by = ''
        ''')

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
                payment_method TEXT NOT NULL DEFAULT 'Cash',
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
            'payment_method': "ALTER TABLE discharge_bills ADD COLUMN payment_method TEXT NOT NULL DEFAULT 'Cash'",
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
                description TEXT,
                vendor TEXT,
                amount REAL NOT NULL,
                payment_method TEXT NOT NULL DEFAULT 'Cash',
                note TEXT,
                created_by TEXT,
                created_at TEXT NOT NULL
            )
        ''')
        print("Daily Expenses table created successfully.")
    else:
        cursor.execute('PRAGMA table_info(daily_expenses)')
        daily_expenses_columns = {row[1]: row for row in cursor.fetchall()}
        description_column = daily_expenses_columns.get('description')
        if description_column and description_column[3]:
            cursor.execute('ALTER TABLE daily_expenses RENAME TO daily_expenses_old')
            cursor.execute('''
                CREATE TABLE daily_expenses (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    expense_date TEXT NOT NULL,
                    category TEXT NOT NULL,
                    description TEXT,
                    vendor TEXT,
                    amount REAL NOT NULL,
                    payment_method TEXT NOT NULL DEFAULT 'Cash',
                    note TEXT,
                    created_by TEXT,
                    created_at TEXT NOT NULL
                )
            ''')
            cursor.execute('''
                INSERT INTO daily_expenses (
                    id, expense_date, category, description, vendor, amount,
                    payment_method, note, created_by, created_at
                )
                SELECT id, expense_date, category, NULLIF(description, ''), vendor, amount,
                       payment_method, note, created_by, created_at
                FROM daily_expenses_old
            ''')
            cursor.execute('DROP TABLE daily_expenses_old')
            print("Daily Expenses description made optional successfully.")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS expense_categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL COLLATE NOCASE UNIQUE,
            created_at TEXT NOT NULL
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS patient_queue_state (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            doctor_id INTEGER NOT NULL,
            queue_date TEXT NOT NULL,
            current_patient_id INTEGER,
            current_ticket_no INTEGER,
            updated_by TEXT,
            updated_at TEXT NOT NULL,
            UNIQUE (doctor_id, queue_date),
            FOREIGN KEY (doctor_id) REFERENCES doctors(id),
            FOREIGN KEY (current_patient_id) REFERENCES patients(id)
        )
    ''')

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
                strips_per_box INTEGER NOT NULL DEFAULT 1,
                strip_price REAL,
                box_price REAL,
                box_quantity INTEGER,
                supplier TEXT,
                purchase_amount REAL NOT NULL DEFAULT 0,
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
        if 'strips_per_box' not in medicine_transactions_columns:
            cursor.execute("ALTER TABLE medicine_transactions ADD COLUMN strips_per_box INTEGER NOT NULL DEFAULT 1")
        if 'strip_price' not in medicine_transactions_columns:
            cursor.execute("ALTER TABLE medicine_transactions ADD COLUMN strip_price REAL")
        if 'box_price' not in medicine_transactions_columns:
            cursor.execute("ALTER TABLE medicine_transactions ADD COLUMN box_price REAL")
        if 'box_quantity' not in medicine_transactions_columns:
            cursor.execute("ALTER TABLE medicine_transactions ADD COLUMN box_quantity INTEGER")
        if 'supplier' not in medicine_transactions_columns:
            cursor.execute("ALTER TABLE medicine_transactions ADD COLUMN supplier TEXT")
        if 'purchase_amount' not in medicine_transactions_columns:
            cursor.execute("ALTER TABLE medicine_transactions ADD COLUMN purchase_amount REAL NOT NULL DEFAULT 0")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS medicine_supplier_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            supplier TEXT NOT NULL,
            amount REAL NOT NULL,
            discount_amount REAL NOT NULL DEFAULT 0,
            payment_date TEXT NOT NULL,
            note TEXT,
            created_by TEXT,
            created_at TEXT NOT NULL
        )
    ''')
    medicine_supplier_payment_columns = {
        row[1] for row in cursor.execute('PRAGMA table_info(medicine_supplier_payments)').fetchall()
    }
    if 'discount_amount' not in medicine_supplier_payment_columns:
        cursor.execute(
            'ALTER TABLE medicine_supplier_payments '
            'ADD COLUMN discount_amount REAL NOT NULL DEFAULT 0'
        )

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
                strips_per_unit INTEGER NOT NULL DEFAULT 1,
                discount REAL NOT NULL DEFAULT 0,
                line_total REAL NOT NULL DEFAULT 0,
                FOREIGN KEY (sale_id) REFERENCES medicine_sales(id)
            )
        ''')
        print("Medicine Sale Items table created successfully.")
    else:
        cursor.execute('PRAGMA table_info(medicine_sale_items)')
        medicine_sale_item_columns = {row[1] for row in cursor.fetchall()}
        if 'strips_per_unit' not in medicine_sale_item_columns:
            cursor.execute("ALTER TABLE medicine_sale_items ADD COLUMN strips_per_unit INTEGER NOT NULL DEFAULT 1")

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

    patient_server_backfill_key = 'patient_served_by_backfill_v1'
    patient_server_backfill_done = cursor.execute(
        'SELECT 1 FROM app_migrations WHERE migration_key = ?',
        (patient_server_backfill_key,)
    ).fetchone()
    if not patient_server_backfill_done:
        cursor.execute('''
            UPDATE patients
            SET served_by = COALESCE(
                NULLIF((
                    SELECT actor_name
                    FROM logs
                    WHERE logs.patient_id = patients.id
                      AND NULLIF(TRIM(COALESCE(logs.actor_name, '')), '') IS NOT NULL
                    ORDER BY logs.id ASC
                    LIMIT 1
                ), ''),
                NULLIF(served_by, ''),
                'Admin'
            )
        ''')
        cursor.execute(
            "INSERT INTO app_migrations (migration_key, applied_at) VALUES (?, datetime('now', '+6 hours'))",
            (patient_server_backfill_key,)
        )

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
    if session.get('role') == 'user':
        return False
    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (user_id,)).fetchone()
    return bool(admin_checker and admin_checker[0] == user_id)

def isuser():
    """Helper function to check if the current user is a regular user."""
    user_id = _current_session_user_id()
    if not user_id:
        return False
    if session.get('role') == 'admin' or user_id == 'root_admin':
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
        'permission_groups': PERMISSION_GROUPS,
        'can_access_page': can_access_page,
        'format_uhid': format_uhid,
        'format_date_display': format_date_display,
        'format_invoice_date': format_invoice_date,
        'format_month_display': format_month_display,
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

    session_role = session.get('role')
    if session_role == 'user':
        user_checker = db.execute('SELECT username FROM users WHERE id=?', (user_id,)).fetchone()
        return user_id, 'user', user_checker[0] if user_checker else 'Unknown user'

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


def parse_stored_datetime(value):
    """Parse common stored date/time strings without changing database storage."""
    if not value:
        return None

    text_value = str(value).strip()
    for date_format in (
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%d %H:%M:%S.%f',
        '%Y-%m-%dT%H:%M:%S.%f',
        '%Y-%m-%d %H:%M',
        '%Y-%m-%dT%H:%M',
        '%Y-%m-%d',
    ):
        try:
            return datetime.strptime(text_value, date_format)
        except ValueError:
            continue

    return None


def has_time_component(value):
    text_value = str(value or '').strip()
    return ' ' in text_value or 'T' in text_value


def format_date_part(date_value):
    return date_value.strftime('%d %B %Y').lstrip('0')


def format_time_part(date_value):
    return date_value.strftime('%I:%M %p').lstrip('0')


def format_invoice_datetime(value):
    """Format stored ISO-like dates as 11 July 2026 03:25 PM for printable invoices."""
    date_value = parse_stored_datetime(value)
    if not date_value:
        return '-' if not value else str(value).strip()

    if has_time_component(value):
        return f"{format_date_part(date_value)} {format_time_part(date_value)}"
    return format_date_part(date_value)

def format_invoice_date(value):
    """Format stored ISO-like dates as 11 July 2026 without time."""
    date_value = parse_stored_datetime(value)
    if not date_value:
        return '-' if not value else str(value).strip()
    return format_date_part(date_value)

def format_date_display(value):
    """Format date text as 11 July 2026, preserving 12-hour time when present."""
    return format_invoice_datetime(value)


def format_uhid(value):
    """Display the numeric patient key as the hospital-facing AJH UHID."""
    if value is None or str(value).strip() == '':
        return '-'

    text_value = str(value).strip()
    if text_value.upper().startswith('AJH'):
        return f"AJH{text_value[3:].strip()}"
    return f"AJH{text_value}"


def normalize_uhid_search(value):
    """Let users search numeric patient IDs with or without the AJH prefix."""
    text_value = str(value or '').strip()
    if text_value.upper().startswith('AJH') and text_value[3:].strip().isdigit():
        return text_value[3:].strip()
    return text_value


def format_month_display(value):
    """Format a YYYY-MM or ISO-like date value as July 2026."""
    if not value:
        return '-'

    text_value = str(value).strip()
    for date_format in ('%Y-%m', '%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S'):
        try:
            return datetime.strptime(text_value, date_format).strftime('%B %Y')
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
        SELECT id, medicine_name, batch_no, unit_type, transaction_type, quantity, price,
               transaction_date, note, created_by, created_at, strips_per_box,
               strip_price, box_price, box_quantity, supplier
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
            'strips_per_box': max(int(row[11] or 1), 1),
            'strip_price': float(row[12] if row[12] is not None else row[6] or 0),
            'box_price': float(row[13] if row[13] is not None else 0),
            'latest_box_quantity': int(row[14] or 0),
            'supplier': row[15] or '',
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

        if row[4] == 'in' and not is_medicine_return_stock_note(row[8]):
            medicine_summary['latest_price'] = row[6]
            medicine_summary['latest_date'] = row[7]
            if int(row[11] or 1) > 1:
                medicine_summary['strips_per_box'] = int(row[11])
            if row[12] is not None:
                medicine_summary['strip_price'] = float(row[12])
            if row[13] is not None:
                medicine_summary['box_price'] = float(row[13])
            if row[14] is not None:
                medicine_summary['latest_box_quantity'] = int(row[14])
            if row[15]:
                medicine_summary['supplier'] = row[15]

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
                        session['role'] = 'admin'
                    else:
                        session['user_id'] = admin_checker[0]  # Store admin_id in session
                        session['role'] = 'admin'
                    return redirect(url_for('admin_portal', admin_success="admin login successful"))  # Redirect to the admin portal page after successful login
                else:
                    session['user_id'] = user_checker[0]  # Store user_id in session
                    session['role'] = 'user'
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
    """Daily operational dashboard for accounts granted follow-up access."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (session.get('user_id'),)).fetchone()
    user_checker = db.execute('SELECT * FROM users WHERE id = ?', (session.get('user_id'),)).fetchone()
    if session.get('user_id') == 'root_admin':
        profile_name = root_admin_username
    elif isadmin() and admin_checker:
        profile_name = admin_checker[1]
    else:
        profile_name = user_checker[1] if user_checker else 'User'

    selected_date = request.args.get('date', '').strip() or current_calendar_date_text()
    try:
        datetime.strptime(selected_date, '%Y-%m-%d')
    except ValueError:
        selected_date = current_calendar_date_text()

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

    selected_date = request.args.get('date', '').strip() or current_calendar_date_text()
    try:
        datetime.strptime(selected_date, '%Y-%m-%d')
    except ValueError:
        selected_date = current_calendar_date_text()

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
        doctor_count = db.execute('SELECT COUNT(*) FROM doctors WHERE COALESCE(is_active, 1) = 1').fetchone()[0]
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


def build_patient_report(filters):
    """Build a filterable patient registration and consultation billing report."""
    today = current_calendar_date_text()

    def valid_date(value, fallback):
        value = (value or '').strip()
        try:
            return datetime.strptime(value, '%Y-%m-%d').strftime('%Y-%m-%d')
        except ValueError:
            return fallback

    from_date = valid_date(filters.get('from_date'), today)
    to_date = valid_date(filters.get('to_date'), today)
    if from_date > to_date:
        from_date, to_date = to_date, from_date

    keyword = (filters.get('keyword') or '').strip()
    doctor_name = (filters.get('doctor') or '').strip()
    patient_status = (filters.get('patient_status') or 'all').strip().upper()
    payment_status = (filters.get('payment_status') or 'all').strip().lower()
    if patient_status not in ('ALL', 'NEW', 'OLD'):
        patient_status = 'ALL'
    if payment_status not in ('all', 'paid', 'due', 'unbilled'):
        payment_status = 'all'

    where_clauses = ['date(p.created_at) BETWEEN ? AND ?']
    params = [from_date, to_date]
    normalized_keyword = normalize_uhid_search(keyword)
    if keyword.upper().startswith('AJH') and normalized_keyword.isdigit():
        where_clauses.append('COALESCE(p.source_patient_id, p.id) = ?')
        params.append(int(normalized_keyword))
    elif keyword:
        like_keyword = f'%{keyword}%'
        where_clauses.append('''
            (p.name LIKE ? OR p.phone LIKE ? OR p.doctor_name LIKE ?
             OR CAST(p.daily_patient_id AS TEXT) LIKE ?)
        ''')
        params.extend([like_keyword] * 4)
    if doctor_name:
        where_clauses.append('TRIM(p.doctor_name) = TRIM(?) COLLATE NOCASE')
        params.append(doctor_name)
    if patient_status != 'ALL':
        where_clauses.append('UPPER(COALESCE(p.patient_status, \'\')) = ?')
        params.append(patient_status)
    if payment_status == 'paid':
        where_clauses.append('COALESCE(p.doctor_fee, 0) > 0 AND COALESCE(p.doctor_due_amount, 0) <= 0')
    elif payment_status == 'due':
        where_clauses.append('COALESCE(p.doctor_due_amount, 0) > 0')
    elif payment_status == 'unbilled':
        where_clauses.append('COALESCE(p.doctor_fee, 0) <= 0')

    rows = db.execute(
        f'''
        SELECT p.id, COALESCE(p.source_patient_id, p.id), p.daily_patient_id,
               p.name, p.age, COALESCE(NULLIF(p.age_unit, ''), 'Y'), p.gender,
               p.phone, p.address, COALESCE(p.patient_status, '-'),
               COALESCE(NULLIF(p.doctor_name, ''), 'Not assigned'),
               COALESCE(p.doctor_fee, 0), COALESCE(p.doctor_paid_amount, 0),
               COALESCE(p.doctor_due_amount, 0),
               COALESCE(NULLIF(p.served_by, ''), 'Admin'), p.created_at
        FROM patients p
        WHERE {' AND '.join(where_clauses)}
        ORDER BY datetime(p.created_at) DESC, p.id DESC
        ''',
        params
    ).fetchall()
    report_rows = [
        {
            'id': row[0], 'uhid': row[1], 'ticket_no': row[2], 'name': row[3],
            'age': row[4], 'age_unit': row[5], 'gender': row[6] or '-',
            'phone': row[7] or '-', 'address': row[8] or '-', 'patient_status': row[9],
            'doctor_name': row[10], 'doctor_fee': float(row[11] or 0),
            'paid_amount': float(row[12] or 0), 'due_amount': float(row[13] or 0),
            'served_by': row[14], 'created_at': row[15],
        }
        for row in rows
    ]
    summary = {
        'visit_count': len(report_rows),
        'patient_count': len({row['uhid'] for row in report_rows}),
        'total_billing': sum(row['doctor_fee'] for row in report_rows),
        'total_paid': sum(row['paid_amount'] for row in report_rows),
        'total_due': sum(row['due_amount'] for row in report_rows),
        'new_count': sum(1 for row in report_rows if row['patient_status'].upper() == 'NEW'),
        'old_count': sum(1 for row in report_rows if row['patient_status'].upper() == 'OLD'),
    }
    doctor_options = [row[0] for row in db.execute('''
        SELECT DISTINCT TRIM(doctor_name)
        FROM patients
        WHERE NULLIF(TRIM(COALESCE(doctor_name, '')), '') IS NOT NULL
        ORDER BY TRIM(doctor_name) COLLATE NOCASE
    ''').fetchall()]
    clean_filters = {
        'from_date': from_date,
        'to_date': to_date,
        'keyword': keyword,
        'doctor': doctor_name,
        'patient_status': patient_status.lower(),
        'payment_status': payment_status,
    }
    return report_rows, summary, doctor_options, clean_filters


def build_pathology_report_sections(filters):
    """Build Step 1 patient cases and Step 2 tests for the Reports page."""
    where_clauses = ['date(tb.created_at) BETWEEN ? AND ?']
    params = [filters['from_date'], filters['to_date']]
    keyword = filters.get('keyword', '')
    doctor_name = filters.get('doctor', '')
    normalized_keyword = normalize_uhid_search(keyword)
    if keyword.upper().startswith('AJH') and normalized_keyword.isdigit():
        where_clauses.append('COALESCE(p.source_patient_id, p.id) = ?')
        params.append(int(normalized_keyword))
    elif keyword:
        like_keyword = f'%{keyword}%'
        where_clauses.append('''
            (p.name LIKE ? OR p.phone LIKE ? OR tb.invoice_no LIKE ?
             OR tb.doctor_name LIKE ? OR tbi.test_name LIKE ?)
        ''')
        params.extend([like_keyword] * 5)
    if doctor_name:
        where_clauses.append('TRIM(tb.doctor_name) = TRIM(?) COLLATE NOCASE')
        params.append(doctor_name)
    where_sql = ' AND '.join(where_clauses)

    case_rows = db.execute(
        f'''
        SELECT tb.id, tb.invoice_no, tb.created_at, COALESCE(tb.sample_status, 'Pending'),
               p.name, p.phone, COALESCE(p.source_patient_id, p.id),
               COALESCE(NULLIF(tb.doctor_name, ''), 'Not assigned'),
               p.age, COALESCE(NULLIF(p.age_unit, ''), 'Y'), p.gender,
               COALESCE(NULLIF(tb.delivery_time, ''), '-'),
               COUNT(tbi.id),
               SUM(CASE WHEN NULLIF(TRIM(COALESCE(tbi.result_value, '')), '') IS NOT NULL THEN 1 ELSE 0 END),
               GROUP_CONCAT(tbi.test_name, ', ')
        FROM test_bills tb
        JOIN patients p ON p.id = tb.patient_id
        JOIN test_bill_items tbi ON tbi.test_bill_id = tb.id
        WHERE {where_sql}
        GROUP BY tb.id
        ORDER BY CASE WHEN COUNT(tbi.id) = SUM(CASE WHEN NULLIF(TRIM(COALESCE(tbi.result_value, '')), '') IS NOT NULL THEN 1 ELSE 0 END) THEN 2 ELSE 1 END,
                 datetime(tb.created_at) DESC, tb.id DESC
        ''',
        params
    ).fetchall()
    cases = [
        {
            'bill_id': row[0], 'invoice_no': row[1], 'created_at': row[2],
            'sample_status': row[3], 'patient_name': row[4], 'phone': row[5] or '-',
            'patient_uhid': row[6], 'doctor_name': row[7],
            'age': row[8], 'age_unit': row[9], 'gender': row[10] or '-',
            'delivery_time': row[11] or '-',
            'test_count': int(row[12] or 0), 'completed_count': int(row[13] or 0),
            'test_names': row[14] or '',
        }
        for row in case_rows
    ]
    order_rows = db.execute(
        f'''
        SELECT tbi.id, tb.id, tb.invoice_no, tb.created_at,
               COALESCE(tb.sample_status, 'Pending'), p.name,
               COALESCE(p.source_patient_id, p.id), COALESCE(NULLIF(tb.doctor_name, ''), 'Not assigned'),
               tbi.test_name, COALESCE(tbi.result_value, ''),
               COALESCE(tbi.result_updated_at, ''), COALESCE(tbi.result_updated_by, '')
        FROM test_bills tb
        JOIN patients p ON p.id = tb.patient_id
        JOIN test_bill_items tbi ON tbi.test_bill_id = tb.id
        WHERE {where_sql}
        ORDER BY CASE WHEN NULLIF(TRIM(COALESCE(tbi.result_value, '')), '') IS NULL THEN 1 ELSE 2 END,
                 datetime(tb.created_at) DESC, tb.id DESC, tbi.id ASC
        ''',
        params
    ).fetchall()
    orders = [
        {
            'item_id': row[0], 'bill_id': row[1], 'invoice_no': row[2],
            'created_at': row[3], 'sample_status': row[4], 'patient_name': row[5],
            'patient_uhid': row[6], 'doctor_name': row[7], 'test_name': row[8],
            'result_value': row[9], 'result_updated_at': row[10], 'result_updated_by': row[11],
        }
        for row in order_rows
    ]
    summary = {
        'patient_count': len(cases),
        'test_count': len(orders),
        'pending_count': sum(1 for item in orders if not item['result_value'].strip()),
        'completed_count': sum(1 for item in orders if item['result_value'].strip()),
    }
    return cases, orders, summary


@app.route('/reports')
def patient_reports():
    """Two-step pathology report desk without the result-entry panel."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    raw_selected_date = request.args.get('date')
    show_all_dates = request.args.get('all_dates', '').strip() == '1'
    if show_all_dates:
        selected_date = ''
    elif raw_selected_date is None:
        selected_date = current_calendar_date_text()
    else:
        selected_date = raw_selected_date.strip()
    try:
        datetime.strptime(selected_date, '%Y-%m-%d')
    except ValueError:
        selected_date = current_calendar_date_text()

    filters = {
        'from_date': selected_date,
        'to_date': selected_date,
        'keyword': '',
        'doctor': '',
        'patient_status': 'all',
        'payment_status': 'all',
    }
    pathology_cases, pathology_orders, pathology_summary = build_pathology_report_sections(filters)
    return render_template(
        'patient_reports.html', selected_date=selected_date,
        date_label=format_date_display(selected_date),
        pathology_cases=pathology_cases, pathology_orders=pathology_orders,
        pathology_summary=pathology_summary
    )


@app.route('/reports/print')
def patient_reports_print():
    """Printable version of the filtered patient report."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))
    rows, summary, _, filters = build_patient_report(request.args)
    return render_template(
        'patient_reports_print.html', rows=rows, summary=summary,
        filters=filters, printed_by=get_current_actor()[2],
        generated_at=current_timestamp_text()
    )


@app.route('/daily_expenses', methods=['GET', 'POST'])
def daily_expenses():
    """Record and review daily hospital expenses."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    default_expense_categories = [
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
    saved_categories = [
        row[0] for row in db.execute(
            'SELECT name FROM expense_categories ORDER BY name COLLATE NOCASE'
        ).fetchall()
    ]
    used_categories = [
        row[0] for row in db.execute(
            "SELECT DISTINCT category FROM daily_expenses WHERE TRIM(category) <> '' ORDER BY category"
        ).fetchall()
    ]
    expense_categories = list(dict.fromkeys(default_expense_categories + saved_categories + used_categories))
    payment_methods = ['Cash', 'Bkash', 'Nagad', 'Bank', 'Card', 'Due']

    selected_date = request.args.get('date', '').strip() or current_calendar_date_text()
    selected_category = request.args.get('category', '').strip()
    keyword = request.args.get('keyword', '').strip()
    message = request.args.get('message', '').strip()
    success = request.args.get('success', '').strip()

    try:
        datetime.strptime(selected_date, '%Y-%m-%d')
    except ValueError:
        selected_date = current_calendar_date_text()

    if request.method == 'POST':
        if request.form.get('form_action') == 'add_category':
            new_category = request.form.get('new_category', '').strip()
            if not new_category:
                return redirect(url_for(
                    'daily_expenses', date=selected_date, category=selected_category,
                    keyword=keyword, message='Please enter a category name.'
                ))
            try:
                db.execute(
                    'INSERT OR IGNORE INTO expense_categories (name, created_at) VALUES (?, ?)',
                    (new_category, current_timestamp_text())
                )
                db.commit()
                return redirect(url_for(
                    'daily_expenses', date=selected_date,
                    success=f'Category "{new_category}" is available in the dropdown.'
                ))
            except sqlite3.Error:
                db.rollback()
                return redirect(url_for(
                    'daily_expenses', date=selected_date,
                    message='Could not add this category. Please try again.'
                ))

        expense_date = request.form.get('expense_date', '').strip() or current_calendar_date_text()
        category = request.form.get('category', '').strip()
        description = request.form.get('description', '').strip() or None
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

        if not category:
            return redirect(url_for(
                'daily_expenses',
                date=selected_date,
                category=selected_category,
                keyword=keyword,
                message='Please enter an expense category.'
            ))

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
                    current_timestamp_text(),
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


def build_all_transation_report(selected_date):
    """Build one day of hospital account totals and ledger rows."""
    selected_date = (selected_date or '').strip() or current_calendar_date_text()
    try:
        selected_date_obj = datetime.strptime(selected_date, '%Y-%m-%d')
    except ValueError:
        selected_date = current_calendar_date_text()
        selected_date_obj = datetime.strptime(selected_date, '%Y-%m-%d')

    previous_date = (selected_date_obj - timedelta(days=1)).strftime('%Y-%m-%d')
    next_date = (selected_date_obj + timedelta(days=1)).strftime('%Y-%m-%d')
    selected_month = selected_date[:7]

    doctor_summary = db.execute(
        '''
        SELECT COUNT(CASE WHEN COALESCE(doctor_fee, 0) > 0 THEN 1 END),
               COALESCE(SUM(doctor_fee), 0),
               COALESCE(SUM(doctor_paid_amount), 0),
               COALESCE(SUM(doctor_due_amount), 0)
        FROM patients
        WHERE date(created_at) = ?
        ''',
        (selected_date,)
    ).fetchone()
    pathology_summary = db.execute(
        '''
        SELECT
            COUNT(*),
            COALESCE(SUM(COALESCE(tbr.original_total_amount, tb.total_amount)), 0),
            COALESCE(SUM(COALESCE(tbr.original_received_amount, tb.received_amount)), 0),
            COALESCE(SUM(COALESCE(tbr.original_due_amount, tb.due_amount)), 0)
        FROM test_bills tb
        LEFT JOIN test_bill_returns tbr ON tbr.test_bill_id = tb.id
        WHERE date(tb.created_at) = ?
        ''',
        (selected_date,)
    ).fetchone()
    visit_return_summary = db.execute(
        '''
        SELECT COUNT(*), COALESCE(SUM(refund_amount), 0)
        FROM patient_visit_returns
        WHERE date(return_date) = ?
        ''',
        (selected_date,)
    ).fetchone()
    pathology_return_summary = db.execute(
        '''
        SELECT COUNT(*),
               COALESCE(SUM(original_total_amount), 0),
               COALESCE(SUM(refund_amount), 0),
               COALESCE(SUM(original_due_amount), 0)
        FROM test_bill_returns
        WHERE date(return_date) = ?
        ''',
        (selected_date,)
    ).fetchone()
    admission_summary = db.execute(
        '''
        SELECT COUNT(*), COALESCE(SUM(admission_fee), 0)
        FROM admissions
        WHERE date(created_at) = ?
        ''',
        (selected_date,)
    ).fetchone()
    discharge_summary = db.execute(
        '''
        SELECT
            COUNT(*),
            COALESCE(SUM(gross_amount), 0),
            COALESCE(SUM(paid_amount), 0),
            COALESCE(SUM(due_amount), 0)
        FROM discharge_bills
        WHERE date(COALESCE(NULLIF(discharge_date, ''), created_at)) = ?
        ''',
        (selected_date,)
    ).fetchone()
    expense_summary = db.execute(
        '''
        SELECT COUNT(*), COALESCE(SUM(amount), 0)
        FROM daily_expenses
        WHERE date(expense_date) = ?
        ''',
        (selected_date,)
    ).fetchone()

    doctor_total = float(doctor_summary[1] or 0)
    doctor_received = float(doctor_summary[2] or 0)
    doctor_due = float(doctor_summary[3] or 0)
    pathology_total = float(pathology_summary[1] or 0)
    pathology_received = float(pathology_summary[2] or 0)
    pathology_due = float(pathology_summary[3] or 0)
    admission_fee_total = float(admission_summary[1] or 0)
    discharge_gross = float(discharge_summary[1] or 0)
    discharge_paid = float(discharge_summary[2] or 0)
    discharge_due = float(discharge_summary[3] or 0)
    expense_total = float(expense_summary[1] or 0)
    visit_return_count = int(visit_return_summary[0] or 0)
    visit_refund_total = float(visit_return_summary[1] or 0)
    pathology_return_count = int(pathology_return_summary[0] or 0)
    pathology_return_billing = float(pathology_return_summary[1] or 0)
    pathology_refund_total = float(pathology_return_summary[2] or 0)
    pathology_return_due = float(pathology_return_summary[3] or 0)

    total_billing = doctor_total + pathology_total + admission_fee_total + discharge_gross - visit_refund_total - pathology_return_billing
    total_collected = doctor_received + pathology_received + admission_fee_total + discharge_paid - visit_refund_total - pathology_refund_total
    total_due = doctor_due + pathology_due + discharge_due - pathology_return_due
    net_cash = total_collected - expense_total

    summary_cards = [
        {
            'label': 'Total Billing',
            'value': total_billing,
            'count': int(doctor_summary[0] or 0) + int(pathology_summary[0] or 0) + int(admission_summary[0] or 0) + int(discharge_summary[0] or 0) + visit_return_count + pathology_return_count,
            'note': 'Billing less visit and pathology returns',
            'icon': 'fas fa-file-invoice-dollar',
            'tone': 'billing',
        },
        {
            'label': 'Daily Expences',
            'value': expense_total,
            'count': int(expense_summary[0] or 0),
            'note': 'Operational outflow',
            'icon': 'fas fa-wallet',
            'tone': 'expense',
        },
    ]

    section_cards = [
        {
            'label': 'Daily Expences',
            'value': expense_total,
            'count': int(expense_summary[0] or 0),
            'meta': 'Outflow',
            'icon': 'fas fa-wallet',
            'tone': 'expense',
        },
        {
            'label': 'Doctor Ticket',
            'value': doctor_total,
            'count': int(doctor_summary[0] or 0),
            'meta': f'Received Tk {doctor_received:.2f} | Due Tk {doctor_due:.2f}',
            'icon': 'fas fa-ticket',
            'tone': 'doctor',
        },
        {
            'label': 'Pathology',
            'value': pathology_total,
            'count': int(pathology_summary[0] or 0),
            'meta': f'Received Tk {pathology_received:.2f} | Due Tk {pathology_due:.2f}',
            'icon': 'fas fa-microscope',
            'tone': 'pathology',
        },
        {
            'label': 'Visit Return',
            'value': -visit_refund_total,
            'count': visit_return_count,
            'meta': f'Refund adjustment Tk {visit_refund_total:.2f}',
            'icon': 'fas fa-rotate-left',
            'tone': 'expense',
        },
        {
            'label': 'Pathology Return',
            'value': -pathology_return_billing,
            'count': pathology_return_count,
            'meta': f'Refund Tk {pathology_refund_total:.2f} | Due cancelled Tk {pathology_return_due:.2f}',
            'icon': 'fas fa-flask-vial',
            'tone': 'expense',
        },
        {
            'label': 'Admission Fee',
            'value': admission_fee_total,
            'count': int(admission_summary[0] or 0),
            'meta': 'Admission records',
            'icon': 'fas fa-bed-pulse',
            'tone': 'admission',
        },
        {
            'label': 'Discharge Bill',
            'value': discharge_gross,
            'count': int(discharge_summary[0] or 0),
            'meta': f'Paid Tk {discharge_paid:.2f} | Due Tk {discharge_due:.2f}',
            'icon': 'fas fa-file-medical',
            'tone': 'discharge',
        },
    ]

    doctor_rows = db.execute(
        '''
        SELECT id, COALESCE(source_patient_id, id), daily_patient_id, name, phone,
               doctor_name, doctor_fee, doctor_paid_amount, doctor_due_amount, created_at
        FROM patients
        WHERE date(created_at) = ?
          AND COALESCE(doctor_fee, 0) > 0
        ORDER BY datetime(created_at) DESC, id DESC
        ''',
        (selected_date,)
    ).fetchall()
    pathology_rows = db.execute(
        '''
        SELECT tb.id, tb.invoice_no, p.name, p.phone, tb.doctor_name,
               COALESCE(tbr.original_total_amount, tb.total_amount),
               COALESCE(tbr.original_received_amount, tb.received_amount),
               COALESCE(tbr.original_due_amount, tb.due_amount),
               tb.payment_method, tb.created_at, tbr.return_no
        FROM test_bills tb
        JOIN patients p ON p.id = tb.patient_id
        LEFT JOIN test_bill_returns tbr ON tbr.test_bill_id = tb.id
        WHERE date(tb.created_at) = ?
        ORDER BY datetime(tb.created_at) DESC, tb.id DESC
        ''',
        (selected_date,)
    ).fetchall()
    admission_rows = db.execute(
        '''
        SELECT a.id, COALESCE(p.source_patient_id, p.id), p.name, p.phone,
               COALESCE(d.name, 'Not assigned'), a.room_number, a.status, a.created_at,
               a.admission_fee
        FROM admissions a
        JOIN patients p ON p.id = a.patient_id
        LEFT JOIN doctors d ON d.id = a.doctor_id
        WHERE date(a.created_at) = ?
        ORDER BY datetime(a.created_at) DESC, a.id DESC
        ''',
        (selected_date,)
    ).fetchall()
    discharge_rows = db.execute(
        '''
        SELECT dbill.id, dbill.bill_no, COALESCE(p.source_patient_id, p.id), p.name, p.phone,
               dbill.gross_amount, dbill.paid_amount, dbill.due_amount,
               COALESCE(NULLIF(dbill.updated_at, ''), dbill.created_at), dbill.discharge_date
        FROM discharge_bills dbill
        JOIN patients p ON p.id = dbill.patient_id
        WHERE date(COALESCE(NULLIF(dbill.discharge_date, ''), dbill.created_at)) = ?
        ORDER BY datetime(COALESCE(NULLIF(dbill.updated_at, ''), dbill.created_at)) DESC, dbill.id DESC
        ''',
        (selected_date,)
    ).fetchall()
    expense_rows = db.execute(
        '''
        SELECT id, expense_date, category, description, vendor, amount,
               payment_method, note, created_by, created_at
        FROM daily_expenses
        WHERE date(expense_date) = ?
        ORDER BY datetime(created_at) DESC, id DESC
        ''',
        (selected_date,)
    ).fetchall()
    visit_return_rows = db.execute(
        '''
        SELECT id, return_no, patient_uhid, ticket_no, patient_name, phone,
               doctor_name, doctor_fee, refund_amount, reason, created_at, return_date
        FROM patient_visit_returns
        WHERE date(return_date) = ?
        ORDER BY datetime(created_at) DESC, id DESC
        ''',
        (selected_date,)
    ).fetchall()
    pathology_return_rows = db.execute(
        '''
        SELECT id, return_no, invoice_no, patient_uhid, ticket_no, patient_name, phone,
               original_total_amount, original_received_amount, original_due_amount,
               refund_amount, reason, created_at, return_date
        FROM test_bill_returns
        WHERE date(return_date) = ?
        ORDER BY datetime(created_at) DESC, id DESC
        ''',
        (selected_date,)
    ).fetchall()

    transaction_rows = []
    for row in doctor_rows:
        transaction_rows.append({
            'type': 'Doctor Ticket',
            'icon': 'fas fa-ticket',
            'ref': f'Ticket {row[2] or row[0]}',
            'person': row[3],
            'phone': row[4],
            'detail': row[5] or 'Doctor consultation',
            'amount': float(row[6] or 0),
            'time': row[9],
            'status': f'Received Tk {float(row[7] or 0):.2f} | Due Tk {float(row[8] or 0):.2f}',
            'payment': 'Cash',
            'direction': 'inflow',
            'sort_time': row[9],
        })
    for row in pathology_rows:
        transaction_rows.append({
            'type': 'Pathology',
            'icon': 'fas fa-microscope',
            'ref': row[1],
            'person': row[2],
            'phone': row[3],
            'detail': row[4] or 'Pathology bill',
            'amount': float(row[5] or 0),
            'time': row[9],
            'status': (f'Returned ({row[10]}) | ' if row[10] else '') + f'Received Tk {float(row[6] or 0):.2f} | Due Tk {float(row[7] or 0):.2f}',
            'payment': row[8] or 'Cash',
            'direction': 'inflow',
            'sort_time': row[9],
        })
    for row in visit_return_rows:
        transaction_rows.append({
            'type': 'Visit Return',
            'icon': 'fas fa-rotate-left',
            'ref': row[1],
            'person': row[4],
            'phone': row[5],
            'detail': f'Ticket {row[3] or "-"} | {row[6] or "Doctor visit"} | {row[9] or "No reason"}',
            'amount': float(row[8] or 0),
            'time': row[10] or row[11],
            'status': f'Refunded Tk {float(row[8] or 0):.2f}',
            'payment': 'Refund',
            'direction': 'outflow',
            'sort_time': row[10] or row[11],
        })
    for row in pathology_return_rows:
        transaction_rows.append({
            'type': 'Pathology Return',
            'icon': 'fas fa-flask-vial',
            'ref': row[1],
            'person': row[5],
            'phone': row[6],
            'detail': f'Invoice {row[2]} | UHID {format_uhid(row[3])} | {row[11] or "No reason"}',
            'amount': float(row[7] or 0),
            'time': row[12] or row[13],
            'status': f'Refund Tk {float(row[10] or 0):.2f} | Due cancelled Tk {float(row[9] or 0):.2f}',
            'payment': 'Refund',
            'direction': 'outflow',
            'sort_time': row[12] or row[13],
        })
    for row in admission_rows:
        transaction_rows.append({
            'type': 'Admission Fee',
            'icon': 'fas fa-bed-pulse',
            'ref': f'Admission #{row[0]}',
            'person': row[2],
            'phone': row[3],
            'detail': f'{row[4]} | Bed {row[5] or "-"}',
            'amount': float(row[8] or 0),
            'time': row[7],
            'status': row[6] or 'Admitted',
            'payment': 'Cash',
            'direction': 'inflow',
            'sort_time': row[7],
        })
    for row in discharge_rows:
        transaction_rows.append({
            'type': 'Discharge Bill',
            'icon': 'fas fa-file-medical',
            'ref': row[1] or f'DB-{row[0]}',
            'person': row[3],
            'phone': row[4],
            'detail': f'UHID {format_uhid(row[2])} | Discharge {format_date_display(row[9])}',
            'amount': float(row[5] or 0),
            'time': row[8],
            'status': f'Paid Tk {float(row[6] or 0):.2f} | Due Tk {float(row[7] or 0):.2f}',
            'payment': 'Billing',
            'direction': 'inflow',
            'sort_time': row[8],
        })
    for row in expense_rows:
        transaction_rows.append({
            'type': 'Daily Expences',
            'icon': 'fas fa-wallet',
            'ref': row[2],
            'person': row[4] or 'Hospital expense',
            'phone': '',
            'detail': row[3],
            'amount': float(row[5] or 0),
            'time': row[9] or row[1],
            'status': 'Expense',
            'payment': row[6] or 'Cash',
            'direction': 'outflow',
            'sort_time': row[9] or row[1],
        })

    expense_records = [
        {
            'id': row[0], 'date': row[1], 'category': row[2],
            'description': row[3], 'vendor': row[4] or '-',
            'amount': float(row[5] or 0), 'payment': row[6] or 'Cash',
            'note': row[7] or '-', 'created_by': row[8] or '-',
            'created_at': row[9] or row[1],
        }
        for row in expense_rows
    ]
    return_records = [
        {
            'type': 'Visit Return', 'ref': row[1], 'patient': row[4],
            'detail': f'Ticket {row[3] or "-"} | {row[9] or "No reason"}',
            'refund': float(row[8] or 0), 'billing_adjustment': float(row[8] or 0),
            'created_at': row[10] or row[11],
        }
        for row in visit_return_rows
    ] + [
        {
            'type': 'Pathology Return', 'ref': row[1], 'patient': row[5],
            'detail': f'Invoice {row[2]} | {row[11] or "No reason"}',
            'refund': float(row[10] or 0), 'billing_adjustment': float(row[7] or 0),
            'created_at': row[12] or row[13],
        }
        for row in pathology_return_rows
    ]
    return_records.sort(
        key=lambda item: parse_stored_datetime(item.get('created_at')) or datetime.min,
        reverse=True
    )

    transaction_rows.sort(
        key=lambda item: parse_stored_datetime(item.get('sort_time')) or datetime.min,
        reverse=True
    )

    month_summary = db.execute(
        '''
        SELECT
            COALESCE((SELECT SUM(doctor_fee) FROM patients WHERE strftime('%Y-%m', created_at) = ?), 0),
            COALESCE((SELECT SUM(COALESCE(tbr.original_total_amount, tb.total_amount))
                      FROM test_bills tb
                      LEFT JOIN test_bill_returns tbr ON tbr.test_bill_id = tb.id
                      WHERE strftime('%Y-%m', tb.created_at) = ?), 0),
            COALESCE((SELECT SUM(gross_amount) FROM discharge_bills WHERE strftime('%Y-%m', COALESCE(NULLIF(discharge_date, ''), created_at)) = ?), 0),
            COALESCE((SELECT SUM(amount) FROM daily_expenses WHERE strftime('%Y-%m', expense_date) = ?), 0)
        ''',
        (selected_month, selected_month, selected_month, selected_month)
    ).fetchone()
    month_return_summary = db.execute(
        '''
        SELECT
            COALESCE((SELECT SUM(refund_amount) FROM patient_visit_returns WHERE strftime('%Y-%m', return_date) = ?), 0),
            COALESCE((SELECT SUM(original_total_amount) FROM test_bill_returns WHERE strftime('%Y-%m', return_date) = ?), 0)
        ''',
        (selected_month, selected_month)
    ).fetchone()

    return {
        'selected_date': selected_date,
        'previous_date': previous_date,
        'next_date': next_date,
        'selected_month': selected_month,
        'summary_cards': summary_cards,
        'section_cards': section_cards,
        'transaction_rows': transaction_rows[:100],
        'expense_records': expense_records,
        'return_records': return_records,
        'total_billing': total_billing,
        'total_collected': total_collected,
        'total_due': total_due,
        'net_cash': net_cash,
        'month_summary': {
            'doctor': float(month_summary[0] or 0) - float(month_return_summary[0] or 0),
            'pathology': float(month_summary[1] or 0) - float(month_return_summary[1] or 0),
            'discharge': float(month_summary[2] or 0),
            'expense': float(month_summary[3] or 0),
        },
    }


@app.route('/all_transation')
def all_transation():
    """Day-wise hospital transaction summary across major account heads."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    report = build_all_transation_report(request.args.get('date', '').strip())
    return render_template('all_transation.html', admin=isadmin(), **report)


@app.route('/all_transation/print')
def all_transation_print():
    """Printable day-wise hospital transaction bill."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    report = build_all_transation_report(request.args.get('date', '').strip())
    report['printed_by'] = get_current_actor()[2]
    report['auto_print'] = request.args.get('auto_print') == '1'
    return render_template('all_transation_print.html', **report)


@app.route('/daily_expenses/print')
def daily_expenses_print():
    """A4 portrait printable expense list using the selected filters."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    selected_date = request.args.get('date', '').strip() or current_calendar_date_text()
    selected_category = request.args.get('category', '').strip()
    keyword = request.args.get('keyword', '').strip()
    try:
        datetime.strptime(selected_date, '%Y-%m-%d')
    except ValueError:
        selected_date = current_calendar_date_text()

    where_clauses = ['date(expense_date) = ?']
    params = [selected_date]
    if selected_category:
        where_clauses.append('category = ?')
        params.append(selected_category)
    if keyword:
        where_clauses.append('''(
            description LIKE ? OR vendor LIKE ? OR note LIKE ?
            OR payment_method LIKE ? OR category LIKE ?
        )''')
        params.extend([f'%{keyword}%'] * 5)

    expense_rows = db.execute(
        f'''
        SELECT id, expense_date, category, description, vendor, amount,
               payment_method, note, created_by, created_at
        FROM daily_expenses
        WHERE {' AND '.join(where_clauses)}
        ORDER BY datetime(created_at) ASC, id ASC
        ''',
        params
    ).fetchall()
    total_amount = sum(float(row[5] or 0) for row in expense_rows)

    return render_template(
        'daily_expenses_print.html',
        expense_rows=expense_rows,
        selected_date=selected_date,
        selected_category=selected_category,
        keyword=keyword,
        total_amount=total_amount,
        printed_by=get_current_actor()[2],
        auto_print=request.args.get('auto_print') == '1',
    )


@app.route('/daily_expenses/delete/<int:expense_id>', methods=['POST'])
def delete_daily_expense(expense_id):
    """Delete one daily expense entry. Admins only."""
    selected_date = request.form.get('selected_date', '').strip() or current_calendar_date_text()
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

    selected_date = request.args.get('date', '').strip() or current_calendar_date_text()
    if selected_date:
        try:
            datetime.strptime(selected_date, '%Y-%m-%d')
        except ValueError:
            selected_date = current_calendar_date_text()

    date_where = 'WHERE date(tb.created_at) = ?' if selected_date else ''
    bill_date_where = 'WHERE date(created_at) = ?' if selected_date else ''
    query_params = (selected_date,) if selected_date else ()
    date_label = format_date_display(selected_date) if selected_date else 'All pathology records'

    available_tests = db.execute("SELECT COUNT(*) FROM services WHERE type = 'test' AND COALESCE(is_active, 1) = 1").fetchone()[0]
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
            tbi.result_updated_by,
            (
                SELECT COUNT(*)
                FROM test_bill_items earlier_item
                WHERE earlier_item.test_bill_id = tbi.test_bill_id
                  AND earlier_item.id <= tbi.id
            ) AS patient_test_serial
        FROM test_bills tb
        JOIN patients p ON p.id = tb.patient_id
        JOIN test_bill_items tbi ON tbi.test_bill_id = tb.id
        {date_where}
        ORDER BY
            datetime(tb.created_at) ASC,
            tb.id ASC,
            patient_test_serial ASC,
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
            GROUP_CONCAT(tbi.test_name, ', ') AS test_names,
            (
                SELECT COUNT(*)
                FROM test_bills earlier_tb
                WHERE date(earlier_tb.created_at) = date(tb.created_at)
                  AND (
                      datetime(earlier_tb.created_at) < datetime(tb.created_at)
                      OR (
                          datetime(earlier_tb.created_at) = datetime(tb.created_at)
                          AND earlier_tb.id <= tb.id
                      )
                  )
            ) AS daily_serial
        FROM test_bills tb
        JOIN patients p ON p.id = tb.patient_id
        JOIN test_bill_items tbi ON tbi.test_bill_id = tb.id
        {date_where}
        GROUP BY tb.id
        ORDER BY
            daily_serial ASC,
            datetime(tb.created_at) ASC,
            tb.id ASC
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
            'daily_serial': row[18],
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
            'patient_test_serial': row[22],
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
        SELECT tbi.id, tbi.test_name, tb.patient_id, tb.invoice_no, tb.id,
               NULLIF(TRIM(COALESCE(tbi.result_value, '')), '')
        FROM test_bill_items tbi
        JOIN test_bills tb ON tb.id = tbi.test_bill_id
        WHERE tbi.id = ?
        ''',
        (test_item_id,)
    ).fetchone()
    if not test_item:
        return redirect(url_for('pathology_dashboard', **redirect_args))

    if test_item[5] is not None:
        return redirect(url_for('pathology_result_print', test_item_id=test_item_id))

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
    if result_value:
        return redirect(url_for('pathology_result_print', test_item_id=test_item_id))
    redirect_args['selected_item'] = test_item_id
    return redirect(url_for('pathology_dashboard', **redirect_args))


@app.route('/pathology/report/<int:test_item_id>')
def pathology_result_print(test_item_id):
    """Printable laboratory result report for one selected pathology test."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    report = db.execute(
        '''
        SELECT tb.id, tb.invoice_no, tb.created_at, tb.doctor_name, tb.referred_by,
               tb.sample_status, tb.delivery_time, p.name, p.age,
               COALESCE(NULLIF(p.age_unit, ''), 'Y'), p.gender, p.phone,
               COALESCE(p.source_patient_id, p.id) AS patient_uhid
        FROM test_bills tb
        JOIN patients p ON p.id = tb.patient_id
        JOIN test_bill_items selected_item ON selected_item.test_bill_id = tb.id
        WHERE selected_item.id = ?
        ''', (test_item_id,)
    ).fetchone()
    if not report:
        return redirect(url_for('pathology_dashboard'))

    item_rows = db.execute(
        '''
        SELECT tbi.test_name, tbi.result_value, tbi.result_note,
               tbi.result_updated_at, tbi.result_updated_by,
               COALESCE(NULLIF(s.sample_type, ''), 'Not specified'),
               COALESCE(NULLIF(s.test_category, ''), 'Laboratory Investigation'),
               COALESCE(NULLIF(s.unit, ''), '-'),
               COALESCE(NULLIF(s.reference_ranges, ''), '-')
        FROM test_bill_items tbi
        LEFT JOIN services s ON s.id = tbi.service_id
        WHERE tbi.id = ?
        ''', (test_item_id,)
    ).fetchall()
    items = [
        {
            'test_name': row[0], 'result': row[1] or 'Pending',
            'methodology': row[2] or '-', 'updated_at': row[3] or '',
            'updated_by': row[4] or '', 'sample_type': row[5],
            'category': row[6], 'unit': row[7], 'reference_ranges': row[8],
        }
        for row in item_rows
    ]
    completed_items = [item for item in items if item['result'] != 'Pending']
    latest_result_at = max((item['updated_at'] for item in completed_items), default=report[2] or '')
    verified_by = next((item['updated_by'] for item in reversed(completed_items) if item['updated_by']), get_current_actor()[2])

    return render_template(
        'pathology_result_print.html', report=report, items=items,
        latest_result_at=latest_result_at, verified_by=verified_by,
        printed_by=get_current_actor()[2]
    )


@app.route('/medicine_stock_dashboard', methods=['GET', 'POST'])
def medicine_stock_dashboard():
    """Medicine stock dashboard for accounts granted stock permission."""
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
        if medicine_name == '__new__':
            medicine_name = request.form.get('new_medicine_name', '').strip()
        supplier = request.form.get('supplier', '').strip()
        batch_no = request.form.get('batch_no', '').strip()
        transaction_type = request.form.get('transaction_type', '').strip()
        box_quantity = request.form.get('box_quantity', '').strip()
        strips_per_box = request.form.get('strips_per_box', '').strip()
        strip_price = request.form.get('strip_price', '').strip()
        box_price = request.form.get('box_price', '').strip()
        purchase_amount = request.form.get('purchase_amount', '').strip()
        transaction_date = request.form.get('transaction_date', '').strip() or current_calendar_date_text()
        note = request.form.get('note', '').strip()

        try:
            box_quantity_value = int(box_quantity)
            strips_per_box_value = int(strips_per_box)
            strip_price_value = float(strip_price)
            box_price_value = float(box_price)
            purchase_amount_value = float(purchase_amount)
            total_strips = box_quantity_value * strips_per_box_value
            if (
                not medicine_name or not supplier or transaction_type != 'in' or box_quantity_value <= 0
                or strips_per_box_value <= 0 or strip_price_value <= 0 or box_price_value <= 0
                or purchase_amount_value <= 0
            ):
                raise ValueError

            db.execute(
                '''
                INSERT INTO medicine_transactions (
                    medicine_name, batch_no, unit_type, transaction_type, quantity, price,
                    strips_per_box, strip_price, box_price, box_quantity, supplier, purchase_amount,
                    transaction_date, note, created_by, created_at
                ) VALUES (?, ?, 'strip', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    medicine_name,
                    batch_no or 'General',
                    transaction_type,
                    total_strips,
                    strip_price_value,
                    strips_per_box_value,
                    strip_price_value,
                    box_price_value,
                    box_quantity_value,
                    supplier,
                    purchase_amount_value,
                    transaction_date,
                    note or 'No remarks added',
                    str(session.get('user_id')),
                    current_timestamp_text(),
                )
            )
            db.commit()
            return redirect(url_for('medicine_stock_dashboard'))
        except (ValueError, TypeError):
            if not error:
                error = 'Please enter the medicine, supplier, box details, selling prices, and total buy amount.'

    summary_rows = get_medicine_balance_rows()
    existing_medicine_names = [
        row[0] for row in db.execute(
            'SELECT DISTINCT medicine_name FROM medicine_transactions ORDER BY medicine_name COLLATE NOCASE'
        ).fetchall()
    ]
    existing_supplier_names = [
        row[0] for row in db.execute(
            '''
            SELECT DISTINCT TRIM(supplier)
            FROM medicine_transactions
            WHERE TRIM(COALESCE(supplier, '')) != ''
            ORDER BY TRIM(supplier) COLLATE NOCASE
            '''
        ).fetchall()
    ]
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
        existing_medicine_names=existing_medicine_names,
        existing_supplier_names=existing_supplier_names,
        today=current_calendar_date_text(),
        admin=isadmin(),
    )


@app.route('/medicine_stock_dashboard/movements/<movement_type>', endpoint='medicine_stock_movements')
def medicine_stock_movements(movement_type):
    """Detailed medicine stock movement pages for stock in, return in, and sold/issued."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))
    movement_configs = {
        'stock-in': {
            'title': 'Stock In Details',
            'label': 'Stock In',
            'kicker': 'Incoming Stock',
            'icon': 'fas fa-arrow-trend-up',
            'tone': 'in',
            'empty': 'No stock-in records found.',
            'where': "transaction_type = 'in' AND LOWER(TRIM(COALESCE(note, ''))) NOT LIKE 'returned on %'",
        },
        'return-in': {
            'title': 'Return In Details',
            'label': 'Return In',
            'kicker': 'Returned Stock',
            'icon': 'fas fa-rotate-left',
            'tone': 'return',
            'empty': 'No return-in records found.',
            'where': "transaction_type = 'in' AND LOWER(TRIM(COALESCE(note, ''))) LIKE 'returned on %'",
        },
        'sold-issued': {
            'title': 'Sold / Issued Details',
            'label': 'Sold / Issued',
            'kicker': 'Outgoing Stock',
            'icon': 'fas fa-cash-register',
            'tone': 'out',
            'empty': 'No sold / issued records found.',
            'where': "transaction_type = 'out'",
        },
    }
    movement_config = movement_configs.get(movement_type)
    if not movement_config:
        return redirect(url_for('medicine_stock_dashboard'))

    selected_date = request.args.get('date', '').strip() or current_calendar_date_text()
    if selected_date:
        try:
            datetime.strptime(selected_date, '%Y-%m-%d')
        except ValueError:
            selected_date = current_calendar_date_text()
    keyword = request.args.get('q', '').strip()
    selected_medicine = request.args.get('medicine', '').strip()

    medicine_buttons = []
    if movement_type == 'stock-in':
        medicine_button_rows = db.execute(
            f'''
            SELECT medicine_name, COUNT(*) AS transaction_count
            FROM medicine_transactions
            WHERE {movement_config['where']}
            GROUP BY medicine_name
            ORDER BY medicine_name COLLATE NOCASE
            '''
        ).fetchall()
        medicine_buttons = [
            {'name': row[0], 'transaction_count': int(row[1] or 0)}
            for row in medicine_button_rows
        ]

    where_clauses = [movement_config['where']]
    params = []
    if selected_date:
        where_clauses.append('date(transaction_date) = ?')
        params.append(selected_date)
    if keyword:
        like_keyword = f'%{keyword}%'
        where_clauses.append(
            '''
            (
                medicine_name LIKE ?
                OR batch_no LIKE ?
                OR unit_type LIKE ?
                OR note LIKE ?
                OR created_by LIKE ?
            )
            '''
        )
        params.extend([like_keyword, like_keyword, like_keyword, like_keyword, like_keyword])
    if selected_medicine:
        where_clauses.append('medicine_name = ? COLLATE NOCASE')
        params.append(selected_medicine)

    movement_rows = db.execute(
        f'''
        SELECT id, medicine_name, batch_no, unit_type, transaction_type, quantity, price,
               transaction_date, note, created_by, created_at, box_quantity, strips_per_box, supplier
        FROM medicine_transactions
        WHERE {' AND '.join(where_clauses)}
        ORDER BY date(transaction_date) DESC, datetime(created_at) DESC, id DESC
        ''',
        params
    ).fetchall()
    movements = [
        {
            'id': row[0],
            'medicine_name': row[1],
            'batch_no': row[2] or 'General',
            'unit_type': row[3] or 'strip',
            'transaction_type': row[4],
            'quantity': int(row[5] or 0),
            'price': float(row[6] or 0),
            'transaction_date': row[7],
            'note': row[8] or 'No remarks added',
            'created_by': row[9] or 'Unknown',
            'created_at': row[10],
            'box_quantity': int(row[11] or 0),
            'strips_per_box': max(int(row[12] or 1), 1),
            'supplier': row[13] or '',
        }
        for row in movement_rows
    ]

    total_quantity = sum(item['quantity'] for item in movements)
    total_value = sum(item['quantity'] * item['price'] for item in movements)
    medicine_count = len({(item['medicine_name'], item['batch_no'], item['unit_type']) for item in movements})

    return render_template(
        'medicine_stock_movements.html',
        movement_type=movement_type,
        movement_config=movement_config,
        movements=movements,
        selected_date=selected_date,
        keyword=keyword,
        selected_medicine=selected_medicine,
        medicine_buttons=medicine_buttons,
        total_quantity=total_quantity,
        total_value=total_value,
        medicine_count=medicine_count,
        today=current_calendar_date_text(),
        admin=isadmin(),
    )


@app.route('/medicine_payments', methods=['GET', 'POST'])
def medicine_payments():
    """Supplier purchase accounts and payment ledger for medicine stock."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    admin_checker = db.execute('SELECT * FROM admins WHERE id = ?', (session.get('user_id'),)).fetchone()
    user_checker = db.execute('SELECT * FROM users WHERE id = ?', (session.get('user_id'),)).fetchone()
    if session.get('user_id') == 'root_admin':
        profile_name = root_admin_username
    elif admin_checker and admin_checker[0] == session.get('user_id'):
        profile_name = admin_checker[1]
    else:
        profile_name = user_checker[1] if user_checker else 'User'

    message = request.args.get('message', '').strip()
    success = request.args.get('success', '').strip()

    if request.method == 'POST':
        supplier = request.form.get('supplier', '').strip()
        payment_date = request.form.get('payment_date', '').strip() or current_calendar_date_text()
        note = request.form.get('note', '').strip()
        try:
            amount = float(request.form.get('amount', '').strip())
        except (TypeError, ValueError):
            amount = 0
        try:
            discount_amount = float(request.form.get('discount_amount', '').strip() or 0)
        except (TypeError, ValueError):
            discount_amount = 0

        purchase_total = db.execute(
            '''
            SELECT COALESCE(SUM(purchase_amount), 0)
            FROM medicine_transactions
            WHERE supplier = ? COLLATE NOCASE
              AND transaction_type = 'in'
              AND LOWER(TRIM(COALESCE(note, ''))) NOT LIKE 'returned on %'
            ''',
            (supplier,)
        ).fetchone()[0]
        settlement_row = db.execute(
            '''
            SELECT COALESCE(SUM(amount), 0), COALESCE(SUM(discount_amount), 0)
            FROM medicine_supplier_payments
            WHERE supplier = ? COLLATE NOCASE
            ''',
            (supplier,)
        ).fetchone()
        paid_total = float(settlement_row[0] or 0)
        discount_total = float(settlement_row[1] or 0)
        due_amount = max(float(purchase_total or 0) - paid_total - discount_total, 0)

        if not supplier or amount < 0 or discount_amount < 0 or amount + discount_amount <= 0:
            return redirect(url_for(
                'medicine_payments',
                message='Select a supplier and enter a payment amount or discount.'
            ))
        if purchase_total <= 0:
            return redirect(url_for('medicine_payments', message='No medicine purchase account was found for this supplier.'))
        if amount + discount_amount > due_amount + 0.001:
            return redirect(url_for(
                'medicine_payments',
                message=f'Payment plus discount cannot exceed the current due amount of Tk {due_amount:.2f}.'
            ))

        db.execute(
            '''
            INSERT INTO medicine_supplier_payments (
                supplier, amount, discount_amount, payment_date, note, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''',
            (
                supplier, amount, discount_amount, payment_date,
                note or 'Supplier medicine payment',
                str(session.get('user_id')), current_timestamp_text()
            )
        )
        db.commit()
        return redirect(url_for(
            'medicine_payments',
            success=(
                f'Tk {amount:.2f} payment and Tk {discount_amount:.2f} discount '
                f'saved for {supplier}.'
            )
        ))

    purchase_rows = db.execute(
        '''
        SELECT supplier, COALESCE(SUM(purchase_amount), 0), COUNT(*), MAX(transaction_date),
               GROUP_CONCAT(DISTINCT TRIM(medicine_name))
        FROM medicine_transactions
        WHERE transaction_type = 'in'
          AND LOWER(TRIM(COALESCE(note, ''))) NOT LIKE 'returned on %'
          AND TRIM(COALESCE(supplier, '')) != ''
        GROUP BY supplier COLLATE NOCASE
        ORDER BY supplier COLLATE NOCASE
        '''
    ).fetchall()
    payment_rows = db.execute(
        '''
        SELECT supplier, COALESCE(SUM(amount), 0), COALESCE(SUM(discount_amount), 0),
               COUNT(*), MAX(payment_date)
        FROM medicine_supplier_payments
        GROUP BY supplier COLLATE NOCASE
        '''
    ).fetchall()
    payment_by_supplier = {
        str(row[0]).strip().lower(): {
            'paid_amount': float(row[1] or 0),
            'discount_amount': float(row[2] or 0),
            'payment_count': int(row[3] or 0),
            'last_payment_date': row[4] or '',
        }
        for row in payment_rows
    }
    supplier_accounts = []
    for row in purchase_rows:
        supplier = row[0]
        payment_info = payment_by_supplier.get(str(supplier).strip().lower(), {})
        purchase_amount = float(row[1] or 0)
        paid_amount = float(payment_info.get('paid_amount', 0))
        discount_amount = float(payment_info.get('discount_amount', 0))
        supplier_accounts.append({
            'supplier': supplier,
            'purchase_amount': purchase_amount,
            'paid_amount': paid_amount,
            'discount_amount': discount_amount,
            'due_amount': max(purchase_amount - paid_amount - discount_amount, 0),
            'purchase_count': int(row[2] or 0),
            'last_purchase_date': row[3] or '',
            'medicine_names': row[4] or '',
            'payment_count': payment_info.get('payment_count', 0),
            'last_payment_date': payment_info.get('last_payment_date', ''),
        })

    payment_history = [
        {
            'id': row[0], 'supplier': row[1], 'amount': float(row[2] or 0),
            'discount_amount': float(row[3] or 0), 'payment_date': row[4],
            'note': row[5] or '', 'created_by': row[6] or '',
        }
        for row in db.execute(
            '''
            SELECT id, supplier, amount, discount_amount, payment_date, note, created_by
            FROM medicine_supplier_payments
            ORDER BY date(payment_date) DESC, id DESC
            LIMIT 100
            '''
        ).fetchall()
    ]
    purchase_history = [
        {
            'id': row[0], 'medicine_name': row[1], 'supplier': row[2],
            'box_quantity': int(row[3] or 0), 'strips_per_box': int(row[4] or 1),
            'strip_price': float(row[5] or 0), 'box_price': float(row[6] or 0),
            'purchase_amount': float(row[7] or 0), 'transaction_date': row[8],
            'batch_no': row[9] or 'General',
        }
        for row in db.execute(
            '''
            SELECT id, medicine_name, supplier, box_quantity, strips_per_box,
                   strip_price, box_price, purchase_amount, transaction_date, batch_no
            FROM medicine_transactions
            WHERE transaction_type = 'in'
              AND LOWER(TRIM(COALESCE(note, ''))) NOT LIKE 'returned on %'
              AND purchase_amount > 0
            ORDER BY date(transaction_date) DESC, id DESC
            LIMIT 100
            '''
        ).fetchall()
    ]

    return render_template(
        'medicine_payments.html',
        profile_name=profile_name,
        supplier_accounts=supplier_accounts,
        supplier_names=[account['supplier'] for account in supplier_accounts],
        payment_history=payment_history,
        purchase_history=purchase_history,
        total_purchase=sum(account['purchase_amount'] for account in supplier_accounts),
        total_paid=sum(account['paid_amount'] for account in supplier_accounts),
        total_discount=sum(account['discount_amount'] for account in supplier_accounts),
        total_due=sum(account['due_amount'] for account in supplier_accounts),
        message=message,
        success=success,
        today=current_calendar_date_text(),
        admin=isadmin(),
    )


@app.route('/medicine_payments/purchase/<int:transaction_id>/edit', methods=['POST'])
def edit_medicine_purchase(transaction_id):
    """Edit a medicine stock-in purchase while preserving valid stock and supplier balances."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    purchase = db.execute(
        '''
        SELECT medicine_name, batch_no, quantity, supplier, purchase_amount
        FROM medicine_transactions
        WHERE id = ? AND transaction_type = 'in' AND purchase_amount > 0
          AND LOWER(TRIM(COALESCE(note, ''))) NOT LIKE 'returned on %'
        ''',
        (transaction_id,)
    ).fetchone()
    if not purchase:
        return redirect(url_for('medicine_payments', message='Medicine purchase record not found.'))

    medicine_name = request.form.get('medicine_name', '').strip()
    supplier = request.form.get('supplier', '').strip()
    batch_no = request.form.get('batch_no', '').strip() or 'General'
    transaction_date = request.form.get('transaction_date', '').strip()
    try:
        box_quantity = int(request.form.get('box_quantity', '').strip())
        strips_per_box = int(request.form.get('strips_per_box', '').strip())
        strip_price = float(request.form.get('strip_price', '').strip())
        box_price = float(request.form.get('box_price', '').strip())
        purchase_amount = float(request.form.get('purchase_amount', '').strip())
    except (TypeError, ValueError):
        return redirect(url_for('medicine_payments', message='Enter valid purchase quantities and amounts.'))

    if (
        not medicine_name or not supplier or not transaction_date
        or box_quantity <= 0 or strips_per_box <= 0
        or strip_price <= 0 or box_price <= 0 or purchase_amount <= 0
    ):
        return redirect(url_for('medicine_payments', message='Complete every purchase field with a valid value.'))

    new_quantity = box_quantity * strips_per_box
    old_medicine, old_batch, old_quantity, old_supplier, old_purchase_amount = purchase

    def stock_balance(name, batch):
        row = db.execute(
            '''
            SELECT COALESCE(SUM(
                CASE WHEN transaction_type = 'in' THEN quantity ELSE -quantity END
            ), 0)
            FROM medicine_transactions
            WHERE medicine_name = ? COLLATE NOCASE AND batch_no = ? COLLATE NOCASE
            ''',
            (name, batch)
        ).fetchone()
        return int(row[0] or 0)

    same_stock = (
        old_medicine.strip().lower() == medicine_name.lower()
        and old_batch.strip().lower() == batch_no.lower()
    )
    if same_stock:
        projected_old_balance = stock_balance(old_medicine, old_batch) - int(old_quantity) + new_quantity
    else:
        projected_old_balance = stock_balance(old_medicine, old_batch) - int(old_quantity)
    if projected_old_balance < 0:
        return redirect(url_for(
            'medicine_payments',
            message='This purchase cannot be reduced or moved because some of its stock has already been sold.'
        ))

    def supplier_totals(name):
        purchase_total = db.execute(
            '''
            SELECT COALESCE(SUM(purchase_amount), 0)
            FROM medicine_transactions
            WHERE supplier = ? COLLATE NOCASE AND transaction_type = 'in'
              AND LOWER(TRIM(COALESCE(note, ''))) NOT LIKE 'returned on %'
            ''',
            (name,)
        ).fetchone()[0]
        settlement_total = db.execute(
            '''
            SELECT COALESCE(SUM(amount + discount_amount), 0)
            FROM medicine_supplier_payments
            WHERE supplier = ? COLLATE NOCASE
            ''',
            (name,)
        ).fetchone()[0]
        return float(purchase_total or 0), float(settlement_total or 0)

    same_supplier = str(old_supplier or '').strip().lower() == supplier.lower()
    old_total, old_settled = supplier_totals(old_supplier or '')
    projected_old_purchase = old_total - float(old_purchase_amount or 0)
    if same_supplier:
        projected_old_purchase += purchase_amount
    if projected_old_purchase + 0.001 < old_settled:
        return redirect(url_for(
            'medicine_payments',
            message='This edit would make the supplier purchase total lower than its payments and discounts.'
        ))
    if not same_supplier:
        new_total, new_settled = supplier_totals(supplier)
        if new_total + purchase_amount + 0.001 < new_settled:
            return redirect(url_for(
                'medicine_payments',
                message='The selected supplier already has settlements exceeding the edited purchase total.'
            ))

    db.execute(
        '''
        UPDATE medicine_transactions
        SET medicine_name = ?, batch_no = ?, unit_type = 'strip', quantity = ?, price = ?,
            strips_per_box = ?, strip_price = ?, box_price = ?, box_quantity = ?,
            supplier = ?, purchase_amount = ?, transaction_date = ?
        WHERE id = ?
        ''',
        (
            medicine_name, batch_no, new_quantity, strip_price, strips_per_box,
            strip_price, box_price, box_quantity, supplier, purchase_amount,
            transaction_date, transaction_id
        )
    )
    db.commit()
    add_system_log(f'Medicine purchase updated: #{transaction_id} {medicine_name} from {supplier}')
    return redirect(url_for('medicine_payments', success='Medicine purchase record updated successfully.'))


@app.route('/medicine_payments/payment/<int:payment_id>/edit', methods=['POST'])
def edit_supplier_payment(payment_id):
    """Edit a supplier payment and discount without over-settling its account."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    payment = db.execute(
        'SELECT supplier FROM medicine_supplier_payments WHERE id = ?',
        (payment_id,)
    ).fetchone()
    if not payment:
        return redirect(url_for('medicine_payments', message='Supplier payment record not found.'))

    supplier = request.form.get('supplier', '').strip()
    payment_date = request.form.get('payment_date', '').strip()
    note = request.form.get('note', '').strip()
    try:
        amount = float(request.form.get('amount', '').strip() or 0)
        discount_amount = float(request.form.get('discount_amount', '').strip() or 0)
    except (TypeError, ValueError):
        amount = -1
        discount_amount = -1

    if (
        not supplier or not payment_date or amount < 0 or discount_amount < 0
        or amount + discount_amount <= 0
    ):
        return redirect(url_for('medicine_payments', message='Enter a valid payment amount or discount.'))

    purchase_total = float(db.execute(
        '''
        SELECT COALESCE(SUM(purchase_amount), 0)
        FROM medicine_transactions
        WHERE supplier = ? COLLATE NOCASE AND transaction_type = 'in'
          AND LOWER(TRIM(COALESCE(note, ''))) NOT LIKE 'returned on %'
        ''',
        (supplier,)
    ).fetchone()[0] or 0)
    other_settlements = float(db.execute(
        '''
        SELECT COALESCE(SUM(amount + discount_amount), 0)
        FROM medicine_supplier_payments
        WHERE supplier = ? COLLATE NOCASE AND id != ?
        ''',
        (supplier, payment_id)
    ).fetchone()[0] or 0)
    available_due = max(purchase_total - other_settlements, 0)
    if purchase_total <= 0:
        return redirect(url_for('medicine_payments', message='No purchase account was found for this supplier.'))
    if amount + discount_amount > available_due + 0.001:
        return redirect(url_for(
            'medicine_payments',
            message=f'Edited payment plus discount cannot exceed Tk {available_due:.2f}.'
        ))

    db.execute(
        '''
        UPDATE medicine_supplier_payments
        SET supplier = ?, amount = ?, discount_amount = ?, payment_date = ?, note = ?
        WHERE id = ?
        ''',
        (
            supplier, amount, discount_amount, payment_date,
            note or 'Supplier medicine payment', payment_id
        )
    )
    db.commit()
    add_system_log(f'Supplier payment updated: #{payment_id} for {supplier}')
    return redirect(url_for('medicine_payments', success='Supplier payment record updated successfully.'))


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
        strip_price = float(row['strip_price'] or row['latest_price'] or 0)
        strips_per_box = max(int(row['strips_per_box'] or 1), 1)
        box_price = float(row['box_price'] or (strip_price * strips_per_box))
        cart_items.append({
            'product': row['medicine_name'],
            'batch': row['batch_no'],
            'unit': 'Strip' if row['unit_type'] == 'strip' else row['unit_type'].title(),
            'available': row['balance'],
            'strips_per_box': strips_per_box,
            'available_boxes': (
                row['balance'] // strips_per_box
                if row['unit_type'] == 'strip' and strips_per_box > 1
                else (row['balance'] if row['unit_type'] == 'box' else 0)
            ),
            'can_sell_box': (row['unit_type'] == 'strip' and strips_per_box > 1) or row['unit_type'] == 'box',
            'can_sell_strip': row['unit_type'] == 'strip',
            'qty': 0,
            'price': strip_price,
            'strip_price': strip_price,
            'box_price': box_price,
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
    today = current_calendar_date_text()
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
        invoice_no=f"MS-{current_invoice_date_code()}-{invoice_count + 1:03d}",
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
    stock_requirements = {}
    for item in items:
        try:
            medicine_name = str(item.get('product', '')).strip()
            batch_no = str(item.get('batch', '')).strip() or 'General'
            unit_type = str(item.get('unit', 'strip')).strip().lower()
            quantity = int(item.get('quantity', 0))
            line_discount = max(float(item.get('discount', 0)), 0)
        except (TypeError, ValueError):
            return jsonify({'success': False, 'error': 'One or more sale items are invalid.'}), 400

        if not medicine_name or quantity <= 0:
            continue
        if unit_type not in ('strip', 'box'):
            unit_type = 'strip'

        stock_unit_type = 'strip'
        available_row = db.execute(
            '''
            SELECT COALESCE(SUM(CASE WHEN transaction_type = 'in' THEN quantity ELSE -quantity END), 0)
            FROM medicine_transactions
            WHERE medicine_name = ? AND COALESCE(NULLIF(batch_no, ''), 'General') = ? AND unit_type = 'strip'
            ''',
            (medicine_name, batch_no)
        ).fetchone()
        pricing_row = db.execute(
            '''
            SELECT price, strips_per_box, strip_price, box_price
            FROM medicine_transactions
            WHERE medicine_name = ?
              AND COALESCE(NULLIF(batch_no, ''), 'General') = ?
              AND unit_type = 'strip'
              AND transaction_type = 'in'
            ORDER BY date(transaction_date) DESC, id DESC
            LIMIT 1
            ''',
            (medicine_name, batch_no)
        ).fetchone()

        # Preserve support for older stock rows that were stored directly as boxes.
        if not pricing_row:
            stock_unit_type = unit_type
            available_row = db.execute(
                '''
                SELECT COALESCE(SUM(CASE WHEN transaction_type = 'in' THEN quantity ELSE -quantity END), 0)
                FROM medicine_transactions
                WHERE medicine_name = ? AND COALESCE(NULLIF(batch_no, ''), 'General') = ? AND unit_type = ?
                ''',
                (medicine_name, batch_no, stock_unit_type)
            ).fetchone()
            pricing_row = db.execute(
                '''
                SELECT price, 1, price, price
                FROM medicine_transactions
                WHERE medicine_name = ?
                  AND COALESCE(NULLIF(batch_no, ''), 'General') = ?
                  AND unit_type = ?
                  AND transaction_type = 'in'
                ORDER BY date(transaction_date) DESC, id DESC
                LIMIT 1
                ''',
                (medicine_name, batch_no, stock_unit_type)
            ).fetchone()

        if not pricing_row:
            return jsonify({'success': False, 'error': f'No stock record was found for {medicine_name}.'}), 400

        available_quantity = int(available_row[0] or 0)
        strips_per_box = max(int(pricing_row[1] or 1), 1)
        strips_per_unit = strips_per_box if unit_type == 'box' and stock_unit_type == 'strip' else 1
        required_stock_quantity = quantity * strips_per_unit
        strip_price = float(pricing_row[2] if pricing_row[2] is not None else pricing_row[0] or 0)
        box_price = float(pricing_row[3] if pricing_row[3] is not None else strip_price * strips_per_box)
        unit_price = box_price if unit_type == 'box' else strip_price
        stock_key = (medicine_name.lower(), batch_no.lower(), stock_unit_type)
        accumulated_stock_quantity = stock_requirements.get(stock_key, 0) + required_stock_quantity
        if accumulated_stock_quantity > available_quantity:
            available_sale_units = available_quantity // strips_per_unit
            return jsonify({
                'success': False,
                'error': f'Only {available_sale_units} {unit_type}(s) available for {medicine_name} batch {batch_no}.'
            }), 400
        stock_requirements[stock_key] = accumulated_stock_quantity

        line_total = max((quantity * unit_price) - line_discount, 0)
        cleaned_items.append({
            'medicine_name': medicine_name,
            'batch_no': batch_no,
            'unit_type': unit_type,
            'quantity': quantity,
            'unit_price': unit_price,
            'strips_per_unit': strips_per_unit,
            'stock_unit_type': stock_unit_type,
            'stock_quantity': required_stock_quantity,
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
    sale_date = current_calendar_date_text()
    created_at = current_timestamp_text()
    invoice_count = db.execute(
        "SELECT COUNT(*) FROM medicine_sales WHERE date(sale_date) = ?",
        (sale_date,)
    ).fetchone()[0]
    invoice_no = f"MS-{current_invoice_date_code()}-{invoice_count + 1:03d}"

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
                    unit_price, strips_per_unit, discount, line_total
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (
                    sale_id, item['medicine_name'], item['batch_no'], item['unit_type'],
                    item['quantity'], item['unit_price'], item['strips_per_unit'],
                    item['discount'], item['line_total']
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
                    item['medicine_name'], item['batch_no'], item['stock_unit_type'],
                    item['stock_quantity'], item['unit_price'], sale_date,
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
            'items': [
                {key: value for key, value in item.items() if key not in ('stock_unit_type', 'stock_quantity')}
                for item in cleaned_items
            ],
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
        if request.form.get('return_mode') == 'medicine':
            medicine_name = request.form.get('medicine_name', '').strip()
            return_unit = request.form.get('return_unit', '').strip().lower()
            reason = request.form.get('reason', '').strip()
            try:
                requested_quantity = int(request.form.get('return_quantity', '').strip())
            except (TypeError, ValueError):
                requested_quantity = 0

            if not medicine_name or return_unit not in {'box', 'strip'} or requested_quantity <= 0:
                return redirect(url_for(
                    'medicine_return',
                    message='Select a medicine, choose Box or Strip, and enter a valid return quantity.'
                ))
            return_unit_label = (
                ('Box' if requested_quantity == 1 else 'Boxes')
                if return_unit == 'box'
                else ('Strip' if requested_quantity == 1 else 'Strips')
            )

            candidate_rows = db.execute(
                '''
                SELECT
                    msi.id, msi.sale_id, msi.medicine_name, msi.batch_no,
                    msi.unit_type, msi.quantity, msi.unit_price, msi.discount,
                    msi.line_total, msi.strips_per_unit,
                    COALESCE((
                        SELECT SUM(mri.quantity)
                        FROM medicine_return_items mri
                        WHERE mri.sale_item_id = msi.id
                    ), 0) AS returned_quantity,
                    ms.invoice_no, ms.customer_name, ms.customer_phone
                FROM medicine_sale_items msi
                JOIN medicine_sales ms ON ms.id = msi.sale_id
                WHERE msi.medicine_name = ? COLLATE NOCASE
                  AND LOWER(msi.unit_type) = ?
                ORDER BY datetime(ms.created_at) DESC, msi.id DESC
                ''',
                (medicine_name, return_unit)
            ).fetchall()
            available_quantity = sum(
                max(int(row[5] or 0) - int(row[10] or 0), 0)
                for row in candidate_rows
            )
            if available_quantity <= 0:
                return redirect(url_for(
                    'medicine_return',
                    message=f'No returnable sold {return_unit}(s) were found for {medicine_name}.'
                ))
            if requested_quantity > available_quantity:
                return redirect(url_for(
                    'medicine_return',
                    message=(
                        f'Only {available_quantity} sold {return_unit}(s) of '
                        f'{medicine_name} can be returned.'
                    )
                ))

            remaining_request = requested_quantity
            allocations_by_sale = {}
            for row in candidate_rows:
                row_remaining = max(int(row[5] or 0) - int(row[10] or 0), 0)
                if row_remaining <= 0 or remaining_request <= 0:
                    continue
                allocated_quantity = min(row_remaining, remaining_request)
                original_quantity = max(int(row[5] or 0), 1)
                item = {
                    'sale_item_id': row[0],
                    'medicine_name': row[2],
                    'batch_no': row[3] or 'General',
                    'unit_type': row[4] or 'strip',
                    'quantity': allocated_quantity,
                    'unit_price': float(row[6] or 0),
                    'strips_per_unit': max(int(row[9] or 1), 1),
                    'discount': round((float(row[7] or 0) / original_quantity) * allocated_quantity, 2),
                    'line_total': round((float(row[8] or 0) / original_quantity) * allocated_quantity, 2),
                }
                sale_group = allocations_by_sale.setdefault(row[1], {
                    'invoice_no': row[11],
                    'customer_name': row[12] or 'Walk-in Customer',
                    'customer_phone': row[13] or '',
                    'items': [],
                })
                sale_group['items'].append(item)
                remaining_request -= allocated_quantity

            return_date = current_calendar_date_text()
            created_at = current_timestamp_text()
            return_count = db.execute(
                "SELECT COUNT(*) FROM medicine_returns WHERE date(return_date) = ?",
                (return_date,)
            ).fetchone()[0]
            saved_return_numbers = []
            try:
                for group_index, (sale_id, sale_group) in enumerate(allocations_by_sale.items(), start=1):
                    return_no = f"MR-{current_invoice_date_code()}-{return_count + group_index:03d}"
                    return_items = sale_group['items']
                    subtotal = sum(item['quantity'] * item['unit_price'] for item in return_items)
                    discount_amount = sum(item['discount'] for item in return_items)
                    refund_amount = sum(item['line_total'] for item in return_items)
                    cursor = db.execute(
                        '''
                        INSERT INTO medicine_returns (
                            return_no, sale_id, invoice_no, customer_name, customer_phone,
                            reason, subtotal, discount_amount, refund_amount, return_date,
                            created_by, created_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''',
                        (
                            return_no, sale_id, sale_group['invoice_no'],
                            sale_group['customer_name'], sale_group['customer_phone'],
                            reason or f'Direct return by medicine name: {medicine_name}',
                            subtotal, discount_amount, refund_amount, return_date,
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
                                return_id, item['sale_item_id'], item['medicine_name'],
                                item['batch_no'], item['unit_type'], item['quantity'],
                                item['unit_price'], item['discount'], item['line_total']
                            )
                        )
                        db.execute(
                            '''
                            INSERT INTO medicine_transactions (
                                medicine_name, batch_no, unit_type, transaction_type,
                                quantity, price, transaction_date, note, created_by, created_at
                            ) VALUES (?, ?, ?, 'in', ?, ?, ?, ?, ?, ?)
                            ''',
                            (
                                item['medicine_name'], item['batch_no'],
                                'strip' if item['strips_per_unit'] > 1 else item['unit_type'],
                                item['quantity'] * item['strips_per_unit'], item['unit_price'],
                                return_date,
                                f'Returned on {return_no} from invoice {sale_group["invoice_no"]}',
                                str(session.get('user_id')), created_at
                            )
                        )
                    saved_return_numbers.append(return_no)
                db.commit()
                add_system_log(
                    f'Direct medicine return saved: {medicine_name}, quantity {requested_quantity}, '
                    f'unit {return_unit}, returns {", ".join(saved_return_numbers)}'
                )
                return redirect(url_for(
                    'medicine_return',
                    success=(
                        f'{requested_quantity} {return_unit_label} of '
                        f'{medicine_name} returned successfully. '
                        'Stock and reports updated.'
                    )
                ))
            except sqlite3.Error:
                db.rollback()
                return redirect(url_for(
                    'medicine_return',
                    message='Could not save medicine return. Please try again.'
                ))

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
                msi.strips_per_unit,
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
            remaining_qty = max(int(row[4] or 0) - int(row[9] or 0), 0)
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
                'strips_per_unit': max(int(row[8] or 1), 1),
                'discount': round(discount_per_unit * return_qty, 2),
                'line_total': round(line_total_per_unit * return_qty, 2),
            })

        if not return_items:
            return redirect(url_for('medicine_return', invoice=sale_row[1], message='Enter at least one return quantity.'))

        return_date = current_calendar_date_text()
        created_at = current_timestamp_text()
        return_count = db.execute(
            "SELECT COUNT(*) FROM medicine_returns WHERE date(return_date) = ?",
            (return_date,)
        ).fetchone()[0]
        return_no = f"MR-{current_invoice_date_code()}-{return_count + 1:03d}"
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
                        item['medicine_name'], item['batch_no'], 'strip' if item['strips_per_unit'] > 1 else item['unit_type'],
                        item['quantity'] * item['strips_per_unit'], item['unit_price'], return_date,
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

    return_medicine_rows = db.execute(
        '''
        SELECT medicine_name, LOWER(unit_type), SUM(remaining_quantity)
        FROM (
            SELECT
                msi.medicine_name,
                msi.unit_type,
                MAX(msi.quantity - COALESCE((
                    SELECT SUM(mri.quantity)
                    FROM medicine_return_items mri
                    WHERE mri.sale_item_id = msi.id
                ), 0), 0) AS remaining_quantity
            FROM medicine_sale_items msi
        )
        WHERE remaining_quantity > 0
        GROUP BY medicine_name COLLATE NOCASE, LOWER(unit_type)
        ORDER BY medicine_name COLLATE NOCASE, LOWER(unit_type)
        '''
    ).fetchall()
    return_medicine_map = {}
    for row in return_medicine_rows:
        medicine = return_medicine_map.setdefault(
            row[0],
            {'medicine_name': row[0], 'available_boxes': 0, 'available_strips': 0}
        )
        if str(row[1]).lower() == 'box':
            medicine['available_boxes'] += int(row[2] or 0)
        elif str(row[1]).lower() == 'strip':
            medicine['available_strips'] += int(row[2] or 0)
    return_medicines = list(return_medicine_map.values())

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
        return_medicines=return_medicines,
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
        SELECT id, return_no, invoice_no, customer_name, customer_phone, subtotal,
               discount_amount, refund_amount, reason, return_date, created_at
        FROM medicine_returns
        WHERE date(return_date) = ?
        ORDER BY created_at DESC, id DESC
        ''',
        (selected_date,)
    ).fetchall()
    returns = []
    total_return_quantity = 0
    for row in return_rows:
        return_item_rows = db.execute(
            '''
            SELECT medicine_name, batch_no, unit_type, quantity, unit_price, discount, line_total
            FROM medicine_return_items
            WHERE return_id = ?
            ORDER BY id ASC
            ''',
            (row[0],)
        ).fetchall()
        return_items = []
        for return_item in return_item_rows:
            quantity = int(return_item[3] or 0)
            unit_price = float(return_item[4] or 0)
            item_discount = float(return_item[5] or 0)
            line_total = float(return_item[6] or 0)
            item_data = {
                'medicine_name': return_item[0],
                'batch_no': return_item[1],
                'unit_type': return_item[2],
                'quantity': quantity,
                'unit_price': unit_price,
                'discount': item_discount,
                'line_total': line_total,
            }
            return_items.append(item_data)
            total_return_quantity += quantity

            summary_key = (
                item_data['medicine_name'] or 'Unknown Medicine',
                item_data['batch_no'] or '-',
                item_data['unit_type'] or '-',
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
            medicine_summary_map[summary_key]['quantity'] -= quantity
            medicine_summary_map[summary_key]['gross_amount'] -= quantity * unit_price
            medicine_summary_map[summary_key]['discount_amount'] -= item_discount
            medicine_summary_map[summary_key]['net_amount'] -= line_total
            medicine_summary_map[summary_key]['invoice_count'].add(row[2])

        returns.append({
            'id': row[0],
            'return_no': row[1],
            'invoice_no': row[2],
            'customer_name': row[3],
            'customer_phone': row[4],
            'subtotal': float(row[5] or 0),
            'discount_amount': float(row[6] or 0),
            'refund_amount': float(row[7] or 0),
            'reason': row[8],
            'return_date': row[9],
            'created_at': row[10],
            'items': return_items,
        })
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
        'total_return_quantity': total_return_quantity,
        'net_medicine_quantity': total_medicine_quantity - total_return_quantity,
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

    selected_date = request.args.get('date', '').strip() or current_calendar_date_text()
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

    selected_date = request.args.get('date', '').strip() or current_calendar_date_text()
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

    selected_month = request.args.get('month', '').strip() or current_calendar_month_text()
    try:
        month_start = datetime.strptime(selected_month, '%Y-%m')
    except ValueError:
        month_start = current_app_datetime().replace(day=1)
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
        generated_at=current_timestamp_text(),
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
    selected_month = request.form.get('month', '').strip() or current_calendar_month_text()
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

    selected_month = request.form.get('month', '').strip() or current_calendar_month_text()
    medicine_name = request.form.get('medicine_name', '').strip()
    batch_no = request.form.get('batch_no', '').strip() or 'General'
    unit_type = request.form.get('unit_type', '').strip().lower()
    try:
        month_start = datetime.strptime(selected_month, '%Y-%m')
    except ValueError:
        month_start = current_app_datetime().replace(day=1)
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
        return redirect(url_for('medicine_sales_list', date=selected_date or current_calendar_date_text()))

    sale_date = selected_date or sale_row[1] or current_calendar_date_text()

    try:
        delete_medicine_sale_records([sale_id])
        db.commit()
    except sqlite3.Error:
        db.rollback()

    return redirect(url_for('medicine_sales_list', date=sale_date))


@app.route('/medicine_stock_dashboard/edit/<int:transaction_id>', methods=['POST'])
def edit_medicine_transaction(transaction_id):
    """Update a stock entry when stock permission is granted."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    next_movement_type = request.form.get('next_movement_type', '').strip()
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

    if next_movement_type in ('stock-in', 'return-in', 'sold-issued'):
        return redirect(url_for('medicine_stock_movements', movement_type=next_movement_type))
    return redirect(url_for('medicine_stock_dashboard'))


@app.route('/medicine_stock_dashboard/delete/<int:transaction_id>', methods=['POST'])
def delete_medicine_transaction(transaction_id):
    """Delete one stock movement when stock permission is granted."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    next_movement_type = request.form.get('next_movement_type', '').strip()
    db.execute('DELETE FROM medicine_transactions WHERE id = ?', (transaction_id,))
    db.commit()
    if next_movement_type in ('stock-in', 'return-in', 'sold-issued'):
        return redirect(url_for('medicine_stock_movements', movement_type=next_movement_type))
    return redirect(url_for('medicine_stock_dashboard'))


@app.route('/medicine_stock_dashboard/delete_medicine', methods=['POST'])
def delete_medicine_balance():
    """Delete a medicine batch balance when stock permission is granted."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

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
            doctor_paid_amount = request.form.get('doctor_paid_amount')
            existing_patient_id = request.form.get('existing_patient_id', '').strip()
            save_action = request.form.get('save_action')
            save_action = 'save_print' if save_action == 'save_print' else 'register'
            is_ajax = request.headers.get('X-Requested-With') == 'XMLHttpRequest'

            if not name or not age or not gender or not phone or not blood_group or not address or not patient_status or not doctor_name:
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
            doctor_fee_value = 0.0
            doctor_paid_value = 0.0
            doctor_due_value = 0.0
            if save_action == 'save_print':
                configured_doctor = db.execute('''
                    SELECT COALESCE(consultation_fee, 0)
                    FROM doctors
                    WHERE TRIM(name) = TRIM(?) COLLATE NOCASE
                      AND COALESCE(is_active, 1) = 1
                    ORDER BY id ASC
                    LIMIT 1
                ''', (doctor_name,)).fetchone()
                try:
                    doctor_fee_value = float(configured_doctor[0] if configured_doctor else doctor_fee)
                    doctor_paid_value = float(doctor_paid_amount or 0)
                    if (
                        not math.isfinite(doctor_fee_value)
                        or not math.isfinite(doctor_paid_value)
                        or doctor_fee_value <= 0
                        or doctor_paid_value < 0
                        or doctor_paid_value > doctor_fee_value
                    ):
                        raise ValueError
                except (TypeError, ValueError):
                    if is_ajax:
                        return {"success": False, "error": "Set a valid fee on the Doctors page and enter a valid paid amount."}, 400
                    return patient_redirect(error="Set a valid fee on the Doctors page and enter a valid paid amount.")
                doctor_due_value = max(doctor_fee_value - doctor_paid_value, 0)

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
                WHERE date(created_at) = ?
            ''', (current_calendar_date_text(),)).fetchone()[0]

            cursor = db.execute('''INSERT INTO patients (
                                      daily_patient_id, serial_no, name, age, age_unit, gender, phone, email,
                                      dob, blood_group, address, emergency_contact_name, emergency_contact_phone,
                                      medical_history, patient_status, doctor_name, doctor_designation,
                                      referer_name, doctor_fee, doctor_paid_amount, doctor_due_amount,
                                      source_patient_id, served_by, created_at
                                  )
                                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+6 hours'))''',
                                (
                                    daily_ticket_no, serial_no, name, age, age_unit, gender, phone, email,
                                    dob, blood_group, address, emergency_contact_name, emergency_contact_phone,
                                    medical_history, patient_status, doctor_name, doctor_designation,
                                    referer_name, doctor_fee_value, doctor_paid_value, doctor_due_value,
                                    source_patient_id, get_current_actor()[2]
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

        return_date = current_calendar_date_text()
        created_at = current_timestamp_text()
        return_count = db.execute(
            "SELECT COUNT(*) FROM patient_visit_returns WHERE date(return_date) = ?",
            (return_date,)
        ).fetchone()[0]
        return_no = f"VR-{current_invoice_date_code()}-{return_count + 1:03d}"

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
            COALESCE(d.name, 'Not assigned'),
            a.admission_fee,
            a.created_at,
            COALESCE(NULLIF(p.referer_name, ''), 'Self'),
            COALESCE(
                NULLIF(a.admitted_by, ''),
                adm.username,
                usr.username,
                CASE WHEN a.created_by IS NULL THEN 'Admin' ELSE CAST(a.created_by AS TEXT) END,
                'Staff'
            )
        FROM admissions a
        JOIN patients p ON a.patient_id = p.id
        LEFT JOIN doctors d ON a.doctor_id = d.id
        LEFT JOIN admins adm ON a.created_by = adm.id
        LEFT JOIN users usr ON a.created_by = usr.id
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
        'admission_fee': row[20],
        'created_at': row[21],
        'referer_name': row[22],
        'admitted_by': row[23],
    }


def format_concern_paper_date(value):
    """Format an ISO date as 11 July 2026 for the concern paper."""
    return format_invoice_date(value)


@app.route('/admissions', methods=['GET', 'POST'])
def admissions():
    """Admit patients and display admission records."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    if request.method == 'POST':
        patient_id = request.form.get('patient_id')
        doctor_id = request.form.get('doctor_id') or None
        admission_date = current_admission_date_text()
        room_number = (request.form.get('room_number') or '').strip()
        bed_number = (request.form.get('bed_number') or '').strip()
        admission_fee_text = (request.form.get('admission_fee') or '').strip()
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

        if not admission_date or not room_number or not admission_fee_text or not guardian_name or not guardian_relation or not reason:
            return redirect(url_for('admissions', message="Please fill in all required admission fields."))

        try:
            admission_fee = float(admission_fee_text)
        except ValueError:
            return redirect(url_for('admissions', message="Please enter a valid admission fee."))

        if not math.isfinite(admission_fee) or admission_fee < 0:
            return redirect(url_for('admissions', message="Admission fee must be a valid non-negative amount."))

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
            doctor = db.execute('SELECT id FROM doctors WHERE id = ? AND COALESCE(is_active, 1) = 1', (doctor_id,)).fetchone()
            if not doctor:
                doctor_id = None

        _, _, admitted_by = get_current_actor()

        admission_cursor = db.execute('''
            INSERT INTO admissions (
                patient_id, doctor_id, admission_date, ward, room_number,
                bed_number, admission_fee, guardian_name, guardian_relation, reason, notes,
                status, created_by, admitted_by, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Admitted', ?, ?, datetime('now', '+6 hours'))
        ''', (
            patient_id, doctor_id, admission_date, ward, room_number,
            bed_number, admission_fee, guardian_name, guardian_relation, reason, notes,
            session.get('user_id'), admitted_by
        ))
        admission_id = admission_cursor.lastrowid
        db.commit()
        session['last_admission_id'] = admission_id
        add_log(patient_id, "Patient admitted")
        return redirect(url_for('admission_form_print', admission_id=admission_id, auto_print=1))

    selected_date = request.args.get('date', '').strip() or current_admission_date_text()
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
        WHERE COALESCE(is_active, 1) = 1
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
            a.created_at,
            a.admission_fee,
            COALESCE(NULLIF(a.admitted_by, ''), 'Admin') AS served_by
        FROM admissions a
        JOIN patients p ON a.patient_id = p.id
        LEFT JOIN doctors d ON a.doctor_id = d.id
        WHERE date(a.admission_date) = ?
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
        default_admission_date=current_admission_date_text(),
        message=request.args.get('message'),
        success=request.args.get('success')
    )


@app.route('/admissions/<int:admission_id>/details')
def admission_details(admission_id):
    """Return the complete admission record for the Admission Records modal."""
    if not isadmin() and not isuser():
        return jsonify({'success': False, 'error': 'Please sign in again.'}), 401

    record = get_admission_print_record(admission_id)
    if not record:
        return jsonify({'success': False, 'error': 'Admission record was not found.'}), 404

    admission_time = '-'
    if record['created_at']:
        try:
            admission_time = datetime.strptime(record['created_at'], '%Y-%m-%d %H:%M:%S').strftime('%I:%M:%S %p')
        except ValueError:
            admission_time = record['created_at']

    return jsonify({
        'success': True,
        'admission': {
            'id': record['id'],
            'registration_no': record['registration_no'],
            'patient_name': record['patient_name'],
            'age': record['age'],
            'age_unit': record['age_unit'],
            'gender': record['gender'],
            'phone': record['phone'] or '-',
            'address': record['address'] or '-',
            'admission_date': format_date_display(record['admission_date']),
            'admission_time': admission_time,
            'ward': record['ward'] or '-',
            'bed_number': record['room_number'] or record['bed_number'] or '-',
            'guardian_name': record['guardian_name'] or '-',
            'guardian_relation': record['guardian_relation'] or '-',
            'doctor_name': record['doctor_name'] or 'Not assigned',
            'reason': record['reason'] or '-',
            'notes': record['notes'] or '-',
            'status': record['status'] or 'Admitted',
            'admission_fee': float(record['admission_fee'] or 0),
            'referer_name': record['referer_name'] or 'Self',
            'served_by': record['admitted_by'] or 'Admin',
            'print_url': url_for('concern_paper', admission_id=record['id']),
        }
    })


@app.route('/admission-form/<int:admission_id>')
def admission_form_print(admission_id):
    """Render the A4 admission form and optionally open the print dialog."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    record = get_admission_print_record(admission_id)
    if not record:
        return redirect(url_for('admissions', message="Admission record not found."))

    admission_time = ''
    if record['created_at']:
        try:
            admission_time = datetime.strptime(record['created_at'], '%Y-%m-%d %H:%M:%S').strftime('%I:%M:%S %p')
        except ValueError:
            admission_time = record['created_at']

    return render_template(
        'admission_form_print.html',
        record=record,
        admission_time=admission_time,
        auto_print=request.args.get('auto_print') == '1'
    )

@app.route('/admissions/search-old')
def search_old_admitted_patient():
    """Find discharged patients who can be admitted again."""
    if not isadmin() and not isuser():
        return jsonify({'success': False, 'patients': []}), 401

    keyword = request.args.get('keyword', '').strip()
    if len(keyword) < 2:
        return jsonify({'success': True, 'patients': []})

    search_keyword = normalize_uhid_search(keyword)

    search_term = f'%{search_keyword}%'
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
        search_term, search_term, search_term, search_term, search_term, search_term, search_keyword
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


@app.route('/due-collection')
def due_collection_hub():
    """Central desk for doctor, pathology and discharge due collection."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    test_due = db.execute(
        'SELECT COUNT(*), COALESCE(SUM(due_amount), 0) FROM test_bills WHERE due_amount > 0'
    ).fetchone()
    discharge_due = db.execute(
        'SELECT COUNT(*), COALESCE(SUM(due_amount), 0) FROM discharge_bills WHERE due_amount > 0'
    ).fetchone()
    doctor_due = db.execute(
        'SELECT COUNT(*), COALESCE(SUM(doctor_due_amount), 0) FROM patients WHERE doctor_due_amount > 0'
    ).fetchone()
    return render_template(
        'due_collection_hub.html',
        test_due_count=int(test_due[0] or 0),
        test_due_total=float(test_due[1] or 0),
        discharge_due_count=int(discharge_due[0] or 0),
        discharge_due_total=float(discharge_due[1] or 0),
        doctor_due_count=int(doctor_due[0] or 0),
        doctor_due_total=float(doctor_due[1] or 0),
    )


@app.route('/doctor-fee/due-collection')
def doctor_fee_due_collection():
    """Show outstanding registration consultation fees for collection."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    keyword = request.args.get('keyword', '').strip()
    sort = request.args.get('sort', 'newest')
    sort_options = {
        'newest': 'datetime(p.created_at) DESC, p.id DESC',
        'oldest': 'datetime(p.created_at) ASC, p.id ASC',
        'highest': 'p.doctor_due_amount DESC, datetime(p.created_at) DESC',
        'patient': 'p.name COLLATE NOCASE ASC, datetime(p.created_at) DESC',
    }
    order_clause = sort_options.get(sort, sort_options['newest'])
    where_clauses = ['p.doctor_due_amount > 0']
    params = []
    normalized_keyword = normalize_uhid_search(keyword)
    if keyword.upper().startswith('AJH') and normalized_keyword.isdigit():
        where_clauses.append('COALESCE(p.source_patient_id, p.id) = ?')
        params.append(int(normalized_keyword))
    elif keyword:
        like_keyword = f'%{keyword}%'
        where_clauses.append('''
            (p.name LIKE ? OR p.phone LIKE ? OR p.doctor_name LIKE ?
             OR CAST(p.daily_patient_id AS TEXT) LIKE ?)
        ''')
        params.extend([like_keyword] * 4)

    rows = db.execute(
        f'''
        SELECT p.id, p.daily_patient_id, p.name, p.phone,
               COALESCE(p.source_patient_id, p.id), p.doctor_name,
               p.doctor_fee, p.doctor_paid_amount, p.doctor_due_amount,
               p.created_at, p.age, COALESCE(NULLIF(p.age_unit, ''), 'Y'), p.gender
        FROM patients p
        WHERE {' AND '.join(where_clauses)}
        ORDER BY {order_clause}
        LIMIT 150
        ''',
        params
    ).fetchall()
    due_tickets = [
        {
            'id': row[0], 'ticket_no': row[1], 'patient_name': row[2],
            'phone': row[3] or '', 'patient_uhid': row[4],
            'doctor_name': row[5] or 'Not assigned', 'doctor_fee': float(row[6] or 0),
            'paid_amount': float(row[7] or 0), 'due_amount': float(row[8] or 0),
            'created_at': row[9], 'age': row[10], 'age_unit': row[11],
            'gender': row[12] or '-',
        }
        for row in rows
    ]
    summary_row = db.execute('''
        SELECT COUNT(*), COALESCE(SUM(doctor_due_amount), 0),
               COALESCE(SUM(CASE WHEN doctor_paid_amount > 0 THEN 1 ELSE 0 END), 0),
               MIN(created_at)
        FROM patients
        WHERE doctor_due_amount > 0
    ''').fetchone()
    today_due = db.execute('''
        SELECT COALESCE(SUM(doctor_due_amount), 0)
        FROM patients
        WHERE doctor_due_amount > 0 AND date(created_at) = ?
    ''', (current_calendar_date_text(),)).fetchone()[0]
    summary = {
        'pending_count': int(summary_row[0] or 0),
        'total_due': float(summary_row[1] or 0),
        'partial_count': int(summary_row[2] or 0),
        'oldest_due_date': summary_row[3],
        'today_due': float(today_due or 0),
    }
    return render_template(
        'doctor_fee_due_collection.html', due_tickets=due_tickets, summary=summary,
        keyword=keyword, sort=sort, message=request.args.get('message')
    )


@app.route('/doctor-fee/collect-due/<int:patient_id>', methods=['POST'])
def collect_doctor_fee_due(patient_id):
    """Collect all or part of a doctor's consultation fee due."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    patient = db.execute('''
        SELECT id, name, daily_patient_id, doctor_fee, doctor_paid_amount, doctor_due_amount
        FROM patients WHERE id = ?
    ''', (patient_id,)).fetchone()
    if not patient:
        return redirect(url_for('doctor_fee_due_collection', message='Patient ticket not found.'))

    previous_due = float(patient[5] or 0)
    if previous_due <= 0:
        return redirect(url_for('doctor_fee_due_collection', message='No doctor fee due is pending for this ticket.'))

    due_discount = min(_to_positive_float(request.form.get('due_discount')), previous_due)
    collectible_due = max(previous_due - due_discount, 0)
    collection_amount = min(_to_positive_float(request.form.get('collection_amount')), collectible_due)
    if collection_amount <= 0 and due_discount <= 0:
        return redirect(url_for('doctor_fee_due_collection', message='Please enter a collection amount or due discount.'))

    payment_method = request.form.get('payment_method', '').strip()
    if payment_method not in ('Cash', 'Bkash', 'Nagad', 'Card', 'Bank'):
        payment_method = 'Cash'
    note = request.form.get('discount_note', '').strip()
    new_fee = max(float(patient[3] or 0) - due_discount, 0)
    new_paid = min(new_fee, float(patient[4] or 0) + collection_amount)
    new_due = max(new_fee - new_paid, 0)
    actor = get_current_actor()
    actor_name = actor[2]

    try:
        db.execute('''
            UPDATE patients
            SET doctor_fee = ?, doctor_paid_amount = ?, doctor_due_amount = ?
            WHERE id = ?
        ''', (new_fee, new_paid, new_due, patient_id))
        db.execute('''
            INSERT INTO doctor_fee_due_collections (
                patient_id, previous_due, collection_amount, discount_amount,
                remaining_due, payment_method, note, collected_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now', '+6 hours'))
        ''', (
            patient_id, previous_due, collection_amount, due_discount,
            new_due, payment_method, note, actor_name
        ))
        db.commit()
        add_system_log(
            f"Doctor fee due collected: Ticket {patient[2] or patient_id}, collected {collection_amount:.2f}, discount {due_discount:.2f}, remaining {new_due:.2f}",
            patient_id=patient_id,
            actor=actor,
        )
        return redirect(url_for('ticket_print', patient_id=patient_id, return_to='doctor_due'))
    except sqlite3.Error:
        db.rollback()
        return redirect(url_for('doctor_fee_due_collection', message='Doctor fee due collection could not be saved. Please try again.'))

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
        today_date=current_calendar_date_text(),
        printed_by=get_current_actor()[2],
        message=request.args.get('message')
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

    discharge_date = request.args.get('discharge_date', '').strip() or current_calendar_date_text()
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
    if total_amount <= 0:
        return redirect(url_for(
            'discharge_bill',
            admission_id=admission_id,
            message='Please enter at least one bill charge before printing the discharge bill.'
        ))

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
        printed_by=printed_by,
        payment_method='Cash'
    )


@app.route('/discharge-bill/saved/<int:bill_id>')
def saved_discharge_bill_print(bill_id):
    """Print a saved discharge bill without recalculating or overwriting its charges."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    bill = db.execute(
        '''
        SELECT id, admission_id, patient_id, patient_uhid, bill_no, admission_date,
               discharge_date, stay_days, bed_charge, doctor_fee, medicine_charge,
               pathology_charge, service_charge, other_charge, total_amount, discount,
               gross_amount, paid_amount, due_amount, change_amount, remarks, prepared_by,
               COALESCE(NULLIF(payment_method, ''), 'Cash')
        FROM discharge_bills
        WHERE id = ?
        ''',
        (bill_id,)
    ).fetchone()
    if not bill:
        return redirect(url_for('discharge_due_collection', message='Discharge bill not found.'))

    admission = db.execute(
        '''
        SELECT
            a.id, p.id, COALESCE(p.source_patient_id, p.id), p.name, p.phone,
            p.age, COALESCE(NULLIF(p.age_unit, ''), 'Y'), p.gender, p.address,
            a.admission_date, a.room_number, a.guardian_name, a.guardian_relation,
            COALESCE(d.name, 'Not assigned'), a.reason, a.notes, a.created_at
        FROM admissions a
        JOIN patients p ON a.patient_id = p.id
        LEFT JOIN doctors d ON a.doctor_id = d.id
        WHERE a.id = ?
        ''',
        (bill[1],)
    ).fetchone()
    if not admission:
        return redirect(url_for('discharge_due_collection', message='Admission record not found.'))

    stay_days = max(int(bill[7] or 1), 1)
    items = [
        {'name': 'Bed Charge', 'qty': stay_days, 'rate': float(bill[8] or 0), 'amount': float(bill[8] or 0) * stay_days},
        {'name': 'Doctor Fee', 'qty': 1, 'rate': float(bill[9] or 0), 'amount': float(bill[9] or 0)},
        {'name': 'Medicine Charge', 'qty': 1, 'rate': float(bill[10] or 0), 'amount': float(bill[10] or 0)},
        {'name': 'Pathology Charge', 'qty': 1, 'rate': float(bill[11] or 0), 'amount': float(bill[11] or 0)},
        {'name': 'Service Charge', 'qty': 1, 'rate': float(bill[12] or 0), 'amount': float(bill[12] or 0)},
        {'name': 'Other Charge', 'qty': 1, 'rate': float(bill[13] or 0), 'amount': float(bill[13] or 0)},
    ]
    return render_template(
        'discharge_bill_print.html',
        admission=admission,
        items=items,
        bill_no=bill[4],
        discharge_date=bill[6],
        remarks=bill[20] or '',
        total_amount=float(bill[14] or 0),
        discount=float(bill[15] or 0),
        gross_amount=float(bill[16] or 0),
        paid_amount=float(bill[17] or 0),
        due_amount=float(bill[18] or 0),
        change_amount=float(bill[19] or 0),
        amount_in_words=amount_to_words(float(bill[16] or 0)),
        prepared_by=bill[21] or 'Admin',
        printed_by=get_current_actor()[2],
        payment_method=bill[22],
        return_url=(
            url_for('discharge_patients_list')
            if request.args.get('return_to') == 'list'
            else url_for('discharge_due_collection')
        )
    )


@app.route('/discharge-bill/due-collection/<int:bill_id>/details')
def discharge_due_details(bill_id):
    """Return complete discharge due information for the settlement modal."""
    if not isadmin() and not isuser():
        return jsonify({'success': False, 'error': 'Please sign in again.'}), 401

    bill = db.execute(
        '''
        SELECT dbill.id, dbill.bill_no, dbill.total_amount, dbill.discount,
               dbill.gross_amount, dbill.paid_amount, dbill.due_amount,
               COALESCE(NULLIF(dbill.payment_method, ''), 'Cash'), dbill.remarks,
               dbill.discharge_date, dbill.stay_days, dbill.bed_charge,
               dbill.doctor_fee, dbill.medicine_charge, dbill.pathology_charge,
               dbill.service_charge, dbill.other_charge, a.id, a.admission_date,
               a.room_number, a.guardian_name, a.guardian_relation, a.reason,
               COALESCE(d.name, 'Not assigned'), p.name, p.phone, p.age,
               COALESCE(NULLIF(p.age_unit, ''), 'Y'), p.gender,
               COALESCE(p.source_patient_id, p.id)
        FROM discharge_bills dbill
        JOIN admissions a ON a.id = dbill.admission_id
        JOIN patients p ON p.id = dbill.patient_id
        LEFT JOIN doctors d ON d.id = a.doctor_id
        WHERE dbill.id = ?
        ''',
        (bill_id,)
    ).fetchone()
    if not bill:
        return jsonify({'success': False, 'error': 'Discharge bill was not found.'}), 404
    if float(bill[6] or 0) <= 0:
        return jsonify({'success': False, 'error': 'This discharge bill has no pending due.'}), 409

    stay_days = max(int(bill[10] or 1), 1)
    bed_rate = float(bill[11] or 0)
    items = [
        {'name': 'Bed Charge', 'qty': stay_days, 'rate': bed_rate, 'amount': bed_rate * stay_days},
        {'name': 'Doctor Fee', 'qty': 1, 'rate': float(bill[12] or 0), 'amount': float(bill[12] or 0)},
        {'name': 'Medicine Charge', 'qty': 1, 'rate': float(bill[13] or 0), 'amount': float(bill[13] or 0)},
        {'name': 'Pathology Charge', 'qty': 1, 'rate': float(bill[14] or 0), 'amount': float(bill[14] or 0)},
        {'name': 'Service Charge', 'qty': 1, 'rate': float(bill[15] or 0), 'amount': float(bill[15] or 0)},
        {'name': 'Other Charge', 'qty': 1, 'rate': float(bill[16] or 0), 'amount': float(bill[16] or 0)},
    ]
    return jsonify({
        'success': True,
        'bill': {
            'id': bill[0], 'bill_no': bill[1], 'subtotal': float(bill[2] or 0),
            'discount': float(bill[3] or 0), 'total': float(bill[4] or 0),
            'received': float(bill[5] or 0), 'due': float(bill[6] or 0),
            'payment_method': bill[7], 'remarks': bill[8] or '',
            'discharge_date': format_date_display(bill[9]),
            'admission_id': bill[17], 'admission_date': format_date_display(bill[18]),
            'bed_number': bill[19] or '-', 'guardian_name': bill[20] or '-',
            'guardian_relation': bill[21] or '-', 'reason': bill[22] or '-',
            'doctor_name': bill[23], 'patient_name': bill[24], 'phone': bill[25] or '-',
            'age': bill[26], 'age_unit': bill[27], 'gender': bill[28] or '-',
            'patient_uhid': format_uhid(bill[29]),
            'collect_url': url_for('collect_discharge_due', bill_id=bill_id),
        },
        'items': items,
    })


@app.route('/discharge-bill/collect-due/<int:bill_id>', methods=['POST'])
def collect_discharge_due(bill_id):
    """Add a payment to an outstanding discharge bill."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    bill = db.execute(
        '''
        SELECT id, patient_id, bill_no, gross_amount, paid_amount, due_amount,
               discount, remarks
        FROM discharge_bills
        WHERE id = ?
        ''',
        (bill_id,)
    ).fetchone()
    if not bill:
        return redirect(url_for('discharge_due_collection', message='Discharge bill not found.'))

    due_amount = float(bill[5] or 0)
    if due_amount <= 0:
        return redirect(url_for('discharge_due_collection', message='No due amount is pending for this bill.'))

    due_discount = min(_to_positive_float(request.form.get('due_discount')), due_amount)
    collectible_due = max(due_amount - due_discount, 0)
    collection_amount = min(_to_positive_float(request.form.get('collection_amount')), collectible_due)
    if collection_amount <= 0 and due_discount <= 0:
        return redirect(url_for('discharge_due_collection', message='Please enter a collection amount or due discount.'))

    payment_method = request.form.get('payment_method', '').strip()
    if payment_method not in ('Cash', 'Bkash', 'Nagad', 'Card', 'Bank'):
        payment_method = 'Cash'
    discount_note = request.form.get('discount_note', '').strip()
    gross_amount = max(float(bill[3] or 0) - due_discount, 0)
    new_discount = float(bill[6] or 0) + due_discount
    new_paid = min(gross_amount, float(bill[4] or 0) + collection_amount)
    new_due = max(gross_amount - new_paid, 0)
    settlement_note = f'Due collection Tk {collection_amount:.2f}'
    if due_discount > 0:
        settlement_note += f' | Due discount Tk {due_discount:.2f}'
    if discount_note:
        settlement_note += f' ({discount_note})'
    existing_remarks = str(bill[7] or '').strip()
    updated_remarks = f'{existing_remarks} | {settlement_note}' if existing_remarks else settlement_note

    try:
        db.execute(
            '''
            UPDATE discharge_bills
            SET discount = ?, gross_amount = ?, paid_amount = ?, due_amount = ?,
                change_amount = 0, payment_method = ?, remarks = ?,
                updated_at = datetime('now', '+6 hours')
            WHERE id = ?
            ''',
            (new_discount, gross_amount, new_paid, new_due, payment_method, updated_remarks, bill_id)
        )
        db.commit()
        add_log(
            int(bill[1]),
            f"Discharge due settled: {bill[2]} (collected {collection_amount:.2f}, discount {due_discount:.2f})"
        )
        return redirect(url_for('saved_discharge_bill_print', bill_id=bill_id))
    except sqlite3.Error:
        db.rollback()
        return redirect(url_for('discharge_due_collection', message='Due collection could not be saved. Please try again.'))


@app.route('/discharge-bill/due-collection')
def discharge_due_collection():
    """Show and collect all pending discharge bill balances."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    keyword = request.args.get('keyword', '').strip()
    sort = request.args.get('sort', 'newest')
    sort_options = {
        'newest': 'datetime(dbill.created_at) DESC, dbill.id DESC',
        'oldest': 'datetime(dbill.created_at) ASC, dbill.id ASC',
        'highest': 'dbill.due_amount DESC, datetime(dbill.created_at) DESC',
        'patient': 'p.name COLLATE NOCASE ASC, datetime(dbill.created_at) DESC',
    }
    order_clause = sort_options.get(sort, sort_options['newest'])
    where_clauses = ['dbill.due_amount > 0']
    params = []
    normalized_keyword = normalize_uhid_search(keyword)
    if keyword.upper().startswith('AJH') and normalized_keyword.isdigit():
        where_clauses.append('COALESCE(p.source_patient_id, p.id) = ?')
        params.append(int(normalized_keyword))
    elif keyword:
        like_keyword = f'%{keyword}%'
        where_clauses.append(
            '''
            (dbill.bill_no LIKE ? OR p.name LIKE ? OR p.phone LIKE ?
             OR a.room_number LIKE ? OR CAST(a.id AS TEXT) LIKE ?)
            '''
        )
        params.extend([like_keyword] * 5)

    due_rows = db.execute(
        f'''
        SELECT dbill.id, dbill.bill_no, dbill.gross_amount, dbill.paid_amount,
               dbill.due_amount, dbill.discharge_date, dbill.created_at,
               p.name, p.phone, COALESCE(p.source_patient_id, p.id),
               a.id, a.room_number, COALESCE(NULLIF(dbill.payment_method, ''), 'Cash')
        FROM discharge_bills dbill
        JOIN patients p ON p.id = dbill.patient_id
        JOIN admissions a ON a.id = dbill.admission_id
        WHERE {' AND '.join(where_clauses)}
        ORDER BY {order_clause}
        LIMIT 120
        ''',
        params
    ).fetchall()
    due_bills = [
        {
            'id': row[0], 'bill_no': row[1], 'total_amount': float(row[2] or 0),
            'paid_amount': float(row[3] or 0), 'due_amount': float(row[4] or 0),
            'discharge_date': row[5], 'created_at': row[6], 'patient_name': row[7],
            'phone': row[8] or '', 'patient_uhid': row[9], 'admission_id': row[10],
            'bed_number': row[11] or '-', 'payment_method': row[12],
        }
        for row in due_rows
    ]
    summary_row = db.execute(
        '''
        SELECT COUNT(*), COALESCE(SUM(due_amount), 0), MIN(discharge_date)
        FROM discharge_bills
        WHERE due_amount > 0
        '''
    ).fetchone()
    today_due = db.execute(
        '''SELECT COALESCE(SUM(due_amount), 0) FROM discharge_bills
           WHERE due_amount > 0 AND date(discharge_date) = ?''',
        (current_calendar_date_text(),)
    ).fetchone()[0]
    summary = {
        'pending_count': int(summary_row[0] or 0),
        'total_due': float(summary_row[1] or 0),
        'oldest_due_date': summary_row[2],
        'today_due': float(today_due or 0),
    }
    return render_template(
        'discharge_due_collection.html', due_bills=due_bills, summary=summary,
        keyword=keyword, sort=sort, message=request.args.get('message')
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
            dbill.updated_at,
            dbill.id
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
        if row[17] and row[35]:
            print_url = url_for('saved_discharge_bill_print', bill_id=row[35], return_to='list')

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
            permission_groups=PERMISSION_GROUPS,
            user_permissions=user_permissions,
            success=request.args.get('success'),
            delete_message=request.args.get('delete_message'),
            message=request.args.get('message')
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


@app.route('/update_account', methods=['POST'])
def update_account():
    """Edit a regular user or admin account without exposing its stored password."""
    if not isadmin():
        return redirect(url_for('login'))

    account_type = request.form.get('account_type', '').strip().lower()
    account_id = request.form.get('account_id', '').strip()
    username = request.form.get('username', '').strip()
    email = request.form.get('email', '').strip().lower()
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')

    if account_type not in {'user', 'admin'} or not account_id.isdigit():
        return redirect(url_for('registered_users', message="Invalid account selected."))
    if not username or not email:
        return redirect(url_for('registered_users', message="Username and email are required."))
    if len(username) < 3:
        return redirect(url_for('registered_users', message="Username must contain at least 3 characters."))
    if '@' not in email or email.startswith('@') or email.endswith('@'):
        return redirect(url_for('registered_users', message="Please enter a valid email address."))
    if new_password and len(new_password) < 6:
        return redirect(url_for('registered_users', message="The new password must contain at least 6 characters."))
    if new_password != confirm_password:
        return redirect(url_for('registered_users', message="The new password confirmation does not match."))
    if username.lower() == root_admin_username.lower():
        return redirect(url_for('registered_users', message="This username is reserved for the root administrator."))

    table_name = 'users' if account_type == 'user' else 'admins'
    account_row = db.execute(
        f'SELECT username, email FROM {table_name} WHERE id = ?',
        (account_id,)
    ).fetchone()
    if not account_row:
        return redirect(url_for('registered_users', message="Account not found."))

    username_conflict = db.execute(
        '''
        SELECT 1
        FROM users
        WHERE LOWER(username) = LOWER(?) AND NOT (? = 'user' AND id = ?)
        UNION ALL
        SELECT 1
        FROM admins
        WHERE LOWER(username) = LOWER(?) AND NOT (? = 'admin' AND id = ?)
        LIMIT 1
        ''',
        (username, account_type, account_id, username, account_type, account_id)
    ).fetchone()
    email_conflict = db.execute(
        '''
        SELECT 1
        FROM users
        WHERE LOWER(COALESCE(email, '')) = LOWER(?) AND NOT (? = 'user' AND id = ?)
        UNION ALL
        SELECT 1
        FROM admins
        WHERE LOWER(COALESCE(email, '')) = LOWER(?) AND NOT (? = 'admin' AND id = ?)
        LIMIT 1
        ''',
        (email, account_type, account_id, email, account_type, account_id)
    ).fetchone()
    if username_conflict:
        return redirect(url_for('registered_users', message="That username is already in use."))
    if email_conflict:
        return redirect(url_for('registered_users', message="That email address is already in use."))

    try:
        if new_password:
            db.execute(
                f'UPDATE {table_name} SET username = ?, email = ?, password = ? WHERE id = ?',
                (username, email, generate_password_hash(new_password), account_id)
            )
        else:
            db.execute(
                f'UPDATE {table_name} SET username = ?, email = ? WHERE id = ?',
                (username, email, account_id)
            )
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        return redirect(url_for(
            'registered_users',
            message="Username or email already exists. Please use different account details."
        ))

    role_label = 'Employee' if account_type == 'user' else 'Admin'
    password_note = ' and password' if new_password else ''
    add_system_log(
        f"{role_label} account updated: {account_row[0]} -> {username}; email{password_note} updated"
    )
    return redirect(url_for('registered_users', success=f"{role_label} account updated successfully."))


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
               department, license_number, availability, experience, room_number,
               COALESCE(consultation_fee, 0)
        FROM doctors
        WHERE COALESCE(is_active, 1) = 1
        ORDER BY id ASC
    ''').fetchall()
    message = request.args.get('message') or request.args.get('success')
    return render_template("doctors.html", doctors=doctor_list, admin=admin_varifier, message=message)


@app.route('/doctor-prescription')
def doctor_prescription():
    """Professional prescription writing workspace for doctors."""
    if not isuser() and not isadmin():
        return redirect(url_for('login'))

    doctor_rows = db.execute('''
        SELECT id, name, COALESCE(designation, ''), COALESCE(specialization, ''),
               COALESCE(department, ''), COALESCE(license_number, ''), COALESCE(room_number, '')
        FROM doctors
        WHERE COALESCE(is_active, 1) = 1
        ORDER BY name ASC
    ''').fetchall()
    patient_rows = db.execute('''
        SELECT id, COALESCE(daily_patient_id, ''), name, age, COALESCE(age_unit, 'Y'),
               gender, phone, COALESCE(address, ''), COALESCE(blood_group, ''),
               COALESCE(medical_history, ''), COALESCE(doctor_name, ''),
               COALESCE(referer_name, ''),
               (SELECT d.id
                FROM doctors d
                WHERE TRIM(d.name) = TRIM(patients.doctor_name) COLLATE NOCASE
                  AND COALESCE(d.is_active, 1) = 1
                ORDER BY d.id ASC
                LIMIT 1) AS assigned_doctor_id
        FROM patients
        WHERE date(created_at) = ?
          AND daily_patient_id IS NOT NULL
        ORDER BY daily_patient_id ASC, id ASC
    ''', (current_calendar_date_text(),)).fetchall()
    test_rows = db.execute('''
        SELECT id, name, price
        FROM services
        WHERE type = 'test' AND COALESCE(is_active, 1) = 1
        ORDER BY name ASC
    ''').fetchall()
    medicine_rows = db.execute('''
        SELECT medicine_name, MAX(price) AS latest_price
        FROM medicine_transactions
        WHERE TRIM(COALESCE(medicine_name, '')) <> ''
        GROUP BY medicine_name
        ORDER BY medicine_name ASC
        LIMIT 500
    ''').fetchall()

    doctors = [
        {
            'id': row[0],
            'name': row[1],
            'designation': row[2],
            'specialization': row[3],
            'department': row[4],
            'license_number': row[5],
            'room_number': row[6],
        }
        for row in doctor_rows
    ]
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
            'blood_group': row[8],
            'medical_history': row[9],
            'doctor_name': row[10],
            'referer_name': row[11],
            'doctor_id': row[12],
        }
        for row in patient_rows
    ]
    initial_patient_id = patients[0]['id'] if patients else None
    if patients and patients[0].get('doctor_id'):
        current_queue_patient = db.execute('''
            SELECT current_patient_id
            FROM patient_queue_state
            WHERE doctor_id = ? AND queue_date = ?
        ''', (patients[0]['doctor_id'], current_calendar_date_text())).fetchone()
        if current_queue_patient and current_queue_patient[0] is not None:
            current_patient_id = int(current_queue_patient[0])
            if any(patient['id'] == current_patient_id for patient in patients):
                initial_patient_id = current_patient_id
    requested_patient_id = request.args.get('patient_id', '').strip()
    if requested_patient_id.isdigit() and any(patient['id'] == int(requested_patient_id) for patient in patients):
        initial_patient_id = int(requested_patient_id)
    tests = [
        {
            'id': row[0],
            'name': row[1],
            'price': row[2],
        }
        for row in test_rows
    ]
    medicines = [
        {
            'name': row[0],
            'latest_price': row[1],
        }
        for row in medicine_rows
    ]

    overview_row = db.execute(
        '''
        SELECT COUNT(*),
               SUM(CASE WHEN UPPER(COALESCE(patient_status, '')) = 'NEW' THEN 1 ELSE 0 END),
               SUM(CASE WHEN UPPER(COALESCE(patient_status, '')) = 'OLD' THEN 1 ELSE 0 END),
               SUM(CASE WHEN LOWER(COALESCE(gender, '')) = 'female' THEN 1 ELSE 0 END),
               SUM(CASE WHEN LOWER(COALESCE(gender, '')) = 'male' THEN 1 ELSE 0 END),
               SUM(CASE WHEN COALESCE(doctor_fee, 0) > 0 THEN 1 ELSE 0 END)
        FROM patients
        WHERE date(created_at) = ?
        ''', (current_calendar_date_text(),)
    ).fetchone()
    daily_overview = {
        'patients': int(overview_row[0] or 0),
        'new_patients': int(overview_row[1] or 0),
        'returning_patients': int(overview_row[2] or 0),
        'female_patients': int(overview_row[3] or 0),
        'male_patients': int(overview_row[4] or 0),
        'doctor_visits': int(overview_row[5] or 0),
        'doctors': len(doctors),
        'tests': len(tests),
        'medicines': len(medicines),
    }

    prescription_count = db.execute(
        'SELECT COUNT(*) FROM doctor_prescriptions WHERE prescription_date = ?',
        (current_calendar_date_text(),)
    ).fetchone()[0]

    return render_template(
        'doctor_prescription.html',
        doctors=doctors,
        patients=patients,
        tests=tests,
        medicines=medicines,
        today=current_calendar_date_text(),
        prescription_no=f"RX-{current_invoice_date_code()}-{int(prescription_count or 0) + 1:03d}",
        daily_overview=daily_overview,
        initial_patient_id=initial_patient_id,
    )


def build_patient_queue_snapshot(doctor_id=None):
    """Return today's live ticket position for one doctor or every doctor."""
    queue_date = current_calendar_date_text()
    doctor_params = []
    doctor_filter = 'WHERE COALESCE(is_active, 1) = 1'
    if doctor_id is not None:
        doctor_filter += ' AND id = ?'
        doctor_params.append(doctor_id)

    doctor_rows = db.execute(
        f'''
        SELECT id, name, COALESCE(designation, ''), COALESCE(specialization, ''),
               COALESCE(department, ''), COALESCE(room_number, '')
        FROM doctors
        {doctor_filter}
        ORDER BY name COLLATE NOCASE
        ''',
        doctor_params
    ).fetchall()

    queues = []
    for doctor in doctor_rows:
        state = db.execute('''
            SELECT current_patient_id, current_ticket_no, updated_at
            FROM patient_queue_state
            WHERE doctor_id = ? AND queue_date = ?
        ''', (doctor[0], queue_date)).fetchone()
        current_ticket = int(state[1]) if state and state[1] is not None else None
        current_patient_id = int(state[0]) if state and state[0] is not None else None

        queue_params = [queue_date, doctor[1]]
        ticket_position_filter = ''
        if current_ticket is not None:
            ticket_position_filter = 'AND p.daily_patient_id > ?'
            queue_params.append(current_ticket)

        next_patient = db.execute(
            f'''
            SELECT p.id, p.daily_patient_id
            FROM patients p
            LEFT JOIN patient_visit_returns r ON r.patient_id = p.id
            WHERE date(p.created_at) = ?
              AND TRIM(p.doctor_name) = TRIM(?) COLLATE NOCASE
              AND p.daily_patient_id IS NOT NULL
              AND r.id IS NULL
              {ticket_position_filter}
            ORDER BY p.daily_patient_id ASC, p.id ASC
            LIMIT 1
            ''',
            queue_params
        ).fetchone()

        count_params = [queue_date, doctor[1]]
        waiting_filter = ''
        if current_ticket is not None:
            waiting_filter = 'AND p.daily_patient_id > ?'
            count_params.append(current_ticket)
        waiting_count = db.execute(
            f'''
            SELECT COUNT(*)
            FROM patients p
            LEFT JOIN patient_visit_returns r ON r.patient_id = p.id
            WHERE date(p.created_at) = ?
              AND TRIM(p.doctor_name) = TRIM(?) COLLATE NOCASE
              AND p.daily_patient_id IS NOT NULL
              AND r.id IS NULL
              {waiting_filter}
            ''',
            count_params
        ).fetchone()[0]
        total_today = db.execute('''
            SELECT COUNT(*)
            FROM patients p
            LEFT JOIN patient_visit_returns r ON r.patient_id = p.id
            WHERE date(p.created_at) = ?
              AND TRIM(p.doctor_name) = TRIM(?) COLLATE NOCASE
              AND p.daily_patient_id IS NOT NULL
              AND r.id IS NULL
        ''', (queue_date, doctor[1])).fetchone()[0]

        queues.append({
            'doctor_id': doctor[0],
            'doctor_name': doctor[1],
            'designation': doctor[2],
            'specialization': doctor[3],
            'department': doctor[4],
            'room_number': doctor[5],
            'current_patient_id': current_patient_id,
            'current_ticket': current_ticket,
            'next_patient_id': int(next_patient[0]) if next_patient else None,
            'next_ticket': int(next_patient[1]) if next_patient else None,
            'waiting_count': int(waiting_count or 0),
            'total_today': int(total_today or 0),
            'updated_at': state[2] if state else None,
        })

    return {'date': queue_date, 'server_time': current_timestamp_text(), 'queues': queues}


@app.route('/patients-serial')
def patients_serial():
    """Reception TV display for one selected doctor's live serial."""
    if not isuser() and not isadmin():
        return redirect(url_for('login'))
    all_queue_data = build_patient_queue_snapshot()
    available_doctor_ids = {queue['doctor_id'] for queue in all_queue_data['queues']}
    selected_doctor_id = request.args.get('doctor_id', '').strip()
    if selected_doctor_id.isdigit() and int(selected_doctor_id) in available_doctor_ids:
        selected_doctor_id = int(selected_doctor_id)
    else:
        selected_doctor_id = all_queue_data['queues'][0]['doctor_id'] if all_queue_data['queues'] else None
    selected_queues = [
        queue for queue in all_queue_data['queues']
        if queue['doctor_id'] == selected_doctor_id
    ]
    queue_data = {**all_queue_data, 'queues': selected_queues}
    return render_template(
        'patients_serial.html',
        queue_data=queue_data,
        doctors=all_queue_data['queues'],
        selected_doctor_id=selected_doctor_id,
        display_date=current_calendar_date_text(),
    )


ADVERTISEMENT_DIR = os.path.join('assets', 'advertisements')
ADVERTISEMENT_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.webp', '.gif'}
ADVERTISEMENT_VIDEO_EXTENSIONS = {'.mp4', '.webm', '.ogg'}


def get_hospital_advertisements():
    os.makedirs(ADVERTISEMENT_DIR, exist_ok=True)
    media = []
    for filename in sorted(os.listdir(ADVERTISEMENT_DIR)):
        extension = os.path.splitext(filename)[1].lower()
        if extension not in ADVERTISEMENT_IMAGE_EXTENSIONS | ADVERTISEMENT_VIDEO_EXTENSIONS:
            continue
        media.append({
            'filename': filename,
            'url': url_for('assets', filename=f'advertisements/{filename}'),
            'type': 'video' if extension in ADVERTISEMENT_VIDEO_EXTENSIONS else 'image',
        })
    return media


@app.route('/hospital-advertisement')
def hospital_advertisement():
    """Full-screen reception display for hospital pictures and videos."""
    if not isuser() and not isadmin():
        return redirect(url_for('login'))
    return render_template(
        'hospital_advertisement.html',
        media_items=get_hospital_advertisements(),
        message=request.args.get('message', '').strip(),
        success=request.args.get('success', '').strip(),
    )


@app.route('/hospital-advertisement/upload', methods=['POST'])
def upload_hospital_advertisement():
    """Upload one reception advertisement image or browser-compatible video."""
    if not isuser() and not isadmin():
        return redirect(url_for('login'))
    upload = request.files.get('media_file')
    if not upload or not upload.filename:
        return redirect(url_for('hospital_advertisement', message='Please choose an image or video.'))
    extension = os.path.splitext(upload.filename)[1].lower()
    allowed_extensions = ADVERTISEMENT_IMAGE_EXTENSIONS | ADVERTISEMENT_VIDEO_EXTENSIONS
    if extension not in allowed_extensions:
        return redirect(url_for(
            'hospital_advertisement',
            message='Supported files: JPG, PNG, WEBP, GIF, MP4, WEBM, and OGG.'
        ))
    if request.content_length and request.content_length > 150 * 1024 * 1024:
        return redirect(url_for('hospital_advertisement', message='Advertisement file must be smaller than 150 MB.'))

    os.makedirs(ADVERTISEMENT_DIR, exist_ok=True)
    clean_name = secure_filename(os.path.splitext(upload.filename)[0]) or 'hospital-media'
    filename = f"{current_app_datetime().strftime('%Y%m%d%H%M%S%f')}-{clean_name}{extension}"
    try:
        upload.save(os.path.join(ADVERTISEMENT_DIR, filename))
        add_system_log(f'Hospital advertisement uploaded: {filename}')
        return redirect(url_for('hospital_advertisement', success='Advertisement media uploaded successfully.'))
    except OSError:
        return redirect(url_for('hospital_advertisement', message='Could not save this advertisement file.'))


@app.route('/patients-serial/status')
def patients_serial_status():
    """Polling API used by the TV display and prescription queue console."""
    if not isuser() and not isadmin():
        return jsonify({'success': False, 'error': 'Authentication required.'}), 401
    doctor_id = request.args.get('doctor_id', '').strip()
    if doctor_id and not doctor_id.isdigit():
        return jsonify({'success': False, 'error': 'Invalid doctor.'}), 400
    snapshot = build_patient_queue_snapshot(int(doctor_id) if doctor_id else None)
    snapshot['success'] = True
    return jsonify(snapshot)


@app.route('/doctor-prescription/queue/next', methods=['POST'])
def advance_patient_serial():
    """Call the next registered ticket for a doctor."""
    if not isuser() and not isadmin():
        return jsonify({'success': False, 'error': 'Authentication required.'}), 401
    payload = request.get_json(silent=True) or request.form
    doctor_id = str(payload.get('doctor_id', '')).strip()
    after_patient_id = str(payload.get('after_patient_id', '')).strip()
    if not doctor_id.isdigit():
        return jsonify({'success': False, 'error': 'Select a doctor before calling the next patient.'}), 400

    doctor = db.execute('SELECT id, name FROM doctors WHERE id = ? AND COALESCE(is_active, 1) = 1', (doctor_id,)).fetchone()
    if not doctor:
        return jsonify({'success': False, 'error': 'Doctor was not found.'}), 404

    queue_date = current_calendar_date_text()
    completed_patient = None
    if after_patient_id:
        if not after_patient_id.isdigit():
            return jsonify({'success': False, 'error': 'Invalid completed patient.'}), 400
        completed_patient = db.execute('''
            SELECT id, daily_patient_id
            FROM patients
            WHERE id = ?
              AND date(created_at) = ?
              AND TRIM(doctor_name) = TRIM(?) COLLATE NOCASE
              AND daily_patient_id IS NOT NULL
        ''', (after_patient_id, queue_date, doctor[1])).fetchone()
        if not completed_patient:
            return jsonify({
                'success': False,
                'error': 'The selected patient is not in this doctor\'s queue today.'
            }), 400
        current_ticket = int(completed_patient[1])
    else:
        state = db.execute('''
            SELECT current_ticket_no
            FROM patient_queue_state
            WHERE doctor_id = ? AND queue_date = ?
        ''', (doctor[0], queue_date)).fetchone()
        current_ticket = int(state[0]) if state and state[0] is not None else None
    params = [queue_date, doctor[1]]
    position_filter = ''
    if current_ticket is not None:
        position_filter = 'AND p.daily_patient_id > ?'
        params.append(current_ticket)
    next_patient = db.execute(
        f'''
        SELECT p.id, p.daily_patient_id
        FROM patients p
        LEFT JOIN patient_visit_returns r ON r.patient_id = p.id
        WHERE date(p.created_at) = ?
          AND TRIM(p.doctor_name) = TRIM(?) COLLATE NOCASE
          AND p.daily_patient_id IS NOT NULL
          AND r.id IS NULL
          {position_filter}
        ORDER BY p.daily_patient_id ASC, p.id ASC
        LIMIT 1
        ''',
        params
    ).fetchone()
    if not next_patient:
        if completed_patient:
            updated_at = current_timestamp_text()
            try:
                db.execute('''
                    INSERT INTO patient_queue_state (
                        doctor_id, queue_date, current_patient_id, current_ticket_no, updated_by, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(doctor_id, queue_date) DO UPDATE SET
                        current_patient_id = excluded.current_patient_id,
                        current_ticket_no = excluded.current_ticket_no,
                        updated_by = excluded.updated_by,
                        updated_at = excluded.updated_at
                ''', (
                    doctor[0], queue_date, completed_patient[0], completed_patient[1],
                    get_current_actor()[2], updated_at
                ))
                db.commit()
            except sqlite3.Error:
                db.rollback()
                return jsonify({'success': False, 'error': 'Could not update the patient queue.'}), 500

            snapshot = build_patient_queue_snapshot(doctor[0])
            return jsonify({
                'success': True,
                'queue_complete': True,
                'message': f'Ticket {completed_patient[1]} completed. No more patients are waiting.',
                **snapshot,
            })

        snapshot = build_patient_queue_snapshot(doctor[0])
        return jsonify({
            'success': False,
            'queue_complete': True,
            'error': 'No more waiting patients for this doctor today.',
            **snapshot,
        }), 409

    updated_at = current_timestamp_text()
    try:
        db.execute('''
            INSERT INTO patient_queue_state (
                doctor_id, queue_date, current_patient_id, current_ticket_no, updated_by, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(doctor_id, queue_date) DO UPDATE SET
                current_patient_id = excluded.current_patient_id,
                current_ticket_no = excluded.current_ticket_no,
                updated_by = excluded.updated_by,
                updated_at = excluded.updated_at
        ''', (
            doctor[0], queue_date, next_patient[0], next_patient[1],
            get_current_actor()[2], updated_at
        ))
        db.commit()
        add_system_log(f'Patient serial called: Ticket {next_patient[1]} for Dr. {doctor[1]}')
    except sqlite3.Error:
        db.rollback()
        return jsonify({'success': False, 'error': 'Could not advance the patient queue.'}), 500

    snapshot = build_patient_queue_snapshot(doctor[0])
    return jsonify({'success': True, 'message': f'Ticket {next_patient[1]} called.', **snapshot})


@app.route('/doctor-prescription/print')
def doctor_prescription_print():
    """A4 print format for doctor prescriptions."""
    if not isuser() and not isadmin():
        return redirect(url_for('login'))

    doctor = {}
    patient = {}
    doctor_id = request.args.get('doctor_id', '').strip()
    patient_id = request.args.get('patient_id', '').strip()

    if doctor_id.isdigit():
        row = db.execute('''
            SELECT id, name, COALESCE(designation, ''), COALESCE(specialization, ''),
                   COALESCE(department, ''), COALESCE(license_number, ''), COALESCE(room_number, '')
            FROM doctors
            WHERE id = ?
        ''', (doctor_id,)).fetchone()
        if row:
            doctor = {
                'id': row[0],
                'name': row[1],
                'designation': row[2],
                'specialization': row[3],
                'department': row[4],
                'license_number': row[5],
                'room_number': row[6],
            }

    if patient_id.isdigit():
        row = db.execute('''
            SELECT id, COALESCE(daily_patient_id, ''), name, age, COALESCE(age_unit, 'Y'),
                   gender, phone, COALESCE(address, ''), COALESCE(blood_group, '')
            FROM patients
            WHERE id = ?
        ''', (patient_id,)).fetchone()
        if row:
            patient = {
                'id': row[0],
                'daily_patient_id': row[1],
                'name': row[2],
                'age': row[3],
                'age_unit': row[4],
                'gender': row[5],
                'phone': row[6],
                'address': row[7],
                'blood_group': row[8],
            }

    vitals = {
        'bp': request.args.get('bp', '').strip(),
        'pulse': request.args.get('pulse', '').strip(),
        'temperature': request.args.get('temperature', '').strip(),
        'weight': request.args.get('weight', '').strip(),
    }
    clinical = {
        'complaints': request.args.get('complaints', '').strip(),
        'findings': request.args.get('findings', '').strip(),
        'diagnosis': request.args.get('diagnosis', '').strip(),
        'investigations': request.args.get('investigations', '').strip(),
        'advice': request.args.get('advice', '').strip(),
        'followup': request.args.get('followup', '').strip(),
    }
    medicine_names = request.args.getlist('medicine_name')
    medicine_doses = request.args.getlist('medicine_dose')
    medicine_durations = request.args.getlist('medicine_duration')
    medicine_instructions = request.args.getlist('medicine_instruction')
    medicines = []
    max_medicine_count = max(
        len(medicine_names),
        len(medicine_doses),
        len(medicine_durations),
        len(medicine_instructions),
        0,
    )
    for index in range(max_medicine_count):
        medicine = {
            'name': medicine_names[index].strip() if index < len(medicine_names) else '',
            'dose': medicine_doses[index].strip() if index < len(medicine_doses) else '',
            'duration': medicine_durations[index].strip() if index < len(medicine_durations) else '',
            'instruction': medicine_instructions[index].strip() if index < len(medicine_instructions) else '',
        }
        if any(medicine.values()):
            medicines.append(medicine)

    prescription_date = request.args.get('date', '').strip() or current_calendar_date_text()
    prescription_no = request.args.get('prescription_no', '').strip() or f"RX-{current_invoice_date_code()}"
    if doctor and patient:
        try:
            db.execute(
                '''
                INSERT INTO doctor_prescriptions (
                    prescription_no, prescription_date, patient_id, doctor_id,
                    vitals_json, clinical_json, medicines_json, created_by, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(prescription_no) DO UPDATE SET
                    prescription_date = excluded.prescription_date,
                    patient_id = excluded.patient_id,
                    doctor_id = excluded.doctor_id,
                    vitals_json = excluded.vitals_json,
                    clinical_json = excluded.clinical_json,
                    medicines_json = excluded.medicines_json
                ''',
                (
                    prescription_no, prescription_date, patient['id'], doctor['id'],
                    json.dumps(vitals, ensure_ascii=False), json.dumps(clinical, ensure_ascii=False),
                    json.dumps(medicines, ensure_ascii=False), get_current_actor()[2], current_timestamp_text()
                )
            )
            db.commit()
            db.execute('DELETE FROM doctor_prescription_drafts WHERE patient_id = ?', (patient['id'],))
            db.commit()
        except sqlite3.Error:
            db.rollback()

    return render_template(
        'doctor_prescription_print.html',
        doctor=doctor,
        patient=patient,
        vitals=vitals,
        clinical=clinical,
        medicines=medicines,
        today=current_calendar_date_text(),
        prescription_date=prescription_date,
        prescription_no=prescription_no,
    )


@app.route('/doctor-prescription/draft', methods=['POST'])
def save_doctor_prescription_draft():
    if not isuser() and not isadmin():
        return jsonify({'success': False, 'error': 'Authentication required.'}), 401
    payload = request.get_json(silent=True) or {}
    patient_id = str(payload.get('patient_id', '')).strip()
    doctor_id = str(payload.get('doctor_id', '')).strip()
    if not patient_id.isdigit():
        return jsonify({'success': False, 'error': 'Select a patient before saving the draft.'}), 400
    patient = db.execute('''
        SELECT p.id,
               (SELECT d.id
                FROM doctors d
                WHERE TRIM(d.name) = TRIM(p.doctor_name) COLLATE NOCASE
                  AND COALESCE(d.is_active, 1) = 1
                ORDER BY d.id ASC
                LIMIT 1)
        FROM patients p
        WHERE p.id = ?
    ''', (patient_id,)).fetchone()
    if not patient:
        return jsonify({'success': False, 'error': 'Patient not found.'}), 404
    assigned_doctor_id = patient[1]
    saved_doctor_id = assigned_doctor_id if assigned_doctor_id is not None else (int(doctor_id) if doctor_id.isdigit() else None)
    payload['doctor_id'] = str(saved_doctor_id or '')
    try:
        db.execute(
            '''INSERT INTO doctor_prescription_drafts (patient_id, doctor_id, draft_json, updated_by, updated_at)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(patient_id) DO UPDATE SET doctor_id=excluded.doctor_id,
                   draft_json=excluded.draft_json, updated_by=excluded.updated_by, updated_at=excluded.updated_at''',
            (int(patient_id), saved_doctor_id,
             json.dumps(payload, ensure_ascii=False), get_current_actor()[2], current_timestamp_text())
        )
        db.commit()
        return jsonify({'success': True})
    except sqlite3.Error:
        db.rollback()
        return jsonify({'success': False, 'error': 'Could not save draft.'}), 500


@app.route('/doctor-prescription/draft/<int:patient_id>', methods=['GET', 'DELETE'])
def get_doctor_prescription_draft(patient_id):
    if not isuser() and not isadmin():
        return jsonify({'success': False, 'error': 'Authentication required.'}), 401
    if request.method == 'DELETE':
        db.execute('DELETE FROM doctor_prescription_drafts WHERE patient_id = ?', (patient_id,))
        db.commit()
        return jsonify({'success': True})
    row = db.execute('SELECT draft_json FROM doctor_prescription_drafts WHERE patient_id = ?', (patient_id,)).fetchone()
    try:
        draft = json.loads(row[0]) if row else None
    except (TypeError, ValueError):
        draft = None
    return jsonify({'success': True, 'draft': draft})


@app.route('/doctor-prescription/saved/<int:prescription_id>')
def saved_doctor_prescription(prescription_id):
    """Open any previously printed prescription without changing the saved record."""
    if not isuser() and not isadmin():
        return redirect(url_for('login'))

    row = db.execute(
        '''
        SELECT dp.prescription_no, dp.prescription_date, dp.vitals_json,
               dp.clinical_json, dp.medicines_json,
               COALESCE(p.source_patient_id, p.id), p.daily_patient_id, p.name,
               p.age, COALESCE(NULLIF(p.age_unit, ''), 'Y'), p.gender, p.phone,
               d.id, d.name, COALESCE(d.designation, ''),
               COALESCE(d.specialization, ''), COALESCE(d.department, ''),
               COALESCE(d.license_number, ''), COALESCE(d.room_number, '')
        FROM doctor_prescriptions dp
        JOIN patients p ON p.id = dp.patient_id
        JOIN doctors d ON d.id = dp.doctor_id
        WHERE dp.id = ?
        ''',
        (prescription_id,)
    ).fetchone()
    if not row:
        return redirect(url_for('doctor_prescription_list'))

    try:
        vitals = json.loads(row[2] or '{}')
        clinical = json.loads(row[3] or '{}')
        medicines = json.loads(row[4] or '[]')
    except (TypeError, ValueError):
        vitals, clinical, medicines = {}, {}, []

    patient = {
        'id': row[5], 'daily_patient_id': row[6], 'name': row[7],
        'age': row[8], 'age_unit': row[9], 'gender': row[10], 'phone': row[11],
    }
    doctor = {
        'id': row[12], 'name': row[13], 'designation': row[14],
        'specialization': row[15], 'department': row[16],
        'license_number': row[17], 'room_number': row[18],
    }
    return render_template(
        'doctor_prescription_print.html',
        doctor=doctor,
        patient=patient,
        vitals=vitals,
        clinical=clinical,
        medicines=medicines,
        today=current_calendar_date_text(),
        prescription_date=row[1],
        prescription_no=row[0],
    )


@app.route('/doctor-prescription/list')
def doctor_prescription_list():
    """Searchable history of all saved/printed doctor prescriptions."""
    if not isuser() and not isadmin():
        return redirect(url_for('login'))
    keyword = request.args.get('q', '').strip()
    selected_date = request.args.get('date', '').strip()
    where = []
    params = []
    if selected_date:
        where.append('dp.prescription_date = ?')
        params.append(selected_date)
    if keyword:
        like = f'%{keyword}%'
        where.append('(dp.prescription_no LIKE ? OR p.name LIKE ? OR p.phone LIKE ? OR CAST(COALESCE(p.source_patient_id, p.id) AS TEXT) LIKE ? OR d.name LIKE ?)')
        params.extend([like] * 5)
    where_sql = ('WHERE ' + ' AND '.join(where)) if where else ''
    rows = db.execute(
        f'''
        SELECT dp.id, dp.prescription_no, dp.prescription_date, dp.created_at,
               p.name, p.phone, COALESCE(p.source_patient_id, p.id), p.daily_patient_id,
               d.name, COALESCE(d.designation, ''), dp.clinical_json, dp.medicines_json,
               dp.created_by, p.id
        FROM doctor_prescriptions dp
        JOIN patients p ON p.id = dp.patient_id
        JOIN doctors d ON d.id = dp.doctor_id
        {where_sql}
        ORDER BY datetime(dp.created_at) DESC, dp.id DESC
        ''', params
    ).fetchall()
    prescriptions = []
    for row in rows:
        try:
            clinical = json.loads(row[10] or '{}')
            medicines = json.loads(row[11] or '[]')
        except (TypeError, ValueError):
            clinical, medicines = {}, []
        prescriptions.append({
            'id': row[0], 'prescription_no': row[1], 'date': row[2], 'created_at': row[3],
            'patient_name': row[4], 'phone': row[5], 'uhid': row[6], 'ticket': row[7],
            'doctor_name': row[8], 'designation': row[9],
            'diagnosis': clinical.get('diagnosis') or '-', 'medicine_count': len(medicines),
            'created_by': row[12] or '-',
            'patient_id': row[13],
            'status': 'Printed',
        })
    draft_rows = db.execute(
        '''SELECT pd.id, pd.draft_json, pd.updated_by, pd.updated_at,
                  p.name, p.phone, COALESCE(p.source_patient_id, p.id), p.daily_patient_id,
                  COALESCE(d.name, 'Not selected'), COALESCE(d.designation, ''), p.id
           FROM doctor_prescription_drafts pd
           JOIN patients p ON p.id = pd.patient_id
           LEFT JOIN doctors d ON d.id = pd.doctor_id
           ORDER BY datetime(pd.updated_at) DESC'''
    ).fetchall()
    for row in draft_rows:
        try:
            draft = json.loads(row[1] or '{}')
        except (TypeError, ValueError):
            draft = {}
        fields = draft.get('fields') or {}
        medicines = draft.get('medicines') or []
        draft_date = str(fields.get('prescriptionDate') or row[3] or '')[:10]
        search_text = f"{row[4]} {row[5]} {row[6]} {row[7]} {row[8]} draft".lower()
        if selected_date and draft_date != selected_date:
            continue
        if keyword and keyword.lower() not in search_text:
            continue
        prescriptions.append({
            'id': f'draft-{row[0]}', 'prescription_no': 'DRAFT', 'date': draft_date,
            'created_at': row[3], 'patient_name': row[4], 'phone': row[5], 'uhid': row[6],
            'ticket': row[7], 'doctor_name': row[8], 'designation': row[9],
            'diagnosis': fields.get('diagnosis') or '-', 'medicine_count': len(medicines),
            'created_by': row[2] or '-', 'status': 'Draft',
            'patient_id': row[10],
        })
    prescription_count_rows = db.execute(
        '''
        SELECT COALESCE(p.source_patient_id, p.id) AS patient_uhid, COUNT(*)
        FROM doctor_prescriptions dp
        JOIN patients p ON p.id = dp.patient_id
        GROUP BY COALESCE(p.source_patient_id, p.id)
        '''
    ).fetchall()
    prescription_counts = {row[0]: int(row[1] or 0) for row in prescription_count_rows}
    today_visit_rows = db.execute(
        '''
        SELECT id, COALESCE(source_patient_id, id) AS patient_uhid, daily_patient_id
        FROM patients
        WHERE date(created_at) = ? AND daily_patient_id IS NOT NULL
        ORDER BY daily_patient_id ASC, id ASC
        ''',
        (current_calendar_date_text(),)
    ).fetchall()
    today_visits = {
        row[1]: {'patient_id': row[0], 'ticket': row[2]}
        for row in today_visit_rows
    }
    for item in prescriptions:
        today_visit = today_visits.get(item['uhid'])
        item['prescription_count'] = prescription_counts.get(item['uhid'], 0)
        item['today_patient_id'] = today_visit['patient_id'] if today_visit else None
        item['today_ticket'] = today_visit['ticket'] if today_visit else None
        item['view_url'] = url_for('saved_doctor_prescription', prescription_id=item['id']) if item['status'] == 'Printed' else None
        item['new_url'] = url_for('doctor_prescription', patient_id=today_visit['patient_id']) if today_visit else None
    prescriptions.sort(key=lambda item: item.get('created_at') or '', reverse=True)
    return render_template('doctor_prescription_list.html', prescriptions=prescriptions, keyword=keyword, selected_date=selected_date)


@app.route('/duty-management', methods=['GET', 'POST'])
def duty_management():
    """Track doctor rounds and nurse duty completion."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    selected_date = request.args.get('date', '').strip() or current_calendar_date_text()

    if request.method == 'POST':
        staff_role = request.form.get('staff_role', '').strip().lower()
        doctor_id = request.form.get('doctor_id', '').strip()
        staff_name = request.form.get('staff_name', '').strip()
        duty_date = request.form.get('duty_date', '').strip() or current_calendar_date_text()
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
            doctor_row = db.execute('SELECT id, name FROM doctors WHERE id = ? AND COALESCE(is_active, 1) = 1', (doctor_id,)).fetchone()
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
        WHERE COALESCE(is_active, 1) = 1
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
    selected_date = request.args.get('date', '').strip() or current_calendar_date_text()
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
            ) AS visit_return_no,
            COALESCE(NULLIF(served_by, ''), 'Admin') AS served_by
        FROM patients
    '''
    if show_all_patients:
        patient_query += '''
            WHERE source_patient_id IS NULL
            ORDER BY datetime(created_at) DESC, id DESC
        '''
        patient_list = db.execute(patient_query).fetchall()
        daily_patient_total = db.execute(
            'SELECT COUNT(*) FROM patients WHERE date(created_at) = ?',
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
        WHERE date(created_at) = ?
    ''', (current_calendar_date_text(),)).fetchone()[0]
    doctor_options = db.execute('''
        SELECT id, name, COALESCE(designation, '') AS designation,
               COALESCE(consultation_fee, 0) AS consultation_fee
        FROM doctors
        WHERE COALESCE(is_active, 1) = 1
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
        like_keyword = f'%{normalize_uhid_search(keyword)}%'
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

    search_keyword = normalize_uhid_search(keyword)
    # AJH18 and a short numeric value such as 18 both mean the exact UHID.
    # Longer numeric values remain available for phone-number searches.
    is_exact_uhid_search = search_keyword.isdigit() and (
        keyword.upper().startswith('AJH') or len(search_keyword) <= 6
    )
    if is_exact_uhid_search:
        search_condition = 'id = ?'
        search_params = (int(search_keyword),)
        search_order = 'id DESC'
    else:
        search_condition = '''
            (
                CAST(id AS TEXT) LIKE ?
                OR CAST(COALESCE(daily_patient_id, '') AS TEXT) LIKE ?
                OR name LIKE ?
                OR phone LIKE ?
            )
        '''
        like_search = f'%{search_keyword}%'
        search_params = (like_search, like_search, like_search, like_search, search_keyword)
        search_order = '''
            CASE WHEN phone = ? THEN 0 ELSE 1 END,
            datetime(created_at) DESC,
            id DESC
        '''

    rows = db.execute(
        f'''
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
          AND {search_condition}
        ORDER BY {search_order}
        LIMIT 12
        ''',
        search_params
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
            doctor_paid_amount,
            doctor_due_amount,
            created_at,
            source_patient_id
        FROM patients
        WHERE id = ?
    ''', (patient_id,)).fetchone()

    if not ticket:
        return redirect(url_for('patients_registration', message="Patient ticket not found."))

    doctor_fee = ticket[15] or 0
    doctor_paid_amount = float(ticket[16] or 0)
    doctor_due_amount = float(ticket[17] or 0)
    doctor_settlement = db.execute('''
        SELECT COALESCE(SUM(discount_amount), 0),
               COALESCE((
                   SELECT payment_method
                   FROM doctor_fee_due_collections latest
                   WHERE latest.patient_id = ?
                   ORDER BY latest.id DESC
                   LIMIT 1
               ), 'Cash')
        FROM doctor_fee_due_collections
        WHERE patient_id = ?
    ''', (patient_id, patient_id)).fetchone()
    doctor_discount_amount = float(doctor_settlement[0] or 0) if doctor_settlement else 0.0
    doctor_payment_method = doctor_settlement[1] if doctor_settlement else 'Cash'
    source_patient_id = ticket[19]
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
        'original_doctor_fee': float(doctor_fee or 0) + doctor_discount_amount,
        'discount_amount': doctor_discount_amount,
        'paid_amount': doctor_paid_amount,
        'due_amount': doctor_due_amount,
        'payment_method': doctor_payment_method,
        'created_at': ticket[18],
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
    ticket_created_date = str(ticket[18]).split(' ')[0] if ticket[18] else None
    if request.args.get('return_to') == 'doctor_due':
        return_url = url_for('doctor_fee_due_collection')
    else:
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
    """Add a doctor when Add Doctor permission is granted."""
    if isadmin() or isuser():
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
            consultation_fee = request.form.get('consultation_fee', '').strip()

            if not name or not phone or not email or not specialization or not designation or not department or not license_number or not availability or not experience or not room_number or consultation_fee == '':
                return render_template("add_doctor.html", error="Please fill in all required fields.")
            if not phone.isdigit() or len(phone) < 7:
                return render_template("add_doctor.html", error="Please enter a valid phone number.")
            if not experience.isdigit() or int(experience) < 0:
                return render_template("add_doctor.html", error="Please enter a valid number of years of experience.")
            try:
                consultation_fee_value = float(consultation_fee)
                if not math.isfinite(consultation_fee_value) or consultation_fee_value < 0:
                    raise ValueError
            except (TypeError, ValueError):
                return render_template("add_doctor.html", error="Please enter a valid consultation fee.")
            
            db.execute('''INSERT INTO doctors (name, phone, email, specialization, designation, department, license_number, availability, experience, room_number, consultation_fee) 
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                      (name, phone, email, specialization, designation, department, license_number, availability, experience, room_number, consultation_fee_value))
            db.commit()
            return redirect(url_for('doctors', success="Doctor added successfully."))
        return render_template("add_doctor.html")
    else:
        return redirect(url_for('login'))

@app.route('/edit_doctor/<int:doctor_id>', methods=['GET', 'POST'])
def edit_doctor(doctor_id):
    """Edit doctor information when Edit Doctor permission is granted."""
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    doctor = db.execute('''
        SELECT id, name, phone, email, specialization, designation,
               department, license_number, availability, experience, room_number,
               COALESCE(consultation_fee, 0)
        FROM doctors
        WHERE id = ? AND COALESCE(is_active, 1) = 1
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
        consultation_fee = request.form.get('consultation_fee', '').strip()

        if not name or not phone or not email or not specialization or not designation or not department or not license_number or not availability or not experience or not room_number or consultation_fee == '':
            return render_template("add_doctor.html", error="Please fill in all required fields.", doctor=doctor, mode="edit")
        if not phone.isdigit() or len(phone) < 7:
            return render_template("add_doctor.html", error="Please enter a valid phone number.", doctor=doctor, mode="edit")
        if not experience.isdigit() or int(experience) < 0:
            return render_template("add_doctor.html", error="Please enter a valid number of years of experience.", doctor=doctor, mode="edit")
        try:
            consultation_fee_value = float(consultation_fee)
            if not math.isfinite(consultation_fee_value) or consultation_fee_value < 0:
                raise ValueError
        except (TypeError, ValueError):
            return render_template("add_doctor.html", error="Please enter a valid consultation fee.", doctor=doctor, mode="edit")

        db.execute('''
            UPDATE doctors
            SET name = ?, phone = ?, email = ?, specialization = ?, designation = ?,
                department = ?, license_number = ?, availability = ?, experience = ?, room_number = ?,
                consultation_fee = ?
            WHERE id = ?
        ''', (name, phone, email, specialization, designation, department, license_number, availability, experience, room_number, consultation_fee_value, doctor_id))
        db.commit()
        return redirect(url_for('doctors', success="Doctor information updated successfully."))

    return render_template("add_doctor.html", doctor=doctor, mode="edit")


@app.route('/delete-doctor/<int:doctor_id>', methods=['POST'])
def delete_doctor(doctor_id):
    """Remove a doctor from active use while preserving linked clinical history."""
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    doctor = db.execute('SELECT id, name FROM doctors WHERE id = ? AND COALESCE(is_active, 1) = 1', (doctor_id,)).fetchone()
    if not doctor:
        return redirect(url_for('doctors', message='Doctor not found.'))

    linked_sources = (
        ('admissions', 'admission record'),
        ('doctor_prescriptions', 'prescription'),
        ('doctor_prescription_drafts', 'prescription draft'),
        ('duty_records', 'duty record'),
        ('patient_queue_state', 'patient queue record'),
    )
    linked_counts = []
    for table_name, label in linked_sources:
        table_exists = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,)
        ).fetchone()
        if not table_exists:
            continue
        count = db.execute(
            f'SELECT COUNT(*) FROM "{table_name}" WHERE doctor_id = ?',
            (doctor_id,)
        ).fetchone()[0]
        if count:
            linked_counts.append(f'{count} {label}{"s" if count != 1 else ""}')

    if linked_counts:
        db.execute('UPDATE doctors SET is_active = 0 WHERE id = ?', (doctor_id,))
        db.commit()
        add_system_log(
            f'Doctor removed from active list: {doctor[1]} (ID {doctor_id}); preserved {", ".join(linked_counts)}'
        )
        return redirect(url_for(
            'doctors',
            success=f'Dr. {doctor[1]} deleted from the active Doctors list. Historical records were preserved.'
        ))

    try:
        db.execute('DELETE FROM doctors WHERE id = ?', (doctor_id,))
        db.commit()
        add_system_log(f'Doctor deleted: {doctor[1]} (ID {doctor_id})')
        return redirect(url_for('doctors', success=f'Dr. {doctor[1]} deleted successfully.'))
    except sqlite3.IntegrityError:
        db.rollback()
        db.execute('UPDATE doctors SET is_active = 0 WHERE id = ?', (doctor_id,))
        db.commit()
        add_system_log(f'Doctor removed from active list: {doctor[1]} (ID {doctor_id})')
        return redirect(url_for(
            'doctors',
            success=f'Dr. {doctor[1]} deleted from the active Doctors list. Historical records were preserved.'
        ))
    
@app.route('/services')
def services():
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    service_list = db.execute('''
        SELECT id, name, type, price, sample_type, test_category, unit, reference_ranges
        FROM services
        WHERE COALESCE(is_active, 1) = 1
        ORDER BY type, name
    ''').fetchall()

    is_admin = isadmin()
    message = request.args.get('message') or request.args.get('success')

    return render_template("services.html", services=service_list, admin=is_admin, message=message)
    
@app.route('/add_service', methods=['GET', 'POST'])
def add_service():
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        service_type = request.form.get('type')  # 'doctor' or 'test'
        price = request.form.get('price')
        sample_type = request.form.get('sample_type', '').strip()
        test_category = request.form.get('test_category', '').strip()
        unit = request.form.get('unit', '').strip()
        reference_ranges = request.form.get('reference_ranges', '').strip()

        # Validation
        if not name or not service_type or not price:
            return render_template("add_new_service.html", error="All fields are required.")

        if service_type not in ['doctor', 'test']:
            return render_template("add_new_service.html", error="Invalid service type.")

        if service_type == 'test' and not all((sample_type, test_category, unit, reference_ranges)):
            return render_template("add_new_service.html", error="Test Name, Sample Type, Test Category, Unit, and Reference Ranges are required.")

        try:
            price = float(price)
            if price < 0:
                return render_template("add_new_service.html", error="Price must be positive.")
        except:
            return render_template("add_new_service.html", error="Invalid price format.")

        #  Insert into DB
        db.execute('''
            INSERT INTO services (name, type, price, sample_type, test_category, unit, reference_ranges)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            name, service_type, price,
            sample_type if service_type == 'test' else None,
            test_category if service_type == 'test' else None,
            unit if service_type == 'test' else None,
            reference_ranges if service_type == 'test' else None,
        ))
        db.commit()

        return redirect(url_for('services', success="Service added successfully."))

    return render_template("add_new_service.html")

@app.route('/edit_service/<int:service_id>', methods=['GET', 'POST'])
def edit_service(service_id):
    if not (isadmin() or isuser()):
        return redirect(url_for('login'))

    service = db.execute(
        'SELECT id, name, type, price, sample_type, test_category, unit, reference_ranges FROM services WHERE id = ?',
        (service_id,)
    ).fetchone()

    if not service:
        return redirect(url_for('services', message="Service not found."))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        service_type = request.form.get('type')
        price = request.form.get('price')
        sample_type = request.form.get('sample_type', '').strip()
        test_category = request.form.get('test_category', '').strip()
        unit = request.form.get('unit', '').strip()
        reference_ranges = request.form.get('reference_ranges', '').strip()

        if not name or not service_type or not price:
            return render_template("edit_service.html", service=service, error="All fields are required.")

        if service_type not in ['doctor', 'test']:
            return render_template("edit_service.html", service=service, error="Invalid service type.")

        if service_type == 'test' and not all((sample_type, test_category, unit, reference_ranges)):
            return render_template("edit_service.html", service=service, error="All test information fields are required.")

        try:
            price = float(price)
            if price < 0:
                return render_template("edit_service.html", service=service, error="Price must be positive.")
        except ValueError:
            return render_template("edit_service.html", service=service, error="Invalid price format.")

        db.execute(
            '''UPDATE services
               SET name = ?, type = ?, price = ?, sample_type = ?, test_category = ?, unit = ?, reference_ranges = ?
               WHERE id = ?''',
            (
                name, service_type, price,
                sample_type if service_type == 'test' else None,
                test_category if service_type == 'test' else None,
                unit if service_type == 'test' else None,
                reference_ranges if service_type == 'test' else None,
                service_id,
            )
        )
        db.commit()
        return redirect(url_for('services', message="Service updated successfully."))

    return render_template("edit_service.html", service=service)

@app.route('/delete_service/<int:service_id>', methods=['POST'])
def delete_service(service_id):
    # Only admin can delete services
    if not isadmin():
        return redirect(url_for('dashboard'))

    service = db.execute('SELECT id, name FROM services WHERE id = ?', (service_id,)).fetchone()
    if not service:
        return redirect(url_for('services', message="Service not found."))

    try:
        db.execute('UPDATE services SET is_active = 0 WHERE id = ?', (service_id,))
        db.commit()
        return redirect(url_for('services', message=f'"{service[1]}" deleted successfully.'))
    except sqlite3.Error:
        db.rollback()
        return redirect(url_for('services', message="Could not delete the service. Please try again."))


def _to_positive_float(value, default=0):
    try:
        amount = float(value or default)
        return amount if amount > 0 else 0
    except (TypeError, ValueError):
        return default


def generate_test_invoice_no():
    today_prefix = f"TB-{current_invoice_date_code()}"
    invoice_count = db.execute(
        "SELECT COUNT(*) FROM test_bills WHERE invoice_no LIKE ?",
        (f"{today_prefix}-%",)
    ).fetchone()[0]
    return f"{today_prefix}-{invoice_count + 1:03d}"


def get_recent_test_bills(bill_date, keyword=''):
    recent_query = '''
        SELECT tb.id, tb.invoice_no, p.name, p.phone, tb.total_amount, tb.due_amount, tb.created_at,
               COALESCE(p.source_patient_id, p.id) AS patient_uhid,
               (
                   SELECT COUNT(*)
                   FROM test_bills earlier_tb
                   WHERE date(earlier_tb.created_at) = date(tb.created_at)
                     AND (
                         datetime(earlier_tb.created_at) < datetime(tb.created_at)
                         OR (
                             datetime(earlier_tb.created_at) = datetime(tb.created_at)
                             AND earlier_tb.id <= tb.id
                         )
                     )
               ) AS daily_serial,
               tbr.return_no,
               CASE
                   WHEN tb.created_by = 'root_admin' THEN 'admin'
                   ELSE COALESCE(
                       (SELECT username FROM users WHERE CAST(users.id AS TEXT) = CAST(tb.created_by AS TEXT)),
                       (SELECT username FROM admins WHERE CAST(admins.id AS TEXT) = CAST(tb.created_by AS TEXT)),
                       NULLIF(tb.created_by, ''),
                       'Admin'
                   )
               END AS served_by
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
        ORDER BY daily_serial ASC, datetime(tb.created_at) ASC, tb.id ASC
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
                f"SELECT id, name, price FROM services WHERE type = 'test' AND COALESCE(is_active, 1) = 1 AND id IN ({placeholders})",
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
        discount_source = request.form.get('discount_source')
        if discount_source == 'percentage':
            discount_amount = subtotal * (percentage_discount_amount / 100)
        else:
            discount_amount = flat_discount_amount
        discount_amount = min(discount_amount, subtotal)
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
                    payment_method, remarks, get_current_actor()[2]
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
    today_text = current_calendar_date_text()
    bill_date = request.args.get('bill_date', '').strip() or today_text
    try:
        datetime.strptime(bill_date, '%Y-%m-%d')
    except ValueError:
        bill_date = today_text

    recent_bills = get_recent_test_bills(bill_date, keyword)

    if request.args.get('partial') == 'day_bills':
        return render_template(
            'day_wise_pathology_bills.html',
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
               created_at, COALESCE(source_patient_id, id) AS patient_uhid,
               CASE WHEN date(created_at) = ? THEN 1 ELSE 0 END AS is_daily
        FROM patients
        ORDER BY is_daily DESC, datetime(created_at) DESC, id DESC
        ''',
        (bill_date,)
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
            'is_daily': bool(row[13]),
        }
        for row in patient_rows
    ]

    test_rows = db.execute(
        '''
        SELECT id, name, price
        FROM services
        WHERE type = 'test' AND COALESCE(is_active, 1) = 1
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


@app.route('/test-billing/patient/<int:patient_id>/prescribed-tests')
def patient_prescribed_tests(patient_id):
    """Return catalog pathology tests selected in a patient's saved prescription draft."""
    if not isadmin() and not isuser():
        return jsonify({'success': False, 'error': 'Please sign in again.'}), 401

    patient = db.execute('SELECT id FROM patients WHERE id = ?', (patient_id,)).fetchone()
    if not patient:
        return jsonify({'success': False, 'error': 'Patient was not found.'}), 404

    draft_row = db.execute(
        'SELECT draft_json, updated_at FROM doctor_prescription_drafts WHERE patient_id = ?',
        (patient_id,)
    ).fetchone()
    if not draft_row:
        return jsonify({'success': True, 'tests': [], 'unmatched': [], 'draft_updated_at': None})

    try:
        draft = json.loads(draft_row[0] or '{}')
    except (TypeError, ValueError):
        draft = {}
    investigations = str((draft.get('fields') or {}).get('investigations') or '')
    requested_names = [line.strip() for line in investigations.splitlines() if line.strip()]

    service_rows = db.execute(
        '''
        SELECT id, name, price
        FROM services
        WHERE type = 'test' AND COALESCE(is_active, 1) = 1
        ORDER BY name ASC
        '''
    ).fetchall()
    services_by_name = {str(row[1]).strip().casefold(): row for row in service_rows}
    matched_tests = []
    unmatched_names = []
    matched_ids = set()
    for requested_name in requested_names:
        service = services_by_name.get(requested_name.casefold())
        if service and service[0] not in matched_ids:
            matched_ids.add(service[0])
            matched_tests.append({
                'id': service[0],
                'name': service[1],
                'price': float(service[2] or 0),
            })
        elif not service:
            unmatched_names.append(requested_name)

    return jsonify({
        'success': True,
        'tests': matched_tests,
        'unmatched': unmatched_names,
        'draft_updated_at': draft_row[1],
    })


@app.route('/test-billing/<int:test_bill_id>/details')
def test_bill_details(test_bill_id):
    """Return patient, selected tests, and prices for the pathology bill modal."""
    if not isadmin() and not isuser():
        return jsonify({'success': False, 'error': 'Please sign in again.'}), 401

    bill = db.execute(
        '''
        SELECT
            tb.id, tb.invoice_no, tb.created_at, tb.doctor_name, tb.referred_by,
            tb.sample_status, tb.subtotal, tb.discount_amount, tb.total_amount,
            tb.received_amount, tb.due_amount, tb.payment_method, tb.remarks,
            p.name, p.phone, p.age, COALESCE(NULLIF(p.age_unit, ''), 'Y'), p.gender,
            COALESCE(p.source_patient_id, p.id) AS patient_uhid,
            CASE
                WHEN tb.created_by = 'root_admin' THEN 'admin'
                ELSE COALESCE(
                    (SELECT username FROM users WHERE CAST(users.id AS TEXT) = CAST(tb.created_by AS TEXT)),
                    (SELECT username FROM admins WHERE CAST(admins.id AS TEXT) = CAST(tb.created_by AS TEXT)),
                    NULLIF(tb.created_by, ''),
                    'Admin'
                )
            END AS served_by
        FROM test_bills tb
        JOIN patients p ON p.id = tb.patient_id
        WHERE tb.id = ?
        ''',
        (test_bill_id,)
    ).fetchone()
    if not bill:
        return jsonify({'success': False, 'error': 'Pathology bill was not found.'}), 404

    item_rows = db.execute(
        '''
        SELECT test_name, price
        FROM test_bill_items
        WHERE test_bill_id = ?
        ORDER BY id ASC
        ''',
        (test_bill_id,)
    ).fetchall()

    return jsonify({
        'success': True,
        'bill': {
            'id': bill[0],
            'invoice_no': bill[1],
            'created_at': bill[2],
            'bill_date': format_date_display(bill[2]),
            'doctor_name': bill[3] or 'Not assigned',
            'referred_by': bill[4] or 'Self',
            'sample_status': bill[5] or 'Pending',
            'subtotal': float(bill[6] or 0),
            'discount': float(bill[7] or 0),
            'total': float(bill[8] or 0),
            'received': float(bill[9] or 0),
            'due': float(bill[10] or 0),
            'payment_method': bill[11] or 'Cash',
            'remarks': bill[12] or '',
            'patient_name': bill[13],
            'phone': bill[14] or '-',
            'age': bill[15],
            'age_unit': bill[16],
            'gender': bill[17] or '-',
            'patient_uhid': bill[18],
            'served_by': bill[19] or 'Admin',
        },
        'items': [
            {'name': row[0], 'price': float(row[1] or 0)}
            for row in item_rows
        ]
    })


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
               p.address, p.daily_patient_id, COALESCE(p.source_patient_id, p.id) AS patient_uhid,
               CASE
                   WHEN tb.created_by = 'root_admin' THEN 'admin'
                   ELSE COALESCE(
                       (SELECT username FROM users WHERE CAST(users.id AS TEXT) = CAST(tb.created_by AS TEXT)),
                       (SELECT username FROM admins WHERE CAST(admins.id AS TEXT) = CAST(tb.created_by AS TEXT)),
                       NULLIF(tb.created_by, ''),
                       'Admin'
                   )
               END AS served_by
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
        total_in_words=amount_to_words(bill[8]),
        prepared_by=bill[23],
        return_url=(
            url_for('test_due_collection')
            if request.args.get('return_to') == 'due'
            else url_for('test_billing')
        )
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
        return_date = current_calendar_date_text()
        created_at = current_timestamp_text()
        return_count = db.execute(
            "SELECT COUNT(*) FROM test_bill_returns WHERE date(return_date) = ?",
            (return_date,)
        ).fetchone()[0]
        return_no = f"TR-{current_invoice_date_code()}-{return_count + 1:03d}"

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


@app.route('/test-billing/due-collection/<int:test_bill_id>/details')
def test_due_details(test_bill_id):
    """Return complete pathology due information for the collection modal."""
    if not isadmin() and not isuser():
        return jsonify({'success': False, 'error': 'Please sign in again.'}), 401

    bill = db.execute(
        '''
        SELECT tb.id, tb.invoice_no, tb.subtotal, tb.discount_amount, tb.total_amount,
               tb.received_amount, tb.due_amount, tb.payment_method, tb.created_at,
               tb.doctor_name, tb.referred_by, tb.remarks, p.name, p.phone, p.age,
               COALESCE(NULLIF(p.age_unit, ''), 'Y'), p.gender,
               COALESCE(p.source_patient_id, p.id) AS patient_uhid,
               p.daily_patient_id
        FROM test_bills tb
        JOIN patients p ON p.id = tb.patient_id
        WHERE tb.id = ?
        ''',
        (test_bill_id,)
    ).fetchone()
    if not bill:
        return jsonify({'success': False, 'error': 'Pathology bill was not found.'}), 404
    if float(bill[6] or 0) <= 0:
        return jsonify({'success': False, 'error': 'This pathology bill has no pending due.'}), 409

    item_rows = db.execute(
        '''SELECT test_name, price FROM test_bill_items
           WHERE test_bill_id = ? ORDER BY id ASC''',
        (test_bill_id,)
    ).fetchall()
    return jsonify({
        'success': True,
        'bill': {
            'id': bill[0],
            'invoice_no': bill[1],
            'subtotal': float(bill[2] or 0),
            'discount': float(bill[3] or 0),
            'total': float(bill[4] or 0),
            'received': float(bill[5] or 0),
            'due': float(bill[6] or 0),
            'payment_method': bill[7] or 'Cash',
            'bill_date': format_date_display(bill[8]),
            'doctor_name': bill[9] or 'Not assigned',
            'referred_by': bill[10] or 'Self',
            'remarks': bill[11] or '',
            'patient_name': bill[12],
            'phone': bill[13] or '-',
            'age': bill[14],
            'age_unit': bill[15],
            'gender': bill[16] or '-',
            'patient_uhid': format_uhid(bill[17]),
            'ticket_no': bill[18] or '-',
            'collect_url': url_for('collect_test_due', test_bill_id=test_bill_id),
        },
        'items': [{'name': row[0], 'price': float(row[1] or 0)} for row in item_rows],
    })


@app.route('/test-billing/collect-due/<int:test_bill_id>', methods=['POST'], endpoint='collect_test_due')
def collect_test_due(test_bill_id):
    if not isadmin() and not isuser():
        return redirect(url_for('login'))

    bill = db.execute(
        '''SELECT id, patient_id, invoice_no, total_amount, received_amount, due_amount,
                  discount_amount, remarks
           FROM test_bills WHERE id = ?''',
        (test_bill_id,)
    ).fetchone()
    if not bill:
        return redirect(url_for('test_due_collection', message='Test bill not found.'))

    due_amount = float(bill[5] or 0)
    if due_amount <= 0:
        return redirect(url_for('test_due_collection', message='No due amount is pending for this bill.'))

    due_discount = min(_to_positive_float(request.form.get('due_discount')), due_amount)
    collectible_due = max(due_amount - due_discount, 0)
    collection_amount = min(_to_positive_float(request.form.get('collection_amount')), collectible_due)
    if collection_amount <= 0 and due_discount <= 0:
        return redirect(url_for('test_due_collection', message='Please enter a collection amount or due discount.'))

    payment_method = request.form.get('payment_method', '').strip()
    if payment_method not in ('Cash', 'Bkash', 'Nagad', 'Card', 'Bank'):
        payment_method = 'Cash'
    discount_note = request.form.get('discount_note', '').strip()
    previous_received = float(bill[4] or 0)
    previous_total = float(bill[3] or 0)
    new_discount = float(bill[6] or 0) + due_discount
    total_amount = max(previous_total - due_discount, 0)
    new_received = min(total_amount, previous_received + collection_amount)
    new_due = max(total_amount - new_received, 0)
    new_change = 0
    settlement_note = f'Due collection Tk {collection_amount:.2f}'
    if due_discount > 0:
        settlement_note += f' | Due discount Tk {due_discount:.2f}'
    if discount_note:
        settlement_note += f' ({discount_note})'
    existing_remarks = str(bill[7] or '').strip()
    updated_remarks = f'{existing_remarks} | {settlement_note}' if existing_remarks else settlement_note

    try:
        db.execute(
            '''
            UPDATE test_bills
            SET discount_amount = ?, total_amount = ?, received_amount = ?, due_amount = ?,
                change_amount = ?, payment_method = ?, remarks = ?
            WHERE id = ?
            ''',
            (
                new_discount, total_amount, new_received, new_due, new_change,
                payment_method, updated_remarks, test_bill_id
            )
        )
        db.commit()
        add_log(
            int(bill[1]),
            f"Test due settled: {bill[2]} (collected {collection_amount:.2f}, discount {due_discount:.2f})"
        )
        return redirect(url_for('test_bill_print', test_bill_id=test_bill_id, return_to='due'))
    except sqlite3.Error:
        db.rollback()
        return redirect(url_for('test_due_collection', message='Due collection could not be saved. Please try again.'))


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
          AND date(created_at) = ?
        ''',
        (current_calendar_date_text(),)
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
        WHERE type = 'test' AND COALESCE(is_active, 1) = 1
        ORDER BY name ASC
    ''').fetchall()

    is_admin = isadmin()

    return render_template("tests.html", tests=test_list, admin=is_admin)

if __name__ == '__main__':
    app_host = os.environ.get('PULSE_HMS_HOST', '127.0.0.1')
    app_port = int(os.environ.get('PULSE_HMS_PORT', '5000'))
    app_debug = os.environ.get('PULSE_HMS_DEBUG', '1') == '1'
    app.run(host=app_host, port=app_port, debug=app_debug, use_reloader=app_debug, threaded=True)
