import sqlite3
import unittest

from werkzeug.security import check_password_hash, generate_password_hash

import app as hospital_app


class RegisteredUserManagementTests(unittest.TestCase):
    def setUp(self):
        self.original_db = hospital_app.db
        self.db = sqlite3.connect(":memory:")
        self.db.executescript(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE
            );
            CREATE TABLE admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT UNIQUE
            );
            CREATE TABLE user_permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                page_key TEXT NOT NULL,
                UNIQUE(user_id, page_key)
            );
            CREATE TABLE logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                role TEXT,
                actor_name TEXT,
                patient_id INTEGER,
                action TEXT,
                timestamp TEXT
            );
            """
        )
        self.user_password = generate_password_hash("user-old-pass")
        self.admin_password = generate_password_hash("admin-old-pass")
        self.db.execute(
            "INSERT INTO users (username, password, email) VALUES (?, ?, ?)",
            ("employee-one", self.user_password, "employee@example.com"),
        )
        self.db.execute(
            "INSERT INTO admins (username, password, email) VALUES (?, ?, ?)",
            ("manager-one", self.admin_password, "manager@example.com"),
        )
        self.db.execute(
            "INSERT INTO user_permissions (user_id, page_key) VALUES (1, 'dashboard')"
        )
        self.db.commit()

        hospital_app.db = self.db
        hospital_app.app.config.update(TESTING=True)
        self.client = hospital_app.app.test_client()
        with self.client.session_transaction() as session:
            session["user_id"] = "root_admin"
            session["role"] = "admin"

    def tearDown(self):
        hospital_app.db = self.original_db
        self.db.close()

    def test_registered_users_page_has_account_editor_and_permission_manager(self):
        page = self.client.get("/registered_users")

        self.assertEqual(page.status_code, 200)
        self.assertIn(b"Manage permissions", page.data)
        self.assertIn(b"Find a page permission", page.data)
        self.assertIn(b'id="accountModal"', page.data)
        self.assertIn(b'data-account-type="user"', page.data)
        self.assertIn(b'data-account-type="admin"', page.data)

    def test_user_details_can_change_without_replacing_password(self):
        response = self.client.post(
            "/update_account",
            data={
                "account_type": "user",
                "account_id": "1",
                "username": "employee-updated",
                "email": "updated.employee@example.com",
                "new_password": "",
                "confirm_password": "",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Employee account updated successfully", response.data)
        row = self.db.execute(
            "SELECT username, password, email FROM users WHERE id = 1"
        ).fetchone()
        self.assertEqual(row[0], "employee-updated")
        self.assertEqual(row[1], self.user_password)
        self.assertEqual(row[2], "updated.employee@example.com")

    def test_admin_password_can_be_replaced(self):
        response = self.client.post(
            "/update_account",
            data={
                "account_type": "admin",
                "account_id": "1",
                "username": "manager-updated",
                "email": "updated.manager@example.com",
                "new_password": "new-secure-pass",
                "confirm_password": "new-secure-pass",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        row = self.db.execute(
            "SELECT username, password, email FROM admins WHERE id = 1"
        ).fetchone()
        self.assertEqual(row[0], "manager-updated")
        self.assertTrue(check_password_hash(row[1], "new-secure-pass"))
        self.assertEqual(row[2], "updated.manager@example.com")

    def test_cross_role_duplicate_username_is_rejected(self):
        response = self.client.post(
            "/update_account",
            data={
                "account_type": "user",
                "account_id": "1",
                "username": "manager-one",
                "email": "employee@example.com",
                "new_password": "",
                "confirm_password": "",
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"That username is already in use", response.data)
        username = self.db.execute("SELECT username FROM users WHERE id = 1").fetchone()[0]
        self.assertEqual(username, "employee-one")


if __name__ == "__main__":
    unittest.main()
