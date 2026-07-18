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

    def test_user_permissions_can_be_updated_and_remain_selected(self):
        response = self.client.post(
            "/update_user_permissions",
            data={
                "user_id": "1",
                "page_permissions": ["medicine_sales", "medicine_return"],
            },
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Employee permissions updated successfully", response.data)
        saved_permissions = {
            row[0]
            for row in self.db.execute(
                "SELECT page_key FROM user_permissions WHERE user_id = 1"
            ).fetchall()
        }
        self.assertEqual(saved_permissions, {"medicine_sales", "medicine_return"})
        self.assertIn(b'value="medicine_sales" checked', response.data)
        self.assertIn(b'value="medicine_return" checked', response.data)
        self.assertIn(b'class="permission-details" open', response.data)

    def test_all_user_permissions_can_be_cleared(self):
        response = self.client.post(
            "/update_user_permissions",
            data={"user_id": "1"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Employee permissions cleared", response.data)
        saved_count = self.db.execute(
            "SELECT COUNT(*) FROM user_permissions WHERE user_id = 1"
        ).fetchone()[0]
        self.assertEqual(saved_count, 0)
        self.assertIn(b'class="permission-details" open', response.data)

    def test_medicine_permissions_are_enforced_individually(self):
        hospital_app.set_user_page_permissions(1, ["medicine_sales"])
        self.db.commit()
        with self.client.session_transaction() as session:
            session["user_id"] = 1
            session["role"] = "user"

        page_response = self.client.get("/medicine_payments")
        purchase_edit_response = self.client.post("/medicine_payments/purchase/1/edit")
        payment_edit_response = self.client.post("/medicine_payments/payment/1/edit")

        self.assertEqual(page_response.status_code, 302)
        self.assertTrue(page_response.headers["Location"].endswith("/medicine_sales"))
        self.assertEqual(purchase_edit_response.status_code, 302)
        self.assertTrue(purchase_edit_response.headers["Location"].endswith("/medicine_sales"))
        self.assertEqual(payment_edit_response.status_code, 302)
        self.assertTrue(payment_edit_response.headers["Location"].endswith("/medicine_sales"))


if __name__ == "__main__":
    unittest.main()
