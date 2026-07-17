import sqlite3
import unittest

import app as hospital_app


class MedicinePackagingFlowTest(unittest.TestCase):
    def setUp(self):
        self.original_db = hospital_app.db
        self.db = sqlite3.connect(':memory:')
        self.db.executescript(
            '''
            CREATE TABLE admins (id TEXT PRIMARY KEY, username TEXT);
            CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT);
            CREATE TABLE patients (id INTEGER PRIMARY KEY, name TEXT, phone TEXT, address TEXT);
            CREATE TABLE medicine_transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                medicine_name TEXT NOT NULL,
                batch_no TEXT NOT NULL,
                unit_type TEXT NOT NULL DEFAULT 'strip',
                transaction_type TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                price REAL NOT NULL,
                strips_per_box INTEGER NOT NULL DEFAULT 1,
                strip_price REAL,
                box_price REAL,
                box_quantity INTEGER,
                strip_quantity INTEGER NOT NULL DEFAULT 0,
                supplier TEXT,
                purchase_amount REAL NOT NULL DEFAULT 0,
                transaction_date TEXT NOT NULL,
                note TEXT,
                created_by TEXT,
                created_at TEXT NOT NULL
            );
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
            );
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
                line_total REAL NOT NULL DEFAULT 0
            );
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
                created_at TEXT NOT NULL
            );
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
                line_total REAL NOT NULL DEFAULT 0
            );
            CREATE TABLE medicine_supplier_payments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                supplier TEXT NOT NULL,
                amount REAL NOT NULL,
                discount_amount REAL NOT NULL DEFAULT 0,
                payment_date TEXT NOT NULL,
                note TEXT,
                created_by TEXT,
                created_at TEXT NOT NULL
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
            '''
        )
        hospital_app.db = self.db
        hospital_app.app.config.update(TESTING=True)
        self.client = hospital_app.app.test_client()
        with self.client.session_transaction() as session:
            session['user_id'] = 'root_admin'
            session['role'] = 'admin'

    def tearDown(self):
        hospital_app.db = self.original_db
        self.db.close()

    def add_example_stock(self):
        response = self.client.post(
            '/medicine_stock_dashboard',
            data={
                'medicine_name': 'Example Medicine',
                'supplier': 'Example Supplier',
                'batch_no': 'B-100',
                'transaction_type': 'in',
                'box_quantity': '10',
                'strips_per_box': '3',
                'strip_price': '580',
                'box_price': '1700',
                'purchase_amount': '12000',
                'transaction_date': '2026-07-18',
            },
        )
        self.assertEqual(response.status_code, 302)

    def test_box_entry_is_stored_as_calculated_strip_stock(self):
        self.add_example_stock()
        row = self.db.execute(
            '''
            SELECT unit_type, quantity, strips_per_box, strip_price, box_price,
                   box_quantity, strip_quantity, supplier
            FROM medicine_transactions
            '''
        ).fetchone()
        self.assertEqual(row, ('strip', 30, 3, 580.0, 1700.0, 10, 0, 'Example Supplier'))

    def test_stock_and_sales_pages_render_packaging_controls(self):
        self.add_example_stock()
        stock_page = self.client.get('/medicine_stock_dashboard')
        sales_page = self.client.get('/medicine_sales')
        self.assertEqual(stock_page.status_code, 200)
        self.assertIn(b'Total Strips (Auto)', stock_page.data)
        self.assertIn(b'name="strip_quantity"', stock_page.data)
        self.assertIn(b'type="search"', stock_page.data)
        self.assertIn(b'list="medicineNameOptions"', stock_page.data)
        self.assertIn(b'list="supplierOptions"', stock_page.data)
        self.assertIn(b'id="supplierSearch"', stock_page.data)
        self.assertIn(b'Example Supplier', stock_page.data)
        self.assertIn(b'Example Medicine', stock_page.data)
        self.assertEqual(sales_page.status_code, 200)
        self.assertIn(b'Sale Unit', sales_page.data)
        self.assertIn(b'data-sale-unit="box"', sales_page.data)
        self.assertIn(b'data-sale-unit="strip"', sales_page.data)
        self.assertNotIn(b'class="sale-unit-select"', sales_page.data)
        self.assertNotIn(b'smart-qty-empty', sales_page.data)
        self.assertLess(sales_page.data.find(b'0 Strip'), sales_page.data.find(b'0 Box'))
        self.assertIn(b'data-box-price="1700.00"', sales_page.data)

    def test_box_and_loose_strip_quantities_are_combined_in_stock(self):
        response = self.client.post(
            '/medicine_stock_dashboard',
            data={
                'medicine_name': 'Mixed Stock Medicine',
                'supplier': 'Example Supplier',
                'batch_no': 'MIX-1',
                'transaction_type': 'in',
                'box_quantity': '2',
                'strip_quantity': '4',
                'strips_per_box': '3',
                'strip_price': '100',
                'box_price': '280',
                'purchase_amount': '700',
                'transaction_date': '2026-07-18',
            },
        )
        self.assertEqual(response.status_code, 302)
        row = self.db.execute(
            'SELECT quantity, box_quantity, strip_quantity, strips_per_box '
            'FROM medicine_transactions WHERE medicine_name = ?',
            ('Mixed Stock Medicine',),
        ).fetchone()
        self.assertEqual(row, (10, 2, 4, 3))

    def test_stock_in_medicine_button_shows_only_that_medicine_history(self):
        self.add_example_stock()
        self.client.post(
            '/medicine_stock_dashboard',
            data={
                'medicine_name': 'Other Medicine',
                'supplier': 'Other Supplier',
                'batch_no': 'B-200',
                'transaction_type': 'in',
                'box_quantity': '2',
                'strips_per_box': '5',
                'strip_price': '100',
                'box_price': '450',
                'purchase_amount': '700',
                'transaction_date': '2026-07-17',
            },
        )
        page = self.client.get(
            '/medicine_stock_dashboard/movements/stock-in',
            query_string={'medicine': 'Example Medicine', 'all_dates': '1'},
        )
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'Showing all transactions for Example Medicine', page.data)
        self.assertIn(b'Box Qty', page.data)
        self.assertIn(b'10 boxes', page.data)
        self.assertIn(b'Example Supplier', page.data)
        transaction_table = page.data.split(b'<div class="table-wrap">', 1)[1]
        self.assertIn(b'Example Medicine', transaction_table)
        self.assertNotIn(b'Other Medicine', transaction_table)

    def test_supplier_payment_page_tracks_purchase_paid_and_due(self):
        self.add_example_stock()
        page = self.client.get('/medicine_payments')
        self.assertEqual(page.status_code, 200)
        self.assertIn(b'Example Supplier', page.data)
        self.assertIn(b'Medicine Name', page.data)
        self.assertIn(b'class="medicine-list">Example Medicine</td>', page.data)
        self.assertIn(b'Tk 12000.00', page.data)

        response = self.client.post(
            '/medicine_payments',
            data={
                'supplier': 'Example Supplier',
                'amount': '5000',
                'payment_date': '2026-07-18',
                'note': 'Bank payment',
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Tk 5000.00 payment and Tk 0.00 discount saved', response.data)
        self.assertIn(b'Tk 7000.00', response.data)

    def test_supplier_discount_and_history_records_can_be_edited(self):
        self.add_example_stock()
        payment_response = self.client.post(
            '/medicine_payments',
            data={
                'supplier': 'Example Supplier',
                'amount': '5000',
                'discount_amount': '500',
                'payment_date': '2026-07-18',
                'note': 'Initial settlement',
            },
            follow_redirects=True,
        )
        self.assertEqual(payment_response.status_code, 200)
        self.assertIn(b'Discount Amount', payment_response.data)
        self.assertIn(b'id="autoSupplierDiscount"', payment_response.data)
        self.assertIn(b'Automatically calculated as Current Due', payment_response.data)
        self.assertIn(b'id="supplierRemainingDue"', payment_response.data)
        self.assertIn(b'purchase-edit-btn', payment_response.data)
        self.assertIn(b'payment-edit-btn', payment_response.data)
        self.assertIn(b'Tk 6500.00', payment_response.data)

        edit_payment = self.client.post(
            '/medicine_payments/payment/1/edit',
            data={
                'supplier': 'Example Supplier',
                'amount': '4500',
                'discount_amount': '1000',
                'payment_date': '2026-07-19',
                'note': 'Edited settlement',
            },
            follow_redirects=True,
        )
        self.assertEqual(edit_payment.status_code, 200)
        self.assertIn(b'Supplier payment record updated successfully', edit_payment.data)
        payment = self.db.execute(
            'SELECT amount, discount_amount, payment_date, note '
            'FROM medicine_supplier_payments WHERE id = 1'
        ).fetchone()
        self.assertEqual(payment, (4500.0, 1000.0, '2026-07-19', 'Edited settlement'))

        edit_purchase = self.client.post(
            '/medicine_payments/purchase/1/edit',
            data={
                'medicine_name': 'Example Medicine',
                'supplier': 'Example Supplier',
                'batch_no': 'B-100',
                'box_quantity': '10',
                'strips_per_box': '3',
                'strip_price': '600',
                'box_price': '1750',
                'purchase_amount': '13000',
                'transaction_date': '2026-07-20',
            },
            follow_redirects=True,
        )
        self.assertEqual(edit_purchase.status_code, 200)
        self.assertIn(b'Medicine purchase record updated successfully', edit_purchase.data)
        purchase = self.db.execute(
            'SELECT quantity, strip_price, box_price, purchase_amount, transaction_date '
            'FROM medicine_transactions WHERE id = 1'
        ).fetchone()
        self.assertEqual(purchase, (30, 600.0, 1750.0, 13000.0, '2026-07-20'))
        self.assertIn(b'Tk 7500.00', edit_purchase.data)

    def test_box_sale_uses_box_price_and_deducts_three_strips(self):
        self.add_example_stock()
        response = self.client.post(
            '/medicine_sales/save',
            json={
                'customerName': 'Walk-in Customer',
                'items': [{
                    'product': 'Example Medicine',
                    'batch': 'B-100',
                    'unit': 'box',
                    'quantity': 1,
                    'price': 1,
                    'discount': 0,
                }],
                'receivedAmount': 1700,
            },
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        sale_item = self.db.execute(
            'SELECT unit_type, quantity, unit_price, strips_per_unit, line_total FROM medicine_sale_items'
        ).fetchone()
        self.assertEqual(sale_item, ('box', 1, 1700.0, 3, 1700.0))
        stock_out = self.db.execute(
            "SELECT unit_type, quantity FROM medicine_transactions WHERE transaction_type = 'out'"
        ).fetchone()
        self.assertEqual(stock_out, ('strip', 3))
        self.assertEqual(hospital_app.get_medicine_balance_rows()[0]['balance'], 27)

    def test_medicine_can_be_returned_directly_by_name_and_quantity(self):
        self.add_example_stock()
        sale_response = self.client.post(
            '/medicine_sales/save',
            json={
                'customerName': 'Walk-in Customer',
                'items': [{
                    'product': 'Example Medicine',
                    'batch': 'B-100',
                    'unit': 'box',
                    'quantity': 2,
                    'price': 1,
                    'discount': 0,
                }],
                'receivedAmount': 3400,
            },
        )
        self.assertEqual(sale_response.status_code, 200, sale_response.get_json())

        return_page = self.client.get('/medicine_return')
        self.assertEqual(return_page.status_code, 200)
        self.assertIn(b'Return by Medicine Name', return_page.data)
        self.assertIn(b'Example Medicine', return_page.data)
        self.assertIn(b'2 Boxes | 0 Strips available', return_page.data)
        self.assertIn(b'name="return_unit"', return_page.data)
        self.assertIn(b'0 Boxes', return_page.data)
        self.assertIn(b'0 Strips', return_page.data)
        self.assertIn(b'name="return_quantity"', return_page.data)

        return_response = self.client.post(
            '/medicine_return',
            data={
                'return_mode': 'medicine',
                'medicine_name': 'Example Medicine',
                'return_unit': 'box',
                'return_quantity': '1',
                'reason': 'Customer returned one box',
            },
            follow_redirects=True,
        )
        self.assertEqual(return_response.status_code, 200)
        self.assertIn(b'1 Box of Example Medicine returned successfully', return_response.data)
        return_item = self.db.execute(
            'SELECT medicine_name, unit_type, quantity FROM medicine_return_items'
        ).fetchone()
        self.assertEqual(return_item, ('Example Medicine', 'box', 1))
        restored_stock = self.db.execute(
            "SELECT unit_type, quantity FROM medicine_transactions "
            "WHERE transaction_type = 'in' AND note LIKE 'Returned on %'"
        ).fetchone()
        self.assertEqual(restored_stock, ('strip', 3))
        self.assertEqual(hospital_app.get_medicine_balance_rows()[0]['balance'], 27)

        sales_list = self.client.get('/medicine_sales_list', query_string={'date': '2026-07-18'})
        print_list = self.client.get('/medicine_sales_list/print', query_string={'date': '2026-07-18'})
        self.assertEqual(sales_list.status_code, 200)
        self.assertEqual(print_list.status_code, 200)
        self.assertIn(b'Sales Records', sales_list.data)
        self.assertIn(b'<th>No.</th>', sales_list.data)
        self.assertIn(b'class="sale-list-row"', sales_list.data)
        self.assertIn(b'class="sale-medicine-list"', sales_list.data)
        self.assertIn(b'Returned Medicine', sales_list.data)
        self.assertIn(b'Box \xc3\x97 1', sales_list.data)
        self.assertIn(b'Medicine-Wise Net Summary', print_list.data)
        self.assertIn(b'Returned Medicine / Unit / Qty', print_list.data)
        self.assertIn(b'Qty 1', print_list.data)

    def test_strip_sale_uses_strip_price_and_deducts_one_per_quantity(self):
        self.add_example_stock()
        response = self.client.post(
            '/medicine_sales/save',
            json={
                'items': [{
                    'product': 'Example Medicine',
                    'batch': 'B-100',
                    'unit': 'strip',
                    'quantity': 2,
                    'price': 1,
                    'discount': 0,
                }],
            },
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        sale_item = self.db.execute(
            'SELECT unit_type, quantity, unit_price, strips_per_unit, line_total FROM medicine_sale_items'
        ).fetchone()
        self.assertEqual(sale_item, ('strip', 2, 580.0, 1, 1160.0))
        self.assertEqual(hospital_app.get_medicine_balance_rows()[0]['balance'], 28)

    def test_mixed_box_and_strip_sale_uses_smart_packaging(self):
        self.add_example_stock()
        response = self.client.post(
            '/medicine_sales/save',
            json={
                'items': [
                    {
                        'product': 'Example Medicine',
                        'batch': 'B-100',
                        'unit': 'box',
                        'quantity': 1,
                        'discount': 0,
                    },
                    {
                        'product': 'Example Medicine',
                        'batch': 'B-100',
                        'unit': 'strip',
                        'quantity': 2,
                        'discount': 0,
                    },
                ],
            },
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        sale_items = self.db.execute(
            'SELECT unit_type, quantity, unit_price FROM medicine_sale_items ORDER BY id'
        ).fetchall()
        self.assertEqual(sale_items, [('box', 1, 1700.0), ('strip', 2, 580.0)])
        self.assertEqual(hospital_app.get_medicine_balance_rows()[0]['balance'], 25)


if __name__ == '__main__':
    unittest.main()
