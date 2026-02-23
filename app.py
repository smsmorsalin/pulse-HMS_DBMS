
from flask import Flask, render_template, request, redirect, url_for
import sqlite3

app = Flask(__name__)

# db = sqlite3.connect('hospital.db', check_same_thread=False)

@app.route('/')
def index():
    return render_template("index.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle login logic here
        username = request.form.get('username')
        password = request.form.get('password')
        # Validate credentials and redirect accordingly
        if not username or not password:
            return render_template("login.html", error="Please enter both username and password.")
        else:
            if username == "admin" and password == "password":  # Example validation
                return redirect(url_for('index'))
            else:
                return render_template("login.html", error="Invalid username or password.")
    return render_template("login.html")


if __name__ == '__main__':
    app.run(debug=True)