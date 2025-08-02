from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
import pickle
import numpy as np

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

# Load ML model
with open('fraud_model.pkl', 'rb') as f:
    model = pickle.load(f)

# ─── CUSTOMER DASHBOARD ──────────────────────────────
@app.route('/', methods=['GET', 'POST'])
def customer_dashboard():
    result = None
    if 'user' not in session or session.get('role') != 'customer':
        return redirect(url_for('login'))

    if request.method == 'POST':
        try:
            amount = float(request.form['amount'])
            time_score = float(request.form['time'])
            location_score = float(request.form['location'])

            features = np.array([[amount, time_score, location_score]])
            prediction = model.predict(features)[0]
            result = 'Fraudulent' if prediction == -1 else 'Safe'

            # Save transaction
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("""
                INSERT INTO transactions (user, amount, time_score, location_score, result)
                VALUES (?, ?, ?, ?, ?)""",
                (session['user'], amount, time_score, location_score, result)
            )
            conn.commit()
            conn.close()
        except Exception as e:
            result = f"Invalid input or system error: {str(e)}"

    return render_template('customer_dashboard.html', result=result)

# ─── ADMIN DASHBOARD ──────────────────────────────
@app.route('/admin')
def admin_dashboard():
    if 'user' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM transactions")
    total_transactions = c.fetchone()[0]

    c.execute("SELECT COUNT(*) FROM transactions WHERE result = 'Fraudulent'")
    fraud_alerts = c.fetchone()[0]

    c.execute("SELECT user, amount, result FROM transactions ORDER BY id DESC LIMIT 5")
    recent_transactions = c.fetchall()
    conn.close()

    return render_template(
        'admin_dashboard.html',
        total_transactions=total_transactions,
        fraud_alerts=fraud_alerts,
        recent_transactions=recent_transactions
    )

# ─── SIGNUP ──────────────────────────────
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        fullname = request.form['fullname']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']
        role = request.form['role']  # 'admin' or 'customer'

        if password != confirm:
            flash('Passwords do not match!')
            return redirect(url_for('signup'))

        hashed_password = generate_password_hash(password)
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (fullname, email, password, role) VALUES (?, ?, ?, ?)",
                      (fullname, email, hashed_password, role))
            conn.commit()
            flash('Account created! Please log in.')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists!')
            return redirect(url_for('signup'))
        finally:
            conn.close()

    return render_template('signup.html')

# ─── LOGIN ──────────────────────────────
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[3], password):
            session['user'] = user[1]  # fullname
            session['role'] = user[4]  # role
            flash('Logged in successfully!')

            if session['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('customer_dashboard'))
        else:
            flash('Invalid login credentials')
            return redirect(url_for('login'))

    return render_template('login.html')

# ─── LOGOUT ──────────────────────────────
@app.route('/logout')
def logout():
    session.pop('user', None)
    session.pop('role', None)
    flash('You have been logged out.')
    return redirect(url_for('login'))

# ─── RUN APP ──────────────────────────────
if __name__ == '__main__':
    app.run(debug=True)
