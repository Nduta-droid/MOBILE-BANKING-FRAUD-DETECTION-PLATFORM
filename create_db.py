import sqlite3

# Connect to SQLite database (it will create the file if it doesn't exist)
conn = sqlite3.connect('users.db')
c = conn.cursor()

# Create users table with roles (admin, customer)
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    fullname TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL
)
''')

# Create transactions table
c.execute('''
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user TEXT NOT NULL,
    amount REAL NOT NULL,
    time_score REAL NOT NULL,
    location_score REAL NOT NULL,
    result TEXT NOT NULL
)
''')

conn.commit()
conn.close()

print("✅ Database and tables created successfully!")
import sqlite3


