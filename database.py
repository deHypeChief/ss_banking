# Add database.py
import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, Optional, List

class BankDatabase:
    def __init__(self, db_path=None):
        if db_path is None:
            # Use /tmp for writable location in containers, or current dir for local development
            if os.path.exists('/tmp'):
                db_path = '/tmp/banking.db'
            else:
                db_path = 'banking.db'

        # Ensure the directory exists
        db_dir = os.path.dirname(db_path)
        if db_dir and not os.path.exists(db_dir):
            os.makedirs(db_dir, exist_ok=True)

        try:
            self.conn = sqlite3.connect(db_path, check_same_thread=False)
            self.create_tables()
        except sqlite3.OperationalError as e:
            print(f"Database connection failed: {e}")
            # Fallback to in-memory database for development/testing
            self.conn = sqlite3.connect(':memory:', check_same_thread=False)
            self.create_tables()

    def create_tables(self):
        # Users table
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash BLOB,
                salt BLOB,
                email TEXT,
                account_balance REAL DEFAULT 0.0,
                registration_date TEXT
            )
        ''')

        # Sessions table
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                username TEXT,
                created_at TEXT,
                expires_at TEXT,
                FOREIGN KEY (username) REFERENCES users (username)
            )
        ''')

        # Transactions table
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                transaction_type TEXT,
                amount REAL,
                to_account TEXT,
                description TEXT,
                timestamp TEXT,
                FOREIGN KEY (username) REFERENCES users (username)
            )
        ''')

        self.conn.commit()

    # User methods
    def add_user(self, username: str, password_hash: bytes, salt: bytes, email: str):
        self.conn.execute('''
            INSERT INTO users (username, password_hash, salt, email, registration_date)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, password_hash, salt, email, datetime.now().isoformat()))
        self.conn.commit()

    def get_user(self, username: str) -> Optional[Dict]:
        cursor = self.conn.execute('SELECT * FROM users WHERE username = ?', (username,))
        row = cursor.fetchone()
        if row:
            return {
                'username': row[0],
                'password_hash': row[1],
                'salt': row[2],
                'email': row[3],
                'account_balance': row[4],
                'registration_date': row[5]
            }
        return None

    def update_balance(self, username: str, new_balance: float):
        self.conn.execute('UPDATE users SET account_balance = ? WHERE username = ?',
                         (new_balance, username))
        self.conn.commit()

    # Session methods
    def add_session(self, session_id: str, username: str, expires_at: datetime):
        self.conn.execute('''
            INSERT INTO sessions (session_id, username, created_at, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (session_id, username, datetime.now().isoformat(), expires_at.isoformat()))
        self.conn.commit()

    def get_session(self, session_id: str) -> Optional[Dict]:
        cursor = self.conn.execute('SELECT * FROM sessions WHERE session_id = ?', (session_id,))
        row = cursor.fetchone()
        if row:
            return {
                'session_id': row[0],
                'username': row[1],
                'created_at': row[2],
                'expires_at': row[3]
            }
        return None

    def delete_session(self, session_id: str):
        self.conn.execute('DELETE FROM sessions WHERE session_id = ?', (session_id,))
        self.conn.commit()

    def cleanup_expired_sessions(self):
        self.conn.execute('DELETE FROM sessions WHERE expires_at < ?',
                         (datetime.now().isoformat(),))
        self.conn.commit()

    # Transaction methods
    def add_transaction(self, username: str, transaction_type: str, amount: float,
                       to_account: Optional[str] = None, description: Optional[str] = None):
        self.conn.execute('''
            INSERT INTO transactions (username, transaction_type, amount, to_account, description, timestamp)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (username, transaction_type, amount, to_account, description, datetime.now().isoformat()))
        self.conn.commit()

    def get_user_transactions(self, username: str, limit: int = 50) -> List[Dict]:
        cursor = self.conn.execute('''
            SELECT * FROM transactions WHERE username = ?
            ORDER BY timestamp DESC LIMIT ?
        ''', (username, limit))
        transactions = []
        for row in cursor.fetchall():
            transactions.append({
                'id': row[0],
                'username': row[1],
                'transaction_type': row[2],
                'amount': row[3],
                'to_account': row[4],
                'description': row[5],
                'timestamp': row[6]
            })
        return transactions

    def close(self):
        self.conn.close()