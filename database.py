# Add database.py
import sqlite3
import json
from datetime import datetime

class BankDatabase:
    def __init__(self):
        self.conn = sqlite3.connect('banking.db', check_same_thread=False)
        self.create_tables()
    
    def create_tables(self):
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash BLOB,
                salt BLOB,
                email TEXT,
                account_balance REAL,
                registration_date TEXT
            )
        ''')