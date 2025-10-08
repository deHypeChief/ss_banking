# Create app.py for web interface
from flask import Flask, render_template, request, jsonify
from src.banking_core import SecureOnlineBanking

app = Flask(__name__)
bank = SecureOnlineBanking()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.json['username']
    password = request.json['password']
    otp = request.json['otp']
    
    session_id = bank.authenticate_user(username, password, otp)
    if session_id:
        return jsonify({'status': 'success', 'session_id': session_id})
    else:
        return jsonify({'status': 'error', 'message': 'Authentication failed'})