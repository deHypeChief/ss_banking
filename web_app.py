from flask import Flask, render_template_string, request, jsonify, session as flask_session
import sys
import os
import json
from datetime import datetime

sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.banking_core import SecureOnlineBanking
from src.performance_reporter import PerformanceReporter

app = Flask(__name__)
app.secret_key = 'your-secret-key-123'  # Needed for flask sessions
bank = SecureOnlineBanking()

# Main dashboard HTML
DASHBOARD_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Banking Dashboard</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 800px; margin: 0 auto; }
        .header { background: #007cba; color: white; padding: 20px; border-radius: 10px 10px 0 0; }
        .nav { background: white; padding: 15px; border-bottom: 1px solid #ddd; }
        .nav button { margin: 0 10px; padding: 10px 20px; background: #007cba; color: white; border: none; border-radius: 5px; cursor: pointer; }
        .content { background: white; padding: 20px; border-radius: 0 0 10px 10px; }
        .card { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #007cba; }
        .success { color: green; }
        .error { color: red; }
        .transaction { border: 1px solid #ddd; padding: 10px; margin: 5px 0; border-radius: 5px; }
        .balance { font-size: 24px; font-weight: bold; color: #007cba; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🏦 Secure Banking Dashboard</h1>
            <p>Welcome, <strong>{{ username }}</strong>! | Session: {{ session_id[:20] }}...</p>
        </div>
        
        <div class="nav">
            <button onclick="showSection('dashboard')">📊 Dashboard</button>
            <button onclick="showSection('transactions')">💳 Transactions</button>
            <button onclick="showSection('transfer')">🔄 Transfer Money</button>
            <button onclick="showSection('profile')">👤 Profile</button>
            <button onclick="showSection('performance')">📈 Performance</button>
            <button onclick="logout()">🚪 Logout</button>
        </div>

        <div class="content">
            <!-- Dashboard Section -->
            <div id="dashboard-section" class="section">
                <h2>Account Overview</h2>
                <div class="card">
                    <h3>💰 Account Balance</h3>
                    <div class="balance" id="balance-display">Loading...</div>
                </div>
                <div class="card">
                    <h3>📈 Recent Activity</h3>
                    <div id="recent-activity">Loading...</div>
                </div>
                <div class="card">
                    <h3>🛡️ Security Status</h3>
                    <p>✅ MFA Enabled</p>
                    <p>✅ Secure Session Active</p>
                    <p>✅ TLS Encryption</p>
                </div>
            </div>

            <!-- Transactions Section -->
            <div id="transactions-section" class="section" style="display:none">
                <h2>Transaction History</h2>
                <div id="transaction-history"></div>
            </div>

            <!-- Transfer Money Section -->
            <div id="transfer-section" class="section" style="display:none">
                <h2>Transfer Money</h2>
                <form onsubmit="transferMoney(event)">
                    <input type="text" id="to-account" placeholder="To Account" required>
                    <input type="number" id="amount" placeholder="Amount" step="0.01" required>
                    <input type="text" id="description" placeholder="Description" required>
                    <button type="submit">Transfer Money</button>
                </form>
                <div id="transfer-result"></div>
            </div>

            <!-- Profile Section -->
            <div id="profile-section" class="section" style="display:none">
                <h2>Account Profile</h2>
                <div class="card">
                    <p><strong>Username:</strong> {{ username }}</p>
                    <p><strong>Email:</strong> {{ email }}</p>
                    <p><strong>Account Created:</strong> {{ registration_date }}</p>
                    <p><strong>MFA Status:</strong> ✅ Enabled</p>
                </div>
            </div>

            <!-- Performance Section -->
            <div id="performance-section" class="section" style="display:none">
                <h2>System Performance</h2>
                <div id="performance-data"></div>
            </div>
        </div>
    </div>

    <script>
        let currentSession = "{{ session_id }}";
        
        function showSection(sectionName) {
            // Hide all sections
            document.querySelectorAll('.section').forEach(section => {
                section.style.display = 'none';
            });
            // Show selected section
            document.getElementById(sectionName + '-section').style.display = 'block';
            
            // Load section data
            if (sectionName === 'dashboard') {
                loadDashboard();
            } else if (sectionName === 'transactions') {
                loadTransactions();
            } else if (sectionName === 'performance') {
                loadPerformance();
            }
        }

        async function loadDashboard() {
            try {
                const response = await fetch('/api/balance?session=' + currentSession);
                const data = await response.json();
                
                if (data.success) {
                    document.getElementById('balance-display').textContent = '$' + data.balance.toFixed(2);
                    document.getElementById('recent-activity').innerHTML = 
                        `<p>Last login: ${new Date().toLocaleString()}</p>
                         <p>Account is secure and active</p>`;
                }
            } catch (error) {
                console.error('Error loading dashboard:', error);
            }
        }

        async function loadTransactions() {
            try {
                const response = await fetch('/api/transactions?session=' + currentSession);
                const data = await response.json();
                
                if (data.success) {
                    let html = `<p>Total Transactions: ${data.transaction_count}</p>`;
                    if (data.transactions && data.transactions.length > 0) {
                        data.transactions.forEach(txn => {
                            html += `<div class="transaction">
                                <strong>${txn}</strong> - Processed
                            </div>`;
                        });
                    } else {
                        html += '<p>No transactions yet</p>';
                    }
                    document.getElementById('transaction-history').innerHTML = html;
                }
            } catch (error) {
                console.error('Error loading transactions:', error);
            }
        }

        async function loadPerformance() {
            try {
                const response = await fetch('/api/performance?session=' + currentSession);
                const data = await response.json();
                
                if (data.success) {
                    let html = '<div class="card">';
                    html += `<h3>System Performance</h3>`;
                    html += `<p>Total Operations: ${data.total_operations}</p>`;
                    html += `<p>Avg Crypto Time: ${data.avg_crypto_time}ms</p>`;
                    html += `<p>System Health: CPU ${data.cpu_usage}%, Memory ${data.memory_usage}%</p>`;
                    html += '</div>';
                    document.getElementById('performance-data').innerHTML = html;
                }
            } catch (error) {
                console.error('Error loading performance:', error);
            }
        }

        async function transferMoney(e) {
            e.preventDefault();
            const data = {
                to_account: document.getElementById('to-account').value,
                amount: parseFloat(document.getElementById('amount').value),
                description: document.getElementById('description').value,
                session: currentSession
            };

            const response = await fetch('/api/transfer', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            });

            const result = await response.json();
            document.getElementById('transfer-result').innerHTML = 
                result.success ? 
                `<div class="success">✅ ${result.message}</div>` :
                `<div class="error">❌ ${result.message}</div>`;
                
            // Reload balance
            if (result.success) {
                loadDashboard();
            }
        }

        function logout() {
            fetch('/api/logout?session=' + currentSession)
                .then(() => {
                    window.location.href = '/';
                });
        }

        // Load dashboard on page load
        showSection('dashboard');
    </script>
</body>
</html>
'''

# Login page HTML (same as before but redirects to dashboard)
LOGIN_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Banking System</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .form-group { margin: 20px 0; }
        input, button { padding: 12px; margin: 8px 0; width: 100%; box-sizing: border-box; border: 1px solid #ddd; border-radius: 5px; }
        button { background: #007cba; color: white; border: none; cursor: pointer; font-size: 16px; }
        button:hover { background: #005a87; }
        .success { color: green; background: #e8f5e8; padding: 10px; border-radius: 5px; }
        .error { color: red; background: #ffe8e8; padding: 10px; border-radius: 5px; }
        .info { color: #666; font-size: 14px; margin-top: 5px; }
        h1 { color: #333; text-align: center; }
        .section { border-bottom: 1px solid #eee; padding-bottom: 20px; margin-bottom: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🏦 Secure Banking System</h1>
        
        <div class="section">
            <h3>📝 Register User</h3>
            <div class="info">Password must be 12+ characters with uppercase, lowercase, numbers, and special characters</div>
            <form onsubmit="registerUser(event)">
                <input type="text" id="reg_username" placeholder="Username" required>
                <input type="password" id="reg_password" placeholder="Password (min 12 characters)" required>
                <input type="email" id="reg_email" placeholder="Email" required>
                <button type="submit">Register User</button>
            </form>
            <div id="register-result"></div>
        </div>

        <div class="section">
            <h3>🔑 Generate OTP</h3>
            <div class="info">OTP codes change every 30 seconds. Generate a fresh one right before login.</div>
            <button onclick="generateOTP()">Generate Fresh OTP</button>
            <div id="otp-result"></div>
        </div>

        <div class="section">
            <h3>🚀 Login</h3>
            <div class="info">Use the OTP from above within 30 seconds</div>
            <form onsubmit="loginUser(event)">
                <input type="text" id="login_username" placeholder="Username" required>
                <input type="password" id="login_password" placeholder="Password" required>
                <input type="text" id="login_otp" placeholder="Paste OTP here" required>
                <button type="submit">Login to Banking System</button>
            </form>
            <div id="login-result"></div>
        </div>

        <div class="section">
            <h3>ℹ️ Quick Start</h3>
            <div class="info">
                <strong>Test Credentials:</strong><br>
                Username: <code>testuser</code><br>
                Password: <code>TestPass123!@</code><br>
                Email: <code>test@test.com</code>
            </div>
            <button onclick="useTestCredentials()">Use Test Credentials</button>
        </div>
    </div>

    <script>
        function useTestCredentials() {
            document.getElementById('reg_username').value = 'testuser';
            document.getElementById('reg_password').value = 'TestPass123!@';
            document.getElementById('reg_email').value = 'test@test.com';
            document.getElementById('login_username').value = 'testuser';
            document.getElementById('login_password').value = 'TestPass123!@';
            alert('Test credentials filled! Click "Register User" first, then "Generate Fresh OTP", then "Login"');
        }

        async function registerUser(e) {
            e.preventDefault();
            const data = {
                username: document.getElementById('reg_username').value,
                password: document.getElementById('reg_password').value,
                email: document.getElementById('reg_email').value
            };
            
            const response = await fetch('/register', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            });
            
            const result = await response.json();
            document.getElementById('register-result').innerHTML = 
                result.success ? 
                `<div class="success">✅ ${result.message}</div>` :
                `<div class="error">❌ ${result.message}</div>`;
        }

        async function generateOTP() {
            const username = document.getElementById('reg_username').value || document.getElementById('login_username').value;
            if (!username) {
                document.getElementById('otp-result').innerHTML = '<div class="error">❌ Please enter a username first</div>';
                return;
            }
            
            const response = await fetch('/generate_otp?username=' + username);
            const result = await response.json();
            document.getElementById('otp-result').innerHTML = 
                result.success ? 
                `<div class="success">✅ OTP for <strong>${username}</strong>: <code style="font-size: 18px;">${result.otp}</code><br>Use this within 30 seconds!</div>` :
                `<div class="error">❌ ${result.message}</div>`;
                
            if (result.success) {
                document.getElementById('login_otp').value = result.otp;
            }
        }

        async function loginUser(e) {
            e.preventDefault();
            const data = {
                username: document.getElementById('login_username').value,
                password: document.getElementById('login_password').value,
                otp: document.getElementById('login_otp').value
            };
            
            const response = await fetch('/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(data)
            });
            
            const result = await response.json();
            if (result.success) {
                // Redirect to dashboard on successful login
                window.location.href = '/dashboard?session=' + result.session_id;
            } else {
                document.getElementById('login-result').innerHTML = 
                    `<div class="error">❌ ${result.message}</div>`;
            }
        }
    </script>
</body>
</html>
'''

@app.route('/')
def home():
    return render_template_string(LOGIN_HTML)

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    try:
        bank.register_user(data['username'], data['password'], data['email'])
        return jsonify({'success': True, 'message': 'User registered successfully!'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    try:
        session_id = bank.authenticate_user(data['username'], data['password'], data['otp'])
        
        if session_id:
            # Store session in flask session
            flask_session['user_session'] = session_id
            flask_session['username'] = data['username']
            
            # Get user data for the dashboard
            user = bank.users[data['username']]
            flask_session['email'] = user.email
            flask_session['registration_date'] = user.registration_date.strftime('%Y-%m-%d %H:%M:%S')
            
            return jsonify({
                'success': True, 
                'message': 'Login successful!', 
                'session_id': session_id
            })
        else:
            return jsonify({'success': False, 'message': 'Invalid credentials'})
            
    except Exception as e:
        return jsonify({'success': False, 'message': f'System error: {str(e)}'})

@app.route('/dashboard')
def dashboard():
    session_id = request.args.get('session')
    if not session_id or not bank.validate_session(session_id):
        return "Invalid or expired session. Please <a href='/'>login again</a>."
    
    username = flask_session.get('username', 'User')
    email = flask_session.get('email', 'N/A')
    registration_date = flask_session.get('registration_date', 'N/A')
    
    return render_template_string(
        DASHBOARD_HTML,
        username=username,
        session_id=session_id,
        email=email,
        registration_date=registration_date
    )

# API endpoints for the dashboard
@app.route('/api/balance')
def api_balance():
    session_id = request.args.get('session')
    if not bank.validate_session(session_id):
        return jsonify({'success': False, 'message': 'Invalid session'})
    
    try:
        balance = bank.get_user_balance(session_id)
        return jsonify({'success': True, 'balance': balance})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/transactions')
def api_transactions():
    session_id = request.args.get('session')
    if not bank.validate_session(session_id):
        return jsonify({'success': False, 'message': 'Invalid session'})
    
    try:
        history = bank.get_transaction_history(session_id)
        return jsonify({
            'success': True,
            'transaction_count': history['transaction_count'],
            'transactions': history['transactions']
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/performance')
def api_performance():
    session_id = request.args.get('session')
    if not bank.validate_session(session_id):
        return jsonify({'success': False, 'message': 'Invalid session'})
    
    try:
        summary = PerformanceReporter.get_performance_summary(bank)
        return jsonify({
            'success': True,
            'total_operations': summary['total_operations'],
            'avg_crypto_time': f"{summary['avg_crypto_time']:.2f}",
            'cpu_usage': f"{summary['system_health']['cpu']:.1f}",
            'memory_usage': f"{summary['system_health']['memory']:.1f}"
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/transfer', methods=['POST'])
def api_transfer():
    data = request.json
    session_id = data.get('session')
    
    if not bank.validate_session(session_id):
        return jsonify({'success': False, 'message': 'Invalid session'})
    
    try:
        # Create a withdrawal transaction
        transaction_data = {
            'id': f"transfer_{int(datetime.now().timestamp())}",
            'type': 'WITHDRAWAL',
            'amount': data['amount'],
            'session_id': session_id,
            'timestamp': datetime.now().isoformat(),
            'from_account': flask_session.get('username'),
            'to_account': data['to_account'],
            'description': data['description']
        }
        
        encrypted_txn = bank.secure_protocol.encrypt_message(
            session_id, 
            json.dumps(transaction_data),
            is_client=True
        )
        
        result = bank.process_transaction(session_id, encrypted_txn)
        return jsonify({'success': True, 'message': f'Transfer of ${data["amount"]} to {data["to_account"]} completed!'})
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/logout')
def api_logout():
    session_id = request.args.get('session')
    if session_id:
        bank.logout_user(session_id)
        flask_session.clear()
    return jsonify({'success': True})

@app.route('/generate_otp')
def generate_otp():
    username = request.args.get('username')
    if not username:
        return jsonify({'success': False, 'message': 'Username required'})
    
    try:
        otp = bank.mfa_auth.generate_totp(username)
        return jsonify({'success': True, 'otp': otp})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

if __name__ == '__main__':
    print("🚀 Starting Enhanced Banking System...")
    print("📍 Open your browser to: http://localhost:5000")
    print("🎯 After login, you'll be redirected to the banking dashboard!")
    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5000)),
        debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true'
    )