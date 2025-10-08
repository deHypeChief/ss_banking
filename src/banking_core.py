import json
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from src.cryptography_manager import CryptographyManager
from src.performance_monitor import PerformanceMonitor  # Updated import
from src.secure_protocol import SecureProtocol, SecurityError
from src.mfa_authenticator import MFAAuthenticator
from src.models.user import User
from src.models.transaction import Transaction, TransactionType
from src.models.session import Session
from config.security_config import SecurityConfig

class SecureOnlineBanking:
    """Complete Secure Online Banking System"""
    
    def __init__(self):
        self.config = SecurityConfig()
        self.crypto_manager = CryptographyManager()
        self.secure_protocol = SecureProtocol()
        self.mfa_auth = MFAAuthenticator()
        self.performance_metrics = []
        
        # Generate server keys
        self.server_private_key, self.server_public_key = self.crypto_manager.generate_rsa_keypair()
        
        # Storage
        self.users: Dict[str, User] = {}
        self.sessions: Dict[str, Session] = {}
        self.login_attempts: Dict[str, int] = {}
        self.audit_trail: List[Dict] = []
    
    @PerformanceMonitor.measure_time
    def register_user(self, username: str, password: str, email: str):
        """Register new user with secure password storage"""
        if username in self.users:
            raise ValueError("User already exists")
        
        if len(password) < self.config.MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {self.config.MIN_PASSWORD_LENGTH} characters")
        
        # Generate salt and hash password
        salt = secrets.token_bytes(32)
        hashed_password, salt = self.crypto_manager.hash_password(password, salt)
        
        # Create user object
        user_data = User(
            username=username,
            password_hash=hashed_password,
            salt=salt,
            email=email,
            registration_date=datetime.now(),
            account_balance=0.0,
            transaction_history=[],
            mfa_enabled=True  # Enable MFA by default
        )
        
        self.users[username] = user_data
        self.mfa_auth.enable_mfa_for_user(username)
        self.log_security_event(f"USER_REGISTRATION: {username}")
        
        return True
    
    @PerformanceMonitor.measure_time
    def authenticate_user(self, username: str, password: str, otp_code: str = None):
        """Authenticate user with MFA"""
        if username not in self.users:
            self.log_failed_attempt(username, "USER_NOT_FOUND")
            return None
        
        # Check login attempts
        if self.login_attempts.get(username, 0) >= self.config.MAX_LOGIN_ATTEMPTS:
            self.log_security_event(f"ACCOUNT_LOCKED: {username}")
            return None
        
        # Verify password
        user_data = self.users[username]
        
        if not self.crypto_manager.verify_password(password, user_data.password_hash, user_data.salt):
            self.log_failed_attempt(username, "INVALID_PASSWORD")
            return None
        
        # Verify MFA if enabled
        if user_data.mfa_enabled:
            if not otp_code:
                self.log_failed_attempt(username, "MFA_REQUIRED")
                return None
            if not self.mfa_auth.verify_totp(username, otp_code):
                self.log_failed_attempt(username, "INVALID_OTP")
                return None
        
        # Generate session
        session_id = self.create_secure_session(username)
        self.log_security_event(f"SUCCESSFUL_LOGIN: {username}")
        
        # Reset login attempts
        self.login_attempts[username] = 0
        
        return session_id
    
    @PerformanceMonitor.measure_time
    def create_secure_session(self, username: str):
        """Create secure session with TLS handshake"""
        session_id = secrets.token_urlsafe(32)
        
        # Perform TLS handshake
        handshake_data = self.secure_protocol.perform_tls_handshake(
            session_id, 
            self.server_public_key
        )
        
        session_data = Session(
            session_id=session_id,
            username=username,
            created_at=datetime.now(),
            last_activity=datetime.now(),
            ip_address='127.0.0.1',  # In real implementation, get from request
            user_agent='Demo Client'
        )
        
        self.sessions[session_id] = session_data
        return session_id
    
    @PerformanceMonitor.measure_time
    def process_transaction(self, session_id: str, transaction_data: dict):
        """Process secure financial transaction"""
        if not self.validate_session(session_id):
            raise SecurityError("Invalid session")
        
        # Verify transaction integrity
        if not self.verify_transaction_integrity(transaction_data):
            raise SecurityError("Transaction integrity check failed")
        
        # Decrypt transaction data
        decrypted_data = self.secure_protocol.decrypt_message(session_id, transaction_data, is_client=False)
        transaction_dict = json.loads(decrypted_data)
        
        # Create transaction object
        transaction = Transaction(
            transaction_id=transaction_dict['id'],
            type=TransactionType(transaction_dict['type']),
            amount=transaction_dict['amount'],
            timestamp=datetime.fromisoformat(transaction_dict['timestamp']),
            from_account=transaction_dict['from_account'],
            to_account=transaction_dict['to_account'],
            description=transaction_dict['description'],
            session_id=session_id
        )
        
        # Process transaction
        self.execute_transaction(transaction)
        
        # Log to immutable audit trail
        self.log_transaction(transaction)
        
        return {"status": "success", "transaction_id": transaction.transaction_id}
    
    @PerformanceMonitor.measure_time
    def verify_transaction_integrity(self, transaction_data: dict):
        """Verify transaction data integrity"""
        required_fields = ['encrypted_data', 'timestamp', 'session_id']
        return all(field in transaction_data for field in required_fields)
    
    @PerformanceMonitor.measure_time
    def execute_transaction(self, transaction: Transaction):
        """Execute the financial transaction"""
        username = self.sessions[transaction.session_id].username
        user_data = self.users[username]
        
        if transaction.type == TransactionType.DEPOSIT:
            user_data.account_balance += transaction.amount
        elif transaction.type == TransactionType.WITHDRAWAL:
            if user_data.account_balance >= transaction.amount:
                user_data.account_balance -= transaction.amount
            else:
                raise ValueError("Insufficient funds")
        
        # Add to transaction history
        user_data.transaction_history.append(transaction.transaction_id)
    
    @PerformanceMonitor.measure_time
    def log_transaction(self, transaction: Transaction):
        """Log transaction to immutable audit trail"""
        audit_entry = {
            'transaction_id': transaction.transaction_id,
            'type': transaction.type.value,
            'amount': transaction.amount,
            'timestamp': datetime.now().isoformat(),
            'user': self.sessions[transaction.session_id].username,
            'hash': self.compute_transaction_hash(transaction),
            'event': 'TRANSACTION_PROCESSED'
        }
        
        self.audit_trail.append(audit_entry)
    
    @PerformanceMonitor.measure_time
    def compute_transaction_hash(self, transaction: Transaction):
        """Compute cryptographic hash for transaction integrity"""
        transaction_string = f"{transaction.transaction_id}{transaction.type.value}{transaction.amount}{transaction.timestamp.isoformat()}"
        return hashlib.sha256(transaction_string.encode()).hexdigest()
    
    @PerformanceMonitor.measure_time
    def validate_session(self, session_id: str):
        """Validate session integrity and timeout"""
        if session_id not in self.sessions:
            return False
        
        session = self.sessions[session_id]
        
        if session.is_expired(self.config.SESSION_TIMEOUT):
            del self.sessions[session_id]
            self.log_security_event(f"SESSION_EXPIRED: {session.username}")
            return False
        
        # Update last activity
        session.update_activity()
        return True
    
    @PerformanceMonitor.measure_time
    def get_user_balance(self, session_id: str):
        """Get user account balance"""
        if not self.validate_session(session_id):
            raise SecurityError("Invalid session")
        
        username = self.sessions[session_id].username
        return self.users[username].account_balance
    
    @PerformanceMonitor.measure_time
    def get_transaction_history(self, session_id: str):
        """Get user transaction history"""
        if not self.validate_session(session_id):
            raise SecurityError("Invalid session")
        
        username = self.sessions[session_id].username
        user_data = self.users[username]
        
        return {
            'username': username,
            'balance': user_data.account_balance,
            'transaction_count': len(user_data.transaction_history),
            'transactions': user_data.transaction_history[-10:]  # Last 10 transactions
        }
    
    @PerformanceMonitor.measure_time
    def logout_user(self, session_id: str):
        """Logout user and clear session"""
        if session_id in self.sessions:
            username = self.sessions[session_id].username
            self.secure_protocol.close_session(session_id)
            del self.sessions[session_id]
            self.log_security_event(f"USER_LOGOUT: {username}")
            return True
        return False
    
    def log_security_event(self, event: str):
        """Log security event for monitoring"""
        log_entry = {
            'timestamp': datetime.now().isoformat(),
            'event': event,
            'severity': 'INFO'
        }
        self.audit_trail.append(log_entry)
        print(f"SECURITY_LOG: {event}")
    
    def log_failed_attempt(self, username: str, reason: str):
        """Log failed authentication attempt"""
        if username not in self.login_attempts:
            self.login_attempts[username] = 0
        self.login_attempts[username] += 1
        
        self.log_security_event(f"FAILED_LOGIN: {username} - {reason}")
        
        # Log security alert if too many attempts
        if self.login_attempts[username] >= self.config.MAX_LOGIN_ATTEMPTS:
            self.log_security_event(f"SECURITY_ALERT: Account {username} locked due to too many failed attempts")