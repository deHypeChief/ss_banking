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
from database import BankDatabase

class SecureOnlineBanking:
    """Complete Secure Online Banking System"""
    
    def __init__(self):
        self.config = SecurityConfig()
        self.crypto_manager = CryptographyManager()
        self.secure_protocol = SecureProtocol()
        self.mfa_auth = MFAAuthenticator()
        self.performance_metrics = []
        self.db = BankDatabase()

        # Generate server keys
        self.server_private_key, self.server_public_key = self.crypto_manager.generate_rsa_keypair()

        # In-memory caches for performance (will be populated from DB as needed)
        self.users_cache: Dict[str, User] = {}
        self.sessions_cache: Dict[str, Session] = {}
        self.login_attempts: Dict[str, int] = {}
        self.audit_trail: List[Dict] = []
    
    @PerformanceMonitor.measure_time
    def register_user(self, username: str, password: str, email: str):
        """Register new user with secure password storage"""
        # Check if user already exists in database
        if self.db.get_user(username):
            raise ValueError("User already exists")

        if len(password) < self.config.MIN_PASSWORD_LENGTH:
            raise ValueError(f"Password must be at least {self.config.MIN_PASSWORD_LENGTH} characters")

        # Generate salt and hash password
        salt = secrets.token_bytes(32)
        hashed_password, salt = self.crypto_manager.hash_password(password, salt)

        # Store user in database
        self.db.add_user(username, hashed_password, salt, email)

        # Update cache
        user_data = User(
            username=username,
            password_hash=hashed_password,
            salt=salt,
            email=email,
            account_balance=0.0,
            registration_date=datetime.now(),
            transaction_history=[],
            mfa_enabled=True
        )
        self.users_cache[username] = user_data
        self.mfa_auth.enable_mfa_for_user(username)
        self.log_security_event(f"USER_REGISTRATION: {username}")

        return True
    
    @PerformanceMonitor.measure_time
    def authenticate_user(self, username: str, password: str, otp_code: Optional[str] = None):
        """Authenticate user with MFA"""
        # Get user from database
        user_db = self.db.get_user(username)
        if not user_db:
            self.log_failed_attempt(username, "USER_NOT_FOUND")
            return None

        # Load user into cache if not already there
        if username not in self.users_cache:
            self.users_cache[username] = User(
                username=user_db['username'],
                password_hash=user_db['password_hash'],
                salt=user_db['salt'],
                email=user_db['email'],
                account_balance=user_db['account_balance'],
                registration_date=datetime.fromisoformat(user_db['registration_date']),
                transaction_history=[],
                mfa_enabled=True
            )

        user_data = self.users_cache[username]

        # Check login attempts
        if self.login_attempts.get(username, 0) >= self.config.MAX_LOGIN_ATTEMPTS:
            self.log_security_event(f"ACCOUNT_LOCKED: {username}")
            return None

        # Verify password
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

        expires_at = datetime.now() + timedelta(hours=1)  # 1 hour session

        # Store session in database
        self.db.add_session(session_id, username, expires_at)

        # Update cache
        session_data = Session(
            session_id=session_id,
            username=username,
            created_at=datetime.now(),
            last_activity=datetime.now(),
            ip_address='127.0.0.1',  # In real implementation, get from request
            user_agent='Demo Client'
        )
        self.sessions_cache[session_id] = session_data
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
        # Get session from database
        session_db = self.db.get_session(transaction.session_id)
        if not session_db:
            raise ValueError("Invalid session")

        username = session_db['username']

        # Get user from database
        user_db = self.db.get_user(username)
        if not user_db:
            raise ValueError("User not found")

        current_balance = user_db['account_balance']

        if transaction.type == TransactionType.DEPOSIT:
            new_balance = current_balance + transaction.amount
        elif transaction.type == TransactionType.WITHDRAWAL:
            if current_balance >= transaction.amount:
                new_balance = current_balance - transaction.amount
            else:
                raise ValueError("Insufficient funds")
        elif transaction.type == TransactionType.TRANSFER:
            # For transfers, we need to handle both sender and receiver
            # This is simplified - in real banking, this would be more complex
            if current_balance >= transaction.amount:
                new_balance = current_balance - transaction.amount
                # Note: Receiver balance update would happen separately
            else:
                raise ValueError("Insufficient funds")
        else:
            raise ValueError("Invalid transaction type")

        # Update balance in database
        self.db.update_balance(username, new_balance)

        # Record transaction in database
        self.db.add_transaction(
            username=username,
            transaction_type=transaction.type.value,
            amount=transaction.amount,
            to_account=getattr(transaction, 'to_account', None),
            description=getattr(transaction, 'description', None)
        )

        # Update cache
        if username in self.users_cache:
            self.users_cache[username].account_balance = new_balance

        return True
    
    @PerformanceMonitor.measure_time
    def log_transaction(self, transaction: Transaction):
        """Log transaction to immutable audit trail"""
        # Get session from database
        session_db = self.db.get_session(transaction.session_id)
        if not session_db:
            username = "UNKNOWN"
        else:
            username = session_db['username']

        audit_entry = {
            'transaction_id': transaction.transaction_id,
            'type': transaction.type.value,
            'amount': transaction.amount,
            'timestamp': datetime.now().isoformat(),
            'user': username,
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
        # Clean up expired sessions first
        self.db.cleanup_expired_sessions()

        # Get session from database
        session_db = self.db.get_session(session_id)
        if not session_db:
            return False

        # Check if expired
        expires_at = datetime.fromisoformat(session_db['expires_at'])
        if datetime.now() > expires_at:
            self.db.delete_session(session_id)
            self.log_security_event(f"SESSION_EXPIRED: {session_db['username']}")
            return False

        return True
    
    @PerformanceMonitor.measure_time
    def get_user_balance(self, session_id: str):
        """Get user account balance"""
        if not self.validate_session(session_id):
            raise SecurityError("Invalid session")

        # Get session from database
        session_db = self.db.get_session(session_id)
        if not session_db:
            raise SecurityError("Session not found")

        username = session_db['username']

        # Get user from database
        user_db = self.db.get_user(username)
        if not user_db:
            raise SecurityError("User not found")

        return user_db['account_balance']
    
    @PerformanceMonitor.measure_time
    def get_transaction_history(self, session_id: str):
        """Get user transaction history"""
        if not self.validate_session(session_id):
            raise SecurityError("Invalid session")

        # Get session from database
        session_db = self.db.get_session(session_id)
        if not session_db:
            raise SecurityError("Session not found")

        username = session_db['username']

        # Get user from database
        user_db = self.db.get_user(username)
        if not user_db:
            raise SecurityError("User not found")

        # Get transactions from database
        transactions = self.db.get_user_transactions(username)

        return {
            'username': username,
            'balance': user_db['account_balance'],
            'transaction_count': len(transactions),
            'transactions': transactions[-10:]  # Last 10 transactions
        }
    
    @PerformanceMonitor.measure_time
    def logout_user(self, session_id: str):
        """Logout user and clear session"""
        session_db = self.db.get_session(session_id)
        if session_db:
            username = session_db['username']
            self.secure_protocol.close_session(session_id)
            self.db.delete_session(session_id)
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