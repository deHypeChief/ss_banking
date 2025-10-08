import unittest
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.banking_core import SecureOnlineBanking

class TestSecureBanking(unittest.TestCase):
    
    def setUp(self):
        """Set up test environment"""
        self.bank = SecureOnlineBanking()
    
    def test_user_registration(self):
        """Test user registration functionality"""
        result = self.bank.register_user("test_user", "TestPass123!", "test@example.com")
        self.assertTrue(result)
        self.assertIn("test_user", self.bank.users)
    
    def test_authentication_success(self):
        """Test successful user authentication"""
        self.bank.register_user("auth_user", "AuthPass123!", "auth@example.com")
        
        # Generate valid OTP
        otp = self.bank.mfa_auth.generate_totp("auth_user")
        session_id = self.bank.authenticate_user("auth_user", "AuthPass123!", otp)
        
        self.assertIsNotNone(session_id)
        self.assertIn(session_id, self.bank.sessions)
    
    def test_authentication_failure(self):
        """Test failed user authentication"""
        self.bank.register_user("fail_user", "FailPass123!", "fail@example.com")
        
        # Wrong password
        session_id = self.bank.authenticate_user("fail_user", "WrongPassword!", "123456")
        self.assertIsNone(session_id)
    
    def test_session_validation(self):
        """Test session validation"""
        self.bank.register_user("session_user", "SessionPass123!", "session@example.com")
        otp = self.bank.mfa_auth.generate_totp("session_user")
        session_id = self.bank.authenticate_user("session_user", "SessionPass123!", otp)
        
        # Session should be valid
        self.assertTrue(self.bank.validate_session(session_id))
        
        # Logout
        self.bank.logout_user(session_id)
        self.assertFalse(self.bank.validate_session(session_id))

if __name__ == '__main__':
    unittest.main()