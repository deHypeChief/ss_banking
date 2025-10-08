import unittest
import sys
import os
import time

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.mfa_authenticator import MFAAuthenticator
from src.banking_core import SecureOnlineBanking

class TestMFAAuthenticator(unittest.TestCase):
    
    def setUp(self):
        """Set up test environment"""
        self.mfa = MFAAuthenticator()
        self.bank = SecureOnlineBanking()
    
    def test_totp_generation(self):
        """Test TOTP generation and verification"""
        user_id = "test_user_totp"
        
        # Generate OTP
        otp = self.mfa.generate_totp(user_id)
        self.assertIsNotNone(otp)
        self.assertEqual(len(otp), 6)  # 6-digit OTP
        
        # Verify correct OTP
        is_valid = self.mfa.verify_totp(user_id, otp)
        self.assertTrue(is_valid)
        
        # Verify wrong OTP
        is_valid_wrong = self.mfa.verify_totp(user_id, "000000")
        self.assertFalse(is_valid_wrong)
    
    def test_totp_time_based(self):
        """Test that TOTP changes over time"""
        user_id = "time_test_user"
        
        # Generate OTP at time T
        otp1 = self.mfa.generate_totp(user_id)
        
        # Generate OTP after a short delay (should be same within 30s window)
        time.sleep(1)
        otp2 = self.mfa.generate_totp(user_id)
        
        self.assertEqual(otp1, otp2)
    
    def test_fido2_challenge(self):
        """Test FIDO2 challenge generation"""
        user_id = "fido2_user"
        
        challenge = self.mfa.generate_fido2_challenge(user_id)
        self.assertIsNotNone(challenge)
        
        # Challenge should be base64 encoded
        import base64
        try:
            decoded = base64.b64decode(challenge)
            self.assertEqual(len(decoded), 32)  # 32-byte challenge
        except:
            self.fail("Challenge is not valid base64")
    
    def test_mfa_enable_disable(self):
        """Test MFA enable/disable functionality"""
        user_id = "mfa_toggle_user"
        
        # Enable MFA
        result_enable = self.mfa.enable_mfa_for_user(user_id)
        self.assertTrue(result_enable)
        
        # Should be able to generate OTP after enabling
        otp = self.mfa.generate_totp(user_id)
        self.assertIsNotNone(otp)
        
        # Verify OTP works
        is_valid = self.mfa.verify_totp(user_id, otp)
        self.assertTrue(is_valid)
        
        # Disable MFA
        result_disable = self.mfa.disable_mfa_for_user(user_id)
        self.assertTrue(result_disable)
        
        # After disabling, OTP verification should fail
        is_valid_after_disable = self.mfa.verify_totp(user_id, otp)
        self.assertFalse(is_valid_after_disable)

class TestAuthenticationIntegration(unittest.TestCase):
    
    def setUp(self):
        """Set up test environment"""
        self.bank = SecureOnlineBanking()
    
    def test_registration_authentication_flow(self):
        """Test complete registration and authentication flow"""
        # Register user
        result = self.bank.register_user("auth_flow_user", "AuthFlowPass123!", "authflow@example.com")
        self.assertTrue(result)
        
        # Generate OTP for authentication
        otp = self.bank.mfa_auth.generate_totp("auth_flow_user")
        self.assertIsNotNone(otp)
        
        # Authenticate with correct credentials
        session_id = self.bank.authenticate_user("auth_flow_user", "AuthFlowPass123!", otp)
        self.assertIsNotNone(session_id)
        self.assertIn(session_id, self.bank.sessions)
        
        # Verify session is valid
        is_valid = self.bank.validate_session(session_id)
        self.assertTrue(is_valid)
        
        # Logout
        logout_result = self.bank.logout_user(session_id)
        self.assertTrue(logout_result)
        
        # Session should be invalid after logout
        is_valid_after_logout = self.bank.validate_session(session_id)
        self.assertFalse(is_valid_after_logout)
    
    def test_failed_authentication_attempts(self):
        """Test failed authentication attempt tracking"""
        # Register user
        self.bank.register_user("fail_user", "FailPass123!", "fail@example.com")
        
        # First failed attempt
        session_id1 = self.bank.authenticate_user("fail_user", "WrongPassword1!", "123456")
        self.assertIsNone(session_id1)
        self.assertEqual(self.bank.login_attempts.get("fail_user", 0), 1)
        
        # Second failed attempt
        session_id2 = self.bank.authenticate_user("fail_user", "WrongPassword2!", "123456")
        self.assertIsNone(session_id2)
        self.assertEqual(self.bank.login_attempts.get("fail_user", 0), 2)
        
        # Third failed attempt (should lock account)
        session_id3 = self.bank.authenticate_user("fail_user", "WrongPassword3!", "123456")
        self.assertIsNone(session_id3)
        self.assertEqual(self.bank.login_attempts.get("fail_user", 0), 3)
        
        # Fourth attempt should still fail (account locked)
        correct_otp = self.bank.mfa_auth.generate_totp("fail_user")
        session_id4 = self.bank.authenticate_user("fail_user", "FailPass123!", correct_otp)
        self.assertIsNone(session_id4)
    
    def test_mfa_required(self):
        """Test that MFA is required for authentication"""
        # Register user (MFA enabled by default)
        self.bank.register_user("mfa_required_user", "MfaRequiredPass123!", "mfarequired@example.com")
        
        # Try to authenticate without OTP
        session_id = self.bank.authenticate_user("mfa_required_user", "MfaRequiredPass123!")
        self.assertIsNone(session_id)
        
        # Try with incorrect OTP
        session_id_wrong_otp = self.bank.authenticate_user("mfa_required_user", "MfaRequiredPass123!", "000000")
        self.assertIsNone(session_id_wrong_otp)
        
        # Try with correct OTP
        correct_otp = self.bank.mfa_auth.generate_totp("mfa_required_user")
        session_id_correct = self.bank.authenticate_user("mfa_required_user", "MfaRequiredPass123!", correct_otp)
        self.assertIsNotNone(session_id_correct)

if __name__ == '__main__':
    unittest.main()