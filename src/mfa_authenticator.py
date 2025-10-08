import secrets
import hmac
import hashlib
import base64
from datetime import datetime
from config.security_config import SecurityConfig
from src.performance_monitor import PerformanceMonitor  # Updated import

class MFAAuthenticator:
    """Multi-Factor Authentication System"""
    
    def __init__(self):
        self.config = SecurityConfig()
        self.user_devices = {}
        self.otp_secrets = {}
        self.performance_metrics = []
    
    @PerformanceMonitor.measure_time
    def generate_fido2_challenge(self, user_id: str):
        """Generate FIDO2/WebAuthn challenge"""
        challenge = secrets.token_bytes(32)
        self.user_devices[user_id] = {
            'challenge': challenge,
            'timestamp': datetime.now()
        }
        return base64.b64encode(challenge).decode()
    
    @PerformanceMonitor.measure_time
    def verify_fido2_response(self, user_id: str, response: str, credential_id: str):
        """Verify FIDO2 authentication response"""
        # Simplified verification - in real implementation, use WebAuthn library
        if user_id not in self.user_devices:
            return False
        
        stored_challenge = self.user_devices[user_id]['challenge']
        # In real implementation, verify cryptographic signature
        return True
    
    @PerformanceMonitor.measure_time
    def generate_totp(self, user_id: str):
        """Generate Time-based One-Time Password"""
        if user_id not in self.otp_secrets:
            self.otp_secrets[user_id] = secrets.token_bytes(20)
        
        secret = self.otp_secrets[user_id]
        time_counter = int(datetime.now().timestamp() // 30)
        
        # HMAC-based OTP calculation
        hmac_result = hmac.new(
            secret,
            time_counter.to_bytes(8, 'big'),
            hashlib.sha1
        ).digest()
        
        # Dynamic truncation
        offset = hmac_result[-1] & 0xf
        binary_code = (
            (hmac_result[offset] & 0x7f) << 24 |
            (hmac_result[offset + 1] & 0xff) << 16 |
            (hmac_result[offset + 2] & 0xff) << 8 |
            (hmac_result[offset + 3] & 0xff)
        )
        
        otp = binary_code % 1000000
        return str(otp).zfill(6)
    
    @PerformanceMonitor.measure_time
    def verify_totp(self, user_id: str, provided_otp: str):
        """Verify TOTP code"""
        if user_id not in self.otp_secrets:
            return False
            
        expected_otp = self.generate_totp(user_id)
        return hmac.compare_digest(expected_otp, provided_otp)
    
    @PerformanceMonitor.measure_time
    def enable_mfa_for_user(self, user_id: str):
        """Enable MFA for a user"""
        if user_id not in self.otp_secrets:
            self.otp_secrets[user_id] = secrets.token_bytes(20)
        return True
    
    @PerformanceMonitor.measure_time
    def disable_mfa_for_user(self, user_id: str):
        """Disable MFA for a user"""
        if user_id in self.otp_secrets:
            del self.otp_secrets[user_id]
        return True