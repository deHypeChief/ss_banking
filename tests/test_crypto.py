import unittest
import sys
import os

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.cryptography_manager import CryptographyManager

class TestCryptographyManager(unittest.TestCase):
    
    def setUp(self):
        """Set up test environment"""
        self.crypto = CryptographyManager()
    
    def test_encryption_decryption(self):
        """Test AES-GCM encryption and decryption"""
        test_message = "This is a secret banking message!"
        key = self.crypto.generate_symmetric_key()
        
        # Encrypt
        encrypted = self.crypto.encrypt_aes_gcm(test_message, key)
        self.assertIsNotNone(encrypted)
        self.assertNotEqual(encrypted, test_message.encode())
        
        # Decrypt
        decrypted = self.crypto.decrypt_aes_gcm(encrypted, key)
        self.assertEqual(decrypted, test_message)
    
    def test_hmac_integrity(self):
        """Test HMAC message integrity verification"""
        test_message = "Important transaction data"
        key = self.crypto.generate_symmetric_key()
        
        # Compute HMAC
        hmac_value = self.crypto.compute_hmac(test_message, key)
        self.assertIsNotNone(hmac_value)
        
        # Verify HMAC
        is_valid = self.crypto.verify_hmac(test_message, key, hmac_value)
        self.assertTrue(is_valid)
        
        # Test with tampered message
        is_valid_tampered = self.crypto.verify_hmac("Tampered message", key, hmac_value)
        self.assertFalse(is_valid_tampered)
    
    def test_password_hashing(self):
        """Test password hashing and verification"""
        password = "SecureBankingPassword123!"
        
        # Hash password
        hashed_password, salt = self.crypto.hash_password(password)
        self.assertIsNotNone(hashed_password)
        self.assertIsNotNone(salt)
        
        # Verify correct password
        is_valid = self.crypto.verify_password(password, hashed_password, salt)
        self.assertTrue(is_valid)
        
        # Verify wrong password
        is_valid_wrong = self.crypto.verify_password("WrongPassword", hashed_password, salt)
        self.assertFalse(is_valid_wrong)
    
    def test_rsa_key_generation(self):
        """Test RSA key pair generation"""
        private_key, public_key = self.crypto.generate_rsa_keypair()
        
        self.assertIsNotNone(private_key)
        self.assertIsNotNone(public_key)
        
        # Test that keys are different
        self.assertNotEqual(private_key, public_key)
    
    def test_key_derivation(self):
        """Test key derivation from password"""
        password = "MySecurePassword"
        salt = os.urandom(32)
        
        derived_key = self.crypto.derive_key_from_password(password, salt)
        self.assertIsNotNone(derived_key)
        self.assertEqual(len(derived_key), 32)  # 256-bit key
        
        # Same password and salt should produce same key
        derived_key2 = self.crypto.derive_key_from_password(password, salt)
        self.assertEqual(derived_key, derived_key2)
        
        # Different salt should produce different key
        different_salt = os.urandom(32)
        derived_key3 = self.crypto.derive_key_from_password(password, different_salt)
        self.assertNotEqual(derived_key, derived_key3)

if __name__ == '__main__':
    unittest.main()