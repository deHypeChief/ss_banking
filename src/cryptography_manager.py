import hashlib
import hmac
import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from config.security_config import SecurityConfig
from src.performance_monitor import PerformanceMonitor  # Updated import

class CryptographyManager:
    """Handles all cryptographic operations for the banking system"""
    
    def __init__(self):
        self.config = SecurityConfig()
        self.performance_metrics = []
    
    @PerformanceMonitor.measure_time
    def generate_rsa_keypair(self):
        """Generate RSA key pair for asymmetric encryption"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.config.RSA_KEY_SIZE,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @PerformanceMonitor.measure_time
    def generate_symmetric_key(self):
        """Generate AES-256 symmetric key"""
        return os.urandom(32)
    
    @PerformanceMonitor.measure_time
    def derive_key_from_password(self, password: str, salt: bytes):
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.config.KEY_DERIVATION_ITERATIONS,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    @PerformanceMonitor.measure_time
    def encrypt_aes_gcm(self, plaintext: str, key: bytes):
        """Encrypt data using AES-GCM mode"""
        # Generate a random 96-bit IV
        iv = os.urandom(12)
        
        # Construct an AES-GCM Cipher object with the given key and IV
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        
        # Encrypt the plaintext and get the associated ciphertext
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        
        return iv + encryptor.tag + ciphertext
    
    @PerformanceMonitor.measure_time
    def decrypt_aes_gcm(self, ciphertext: bytes, key: bytes):
        """Decrypt data using AES-GCM mode"""
        # Extract IV, tag, and actual ciphertext
        iv = ciphertext[:12]
        tag = ciphertext[12:28]
        actual_ciphertext = ciphertext[28:]
        
        # Construct a Cipher object with the key, IV, and GCM tag
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        
        # Decrypt the ciphertext
        plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
        return plaintext.decode()
    
    @PerformanceMonitor.measure_time
    def compute_hmac(self, message: str, key: bytes):
        """Compute HMAC for message integrity verification"""
        return hmac.new(key, message.encode(), hashlib.sha256).digest()
    
    @PerformanceMonitor.measure_time
    def verify_hmac(self, message: str, key: bytes, received_hmac: bytes):
        """Verify HMAC for message integrity"""
        computed_hmac = hmac.new(key, message.encode(), hashlib.sha256).digest()
        return hmac.compare_digest(computed_hmac, received_hmac)
    
    @PerformanceMonitor.measure_time
    def hash_password(self, password: str, salt: bytes = None):
        """Hash password with salt using PBKDF2"""
        if salt is None:
            salt = os.urandom(32)
        
        hashed_password = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode(),
            salt,
            self.config.KEY_DERIVATION_ITERATIONS
        )
        
        return hashed_password, salt
    
    @PerformanceMonitor.measure_time
    def verify_password(self, password: str, stored_hash: bytes, salt: bytes):
        """Verify password against stored hash"""
        computed_hash, _ = self.hash_password(password, salt)
        return hmac.compare_digest(computed_hash, stored_hash)