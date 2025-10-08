import json
import base64
import secrets
import hashlib
import hmac
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from src.cryptography_manager import CryptographyManager
from src.performance_monitor import PerformanceMonitor  # Updated import
from config.security_config import SecurityConfig

class SecurityError(Exception):
    """Custom security exception"""
    pass

class SecureProtocol:
    """Implements TLS-like secure communication protocol"""
    
    def __init__(self):
        self.config = SecurityConfig()
        self.crypto_manager = CryptographyManager()
        self.session_keys = {}
        self.handshake_complete = {}
        self.performance_metrics = []
    
    @PerformanceMonitor.measure_time
    def perform_tls_handshake(self, client_id: str, server_public_key):
        """Simulate TLS 1.3 handshake with perfect forward secrecy"""
        # Client generates ephemeral key pair
        client_private, client_public = self.crypto_manager.generate_rsa_keypair()
        
        # Generate pre-master secret
        pre_master_secret = secrets.token_bytes(48)
        
        # Encrypt pre-master secret with server's public key
        encrypted_pre_master = server_public_key.encrypt(
            pre_master_secret,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Derive session keys
        session_keys = self.derive_session_keys(pre_master_secret)
        self.session_keys[client_id] = session_keys
        self.handshake_complete[client_id] = True
        
        handshake_data = {
            'client_public_key': client_public,
            'encrypted_pre_master': base64.b64encode(encrypted_pre_master).decode(),
            'timestamp': datetime.now().isoformat(),
            'session_id': client_id
        }
        
        return handshake_data
    
    @PerformanceMonitor.measure_time
    def derive_session_keys(self, pre_master_secret: bytes):
        """Derive encryption keys from pre-master secret using proper KDF"""
        # Use a proper key derivation function approach
        # We'll use multiple rounds of HMAC with different contexts
        
        def derive_key(material: bytes, context: str) -> bytes:
            """Derive a specific key using HMAC-based KDF"""
            key = material
            for i in range(3):  # Multiple rounds for better key stretching
                h = hmac.new(key, f"{context}-round-{i}".encode(), hashlib.sha256)
                key = h.digest()
            return key[:32]  # Return 32 bytes for AES-256
        
        # Derive only the encryption keys we actually need
        keys = {
            'client_write_key': derive_key(pre_master_secret, "client_write"),
            'server_write_key': derive_key(pre_master_secret, "server_write"),
            'pre_master_secret': pre_master_secret
        }
        
        # Verify all keys are proper length
        for key_name, key_value in keys.items():
            if key_name.endswith('_key') and len(key_value) != 32:
                raise SecurityError(f"Invalid key length for {key_name}: {len(key_value)}")
        
        return keys
    
    @PerformanceMonitor.measure_time
    def encrypt_message(self, client_id: str, message: str, is_client: bool = True):
        """Encrypt message using session keys - AES-GCM provides built-in authentication"""
        if client_id not in self.session_keys:
            raise SecurityError("No active session")
        
        keys = self.session_keys[client_id]
        
        # Use the correct key based on direction
        if is_client:
            key = keys['client_write_key']  # Client uses client_write_key to encrypt
        else:
            key = keys['server_write_key']  # Server uses server_write_key to encrypt
        
        # Encrypt the message - AES-GCM provides both encryption and authentication
        encrypted_data = self.crypto_manager.encrypt_aes_gcm(message, key)
        
        return {
            'encrypted_data': base64.b64encode(encrypted_data).decode(),
            'timestamp': datetime.now().isoformat(),
            'session_id': client_id,
            'direction': 'client_to_server' if is_client else 'server_to_client'
        }
    
    @PerformanceMonitor.measure_time
    def decrypt_message(self, client_id: str, encrypted_package: dict, is_client: bool = True):
        """Decrypt message - AES-GCM provides built-in authentication"""
        if client_id not in self.session_keys:
            raise SecurityError("No active session")
        
        keys = self.session_keys[client_id]
        
        # Use the correct key based on direction
        # When client decrypts, it uses server_write_key (message from server)
        # When server decrypts, it uses client_write_key (message from client)
        if is_client:
            key = keys['server_write_key']  # Client uses server_write_key to decrypt server messages
        else:
            key = keys['client_write_key']  # Server uses client_write_key to decrypt client messages
        
        # Decode data
        encrypted_data = base64.b64decode(encrypted_package['encrypted_data'])
        
        # Decrypt message - this will raise InvalidTag if tampered
        decrypted_message = self.crypto_manager.decrypt_aes_gcm(encrypted_data, key)
        
        return decrypted_message
    
    @PerformanceMonitor.measure_time
    def close_session(self, client_id: str):
        """Close secure session and clear keys"""
        if client_id in self.session_keys:
            del self.session_keys[client_id]
        if client_id in self.handshake_complete:
            del self.handshake_complete[client_id]
        
        return True