import unittest
import sys
import os
import json
import base64
import hmac
import hashlib

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.secure_protocol import SecureProtocol, SecurityError
from src.cryptography_manager import CryptographyManager
from cryptography.exceptions import InvalidTag

class TestSecureProtocol(unittest.TestCase):
    
    def setUp(self):
        """Set up test environment"""
        self.protocol = SecureProtocol()
        self.crypto = CryptographyManager()
        self.server_private_key, self.server_public_key = self.crypto.generate_rsa_keypair()
    
    def test_tls_handshake(self):
        """Test TLS-like handshake process"""
        client_id = "test_client_123"
        
        # Perform handshake
        handshake_data = self.protocol.perform_tls_handshake(client_id, self.server_public_key)
        
        self.assertIsNotNone(handshake_data)
        self.assertIn('client_public_key', handshake_data)
        self.assertIn('encrypted_pre_master', handshake_data)
        self.assertIn('timestamp', handshake_data)
        self.assertIn('session_id', handshake_data)
        
        # Verify handshake completed
        self.assertTrue(self.protocol.handshake_complete[client_id])
        self.assertIn(client_id, self.protocol.session_keys)
    
    def test_secure_communication(self):
        """Test encrypted message exchange"""
        client_id = "comm_test_client"
        
        # Establish secure session
        self.protocol.perform_tls_handshake(client_id, self.server_public_key)
        
        # Test message from client to server
        client_message = "Hello from client!"
        encrypted_package = self.protocol.encrypt_message(client_id, client_message, is_client=True)
        
        self.assertIsNotNone(encrypted_package)
        self.assertIn('encrypted_data', encrypted_package)
        self.assertIn('timestamp', encrypted_package)
        self.assertIn('direction', encrypted_package)
        
        # Server decrypts the message (is_client=False because server is decrypting)
        decrypted_message = self.protocol.decrypt_message(client_id, encrypted_package, is_client=False)
        self.assertEqual(decrypted_message, client_message)
        
        # Test message from server to client
        server_message = "Hello from server!"
        encrypted_package_server = self.protocol.encrypt_message(client_id, server_message, is_client=False)
        
        # Client decrypts the message (is_client=True because client is decrypting)
        decrypted_server_message = self.protocol.decrypt_message(client_id, encrypted_package_server, is_client=True)
        self.assertEqual(decrypted_server_message, server_message)
    
    def test_message_integrity(self):
        """Test message integrity verification using AES-GCM authentication"""
        client_id = "integrity_test_client"
        
        # Establish secure session
        self.protocol.perform_tls_handshake(client_id, self.server_public_key)
        
        # Create legitimate message
        message = "Secure transaction data"
        encrypted_package = self.protocol.encrypt_message(client_id, message, is_client=True)
        
        # Tamper with the encrypted data
        tampered_package = encrypted_package.copy()
        tampered_data = base64.b64decode(tampered_package['encrypted_data'])
        
        # Modify one byte of the encrypted data (after the IV and tag)
        tampered_bytes = bytearray(tampered_data)
        if len(tampered_bytes) > 40:  # Skip IV (12 bytes) and tag (16 bytes) = 28 bytes
            tampered_bytes[40] ^= 0x01  # Flip one bit in the ciphertext
        
        tampered_package['encrypted_data'] = base64.b64encode(bytes(tampered_bytes)).decode()
        
        # Should raise InvalidTag when verifying tampered message
        with self.assertRaises(InvalidTag):
            self.protocol.decrypt_message(client_id, tampered_package, is_client=False)
    
    def test_session_management(self):
        """Test session opening and closing"""
        client_id = "session_test_client"
        
        # Open session
        self.protocol.perform_tls_handshake(client_id, self.server_public_key)
        self.assertIn(client_id, self.protocol.session_keys)
        self.assertIn(client_id, self.protocol.handshake_complete)
        
        # Close session
        close_result = self.protocol.close_session(client_id)
        self.assertTrue(close_result)
        self.assertNotIn(client_id, self.protocol.session_keys)
        self.assertNotIn(client_id, self.protocol.handshake_complete)
    
    def test_multiple_clients(self):
        """Test handling multiple simultaneous clients"""
        client1_id = "client_1"
        client2_id = "client_2"
        
        # Establish sessions for both clients
        self.protocol.perform_tls_handshake(client1_id, self.server_public_key)
        self.protocol.perform_tls_handshake(client2_id, self.server_public_key)
        
        # Both clients should have independent sessions
        self.assertIn(client1_id, self.protocol.session_keys)
        self.assertIn(client2_id, self.protocol.session_keys)
        
        # Messages should be independent
        message1 = "Message from client 1"
        message2 = "Message from client 2"
        
        # Client 1 sends message (encrypted with client1's client_write_key)
        encrypted1 = self.protocol.encrypt_message(client1_id, message1, is_client=True)
        # Server decrypts message from client 1
        decrypted1 = self.protocol.decrypt_message(client1_id, encrypted1, is_client=False)
        
        # Client 2 sends message (encrypted with client2's client_write_key)  
        encrypted2 = self.protocol.encrypt_message(client2_id, message2, is_client=True)
        # Server decrypts message from client 2
        decrypted2 = self.protocol.decrypt_message(client2_id, encrypted2, is_client=False)
        
        self.assertEqual(decrypted1, message1)
        self.assertEqual(decrypted2, message2)
        
        # Server shouldn't be able to decrypt client2's message using client1's session
        with self.assertRaises(InvalidTag):
            self.protocol.decrypt_message(client1_id, encrypted2, is_client=False)
    
    def test_key_derivation_debug(self):
        """Debug method to check key derivation"""
        client_id = "debug_client"
        
        # Perform handshake
        handshake_data = self.protocol.perform_tls_handshake(client_id, self.server_public_key)
        
        # Check session keys
        session_keys = self.protocol.session_keys[client_id]
        for key_name, key_value in session_keys.items():
            if key_name.endswith('_key'):
                print(f"{key_name}: {len(key_value)} bytes - {key_value.hex()[:16]}...")
        
        # Test a simple message from client to server
        test_message = "Test message"
        encrypted = self.protocol.encrypt_message(client_id, test_message, is_client=True)
        decrypted = self.protocol.decrypt_message(client_id, encrypted, is_client=False)
        
        self.assertEqual(test_message, decrypted)
        print("✓ Basic encryption/decryption working")

if __name__ == '__main__':
    unittest.main()
    
    # Add to src/banking_core.py - Quantum-resistant cryptography
def enable_quantum_resistance(self):
    """Add post-quantum cryptography support"""
    # Implement hybrid encryption with lattice-based algorithms
    pass

# Add blockchain-based audit trails
def create_blockchain_audit_trail(self, transaction_data):
    """Create immutable blockchain records"""
    pass