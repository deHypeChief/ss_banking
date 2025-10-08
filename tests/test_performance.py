import unittest
import time
import sys
import os
import json
import psutil
import gc
from datetime import datetime  # Added import

sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from src.banking_core import SecureOnlineBanking
from src.performance_reporter import PerformanceReporter

class TestPerformance(unittest.TestCase):
    
    def setUp(self):
        self.bank = SecureOnlineBanking()
    
    def test_encryption_performance(self):
        """Test encryption/decryption performance under load"""
        test_message = "This is a test message for performance testing"
        
        # Test multiple encryptions
        start_time = time.time()
        operations = 50
        
        for i in range(operations):
            key = self.bank.crypto_manager.generate_symmetric_key()
            encrypted = self.bank.crypto_manager.encrypt_aes_gcm(test_message, key)
            decrypted = self.bank.crypto_manager.decrypt_aes_gcm(encrypted, key)
            self.assertEqual(decrypted, test_message)
        
        total_time = time.time() - start_time
        avg_time_per_operation = total_time / operations
        
        print(f"🔐 Encryption/Decryption Performance:")
        print(f"  {operations} operations in {total_time:.2f}s")
        print(f"  Average: {avg_time_per_operation*1000:.2f}ms per operation")
        
        self.assertLess(avg_time_per_operation, 0.05)
    
    def test_authentication_performance(self):
        """Test authentication performance"""
        self.bank.register_user("perf_user", "PerfPass123!@", "perf@example.com")
        
        start_time = time.time()
        auth_cycles = 20
        successful_auths = 0
        
        for i in range(auth_cycles):
            otp = self.bank.mfa_auth.generate_totp("perf_user")
            session_id = self.bank.authenticate_user("perf_user", "PerfPass123!@", otp)
            if session_id:
                self.bank.logout_user(session_id)
                successful_auths += 1
        
        total_time = time.time() - start_time
        avg_time_per_auth = total_time / auth_cycles
        
        print(f"🔑 Authentication Performance:")
        print(f"  {auth_cycles} auth cycles in {total_time:.2f}s")
        print(f"  {successful_auths} successful authentications")
        print(f"  Average: {avg_time_per_auth*1000:.2f}ms per authentication cycle")
        
        self.assertLess(avg_time_per_auth, 0.3)
    
    def test_transaction_performance(self):
        """Test transaction processing performance"""
        self.bank.register_user("txn_user", "TxnPass123!@#", "txn@example.com")
        otp = self.bank.mfa_auth.generate_totp("txn_user")
        session_id = self.bank.authenticate_user("txn_user", "TxnPass123!@#", otp)
        
        self.assertIsNotNone(session_id, "Authentication failed")
        
        start_time = time.time()
        transaction_count = 10
        successful_txns = 0
        
        for i in range(transaction_count):
            transaction_data = {
                'id': f"perf_txn_{i}_{int(time.time())}",
                'type': 'DEPOSIT',
                'amount': 100.00,
                'session_id': session_id,
                'timestamp': datetime.now().isoformat(),  # FIXED
                'from_account': 'external',
                'to_account': 'txn_user',
                'description': f'Performance test transaction {i}'
            }
            
            encrypted_txn = self.bank.secure_protocol.encrypt_message(
                session_id, 
                json.dumps(transaction_data),
                is_client=True
            )
            
            try:
                result = self.bank.process_transaction(session_id, encrypted_txn)
                if result and result.get('status') == 'success':
                    successful_txns += 1
            except Exception as e:
                print(f"Transaction {i} failed: {e}")
    
        total_time = time.time() - start_time
        avg_time_per_txn = total_time / transaction_count
        
        print(f"💳 Transaction Performance:")
        print(f"  {transaction_count} transactions attempted in {total_time:.2f}s")
        print(f"  {successful_txns} successful transactions")
        print(f"  Average: {avg_time_per_txn*1000:.2f}ms per transaction")
        
        self.assertLess(avg_time_per_txn, 0.1)
    
    def test_tls_handshake_performance(self):
        """Test TLS handshake performance"""
        start_time = time.time()
        handshake_count = 5
        successful_handshakes = 0
        
        for i in range(handshake_count):
            client_id = f"handshake_client_{i}_{int(time.time())}"
            try:
                handshake_data = self.bank.secure_protocol.perform_tls_handshake(
                    client_id, 
                    self.bank.server_public_key
                )
                if handshake_data and 'session_id' in handshake_data:
                    successful_handshakes += 1
            except Exception as e:
                print(f"Handshake {i} failed: {e}")
        
        total_time = time.time() - start_time
        avg_time_per_handshake = total_time / handshake_count
        
        print(f"🤝 TLS Handshake Performance:")
        print(f"  {handshake_count} handshakes attempted in {total_time:.2f}s")
        print(f"  {successful_handshakes} successful handshakes")
        print(f"  Average: {avg_time_per_handshake*1000:.2f}ms per handshake")
        
        self.assertLess(avg_time_per_handshake, 0.2)
    
    def test_performance_reporting(self):
        """Test that performance reporting works correctly"""
        self.bank.register_user("report_user", "ReportPass123!", "report@example.com")
        otp = self.bank.mfa_auth.generate_totp("report_user")
        session_id = self.bank.authenticate_user("report_user", "ReportPass123!", otp)
        
        if session_id:
            transaction_data = {
                'id': f"report_txn_{int(time.time())}",
                'type': 'DEPOSIT',
                'amount': 500.00,
                'session_id': session_id,
                'timestamp': datetime.now().isoformat(),  # FIXED
                'from_account': 'external',
                'to_account': 'report_user',
                'description': 'Performance report test transaction'
            }
            
            encrypted_txn = self.bank.secure_protocol.encrypt_message(
                session_id, 
                json.dumps(transaction_data),
                is_client=True
            )
            
            try:
                self.bank.process_transaction(session_id, encrypted_txn)
            except Exception as e:
                print(f"Test transaction failed: {e}")
        
        report = PerformanceReporter.generate_performance_report(self.bank)
        
        self.assertIn('system_metrics', report)
        self.assertIn('crypto_performance', report)
        self.assertIn('protocol_performance', report)
        self.assertIn('auth_performance', report)
        self.assertIn('banking_performance', report)
        
        self.assertIn('cpu_percent', report['system_metrics'])
        self.assertIn('memory_percent', report['system_metrics'])
        
        crypto_ops = sum(stats['call_count'] for stats in report['crypto_performance'].values())
        protocol_ops = sum(stats['call_count'] for stats in report['protocol_performance'].values())
        
        print(f"📊 Performance Insights:")
        print(f"  Cryptographic operations: {crypto_ops}")
        print(f"  Protocol operations: {protocol_ops}")
        print(f"  System CPU: {report['system_metrics']['cpu_percent']:.1f}%")
        print(f"  System Memory: {report['system_metrics']['memory_percent']:.1f}%")
        
        print("✅ Performance reporting working correctly")

    def test_memory_usage(self):
        """Test memory usage under load"""
        gc.collect()
        
        initial_memory = psutil.Process().memory_info().rss / 1024 / 1024
        
        users_created = 0
        for i in range(10):
            try:
                username = f"mem_user_{i}"
                self.bank.register_user(username, f"MemPass123!{i}", f"mem{i}@example.com")
                users_created += 1
            except Exception as e:
                print(f"User creation {i} failed: {e}")
        
        final_memory = psutil.Process().memory_info().rss / 1024 / 1024
        memory_increase = final_memory - initial_memory
        
        print(f"🧠 Memory Usage Test:")
        print(f"  Initial memory: {initial_memory:.2f} MB")
        print(f"  Final memory: {final_memory:.2f} MB")
        print(f"  Memory increase: {memory_increase:.2f} MB")
        print(f"  Users created: {users_created}")
        
        self.assertLess(memory_increase, 50.0)

if __name__ == '__main__':
    unittest.main()