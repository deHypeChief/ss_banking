#!/usr/bin/env python3
"""
Main entry point for Secure Online Banking System with Performance Monitoring
"""

import sys
import os
import json
from datetime import datetime

# Add src to Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.banking_core import SecureOnlineBanking
from src.models.transaction import TransactionType
from src.performance_reporter import PerformanceReporter

def main():
    """Main demonstration function with performance monitoring"""
    print("=== Secure Online Banking System with Performance Monitoring ===\n")
    
    try:
        # Initialize banking system
        bank = SecureOnlineBanking()
        
        # Demonstration
        run_demo(bank)
        
        # Generate performance report
        print("\n" + "="*60)
        print("📈 PERFORMANCE REPORT")
        print("="*60)
        PerformanceReporter.print_real_time_dashboard(bank)
        
        # Save detailed report
        PerformanceReporter.save_performance_report(bank)
        
        # Quick summary
        summary = PerformanceReporter.get_performance_summary(bank)
        print(f"\n🚀 PERFORMANCE SUMMARY:")
        print(f"  Total Operations: {summary['total_operations']}")
        print(f"  Avg Crypto Time: {summary['avg_crypto_time']:.2f}ms")
        print(f"  Avg Protocol Time: {summary['avg_protocol_time']:.2f}ms")
        print(f"  System Health: CPU {summary['system_health']['cpu']:.1f}%, "
              f"Memory {summary['system_health']['memory']:.1f}%")
        
    except Exception as e:
        print(f"Error: {e}")
        return 1
    
    return 0

def run_demo(bank: SecureOnlineBanking):
    """Run the banking system demonstration"""
    
    print("1. User Registration:")
    try:
        bank.register_user("alice_smith", "SecurePass123!", "alice@example.com")
        bank.register_user("bob_jones", "StrongPassword456!", "bob@example.com")
        print("   ✓ Users 'alice_smith' and 'bob_jones' registered successfully")
    except ValueError as e:
        print(f"   ✗ Registration failed: {e}")
    
    print("\n2. User Authentication with MFA:")
    # Generate OTP for Alice
    otp_alice = bank.mfa_auth.generate_totp("alice_smith")
    print(f"   Generated OTP for alice_smith: {otp_alice}")
    
    session_alice = bank.authenticate_user("alice_smith", "SecurePass123!", otp_alice)
    
    if session_alice:
        print("   ✓ User 'alice_smith' authenticated successfully")
        print(f"   Session ID: {session_alice[:20]}...")
    else:
        print("   ✗ Authentication failed for alice_smith")
        return
    
    print("\n3. Secure Transaction Processing:")
    try:
        # Create deposit transaction for Alice
        transaction_data = {
            'id': f"txn_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'type': 'DEPOSIT',
            'amount': 1500.00,
            'session_id': session_alice,
            'timestamp': datetime.now().isoformat(),
            'from_account': 'external',
            'to_account': 'alice_smith',
            'description': 'Initial deposit'
        }
        
        # Encrypt and process transaction
        encrypted_txn = bank.secure_protocol.encrypt_message(
            session_alice, 
            json.dumps(transaction_data)
        )
        
        result = bank.process_transaction(session_alice, encrypted_txn)
        print("   ✓ Transaction processed successfully")
        print(f"   Transaction ID: {result['transaction_id']}")
        
        # Check balance
        balance = bank.get_user_balance(session_alice)
        print(f"   New Balance for Alice: ${balance:.2f}")
        
    except Exception as e:
        print(f"   ✗ Transaction failed: {e}")
    
    print("\n4. Second Transaction (Withdrawal):")
    try:
        # Create withdrawal transaction
        transaction_data = {
            'id': f"txn_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            'type': 'WITHDRAWAL',
            'amount': 200.00,
            'session_id': session_alice,
            'timestamp': datetime.now().isoformat(),
            'from_account': 'alice_smith',
            'to_account': 'external',
            'description': 'ATM withdrawal'
        }
        
        encrypted_txn = bank.secure_protocol.encrypt_message(
            session_alice, 
            json.dumps(transaction_data)
        )
        
        result = bank.process_transaction(session_alice, encrypted_txn)
        print("   ✓ Withdrawal processed successfully")
        
        balance = bank.get_user_balance(session_alice)
        print(f"   Updated Balance: ${balance:.2f}")
        
    except Exception as e:
        print(f"   ✗ Withdrawal failed: {e}")
    
    print("\n5. Security Audit and Monitoring:")
    print(f"   Total security events logged: {len(bank.audit_trail)}")
    print("   Recent security events:")
    for event in bank.audit_trail[-5:]:
        print(f"   - {event['timestamp'][11:19]} | {event['event']}")
    
    print("\n6. Transaction History:")
    history = bank.get_transaction_history(session_alice)
    print(f"   Account: {history['username']}")
    print(f"   Current Balance: ${history['balance']:.2f}")
    print(f"   Total Transactions: {history['transaction_count']}")
    
    print("\n7. Logout:")
    bank.logout_user(session_alice)
    print("   ✓ User logged out successfully")
    
    print("\n=== Demonstration Complete ===")
    print("\nSecurity Features Demonstrated:")
    features = [
        "✓ TLS 1.3-like Secure Communication",
        "✓ AES-256-GCM Encryption", 
        "✓ Multi-Factor Authentication (TOTP)",
        "✓ Secure Session Management",
        "✓ Immutable Audit Trail",
        "✓ Cryptographic Integrity Checks", 
        "✓ Perfect Forward Secrecy",
        "✓ Rate Limiting and Brute Force Protection",
        "✓ Secure Password Hashing (PBKDF2)",
        "✓ End-to-End Encryption",
        "✓ Performance Monitoring & Analytics"
    ]
    
    for feature in features:
        print(f"   {feature}")

if __name__ == "__main__":
    sys.exit(main())