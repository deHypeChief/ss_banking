#!/usr/bin/env python3
"""
Debug Login Issues
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.banking_core import SecureOnlineBanking

def debug_login():
    print("🔍 DEBUGGING LOGIN ISSUES")
    print("=" * 50)
    
    bank = SecureOnlineBanking()
    
    # Test user credentials
    username = "debug_user"
    password = "DebugPass123!@"
    email = "debug@example.com"
    
    print(f"Testing with:")
    print(f"  Username: {username}")
    print(f"  Password: {password}")
    print(f"  Email: {email}")
    
    # Step 1: Try to register
    print("\n1. 🔄 Attempting registration...")
    try:
        result = bank.register_user(username, password, email)
        print("   ✅ Registration successful!")
        print(f"   User exists in system: {username in bank.users}")
    except Exception as e:
        print(f"   ❌ Registration failed: {e}")
        return
    
    # Step 2: Generate OTP
    print("\n2. 🔑 Generating OTP...")
    try:
        otp = bank.mfa_auth.generate_totp(username)
        print(f"   ✅ OTP generated: {otp}")
        print(f"   OTP secrets exist: {username in bank.mfa_auth.otp_secrets}")
    except Exception as e:
        print(f"   ❌ OTP generation failed: {e}")
        return
    
    # Step 3: Check user data
    print("\n3. 👤 Checking user data...")
    user = bank.users.get(username)
    if user:
        print(f"   ✅ User found in system")
        print(f"   MFA enabled: {user.mfa_enabled}")
        print(f"   Password hash length: {len(user.password_hash)}")
        print(f"   Salt length: {len(user.salt)}")
    else:
        print("   ❌ User not found in system")
        return
    
    # Step 4: Verify OTP separately
    print("\n4. ✅ Verifying OTP...")
    try:
        is_otp_valid = bank.mfa_auth.verify_totp(username, otp)
        print(f"   OTP verification: {is_otp_valid}")
    except Exception as e:
        print(f"   ❌ OTP verification failed: {e}")
    
    # Step 5: Attempt login
    print("\n5. 🚀 Attempting login...")
    session_id = bank.authenticate_user(username, password, otp)
    
    if session_id:
        print(f"   ✅ LOGIN SUCCESSFUL!")
        print(f"   Session ID: {session_id}")
        print(f"   Session valid: {session_id in bank.sessions}")
    else:
        print("   ❌ LOGIN FAILED")
        print("   Checking login attempts...")
        print(f"   Failed attempts: {bank.login_attempts.get(username, 0)}")
        
        # Test password verification separately
        print("\n6. 🔐 Testing password verification...")
        user = bank.users[username]
        password_correct = bank.crypto_manager.verify_password(password, user.password_hash, user.salt)
        print(f"   Password correct: {password_correct}")
        
        # Test without OTP
        print("\n7. 🔄 Testing without OTP...")
        session_no_otp = bank.authenticate_user(username, password)
        print(f"   Login without OTP: {'Failed as expected' if session_no_otp is None else 'Unexpected success'}")
        
        # Test with wrong OTP
        print("\n8. ❌ Testing with wrong OTP...")
        session_wrong_otp = bank.authenticate_user(username, password, "000000")
        print(f"   Login with wrong OTP: {'Failed as expected' if session_wrong_otp is None else 'Unexpected success'}")

if __name__ == "__main__":
    debug_login()