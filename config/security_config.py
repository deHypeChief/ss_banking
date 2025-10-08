class SecurityConfig:
    """Security configuration settings"""
    
    # Encryption settings
    ENCRYPTION_ALGORITHM = "AES-256-GCM"
    HASH_ALGORITHM = "SHA-256"
    KEY_DERIVATION_ITERATIONS = 100000
    RSA_KEY_SIZE = 2048
    
    # Session settings
    SESSION_TIMEOUT = 900  # 15 minutes
    MAX_LOGIN_ATTEMPTS = 3
    
    # Password policy
    MIN_PASSWORD_LENGTH = 12
    REQUIRE_SPECIAL_CHARS = True
    REQUIRE_NUMBERS = True
    
    # MFA settings
    OTP_VALIDITY_PERIOD = 30  # seconds
    FIDO2_TIMEOUT = 120000  # milliseconds