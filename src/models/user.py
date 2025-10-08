from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional

@dataclass
class User:
    username: str
    password_hash: bytes
    salt: bytes
    email: str
    registration_date: datetime
    account_balance: float
    transaction_history: List[str]
    mfa_enabled: bool = False
    fido2_credentials: Optional[dict] = None
    
    def to_dict(self):
        return {
            'username': self.username,
            'email': self.email,
            'registration_date': self.registration_date.isoformat(),
            'account_balance': self.account_balance,
            'mfa_enabled': self.mfa_enabled
        }