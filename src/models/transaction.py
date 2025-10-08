from dataclasses import dataclass
from datetime import datetime
from enum import Enum

class TransactionType(Enum):
    DEPOSIT = "DEPOSIT"
    WITHDRAWAL = "WITHDRAWAL"
    TRANSFER = "TRANSFER"

@dataclass
class Transaction:
    transaction_id: str
    type: TransactionType
    amount: float
    timestamp: datetime
    from_account: str
    to_account: str
    description: str
    session_id: str
    
    def to_encrypted_dict(self):
        return {
            'id': self.transaction_id,
            'type': self.type.value,
            'amount': self.amount,
            'timestamp': self.timestamp.isoformat(),
            'from_account': self.from_account,
            'to_account': self.to_account,
            'description': self.description,
            'session_id': self.session_id
        }