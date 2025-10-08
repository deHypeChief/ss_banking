from dataclasses import dataclass
from datetime import datetime

@dataclass
class Session:
    session_id: str
    username: str
    created_at: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    is_active: bool = True
    
    def update_activity(self):
        self.last_activity = datetime.now()
    
    def is_expired(self, timeout_seconds: int) -> bool:
        return (datetime.now() - self.last_activity).total_seconds() > timeout_seconds