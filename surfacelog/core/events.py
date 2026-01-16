from dataclasses import dataclass
from datetime import datetime

@dataclass
class LogEvent:
    timestamp: datetime
    source_ip: str
    message: str
    raw: str