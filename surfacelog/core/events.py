from dataclasses import dataclass
from datetime import datetime
from surfacelog.core.models import EventType, Severity


@dataclass
class LogEvent:
    timestamp: datetime
    source_ip: str
    message: str
    raw: str
    event_type: EventType = EventType.INFO
    severity: Severity = Severity.LOW
    source_port: str = None
