from enum import Enum
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any, List


# =====================
# ENUMS CANÔNICOS
# =====================

class EventType(str, Enum):
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    ACCESS_DENIED = "ACCESS_DENIED"
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# =====================
# EVENTO NORMALIZADO
# =====================

@dataclass
class NormalizedEvent:
    timestamp: datetime
    source: str
    vendor: str
    device_type: str
    event_type: EventType
    action: str
    username: Optional[str]
    src_ip: Optional[str]
    src_port: Optional[int]
    dst_ip: Optional[str]
    dst_port: Optional[int]
    protocol: Optional[str]
    raw: str


# =====================
# ALERTA CANÔNICO
# =====================

@dataclass
class AlertSource:
    ip: Optional[str]
    port: Optional[int]


@dataclass(frozen=True)
class Alert:
    id: str
    type: str
    severity: Severity
    timestamp: datetime
    source: AlertSource
    summary: str
    details: Optional[Dict[str, Any]] = None
    related_events: Optional[List[str]] = None
    tags: Optional[List[str]] = None


# =====================
# MAPEAMENTO DE SEVERIDADE
# =====================

ALERT_SEVERITY = {
    "BRUTE_FORCE": Severity.CRITICAL,
    "OFF_HOURS_ACTIVITY": Severity.MEDIUM,
}
