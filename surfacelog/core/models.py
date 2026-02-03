from enum import Enum
from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict, Any, List


# ======================================================
# ENUMS CANÔNICOS
# ======================================================

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


# ======================================================
# EVENTO NORMALIZADO (contrato principal do pipeline)
# Parser → Classifier → Analyzer → Detector
# ======================================================

@dataclass(slots=True)
class NormalizedEvent:
    timestamp: datetime

    # origem do log
    source: str               # ex: system, firewall, sshd
    vendor: str               # ex: fortinet, linux
    device_type: str          # ex: firewall, server, endpoint

    # classificação
    event_type: EventType
    action: str

    # identidade
    username: Optional[str]

    # rede
    src_ip: Optional[str]
    src_port: Optional[int]
    dst_ip: Optional[str]
    dst_port: Optional[int]
    protocol: Optional[str]

    # linha original
    raw: str


# ======================================================
# ALERTAS (saída do detector/analyzer)
# ======================================================

@dataclass(slots=True)
class AlertSource:
    ip: Optional[str]
    port: Optional[int]


@dataclass(frozen=True, slots=True)
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


# ======================================================
# MAPEAMENTO DE SEVERIDADE PADRÃO
# ======================================================

ALERT_SEVERITY = {
    "BRUTE_FORCE": Severity.CRITICAL,
    "OFF_HOURS_ACTIVITY": Severity.MEDIUM,
}
