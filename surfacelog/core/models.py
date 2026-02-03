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
    source: str
    vendor: str
    device_type: str

    # classificação
    event_type: EventType
    severity: Severity          # <- ADICIONADO
    action: str

    # identidade
    username: Optional[str]

    # rede
    src_ip: Optional[str]
    src_port: Optional[int | str]   # <- AJUSTADO
    dst_ip: Optional[str]
    dst_port: Optional[int | str]   # <- AJUSTADO
    protocol: Optional[str]

    # linha original
    raw: str


# ======================================================
# ALERTAS (saída do detector/analyzer)
# ======================================================

@dataclass(slots=True)
class AlertSource:
    ip: Optional[str]
    port: Optional[int | str]   # <- manter consistente


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
