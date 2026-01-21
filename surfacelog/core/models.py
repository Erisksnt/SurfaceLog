from enum import Enum

class EventType(str, Enum):
    AUTH_FAILURE = "AUTH_FAILURE"
    AUTH_SUCCESS = "AUTH_SUCCESS"
    ACCESS_DENIED = "ACCESS_DENIED"
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"
    UNKNOWN = "unknown"


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Mapeamento de severidade por tipo de alerta
ALERT_SEVERITY = {
    "BRUTE_FORCE": Severity.CRITICAL,
    "OFF_HOURS_ACTIVITY": Severity.MEDIUM,
}
