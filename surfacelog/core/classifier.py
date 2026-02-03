from surfacelog.core.parser import LogEvent
from surfacelog.core.models import (
    EventType,
    Severity,
    NormalizedEvent,
)


AUTH_FAILURE_PATTERNS = (
    "failed password",
    "authentication failure",
    "denied",
    "permission denied",
    "login failure",
)

AUTH_SUCCESS_PATTERNS = (
    "accepted password",
    "login successful",
    "logged in",
    "logged out",
)


def classify_event(event: LogEvent) -> NormalizedEvent:
    message = event.message.lower()

    event_type = EventType.INFO
    severity = Severity.LOW

    # =========================
    # CLASSIFICAÇÃO SEMÂNTICA
    # =========================

    if any(p in message for p in AUTH_FAILURE_PATTERNS):
        event_type = EventType.AUTH_FAILURE
        severity = Severity.HIGH

    elif any(p in message for p in AUTH_SUCCESS_PATTERNS):
        event_type = EventType.AUTH_SUCCESS
        severity = Severity.LOW

    elif "error" in message:
        event_type = EventType.ERROR
        severity = Severity.HIGH

    elif "warning" in message:
        event_type = EventType.WARNING
        severity = Severity.MEDIUM

    elif "unknown" in message:
        event_type = EventType.UNKNOWN
        severity = Severity.MEDIUM

    # =========================
    # NORMALIZAÇÃO CANÔNICA
    # =========================

    return NormalizedEvent(
        timestamp=event.timestamp,
        source="auth.log",
        vendor="linux",
        device_type="server",

        event_type=event_type,
        severity=severity,   # <- OBRIGATÓRIO AGORA

        action="log",

        username=None,

        src_ip=event.source_ip,
        src_port=event.source_port,
        dst_ip=None,
        dst_port=None,
        protocol=None,

        raw=event.raw,
    )
