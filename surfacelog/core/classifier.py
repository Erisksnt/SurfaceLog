from surfacelog.core.parser import LogEvent
from surfacelog.core.models import (EventType,NormalizedEvent)


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

    # =========================
    # CLASSIFICAÇÃO SEMÂNTICA
    # =========================

    if any(p in message for p in AUTH_FAILURE_PATTERNS):
        event_type = EventType.AUTH_FAILURE

    elif any(p in message for p in AUTH_SUCCESS_PATTERNS):
        event_type = EventType.AUTH_SUCCESS

    elif "error" in message:
        event_type = EventType.ERROR

    elif "warning" in message:
        event_type = EventType.WARNING

    elif "unknown" in message:
        event_type = EventType.UNKNOWN

    # =========================
    # NORMALIZAÇÃO CANÔNICA
    # =========================

    return NormalizedEvent(
        timestamp=event.timestamp,
        source="auth.log",
        vendor="unknown",
        device_type="unknown",
        event_type=event_type,
        action="log",
        username=None,
        src_ip=event.source_ip,
        src_port=event.source_port,
        dst_ip=None,
        dst_port=None,
        protocol=None,
        raw=event.raw,
    )
