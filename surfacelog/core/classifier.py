from surfacelog.core.models import (
    EventType,
    Severity,
    NormalizedEvent,
)


def classify_event(event) -> NormalizedEvent:
    message = event.message.lower()

    event_type = EventType.INFO
    severity = Severity.LOW

    if any(x in message for x in (
        "failed password",
        "authentication failure",
        "denied",
        "permission denied",
        "login failure",
    )):
        event_type = EventType.AUTH_FAILURE
        severity = Severity.HIGH

    elif any(x in message for x in (
        "accepted password",
        "login successful",
        "logged in",
        "logged out",
    )):
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

    return NormalizedEvent(
        timestamp=event.timestamp,
        source="system",          # pode ajustar depois
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
