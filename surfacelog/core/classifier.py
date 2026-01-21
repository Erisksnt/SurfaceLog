from surfacelog.core.events import LogEvent
from .models import EventType, Severity


def classify_event(event: LogEvent) -> LogEvent:
    message = event.message.lower()

    if "failed password" in message or "authentication failure" in message:
        event.event_type = EventType.AUTH_FAILURE
        event.severity = Severity.HIGH

    elif "accepted password" in message or "login successful" in message:
        event.event_type = EventType.AUTH_SUCCESS
        event.severity = Severity.LOW

    elif "denied" in message or "permission denied" in message:
        event.event_type = EventType.ACCESS_DENIED
        event.severity = Severity.HIGH

    elif "error" in message:
        event.event_type = EventType.ERROR
        event.severity = Severity.HIGH

    elif "warning" in message:
        event.event_type = EventType.WARNING
        event.severity = Severity.MEDIUM

    else:
        event.event_type = EventType.INFO
        event.severity = Severity.LOW

    return event
