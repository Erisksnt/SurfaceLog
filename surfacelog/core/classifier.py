from surfacelog.core.models import EventType, Severity

def classify_event(event: dict) -> dict:
    message = event.get("message", "").lower()

    # ---- Tipo de evento ----
    if "failed password" in message or "authentication failure" in message:
        event_type = EventType.AUTH_FAILURE
        severity = Severity.HIGH

    elif "accepted password" in message or "login successful" in message:
        event_type = EventType.AUTH_SUCCESS
        severity = Severity.LOW

    elif "denied" in message or "permission denied" in message:
        event_type = EventType.ACCESS_DENIED
        severity = Severity.HIGH

    elif "error" in message:
        event_type = EventType.ERROR
        severity = Severity.HIGH

    elif "warning" in message:
        event_type = EventType.WARNING
        severity = Severity.MEDIUM

    else:
        event_type = EventType.INFO
        severity = Severity.LOW

    # ---- Enriquecimento do evento ----
    event["event_type"] = event_type.value
    event["severity"] = severity.value

    return event
