from surfacelog.core.events import LogEvent


def classify_event(event: LogEvent) -> LogEvent:
    message = event.message.lower()

    if "failed password" in message or "authentication failure" in message:
        event.event_type = "AUTH_FAILURE"
        event.severity = "HIGH"

    elif "accepted password" in message or "login successful" in message:
        event.event_type = "AUTH_SUCCESS"
        event.severity = "LOW"

    elif "denied" in message or "permission denied" in message:
        event.event_type = "ACCESS_DENIED"
        event.severity = "HIGH"

    elif "error" in message:
        event.event_type = "ERROR"
        event.severity = "HIGH"

    elif "warning" in message:
        event.event_type = "WARNING"
        event.severity = "MEDIUM"

    else:
        event.event_type = "INFO"
        event.severity = "LOW"

    return event
