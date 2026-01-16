def classify_event(event: dict) -> dict:
    """
    Recebe um evento parseado e adiciona:
    - event_type
    - severity
    """

    message = event.get("message", "").lower()

    # ---- Tipo de evento ----
    if "failed password" in message or "authentication failure" in message:
        event_type = "AUTH_FAILURE"
        severity = "HIGH"

    elif "accepted password" in message or "login successful" in message:
        event_type = "AUTH_SUCCESS"
        severity = "LOW"

    elif "denied" in message or "permission denied" in message:
        event_type = "ACCESS_DENIED"
        severity = "HIGH"

    elif "error" in message:
        event_type = "ERROR"
        severity = "HIGH"

    elif "warning" in message:
        event_type = "WARNING"
        severity = "MEDIUM"

    else:
        event_type = "INFO"
        severity = "LOW"

    # ---- Enriquecimento do evento ----
    event["event_type"] = event_type
    event["severity"] = severity

    return event
