from uuid import uuid4

from surfacelog.core.models import (
    Alert,
    AlertSource,
    EventType,
    ALERT_SEVERITY,
)
from surfacelog.core.rules import load_rules, is_off_hours


def detect_off_hours_activity(events) -> list[Alert]:
    rules = load_rules()
    alerts: list[Alert] = []

    suspicious_types = {
        EventType.AUTH_FAILURE,
        EventType.ACCESS_DENIED,
        EventType.ERROR,
    }

    for event in events:
        if not event.timestamp:
            continue

        if event.event_type in suspicious_types and is_off_hours(event.timestamp, rules):
            alerts.append(
                Alert(
                    id=str(uuid4()),
                    type="OFF_HOURS_ACTIVITY",
                    severity=ALERT_SEVERITY["OFF_HOURS_ACTIVITY"],
                    timestamp=event.timestamp,
                    source=AlertSource(
                        ip=event.source_ip,
                        port=None,
                    ),
                    summary="Suspicious activity detected outside business hours",
                    details={
                        "event_type": event.event_type.value
                        if hasattr(event.event_type, "value")
                        else event.event_type,
                        "message": event.message,
                    },
                )
            )

    return alerts
