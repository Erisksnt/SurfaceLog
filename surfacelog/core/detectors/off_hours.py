from uuid import uuid4
from datetime import datetime

from surfacelog.core.models import (
    Alert,
    AlertSource,
    EventType,
    ALERT_SEVERITY,
    NormalizedEvent,
)
from surfacelog.core.rules import load_rules, is_off_hours


SUSPICIOUS_TYPES = {
    EventType.AUTH_FAILURE,
    EventType.ACCESS_DENIED,
    EventType.ERROR,
}


def detect(events: list[NormalizedEvent]) -> list[Alert]:
    rules = load_rules()
    alerts: list[Alert] = []

    for event in events:
        if not event.timestamp:
            continue

        if (
            event.event_type in SUSPICIOUS_TYPES
            and is_off_hours(event.timestamp, rules)
        ):
            alerts.append(
                Alert(
                    id=str(uuid4()),
                    type="OFF_HOURS_ACTIVITY",
                    severity=ALERT_SEVERITY["OFF_HOURS_ACTIVITY"],
                    timestamp=event.timestamp,
                    source=AlertSource(
                        ip=event.src_ip,
                        port=event.src_port,
                    ),
                    summary="Suspicious activity detected outside business hours",
                    details={
                        "event_type": event.event_type.value,
                        "raw": event.raw,  # ← substitui message
                    },
                )
            )

    return alerts
