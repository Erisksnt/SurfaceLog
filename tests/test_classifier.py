from surfacelog.core.parser import LogEvent
from surfacelog.core.classifier import classify_event
from datetime import datetime


def make_event(msg):
    return LogEvent(datetime.now(), "1.1.1.1", 22, msg, msg)


def test_auth_failure():
    ev = classify_event(make_event("Failed password for root"))
    assert ev.event_type.value == "AUTH_FAILURE"


def test_auth_success():
    ev = classify_event(make_event("Accepted password for root"))
    assert ev.event_type.value == "AUTH_SUCCESS"
