from surfacelog.core.models import NormalizedEvent, EventType
from surfacelog.core.detectors.registry import run_detectors
from datetime import datetime


def make_failure(ip):
    return NormalizedEvent(
        timestamp=datetime.now(),
        source="auth",
        vendor="linux",
        device_type="server",
        event_type=EventType.AUTH_FAILURE,
        action="log",
        username=None,
        src_ip=ip,
        src_port=22,
        dst_ip=None,
        dst_port=None,
        protocol=None,
        raw="fail"
    )


def test_bruteforce_detection():
    events = [make_failure("1.1.1.1") for _ in range(6)]

    alerts = run_detectors(events)

    assert any(a.type == "BRUTE_FORCE" for a in alerts)
