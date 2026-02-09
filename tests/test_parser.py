from surfacelog.core.parser import parse_line


def test_parse_ip_and_port_numeric():
    line = "Jan 10 12:01:01 sshd Failed password from 10.0.0.1 port 5001"
    event = parse_line(line)

    assert event.source_ip == "10.0.0.1"
    assert event.source_port == 5001


def test_parse_named_port():
    line = "Jan 10 12:01:01 winbox login failed from 201.55.10.8 via winbox"
    event = parse_line(line)

    assert event.source_port == "winbox"


def test_ignore_empty_line():
    assert parse_line("") is None
