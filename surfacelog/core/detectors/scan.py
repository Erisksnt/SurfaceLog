from __future__ import annotations
from datetime import datetime, timezone
from surfacescan import ScanConfig, parse_ports, run_scan

def run_port_scan_detector(target: str, ports_expr: str = "1-1024") -> list[dict]:
    """
    Executa scan e retorna eventos já no formato do SurfaceLog.
    """
    config = ScanConfig(
        host=target,
        ports=parse_ports(ports_expr),
        timeout=1.0,
        threads=80,
    )

    raw_results = run_scan(config)

    # normaliza para o formato de evento do SIEM
    events: list[dict] = []
    now = datetime.now(timezone.utc).isoformat()

    for item in raw_results:
        events.append(
            {
                "timestamp": now,
                "detector": "port_scan",
                "source": "surfacescan",
                "target": target,
                "port": item.get("port"),
                "service": item.get("service"),
                "status": item.get("status"),
                "banner": item.get("banner"),
                "severity": "medium", 
            }
        )

    return events