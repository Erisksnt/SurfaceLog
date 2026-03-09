from scanner.api import ScanConfig, run_scan
from .base import BaseDetector

class PortScanDetector(BaseDetector):
    """Detects open ports on specified hosts."""
    
    def detect(self, host: str, ports: str, timeout: float = 1.0) -> list[dict]:
        """
        Scan ports on a target host.
        
        Args:
            host: Target IP or hostname
            ports: Port expression (e.g., "22,80,443,8000-8100")
            timeout: Connection timeout in seconds
        
        Returns:
            List of open ports with details
        """
        try:
            config = ScanConfig(
                host=host,
                ports=self._parse_ports(ports),
                timeout=timeout,
                threads=50
            )
            results = run_scan(config)
            
            return [{
                "type": "open_port",
                "severity": "medium",
                "host": host,
                "port": r["port"],
                "service": r["service"],
                "banner": r.get("banner", ""),
                "timestamp": self.timestamp
            } for r in results if r["status"] == "open"]
        except Exception as e:
            self.logger.error(f"Port scan failed: {e}")
            return []
    
    @staticmethod
    def _parse_ports(ports_expr: str) -> list[int]:
        """Parse port expression string."""
        from scanner.api import parse_ports
        return parse_ports(ports_expr)