
import json
import subprocess
from collections import deque
from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("AI SOC Lab")

SURICATA_LOG = Path("/var/log/suricata/eve.json")
ALLOWED_PORTS = {22, 80, 443, 445, 5432}


@mcp.tool()
def scan_localhost(ports: list[int]) -> dict:
    """Scan approved TCP ports on localhost only."""

    if not ports or len(ports) > 10:
        return {"error": "Specify 1 to 10 ports"}

    if any(type(p) is not int or p not in ALLOWED_PORTS
           for p in ports):
        return {"error": "Port not permitted"}

    selected = sorted(set(ports))

    cmd = [
        "nmap",
        "-sT",
        "-T3",
        "-Pn",
        "-p", ",".join(map(str, selected)),
        "127.0.0.1",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return {
            "target": "127.0.0.1",
            "ports": selected,
            "exit_code": result.returncode,
            "stdout": result.stdout[:12000],
            "stderr": result.stderr[:2000],
        }
    except subprocess.TimeoutExpired:
        return {"error": "Nmap timed out"}


@mcp.tool()
def get_suricata_alerts(limit: int = 10) -> dict:
    """Read recent Suricata alerts from local EVE JSON."""

    if not isinstance(limit, int) or not 1 <= limit <= 50:
        return {"error": "Limit must be 1-50"}

    if not SURICATA_LOG.is_file():
        return {"error": "Suricata EVE log not found"}

    alerts = deque(maxlen=limit)

    try:
        with SURICATA_LOG.open(
            "r", encoding="utf-8", errors="replace"
        ) as f:
            for line in f:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue

                if event.get("event_type") == "alert":
                    alerts.append({
                        "timestamp": event.get("timestamp"),
                        "src_ip": event.get("src_ip"),
                        "dest_ip": event.get("dest_ip"),
                        "dest_port": event.get("dest_port"),
                        "signature": event.get(
                            "alert", {}
                        ).get("signature"),
                        "signature_id": event.get(
                            "alert", {}
                        ).get("signature_id"),
                    })

        return {
            "source": str(SURICATA_LOG),
            "alerts": list(alerts),
            "count": len(alerts),
        }

    except PermissionError:
        return {"error": "Permission denied reading EVE log"}


@mcp.tool()
def get_incident_report() -> dict:
    """Read the latest locally generated SOC incident report."""

    report = (
        Path.home()
        / "ai-soc-lab"
        / "reports"
        / "incident-report.md"
    )

    if not report.is_file():
        return {"error": "Incident report not found"}

    content = report.read_text(encoding="utf-8")

    return {
        "status": "success",
        "report_path": str(report),
        "report_content": content[:30000],
        "truncated": len(content) > 30000,
        "source": "local_correlation_engine",
    }

if __name__ == "__main__":
    mcp.run(transport="stdio")
