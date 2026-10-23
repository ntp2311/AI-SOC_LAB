
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE = Path.home() / "ai-soc-lab"
DATA = BASE / "data"
REPORTS = BASE / "reports"

WINDOW_SECONDS = 120


def read_jsonl(path):
    records = []
    if not path.exists():
        return records
    with path.open(encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return records


def parse_time(value):
    if not value:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            return None
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def identifier(value):
    return str(value) if value is not None else None

import ipaddress
from decimal import Decimal, InvalidOperation

def normalize_ip(value):
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return str(value)

def normalize_flow_id(value):
    if value is None:
        return None
    try:
        return str(int(Decimal(str(value))))
    except (InvalidOperation, ValueError):
        return str(value)

def normalize_suricata(event):
    alert = event.get("alert") or {}
    return {
        "time": parse_time(event.get("timestamp")),
        "src": normalize_ip(event.get("src_ip")),
"dst": normalize_ip(event.get("dest_ip")),
        "port": event.get("dest_port"),
        "sid": identifier(alert.get("signature_id")),
        "description": alert.get("signature", ""),
        "source": "Suricata",
        "raw": event,
    }


def normalize_wazuh(event):
    data = event.get("data") or {}
    alert = data.get("alert") or {}
    return {
        "time": parse_time(
    data.get("timestamp") or event.get("timestamp")
),
        "src": normalize_ip(data.get("src_ip")),
"dst": normalize_ip(data.get("dest_ip")),
        "port": data.get("dest_port"),
        "sid": identifier(alert.get("signature_id")),
        "description": (
            event.get("rule", {}).get("description", "")
        ),
        "source": "Wazuh",
        "raw": event,
    }


def is_suricata_wazuh(event):
    groups = event.get("rule", {}).get("groups") or []
    return (
        "suricata" in [str(g).lower() for g in groups]
        or (event.get("location") or "").endswith("eve.json")
    )


def match(a, b):
    if not a["time"] or not b["time"]:
        return False

    delta = abs((a["time"] - b["time"]).total_seconds())
    if delta > WINDOW_SECONDS:
        return False

    # Require the same signature and both endpoint IPs.
    if not a["sid"] or a["sid"] != b["sid"]:
        return False

    if not a["src"] or not a["dst"]:
        return False

    if a["src"] != b["src"] or a["dst"] != b["dst"]:
        return False

    if a["port"] is not None and b["port"] is not None:
        if str(a["port"]) != str(b["port"]):
            return False

    return True


def main():
    REPORTS.mkdir(parents=True, exist_ok=True)

    suricata_raw = read_jsonl(DATA / "suricata.jsonl")
    wazuh_raw = read_jsonl(DATA / "wazuh.jsonl")

    suricata = [
        normalize_suricata(e)
        for e in suricata_raw
        if e.get("event_type") == "alert"
    ]

    wazuh = [
        normalize_wazuh(e)
        for e in wazuh_raw
        if is_suricata_wazuh(e)
    ]

    pairs = []
    used_wazuh = set()

    for s in suricata:
        candidates = [
            (i, w)
            for i, w in enumerate(wazuh)
            if i not in used_wazuh and match(s, w)
        ]
        if candidates:
            i, w = min(
                candidates,
                key=lambda item: abs(
                    (s["time"] - item[1]["time"]).total_seconds()
                ),
            )
            used_wazuh.add(i)
            pairs.append((s, w))

    now = datetime.now(timezone.utc).isoformat()

    lines = [
        "# AI SOC Lab — Incident Correlation Report",
        "",
        f"Generated (UTC): {now}",
        "",
        "## Evidence summary",
        f"- Suricata alerts in snapshot: {len(suricata)}",
        f"- Wazuh Suricata alerts in snapshot: {len(wazuh)}",
        f"- Correlated alert pairs: {len(pairs)}",
        f"- Correlation window: ±{WINDOW_SECONDS} seconds",
        "",
        "## Correlation results",
    ]

    if not pairs:
        lines += [
            "",
            "No matching alert pairs were found.",
            "This does not prove that no attack occurred.",
            "Check event time windows, log collection, and fields.",
        ]

    for number, (s, w) in enumerate(pairs, 1):
        lines += [
            "",
            f"### Event {number}",
            f"- Suricata time (UTC): {s['time'].isoformat()}",
            f"- Wazuh time (UTC): {w['time'].isoformat()}",
            f"- Source IP: {s['src']}",
            f"- Destination IP: {s['dst']}",
            f"- Destination port: {s['port']}",
            f"- Signature ID: {s['sid']}",
            f"- Suricata signature: {s['description']}",
            f"- Wazuh rule: {w['description']}",
            "- Assessment: Matching IDS/SIEM alert records; "
              "no exploitation is established by this match alone.",
        ]

    lines += [
        "",
        "## Analyst recommendations",
        "- Verify the scan was within the approved lab scope.",
        "- Compare timestamps with the authorized Nmap test.",
        "- Review exposed services and rule coverage.",
        "- Preserve original logs for further investigation.",
        "",
        "## Limitations",
        "- Matching is based on timestamp, source/destination "
          "IP and signature ID.",
        "- The report does not establish attacker identity.",
        "- File snapshots may omit events outside the last "
          "3,000 lines.",
        "- Correlation does not independently validate "
          "the underlying Suricata detection.",
    ]

    report = REPORTS / "incident-report.md"
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Suricata alerts: {len(suricata)}")
    print(f"Wazuh alerts: {len(wazuh)}")
    print(f"Correlated pairs: {len(pairs)}")
    print(f"Report: {report}")


if __name__ == "__main__":
    main()
