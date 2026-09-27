"""
session_tracker.py

Groups raw Wazuh/Suricata alerts (one JSON object per line, dataset_ia.jsonl format)
into per-attacker sessions, keyed by (source_ip, time window).

Usage:
    python3 session_tracker.py dataset_ia.jsonl sessions.jsonl

Design notes:
- Uses data.src_ip / data.dest_ip / data.timestamp / data.alert.signature,
  confirmed against the real schema on 2026-07-28.
- A new session starts whenever the gap between two consecutive alerts from
  the SAME source IP exceeds SESSION_GAP_SECONDS. This is the standard
  "session windowing" approach and is pure software logic, no AI involved.
- Alerts are sorted by timestamp before grouping, since dataset_ia.jsonl is
  not guaranteed to be in strict chronological order.
"""

import sys
import json
import os
from datetime import datetime

# --- Configurable ---
SESSION_GAP_SECONDS = int(os.environ.get("SESSION_GAP_SECONDS", "10"))  # inactivity gap => new session

# The real attacker in this lab. Confirmed against actual (src_ip, dest_ip)
# pair counts on 2026-07-28: attacker<->honeypot traffic (attacker<->honeypot,
# both directions), DHCP-related broadcast traffic (DHCP
# scenario, same physical machine pre-IP-assignment), manager<->honeypot housekeeping
# (wazuh-vm <-> conpot-vm agent/manager housekeeping -- genuine noise,
# unrelated to any attack).
#
# IMPORTANT: filtering by src_ip alone is WRONG here -- Suricata logs
# whichever side sent a given packet as "source", so honeypot REPLY traffic
# (conpot-vm as src, attacker as dest) is still part of the attack and must
# be kept. The correct filter is: keep the alert if the attacker appears as
# EITHER src or dest, or it matches the DHCP broadcast pattern.
ATTACKER_IP = os.environ.get("LAB_ATTACKER_IP", "192.0.2.10")
DHCP_BROADCAST_SRC = "0.0.0.0"


def is_attacker_relevant(src_ip, dest_ip):
    if src_ip == ATTACKER_IP or dest_ip == ATTACKER_IP:
        return True
    if src_ip == DHCP_BROADCAST_SRC:
        return True
    return False


def safe_get(d, path, default=None):
    """Safely walk a dotted path through nested dicts."""
    keys = path.split(".")
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def parse_timestamp(ts_str):
    """Parse Suricata-style ISO8601 timestamps like 2026-07-05T19:59:50.300909+0000"""
    if ts_str is None:
        return None
    # Normalize "+0000" -> "+00:00" for fromisoformat compatibility
    if len(ts_str) >= 5 and ts_str[-5] in "+-" and ts_str[-3] != ":":
        ts_str = ts_str[:-2] + ":" + ts_str[-2:]
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        return None


def load_alerts(path):
    """Load and flatten the fields we need from each raw alert line."""
    alerts = []
    skipped = 0
    filtered_noise = 0
    with open(path, "r") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue

            ts = parse_timestamp(safe_get(raw, "data.timestamp"))
            src_ip = safe_get(raw, "data.src_ip")
            dest_ip = safe_get(raw, "data.dest_ip")
            signature = safe_get(raw, "data.alert.signature")

            if ts is None or src_ip is None:
                skipped += 1
                continue

            if not is_attacker_relevant(src_ip, dest_ip):
                filtered_noise += 1
                continue

            alerts.append({
                "line_num": line_num,
                "timestamp": ts,
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "signature": signature,
                "severity": safe_get(raw, "data.alert.severity"),
                "dest_port": safe_get(raw, "data.dest_port"),
                "src_port": safe_get(raw, "data.src_port"),
                "proto": safe_get(raw, "data.proto"),
                "category": safe_get(raw, "data.alert.category"),
                "action": safe_get(raw, "data.alert.action"),
                "direction": safe_get(raw, "data.direction"),
                "pkts_toserver": safe_get(raw, "data.flow.pkts_toserver"),
                "pkts_toclient": safe_get(raw, "data.flow.pkts_toclient"),
                "bytes_toserver": safe_get(raw, "data.flow.bytes_toserver"),
                "bytes_toclient": safe_get(raw, "data.flow.bytes_toclient"),
                "rule_level": safe_get(raw, "rule.level"),
            })

    print(f"Loaded {len(alerts)} attacker-relevant alerts (attacker={ATTACKER_IP} as src or dest, "
          f"or DHCP broadcast).")
    print(f"Skipped {skipped} (malformed or missing src_ip/timestamp).")
    print(f"Filtered {filtered_noise} as unrelated infrastructure noise (e.g. wazuh-vm<->conpot-vm housekeeping).")
    return alerts


def build_sessions(alerts):
    """
    Group alerts into sessions using a single continuous timeline, gapped by
    inactivity. NOT partitioned by src_ip: in this lab there is exactly one
    attacker, and Suricata alternates which IP it labels as "source" depending
    on packet direction (attacker->honeypot vs. honeypot reply). Partitioning
    by src_ip would incorrectly split a single attack into separate sessions.
    """
    alerts_sorted = sorted(alerts, key=lambda a: a["timestamp"])
    if not alerts_sorted:
        return []

    sessions = []
    session_counter = 0
    current_session_alerts = [alerts_sorted[0]]

    for prev, cur in zip(alerts_sorted, alerts_sorted[1:]):
        gap = (cur["timestamp"] - prev["timestamp"]).total_seconds()
        if gap > SESSION_GAP_SECONDS:
            sessions.append(finalize_session(session_counter, current_session_alerts))
            session_counter += 1
            current_session_alerts = [cur]
        else:
            current_session_alerts.append(cur)

    sessions.append(finalize_session(session_counter, current_session_alerts))
    return sessions


def finalize_session(session_id, alerts):
    src_ips = sorted(set(a["src_ip"] for a in alerts if a["src_ip"]))
    dest_ips = sorted(set(a["dest_ip"] for a in alerts if a["dest_ip"]))
    signatures = [a["signature"] for a in alerts]
    start = min(a["timestamp"] for a in alerts)
    end = max(a["timestamp"] for a in alerts)

    return {
        "session_id": f"S{session_id:04d}",
        "source_ips_seen": src_ips,
        "destination_ips": dest_ips,
        "start_time": start.isoformat(),
        "end_time": end.isoformat(),
        "duration_seconds": round((end - start).total_seconds(), 3),
        "alert_count": len(alerts),
        "signatures": signatures,
        "unique_signatures": sorted(set(signatures)),
        "alerts": alerts,  # full raw feature rows, timestamps converted to isoformat below
    }


def make_json_serializable(sessions):
    for s in sessions:
        for a in s["alerts"]:
            a["timestamp"] = a["timestamp"].isoformat()
    return sessions


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 session_tracker.py <input_dataset.jsonl> <output_sessions.jsonl>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    alerts = load_alerts(input_path)
    sessions = build_sessions(alerts)
    sessions = make_json_serializable(sessions)

    with open(output_path, "w") as f:
        for s in sessions:
            f.write(json.dumps(s) + "\n")

    print(f"\nBuilt {len(sessions)} sessions from {len(alerts)} alerts.")
    print(f"Written to {output_path}")

    # Quick sanity summary
    counts = [s["alert_count"] for s in sessions]
    if counts:
        print(f"Session sizes -> min: {min(counts)}, max: {max(counts)}, "
              f"avg: {sum(counts)/len(counts):.1f}")
    all_ips = set()
    for s in sessions:
        all_ips.update(s["source_ips_seen"])
    print(f"Distinct source IPs seen across all sessions: {sorted(all_ips)}")


if __name__ == "__main__":
    main()
