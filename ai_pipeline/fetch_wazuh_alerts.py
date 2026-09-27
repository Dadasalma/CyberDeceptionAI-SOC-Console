import json
import os
import shlex
import subprocess
import time
import sys
from datetime import datetime, timezone

WAZUH_HOST = os.environ.get("WAZUH_SSH_HOST", "analyst@192.0.2.30")
SSH_KEY = os.path.expanduser(os.environ.get("WAZUH_SSH_KEY", "~/.ssh/id_ed25519_wazuh"))
WAZUH_USER = os.environ.get("WAZUH_USER", "admin")
WAZUH_PASS = os.environ.get("WAZUH_PASSWORD", "")
WAZUH_OPENSEARCH_URL = os.environ.get("WAZUH_OPENSEARCH_URL", "https://localhost:9200")
STATE_FILE = os.environ.get("WAZUH_FETCH_STATE", "fetch_state.json")
OUTPUT_FILE = os.environ.get("WAZUH_OUTPUT_FILE", "dataset_ia_live.jsonl")
POLL_INTERVAL_SECONDS = int(os.environ.get("WAZUH_POLL_SECONDS", "5"))


def load_state():
    try:
        with open(STATE_FILE, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {"last_timestamp": None}


def save_state(state):
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(state, f)


def today_index():
    return "wazuh-alerts-4.x-" + datetime.now(timezone.utc).strftime("%Y.%m.%d")


def build_query(last_timestamp):
    decoder_filter = {"term": {"decoder.name": "json"}}
    if last_timestamp is None:
        return {
            "query": {"bool": {"filter": [decoder_filter]}},
            "sort": [{"@timestamp": "asc"}],
            "size": 0,
        }
    return {
        "query": {"bool": {"filter": [
            decoder_filter,
            {"range": {"@timestamp": {"gt": last_timestamp}}},
        ]}},
        "sort": [{"@timestamp": "asc"}],
        "size": 500,
    }


def fetch_new_alerts(last_timestamp):
    if not WAZUH_PASS:
        print("[fetch_wazuh_alerts] WAZUH_PASSWORD is not set; collector is disabled.")
        return [], last_timestamp

    index = today_index()
    query_json = json.dumps(build_query(last_timestamp))

    # Executes curl on the Wazuh host through SSH. Credentials and lab endpoints
    # are supplied through environment variables in the public version.
    remote_cmd = (
        f"curl -sk -u {shlex.quote(WAZUH_USER + ':' + WAZUH_PASS)} "
        f"-H 'Content-Type: application/json' "
        f"-d {shlex.quote(query_json)} "
        f"{shlex.quote(WAZUH_OPENSEARCH_URL + '/' + index + '/_search')}"
    )
    ssh_cmd = ["ssh", "-i", SSH_KEY, WAZUH_HOST, remote_cmd]

    try:
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        print("[fetch_wazuh_alerts] SSH/curl request timed out.")
        return [], last_timestamp

    if result.returncode != 0:
        print(f"[fetch_wazuh_alerts] SSH error ({result.returncode}): {result.stderr[:300]}")
        return [], last_timestamp

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        print(f"[fetch_wazuh_alerts] Non-JSON response: {result.stdout[:300]}")
        return [], last_timestamp

    if "error" in data:
        print(f"[fetch_wazuh_alerts] OpenSearch error: {json.dumps(data['error'])[:300]}")
        return [], last_timestamp

    hits = data.get("hits", {}).get("hits", [])
    if not hits:
        return [], last_timestamp

    new_alerts = [h["_source"] for h in hits]
    newest_timestamp = hits[-1]["_source"].get("@timestamp", last_timestamp)
    return new_alerts, newest_timestamp


def append_alerts(alerts):
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(alert) + "\n")


def main():
    print("=" * 70)
    print("fetch_wazuh_alerts.py - Wazuh -> AI pipeline bridge")
    print(f"Polling every {POLL_INTERVAL_SECONDS}s on {today_index()}")
    print("=" * 70)

    state = load_state()
    last_timestamp = state.get("last_timestamp")
    if last_timestamp is None:
        last_timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        save_state({"last_timestamp": last_timestamp})
        print(f"Initial cursor: {last_timestamp}")

    try:
        while True:
            new_alerts, newest_timestamp = fetch_new_alerts(last_timestamp)
            if new_alerts:
                append_alerts(new_alerts)
                last_timestamp = newest_timestamp
                save_state({"last_timestamp": last_timestamp})
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Added {len(new_alerts)} alert(s) to {OUTPUT_FILE}")
            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\nCollector stopped. Cursor saved.")
        sys.exit(0)


if __name__ == "__main__":
    main()
