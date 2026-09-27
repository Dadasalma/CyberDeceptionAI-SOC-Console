import json
import os
import pickle
import time
from datetime import datetime
import pandas as pd

from fetch_wazuh_alerts import fetch_new_alerts, load_state, save_state, OUTPUT_FILE
from session_tracker_gap10 import load_alerts as load_alerts_for_sessions, build_sessions, make_json_serializable
import decision_engine

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
POLL_INTERVAL_SECONDS = int(os.environ.get("PIPELINE_POLL_SECONDS", "5"))
MODEL_PATH = os.environ.get("MODEL_PATH", os.path.join(BASE_DIR, "models", "model_extended.pkl"))
SESSIONS_OUTPUT = os.environ.get("SESSIONS_OUTPUT", os.path.join(BASE_DIR, "sessions_live.jsonl"))
LIVE_LOGFILE = os.environ.get("ACTIONS_LOG", os.path.join(BASE_DIR, "actions_log_live.txt"))


def safe_get(d, path, default=None):
    cur = d
    for key in path.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return default
    return cur


def build_feature_vector(alert, model_bundle):
    feature_cols = model_bundle["feature_cols"]
    num_cols = model_bundle["num_cols"]
    cat_cols = model_bundle["cat_cols"]

    record = {
        "severity": safe_get(alert, "data.alert.severity", "0"),
        "proto": safe_get(alert, "data.proto", "UNKNOWN"),
        "dest_port": safe_get(alert, "data.dest_port", "0"),
        "src_port": safe_get(alert, "data.src_port", "0"),
        "action": safe_get(alert, "data.alert.action", "unknown"),
        "category": safe_get(alert, "data.alert.category", "unknown"),
        "pkts_toserver": safe_get(alert, "data.flow.pkts_toserver", "0"),
        "pkts_toclient": safe_get(alert, "data.flow.pkts_toclient", "0"),
        "bytes_toserver": safe_get(alert, "data.flow.bytes_toserver", "0"),
        "bytes_toclient": safe_get(alert, "data.flow.bytes_toclient", "0"),
        "direction": safe_get(alert, "data.direction", "unknown"),
        "rule_level": safe_get(alert, "rule.level", 0),
    }
    df = pd.DataFrame([record])
    for col in num_cols:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)
    df_encoded = pd.get_dummies(df, columns=cat_cols)

    # Alignement strict sur les colonnes vues a l'entrainement
    df_aligned = df_encoded.reindex(columns=feature_cols, fill_value=0)
    return df_aligned


def process_new_alert(alert, model_bundle):
    model = model_bundle["model"]
    le = model_bundle["label_encoder"]

    X = build_feature_vector(alert, model_bundle)
    pred_encoded = model.predict(X)[0]
    pred_label = le.inverse_transform([pred_encoded])[0]
    confidence = model.predict_proba(X)[0].max()
    src_ip = safe_get(alert, "data.src_ip", "unknown")

    decision_engine.handle_prediction(pred_label, src_ip, confidence, logfile=LIVE_LOGFILE)


def rebuild_sessions():
    try:
        alerts = load_alerts_for_sessions(OUTPUT_FILE)
    except FileNotFoundError:
        return
    if not alerts:
        return
    sessions = build_sessions(alerts)
    sessions = make_json_serializable(sessions)
    with open(SESSIONS_OUTPUT, "w") as f:
        for s in sessions:
            f.write(json.dumps(s) + "\n")


def main():
    print("=" * 70)
    print("run_pipeline.py - AI-Driven Adaptive Cyber Deception - Pipeline live")
    print(f"Cycle : fetch -> sessions -> features -> prediction -> decision engine")
    print(f"Intervalle de polling : {POLL_INTERVAL_SECONDS}s")
    print("=" * 70)

    print(f"\nLoading model bundle: {MODEL_PATH}")
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError("Model bundle not found. Train/export it with module2_classification.py or set MODEL_PATH.")
    with open(MODEL_PATH, "rb") as f:
        model_bundle = pickle.load(f)
    print(f"Model loaded. Known classes: {list(model_bundle['label_encoder'].classes_)}")

    state = load_state()
    last_timestamp = state.get("last_timestamp")
    if last_timestamp is None:
        last_timestamp = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
        save_state({"last_timestamp": last_timestamp})
        print(f"Curseur initial : {last_timestamp}")

    print("\nEn attente d'attaques... (Ctrl+C pour arreter)\n")

    try:
        while True:
            new_alerts, newest_timestamp = fetch_new_alerts(last_timestamp)

            if new_alerts:
                with open(OUTPUT_FILE, "a") as f:
                    for alert in new_alerts:
                        f.write(json.dumps(alert) + "\n")
                last_timestamp = newest_timestamp
                save_state({"last_timestamp": last_timestamp})

                print(f"[{datetime.now().strftime('%H:%M:%S')}] {len(new_alerts)} nouvelle(s) alerte(s) recue(s)")

                rebuild_sessions()

                for alert in new_alerts:
                    process_new_alert(alert, model_bundle)

                print("-" * 70)

            time.sleep(POLL_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        print("\nArret demande (Ctrl+C). Pipeline arrete proprement.")


if __name__ == "__main__":
    main()
