import os
import subprocess
from datetime import datetime

CONPOT_HOST = os.environ.get("CONPOT_SSH_HOST", "analyst@192.0.2.20")
SSH_KEY = os.path.expanduser(os.environ.get("CONPOT_SSH_KEY", "~/.ssh/id_ed25519_conpot"))
CONPOT_DIR = os.environ.get("CONPOT_DIR", "/opt/conpot")
ENABLE_REMOTE_ACTIONS = os.environ.get("ENABLE_REMOTE_ACTIONS", "0") == "1"

RISK_LEVELS = {
    "SURICATA STREAM 3way handshake excessive different SYNs": "ELEVE",
    "SURICATA STREAM 3way handshake SYN resend different seq on SYN recv": "ELEVE",
    "SURICATA STREAM Packet with invalid timestamp": "MOYEN",
    "SURICATA Applayer Detect protocol only one direction": "MOYEN",
    "ET INFO Possible Kali Linux hostname in DHCP Request Packet": "MOYEN",
    "SURICATA ICMPv4 unknown code": "FAIBLE",
    "SURICATA HTTP unable to match response to request": "FAIBLE",
}

ACTIONS = {
    "ELEVE": "Escalate to high-risk handling + analyst alert",
    "MOYEN": "Increase monitoring for the source",
    "FAIBLE": "Log only",
}

DEFENSE_PROFILE = {
    "SURICATA STREAM 3way handshake excessive different SYNs": "IEC104",
    "SURICATA STREAM 3way handshake SYN resend different seq on SYN recv": "IEC104",
}

CURRENT_PROFILE = "default"


def log_action(logfile, entry):
    with open(logfile, "a", encoding="utf-8") as f:
        f.write(entry + "\n")


def classify_risk(pred_label):
    return RISK_LEVELS.get(pred_label, "INCONNU")


def get_action(risk):
    return ACTIONS.get(risk, "No action defined for unknown signature")


def deploy_profile(profile_name, logfile, pred_label, risk):
    """Optionally switch a Conpot profile.

    Remote actions are disabled by default in the public repository. Set
    ENABLE_REMOTE_ACTIONS=1 only in an isolated lab that you own/control.
    """
    global CURRENT_PROFILE
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if CURRENT_PROFILE == profile_name:
        log_action(logfile, f"[{timestamp}] DEPLOY_PROFILE={profile_name} | STATUS=SKIPPED_ALREADY_ACTIVE")
        return

    if not ENABLE_REMOTE_ACTIONS:
        print(f"[DRY RUN] Would deploy Conpot profile: {profile_name}")
        log_action(logfile, f"[{timestamp}] DEPLOY_PROFILE={profile_name} | STATUS=DRY_RUN")
        return

    cmd = (
        f"cd {CONPOT_DIR} && "
        "docker compose down && "
        f"CONPOT_TEMPLATE={profile_name} docker compose up -d"
    )
    ssh_cmd = ["ssh", "-i", SSH_KEY, CONPOT_HOST, cmd]

    try:
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            CURRENT_PROFILE = profile_name
            log_action(logfile, f"[{timestamp}] DEPLOY_PROFILE={profile_name} | STATUS=SUCCESS")
        else:
            log_action(logfile, f"[{timestamp}] DEPLOY_PROFILE={profile_name} | STATUS=FAILED")
    except subprocess.TimeoutExpired:
        log_action(logfile, f"[{timestamp}] DEPLOY_PROFILE={profile_name} | STATUS=TIMEOUT")


def handle_prediction(pred_label, src_ip, confidence, logfile="actions_log.txt"):
    risk = classify_risk(pred_label)
    action = get_action(risk)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"[{timestamp}] Source IP: {src_ip}")
    print(f"    Prediction : {pred_label}")
    print(f"    Confidence : {confidence:.2%}")
    print(f"    Risk       : {risk}")
    print(f"    Action     : {action}")

    if risk == "ELEVE":
        target_profile = DEFENSE_PROFILE.get(pred_label)
        if target_profile:
            deploy_profile(target_profile, logfile, pred_label, risk)

    log_entry = (
        f"[{timestamp}] IP={src_ip} | Prediction={pred_label} | "
        f"Confidence={confidence:.2%} | Risk={risk} | Action={action}"
    )
    log_action(logfile, log_entry)
    return risk, action
