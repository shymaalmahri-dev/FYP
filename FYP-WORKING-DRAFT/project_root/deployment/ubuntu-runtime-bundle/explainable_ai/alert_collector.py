import json
import os
from datetime import datetime

ALERT_FILE = os.path.join(os.path.dirname(__file__), "alerts", "alerts_log.json")

def ensure_file():
    """Ensure alerts file exists."""
    if not os.path.exists(ALERT_FILE):
        print("[AlertCollector] Creating alerts_log.json")
        with open(ALERT_FILE, "w") as f:
            json.dump([], f)

def load_alerts():
    ensure_file()
    with open(ALERT_FILE, "r") as f:
        return json.load(f)

def save_alert(alert):
    """
    Append new alert to alerts_log.json
    """
    try:
        alerts = load_alerts()

        alerts.append(alert)

        with open(ALERT_FILE, "w") as f:
            json.dump(alerts, f, indent=4)

        print(f"[AlertCollector] Alert stored successfully. Total alerts: {len(alerts)}")

    except Exception as e:
        print("[AlertCollector] ERROR saving alert:", e)


def create_alert(attacker_ip, attack_type, features, destination_ip=None):
    """
    Build structured alert dictionary
    """

    alert = {
        "timestamp": datetime.utcnow().isoformat(),
        "attacker_ip": attacker_ip,
        "attack_type": attack_type,
        "destination_ip": destination_ip,
        "features": features
    }

    return alert