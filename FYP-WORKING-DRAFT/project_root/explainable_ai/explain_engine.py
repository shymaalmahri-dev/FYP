import json
import os
from shap_analyzer import explain_prediction

print("[ExplainEngine] Starting explanation engine...")

BASE_DIR = os.path.dirname(__file__)

ALERT_FILE = os.path.join(BASE_DIR, "alerts", "alerts_log.json")
REPORT_FILE = os.path.join(BASE_DIR, "reports", "explanations.json")

def load_json(path):

    if not os.path.exists(path):
        return []

    with open(path, "r") as f:
        return json.load(f)

def save_json(path, data):

    with open(path, "w") as f:
        json.dump(data, f, indent=4)

def process_alerts():

    print("[ExplainEngine] Loading alerts...")

    alerts = load_json(ALERT_FILE)
    reports = load_json(REPORT_FILE)

    processed = len(reports)

    print(f"[ExplainEngine] Alerts found: {len(alerts)}")
    print(f"[ExplainEngine] Already explained: {processed}")

    new_alerts = alerts[processed:]

    if not new_alerts:
        print("[ExplainEngine] No new alerts to explain.")
        return

    for alert in new_alerts:

        attack_type = alert["attack_type"]
        attacker_ip = alert["attacker_ip"]
        features = alert["features"]

        print(f"\n[ExplainEngine] Explaining attack from {attacker_ip}")

        if not features:
            explanation = []
        else:
            explanation = explain_prediction(features)

        report = {
            "timestamp": alert["timestamp"],
            "attacker_ip": attacker_ip,
            "attack_type": attack_type,
            "top_features": explanation
        }

        reports.append(report)

    save_json(REPORT_FILE, reports)

    print(f"[ExplainEngine] Saved {len(new_alerts)} explanations.")

if __name__ == "__main__":

    print("[ExplainEngine] Running explanation pipeline...")
    process_alerts()