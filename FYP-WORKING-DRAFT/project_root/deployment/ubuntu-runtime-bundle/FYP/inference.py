from pathlib import Path
import json
import math
import os
import socket
import sys
import time
import urllib.error
import urllib.request
import warnings

import joblib
import pandas as pd
from scapy.all import IP, TCP, UDP, ICMP, sniff, get_if_list, get_if_addr

# --- CONNECT EXPLAINABILITY SYSTEM ---
BASE_DIR = Path(__file__).resolve().parent
EXPLAINABLE_AI_DIR = BASE_DIR.parent / "explainable_ai"
sys.path.append(str(EXPLAINABLE_AI_DIR))

from alert_collector import create_alert, save_alert

try:
    from shap_analyzer import explain_prediction
except Exception as e:
    print(f"[Inference] WARNING: failed to import SHAP explainability module: {e}")
    explain_prediction = None

try:
    from incident_generator import build_prompt, generate_report
except Exception as e:
    print(f"[Inference] WARNING: failed to import LLM incident generator: {e}")
    build_prompt = None
    generate_report = None

warnings.filterwarnings("ignore", category=UserWarning)

DASHBOARD_ALERT_URL = os.environ.get(
    "DASHBOARD_ALERT_URL",
    "http://localhost:4000/api/alerts"
)

SEVERITY_MAP = {
    "SQL_Injection": "critical",
    "Directory_Traversal": "critical",
    "Command_Injection": "critical",
    "XSS_Injection": "critical",
}

PROTOCOL_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
}


def infer_severity(attack_type):
    return SEVERITY_MAP.get(attack_type, "high")


def normalize_protocol(protocol):
    if isinstance(protocol, int):
        return PROTOCOL_MAP.get(protocol, str(protocol))
    return protocol or "TCP"


def build_fallback_llm_explanation(attacker_ip, attack_type, features, shap_features):
    top_items = shap_features[:3] if shap_features else []
    feature_text = ", ".join(
        f"{item.get('name') or item.get('feature')} ({round(item.get('importance') or item.get('impact', 0), 3)})"
        for item in top_items
    )
    if feature_text:
        return (
            f"This packet was flagged as a {attack_type} attack from {attacker_ip}. "
            f"The model identified key indicators such as {feature_text}. "
            "These contributions suggest malicious protocol behavior and payload anomalies."
        )
    return (
        f"This packet was flagged as a {attack_type} attack from {attacker_ip}. "
        "Feature importance is not yet available, but the model marked this flow as suspicious."
    )


def build_llm_explanation(attacker_ip, attack_type, features, shap_features):
    if build_prompt is None or generate_report is None:
        return build_fallback_llm_explanation(attacker_ip, attack_type, features, shap_features)

    try:
        top_features = [
            {
                "feature": item.get("name") or item.get("feature"),
                "impact": item.get("importance") or item.get("impact", 0),
            }
            for item in (shap_features or [])
            if item.get("name") or item.get("feature")
        ]

        if not top_features:
            return build_fallback_llm_explanation(attacker_ip, attack_type, features, shap_features)

        print(f"[Inference] Building LLM explanation with {len(top_features)} features: {[f['feature'] for f in top_features]}")
        prompt = build_prompt(attack_type, attacker_ip, top_features)

        print("[Inference] Calling Ollama to generate incident report...")
        explanation = generate_report(prompt)

        if explanation and isinstance(explanation, str) and explanation.strip():
            print(f"[Inference] LLM explanation generated ({len(explanation)} chars)")
            return explanation.strip()

        print("[Inference] LLM returned empty response, using fallback")
        return build_fallback_llm_explanation(attacker_ip, attack_type, features, shap_features)
    except Exception as e:
        print("[Inference] LLM explanation failed:", e)
        return build_fallback_llm_explanation(attacker_ip, attack_type, features, shap_features)


def build_shap_explanation(features):
    if not features:
        return None

    if explain_prediction is None:
        print("[Inference] SHAP explainability module not available; skipping SHAP output.")
        return None

    try:
        top_features = explain_prediction(features)
        if not top_features:
            print("[Inference] SHAP explanation returned no top features.")
            return None

        print(f"[Inference] SHAP explanation built with {len(top_features)} features.")

        return {
            "baseValue": 0.5,
            "prediction": 0.95,
            "features": [
                {
                    "name": item.get("feature") or item.get("name"),
                    "importance": abs(float(item.get("impact") or item.get("importance") or 0)),
                    "value": str(features.get(item.get("feature") or item.get("name"), "")),
                }
                for item in top_features
            ],
        }
    except Exception as e:
        print("[Inference] SHAP explanation failed:", e)
        return None


def build_dashboard_alert(alert):
    features = alert.get("features", {}) or {}
    protocol = normalize_protocol(features.get("ip_proto"))
    destination_ip = alert.get("destination_ip") or alert.get("destinationIp") or "unknown"
    shap_values = build_shap_explanation(features)

    description = (
        f"Suspicious packet detected from {alert.get('attacker_ip')} to {destination_ip}. "
        f"The model classified this event as a {alert.get('attack_type')} attack."
    )

    llm_explanation = build_llm_explanation(
        alert.get("attacker_ip"),
        alert.get("attack_type"),
        features,
        shap_values.get("features") if shap_values else [],
    )

    return {
        "timestamp": alert.get("timestamp"),
        "severity": infer_severity(alert.get("attack_type")),
        "threatType": alert.get("attack_type"),
        "sourceIp": alert.get("attacker_ip"),
        "destinationIp": destination_ip,
        "protocol": protocol,
        "port": int(features.get("dport", 0)) if features.get("dport") else None,
        "description": description,
        "modelConfidence": "95",
        "isBlocked": 0,
        "shapeExplanation": json.dumps(shap_values) if shap_values else None,
        "llmExplanation": llm_explanation,
    }


def post_alert_to_dashboard(alert):
    dashboard_alert = build_dashboard_alert(alert)
    payload = json.dumps(dashboard_alert).encode("utf-8")
    request = urllib.request.Request(
        DASHBOARD_ALERT_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            status = response.getcode()
            if 200 <= status < 300:
                print("[Inference] Sent alert to dashboard API")
            else:
                print(
                    f"[Inference] Dashboard API responded with status {status}: {response.read().decode('utf-8', errors='ignore')}"
                )
    except urllib.error.URLError as err:
        print(f"[Inference] Failed to post alert to dashboard: {err}")


print("[*] Booting up ELAI Smart Multilayer Intrusion Prevention System...")


def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        ip_addr = sock.getsockname()[0]
    except Exception:
        ip_addr = "127.0.0.1"
    finally:
        sock.close()
    return ip_addr


LOCAL_VM_IP = get_local_ip()
print(f"[*] Protected VM IP Address: {LOCAL_VM_IP}")

# 1. LOAD THE ML ARTIFACTS
ARTIFACT_DIR = "edge_ai_artifacts"

try:
    model = joblib.load(os.path.join(ARTIFACT_DIR, "rf_model.joblib"))
    scaler = joblib.load(os.path.join(ARTIFACT_DIR, "scaler.joblib"))
    label_encoder = joblib.load(os.path.join(ARTIFACT_DIR, "label_encoder.joblib"))
    expected_features = joblib.load(os.path.join(ARTIFACT_DIR, "feature_columns.joblib"))

    print(f"[*] Success: Loaded Layer 1 Micro-Model with {len(expected_features)} features.")
except Exception as e:
    print(f"[!] Error loading artifacts: {e}. Check if files are in {ARTIFACT_DIR}")
    exit(1)

# --- LIVE STATE TRACKERS ---
ip_history = {}
port_history = {}
byte_history = {}
layer3_state = {}


def clean_old_state(current_time, window_size=1.5):
    for ip in list(ip_history.keys()):
        ip_history[ip] = [t for t in ip_history[ip] if current_time - t <= window_size]
        if not ip_history[ip]:
            del ip_history[ip]

    for ip in list(port_history.keys()):
        port_history[ip] = {t: p for t, p in port_history[ip].items() if current_time - t <= window_size}
        if not port_history[ip]:
            del port_history[ip]

    for ip in list(byte_history.keys()):
        byte_history[ip] = {t: b for t, b in byte_history[ip].items() if current_time - t <= window_size}
        if not byte_history[ip]:
            del byte_history[ip]


def calculate_entropy(port_list):
    if not port_list:
        return 0.0

    port_counts = {}
    for port in port_list:
        port_counts[port] = port_counts.get(port, 0) + 1

    entropy = 0.0
    for count in port_counts.values():
        prob = count / len(port_list)
        entropy -= prob * math.log2(prob)
    return entropy


def extract_live_features(packet):
    if IP not in packet:
        return None

    src_ip = packet[IP].src
    current_time = time.time()
    pkt_length = len(packet)
    clean_old_state(current_time)

    if src_ip not in ip_history:
        ip_history[src_ip] = []
    if src_ip not in byte_history:
        byte_history[src_ip] = {}

    ip_history[src_ip].append(current_time)
    byte_history[src_ip][current_time] = pkt_length

    iat = 0.0
    if len(ip_history[src_ip]) > 1:
        iat = ip_history[src_ip][-1] - ip_history[src_ip][-2]

    raw_features = {
        "pkt_len": pkt_length,
        "ip_proto": packet[IP].proto,
        "ip_ttl": packet[IP].ttl,
        "is_icmp": 1 if ICMP in packet else 0,
        "tcp_flags": 0,
        "is_syn": 0,
        "is_ack": 0,
        "is_rst": 0,
        "is_fin": 0,
        "is_psh": 0,
        "is_urg": 0,
        "is_ece": 0,
        "is_cwr": 0,
        "tcp_win": 0,
        "payload_len": 0,
        "dport": 0,
        "is_well_known_port": 0,
        "is_modbus": 0,
        "is_mqtt": 0,
        "is_http": 0,
        "is_dns": 0,
        "iat": iat,
        "pkt_rate": len(ip_history[src_ip]),
        "byte_rate": sum(byte_history[src_ip].values()),
        "unique_ports_hit": 0,
        "port_entropy": 0.0,
    }

    if TCP in packet or UDP in packet:
        if TCP in packet:
            flags = packet[TCP].flags
            raw_features["tcp_flags"] = int(flags)
            raw_features["is_syn"] = 1 if "S" in flags else 0
            raw_features["is_ack"] = 1 if "A" in flags else 0
            raw_features["is_rst"] = 1 if "R" in flags else 0
            raw_features["is_fin"] = 1 if "F" in flags else 0
            raw_features["is_psh"] = 1 if "P" in flags else 0
            raw_features["is_urg"] = 1 if "U" in flags else 0
            raw_features["is_ece"] = 1 if "E" in flags else 0
            raw_features["is_cwr"] = 1 if "C" in flags else 0
            raw_features["tcp_win"] = packet[TCP].window
            raw_features["payload_len"] = len(packet[TCP].payload)
            raw_features["dport"] = packet[TCP].dport
        elif UDP in packet:
            raw_features["payload_len"] = len(packet[UDP].payload)
            raw_features["dport"] = packet[UDP].dport

        raw_features["is_well_known_port"] = 1 if raw_features["dport"] < 1024 else 0
        raw_features["is_modbus"] = 1 if raw_features["dport"] == 502 else 0
        raw_features["is_mqtt"] = 1 if raw_features["dport"] == 1883 else 0
        raw_features["is_http"] = 1 if raw_features["dport"] in [80, 443, 8080] else 0
        raw_features["is_dns"] = 1 if raw_features["dport"] == 53 else 0

        if src_ip not in port_history:
            port_history[src_ip] = {}
        port_history[src_ip][current_time] = raw_features["dport"]

        recent_ports = list(port_history[src_ip].values())
        raw_features["unique_ports_hit"] = len(set(recent_ports))
        raw_features["port_entropy"] = calculate_entropy(recent_ports)

    features = {col: 0 for col in expected_features}
    for col in expected_features:
        if col in raw_features:
            features[col] = raw_features[col]

    df_live = pd.DataFrame([features])
    return df_live[expected_features]


def layer_2_dpi(packet):
    if packet.haslayer(TCP) and len(packet[TCP].payload) > 0:
        payload = bytes(packet[TCP].payload).decode("utf-8", errors="ignore").lower()
        if "select" in payload and "from" in payload:
            return "SQL_Injection"
        if "union all" in payload or "1=1" in payload:
            return "SQL_Injection"
        if "cat /etc/passwd" in payload:
            return "Directory_Traversal"
        if "wget " in payload or "curl " in payload:
            return "Command_Injection"
        if "<script>" in payload:
            return "XSS_Injection"
    return "Clean"


def layer_3_behavior(src_ip, dst_port, current_time):
    if src_ip not in layer3_state:
        layer3_state[src_ip] = {"times": [], "ports": set()}

    layer3_state[src_ip]["times"].append(current_time)
    layer3_state[src_ip]["ports"].add(dst_port)
    layer3_state[src_ip]["times"] = [
        t for t in layer3_state[src_ip]["times"] if current_time - t <= 15.0
    ]

    if dst_port > 1024:
        return "Clean"

    connection_count = len(layer3_state[src_ip]["times"])
    unique_ports = len(layer3_state[src_ip]["ports"])

    if unique_ports > 10:
        return "Stealth_Horizontal_Port_Scan"

    if connection_count > 25 and unique_ports <= 3:
        recent_bytes = sum(byte_history.get(src_ip, {}).values())
        if recent_bytes < 8192:
            return f"Brute_Force_Attempt_on_Port_{dst_port}"

    return "Clean"


def emit_alert(attacker_ip, attack_type, features, destination_ip, layer_name):
    print(f"\n[{layer_name}] Alert: {attack_type} from {attacker_ip}")
    alert = create_alert(
        attacker_ip=attacker_ip,
        attack_type=attack_type,
        features=features or {},
        destination_ip=destination_ip,
    )
    save_alert(alert)
    post_alert_to_dashboard(alert)
    return alert


def choose_detection_result(layer_1_prediction, layer_2_prediction, layer_3_prediction):
    """
    Priority order:
    1. Layer 2 payload signatures
    2. Layer 3 behavior signatures
    3. Layer 1 ML prediction
    """
    if layer_2_prediction != "Clean":
        return ("LAYER 2 DPI", layer_2_prediction)

    if layer_3_prediction != "Clean":
        return ("LAYER 3 BEHAVIOR", layer_3_prediction)

    if layer_1_prediction != "Normal":
        return ("LAYER 1 ML", layer_1_prediction)

    return (None, None)


def analyze_packet(packet):
    try:
        if not packet.haslayer(IP):
            return

        attacker_ip = packet[IP].src
        dst_ip = packet[IP].dst
        current_time = time.time()

        if attacker_ip == LOCAL_VM_IP:
            return

        dst_port = 0
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport

        live_data = extract_live_features(packet)
        if live_data is None:
            return

        live_data_scaled = scaler.transform(live_data)
        prediction_num = model.predict(live_data_scaled)[0]
        layer_1_prediction = label_encoder.inverse_transform([prediction_num])[0]
        feature_dict = live_data.iloc[0].to_dict()

        layer_2_prediction = layer_2_dpi(packet)
        layer_3_prediction = layer_3_behavior(attacker_ip, dst_port, current_time)

        triggered_layers = []
        if layer_1_prediction != "Normal":
            triggered_layers.append(f"L1={layer_1_prediction}")
        if layer_2_prediction != "Clean":
            triggered_layers.append(f"L2={layer_2_prediction}")
        if layer_3_prediction != "Clean":
            triggered_layers.append(f"L3={layer_3_prediction}")

        if triggered_layers:
            print(f"[Inference] Triggered layers for {attacker_ip}: {', '.join(triggered_layers)}")

        selected_layer, selected_attack = choose_detection_result(
            layer_1_prediction,
            layer_2_prediction,
            layer_3_prediction,
        )

        if selected_attack is not None:
            emit_alert(
                attacker_ip=attacker_ip,
                attack_type=selected_attack,
                features=feature_dict,
                destination_ip=dst_ip,
                layer_name=selected_layer,
            )

            if selected_layer == "LAYER 3 BEHAVIOR":
                layer3_state[attacker_ip] = {"times": [], "ports": set()}
            return

    except Exception:
        pass


IFACE_NAME = None
for iface in get_if_list():
    try:
        if get_if_addr(iface) == LOCAL_VM_IP:
            IFACE_NAME = iface
            break
    except Exception:
        continue

if IFACE_NAME is None:
    print("[!] Could not find a network interface matching the local VM IP.")
    exit(1)

print(f"[*] Sniffing on interface: {IFACE_NAME}. Multi-Layer Defense Active.")

try:
    sniff(
        iface=IFACE_NAME,
        filter="not port 22 and not icmp",
        prn=analyze_packet,
        store=False,
    )
except KeyboardInterrupt:
    print("\n[*] Shutting down IDS...")
