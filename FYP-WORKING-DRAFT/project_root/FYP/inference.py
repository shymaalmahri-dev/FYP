"""
ELAI — Edge Layered AI

This script implements the working Ubuntu/Kali lab inference pipeline:
- live packet sniffing
- ML + DPI + behavior detection
- SHAP explanation generation
- LLM / fallback incident explanation
- alert posting to the dashboard API

The current implementation stays detection-oriented. Blocking / prevention is
not performed here, but the packet filters and logging hooks make it easier to
integrate with a stronger edge deployment later.
"""
from pathlib import Path
import json
import logging
import math
import os
import random
import socket
import sys
import time
import urllib.error
import urllib.request
import warnings
import ipaddress

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

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("elai")

ALERT_LOG_PATH = BASE_DIR / "alerts.log"
SUSPICIOUS_LOG_PATH = BASE_DIR / "suspicious.log"


def append_line(path: Path, line: str) -> None:
    try:
        with path.open("a", encoding="utf-8") as file_handle:
            file_handle.write(line + "\n")
    except Exception:
        logger.exception("Failed to append to %s", path)


DASHBOARD_ALERT_URL = os.environ.get(
    "DASHBOARD_ALERT_URL",
    "http://localhost:4000/api/alerts"
)
EDGE_BLOCK_AGENT_URL = os.environ.get("EDGE_BLOCK_AGENT_URL", "").strip()
EDGE_BLOCK_AGENT_TOKEN = os.environ.get("EDGE_BLOCK_AGENT_TOKEN", "").strip()
EDGE_DEVICE_NAME = os.environ.get("EDGE_DEVICE_NAME", socket.gethostname())
LAYER2_FIRST = os.environ.get("ELAI_LAYER2_FIRST", "0").strip().lower() in ("1", "true", "yes")
MONITOR_DST_IP = os.environ.get("ELAI_MONITOR_DST_IP", "").strip()
MONITOR_SRC_SUBNET = os.environ.get("ELAI_MONITOR_SRC_SUBNET", "").strip()
NORMAL_CONFIDENCE_STRONG = float(os.environ.get("ELAI_NORMAL_MIN_PROBA", "0.85"))
ATTACK_CONFIDENCE_STRONG = float(os.environ.get("ELAI_ATTACK_STRONG_PROBA", "0.90"))
GRAY_ZONE_MIN_CONFIDENCE = float(os.environ.get("ELAI_GRAY_MIN_PROBA", "0.60"))
GRAY_ZONE_ENABLED = os.environ.get("ELAI_GRAY_ZONE_ENABLED", "1").strip().lower() in ("1", "true", "yes")
NORMAL_SAMPLE_RATE = float(os.environ.get("ELAI_NORMAL_SAMPLE_RATE", "0.20"))
EVENT_COOLDOWN_SEC = float(os.environ.get("ELAI_ALERT_COOLDOWN_SEC", "5"))
SOFT_NORMAL_MIN_CONFIDENCE = float(os.environ.get("ELAI_SOFT_NORMAL_MIN_PROBA", "0.45"))
SOFT_NORMAL_MAX_GAP = float(os.environ.get("ELAI_SOFT_NORMAL_MAX_GAP", "0.12"))
IGNORE_SRC_IPS = {
    value.strip()
    for value in os.environ.get("ELAI_IGNORE_SRC_IPS", "").split(",")
    if value.strip()
}
ALLOW_SRC_IPS = {
    value.strip()
    for value in os.environ.get("ELAI_ALLOW_SRC_IPS", "").split(",")
    if value.strip()
}

SRC_SUBNET_OBJ = None
if MONITOR_SRC_SUBNET:
    try:
        SRC_SUBNET_OBJ = ipaddress.ip_network(MONITOR_SRC_SUBNET, strict=False)
    except ValueError:
        logger.warning("Invalid ELAI_MONITOR_SRC_SUBNET=%s (ignored)", MONITOR_SRC_SUBNET)
        SRC_SUBNET_OBJ = None

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

FEATURE_LABELS = {
    "pkt_len": "Packet Length",
    "ip_proto": "IP Protocol",
    "ip_ttl": "IP TTL",
    "tcp_flags": "TCP Flags",
    "is_syn": "SYN Flag",
    "is_ack": "ACK Flag",
    "is_rst": "RST Flag",
    "is_fin": "FIN Flag",
    "is_psh": "PSH Flag",
    "tcp_win": "TCP Window",
    "payload_len": "Payload Length",
    "dport": "Destination Port",
    "iat": "Inter-arrival Time",
    "pkt_rate": "Packet Rate",
    "byte_rate": "Byte Rate",
    "unique_ports_hit": "Unique Ports Hit",
    "port_entropy": "Port Entropy",
    "is_http": "HTTP Port Hit",
    "is_dns": "DNS Port Hit",
    "is_well_known_port": "Well-known Port",
}

last_event_state = {}


def infer_severity(attack_type):
    return SEVERITY_MAP.get(attack_type, "high")


def normalize_protocol(protocol):
    if isinstance(protocol, int):
        return PROTOCOL_MAP.get(protocol, str(protocol))
    return protocol or "TCP"


def round_probability(value):
    return round(float(value) * 100, 2)


def build_normal_explanation(attacker_ip, destination_ip, prediction_details):
    primary = prediction_details.get("primary_prediction", "Normal")
    secondary = prediction_details.get("secondary_prediction", "unknown")
    return (
        f"Traffic from {attacker_ip} to {destination_ip} matched the model's normal profile. "
        f"Primary class: {primary}. Confidence: {prediction_details.get('primary_confidence', 0):.2f}%."
        f"{' The nearest competing class was ' + secondary + '.' if secondary and secondary != 'None' else ''}"
    )


def build_gray_zone_explanation(attacker_ip, destination_ip, prediction_details):
    primary = prediction_details.get("primary_prediction", "unknown")
    secondary = prediction_details.get("secondary_prediction", "unknown")
    primary_confidence = round_probability(prediction_details.get("primary_probability", 0))
    secondary_confidence = round_probability(prediction_details.get("secondary_probability", 0))
    confidence_gap = round_probability(prediction_details.get("confidence_gap", 0))
    return (
        f"Traffic from {attacker_ip} to {destination_ip} landed in the gray zone. "
        f"The model is leaning toward {primary} ({primary_confidence:.2f}%) with {secondary} "
        f"as the next closest class ({secondary_confidence:.2f}%). The confidence gap is only "
        f"{confidence_gap:.2f}%, so analyst review is recommended before containment."
    )


def should_emit_event(event_key, current_time):
    last_seen = last_event_state.get(event_key, 0.0)
    if current_time - last_seen < EVENT_COOLDOWN_SEC:
        return False
    last_event_state[event_key] = current_time
    return True


def block_ip_on_edge(ip_address, reason):
    if not EDGE_BLOCK_AGENT_URL:
        return {
            "isBlocked": 0,
            "blockStatus": "disabled",
            "blockMessage": "EDGE_BLOCK_AGENT_URL is not configured.",
        }

    payload = json.dumps({
        "ipAddress": ip_address,
        "reason": reason,
    }).encode("utf-8")
    request = urllib.request.Request(
        EDGE_BLOCK_AGENT_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            **({"Authorization": f"Bearer {EDGE_BLOCK_AGENT_TOKEN}"} if EDGE_BLOCK_AGENT_TOKEN else {}),
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(request, timeout=5) as response:
            body = json.loads(response.read().decode("utf-8", errors="ignore") or "{}")
            return {
                "isBlocked": 1 if body.get("success") else 0,
                "blockStatus": "blocked" if body.get("success") else "failed",
                "blockMessage": body.get("message") or "Edge block response received",
            }
    except urllib.error.URLError as err:
        return {
            "isBlocked": 0,
            "blockStatus": "failed",
            "blockMessage": f"Edge block failed: {err}",
        }


def get_prediction_details(live_data_scaled):
    probabilities = model.predict_proba(live_data_scaled)[0]
    classes = list(label_encoder.classes_)
    order = probabilities.argsort()[::-1]

    primary_index = int(order[0])
    primary_prediction = classes[primary_index]
    primary_probability = float(probabilities[primary_index])

    secondary_prediction = "None"
    secondary_probability = 0.0
    if len(order) > 1:
        secondary_index = int(order[1])
        secondary_prediction = classes[secondary_index]
        secondary_probability = float(probabilities[secondary_index])

    normal_probability = 0.0
    if "Normal" in classes:
        normal_probability = float(probabilities[classes.index("Normal")])

    return {
        "primary_prediction": primary_prediction,
        "primary_probability": primary_probability,
        "secondary_prediction": secondary_prediction,
        "secondary_probability": secondary_probability,
        "normal_probability": normal_probability,
        "confidence_gap": primary_probability - secondary_probability,
    }


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
        print("[Inference] SHAP explainability module not available; using heuristic feature ranking.")
        return build_heuristic_feature_explanation(features)

    try:
        top_features = explain_prediction(features)
        if not top_features:
            print("[Inference] SHAP explanation returned no top features; using heuristic feature ranking.")
            return build_heuristic_feature_explanation(features)

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
        return build_heuristic_feature_explanation(features)


def build_heuristic_feature_explanation(features):
    ranked = []

    for key, raw_value in (features or {}).items():
        if key not in FEATURE_LABELS:
            continue

        try:
            numeric_value = float(raw_value)
        except (TypeError, ValueError):
            continue

        if abs(numeric_value) <= 0:
            continue

        ranked.append((key, numeric_value))

    if not ranked:
        return None

    max_magnitude = max(abs(value) for _, value in ranked) or 1.0
    top_ranked = sorted(ranked, key=lambda item: abs(item[1]), reverse=True)[:5]

    return {
        "baseValue": 0.5,
        "prediction": 0.0,
        "features": [
            {
                "name": FEATURE_LABELS.get(name, name),
                "importance": round(abs(value) / max_magnitude, 4),
                "value": str(round(value, 4)),
            }
            for name, value in top_ranked
        ],
    }


def build_dashboard_alert(alert):
    features = alert.get("features", {}) or {}
    protocol = normalize_protocol(features.get("ip_proto"))
    destination_ip = alert.get("destination_ip") or alert.get("destinationIp") or "unknown"
    shap_values = build_shap_explanation(features)
    prediction_details = alert.get("prediction_details", {}) or {}
    event_category = alert.get("event_category", "malicious")
    primary_probability = round_probability(prediction_details.get("primary_probability", 0))

    if event_category == "normal":
        description = build_normal_explanation(
            alert.get("attacker_ip"),
            destination_ip,
            {
                "primary_confidence": round_probability(prediction_details.get("primary_probability", 0)),
            },
        )
        llm_explanation = "Sampled normal traffic retained for expert validation."
    elif event_category == "gray_zone":
        description = build_gray_zone_explanation(
            alert.get("attacker_ip"),
            destination_ip,
            prediction_details,
        )
        llm_explanation = (
            f"Gray-zone event. Primary prediction={prediction_details.get('primary_prediction', 'unknown')} "
            f"with confidence {primary_probability:.2f}%."
        )
    else:
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

    if shap_values:
        shap_values["prediction"] = prediction_details.get("primary_probability", 0)

    return {
        "timestamp": alert.get("timestamp"),
        "severity": alert.get("severity") or infer_severity(alert.get("attack_type")),
        "eventCategory": event_category,
        "threatType": alert.get("attack_type"),
        "sourceIp": alert.get("attacker_ip"),
        "destinationIp": destination_ip,
        "protocol": protocol,
        "port": int(features.get("dport", 0)) if features.get("dport") else None,
        "description": description,
        "modelConfidence": str(round_probability(prediction_details.get("primary_probability", 0))),
        "primaryPrediction": prediction_details.get("primary_prediction"),
        "secondaryPrediction": prediction_details.get("secondary_prediction"),
        "primaryConfidence": str(round_probability(prediction_details.get("primary_probability", 0))),
        "secondaryConfidence": str(round_probability(prediction_details.get("secondary_probability", 0))),
        "confidenceGap": str(round_probability(prediction_details.get("confidence_gap", 0))),
        "recommendedAction": alert.get("recommended_action"),
        "isBlocked": alert.get("isBlocked", 0),
        "blockStatus": alert.get("blockStatus", "not_requested"),
        "blockMessage": alert.get("blockMessage"),
        "blockUpdatedAt": alert.get("blockUpdatedAt"),
        "edgeDevice": alert.get("edge_device") or EDGE_DEVICE_NAME,
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
if LAYER2_FIRST:
    print("[*] Policy: Layer 2 DPI runs before Layer 1 ML for TCP payloads.")
if MONITOR_DST_IP:
    print(f"[*] Filter: monitor only packets destined to {MONITOR_DST_IP}")
if SRC_SUBNET_OBJ is not None:
    print(f"[*] Filter: monitor only source subnet {SRC_SUBNET_OBJ}")
if ALLOW_SRC_IPS:
    print(f"[*] Filter: allow source IPs only ({len(ALLOW_SRC_IPS)} entries)")
if IGNORE_SRC_IPS:
    print(f"[*] Filter: ignore source IPs ({len(IGNORE_SRC_IPS)} entries)")
print(f"[*] Alert log: {ALERT_LOG_PATH}")
print(f"[*] Suspicious log: {SUSPICIOUS_LOG_PATH}")


def get_local_ip():
    forced_ip = os.environ.get("PROTECTED_VM_IP") or os.environ.get("ELAI_PROTECTED_VM_IP")
    if forced_ip:
        return forced_ip

    # Prefer the VirtualBox host-only adapter used for the Ubuntu/Kali lab.
    preferred_prefixes = ("192.168.56.",)
    for iface in get_if_list():
        try:
            ip_addr = get_if_addr(iface)
        except Exception:
            continue

        if any(ip_addr.startswith(prefix) for prefix in preferred_prefixes):
            return ip_addr

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("10.255.255.255", 1))
        ip_addr = sock.getsockname()[0]
    except Exception:
        ip_addr = "127.0.0.1"
    finally:
        sock.close()
    return ip_addr


def resolve_capture_interface(local_vm_ip):
    forced_iface = os.environ.get("CAPTURE_INTERFACE") or os.environ.get("ELAI_IFACE")
    available_ifaces = list(get_if_list())

    if forced_iface:
        if forced_iface in available_ifaces:
            return forced_iface

        logger.warning(
            "Forced capture interface %s was not found in get_if_list(); using it anyway.",
            forced_iface,
        )
        return forced_iface

    # Match the exact interface address first.
    for iface in available_ifaces:
        try:
            if get_if_addr(iface) == local_vm_ip:
                return iface
        except Exception:
            continue

    # Ubuntu/Kali lab fallback: prefer the VirtualBox host-only adapter when the
    # protected IP is on the host-only subnet and the interface exists.
    if local_vm_ip.startswith("192.168.56.") and "enp0s8" in available_ifaces:
        logger.warning(
            "Falling back to host-only adapter enp0s8 for local VM IP %s.",
            local_vm_ip,
        )
        return "enp0s8"

    # Final best-effort fallback: choose another interface on the same /24.
    try:
        ip_parts = local_vm_ip.split(".")
        if len(ip_parts) == 4:
            subnet_prefix = ".".join(ip_parts[:3]) + "."
            for iface in available_ifaces:
                try:
                    iface_ip = get_if_addr(iface)
                except Exception:
                    continue

                if iface_ip.startswith(subnet_prefix):
                    logger.warning(
                        "Falling back to interface %s on matching subnet for local VM IP %s.",
                        iface,
                        local_vm_ip,
                    )
                    return iface
    except Exception:
        logger.exception("Failed while resolving capture interface fallback")

    return None


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


def emit_event(
    attacker_ip,
    attack_type,
    features,
    destination_ip,
    layer_name,
    event_category,
    severity,
    prediction_details,
    recommended_action,
    should_block=False,
):
    prefix = {
        "malicious": "Alert",
        "gray_zone": "Gray-Zone Review",
        "normal": "Normal Sample",
    }.get(event_category, "Event")
    print(f"\n[{layer_name}] {prefix}: {attack_type} from {attacker_ip}")

    log_path = ALERT_LOG_PATH if event_category == "malicious" else SUSPICIOUS_LOG_PATH
    append_line(
        log_path,
        f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
        f"layer={layer_name} category={event_category} src={attacker_ip} dst={destination_ip} label={attack_type} "
        f"p1={prediction_details.get('primary_prediction')} conf={round_probability(prediction_details.get('primary_probability', 0)):.2f}",
    )

    alert = create_alert(
        attacker_ip=attacker_ip,
        attack_type=attack_type,
        features=features or {},
        destination_ip=destination_ip,
    )
    alert["event_category"] = event_category
    alert["severity"] = severity
    alert["prediction_details"] = prediction_details
    alert["recommended_action"] = recommended_action
    alert["edge_device"] = EDGE_DEVICE_NAME

    if should_block:
        block_result = block_ip_on_edge(
            attacker_ip,
            f"Auto-blocked after {layer_name} detected {attack_type}",
        )
    else:
        block_result = {
            "isBlocked": 0,
            "blockStatus": "not_requested",
            "blockMessage": "No immediate block requested for this event.",
        }

    alert.update(block_result)
    alert["blockUpdatedAt"] = time.strftime("%Y-%m-%dT%H:%M:%S")

    save_alert(alert)
    post_alert_to_dashboard(alert)
    return alert


def analyze_packet(packet):
    try:
        if not packet.haslayer(IP):
            return

        attacker_ip = packet[IP].src
        dst_ip = packet[IP].dst
        current_time = time.time()

        if attacker_ip == LOCAL_VM_IP:
            return
        if MONITOR_DST_IP and dst_ip != MONITOR_DST_IP:
            return
        if attacker_ip in IGNORE_SRC_IPS:
            return
        if ALLOW_SRC_IPS and attacker_ip not in ALLOW_SRC_IPS:
            return
        if SRC_SUBNET_OBJ is not None:
            try:
                if ipaddress.ip_address(attacker_ip) not in SRC_SUBNET_OBJ:
                    return
            except ValueError:
                return

        dst_port = 0
        if packet.haslayer(TCP):
            dst_port = packet[TCP].dport
        elif packet.haslayer(UDP):
            dst_port = packet[UDP].dport

        if LAYER2_FIRST and packet.haslayer(TCP):
            early_layer_2_prediction = layer_2_dpi(packet)
            if early_layer_2_prediction != "Clean":
                event_key = (attacker_ip, early_layer_2_prediction, "malicious")
                if not should_emit_event(event_key, current_time):
                    return
                emit_event(
                    attacker_ip=attacker_ip,
                    attack_type=early_layer_2_prediction,
                    features={},
                    destination_ip=dst_ip,
                    layer_name="LAYER 2 FIRST",
                    event_category="malicious",
                    severity=infer_severity(early_layer_2_prediction),
                    prediction_details={},
                    recommended_action="Auto-block strong signature hit",
                    should_block=True,
                )
                return

        live_data = extract_live_features(packet)
        if live_data is None:
            return

        live_data_scaled = scaler.transform(live_data)
        prediction_details = get_prediction_details(live_data_scaled)
        layer_1_prediction = prediction_details["primary_prediction"]
        feature_dict = live_data.iloc[0].to_dict()

        layer_2_prediction = layer_2_dpi(packet)
        layer_3_prediction = layer_3_behavior(attacker_ip, dst_port, current_time)
        primary_probability = prediction_details["primary_probability"]
        normal_probability = prediction_details["normal_probability"]
        secondary_prediction = prediction_details["secondary_prediction"]
        secondary_probability = prediction_details["secondary_probability"]
        confidence_gap = prediction_details["confidence_gap"]

        triggered_layers = []
        if layer_1_prediction != "Normal":
            triggered_layers.append(
                f"L1={layer_1_prediction}@{round_probability(primary_probability):.2f}%"
            )
        if layer_2_prediction != "Clean":
            triggered_layers.append(f"L2={layer_2_prediction}")
        if layer_3_prediction != "Clean":
            triggered_layers.append(f"L3={layer_3_prediction}")

        if triggered_layers:
            print(f"[Inference] Triggered layers for {attacker_ip}: {', '.join(triggered_layers)}")
            append_line(
                SUSPICIOUS_LOG_PATH,
                f"{time.strftime('%Y-%m-%d %H:%M:%S')} src={attacker_ip} dst={dst_ip} triggers={','.join(triggered_layers)}",
            )

        if layer_2_prediction != "Clean":
            event_key = (attacker_ip, layer_2_prediction, "malicious")
            if not should_emit_event(event_key, current_time):
                return
            emit_event(
                attacker_ip=attacker_ip,
                attack_type=layer_2_prediction,
                features=feature_dict,
                destination_ip=dst_ip,
                layer_name="LAYER 2 DPI",
                event_category="malicious",
                severity=infer_severity(layer_2_prediction),
                prediction_details=prediction_details,
                recommended_action="Auto-block strong payload signature",
                should_block=True,
            )
            return

        if layer_3_prediction != "Clean":
            event_key = (attacker_ip, layer_3_prediction, "malicious")
            if not should_emit_event(event_key, current_time):
                return
            emit_event(
                attacker_ip=attacker_ip,
                attack_type=layer_3_prediction,
                features=feature_dict,
                destination_ip=dst_ip,
                layer_name="LAYER 3 BEHAVIOR",
                event_category="malicious",
                severity="high",
                prediction_details=prediction_details,
                recommended_action="Auto-block strong behavioral attack",
                should_block=True,
            )
            layer3_state[attacker_ip] = {"times": [], "ports": set()}
            return

        if layer_1_prediction != "Normal" and primary_probability >= ATTACK_CONFIDENCE_STRONG:
            event_key = (attacker_ip, layer_1_prediction, "malicious")
            if not should_emit_event(event_key, current_time):
                return
            emit_event(
                attacker_ip=attacker_ip,
                attack_type=layer_1_prediction,
                features=feature_dict,
                destination_ip=dst_ip,
                layer_name="LAYER 1 ML",
                event_category="malicious",
                severity="high",
                prediction_details=prediction_details,
                recommended_action="Auto-block high-confidence ML attack",
                should_block=True,
            )
            return

        strong_normal = layer_1_prediction == "Normal" and normal_probability >= NORMAL_CONFIDENCE_STRONG
        soft_normal = (
            layer_2_prediction == "Clean"
            and layer_3_prediction == "Clean"
            and (
                (
                    layer_1_prediction == "Normal"
                    and normal_probability >= SOFT_NORMAL_MIN_CONFIDENCE
                    and confidence_gap <= SOFT_NORMAL_MAX_GAP
                )
                or (
                    layer_1_prediction != "Normal"
                    and secondary_prediction == "Normal"
                    and secondary_probability >= SOFT_NORMAL_MIN_CONFIDENCE
                    and confidence_gap <= SOFT_NORMAL_MAX_GAP
                )
            )
        )

        if strong_normal or soft_normal:
            if random.random() <= NORMAL_SAMPLE_RATE:
                event_key = (attacker_ip, dst_ip, "normal")
                if not should_emit_event(event_key, current_time):
                    return
                emit_event(
                    attacker_ip=attacker_ip,
                    attack_type="Normal_Traffic",
                    features=feature_dict,
                    destination_ip=dst_ip,
                    layer_name="LAYER 1 NORMAL",
                    event_category="normal",
                    severity="low",
                    prediction_details=prediction_details,
                    recommended_action="Observe only",
                    should_block=False,
                )
            return

        if GRAY_ZONE_ENABLED:
            gray_zone_triggered = False
            if layer_1_prediction == "Normal" and normal_probability < NORMAL_CONFIDENCE_STRONG:
                gray_zone_triggered = True
            elif layer_1_prediction != "Normal" and primary_probability >= GRAY_ZONE_MIN_CONFIDENCE:
                gray_zone_triggered = True

            if gray_zone_triggered:
                event_key = (attacker_ip, prediction_details["primary_prediction"], "gray_zone")
                if not should_emit_event(event_key, current_time):
                    return
                emit_event(
                    attacker_ip=attacker_ip,
                    attack_type="Gray_Zone_Review",
                    features=feature_dict,
                    destination_ip=dst_ip,
                    layer_name="GRAY ZONE",
                    event_category="gray_zone",
                    severity="medium",
                    prediction_details=prediction_details,
                    recommended_action="Review before containment",
                    should_block=False,
                )
                return

    except Exception:
        logger.exception("analyze_packet failed")


IFACE_NAME = resolve_capture_interface(LOCAL_VM_IP)

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
