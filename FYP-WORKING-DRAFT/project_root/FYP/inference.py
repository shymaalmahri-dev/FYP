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

─────────────────────────────────────────────────────────────────────────────
HOW THE THREE LAYERS WORK TOGETHER
─────────────────────────────────────────────────────────────────────────────

  Layer 1 — ML (Random Forest)
      Every incoming packet is feature-engineered and scored by a pre-trained
      scikit-learn Random Forest. The scaler and label encoder loaded at
      startup normalize the features and map numeric class indices back to
      human-readable attack names (e.g. "SQL_Injection", "Normal").

  Layer 2 — DPI (Deep Packet Inspection)
      The raw TCP payload bytes are searched for known malicious string
      signatures (SQL keywords, shell commands, XSS tags). This layer catches
      attacks that are too novel or too low-volume for the ML model to flag
      with high confidence.

  Layer 3 — Behavioral Heuristics
      Per-source-IP counters track connection rate and unique port spread over
      a 15-second rolling window. Sudden fan-out to many ports signals a port
      scan; rapid repetitive connections to a single port with small payloads
      signal a brute-force attempt.

The three layers share a common emit_event / post_alert_to_dashboard pipeline
so every detection — regardless of which layer raised it — produces a
consistent JSON alert object consumed by the Node.js dashboard.
─────────────────────────────────────────────────────────────────────────────
"""

# ─── Standard library ────────────────────────────────────────────────────────
from pathlib import Path   # Cross-platform path manipulation; BASE_DIR is built from this
import json                # Serialise alert payloads before HTTP POST and log writes
import logging             # Structured logging to stderr (keeps stdout clean for prints)
import math                # math.log2 used in Shannon entropy calculation for port_entropy
import os                  # Environment variable reads (DASHBOARD_ALERT_URL, CAPTURE_INTERFACE …)
import random              # Stochastic sampling of normal-traffic events (NORMAL_SAMPLE_RATE)
import socket              # socket.gethostname() for the default EDGE_DEVICE_NAME label
import sys                 # sys.path manipulation so explainable_ai/ sibling dir is importable
import time                # time.time() for inter-arrival times, cooldown logic, and log timestamps
import urllib.error        # Catch network errors when POSTing to the dashboard or block agent
import urllib.request      # Pure-stdlib HTTP client — no requests dependency required
import warnings            # Suppress scikit-learn UserWarnings that clutter stderr
import ipaddress           # Parse and match CIDR subnets for the ELAI_MONITOR_SRC_SUBNET filter

# ─── Third-party: ML stack ────────────────────────────────────────────────────
import joblib              # Deserialise pre-trained model, scaler, encoder, and feature list
import pandas as pd        # Build the per-packet feature DataFrame that the scaler expects

# ─── Third-party: Packet capture ─────────────────────────────────────────────
# scapy decodes raw network frames into typed layer objects.
# sniff()      — blocking capture loop; prn= callback is called for each packet
# get_if_list  — enumerate all network interfaces visible to the OS
# get_if_addr  — look up the IPv4 address bound to a given interface name
from scapy.all import IP, TCP, UDP, ICMP, sniff, get_if_list, get_if_addr

# ─────────────────────────────────────────────────────────────────────────────
# PATH SETUP — make the sibling explainable_ai/ directory importable
# ─────────────────────────────────────────────────────────────────────────────
# BASE_DIR  = the directory that contains THIS file (FYP/)
# EXPLAINABLE_AI_DIR = FYP/../explainable_ai/ = project_root/explainable_ai/
#
# The explainable_ai package holds:
#   alert_collector.py   — create_alert / save_alert helpers
#   shap_analyzer.py     — explain_prediction (SHAP values)
#   incident_generator.py — build_prompt / generate_report (Ollama LLM)
BASE_DIR = Path(__file__).resolve().parent
EXPLAINABLE_AI_DIR = BASE_DIR.parent / "explainable_ai"
sys.path.append(str(EXPLAINABLE_AI_DIR))

# alert_collector is always required — it stamps and persists every alert JSON.
from alert_collector import create_alert, save_alert

# ─── Optional: SHAP explainability ───────────────────────────────────────────
# If the shap package or the SHAP TreeExplainer fails to initialise, ELAI
# degrades gracefully to a heuristic feature-ranking fallback instead of
# crashing the entire capture loop.
try:
    from shap_analyzer import explain_prediction
except Exception as e:
    print(f"[Inference] WARNING: failed to import SHAP explainability module: {e}")
    explain_prediction = None   # Sentinel: build_shap_explanation checks for None

# ─── Optional: Ollama LLM incident reports ───────────────────────────────────
# build_prompt  — assembles a structured prompt from attack type + SHAP features
# generate_report — sends the prompt to a local Ollama endpoint and returns text
# Both fall back to build_fallback_llm_explanation if unavailable.
try:
    from incident_generator import build_prompt, generate_report
except Exception as e:
    print(f"[Inference] WARNING: failed to import LLM incident generator: {e}")
    build_prompt = None
    generate_report = None

# Suppress "X does not have valid feature names" warnings from sklearn when
# we pass a plain numpy array after scaling.
warnings.filterwarnings("ignore", category=UserWarning)

# ─────────────────────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────────────────────
# Uses stderr so print() statements (which go to stdout) remain separate.
# This makes it easy to redirect alert JSON to a file while still reading logs:
#   python inference.py 2>elai.log
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger("elai")

# Two append-only flat log files written by append_line():
#   alerts.log      — confirmed malicious events (Layer 1/2/3 hits)
#   suspicious.log  — gray-zone events + normal samples + triggered-layer summaries
ALERT_LOG_PATH = BASE_DIR / "alerts.log"
SUSPICIOUS_LOG_PATH = BASE_DIR / "suspicious.log"


def append_line(path: Path, line: str) -> None:
    """
    Appends a single newline-terminated string to a flat log file.

    Uses append mode ("a") so concurrent writes from multiple sniff() callbacks
    do not truncate earlier entries. Errors are logged rather than re-raised so
    a disk-full condition never kills the capture loop.
    """
    try:
        with path.open("a", encoding="utf-8") as file_handle:
            file_handle.write(line + "\n")
    except Exception:
        logger.exception("Failed to append to %s", path)


# ─────────────────────────────────────────────────────────────────────────────
# RUNTIME CONFIGURATION — all tuneable via environment variables
# ─────────────────────────────────────────────────────────────────────────────
# This design keeps the Docker image / systemd unit image-immutable:
# operators adjust behaviour through /etc/elai/inference.env without rebuilding.

# Where to POST completed alert JSON objects.
# Default assumes the Node.js dashboard runs on the same Ubuntu VM.
DASHBOARD_ALERT_URL = os.environ.get(
    "DASHBOARD_ALERT_URL",
    "http://localhost:4000/api/alerts"
)

# Optional sidecar HTTP service that translates POST /block-ip into a local
# iptables DROP rule on the edge VM.  If empty, block actions are simulated
# (isBlocked=0, blockStatus="disabled") so the rest of the pipeline still runs.
EDGE_BLOCK_AGENT_URL = os.environ.get("EDGE_BLOCK_AGENT_URL", "").strip()
EDGE_BLOCK_AGENT_TOKEN = os.environ.get("EDGE_BLOCK_AGENT_TOKEN", "").strip()

# Label attached to every alert so the dashboard can display which edge node
# generated it.  Defaults to the OS hostname when unset.
EDGE_DEVICE_NAME = os.environ.get("EDGE_DEVICE_NAME", socket.gethostname())

# When True, Layer 2 DPI runs BEFORE Layer 1 ML for TCP packets.
# Useful in high-certainty environments where known-bad payloads should be
# blocked immediately without waiting for the ML inference path.
LAYER2_FIRST = os.environ.get("ELAI_LAYER2_FIRST", "0").strip().lower() in ("1", "true", "yes")

# Traffic scope filters — narrow the capture to a specific destination IP
# and/or a source CIDR.  Empty strings disable both filters.
MONITOR_DST_IP = os.environ.get("ELAI_MONITOR_DST_IP", "").strip()
MONITOR_SRC_SUBNET = os.environ.get("ELAI_MONITOR_SRC_SUBNET", "").strip()

# ── Confidence thresholds ──────────────────────────────────────────────────
# NORMAL_CONFIDENCE_STRONG  — P(Normal) ≥ this → packet is confidently normal
# ATTACK_CONFIDENCE_STRONG  — P(attack_class) ≥ this → high-confidence malicious alert
# GRAY_ZONE_MIN_CONFIDENCE  — P(primary) ≥ this when not strongly normal → gray zone
# SOFT_NORMAL_MIN_CONFIDENCE / SOFT_NORMAL_MAX_GAP — secondary soft-normal rule:
#     primary is Normal with moderate confidence AND the gap to second class is small
NORMAL_CONFIDENCE_STRONG = float(os.environ.get("ELAI_NORMAL_MIN_PROBA", "0.85"))
ATTACK_CONFIDENCE_STRONG = float(os.environ.get("ELAI_ATTACK_STRONG_PROBA", "0.90"))
GRAY_ZONE_MIN_CONFIDENCE = float(os.environ.get("ELAI_GRAY_MIN_PROBA", "0.60"))
GRAY_ZONE_ENABLED = os.environ.get("ELAI_GRAY_ZONE_ENABLED", "1").strip().lower() in ("1", "true", "yes")

# Fraction of confidently normal packets that are kept and POSTed as "normal"
# events for analyst validation.  0.20 = 20 % pass-through, 80 % silently dropped.
NORMAL_SAMPLE_RATE = float(os.environ.get("ELAI_NORMAL_SAMPLE_RATE", "0.20"))

# Minimum gap (seconds) between two alerts with the same (src_ip, label, category)
# key.  Prevents alert storms during sustained attacks flooding the dashboard DB.
EVENT_COOLDOWN_SEC = float(os.environ.get("ELAI_ALERT_COOLDOWN_SEC", "5"))

SOFT_NORMAL_MIN_CONFIDENCE = float(os.environ.get("ELAI_SOFT_NORMAL_MIN_PROBA", "0.45"))
SOFT_NORMAL_MAX_GAP = float(os.environ.get("ELAI_SOFT_NORMAL_MAX_GAP", "0.12"))

# IP-level allow / deny lists (comma-separated).
# IGNORE_SRC_IPS — always skip packets from these addresses (e.g. monitoring agents)
# ALLOW_SRC_IPS  — when non-empty, ONLY packets from these addresses are inspected
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

# Pre-parse the optional source-subnet filter once at startup.
# ipaddress.ip_network(strict=False) accepts host addresses like 192.168.56.0/24
# without raising because the host bits are non-zero.
SRC_SUBNET_OBJ = None
if MONITOR_SRC_SUBNET:
    try:
        SRC_SUBNET_OBJ = ipaddress.ip_network(MONITOR_SRC_SUBNET, strict=False)
    except ValueError:
        logger.warning("Invalid ELAI_MONITOR_SRC_SUBNET=%s (ignored)", MONITOR_SRC_SUBNET)
        SRC_SUBNET_OBJ = None

# ─────────────────────────────────────────────────────────────────────────────
# STATIC LOOKUP TABLES
# ─────────────────────────────────────────────────────────────────────────────

# Maps attack class names to CVSS-style severity strings.
# Classes absent from this dict fall through to the "high" default in
# infer_severity(), so new attack types are still actionable.
SEVERITY_MAP = {
    "SQL_Injection": "critical",
    "Directory_Traversal": "critical",
    "Command_Injection": "critical",
    "XSS_Injection": "critical",
}

# Maps IANA protocol numbers to readable strings for the dashboard protocol field.
PROTOCOL_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP",
}

# Human-readable display names for the numeric feature columns produced by
# extract_live_features().  Used in SHAP + heuristic explanations shown to analysts.
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

# ─── Per-key cooldown state ───────────────────────────────────────────────────
# Maps (src_ip, label, category) → last Unix timestamp an event was emitted.
# should_emit_event() consults this before calling emit_event() so that sustained
# attacks produce one dashboard alert every EVENT_COOLDOWN_SEC seconds rather
# than one per packet.
last_event_state = {}


# ─────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ─────────────────────────────────────────────────────────────────────────────

def infer_severity(attack_type):
    """
    Resolve a severity string for an attack label.

    Returns the value from SEVERITY_MAP when the label is known, or "high"
    as a safe catch-all for newly discovered attack classes that have not yet
    been added to the map.
    """
    return SEVERITY_MAP.get(attack_type, "high")


def normalize_protocol(protocol):
    """
    Convert an IANA IP protocol number (or any string) to a readable label.

    The dashboard stores protocol as a string ("TCP", "UDP", "ICMP").
    When the feature extractor stores the raw integer (6, 17, 1), this
    function maps it back; unknown protocols are stringified as-is.
    """
    if isinstance(protocol, int):
        return PROTOCOL_MAP.get(protocol, str(protocol))
    return protocol or "TCP"


def round_probability(value):
    """
    Scale a [0, 1] float probability to a percentage with two decimal places.

    Example: 0.9342 → 93.42
    Used throughout the dashboard payload so all confidence fields share
    the same unit and precision.
    """
    return round(float(value) * 100, 2)


def build_normal_explanation(attacker_ip, destination_ip, prediction_details):
    """
    Generate a one-sentence human-readable description for a normal-traffic sample.

    Called only when a packet is confidently classified as benign and randomly
    selected for the 20 % analyst-validation pass-through.  The description is
    stored in the dashboard 'description' column so analysts understand why a
    "low" severity record exists.
    """
    primary = prediction_details.get("primary_prediction", "Normal")
    secondary = prediction_details.get("secondary_prediction", "unknown")
    return (
        f"Traffic from {attacker_ip} to {destination_ip} matched the model's normal profile. "
        f"Primary class: {primary}. Confidence: {prediction_details.get('primary_confidence', 0):.2f}%."
        f"{' The nearest competing class was ' + secondary + '.' if secondary and secondary != 'None' else ''}"
    )


def build_gray_zone_explanation(attacker_ip, destination_ip, prediction_details):
    """
    Generate a multi-sentence description for a gray-zone (ambiguous) packet.

    A gray-zone event occurs when the ML model's top-two class probabilities
    are close together — the model leans toward an attack class but lacks the
    confidence threshold to trigger an automatic block.  The explanation
    surfaces the confidence gap so analysts can decide whether to escalate.
    """
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
    """
    Rate-limit repeated alerts for the same (src_ip, label, category) tuple.

    Returns True  — the event is fresh; emit it and update last_event_state.
    Returns False — the same event was emitted within EVENT_COOLDOWN_SEC seconds;
                    silently drop this instance to avoid dashboard flooding.

    The cooldown is per (attacker, attack_type, category) triple, so two
    different attack types from the same IP each get their own independent
    cooldown window.
    """
    last_seen = last_event_state.get(event_key, 0.0)
    if current_time - last_seen < EVENT_COOLDOWN_SEC:
        return False
    last_event_state[event_key] = current_time
    return True


def block_ip_on_edge(ip_address, reason):
    """
    POST a block-IP request to the optional edge block agent sidecar.

    The edge block agent (edge_block_agent.py) listens on EDGE_BLOCK_AGENT_URL
    and translates the request into a local iptables DROP rule.  If the URL is
    not configured, the function returns a "disabled" status dict so the rest of
    the alert pipeline can still record the block attempt in MySQL.

    Returns a dict with three keys consumed by emit_event():
      isBlocked   — 1 if the agent confirmed success, 0 otherwise
      blockStatus — "blocked" | "failed" | "disabled"
      blockMessage — human-readable detail from the agent response or error
    """
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
            # Bearer token is optional; omit the header entirely when absent
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
    """
    Run the Random Forest model and return a structured prediction dict.

    Calls model.predict_proba() once and extracts:
      primary_prediction   — class name with highest probability
      primary_probability  — its float probability (0–1)
      secondary_prediction — runner-up class name
      secondary_probability — runner-up probability
      normal_probability   — P(Normal) specifically (used for the normal/gray-zone
                             decision tree, regardless of what the primary class is)
      confidence_gap       — difference between top two probabilities; small gaps
                             signal ambiguity and trigger the gray-zone path

    The model and label_encoder objects are module-level globals loaded once at
    startup from edge_ai_artifacts/.
    """
    probabilities = model.predict_proba(live_data_scaled)[0]
    classes = list(label_encoder.classes_)
    order = probabilities.argsort()[::-1]  # Descending rank

    primary_index = int(order[0])
    primary_prediction = classes[primary_index]
    primary_probability = float(probabilities[primary_index])

    secondary_prediction = "None"
    secondary_probability = 0.0
    if len(order) > 1:
        secondary_index = int(order[1])
        secondary_prediction = classes[secondary_index]
        secondary_probability = float(probabilities[secondary_index])

    # Explicitly look up P(Normal) because the primary class may be an attack class
    # even when the normal probability is still the highest among attacks' complement.
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
    """
    Produce a short, template-based explanation when Ollama is unavailable.

    This fallback is used when:
      • incident_generator failed to import (Ollama not installed / not running)
      • Ollama returned an empty or non-string response
      • Any exception propagated from generate_report()

    The function incorporates up to three top SHAP features by name and
    importance so the text is more informative than a pure static template.
    """
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
    """
    Request a narrative incident report from the local Ollama LLM.

    Workflow:
      1. Normalise shap_features into the {feature, impact} format expected
         by build_prompt().
      2. Call build_prompt() to assemble a structured prompt string.
      3. Call generate_report() which POSTs to http://localhost:11434 (Ollama).
      4. Return the stripped text response.
      5. If any step fails, delegate to build_fallback_llm_explanation().

    The LLM adds natural-language context that helps tier-1 analysts understand
    WHY the model flagged the packet without needing to read SHAP values directly.
    """
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
    """
    Build a SHAP-style feature importance dict for one packet.

    Priority order:
      1. explain_prediction() from shap_analyzer — real TreeExplainer SHAP values
      2. build_heuristic_feature_explanation() — magnitude-ranked fallback
      3. None — if the feature dict itself is empty

    The returned dict has the shape expected by build_dashboard_alert():
      {
        "baseValue": float,        # SHAP expected value (0.5 for heuristic)
        "prediction": float,       # model output probability (patched in later)
        "features": [
          { "name": str, "importance": float, "value": str },
          ...
        ]
      }

    This structure is serialised to JSON and stored in the dashboard
    shapeExplanation column for the React SHAP waterfall chart.
    """
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
            "prediction": 0.95,    # Placeholder; overwritten by build_dashboard_alert()
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
    """
    Rank features by absolute magnitude as a SHAP-compatible fallback.

    When the SHAP library is absent or raises, this function iterates over the
    feature dict, filters to only the keys that appear in FEATURE_LABELS (i.e.
    the 20 engineered features), and returns the top-5 by absolute value
    normalised to [0, 1].

    The heuristic is intentionally simple: larger raw feature values are treated
    as more "important".  This is a rough proxy — features like byte_rate are
    genuinely large for flood attacks — but avoids hallucinated explanations.
    """
    ranked = []

    for key, raw_value in (features or {}).items():
        if key not in FEATURE_LABELS:
            continue   # Skip non-display features (is_icmp, is_modbus, etc.)

        try:
            numeric_value = float(raw_value)
        except (TypeError, ValueError):
            continue   # Skip non-numeric values (shouldn't happen, but be safe)

        if abs(numeric_value) <= 0:
            continue   # Zero-valued features contribute nothing useful

        ranked.append((key, numeric_value))

    if not ranked:
        return None

    max_magnitude = max(abs(value) for _, value in ranked) or 1.0
    top_ranked = sorted(ranked, key=lambda item: abs(item[1]), reverse=True)[:5]

    return {
        "baseValue": 0.5,
        "prediction": 0.0,    # Placeholder; overwritten by build_dashboard_alert()
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
    """
    Transform the internal alert dict into the flat JSON schema the dashboard API expects.

    This function is the single point of truth for the dashboard payload contract.
    All three detection layers produce alerts via emit_event() using the same
    internal dict; this function adapts that dict to the Node.js API schema.

    Key decisions made here:
      • description — human-readable one-liner; varies by event_category
      • llmExplanation — Ollama narrative or template fallback
      • shapeExplanation — JSON-serialised SHAP dict (or None)
      • modelConfidence / primaryConfidence / secondaryConfidence — all in %
      • protocol — integer → "TCP" / "UDP" / "ICMP" string conversion
    """
    features = alert.get("features", {}) or {}
    protocol = normalize_protocol(features.get("ip_proto"))
    destination_ip = alert.get("destination_ip") or alert.get("destinationIp") or "unknown"
    shap_values = build_shap_explanation(features)
    prediction_details = alert.get("prediction_details", {}) or {}
    event_category = alert.get("event_category", "malicious")
    primary_probability = round_probability(prediction_details.get("primary_probability", 0))

    # ── Select description and LLM explanation by event category ──────────
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
        # Malicious path: generate a full LLM narrative using SHAP top features
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

    # Patch the SHAP dict's prediction field with the actual model output
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
    """
    HTTP POST the alert to the Node.js dashboard REST API.

    Calls build_dashboard_alert() to convert the internal alert dict to the
    API schema, then sends it as JSON.  Network errors are caught and printed
    rather than raised so a dashboard outage never stalls the capture loop.

    The dashboard API (POST /api/alerts) is defined in elai-dashboard/src/routes/alerts.ts.
    A 2xx response means the alert was persisted to MySQL and is now visible
    in the React frontend.
    """
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


# ─────────────────────────────────────────────────────────────────────────────
# STARTUP BANNER
# ─────────────────────────────────────────────────────────────────────────────
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
    """
    Determine the IP address that identifies this Ubuntu VM on the lab network.

    Resolution order (first match wins):
      1. PROTECTED_VM_IP or ELAI_PROTECTED_VM_IP env var — set this in production
         to guarantee a stable address across reboots.
      2. First interface whose address starts with 192.168.56. — the default
         VirtualBox host-only subnet used in the Ubuntu/Kali lab.
      3. UDP connect trick — connect a datagram socket to a non-routable address
         and read back the source IP chosen by the kernel.  Never actually sends
         a packet.
      4. 127.0.0.1 — last-resort loopback.

    The returned IP is stored in LOCAL_VM_IP and used by analyze_packet() to
    filter out packets that the Ubuntu VM itself originated (self-traffic).
    """
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
    """
    Find the network interface name to pass to scapy's sniff().

    Resolution order:
      1. CAPTURE_INTERFACE or ELAI_IFACE env var — overrides everything.
         If the named interface is not in get_if_list() a warning is logged
         and the name is used anyway (edge case: tun/tap interfaces may not
         appear in some scapy builds).
      2. Exact IP match — iterate get_if_list() and return the first interface
         whose bound address equals local_vm_ip.
      3. VirtualBox host-only fallback — if local_vm_ip is on 192.168.56.x and
         enp0s8 exists, use it.  enp0s8 is the conventional name for the second
         VirtualBox adapter on Ubuntu 22.04+.
      4. Same-/24 fallback — look for any interface on the same Class C subnet
         as local_vm_ip.
      5. Returns None — caller exits with a helpful message.
    """
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


# Resolve and print the local VM IP so operators can confirm the correct address
# is detected before any packets are captured.
LOCAL_VM_IP = get_local_ip()
print(f"[*] Protected VM IP Address: {LOCAL_VM_IP}")

# ─────────────────────────────────────────────────────────────────────────────
# LAYER 1 — LOAD ML ARTIFACTS
# ─────────────────────────────────────────────────────────────────────────────
# All four files are produced by the training notebook (train_model.ipynb) and
# must be present in edge_ai_artifacts/ before inference.py is started.
#
#   rf_model.joblib       — trained RandomForestClassifier (scikit-learn)
#   scaler.joblib         — fitted StandardScaler; same transform used at training
#   label_encoder.joblib  — LabelEncoder mapping integer class indices → attack names
#   feature_columns.joblib — ordered list of column names; ensures feature alignment
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

# ─────────────────────────────────────────────────────────────────────────────
# ROLLING STATE TRACKERS (in-memory, reset on restart)
# ─────────────────────────────────────────────────────────────────────────────
# These dicts accumulate per-source-IP statistics over a 1.5-second rolling
# window (clean_old_state purges expired entries on every packet).
#
#   ip_history[src_ip]     — list of arrival timestamps → pkt_rate, iat
#   port_history[src_ip]   — {timestamp: dport} → unique_ports_hit, port_entropy
#   byte_history[src_ip]   — {timestamp: pkt_len} → byte_rate
#   layer3_state[src_ip]   — {"times": [...], "ports": set()} for 15-sec behavior window
ip_history = {}
port_history = {}
byte_history = {}
layer3_state = {}


def clean_old_state(current_time, window_size=1.5):
    """
    Evict expired entries from the three rolling-window state dicts.

    Called at the start of extract_live_features() for every packet so the
    per-IP statistics always reflect only the last 1.5 seconds of traffic.
    Without this, the dicts would grow unboundedly during a long capture session.

    Layer 3's layer3_state uses a 15-second window and is cleaned inline in
    layer_3_behavior() for consistency.
    """
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
    """
    Calculate Shannon entropy (bits) of a port list.

    H = -Σ p(x) * log₂(p(x))

    High entropy (many distinct ports hit equally often) → likely a port scan.
    Low entropy (repeated hits on a single port) → likely brute force or flood.
    Zero-length list → 0.0 to avoid division by zero.

    The result is stored as port_entropy in the feature vector fed to Layer 1.
    """
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
    """
    Engineer the 20-feature vector from a raw Scapy packet object.

    Returns a one-row pandas DataFrame with columns matching expected_features,
    ready to be passed directly to scaler.transform().  Returns None if the
    packet has no IP layer (ARP, 802.1Q, etc.).

    Feature groups:
      Packet-level   — pkt_len, ip_proto, ip_ttl
      TCP flags      — tcp_flags (raw bitmask) + individual is_* booleans
      TCP window     — tcp_win (congestion + OS fingerprinting signal)
      Payload        — payload_len (zero for header-only SYN floods)
      Port           — dport + is_well_known_port / is_modbus / is_mqtt / is_http / is_dns
      Rate (rolling) — iat, pkt_rate, byte_rate (1.5 s window from ip_history / byte_history)
      Diversity      — unique_ports_hit, port_entropy (1.5 s window from port_history)

    Any feature not present in expected_features is silently ignored, and any
    expected feature absent from raw_features defaults to 0.  This keeps the
    DataFrame column order stable regardless of protocol.
    """
    if IP not in packet:
        return None

    src_ip = packet[IP].src
    current_time = time.time()
    pkt_length = len(packet)
    clean_old_state(current_time)

    # Update rolling histories for this source IP
    if src_ip not in ip_history:
        ip_history[src_ip] = []
    if src_ip not in byte_history:
        byte_history[src_ip] = {}

    ip_history[src_ip].append(current_time)
    byte_history[src_ip][current_time] = pkt_length

    # iat = time since previous packet from the same source (0 for first packet)
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
        "pkt_rate": len(ip_history[src_ip]),         # packets from this IP in last 1.5 s
        "byte_rate": sum(byte_history[src_ip].values()),  # bytes from this IP in last 1.5 s
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

        # Update port diversity history for entropy / unique-port features
        if src_ip not in port_history:
            port_history[src_ip] = {}
        port_history[src_ip][current_time] = raw_features["dport"]

        recent_ports = list(port_history[src_ip].values())
        raw_features["unique_ports_hit"] = len(set(recent_ports))
        raw_features["port_entropy"] = calculate_entropy(recent_ports)

    # Build the final aligned DataFrame: only keep expected_features columns
    # in the exact order the scaler was fitted with; fill gaps with 0.
    features = {col: 0 for col in expected_features}
    for col in expected_features:
        if col in raw_features:
            features[col] = raw_features[col]

    df_live = pd.DataFrame([features])
    return df_live[expected_features]


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 2 — DEEP PACKET INSPECTION
# ─────────────────────────────────────────────────────────────────────────────

def layer_2_dpi(packet):
    """
    Scan the TCP payload for known malicious byte patterns.

    Returns the attack class name string when a signature matches, or "Clean"
    when no match is found.  The check is intentionally simple (substring
    search on lowercased UTF-8 decoded bytes) because the goal is to catch
    textbook attack payloads from tools like sqlmap, nikto, or curl one-liners.

    Signatures checked:
      SQL_Injection       — "select … from", "union all", "1=1" (SQLi classics)
      Directory_Traversal — "cat /etc/passwd" (LFI via shell)
      Command_Injection   — "wget " / "curl " (remote code execution payloads)
      XSS_Injection       — "<script>" (reflected/stored XSS)

    The function only inspects TCP payloads; UDP and ICMP always return "Clean".
    """
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


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 3 — BEHAVIORAL HEURISTICS
# ─────────────────────────────────────────────────────────────────────────────

def layer_3_behavior(src_ip, dst_port, current_time):
    """
    Detect attack patterns from per-source-IP connection behaviour over 15 seconds.

    State is maintained in layer3_state[src_ip], a dict with:
      "times" — list of recent connection timestamps (pruned to 15 s window)
      "ports" — cumulative set of all unique destination ports ever seen

    Detection rules:
      Stealth Horizontal Port Scan
        > 10 unique destination ports → the source is enumerating open services.
        The port set is cumulative (not windowed) so slow/distributed scans
        that spread hits across the 15 s window are still caught.

      Brute Force Attempt on Port N
        > 25 connections in 15 s to ≤ 3 distinct ports AND total payload < 8 KB.
        Small payload + high rate to one port = repeated login attempts.

    Only inspects connections to well-known ports (< 1024) for the brute-force
    rule because ephemeral-port traffic is typical for established sessions and
    would generate too many false positives.

    Returns the detection label string or "Clean".
    """
    if src_ip not in layer3_state:
        layer3_state[src_ip] = {"times": [], "ports": set()}

    layer3_state[src_ip]["times"].append(current_time)
    layer3_state[src_ip]["ports"].add(dst_port)
    layer3_state[src_ip]["times"] = [
        t for t in layer3_state[src_ip]["times"] if current_time - t <= 15.0
    ]

    if dst_port > 1024:
        return "Clean"   # Skip ephemeral-port traffic for brute-force check

    connection_count = len(layer3_state[src_ip]["times"])
    unique_ports = len(layer3_state[src_ip]["ports"])

    if unique_ports > 10:
        return "Stealth_Horizontal_Port_Scan"

    if connection_count > 25 and unique_ports <= 3:
        recent_bytes = sum(byte_history.get(src_ip, {}).values())
        if recent_bytes < 8192:
            return f"Brute_Force_Attempt_on_Port_{dst_port}"

    return "Clean"


# ─────────────────────────────────────────────────────────────────────────────
# ALERT EMISSION — shared by all three layers
# ─────────────────────────────────────────────────────────────────────────────

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
    """
    Persist and broadcast a single detection event.

    This is the final common path for every detection, regardless of which layer
    triggered it.  The function:

      1. Prints a one-liner to stdout for live terminal monitoring.
      2. Appends a compact record to alerts.log (malicious) or suspicious.log.
      3. Calls create_alert() to stamp the alert with a UUID and ISO timestamp.
      4. Optionally calls block_ip_on_edge() for high-confidence malicious events.
      5. Calls save_alert() to write the full JSON to the local alert store.
      6. Calls post_alert_to_dashboard() to push the event to the React UI.

    Parameters
    ----------
    attacker_ip       Source IP address of the detected packet.
    attack_type       Human-readable label ("SQL_Injection", "Normal_Traffic", …).
    features          Dict of engineered feature values for this packet.
    destination_ip    Packet destination IP.
    layer_name        Which layer raised the event (shown in the terminal prefix).
    event_category    "malicious" | "gray_zone" | "normal" — controls log routing.
    severity          "critical" | "high" | "medium" | "low".
    prediction_details Dict from get_prediction_details() (may be {} for L2/L3).
    recommended_action Free-text action hint shown in the dashboard.
    should_block      When True, attempt to block the attacker via block_ip_on_edge().
    """
    prefix = {
        "malicious": "Alert",
        "gray_zone": "Gray-Zone Review",
        "normal": "Normal Sample",
    }.get(event_category, "Event")
    print(f"\n[{layer_name}] {prefix}: {attack_type} from {attacker_ip}")

    # Route to the appropriate flat log file
    log_path = ALERT_LOG_PATH if event_category == "malicious" else SUSPICIOUS_LOG_PATH
    append_line(
        log_path,
        f"{time.strftime('%Y-%m-%d %H:%M:%S')} "
        f"layer={layer_name} category={event_category} src={attacker_ip} dst={destination_ip} label={attack_type} "
        f"p1={prediction_details.get('primary_prediction')} conf={round_probability(prediction_details.get('primary_probability', 0)):.2f}",
    )

    # create_alert() adds uuid, timestamp, and structures the base alert dict
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

    save_alert(alert)             # Persist locally (JSON file / append-log)
    post_alert_to_dashboard(alert)  # Push to Node.js dashboard API
    return alert


# ─────────────────────────────────────────────────────────────────────────────
# MAIN PACKET ANALYSIS CALLBACK
# ─────────────────────────────────────────────────────────────────────────────

def analyze_packet(packet):
    """
    Per-packet decision engine — called by scapy's sniff() for every captured frame.

    Decision tree (evaluated top-to-bottom; first match wins):

      ① Pre-filter checks (discard immediately if any fail)
           • Packet must have an IP layer
           • Source IP must not equal LOCAL_VM_IP (self-traffic)
           • Destination IP must match MONITOR_DST_IP (if configured)
           • Source IP must not be in IGNORE_SRC_IPS
           • Source IP must be in ALLOW_SRC_IPS (if configured)
           • Source IP must be within SRC_SUBNET_OBJ (if configured)

      ② Optional Layer 2 FIRST mode (ELAI_LAYER2_FIRST=1)
           Run DPI before ML; emit and return immediately on a DPI hit.
           Used when the environment strongly favours latency over ML precision.

      ③ Layer 1 — ML inference
           extract_live_features() → scaler.transform() → get_prediction_details()

      ④ Layer 2 — DPI (standard position)
           Inspect TCP payload for signature patterns.

      ⑤ Layer 3 — Behavioral heuristics
           Update rolling connection counters; check port-scan and brute-force rules.

      ⑥ Layer 2 hit? → emit malicious alert + block, return.

      ⑦ Layer 3 hit? → emit malicious alert + block, reset state, return.

      ⑧ Layer 1 strong attack? (primary_probability ≥ ATTACK_CONFIDENCE_STRONG)
           → emit malicious alert + block, return.

      ⑨ Strong or soft normal? → maybe emit normal sample (NORMAL_SAMPLE_RATE), return.

      ⑩ Gray zone? (GRAY_ZONE_ENABLED and ambiguous confidence)
           → emit gray-zone review alert (no block), return.

      ⑪ Packet passes all checks silently — no alert emitted.

    All exceptions are caught and logged so a malformed packet never terminates
    the sniff() loop.
    """
    try:
        if not packet.haslayer(IP):
            return

        attacker_ip = packet[IP].src
        dst_ip = packet[IP].dst
        current_time = time.time()

        # ── ① Pre-filter ────────────────────────────────────────────────────
        if attacker_ip == LOCAL_VM_IP:
            return   # Ignore outbound traffic this VM generated
        if MONITOR_DST_IP and dst_ip != MONITOR_DST_IP:
            return   # Only monitor traffic destined to the protected IP
        if attacker_ip in IGNORE_SRC_IPS:
            return   # Allowlisted scanner / monitoring agent
        if ALLOW_SRC_IPS and attacker_ip not in ALLOW_SRC_IPS:
            return   # Restrict to known attacker IPs (lab mode)
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

        # ── ② Layer 2 FIRST mode ────────────────────────────────────────────
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

        # ── ③ Layer 1 — ML feature extraction and inference ─────────────────
        live_data = extract_live_features(packet)
        if live_data is None:
            return

        live_data_scaled = scaler.transform(live_data)
        prediction_details = get_prediction_details(live_data_scaled)
        layer_1_prediction = prediction_details["primary_prediction"]
        feature_dict = live_data.iloc[0].to_dict()   # Preserve for SHAP + alert payload

        # ── ④ & ⑤ Layer 2 DPI + Layer 3 behavioral ──────────────────────────
        layer_2_prediction = layer_2_dpi(packet)
        layer_3_prediction = layer_3_behavior(attacker_ip, dst_port, current_time)
        primary_probability = prediction_details["primary_probability"]
        normal_probability = prediction_details["normal_probability"]
        secondary_prediction = prediction_details["secondary_prediction"]
        secondary_probability = prediction_details["secondary_probability"]
        confidence_gap = prediction_details["confidence_gap"]

        # Debug output: show which layers fired for every non-clean packet
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

        # ── ⑥ Layer 2 confirmed attack ──────────────────────────────────────
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

        # ── ⑦ Layer 3 confirmed attack ──────────────────────────────────────
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
            # Reset state so the attacker is re-evaluated after blocking rather
            # than continuing to trigger on already-accumulated history.
            layer3_state[attacker_ip] = {"times": [], "ports": set()}
            return

        # ── ⑧ Layer 1 high-confidence attack ────────────────────────────────
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

        # ── ⑨ Normal traffic ─────────────────────────────────────────────────
        # strong_normal — model is very confident this is benign
        # soft_normal   — model leans normal with moderate confidence AND the
        #                 gap to the second class is small (the two classes
        #                 are close, but both layers 2 and 3 are clean)
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
            # Stochastic pass-through: only emit 20 % of normal events so analysts
            # see a representative sample without being overwhelmed.
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

        # ── ⑩ Gray zone ──────────────────────────────────────────────────────
        # Triggered when the model is leaning toward an attack class or an
        # uncertain normal class but confidence is below the strong thresholds.
        # No automatic block; the alert is queued for analyst review.
        if GRAY_ZONE_ENABLED:
            gray_zone_triggered = False
            if layer_1_prediction == "Normal" and normal_probability < NORMAL_CONFIDENCE_STRONG:
                gray_zone_triggered = True   # Normal prediction but with low confidence
            elif layer_1_prediction != "Normal" and primary_probability >= GRAY_ZONE_MIN_CONFIDENCE:
                gray_zone_triggered = True   # Attack prediction with moderate confidence

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

        # ⑪ Packet passes all checks — silently drop (no alert, no log entry)

    except Exception:
        logger.exception("analyze_packet failed")


# ─────────────────────────────────────────────────────────────────────────────
# INTERFACE RESOLUTION AND CAPTURE LOOP
# ─────────────────────────────────────────────────────────────────────────────

# Resolve the capture interface based on LOCAL_VM_IP using the priority chain
# defined in resolve_capture_interface().
IFACE_NAME = resolve_capture_interface(LOCAL_VM_IP)

if IFACE_NAME is None:
    print("[!] Could not find a network interface matching the local VM IP.")
    exit(1)

print(f"[*] Sniffing on interface: {IFACE_NAME}. Multi-Layer Defense Active.")

# ── scapy sniff() capture loop ────────────────────────────────────────────────
# iface   — restrict capture to the single host-only interface; avoids picking
#            up loopback or NAT traffic on other adapters.
# filter  — BPF expression applied in the kernel before packets reach Python:
#            "not port 22"  — exclude SSH traffic to prevent the capture from
#                             feeding on its own remote-admin session (would
#                             inflate pkt_rate and trigger false positives).
#            "not icmp"     — exclude ICMP; ping/traceroute noise is filtered
#                             here rather than in analyze_packet() for efficiency.
# prn     — callback called for every packet that passes the BPF filter.
# store   — False prevents scapy from buffering packets in memory; essential for
#            long-running captures to avoid OOM on a busy interface.
try:
    sniff(
        iface=IFACE_NAME,
        filter="not port 22 and not icmp",
        prn=analyze_packet,
        store=False,
    )
except KeyboardInterrupt:
    print("\n[*] Shutting down IDS...")
