#!/usr/bin/env bash
set -euo pipefail

ENV_FILE="/etc/elai/inference.env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_PROJECT_HOME="$SCRIPT_DIR"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

if [[ ! -f "$DEFAULT_PROJECT_HOME/inference.py" && -d "$HOME/FYP" ]]; then
  DEFAULT_PROJECT_HOME="$HOME/FYP"
fi

PROJECT_HOME="${PROJECT_HOME:-$DEFAULT_PROJECT_HOME}"
INFERENCE_SCRIPT="${INFERENCE_SCRIPT:-$PROJECT_HOME/inference.py}"
VENV_PYTHON="${VENV_PYTHON:-$PROJECT_HOME/venv/bin/python}"

CAPTURE_INTERFACE="${CAPTURE_INTERFACE:-enp0s8}"
PROTECTED_VM_IP="${PROTECTED_VM_IP:-192.168.56.101}"
PROTECTED_VM_CIDR="${PROTECTED_VM_CIDR:-${PROTECTED_VM_IP}/24}"
DASHBOARD_ALERT_URL="${DASHBOARD_ALERT_URL:-http://localhost:4000/api/alerts}"
ELAI_MONITOR_DST_IP="${ELAI_MONITOR_DST_IP:-$PROTECTED_VM_IP}"
ELAI_ALLOW_SRC_IPS="${ELAI_ALLOW_SRC_IPS:-192.168.56.102}"
EDGE_BLOCK_AGENT_URL="${EDGE_BLOCK_AGENT_URL:-http://127.0.0.1:8787/block-ip}"
EDGE_BLOCK_AGENT_TOKEN="${EDGE_BLOCK_AGENT_TOKEN:-}"

if [[ ! -f "$INFERENCE_SCRIPT" ]]; then
  echo "[ELAI] inference.py not found at $INFERENCE_SCRIPT" >&2
  exit 1
fi

if [[ ! -x "$VENV_PYTHON" ]]; then
  echo "[ELAI] Python runtime not found at $VENV_PYTHON" >&2
  exit 1
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo /usr/bin/env \
    PROJECT_HOME="$PROJECT_HOME" \
    INFERENCE_SCRIPT="$INFERENCE_SCRIPT" \
    VENV_PYTHON="$VENV_PYTHON" \
    CAPTURE_INTERFACE="$CAPTURE_INTERFACE" \
    PROTECTED_VM_IP="$PROTECTED_VM_IP" \
    PROTECTED_VM_CIDR="$PROTECTED_VM_CIDR" \
    DASHBOARD_ALERT_URL="$DASHBOARD_ALERT_URL" \
    ELAI_MONITOR_DST_IP="$ELAI_MONITOR_DST_IP" \
    ELAI_ALLOW_SRC_IPS="$ELAI_ALLOW_SRC_IPS" \
    EDGE_BLOCK_AGENT_URL="$EDGE_BLOCK_AGENT_URL" \
    EDGE_BLOCK_AGENT_TOKEN="$EDGE_BLOCK_AGENT_TOKEN" \
    bash "$0"
fi

cd "$PROJECT_HOME"

if ! ip link show "$CAPTURE_INTERFACE" >/dev/null 2>&1; then
  echo "[ELAI] Interface $CAPTURE_INTERFACE was not found on this Ubuntu VM." >&2
  exit 1
fi

ip link set "$CAPTURE_INTERFACE" up || true

if ! ip -4 addr show dev "$CAPTURE_INTERFACE" | grep -Fq "$PROTECTED_VM_IP/"; then
  echo "[ELAI] $CAPTURE_INTERFACE is missing $PROTECTED_VM_IP; assigning $PROTECTED_VM_CIDR"
  ip addr replace "$PROTECTED_VM_CIDR" dev "$CAPTURE_INTERFACE"
fi

echo "[ELAI] Launching inference with:"
echo "[ELAI]   interface=$CAPTURE_INTERFACE"
echo "[ELAI]   protected_ip=$PROTECTED_VM_IP"
echo "[ELAI]   alert_url=$DASHBOARD_ALERT_URL"
echo "[ELAI]   block_url=$EDGE_BLOCK_AGENT_URL"

exec /usr/bin/env \
  PROTECTED_VM_IP="$PROTECTED_VM_IP" \
  CAPTURE_INTERFACE="$CAPTURE_INTERFACE" \
  DASHBOARD_ALERT_URL="$DASHBOARD_ALERT_URL" \
  ELAI_MONITOR_DST_IP="$ELAI_MONITOR_DST_IP" \
  ELAI_ALLOW_SRC_IPS="$ELAI_ALLOW_SRC_IPS" \
  EDGE_BLOCK_AGENT_URL="$EDGE_BLOCK_AGENT_URL" \
  EDGE_BLOCK_AGENT_TOKEN="$EDGE_BLOCK_AGENT_TOKEN" \
  "$VENV_PYTHON" "$INFERENCE_SCRIPT"
