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

if [[ ! -f "$DEFAULT_PROJECT_HOME/edge_block_agent.py" && -d "$HOME/FYP" ]]; then
  DEFAULT_PROJECT_HOME="$HOME/FYP"
fi

PROJECT_HOME="${PROJECT_HOME:-$DEFAULT_PROJECT_HOME}"
AGENT_SCRIPT="${AGENT_SCRIPT:-$PROJECT_HOME/edge_block_agent.py}"
VENV_PYTHON="${VENV_PYTHON:-$PROJECT_HOME/venv/bin/python}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo /usr/bin/env \
    PROJECT_HOME="$PROJECT_HOME" \
    AGENT_SCRIPT="$AGENT_SCRIPT" \
    VENV_PYTHON="$VENV_PYTHON" \
    EDGE_BLOCK_AGENT_HOST="${EDGE_BLOCK_AGENT_HOST:-0.0.0.0}" \
    EDGE_BLOCK_AGENT_PORT="${EDGE_BLOCK_AGENT_PORT:-8787}" \
    EDGE_BLOCK_AGENT_TOKEN="${EDGE_BLOCK_AGENT_TOKEN:-}" \
    bash "$0"
fi

if [[ ! -f "$AGENT_SCRIPT" ]]; then
  echo "[ELAI] edge_block_agent.py not found at $AGENT_SCRIPT" >&2
  exit 1
fi

exec /usr/bin/env \
  EDGE_BLOCK_AGENT_HOST="${EDGE_BLOCK_AGENT_HOST:-0.0.0.0}" \
  EDGE_BLOCK_AGENT_PORT="${EDGE_BLOCK_AGENT_PORT:-8787}" \
  EDGE_BLOCK_AGENT_TOKEN="${EDGE_BLOCK_AGENT_TOKEN:-}" \
  "$VENV_PYTHON" "$AGENT_SCRIPT"
