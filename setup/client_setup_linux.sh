#!/usr/bin/env bash
# Setup isolated Python venv and launch the ASP thin log collector on Ubuntu/Linux.
set -euo pipefail

# Lấy thư mục gốc của dự án (thư mục cha của setup/)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/../client/collector.py" ]]; then
  ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
else
  ROOT_DIR="$SCRIPT_DIR"
fi

VENV_DIR="$ROOT_DIR/.venv-client"
ENV_FILE="$ROOT_DIR/.env"
SETUP_ONLY=0
CONFIG_ARG=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --setup-only)
      SETUP_ONLY=1
      shift
      ;;
    --config)
      CONFIG_ARG="${2:-}"
      shift 2
      ;;
    -h|--help)
      cat <<'EOF'
Usage: bash client_setup.sh [--setup-only] [--config PATH]
  --setup-only    Create .venv-client, install client deps, generate config, then exit.
  --config PATH   Use custom collector YAML config (default: $HOME/asp-agent-config.yaml).
EOF
      exit 0
      ;;
    *)
      echo "[ERROR] Unknown argument: $1" >&2
      exit 1
      ;;
  esac
done

echo "[1/4] Checking Python 3 and creating client venv at: $VENV_DIR"
if ! command -v python3 >/dev/null 2>&1; then
  echo "[ERROR] python3 not found. Install Python 3.10+ first." >&2
  exit 1
fi

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
  if ! python3 -m venv "$VENV_DIR"; then
    echo "[ERROR] Failed to create venv. On Ubuntu run: sudo apt-get update && sudo apt-get install -y python3-venv" >&2
    exit 1
  fi
fi

echo "[2/4] Installing lightweight client dependencies (requests, pyyaml, pydantic)..."
"$VENV_DIR/bin/python" -m pip install --upgrade pip >/dev/null
"$VENV_DIR/bin/python" -m pip install "requests>=2.31.0" "pyyaml>=6.0.1" "pydantic>=2.7.0"

echo "[3/4] Loading unified .env configuration..."
if [[ ! -f "$ENV_FILE" ]]; then
  echo "[ERROR] Missing $ENV_FILE. Copy .env.example to .env and fill ASP_AGENT_API_KEY / ASP_SERVER_URL." >&2
  exit 1
fi

# Strip CR safely in case .env was edited on Windows
set -a
# shellcheck disable=SC1090
source <(sed 's/\r$//' "$ENV_FILE")
set +a

if [[ -z "${ASP_AGENT_API_KEY:-}" || "${ASP_AGENT_API_KEY}" == CHANGE_ME* ]]; then
  echo "[ERROR] ASP_AGENT_API_KEY is missing or still a placeholder in $ENV_FILE." >&2
  exit 1
fi

STATE_DIR="${ASP_AGENT_STATE_DIR:-$HOME/.asp-agent}"
mkdir -p "$STATE_DIR/spool"
chmod 700 "$STATE_DIR" "$STATE_DIR/spool" 2>/dev/null || true

CONFIG_PATH="${CONFIG_ARG:-${ASP_CLIENT_CONFIG:-$HOME/asp-agent-config.yaml}}"
if [[ -z "$CONFIG_ARG" ]]; then
  "$VENV_DIR/bin/python" - "$ROOT_DIR/client/config.yaml" "$CONFIG_PATH" "$STATE_DIR" <<'PY'
import os
import sys
import yaml
from pathlib import Path

base_cfg_path, out_cfg_path, state_dir = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = yaml.safe_load(Path(base_cfg_path).read_text(encoding="utf-8")) or {}

cfg["agent_id"] = os.environ.get("ASP_AGENT_ID") or cfg.get("agent_id", "web-01")
if os.environ.get("ASP_SERVER_URL"):
    cfg["server_url"] = os.environ["ASP_SERVER_URL"]
verify_env = os.environ.get("ASP_VERIFY_TLS")
if verify_env is not None and verify_env != "":
    cfg["verify_tls"] = verify_env.lower() in ("1", "true", "yes")
    if not cfg["verify_tls"]:
        cfg.pop("ca_file", None)
cfg["state_file"] = f"{state_dir}/state.json"
cfg["spool_dir"] = f"{state_dir}/spool"

out_p = Path(out_cfg_path)
out_p.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
os.chmod(out_p, 0o600)
PY
fi

echo "[4/4] Client setup ready:"
echo "  - Venv python : $VENV_DIR/bin/python"
echo "  - Config file : $CONFIG_PATH"
echo "  - Agent ID    : ${ASP_AGENT_ID:-web-01}"
echo "  - Server URL  : ${ASP_SERVER_URL:-from yaml}"

if [[ "$SETUP_ONLY" -eq 1 ]]; then
  echo ""
  echo "Run collector anytime with:"
  echo "  set -a && source <(sed 's/\r$//' \"$ENV_FILE\") && set +a"
  echo "  \"$VENV_DIR/bin/python\" \"$ROOT_DIR/client/collector.py\" --config \"$CONFIG_PATH\""
  exit 0
fi

echo "Starting ASP collector..."
cd "$ROOT_DIR"
exec "$VENV_DIR/bin/python" "$ROOT_DIR/client/collector.py" --config "$CONFIG_PATH"
