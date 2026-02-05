#!/usr/bin/env bash
set -euo pipefail

APP_NAME="nexora-scanner"
INSTALL_DIR="/opt/${APP_NAME}"
BRANCH="main"
REPO_URL=""
RUN_USER="www-data"
RUN_GROUP="www-data"
PORT="5000"
HOST="0.0.0.0"

usage() {
  cat <<USAGE
Install Nexora Scanner on Kali Linux (Raspberry Pi) from GitHub.

Usage:
  sudo bash scripts/install_kali_rpi.sh --repo <github_repo_url> [options]

Required:
  --repo <url>          GitHub repository URL (e.g. https://github.com/org/repo.git)

Options:
  --branch <name>       Git branch (default: ${BRANCH})
  --dir <path>          Install directory (default: ${INSTALL_DIR})
  --user <name>         Service runtime user (default: ${RUN_USER})
  --group <name>        Service runtime group (default: ${RUN_GROUP})
  --host <host>         Bind host (default: ${HOST})
  --port <port>         Bind port (default: ${PORT})
  --help                Show this help
USAGE
}

log() {
  echo "[install] $*"
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    echo "Please run as root (use sudo)."
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      REPO_URL="${2:-}"
      shift 2
      ;;
    --branch)
      BRANCH="${2:-}"
      shift 2
      ;;
    --dir)
      INSTALL_DIR="${2:-}"
      shift 2
      ;;
    --user)
      RUN_USER="${2:-}"
      shift 2
      ;;
    --group)
      RUN_GROUP="${2:-}"
      shift 2
      ;;
    --host)
      HOST="${2:-}"
      shift 2
      ;;
    --port)
      PORT="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${REPO_URL}" ]]; then
  echo "--repo is required"
  usage
  exit 1
fi

require_root

log "Installing base packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends \
  git curl ca-certificates python3 python3-venv python3-pip nmap sqlite3

if ! getent group "${RUN_GROUP}" >/dev/null; then
  log "Creating group ${RUN_GROUP}"
  groupadd --system "${RUN_GROUP}"
fi

if ! id -u "${RUN_USER}" >/dev/null 2>&1; then
  log "Creating user ${RUN_USER}"
  useradd --system --create-home --gid "${RUN_GROUP}" --shell /usr/sbin/nologin "${RUN_USER}"
fi

log "Preparing install dir ${INSTALL_DIR}"
mkdir -p "${INSTALL_DIR}"

if [[ -d "${INSTALL_DIR}/.git" ]]; then
  log "Existing repo found. Updating..."
  git -C "${INSTALL_DIR}" fetch --all --prune
  git -C "${INSTALL_DIR}" checkout "${BRANCH}"
  git -C "${INSTALL_DIR}" reset --hard "origin/${BRANCH}"
else
  log "Cloning ${REPO_URL} (${BRANCH})"
  rm -rf "${INSTALL_DIR}"
  git clone --branch "${BRANCH}" --depth 1 "${REPO_URL}" "${INSTALL_DIR}"
fi

log "Creating Python virtual environment"
python3 -m venv "${INSTALL_DIR}/.venv"
"${INSTALL_DIR}/.venv/bin/pip" install --upgrade pip
"${INSTALL_DIR}/.venv/bin/pip" install -r "${INSTALL_DIR}/requirements.txt"

log "Writing environment file"
cat > /etc/default/nexora-scanner <<ENV
NEXORA_HOST=${HOST}
NEXORA_PORT=${PORT}
ENV

log "Installing systemd service"
cat > /etc/systemd/system/nexora-scanner.service <<SERVICE
[Unit]
Description=Nexora Vulnerability Scanner
After=network.target

[Service]
Type=simple
User=${RUN_USER}
Group=${RUN_GROUP}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=-/etc/default/nexora-scanner
ExecStart=${INSTALL_DIR}/.venv/bin/python ${INSTALL_DIR}/app.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

chown -R "${RUN_USER}:${RUN_GROUP}" "${INSTALL_DIR}"

log "Enabling service"
systemctl daemon-reload
systemctl enable --now nexora-scanner

log "Waiting for service startup"
sleep 2
if ! systemctl is-active --quiet nexora-scanner; then
  echo "Service failed to start. Check: journalctl -u nexora-scanner -n 100 --no-pager"
  exit 1
fi

if command -v curl >/dev/null 2>&1; then
  HEALTH_CODE="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/" || true)"
  if [[ "${HEALTH_CODE}" != "200" ]]; then
    echo "Health check returned HTTP ${HEALTH_CODE}. Check service logs."
  fi
fi

log "Install complete"
log "Check service: systemctl status nexora-scanner"
log "Open: http://<raspberry-pi-ip>:${PORT}"
