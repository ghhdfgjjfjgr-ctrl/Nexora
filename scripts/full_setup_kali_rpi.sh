#!/usr/bin/env bash
set -euo pipefail

REPO_URL=""
BRANCH="main"
INSTALL_DIR="/opt/nexora-scanner"
RUN_USER="www-data"
RUN_GROUP="www-data"
HOST="0.0.0.0"
PORT="5000"
KEEP_TMP="false"

usage() {
  cat <<USAGE
One-command installer for Nexora Scanner on Kali Linux (Raspberry Pi).
This script clones the GitHub repo then invokes scripts/install_kali_rpi.sh.

Usage:
  sudo bash full_setup_kali_rpi.sh --repo <github_repo_url> [options]

Required:
  --repo <url>          GitHub repository URL (e.g. https://github.com/org/repo.git)

Options:
  --branch <name>       Git branch/tag (default: ${BRANCH})
  --dir <path>          App install directory (default: ${INSTALL_DIR})
  --user <name>         Runtime user (default: ${RUN_USER})
  --group <name>        Runtime group (default: ${RUN_GROUP})
  --host <host>         Bind host (default: ${HOST})
  --port <port>         Bind port (default: ${PORT})
  --keep-tmp            Keep temporary cloned repo under /tmp for debugging
  --help                Show help
USAGE
}

log() {
  echo "[bootstrap] $*"
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
    --keep-tmp)
      KEEP_TMP="true"
      shift 1
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

log "Installing bootstrap dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y --no-install-recommends git ca-certificates curl

TMP_DIR="$(mktemp -d /tmp/nexora-bootstrap.XXXXXX)"
log "Cloning ${REPO_URL} (${BRANCH}) to ${TMP_DIR}"
git clone --depth 1 --branch "${BRANCH}" "${REPO_URL}" "${TMP_DIR}"

INSTALL_SCRIPT="${TMP_DIR}/scripts/install_kali_rpi.sh"
if [[ ! -f "${INSTALL_SCRIPT}" ]]; then
  echo "Install script not found: ${INSTALL_SCRIPT}"
  exit 1
fi

chmod +x "${INSTALL_SCRIPT}"

log "Running project install script"
bash "${INSTALL_SCRIPT}" \
  --repo "${REPO_URL}" \
  --branch "${BRANCH}" \
  --dir "${INSTALL_DIR}" \
  --user "${RUN_USER}" \
  --group "${RUN_GROUP}" \
  --host "${HOST}" \
  --port "${PORT}"

if [[ "${KEEP_TMP}" == "true" ]]; then
  log "Keeping temporary directory: ${TMP_DIR}"
else
  rm -rf "${TMP_DIR}"
  log "Temporary directory removed"
fi

log "Done. Service status: systemctl status nexora-scanner"
