#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/nexora-scanner"
REMOVE_DATA="false"

usage() {
  cat <<USAGE
Uninstall Nexora Scanner service from Kali Linux (Raspberry Pi).

Usage:
  sudo bash uninstall_kali_rpi.sh [options]

Options:
  --dir <path>          Install directory to remove (default: ${INSTALL_DIR})
  --remove-data         Remove install directory and /etc/default/nexora-scanner
  --help                Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir)
      INSTALL_DIR="${2:-}"
      shift 2
      ;;
    --remove-data)
      REMOVE_DATA="true"
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

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root (use sudo)."
  exit 1
fi

systemctl disable --now nexora-scanner 2>/dev/null || true
rm -f /etc/systemd/system/nexora-scanner.service
systemctl daemon-reload

if [[ "${REMOVE_DATA}" == "true" ]]; then
  rm -rf "${INSTALL_DIR}"
  rm -f /etc/default/nexora-scanner
fi

echo "Uninstall complete"
