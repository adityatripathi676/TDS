#!/usr/bin/env bash
# AI-HIDS Sentinel - Linux Systemd Installation Script
# Must be executed with sudo privileges

set -e

if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Please run as root or with sudo!"
  exit 1
fi

echo "======================================================================"
echo " AI-HIDS Sentinel - Linux Systemd Background Service Installer"
echo "======================================================================"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TARGET_DIR="/opt/ai-hids"

echo "Copying application files to $TARGET_DIR..."
mkdir -p "$TARGET_DIR"
cp -r "$PROJECT_DIR"/* "$TARGET_DIR"/

echo "Installing Systemd unit file..."
cp "$SCRIPT_DIR/ai-hids.service" /etc/systemd/system/ai-hids.service

echo "Reloading systemctl daemon and enabling service on boot..."
systemctl daemon-reload
systemctl enable ai-hids.service
systemctl start ai-hids.service

echo "----------------------------------------------------------------------"
echo "Installation Complete! Service Status:"
systemctl status ai-hids.service --no-pager
echo "----------------------------------------------------------------------"
