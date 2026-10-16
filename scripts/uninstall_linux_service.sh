#!/usr/bin/env bash
# AI-HIDS Sentinel - Linux Systemd Uninstallation Script
# Must be executed with sudo privileges

set -e

if [ "$EUID" -ne 0 ]; then
  echo "ERROR: Please run as root or with sudo!"
  exit 1
fi

echo "Stopping and disabling AI-HIDS Sentinel Systemd service..."
systemctl stop ai-hids.service || true
systemctl disable ai-hids.service || true

if [ -f /etc/systemd/system/ai-hids.service ]; then
  rm /etc/systemd/system/ai-hids.service
  systemctl daemon-reload
fi

echo "AI-HIDS Sentinel service successfully uninstalled."
