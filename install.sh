#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
SERVICE_NAME="wifi-captive-portal"
SYSTEMD_DIR="/etc/systemd/system"

echo "==> Creating data directory..."
mkdir -p "$REPO_DIR/data"

echo "==> Checking .env..."
if [ ! -f "$REPO_DIR/.env" ]; then
  cp "$REPO_DIR/.env.example" "$REPO_DIR/.env"
  echo "    .env created from .env.example — fill in your credentials before starting."
else
  echo "    .env already exists, skipping."
fi

echo "==> Syncing dependencies with uv..."
uv sync

echo "==> Installing systemd service..."
ln -sf "$REPO_DIR/systemd/$SERVICE_NAME.service" "$SYSTEMD_DIR/$SERVICE_NAME.service"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

echo ""
echo "Done. Edit .env with your credentials, then run:"
echo "  systemctl start $SERVICE_NAME"
echo "  systemctl status $SERVICE_NAME"
echo ""
echo "Configure UniFi hotspot external portal URL to:"
echo "  http://<this-container-ip>"
