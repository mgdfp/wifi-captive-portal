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

echo "==> Installing uv (if not present)..."
if ! command -v uv &>/dev/null; then
  curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh
fi

echo "==> Syncing Python dependencies..."
uv sync

echo "==> Enabling IP forwarding..."
cat > /etc/sysctl.d/99-captive-portal.conf << 'EOF'
net.ipv4.ip_forward=1
EOF
sysctl -w net.ipv4.ip_forward=1

echo "==> Installing dnsmasq (if not present)..."
if ! command -v dnsmasq &>/dev/null; then
  apt-get install -y dnsmasq
fi

echo "==> Writing dnsmasq DHCP config..."
cat > /etc/dnsmasq.d/captive-portal.conf << 'EOF'
# Only serve DHCP on the guest NIC — no DNS (port=0 avoids conflict with systemd-resolved)
interface=eth0
bind-interfaces
port=0

dhcp-range=192.168.21.100,192.168.21.200,12h
dhcp-option=option:router,192.168.21.2
dhcp-option=option:dns-server,8.8.8.8,8.8.4.4

log-dhcp
EOF
systemctl enable dnsmasq
systemctl restart dnsmasq

echo "==> Installing systemd service..."
ln -sf "$REPO_DIR/systemd/$SERVICE_NAME.service" "$SYSTEMD_DIR/$SERVICE_NAME.service"
systemctl daemon-reload
systemctl enable "$SERVICE_NAME"

echo ""
echo "Done. Network config checklist (one-time, done via netplan):"
echo "  eth0: static 192.168.21.2/24  (guest NIC — no gateway)"
echo "  eth1: DHCP                     (uplink to LAN)"
echo ""
echo "UDM Pro VLAN21 checklist:"
echo "  DHCP: None"
echo "  Allow internet access: unchecked"
echo "  mDNS repeater: enabled"
echo ""
echo "Start the portal with:"
echo "  systemctl start $SERVICE_NAME"
echo "  journalctl -f -u $SERVICE_NAME"
