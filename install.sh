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

echo "==> Removing legacy dnsmasq DHCP setup (DHCP is now served by the UDM)..."
if [ -f /etc/dnsmasq.d/captive-portal.conf ]; then
  rm /etc/dnsmasq.d/captive-portal.conf
  systemctl disable --now dnsmasq 2>/dev/null || true
  echo "    dnsmasq config removed and service stopped."
else
  echo "    no legacy dnsmasq config found, skipping."
fi

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
echo "  DHCP: Server mode (range e.g. 192.168.21.100-200)"
echo "  DHCP Gateway IP override: 192.168.21.2 (this VM)"
echo "  DHCP DNS: Auto (the UDM itself)"
echo "  Allow internet access: unchecked (guests egress via this VM only)"
echo "  mDNS repeater: enabled"
echo "  Firewall: drop NEW connections from VLAN21 subnet to other VLANs"
echo "            (prevents bypassing the VM by manually setting gateway .1)"
echo ""
echo "Start the portal with:"
echo "  systemctl start $SERVICE_NAME"
echo "  journalctl -f -u $SERVICE_NAME"
